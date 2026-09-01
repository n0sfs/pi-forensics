"""Video keyframe/thumbnail triage - a single ffmpeg invocation extracts a
grid of evenly-spaced frames from a video file and tiles them into one
"contact sheet" image, giving an examiner a fast visual overview of a
video's contents without needing to open and scrub through it in a media
player. Real, standard ffmpeg filter-graph usage (`select` picks frames at
a fixed time interval, `tile` arranges them into a grid, `-frames:v 1`
writes exactly one composite image) - this exact select+tile contact-sheet
pattern is well-documented, common ffmpeg usage, not a reverse-engineered
format needing the same "fetch and read real source first" grounding this
session's binary-format parsers (BITS, RDP Bitmap Cache) needed.

Invokes the real `ffprobe`/`ffmpeg` CLIs directly via subprocess -
`ffmpeg` (which bundles `ffprobe`) is a Debian package, confirmed present
on trixie/arm64 via apt-cache before adding to install.py (and already
installed as a transitive dependency on the deployed station).
"""
import json
import os
import subprocess

VIDEO_FILE_EXTENSIONS = {'.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.3gp', '.mpg', '.mpeg'}
VIDEO_PROBE_TIMEOUT_SECONDS = 30
VIDEO_CONTACT_SHEET_TIMEOUT_SECONDS = 180
CONTACT_SHEET_GRID_COLS = 4
CONTACT_SHEET_GRID_ROWS = 3
CONTACT_SHEET_THUMB_WIDTH = 320


def is_video_candidate_file(filename):
    """Returns True if filename's extension is a common real video
    container format."""
    return os.path.splitext(filename)[1].lower() in VIDEO_FILE_EXTENSIONS


def get_video_duration_seconds(video_path):
    """Returns (duration_seconds_or_none, error_or_none) via a real
    ffprobe call - never raises."""
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration',
             '-of', 'json', video_path],
            capture_output=True, text=True, timeout=VIDEO_PROBE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "ffmpeg/ffprobe is not installed on this station."
    except subprocess.TimeoutExpired:
        return None, "Reading video metadata timed out."
    except Exception as e:
        return None, str(e)

    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        return None, stderr or "Not a recognized video file (ffprobe could not read it)."

    try:
        duration = float(json.loads(result.stdout)['format']['duration'])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None, "Could not determine this video's duration."
    if duration <= 0:
        return None, "This video reports a zero or negative duration."
    return duration, None


def generate_video_contact_sheet(video_path, output_path, cols=CONTACT_SHEET_GRID_COLS,
                                  rows=CONTACT_SHEET_GRID_ROWS, thumb_width=CONTACT_SHEET_THUMB_WIDTH):
    """Writes a real, single JPEG contact-sheet image to output_path -
    cols*rows evenly-spaced frames tiled into one grid. Returns
    (frame_count_or_none, error_or_none) - never raises. A video shorter
    than one frame per grid cell still produces a real (if repeated-frame)
    sheet rather than failing - ffmpeg's own select filter naturally
    degrades to whatever frames actually exist."""
    duration, error = get_video_duration_seconds(video_path)
    if error:
        return None, error

    frame_count = cols * rows
    interval = max(duration / frame_count, 0.1)
    # Real ffmpeg filter-graph syntax: select one frame roughly every
    # `interval` seconds (comparing each candidate frame's own timestamp
    # against the last SELECTED frame's timestamp, not simple frame
    # counting - correct regardless of the source's real frame rate),
    # scale each to a fixed width, then tile cols x rows of them into one
    # composite image. -frames:v 1 ensures exactly one output file (the
    # tiled composite itself), not one file per selected frame.
    vf = (
        f"select='isnan(prev_selected_t)+gte(t-prev_selected_t\\,{interval})',"
        f"scale={thumb_width}:-1,tile={cols}x{rows}"
    )
    try:
        result = subprocess.run(
            ['ffmpeg', '-y', '-i', video_path, '-vf', vf, '-frames:v', '1', output_path],
            capture_output=True, text=True, timeout=VIDEO_CONTACT_SHEET_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "ffmpeg is not installed on this station."
    except subprocess.TimeoutExpired:
        return None, "Contact sheet generation timed out."
    except Exception as e:
        return None, str(e)

    if result.returncode != 0 or not os.path.isfile(output_path):
        stderr = (result.stderr or '').strip().splitlines()
        return None, (stderr[-1] if stderr else "ffmpeg failed to produce a contact sheet.")

    return frame_count, None
