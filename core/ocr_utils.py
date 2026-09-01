"""OCR (Optical Character Recognition) text extraction from image files -
screenshots, scanned documents, and photographed text/signage often carry
real evidentiary text that no other tool in this app can surface (Strings
only reads a file's raw bytes, never rendered pixel content). Invokes the
real `tesseract` CLI directly via subprocess (`tesseract-ocr`, Debian
package, confirmed present on trixie/arm64 via apt-cache before adding to
install.py) - deliberately no `pytesseract` pip wrapper, since that
package is itself just a thin subprocess shim around this same CLI call;
adding it would be a second layer with no real capability this module
doesn't already have direct access to, matching this app's own
established preference for a real, documented CLI tool over an
unnecessary wrapper (Strings/Binwalk/ClamAV are all invoked the identical
direct-subprocess way).

`tesseract <image> stdout` is real, standard, documented tesseract CLI
usage - the special output-base argument `stdout` (in place of a real
file-basename) tells tesseract to print recognized text to stdout instead
of writing a `<basename>.txt` file, so this never needs to touch the
filesystem at all beyond reading the source image.

Scoped to English only for v1 (the `tesseract-ocr` Debian package bundles
English language data by default; additional language packs, e.g.
`tesseract-ocr-fra`, are a real, deliberate out-of-scope for this pass,
not silently unsupported - flagged in the module docstring, not hidden).
"""
import os
import subprocess

OCR_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tif', '.tiff', '.gif', '.webp', '.pnm'}
OCR_TIMEOUT_SECONDS = 90
OCR_MAX_OUTPUT_CHARS = 20_000


def is_ocr_candidate_image(filename):
    """Returns True if filename's extension is a real, tesseract-supported
    raster image format (via leptonica) - the same gate every context-menu
    OCR action checks before offering it."""
    return os.path.splitext(filename)[1].lower() in OCR_IMAGE_EXTENSIONS


def run_ocr_on_image(image_path):
    """Runs the real `tesseract` CLI against image_path, returns
    (text_or_none, error_or_none) - never raises. A real, successful OCR
    pass with genuinely no recognizable text returns ('', None), not an
    error - tesseract itself does this for a blank/photo-only image, and
    that's a real, meaningful result (this image has no OCR-able text),
    not a failure. Output is capped at OCR_MAX_OUTPUT_CHARS with a
    disclosed truncation note, matching this app's established
    no-silent-truncation convention for every other capped-output tool
    (Strings/Quick Triage Scan)."""
    if not os.path.isfile(image_path):
        return None, "File not found."
    try:
        result = subprocess.run(
            ['tesseract', image_path, 'stdout'],
            capture_output=True, text=True, timeout=OCR_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "tesseract is not installed on this station."
    except subprocess.TimeoutExpired:
        return None, "OCR timed out."
    except Exception as e:
        return None, str(e)

    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        return None, stderr or f"tesseract exited with status {result.returncode}."

    text = (result.stdout or '').strip()
    if len(text) > OCR_MAX_OUTPUT_CHARS:
        text = text[:OCR_MAX_OUTPUT_CHARS] + f"\n\n[... truncated, {len(text) - OCR_MAX_OUTPUT_CHARS} more character(s) not shown ...]"
    return text, None
