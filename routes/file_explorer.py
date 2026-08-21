"""File Explorer: browse/copy/delete, preview (raw/text/hex), metadata
(ExifTool + plain stat_info), hash verification, and the analysis-tool
actions (Binwalk, ClamAV, hashdeep, Geolocation KML export, strings, Quick
Triage Scan, MVT). /api/report/load and /api/report/save stay behind in
app.py for now - reclassified into routes/reporting.py in a later step
(they're reporting-permission-gated, not file_explorer-permission-gated,
despite sitting physically inside this block today).

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import re
import time
import json
import stat
import pwd
import grp
import mimetypes
import base64
import shutil
import hashlib
import subprocess

from flask import Blueprint, jsonify, request, send_file

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, case_consolidated_path, classify_case_role
from core.config import EVIDENCE_ROOT, ALLOWED_HASH_ALGOS, MVT_IOS_BIN, MVT_ANDROID_BIN
from core.case_index_db import (
    build_scan_patterns, resolve_scan_category_label,
    case_index_db_path, _case_index_connect, _record_analysis_result, _auto_tag_case_artifact,
    _record_parsed_artifacts,
)
from core.geo_utils import GEO_IMAGE_EXTENSIONS, _geo_points_from_exiftool_entries, _build_geo_kml
from core.browser_artifacts import find_browser_artifact_files, parse_browser_profile_file

file_explorer_bp = Blueprint('file_explorer', __name__)

# --- File Explorer Endpoints ---
@file_explorer_bp.route('/api/files/browse', methods=['POST'])
@requires_auth
def browse_files():
    req = request.get_json() or {}
    path = safe_path(req.get('path', EVIDENCE_ROOT))
    if not path:
        return jsonify({"error": "Path is outside the permitted evidence directory."}), 403
    if not os.path.exists(path):
        return jsonify({"error": f"Path '{path}' does not exist"}), 404

    items = []
    try:
        for entry in os.scandir(path):
            try:
                st = entry.stat()
                is_dir = entry.is_dir()
                # Full MACB timestamp set per entry (Modified/Accessed/Changed/Born), matching what
                # the Sleuth Kit image-mode listing already exposes - "Created" stays honestly
                # best-effort (see _format_epoch/_human_size above: st_ctime is inode-change time on
                # the ext4/XFS filesystems this app targets, never mislabeled as a real creation
                # time; a genuine st_birthtime is used only when the platform/filesystem actually
                # provides one).
                items.append({
                    "name": entry.name,
                    "path": entry.path,
                    "is_dir": is_dir,
                    "size_bytes": st.st_size if not is_dir else 0,
                    "size_str": _human_size(st.st_size) if not is_dir else "--",
                    "modified": _format_epoch(st.st_mtime),
                    "accessed": _format_epoch(st.st_atime),
                    "changed": _format_epoch(st.st_ctime),
                    "created": _format_epoch(getattr(st, 'st_birthtime', None)),
                    # None for a directory or anything that isn't a
                    # recognized artifact kind this app itself generates -
                    # see classify_case_role()'s own docstring.
                    "case_role": None if is_dir else classify_case_role(entry.name),
                })
            except Exception:
                pass
        return jsonify({"path": path, "items": sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@file_explorer_bp.route('/api/files/copy', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def copy_file():
    req = request.get_json() or {}
    src = safe_path(req.get('source'))
    dest_dir = safe_path(req.get('destination_dir'))

    if not src or not os.path.exists(src) or not dest_dir or not os.path.exists(dest_dir):
        return jsonify({"success": False, "error": "Invalid source or destination path"}), 400

    try:
        dest_path = os.path.join(dest_dir, os.path.basename(src))
        if os.path.isdir(src):
            shutil.copytree(src, dest_path, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dest_path)
        log_chain_of_custody("file_copy", {"source": src, "destination": dest_path})
        return jsonify({"success": True, "message": f"Copied {os.path.basename(src)} to {dest_dir}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@file_explorer_bp.route('/api/files/delete', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def delete_file():
    req = request.get_json() or {}
    path = safe_path(req.get('path'))

    if not path or not os.path.exists(path):
        return jsonify({"success": False, "error": "Path does not exist or is outside the permitted evidence directory."}), 400

    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        log_chain_of_custody("file_delete", {"path": path})
        return jsonify({"success": True, "message": f"Deleted {os.path.basename(path)}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- File Preview (image/PDF src / text content) ---
_PREVIEWABLE_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
_PREVIEWABLE_TEXT_EXT = {'.txt', '.json', '.log', '.md', '.csv', '.xml', '.html', '.htm', '.py', '.js', '.sh', '.conf', '.ini', '.cfg', '.yaml', '.yml'}
# PDF is deliberately in its own set, not merged into _PREVIEWABLE_IMAGE_EXT - it's still
# served raw (needs the real bytes for the browser's native PDF viewer, can't be inlined as
# text), but unlike images it's never routed through innerHTML-adjacent code, and its
# eventual rendering context (a plain <iframe src=...>, browser's built-in PDF viewer) has no
# script-execution surface, unlike HTML - see the note on get_raw_file() below for why HTML
# preview deliberately does NOT go through this same raw-serving endpoint.
_PREVIEWABLE_PDF_EXT = {'.pdf'}
_PREVIEW_TEXT_MAX_BYTES = 200 * 1024  # 200 KB - enough for a meaningful preview without loading huge files into memory
_HEX_PREVIEW_MAX_BYTES = 64 * 1024  # 64 KB - rendered client-side as a classic hex dump (offset/hex/ASCII), kept smaller than the plain-text cap since hex output is far denser per byte

@file_explorer_bp.route('/api/files/raw', methods=['GET'])
@requires_auth
def get_raw_file():
    # Deliberately excludes HTML: serving a suspect-drive HTML file at a directly-navigable,
    # same-origin URL with a real text/html Content-Type would let it execute script with this
    # app's own origin/session if ever opened outside the sandboxed-iframe preview (bookmarked,
    # pasted into another tab, etc.) - the exact stored-XSS risk this app's "never innerHTML
    # untrusted content" discipline exists to prevent, just via a URL instead of the DOM. HTML
    # preview instead reuses the existing JSON-only preview_text_file() below and is rendered
    # into a fully sandboxed iframe (sandbox="", no allow-scripts/allow-same-origin) client-side
    # - see previewSelectedFile() in main.js - so no route ever serves raw HTML bytes as HTML.
    path = safe_path(request.args.get('path', ''))
    if not path or not os.path.isfile(path):
        return jsonify({"error": "File not found or outside the permitted evidence directory."}), 404

    ext = os.path.splitext(path)[1].lower()
    if ext not in _PREVIEWABLE_IMAGE_EXT and ext not in _PREVIEWABLE_PDF_EXT:
        return jsonify({"error": "Only image and PDF files can be served this way."}), 400

    resp = send_file(path)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

@file_explorer_bp.route('/api/files/preview_text', methods=['POST'])
@requires_auth
def preview_text_file():
    req = request.get_json() or {}
    path = safe_path(req.get('path'))
    if not path or not os.path.isfile(path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 404

    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            raw = f.read(_PREVIEW_TEXT_MAX_BYTES)
        text = raw.decode('utf-8', errors='replace')
        truncated = size > _PREVIEW_TEXT_MAX_BYTES
        return jsonify({"success": True, "content": text, "truncated": truncated, "size_bytes": size})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@file_explorer_bp.route('/api/files/hex', methods=['POST'])
@requires_auth
def get_file_hex():
    """Capped raw-byte read for the Hex tab - returns base64, not a
    pre-formatted dump; the client builds the offset/hex/ASCII columns
    (matches how image_preview()/image_hex() already hand back base64 image
    data for client-side rendering rather than doing layout server-side)."""
    req = request.get_json() or {}
    path = safe_path(req.get('path'))
    if not path or not os.path.isfile(path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 404

    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            raw = f.read(_HEX_PREVIEW_MAX_BYTES)
        return jsonify({
            "success": True, "data": base64.b64encode(raw).decode('ascii'),
            "bytes_read": len(raw), "total_size": size, "truncated": size > len(raw),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Post-Acquisition Hash Verifier ---
@file_explorer_bp.route('/api/verify_hash', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def verify_file_hash():
    req = request.get_json() or {}
    file_path = safe_path(req.get('file_path'))
    algo = req.get('algorithm', 'sha256').lower()

    if not file_path or not os.path.exists(file_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    if algo not in ALLOWED_HASH_ALGOS:
        return jsonify({"success": False, "error": f"Unsupported algorithm '{algo}'. Use one of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    try:
        hasher = getattr(hashlib, algo)()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed = hasher.hexdigest()

        return jsonify({
            "success": True,
            "file_name": os.path.basename(file_path),
            "algorithm": algo.upper(),
            "hash": computed
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- File Metadata (ExifTool) ---
@file_explorer_bp.route('/api/files/exif', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def get_file_exif():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))

    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    try:
        # -j = JSON output, -a = allow duplicate tags, -G = group names (helps
        # distinguish e.g. EXIF:CreateDate from File:FileModifyDate at a glance)
        res = subprocess.run(['exiftool', '-j', '-a', '-G', file_path], capture_output=True, text=True, timeout=30)
        if res.returncode != 0 and not res.stdout.strip():
            return jsonify({"success": False, "error": res.stderr.strip() or "exiftool failed with no output."}), 500

        parsed = json.loads(res.stdout)
        metadata = parsed[0] if parsed else {}
        # SourceFile is just the path we already know - drop it to avoid
        # re-exposing the full server-side path in the UI unnecessarily.
        metadata.pop('SourceFile', None)

        return jsonify({"success": True, "file_name": os.path.basename(file_path), "metadata": metadata})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "exiftool timed out."}), 500
    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Could not parse exiftool output."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _human_size(num_bytes):
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024


def _format_epoch(ts):
    # time.localtime(None) silently defaults to the CURRENT time rather than raising - a falsy/
    # missing timestamp must be rejected explicitly here, not left to the caller to remember to
    # guard against, or a genuinely-unknown timestamp would render as "right now" instead of
    # "Unknown".
    if not ts:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OSError, OverflowError, ValueError):
        return None


# Real filesystem facts (size, timestamps, permissions, owner) for whatever is currently selected
# in File Explorer - works for both files and directories, unlike /api/files/exif above (ExifTool-
# only, file-only, embedded metadata). Deliberately does NOT compute a hash here - that's a
# dedicated, already-existing right-click action (Verify Image Hash) precisely because hashing a
# large file is slow and shouldn't happen as a side effect of just clicking to look at something.
@file_explorer_bp.route('/api/files/stat_info', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def get_file_stat_info():
    req = request.get_json() or {}
    target_path = safe_path(req.get('path'))
    if not target_path or not os.path.exists(target_path):
        return jsonify({"success": False, "error": "Path not found or outside the permitted evidence directory."}), 400

    try:
        st = os.stat(target_path)
        is_dir = os.path.isdir(target_path)
        name = os.path.basename(target_path)

        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        extension = None
        mime_type = None
        if not is_dir:
            _, ext = os.path.splitext(name)
            extension = ext[1:].lower() if ext else None
            mime_type, _ = mimetypes.guess_type(name)

        # "Created" is honestly best-effort, not guaranteed - st_ctime is inode-change time on the
        # ext4/XFS filesystems this app actually targets, NOT a real creation time, and Python's
        # st_birthtime attribute (a genuine creation time, via statx()) is only populated when both
        # the Python version and the underlying filesystem support it. Reported as null/"Unknown"
        # rather than silently mislabeling ctime as a creation date when birthtime isn't available.
        created_epoch = getattr(st, 'st_birthtime', None)

        return jsonify({
            "success": True,
            "name": name,
            "path": target_path,
            "is_dir": is_dir,
            "size_bytes": st.st_size,
            "size_str": _human_size(st.st_size) if not is_dir else None,
            "extension": extension,
            "mime_type": mime_type,
            "created": _format_epoch(created_epoch) if created_epoch else None,
            "modified": _format_epoch(st.st_mtime),
            "accessed": _format_epoch(st.st_atime),
            "permissions": stat.filemode(st.st_mode),
            "permissions_octal": oct(stat.S_IMODE(st.st_mode))[2:].zfill(4),
            "owner": owner,
            "group": group,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Binwalk: Embedded Filesystem / Firmware Signature Scan ---
@file_explorer_bp.route('/api/files/binwalk', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def run_binwalk():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    # Optional, best-effort - see quick_triage_scan()'s matching comment.
    # Only persisted into the case's analysis index when this file is being
    # scanned in the context of an active, already-consolidated case.
    case_folder = req.get('case_folder')

    try:
        # Signature scan only - deliberately not using -e (extract), which
        # would write files into the evidence directory automatically.
        # Extraction can be added as an explicit, separate action later if
        # needed, with its own destination picker rather than happening
        # silently as a side effect of scanning.
        res = subprocess.run(['binwalk', file_path], capture_output=True, text=True, timeout=120)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        sig_count = len(re.findall(r'^\d+\s', output, re.MULTILINE))
        summary = f"{sig_count} signature(s) found" if sig_count else "No signatures found"
        log_chain_of_custody("binwalk_scan", {"path": file_path})
        _record_analysis_result(case_folder, {"source_type": "real_fs", "path": file_path,
                                               "name": os.path.basename(file_path)}, "Binwalk", summary, output)
        return jsonify({"success": True, "file_name": os.path.basename(file_path), "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "binwalk timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# testdisk_analyze now lives in routes/recovery.py, alongside the other 5
# recovery routes - see the dated CLAUDE.md entry for this refactor.

# --- ClamAV: Malware Scan ---
@file_explorer_bp.route('/api/files/clamscan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def run_clamscan():
    req = request.get_json() or {}
    target_path = safe_path(req.get('path'))
    if not target_path or not os.path.exists(target_path):
        return jsonify({"success": False, "error": "Path not found or outside the permitted evidence directory."}), 400

    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    try:
        # -r = recursive (harmless no-op on a single file), --no-summary
        # keeps output focused on actual findings rather than a stats block.
        res = subprocess.run(['clamscan', '-r', '--no-summary', target_path], capture_output=True, text=True, timeout=300)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        # clamscan exit codes: 0 = clean, 1 = virus(es) found, 2 = error
        infected = res.returncode == 1
        log_chain_of_custody("clamav_scan", {"path": target_path, "infected": infected})
        _record_analysis_result(case_folder, {"source_type": "real_fs", "path": target_path,
                                               "name": os.path.basename(target_path)}, "ClamAV",
                                 "THREAT(S) FOUND" if infected else "CLEAN", output)
        return jsonify({"success": True, "path": target_path, "infected": infected, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "clamscan timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- hashdeep: Recursive Directory Hash Manifest ---
@file_explorer_bp.route('/api/files/hashdeep', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def run_hashdeep():
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    algo = req.get('algorithm', 'sha256').lower()
    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400
    if algo not in ALLOWED_HASH_ALGOS:
        return jsonify({"success": False, "error": f"Unsupported algorithm '{algo}'. Use one of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    manifest_path = os.path.join(target_dir, f"_hashdeep_{algo}_manifest.txt")
    try:
        res = subprocess.run(
            ['hashdeep', '-r', '-c', algo, target_dir],
            capture_output=True, text=True, timeout=600
        )
        with open(manifest_path, 'w') as f:
            f.write(res.stdout)
        _auto_tag_case_artifact(target_dir, manifest_path)

        file_count = sum(1 for line in res.stdout.splitlines() if line and not line.startswith('%') and not line.startswith('#'))
        log_chain_of_custody("hashdeep_manifest", {"directory": target_dir, "algorithm": algo, "file_count": file_count})
        return jsonify({"success": True, "manifest_path": manifest_path, "file_count": file_count})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "hashdeep timed out (large directory - consider a subdirectory instead)."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Geolocation: Extract GPS EXIF Data as a KML File ---
# GEO_IMAGE_EXTENSIONS/_kml_escape/_geo_points_from_exiftool_entries/
# _build_geo_kml now live in core/geo_utils.py (imported at the top of this
# file) - shared with the in-image geolocation route, which still lives in
# app.py pending its own Step 7 extraction into routes/image_browser.py.

@file_explorer_bp.route('/api/files/geolocation_kml', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def extract_geolocation_kml():
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400

    # -n: signed decimal degrees for GPSLatitude/GPSLongitude (exiftool applies the
    # N/S/E/W hemisphere sign automatically) instead of a "39 deg 21' N" DMS string -
    # this is what makes the values directly usable as KML <coordinates>.
    cmd = ['exiftool', '-j', '-n', '-r']
    for ext in GEO_IMAGE_EXTENSIONS:
        cmd += ['-ext', ext]
    cmd += ['-GPSLatitude', '-GPSLongitude', '-GPSAltitude', '-DateTimeOriginal', '-FileName', '-Directory', target_dir]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if res.returncode != 0 and not res.stdout.strip():
            return jsonify({"success": False, "error": res.stderr.strip() or "exiftool failed with no output."}), 500
        entries = json.loads(res.stdout) if res.stdout.strip() else []
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "exiftool timed out (large directory - consider a subdirectory instead)."}), 500
    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Could not parse exiftool output."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    points = _geo_points_from_exiftool_entries(entries)
    kml_doc = _build_geo_kml(points, f"{os.path.basename(target_dir)} - Geolocation Export")

    kml_path = None
    if kml_doc:
        # Only written when at least one point is found - this action is expected
        # to be run on plenty of folders with no GPS-tagged photos at all, and a
        # dead empty file every time would just be clutter, not documentation.
        kml_path = os.path.join(target_dir, "_geolocation_export.kml")
        try:
            with open(kml_path, 'w', encoding='utf-8') as f:
                f.write(kml_doc)
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to write KML file: {e}"}), 500
        _auto_tag_case_artifact(target_dir, kml_path)

    log_chain_of_custody("geolocation_kml_export", {
        "directory": target_dir, "files_scanned": len(entries), "points_found": len(points)
    })
    return jsonify({"success": True, "kml_path": kml_path, "files_scanned": len(entries), "points_found": len(points)})

# --- Browser Artifacts: real per-app parsing (Chrome/Chromium family + Firefox) ---
# core/browser_artifacts.py holds the actual parsing (History/Downloads/
# Bookmarks/Cookies, either browser family) and the real-fs candidate-file
# walk; this route is
# just the HTTP layer - find candidates under target_dir, parse each,
# persist into the case's analysis index (File Views' new "Web Artifacts"
# category reads it back), and report a summary. No flat report file is
# written for this one (unlike hashdeep/geolocation above) - the per-case
# SQLite index is already the durable, queryable record, and this is the
# first analysis feature built after that index existed, so there's no
# legacy flat-file expectation to preserve here.
@file_explorer_bp.route('/api/files/parse_browser_artifacts', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def parse_browser_artifacts():
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    candidate_paths, truncated = find_browser_artifact_files(target_dir)
    counts = {}
    files_parsed = 0
    for path in candidate_paths:
        filename = os.path.basename(path)
        records = parse_browser_profile_file(path, filename)
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": path}, records)

    log_chain_of_custody("browser_artifacts_parsed", {
        "directory": target_dir, "candidates_found": len(candidate_paths),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidate_paths), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated,
        "indexed": bool(case_folder),
    })

# --- strings: Extract Printable Text From a Binary File ---
@file_explorer_bp.route('/api/files/strings', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def run_strings():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    try:
        res = subprocess.run(['strings', '-n', '6', file_path], capture_output=True, text=True, timeout=60)
        lines = res.stdout.splitlines()
        truncated = len(lines) > 1000
        output = "\n".join(lines[:1000])
        if truncated:
            output += f"\n\n[... truncated, {len(lines) - 1000} more lines not shown ...]"
        output = output or "[no printable strings found]"
        summary = f"{min(len(lines), 1000)} line(s) extracted" + (" (capped)" if truncated else "")
        _record_analysis_result(case_folder, {"source_type": "real_fs", "path": file_path,
                                               "name": os.path.basename(file_path)}, "Strings", summary, output)
        return jsonify({"success": True, "file_name": os.path.basename(file_path), "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "strings timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Quick Triage Scan: fast, capped IOC scan for a single right-clicked file ---
# Reuses build_scan_patterns()/the same regex-per-chunk-with-overlap
# technique execution_worker_triage_scan() (File Recovery's background job)
# already uses - this is deliberately NOT a second scanning implementation,
# just a capped, synchronous entry point into the same category matching
# (the 5 built-in structured-data categories, plus any keyword_list_ids the
# caller selects), for a quick right-click look at a .dd/.E01 image (or any
# other file) without configuring and running the full background job. Only
# scans the first QUICK_TRIAGE_MAX_BYTES of the file - large/exhaustive
# scans still belong to the File Recovery tab's Triage Scan tool.
QUICK_TRIAGE_MAX_BYTES = 32 * 1024 * 1024  # 32 MB - fast enough to stay synchronous within one request
QUICK_TRIAGE_MAX_MATCHES_PER_CATEGORY = 500  # smaller than the background job's 50000 - this is a quick preview, not an exhaustive collection

@file_explorer_bp.route('/api/files/quick_triage_scan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def quick_triage_scan():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    # Optional - the frontend sends activeCase.case_folder when a case is
    # selected (no server-side "active case" state, matching every other
    # case-aware route in this app). If it resolves to a real, already-
    # consolidated case folder, this scan's hits get recorded into that
    # case's analysis index too, alongside whatever image-based scans have
    # already indexed - a quick single-file scan never needs a full re-index.
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    patterns = build_scan_patterns(req.get('keyword_list_ids'))

    CHUNK_SIZE = 8 * 1024 * 1024
    OVERLAP = 256  # bytes carried over between chunks so a match spanning a chunk boundary isn't missed
    results = {name: set() for name in patterns}
    truncated = {name: False for name in patterns}

    try:
        total_size = os.path.getsize(file_path)
        bytes_read = 0
        tail = b""
        with open(file_path, 'rb') as f:
            while bytes_read < QUICK_TRIAGE_MAX_BYTES:
                chunk = f.read(min(CHUNK_SIZE, QUICK_TRIAGE_MAX_BYTES - bytes_read))
                if not chunk:
                    break
                data = tail + chunk
                for name, pattern in patterns.items():
                    if truncated[name]:
                        continue
                    for m in pattern.finditer(data):
                        val = m.group(0)
                        if len(val) > 4:  # skip trivial/near-empty matches
                            results[name].add(val)
                            if len(results[name]) >= QUICK_TRIAGE_MAX_MATCHES_PER_CATEGORY:
                                truncated[name] = True
                                break
                tail = data[-OVERLAP:] if len(data) >= OVERLAP else data
                bytes_read += len(chunk)
    except Exception as e:
        return jsonify({"success": False, "error": f"Scan failed: {e}"}), 500

    scan_truncated_to_prefix = total_size > QUICK_TRIAGE_MAX_BYTES
    total_hits = sum(len(v) for v in results.values())

    if case_folder and total_hits:
        index_db_path = case_index_db_path(case_folder)
        if index_db_path:
            found_at = time.strftime("%Y-%m-%d %H:%M:%S")
            hit_rows = [
                ('real_fs', None, None, None, file_path, name, val.decode('utf-8', errors='replace'), found_at)
                for name, matches in results.items() for val in matches
            ]
            try:
                conn = _case_index_connect(index_db_path)
                conn.executemany(
                    "INSERT INTO triage_hits (source_type, image_path, fs_offset, inode, path, category, value, found_at) VALUES (?,?,?,?,?,?,?,?)",
                    hit_rows)
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Warning: quick_triage_scan could not write to case index: {e}")

    lines = [f"Scanned {bytes_read / (1024*1024):.1f} MB of {total_size / (1024*1024):.1f} MB total."]
    if scan_truncated_to_prefix:
        lines.append("(First-32MB quick preview only - use the full Triage Scan tool in File Recovery for an exhaustive scan of the whole file.)")
    lines.append("")
    for name in patterns:
        matches = sorted(results[name])
        label = resolve_scan_category_label(name)
        cap_note = " (capped)" if truncated[name] else ""
        lines.append(f"{label} ({len(matches)} found{cap_note}):")
        if matches:
            for val in matches:
                lines.append(f"  {val.decode('utf-8', errors='replace')}")
        lines.append("")

    log_chain_of_custody("quick_triage_scan", {"path": file_path, "bytes_scanned": bytes_read, "total_hits": total_hits})
    return jsonify({
        "success": True, "file_name": os.path.basename(file_path),
        "output": "\n".join(lines).strip(), "total_hits": total_hits,
    })

# --- MVT (Mobile Verification Toolkit): Spyware/IOC Analysis ---
# Analyzes an already-acquired mobile backup for indicators of compromise
# (known spyware, e.g. Pegasus) - this does NOT acquire anything itself, it
# runs against output the Mobile Forensics tab already produced. iOS is a
# clean fit: mvt-ios's check-backup expects exactly the directory structure
# idevicebackup2 --full already writes. Android is best-effort only -
# mvt-android's check-backup expects a decrypted `adb backup` (.ab)
# extraction, which doesn't line up with this app's adb pull/bugreport
# output; it will error clearly on those rather than silently finding
# nothing, so it's still exposed rather than blocked outright.
@file_explorer_bp.route('/api/files/mvt_scan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def run_mvt_scan():
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    platform = req.get('platform', '')

    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400
    if platform not in ('ios', 'android'):
        return jsonify({"success": False, "error": "platform must be 'ios' or 'android'."}), 400

    mvt_bin = MVT_IOS_BIN if platform == 'ios' else MVT_ANDROID_BIN
    if not os.path.isfile(mvt_bin):
        return jsonify({"success": False, "error": f"{os.path.basename(mvt_bin)} is not installed. Check Advanced Settings > Tool Versions."}), 400

    output_dir = os.path.join(target_dir, f"_mvt_{platform}_scan")
    os.makedirs(output_dir, exist_ok=True)

    try:
        res = subprocess.run(
            [mvt_bin, 'check-backup', '--output', output_dir, target_dir],
            capture_output=True, text=True, timeout=900
        )
        output = ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip() or "[no output]"
        log_chain_of_custody("mvt_scan", {"path": target_dir, "platform": platform, "output_dir": output_dir})
        return jsonify({"success": True, "platform": platform, "output_dir": output_dir, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "MVT scan timed out (large backup - partial results may still be in output_dir)."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

