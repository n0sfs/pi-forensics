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
import sqlite3
import pwd
import grp
import mimetypes
import base64
import shutil
import hashlib
import subprocess
import threading

from flask import Blueprint, jsonify, request, send_file, g

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, case_consolidated_path, classify_case_role
from core.config import EVIDENCE_ROOT, ALLOWED_HASH_ALGOS, MVT_IOS_BIN, MVT_ANDROID_BIN, VOL3_BIN, load_hash_list_sets
from core.case_index_db import (
    build_scan_patterns, resolve_scan_category_label,
    case_index_db_path, _case_index_connect, _record_analysis_result, _auto_tag_case_artifact,
    _record_parsed_artifacts,
)
from core.geo_utils import GEO_IMAGE_EXTENSIONS, _geo_points_from_exiftool_entries, _build_geo_kml
from core.browser_artifacts import find_browser_artifact_files, parse_browser_profile_file, _open_sqlite_readonly
from core.registry_utils import find_registry_hive_files, parse_registry_hive_file
from core.evtx_utils import find_evtx_files, parse_evtx_file
from core.lnk_utils import parse_lnk_file
from core.jobs import job_lock, current_job, update_job, snapshot_job

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
# 'reporting' too, not just 'file_explorer': this route is also reached
# from Reporting's own Geolocation section and its Files gallery's KML
# viewer, not only File Explorer's Preview pane - same two-permission
# pattern already used for attach_file_to_case()/report_templates_custom_
# detail() for the identical reason. Found missing entirely during the
# 2026-08-22 security audit (no permission check at all, letting a
# 'file_explorer'-revoked account still read full evidence content).
@requires_permission('file_explorer', 'reporting')
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
# Found missing entirely during the 2026-08-22 security audit - every
# sibling content route (copy/delete/verify_hash/exif/binwalk/etc.) has
# this check; this one didn't, letting a 'file_explorer'-revoked account
# still read the full raw bytes of any evidence file. Unlike
# preview_text_file() above, the Hex tab is File-Explorer-only (no
# Reporting call site), so a single permission key is correct here.
@requires_permission('file_explorer')
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

@file_explorer_bp.route('/api/files/check_hash_lists', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def check_hash_lists():
    """D2 (hash-set filtering) - hashes a single selected file with
    whichever algorithm(s) the requested hash lists actually use (a file
    is only ever hashed once per distinct algorithm, even if several
    selected lists share one), then checks membership against each list's
    loaded set. No new hashing implementation - this is the same plain
    read-and-update-in-chunks pattern verify_file_hash() above already
    uses, just possibly repeated for more than one algorithm."""
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    hash_list_ids = req.get('hash_list_ids') or []
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400
    if not hash_list_ids:
        return jsonify({"success": False, "error": "No hash lists selected."}), 400

    hash_sets = load_hash_list_sets(hash_list_ids)
    if not hash_sets:
        return jsonify({"success": False, "error": "None of the selected hash lists could be loaded."}), 400

    needed_algos = {s["algorithm"] for s in hash_sets.values()}
    computed = {}
    try:
        for algo in needed_algos:
            hasher = hashlib.new(algo)
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            computed[algo] = hasher.hexdigest()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    matches = []
    for list_id, s in hash_sets.items():
        digest = computed.get(s["algorithm"])
        if digest and digest in s["hashes"]:
            matches.append({"list_id": list_id, "list_name": s["name"], "label": s.get("label", "known_bad"),
                             "algorithm": s["algorithm"], "hash": digest})

    log_chain_of_custody("hash_list_check", {"path": file_path, "lists_checked": len(hash_sets), "matches": len(matches)})
    return jsonify({"success": True, "file_name": os.path.basename(file_path), "computed_hashes": computed, "matches": matches})

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

@file_explorer_bp.route('/api/files/parse_registry', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def parse_registry():
    """Whole-directory scan for Windows Registry hives (NTUSER.DAT/SYSTEM/
    SOFTWARE) - same shape as parse_browser_artifacts() above, just a
    different candidate-file matcher/dispatcher pair."""
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    candidate_paths, truncated = find_registry_hive_files(target_dir)
    counts = {}
    files_parsed = 0
    for path in candidate_paths:
        filename = os.path.basename(path)
        records = parse_registry_hive_file(path, filename)
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": path}, records)

    log_chain_of_custody("registry_hives_parsed", {
        "directory": target_dir, "candidates_found": len(candidate_paths),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidate_paths), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@file_explorer_bp.route('/api/files/parse_evtx', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def parse_evtx():
    """Whole-directory scan for Windows Event Log (.evtx) files - same
    shape as parse_browser_artifacts()/parse_registry() above."""
    req = request.get_json() or {}
    target_dir = safe_path(req.get('path'))
    if not target_dir or not os.path.isdir(target_dir):
        return jsonify({"success": False, "error": "Directory not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    candidate_paths, truncated = find_evtx_files(target_dir)
    counts = {}
    files_parsed = 0
    for path in candidate_paths:
        records = parse_evtx_file(path)
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": path}, records)

    log_chain_of_custody("evtx_files_parsed", {
        "directory": target_dir, "candidates_found": len(candidate_paths),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidate_paths), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

SQLITE_QUERY_MAX_ROWS = 500  # a page's worth - real pagination via limit/offset, not a hard cap on total table size

def _sqlite_list_tables(conn):
    """Real table names + row counts - `table` here is always read back from
    sqlite_master itself (never client-supplied) before being interpolated
    into a COUNT(*) query, so this is safe despite the f-string: the only
    way a name reaches this loop is if SQLite itself already reports it as
    a real table in this exact file."""
    tables = []
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        try:
            count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.DatabaseError:
            count = None
        tables.append({"name": name, "row_count": count})
    return tables

@file_explorer_bp.route('/api/files/sqlite/tables', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def sqlite_list_tables():
    """Generic SQLite viewer (D1) - lists every real table in a selected
    .db/.sqlite/.sqlite3 file, read-only. No raw client-supplied SQL
    anywhere in this feature - see sqlite_query_table() below."""
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400
    try:
        conn = _open_sqlite_readonly(file_path)
        try:
            tables = _sqlite_list_tables(conn)
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        return jsonify({"success": False, "error": f"Not a readable SQLite database: {e}"}), 400
    return jsonify({"success": True, "tables": tables})

@file_explorer_bp.route('/api/files/sqlite/query', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def sqlite_query_table():
    """Paginated row browser for one table - `table` is validated against
    the file's own live sqlite_master listing before ever being
    interpolated into a query (never raw client-supplied SQL, and never a
    name that wasn't already confirmed to be a real table in this exact
    file), then only `limit`/`offset` (always parameterized) vary the
    actual SELECT."""
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    table = req.get('table', '')
    try:
        offset = max(0, int(req.get('offset', 0)))
    except (TypeError, ValueError):
        offset = 0
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400
    if not table:
        return jsonify({"success": False, "error": "No table specified."}), 400

    try:
        conn = _open_sqlite_readonly(file_path)
        try:
            real_tables = {t["name"] for t in _sqlite_list_tables(conn)}
            if table not in real_tables:
                return jsonify({"success": False, "error": "Not a real table in this database."}), 400
            cur = conn.execute(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (SQLITE_QUERY_MAX_ROWS, offset))
            columns = [d[0] for d in cur.description]
            rows = [list(r) for r in cur.fetchall()]
            total_rows = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        return jsonify({"success": False, "error": f"Query failed: {e}"}), 400

    return jsonify({
        "success": True, "columns": columns, "rows": rows, "total_rows": total_rows,
        "offset": offset, "returned": len(rows), "page_size": SQLITE_QUERY_MAX_ROWS,
    })

@file_explorer_bp.route('/api/files/parse_lnk', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def parse_lnk():
    """Single selected .lnk file - unlike Registry/EVTX above, an LNK is
    one artifact, not a container to scan for candidates, so this mirrors
    run_strings()'s single-file shape instead."""
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    records = parse_lnk_file(file_path, name_hint=os.path.basename(file_path))
    if case_folder and records:
        _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": file_path}, records)

    log_chain_of_custody("lnk_file_parsed", {"path": file_path, "parsed": bool(records)})
    return jsonify({
        "success": bool(records), "record": records[0] if records else None,
        "indexed": bool(case_folder and records),
        "error": None if records else "Could not parse this file as a valid .lnk shortcut.",
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

# --- Memory Forensics: Volatility3 analysis of an already-captured Windows
# RAM image. This app never acquires memory itself (there's no live target
# to capture from - it's a dead-box disk-imaging appliance); it only ever
# receives an already-captured image file (WinPmem/LiME/AVML/etc.), exactly
# like it already does for a logical acquisition.
#
# Windows-only for v1 (confirmed with the user) - Volatility3 needs an
# OS-specific symbol table to interpret a memory image's kernel structures,
# fetched live from the Volatility Foundation's public symbol server by
# default (no useful symbols ship bundled with the package at all -
# confirmed by inspecting the installed package's own symbols/ directory,
# which holds nothing but unrelated generic VMCS/CPU-architecture data).
# Windows is the only one of the three OSes where this online-fetch-based
# resolution reliably works out of the box; Linux/Mac need a symbol bank
# built from the *exact* source kernel, which a downstream station
# receiving just a raw memory dump essentially never has separately - not
# offered this pass rather than silently shipped as an unreliable surface.
#
# A curated plugin allowlist, not all ~170 real windows/linux/mac plugins -
# matches this project's own established curation philosophy elsewhere
# (e.g. scalpel.conf's curated signature set) - and is a real security
# boundary too: the plugin identifier is passed directly on the `vol`
# command line, so only ever a value from this fixed server-side map, never
# an arbitrary client-supplied string.
MEMORY_FORENSICS_PLUGINS = {
    "info": {"plugin": "windows.info.Info", "label": "OS & Kernel Info"},
    "pslist": {"plugin": "windows.pslist.PsList", "label": "Process List"},
    "pstree": {"plugin": "windows.pstree.PsTree", "label": "Process Tree"},
    "cmdline": {"plugin": "windows.cmdline.CmdLine", "label": "Process Command Lines"},
    "netscan": {"plugin": "windows.netscan.NetScan", "label": "Network Connections (netscan)"},
    "netstat": {"plugin": "windows.netstat.NetStat", "label": "Network Connections (netstat)"},
    "dlllist": {"plugin": "windows.dlllist.DllList", "label": "Loaded DLLs"},
    "filescan": {"plugin": "windows.filescan.FileScan", "label": "Open File Handles (filescan)"},
    "malfind": {"plugin": "windows.malfind.Malfind", "label": "Injected Code Detection (malfind)"},
    "svcscan": {"plugin": "windows.svcscan.SvcScan", "label": "Windows Services"},
    "handles": {"plugin": "windows.handles.Handles", "label": "Process Handles"},
}
MEMORY_FORENSICS_PLUGIN_TIMEOUT_SECONDS = 1800  # 30 min per plugin - some (handles/filescan) can run long on a busy system's memory image

def execution_worker_memory_forensics_scan(image_path, dest_dir, plugin_keys, source_ip=None, user=None):
    """Runs each requested Volatility3 plugin against image_path in turn,
    writing each plugin's own -r json output to a real file (mirrors Hash
    Manifest/Triage-Scan-report/Geolocation-KML's own "write a real result
    file, don't index every row into SQLite" pattern - Volatility3 output
    can run into the thousands of rows for filescan/handles, well past what
    the per-case parsed_artifacts index was ever sized for). A failing
    plugin (wrong OS, missing symbols, no internet) records its own real
    error and the scan continues with the next plugin, rather than aborting
    the whole run - surfaced to the examiner directly, never silently
    skipped."""
    global current_job
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    base_name = os.path.splitext(os.path.basename(image_path))[0]
    total = len(plugin_keys)
    completed = 0
    failed = 0

    try:
        update_job(format="memory_forensics_scan", status="Initializing...", progress_percent=0.0,
                   transferred_bytes=0, total_bytes=total)
        append_log(f"[*] Starting Volatility3 memory forensics scan of {image_path} ({total} plugin(s) requested)...")

        for key in plugin_keys:
            if snapshot_job()["status"] == "Stopped":
                append_log("[!] Stopped by user.")
                return

            info = MEMORY_FORENSICS_PLUGINS.get(key)
            if not info:
                append_log(f"[-] Skipping unrecognized plugin key '{key}'.")
                continue

            update_job(status=f"Running {info['label']}...", transferred_bytes=completed + failed)
            append_log(f"[*] Running {info['plugin']}...")

            try:
                res = subprocess.run(
                    [VOL3_BIN, "-f", image_path, "-r", "json", info["plugin"]],
                    capture_output=True, text=True, timeout=MEMORY_FORENSICS_PLUGIN_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                failed += 1
                append_log(f"[-] {info['plugin']} timed out after {MEMORY_FORENSICS_PLUGIN_TIMEOUT_SECONDS}s.")
                continue
            except FileNotFoundError:
                append_log("[-] volatility3 is not installed on this station. Check Settings > Service Controls & Diagnostics > Tool Versions.")
                update_job(status="Failed")
                return

            identity = {"source_type": "real_fs", "path": image_path, "name": os.path.basename(image_path)}
            tool_label = f"Volatility3 {info['plugin']}"

            if res.returncode != 0 or not res.stdout.strip():
                failed += 1
                err = (res.stderr or res.stdout or "Unknown volatility3 error.").strip()
                append_log(f"[-] {info['plugin']} failed: {err[:300]}")
                _record_analysis_result(dest_dir, identity, tool_label, "FAILED", err)
                continue

            out_path = os.path.join(dest_dir, f"{base_name}_vol3_{key}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(res.stdout)
            _auto_tag_case_artifact(dest_dir, out_path)

            try:
                rows = json.loads(res.stdout)
                row_count = len(rows) if isinstance(rows, list) else 0
            except (ValueError, TypeError):
                row_count = 0

            completed += 1
            summary = f"{row_count} row(s)"
            _record_analysis_result(dest_dir, identity, tool_label, summary, res.stdout[:20000])
            log_chain_of_custody("memory_forensics_scan", {
                "image_path": image_path, "plugin": info["plugin"], "row_count": row_count,
                "output_path": out_path,
            }, source_ip=source_ip, user=user)
            append_log(f"[+] {info['plugin']} complete - {summary} -> {out_path}")

        update_job(status="Completed Successfully" if failed == 0 or completed > 0 else "Failed",
                  progress_percent=100.0, transferred_bytes=completed + failed)
        append_log(f"[+] Scan complete: {completed} plugin(s) succeeded, {failed} failed.")
    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        update_job(active=False)

@file_explorer_bp.route('/api/files/memory/start_scan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def start_memory_forensics_scan():
    global current_job
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Another job is already running station-wide - wait for it to finish or stop it first."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    image_path = safe_path(req.get('path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    plugin_keys = [k for k in (req.get('plugins') or []) if k in MEMORY_FORENSICS_PLUGINS]

    if not image_path or not os.path.isfile(image_path):
        update_job(active=False)
        return jsonify({"success": False, "error": "Memory image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        update_job(active=False)
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400
    if not plugin_keys:
        update_job(active=False)
        return jsonify({"success": False, "error": "Select at least one plugin to run."}), 400

    update_job(
        format="memory_forensics_scan", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=len(plugin_keys), status="Initializing...",
        log=f"[*] Initializing Volatility3 memory forensics scan of {image_path}..."
    )

    # Captured now, in the real request thread - the worker runs in a
    # background daemon thread with no Flask request context (request/g
    # would raise RuntimeError if touched directly there).
    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
    requester_user = getattr(g, 'forensic_user', None)

    thread = threading.Thread(
        target=execution_worker_memory_forensics_scan,
        args=(image_path, dest_dir, plugin_keys, requester_ip, requester_user)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("memory_forensics_scan_start", {"image_path": image_path, "plugins": plugin_keys, "destination": dest_dir})
    return jsonify({"success": True, "message": "Memory forensics scan started."})

