"""Sleuth Kit (pytsk3) Image Browser: browse/search/timeline/preview/hex/
extract inside an acquired disk image, plus the whole-image analysis
actions that operate directly on an unmounted image (Geolocation KML
export, Hash Manifest, filesystem-aware Triage Scan, Binwalk, Strings,
ExifTool, and filesystem-aware deleted-file recovery). Everything here
only ever reads the image file - nothing writes to evidence except a
file the examiner explicitly extracts/recovers.

/api/case_index/* (a separate, closely-related but functionally distinct
concern - the per-case SQLite tag/analysis index, not image browsing
itself) lives in routes/case_index.py, not here - see that file's own
docstring for why it's split out despite sitting physically interleaved
with this block in the original app.py.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import io
import re
import time
import json
import base64
import hashlib
import tempfile
import subprocess
import threading

import pytsk3
from flask import Blueprint, jsonify, request, g

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, case_consolidated_path, classify_extension
from core.config import EVIDENCE_ROOT, ALLOWED_HASH_ALGOS
from core.jobs import job_lock, current_job, update_job, snapshot_job
from core.tsk_utils import (
    _tsk_walk, _tsk_resolve_filesystems, _tsk_entry_dict,
    _tsk_open_fs, _tsk_list_dir, _tsk_stream_file, _tsk_parse_inode,
    TSK_MAX_TIMELINE_ENTRIES,
)
from core.geo_utils import GEO_IMAGE_EXTENSIONS, _geo_points_from_exiftool_entries, _build_geo_kml
from core.case_index_db import (
    build_scan_patterns, resolve_scan_category_label,
    case_index_db_path, _case_index_connect, _record_analysis_result, _auto_tag_case_artifact,
)

image_browser_bp = Blueprint('image_browser', __name__)

# --- Sleuth Kit (pytsk3): Browse/Search/Timeline Filesystems Inside Acquired Images ---
# Everything here only ever reads the image file - nothing writes to evidence.
# Uses pytsk3 (Python bindings for libtsk) instead of shelling out to
# mmls/fls/icat: one in-process filesystem walk yields name + full MACB
# timestamps + size together, and lets recursive search / timeline / an
# in-memory preview work without spawning a subprocess per file or per
# directory the way the old CLI-wrapped version needed to. Verified against
# Debian trixie/aarch64 before adding - PyPI ships a prebuilt manylinux
# aarch64 wheel (no compile step, installs in ~10s) that was functionally
# tested against a real acquired image on the deployed Pi. See CLAUDE.md.
# TSK_DEFAULT_SECTOR_SIZE/TSK_READ_CHUNK_BYTES/TSK_MAX_WALK_DIRS/
# TSK_MAX_WALK_DEPTH/TSK_MAX_TIMELINE_ENTRIES now live in core/tsk_utils.py
# (imported at the top of this file) - see the Step 0 core/ extraction.
# TSK_MAX_SEARCH_RESULTS and everything below stays here - single-consumer,
# only this file's own image-browser routes use them.
TSK_MAX_SEARCH_RESULTS = 500
TSK_PREVIEW_TEXT_MAX_BYTES = 200_000
TSK_PREVIEW_IMAGE_MAX_BYTES = 8_000_000
TSK_PREVIEW_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
TSK_HEX_PREVIEW_MAX_BYTES = 64 * 1024  # matches _HEX_PREVIEW_MAX_BYTES's rationale for the real-fs route
TSK_PREVIEW_MIME = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
                     '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp'}

def detect_image_format_support():
    # pytsk3's PyPI wheels bundle libewf support at build time, unlike the
    # old mmls-based check (which could only string-match mmls's "-i list"
    # advertised formats, never confirm a real E01 would actually open) -
    # safe to report as always-on rather than re-probing per request.
    return {"raw": True, "ewf": True, "aff": hasattr(pytsk3, 'TSK_IMG_TYPE_AFF_AFF')}

@image_browser_bp.route('/api/image/format_support', methods=['GET'])
@requires_auth
def image_format_support():
    return jsonify({"success": True, "support": detect_image_format_support()})

# _tsk_parse_inode/_tsk_open_fs/_tsk_entry_dict/_tsk_list_dir/_tsk_walk/
# _tsk_stream_file now live in core/tsk_utils.py (imported at the top of
# this file) - see the Step 0 core/ extraction.

@image_browser_bp.route('/api/image/mmls', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_mmls():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    try:
        img = pytsk3.Img_Info(image_path)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not open image: {e}"}), 500

    partitions = []
    try:
        vol = pytsk3.Volume_Info(img)
        for part in vol:
            partitions.append({
                "slot": str(part.addr),
                "start_sector": part.start,
                "end_sector": part.start + part.len - 1,
                "length_sectors": part.len,
                "description": part.desc.decode('utf-8', errors='replace'),
            })
    except IOError:
        pass  # no partition table - normal for a single-filesystem image (phone/media card dd)

    return jsonify({"success": True, "partitions": partitions})

@image_browser_bp.route('/api/image/fls', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_fls():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')  # empty = root of the filesystem at this offset

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "offset must be a sector number."}), 400

    inode_num = None
    if inode:
        try:
            inode_num = _tsk_parse_inode(inode)
        except ValueError:
            return jsonify({"success": False, "error": "Invalid inode reference."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
        entries = _tsk_list_dir(fs, inode_num)
        return jsonify({"success": True, "entries": entries})
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not list directory: {e}"}), 500

@image_browser_bp.route('/api/image/extract', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_extract():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    out_name = req.get('output_name', '')
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "offset must be a sector number."}), 400
    if not inode:
        return jsonify({"success": False, "error": "Invalid inode reference."}), 400
    try:
        inode_num = _tsk_parse_inode(inode)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid inode reference."}), 400

    # Sanitize the requested filename (from an untrusted evidence filesystem)
    # to a bare basename before using it to build a destination path.
    safe_name = os.path.basename(out_name).strip() or f"extracted_{inode_num}"
    dest_file = os.path.join(dest_dir, safe_name)
    if not safe_path(dest_file):
        return jsonify({"success": False, "error": "Resulting destination path is outside the permitted evidence directory."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
        tsk_file = fs.open_meta(inode=inode_num)
        with open(dest_file, 'wb') as out:
            _tsk_stream_file(tsk_file, out.write)
    except Exception as e:
        try:
            os.remove(dest_file)
        except OSError:
            pass
        return jsonify({"success": False, "error": f"Extraction failed: {e}"}), 500

    log_chain_of_custody("image_file_extract", {"image_path": image_path, "inode": str(inode), "extracted_to": dest_file})
    return jsonify({"success": True, "message": f"Extracted to {dest_file}", "path": dest_file})

@image_browser_bp.route('/api/image/preview', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_preview():
    """In-memory preview of a file still inside the image - no extract-to-
    disk step first, unlike the old icat-then-browse-in-File-Explorer flow."""
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '')

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
        tsk_file = fs.open_meta(inode=inode_num)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not open file: {e}"}), 500

    size = tsk_file.info.meta.size if tsk_file.info.meta else 0
    ext = os.path.splitext(name_hint)[1].lower()

    try:
        if ext in TSK_PREVIEW_IMAGE_EXT:
            if size > TSK_PREVIEW_IMAGE_MAX_BYTES:
                return jsonify({"success": True, "kind": "too_large", "size": size})
            buf = io.BytesIO()
            _tsk_stream_file(tsk_file, buf.write, max_bytes=TSK_PREVIEW_IMAGE_MAX_BYTES)
            mime = TSK_PREVIEW_MIME.get(ext, 'application/octet-stream')
            return jsonify({"success": True, "kind": "image", "size": size, "mime": mime,
                             "data": base64.b64encode(buf.getvalue()).decode('ascii')})
        else:
            buf = io.BytesIO()
            truncated = size > TSK_PREVIEW_TEXT_MAX_BYTES
            _tsk_stream_file(tsk_file, buf.write, max_bytes=TSK_PREVIEW_TEXT_MAX_BYTES)
            return jsonify({"success": True, "kind": "text", "size": size, "truncated": truncated,
                             "text": buf.getvalue().decode('utf-8', errors='replace')})
    except Exception as e:
        return jsonify({"success": False, "error": f"Preview failed: {e}"}), 500

@image_browser_bp.route('/api/image/hex', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_hex():
    """Capped raw-byte read of a single in-image file for the Hex tab -
    counterpart to get_file_hex() above. Streams directly via
    _tsk_stream_file(max_bytes=...), no temp-file extraction needed since
    this doesn't shell out to anything (unlike Binwalk/Strings/ExifTool)."""
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
        tsk_file = fs.open_meta(inode=inode_num)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not open file: {e}"}), 500

    size = tsk_file.info.meta.size if tsk_file.info.meta else 0
    try:
        buf = io.BytesIO()
        _tsk_stream_file(tsk_file, buf.write, max_bytes=TSK_HEX_PREVIEW_MAX_BYTES)
        raw = buf.getvalue()
        return jsonify({
            "success": True, "data": base64.b64encode(raw).decode('ascii'),
            "bytes_read": len(raw), "total_size": size, "truncated": size > len(raw),
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500

@image_browser_bp.route('/api/image/search', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_search():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    query = (req.get('query') or '').strip().lower()
    start_inode = req.get('start_inode', '')

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not query:
        return jsonify({"success": False, "error": "A search query is required."}), 400
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "offset must be a sector number."}), 400

    start_inode_num = None
    if start_inode:
        try:
            start_inode_num = _tsk_parse_inode(start_inode)
        except ValueError:
            return jsonify({"success": False, "error": "Invalid inode reference."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not open filesystem: {e}"}), 500

    results = []
    truncated = False
    for entry, path in _tsk_walk(fs, start_inode_num):
        if query in entry['name'].lower():
            results.append({**entry, "path": path})
            if len(results) >= TSK_MAX_SEARCH_RESULTS:
                truncated = True
                break

    return jsonify({"success": True, "results": results, "truncated": truncated})

@image_browser_bp.route('/api/image/timeline', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_timeline():
    """MACB timeline built directly from a pytsk3 walk - no dependency on
    the external mactime perl script fls -m output traditionally needs."""
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    start_inode = req.get('start_inode', '')

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "offset must be a sector number."}), 400

    start_inode_num = None
    if start_inode:
        try:
            start_inode_num = _tsk_parse_inode(start_inode)
        except ValueError:
            return jsonify({"success": False, "error": "Invalid inode reference."}), 400

    try:
        fs = _tsk_open_fs(image_path, offset)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not open filesystem: {e}"}), 500

    events = []
    truncated = False
    for entry, path in _tsk_walk(fs, start_inode_num):
        if entry['is_virtual']:
            continue  # TSK's own $MBR/$FAT1/$FAT2/$OrphanFiles pseudo-entries, not real evidence
        for ts_field, label in (('mtime', 'M'), ('atime', 'A'), ('ctime', 'C'), ('crtime', 'B')):
            ts = entry.get(ts_field)
            if ts:
                events.append({"timestamp": ts, "activity": label, "path": path,
                                "name": entry['name'], "is_dir": entry['is_dir'], "deleted": entry['deleted']})
        if len(events) >= TSK_MAX_TIMELINE_ENTRIES:
            truncated = True
            break

    events.sort(key=lambda e: e['timestamp'], reverse=True)
    return jsonify({"success": True, "events": events[:TSK_MAX_TIMELINE_ENTRIES], "truncated": truncated})

# --- Geolocation KML export, scanned directly inside an acquired image ---
# Same GEO_IMAGE_EXTENSIONS/_geo_points_from_exiftool_entries()/_build_geo_kml()
# helpers the real-directory /api/files/geolocation_kml route above uses - only
# how each candidate photo's bytes reach exiftool differs. Unlike that route
# (one batch `exiftool -r` call for the whole directory), each candidate here
# needs its own subprocess call, since exiftool can't be pointed at a path
# inside an unmounted image.
#
# Originally a synchronous route (like every other File Explorer in-image
# tool), converted to a real background job for the same reason Triage Scan
# was: up to IMAGE_GEO_MAX_FILES candidates each cost a real exiftool
# subprocess spawn, which can genuinely take a while, and a silent multi-
# minute browser hang is worse than a trackable job with a Stop button. Same
# shared current_job system, same one-global-slot-at-a-time rule.
IMAGE_GEO_MAX_FILES = 300
IMAGE_GEO_MAX_FILE_BYTES = 32 * 1024 * 1024  # generous for JPEG/HEIC, skips oversized RAW/DNG

def execution_worker_image_geolocation_kml(image_path, dest_dir, source_ip=None, user=None):
    """Deliberately excludes deleted files, extending _tsk_walk()'s own
    deleted-directory precedent: a deleted file's data blocks may already be
    partially overwritten by something unrelated on a live evidence
    filesystem, and presenting whatever garbage EXIF happens to parse out of
    that as real GPS evidence would be a forensic-accuracy problem, not just
    a missed opportunity."""
    global current_job
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    try:
        filesystems = _tsk_resolve_filesystems(image_path)
        if not filesystems:
            append_log("[-] No recognized filesystem found in this image.")
            update_job(status="Failed")
            return

        update_job(format="image_geolocation_kml", status="Finding candidate photos...", progress_percent=0.0,
                   transferred_bytes=0, total_bytes=0)
        append_log(f"[*] Scanning {image_path} for GPS-tagged photos...")

        # Collect candidates first (cheap - just directory-entry metadata),
        # which also gives a real total for progress tracking below, so the
        # per-file cap applies before any actual file reads/subprocess calls
        # happen.
        candidates = []
        for fsinfo in filesystems:
            if snapshot_job()["status"] == "Stopped":
                break
            try:
                fs = _tsk_open_fs(image_path, fsinfo['offset'])
            except Exception:
                continue
            for entry, path in _tsk_walk(fs):
                if entry['is_dir'] or entry['deleted']:
                    continue
                ext = os.path.splitext(entry['name'])[1].lower().lstrip('.')
                if ext not in GEO_IMAGE_EXTENSIONS:
                    continue
                candidates.append((fs, entry, path))
                if len(candidates) >= IMAGE_GEO_MAX_FILES:
                    break
            if len(candidates) >= IMAGE_GEO_MAX_FILES:
                break
        truncated = len(candidates) >= IMAGE_GEO_MAX_FILES

        update_job(status="Reading EXIF from candidate photos...", total_bytes=len(candidates))
        append_log(f"[*] Found {len(candidates)} candidate photo(s) to check (capped at {IMAGE_GEO_MAX_FILES}).")

        exif_entries = []
        skipped_too_large = 0
        files_checked = 0
        last_update_time = time.time()
        for fs, entry, path in candidates:
            if snapshot_job()["status"] == "Stopped":
                append_log("[!] Scan stopped by user.")
                break
            if entry['size'] and entry['size'] > IMAGE_GEO_MAX_FILE_BYTES:
                skipped_too_large += 1
                files_checked += 1
                continue
            suffix = os.path.splitext(entry['name'])[1]
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
            os.close(tmp_fd)
            try:
                tsk_file = fs.open_meta(inode=_tsk_parse_inode(entry['inode']))
                with open(tmp_path, 'wb') as out:
                    _tsk_stream_file(tsk_file, out.write, max_bytes=IMAGE_GEO_MAX_FILE_BYTES)
                res = subprocess.run(
                    ['exiftool', '-j', '-n', '-GPSLatitude', '-GPSLongitude', '-GPSAltitude', '-DateTimeOriginal', tmp_path],
                    capture_output=True, text=True, timeout=15
                )
                if res.returncode == 0 and res.stdout.strip():
                    parsed = json.loads(res.stdout)
                    if parsed:
                        exif_entry = parsed[0]
                        exif_entry['FileName'] = entry['name']
                        exif_entry['Directory'] = path  # in-image path, for the KML description text
                        exif_entries.append(exif_entry)
            except Exception:
                pass  # one unreadable/corrupt candidate shouldn't fail the whole scan
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            files_checked += 1
            if time.time() - last_update_time > 0.5:
                updates = {"transferred_bytes": files_checked}
                if len(candidates) > 0:
                    updates["progress_percent"] = round((files_checked / len(candidates)) * 100, 1)
                update_job(**updates)
                last_update_time = time.time()

        update_job(transferred_bytes=files_checked)

        points = _geo_points_from_exiftool_entries(exif_entries)
        image_base = os.path.splitext(os.path.basename(image_path))[0]
        kml_doc = _build_geo_kml(points, f"{image_base} - Geolocation Export")

        kml_path = None
        if kml_doc:
            kml_path = os.path.join(dest_dir, f"{image_base}_geolocation_export.kml")
            with open(kml_path, 'w', encoding='utf-8') as f:
                f.write(kml_doc)
            _auto_tag_case_artifact(dest_dir, kml_path)
            append_log(f"[+] {len(points)} GPS-tagged point(s) found -> {kml_path}")
        else:
            append_log("[*] No GPS-tagged photos found - no KML file was written.")

        if snapshot_job()["status"] == "Stopped":
            pass  # already logged above
        else:
            update_job(status="Completed Successfully", progress_percent=100.0)

        log_chain_of_custody("geolocation_kml_export_image", {
            "image_path": image_path, "files_scanned": len(candidates), "points_found": len(points),
            "files_skipped_too_large": skipped_too_large, "truncated": truncated
        }, source_ip=source_ip, user=user)
    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        update_job(active=False)

@image_browser_bp.route('/api/image/start_geolocation_kml', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def start_image_geolocation_kml():
    global current_job
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Another job is already running station-wide - wait for it to finish or stop it first."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path or not os.path.isfile(image_path):
        update_job(active=False)
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        update_job(active=False)
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    update_job(
        format="image_geolocation_kml", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing geolocation scan of {image_path}..."
    )

    # Captured now, in the real request thread - execution_worker_image_geolocation_kml()
    # runs in a background daemon thread with no Flask request context, where
    # request/g would raise RuntimeError if touched directly (the same
    # gotcha the image triage scan job's own log_chain_of_custody() call hit
    # once already, before it was fixed the same way as network config's
    # delayed-revert thread).
    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
    requester_user = getattr(g, 'forensic_user', None)

    thread = threading.Thread(
        target=execution_worker_image_geolocation_kml,
        args=(image_path, dest_dir, requester_ip, requester_user)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("geolocation_kml_export_image_start", {"image_path": image_path, "destination": dest_dir})
    return jsonify({"success": True, "message": "Geolocation scan started."})

# --- Recursive hash manifest, computed directly inside an acquired image ---
# Unlike the geolocation route above (which needs a real file for exiftool to
# open), hashing needs nothing but bytes - _tsk_stream_file() can feed a
# hashlib object's .update() directly as its write_fn, so this needs no
# subprocess calls and no temp files at all, and isn't limited to a specific
# file extension the way geolocation is (matches the real-directory hashdeep
# route's own unrestricted scope - every file gets hashed, not just photos).
IMAGE_HASH_MAX_FILES = 5000
IMAGE_HASH_MAX_SECONDS = 300

@image_browser_bp.route('/api/image/hash_manifest', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_hash_manifest():
    """Recursively hashes every real, non-deleted file inside an acquired
    image without extracting anything to disk first. Deleted files are
    excluded for the same reason the geolocation/timeline routes exclude
    them - a deleted file's data blocks may already be partially overwritten
    on a live evidence filesystem, and a hash computed over that isn't a
    trustworthy fingerprint of the original file, so including it in a
    manifest meant to prove integrity would be actively misleading rather
    than just incomplete."""
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    algo = req.get('algorithm', 'sha256').lower()

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400
    if algo not in ALLOWED_HASH_ALGOS:
        return jsonify({"success": False, "error": f"Unsupported algorithm '{algo}'. Use one of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    start_time = time.time()
    rows = []  # (hash_hex, size, in-image path)
    files_hashed = 0
    files_errored = 0
    truncated = False
    for fsinfo in filesystems:
        try:
            fs = _tsk_open_fs(image_path, fsinfo['offset'])
        except Exception:
            continue
        for entry, path in _tsk_walk(fs):
            if entry['is_dir'] or entry['deleted'] or entry['is_virtual']:
                continue
            if files_hashed >= IMAGE_HASH_MAX_FILES or (time.time() - start_time) > IMAGE_HASH_MAX_SECONDS:
                truncated = True
                break
            try:
                tsk_file = fs.open_meta(inode=_tsk_parse_inode(entry['inode']))
                h = hashlib.new(algo)
                size = _tsk_stream_file(tsk_file, h.update)
                rows.append((h.hexdigest(), size, path))
                files_hashed += 1
            except Exception:
                files_errored += 1
                continue  # one unreadable/corrupt file shouldn't fail the whole manifest
        if truncated:
            break

    image_base = os.path.splitext(os.path.basename(image_path))[0]
    manifest_path = os.path.join(dest_dir, f"{image_base}_hash_manifest_{algo}.txt")
    lines = [
        "# Pi Forensics Suite - In-Image File Hash Manifest",
        f"# Image: {image_path}",
        f"# Algorithm: {algo.upper()}",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Files hashed: {files_hashed}" + (f" (capped - more files remained unscanned)" if truncated else ""),
        f"# Files skipped (unreadable): {files_errored}",
        "# Deleted files are excluded - see route documentation for why.",
        "#",
        f"# {'hash'.ljust(len(rows[0][0]) if rows else 64)}  size(bytes)  path",
    ]
    for digest, size, path in rows:
        lines.append(f"{digest}  {size}  {path}")
    try:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to write manifest file: {e}"}), 500
    _auto_tag_case_artifact(dest_dir, manifest_path)

    log_chain_of_custody("hash_manifest_export_image", {
        "image_path": image_path, "algorithm": algo, "files_hashed": files_hashed,
        "files_errored": files_errored, "truncated": truncated
    })
    return jsonify({
        "success": True, "manifest_path": manifest_path, "files_hashed": files_hashed,
        "files_errored": files_errored, "truncated": truncated
    })

# --- Filesystem-aware triage scan, directly against an acquired image ---
# Unlike quick_triage_scan() above (a single-file, 32MB-capped preview) and
# execution_worker_triage_scan() (the background device/file-level job that
# scans one continuous byte stream with no filesystem awareness at all),
# this walks the image's real directory structure and scans each file's own
# content, so results come back tied to real in-image paths. Same
# TRIAGE_PATTERNS, same regex-matching logic - not a third scanning
# implementation, just a third entry point into it. Long-running (walks
# potentially thousands of files), so unlike every other File Explorer
# in-image tool (which are synchronous, capped by a time/count budget) this
# one goes through the app's single shared current_job system for real
# progress tracking and a Stop button, the same way Acquisition/Recovery/
# Mobile jobs already do - it competes for that same one global job slot,
# which is correct: only one long-running operation should run at a time
# station-wide, regardless of which tab started it.
IMAGE_TRIAGE_MAX_FILES = 5000  # matches IMAGE_HASH_MAX_FILES's precedent
IMAGE_TRIAGE_MAX_FILE_BYTES = 4 * 1024 * 1024  # 4 MB per file - smaller than quick_triage_scan()'s single-file 32MB cap, since this walks many files
IMAGE_TRIAGE_MAX_MATCHES_PER_CATEGORY = 2000  # between quick_triage_scan()'s 500 (one file) and the background job's 50000 (one whole device)

def execution_worker_image_triage_scan(image_path, dest_dir, source_ip=None, user=None, keyword_list_ids=None):
    global current_job
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    patterns = build_scan_patterns(keyword_list_ids)
    results = {name: [] for name in patterns}       # list of (path, value) tuples, in match order
    seen = {name: set() for name in patterns}       # dedupe by (path, value)
    truncated = {name: False for name in patterns}
    files_scanned = 0
    files_errored = 0
    indexed_files_count = 0
    walk_truncated = False

    # Per-case analysis index (SQLite) - only populated if dest_dir is a real
    # active case folder, matching this app's "case selection optional,
    # nothing breaks if none is active" convention elsewhere. index_conn
    # stays None otherwise, and every index_conn-gated block below is a
    # no-op in that case - the flat .txt report (below) is written either way.
    index_conn = None
    index_rows_buf = []
    hit_rows_buf = []
    indexed_at = time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        if case_consolidated_path(dest_dir):
            index_db_path = case_index_db_path(dest_dir)
            if index_db_path:
                index_conn = _case_index_connect(index_db_path)
                # Re-scan safety: replace this image's prior rows rather than
                # duplicating them - other images' rows in the same case DB
                # (a case-wide index) are untouched.
                index_conn.execute("DELETE FROM indexed_files WHERE image_path=?", (image_path,))
                index_conn.execute("DELETE FROM triage_hits WHERE image_path=?", (image_path,))
                index_conn.commit()
        filesystems = _tsk_resolve_filesystems(image_path)
        if not filesystems:
            append_log("[-] No recognized filesystem found in this image.")
            update_job(status="Failed")
            return

        update_job(format="image_triage_scan", status="Counting files...", progress_percent=0.0,
                   transferred_bytes=0, total_bytes=0)
        append_log(f"[*] Scanning {image_path} for structured data (emails, URLs, IPs, card-like numbers, phone numbers), file by file...")

        # A cheap first pass (directory-entry metadata only, no file content
        # read) so the real scanning pass below can report a true
        # percentage instead of an indeterminate spinner.
        total_files_estimate = 0
        for fsinfo in filesystems:
            try:
                fs = _tsk_open_fs(image_path, fsinfo['offset'])
            except Exception:
                continue
            for entry, _ in _tsk_walk(fs):
                # Deleted (but not virtual) entries are now counted too - they
                # get indexed for the Deleted Files category even though their
                # content is never read/regex-scanned below.
                if not entry['is_dir'] and not entry['is_virtual']:
                    total_files_estimate += 1
                if total_files_estimate >= IMAGE_TRIAGE_MAX_FILES:
                    break
            if total_files_estimate >= IMAGE_TRIAGE_MAX_FILES:
                break

        update_job(status="Scanning files for structured data...", total_bytes=total_files_estimate)
        append_log(f"[*] Found {total_files_estimate} file(s) to scan (capped at {IMAGE_TRIAGE_MAX_FILES}).")

        last_update_time = time.time()
        for fsinfo in filesystems:
            if snapshot_job()["status"] == "Stopped":
                break
            try:
                fs = _tsk_open_fs(image_path, fsinfo['offset'])
            except Exception:
                continue
            for entry, path in _tsk_walk(fs):
                if snapshot_job()["status"] == "Stopped":
                    append_log("[!] Scan stopped by user.")
                    break
                if entry['is_dir'] or entry['is_virtual']:
                    continue
                if files_scanned >= IMAGE_TRIAGE_MAX_FILES:
                    walk_truncated = True
                    break

                # Index this entry's metadata regardless of deletion status -
                # "Deleted Files" needs real data too. Only content-scanning
                # (below) still skips deleted entries - their data blocks may
                # already be partially overwritten, same reasoning as before.
                if index_conn is not None:
                    category, ext = classify_extension(entry['name'])
                    index_rows_buf.append((
                        image_path, fsinfo['offset'], entry['inode'], path, entry['name'],
                        ext, category, entry['size'], int(entry['deleted']), int(entry['is_virtual']),
                        entry['mtime'], entry['atime'], entry['ctime'], entry['crtime'], indexed_at,
                    ))
                    indexed_files_count += 1

                if entry['deleted']:
                    files_scanned += 1
                else:
                    try:
                        tsk_file = fs.open_meta(inode=_tsk_parse_inode(entry['inode']))
                        buf = io.BytesIO()
                        _tsk_stream_file(tsk_file, buf.write, max_bytes=IMAGE_TRIAGE_MAX_FILE_BYTES)
                        data = buf.getvalue()
                        for name, pattern in patterns.items():
                            if truncated[name]:
                                continue
                            for m in pattern.finditer(data):
                                val = m.group(0)
                                if len(val) <= 4:  # skip trivial/near-empty matches
                                    continue
                                key = (path, val)
                                if key in seen[name]:
                                    continue
                                seen[name].add(key)
                                results[name].append((path, val))
                                if index_conn is not None:
                                    hit_rows_buf.append((
                                        'image', image_path, fsinfo['offset'], entry['inode'], path,
                                        name, val.decode('utf-8', errors='replace'), indexed_at,
                                    ))
                                if len(results[name]) >= IMAGE_TRIAGE_MAX_MATCHES_PER_CATEGORY:
                                    truncated[name] = True
                                    append_log(f"[!] {resolve_scan_category_label(name)}: hit the {IMAGE_TRIAGE_MAX_MATCHES_PER_CATEGORY}-match cap, no longer collecting new ones.")
                                    break
                        files_scanned += 1
                    except Exception:
                        files_errored += 1

                if index_conn is not None and (len(index_rows_buf) >= 200 or len(hit_rows_buf) >= 200):
                    if index_rows_buf:
                        index_conn.executemany(
                            "INSERT INTO indexed_files (image_path, fs_offset, inode, path, name, extension, category, size, deleted, is_virtual, mtime, atime, ctime, crtime, indexed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            index_rows_buf)
                        index_rows_buf = []
                    if hit_rows_buf:
                        index_conn.executemany(
                            "INSERT INTO triage_hits (source_type, image_path, fs_offset, inode, path, category, value, found_at) VALUES (?,?,?,?,?,?,?,?)",
                            hit_rows_buf)
                        hit_rows_buf = []
                    index_conn.commit()

                if time.time() - last_update_time > 0.5:
                    updates = {"transferred_bytes": files_scanned}
                    if total_files_estimate > 0:
                        updates["progress_percent"] = round((files_scanned / total_files_estimate) * 100, 1)
                    update_job(**updates)
                    last_update_time = time.time()
            if walk_truncated or snapshot_job()["status"] == "Stopped":
                break

        if index_conn is not None:
            if index_rows_buf:
                index_conn.executemany(
                    "INSERT INTO indexed_files (image_path, fs_offset, inode, path, name, extension, category, size, deleted, is_virtual, mtime, atime, ctime, crtime, indexed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    index_rows_buf)
            if hit_rows_buf:
                index_conn.executemany(
                    "INSERT INTO triage_hits (source_type, image_path, fs_offset, inode, path, category, value, found_at) VALUES (?,?,?,?,?,?,?,?)",
                    hit_rows_buf)
            index_conn.commit()

        update_job(transferred_bytes=files_scanned)

        image_base = os.path.splitext(os.path.basename(image_path))[0]
        report_path = os.path.join(dest_dir, f"{image_base}_triage_scan_report.txt")
        lines = [
            "# Pi Forensics Suite - Filesystem-Aware Triage Scan Report",
            f"# Image: {image_path}",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Files scanned: {files_scanned}" + (" (capped - more files remained unscanned)" if walk_truncated else ""),
            f"# Files skipped (unreadable): {files_errored}",
            "# Deleted files are excluded - their data blocks may already be partially overwritten.",
            "",
        ]
        total_hits = 0
        for name in patterns:
            label = resolve_scan_category_label(name)
            matches = results[name]
            total_hits += len(matches)
            cap_note = " (capped)" if truncated[name] else ""
            lines.append(f"## {label} ({len(matches)} found{cap_note})")
            for path, val in matches:
                lines.append(f"{path}\t{val.decode('utf-8', errors='replace')}")
            lines.append("")

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines).strip() + "\n")

        if snapshot_job()["status"] == "Stopped":
            pass  # already logged above
        else:
            update_job(status="Completed Successfully", progress_percent=100.0)
            append_log(f"[+] Triage scan completed. {total_hits} total match(es) across {files_scanned} file(s) -> {report_path}")

        log_chain_of_custody("image_triage_scan_complete", {
            "image_path": image_path, "files_scanned": files_scanned,
            "files_errored": files_errored, "total_hits": total_hits, "report_path": report_path,
            "indexed_files_count": indexed_files_count,
        }, source_ip=source_ip, user=user)
    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        if index_conn is not None:
            try:
                index_conn.close()
            except Exception:
                pass
        update_job(active=False)

@image_browser_bp.route('/api/image/start_triage_scan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def start_image_triage_scan():
    global current_job
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Another job is already running station-wide - wait for it to finish or stop it first."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    keyword_list_ids = req.get('keyword_list_ids') or []

    if not image_path or not os.path.isfile(image_path):
        update_job(active=False)
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        update_job(active=False)
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    update_job(
        format="image_triage_scan", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing filesystem-aware triage scan of {image_path}..."
    )

    # Captured now, in the real request thread - the worker runs in a
    # background daemon thread with no Flask request context, where
    # request/g would raise RuntimeError if touched directly (the same
    # gotcha network config's delayed-revert thread already hit once).
    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
    requester_user = getattr(g, 'forensic_user', None)

    thread = threading.Thread(
        target=execution_worker_image_triage_scan,
        args=(image_path, dest_dir, requester_ip, requester_user, keyword_list_ids)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("image_triage_scan_start", {"image_path": image_path, "destination": dest_dir})
    return jsonify({"success": True, "message": "Filesystem-aware triage scan started."})
# --- Binwalk / Strings, run directly against a single selected in-image file ---
# Unlike the whole-image geolocation/hash-manifest routes above, these operate on
# one already-selected file (matching how they already work in the real-filesystem
# context menu) - no walk needed, just read that one file out of the image.

def _tsk_extract_to_temp(fs, inode_num, suffix=''):
    """Reads a file out of an image into a short-lived temp file - binwalk/
    strings (like exiftool for geolocation) need a real file path on disk,
    not raw bytes. Caller must remove the returned path when done."""
    tsk_file = fs.open_meta(inode=inode_num)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(tmp_fd)
    with open(tmp_path, 'wb') as out:
        _tsk_stream_file(tsk_file, out.write)
    return tmp_path

@image_browser_bp.route('/api/image/binwalk', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_binwalk():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'
    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix=os.path.splitext(name_hint)[1])
        res = subprocess.run(['binwalk', tmp_path], capture_output=True, text=True, timeout=120)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        output = output.replace(tmp_path, name_hint)  # don't leak the temp path to the examiner
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "binwalk timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not scan file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    sig_count = len(re.findall(r'^\d+\s', output, re.MULTILINE))
    summary = f"{sig_count} signature(s) found" if sig_count else "No signatures found"
    log_chain_of_custody("binwalk_scan_image", {"image_path": image_path, "inode": str(inode), "name": name_hint})
    _record_analysis_result(case_folder, {"source_type": "image", "image_path": image_path, "fs_offset": offset,
                                           "inode": str(inode), "path": req.get('path'), "name": name_hint},
                             "Binwalk", summary, output)
    return jsonify({"success": True, "file_name": name_hint, "output": output})

@image_browser_bp.route('/api/image/strings', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_strings():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'
    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix=os.path.splitext(name_hint)[1])
        res = subprocess.run(['strings', '-n', '6', tmp_path], capture_output=True, text=True, timeout=60)
        lines = res.stdout.splitlines()
        truncated = len(lines) > 1000
        output = "\n".join(lines[:1000])
        if truncated:
            output += f"\n\n[... truncated, {len(lines) - 1000} more lines not shown ...]"
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "strings timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not scan file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    summary = f"{min(len(lines), 1000)} line(s) extracted" + (" (capped)" if truncated else "")
    _record_analysis_result(case_folder, {"source_type": "image", "image_path": image_path, "fs_offset": offset,
                                           "inode": str(inode), "path": req.get('path'), "name": name_hint},
                             "Strings", summary, output)
    log_chain_of_custody("strings_scan_image", {"image_path": image_path, "inode": str(inode), "name": name_hint})
    return jsonify({"success": True, "file_name": name_hint, "output": output or "[no printable strings found]"})

@image_browser_bp.route('/api/image/exif', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_exif():
    """Embedded metadata (EXIF/GPS/camera make-model, etc.) for a single
    selected in-image file - the counterpart to /api/files/exif for the
    real filesystem. Same extract-to-temp-then-run pattern as image_binwalk/
    image_strings above, since exiftool needs a real path on disk."""
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix=os.path.splitext(name_hint)[1])
        res = subprocess.run(['exiftool', '-j', '-a', '-G', tmp_path], capture_output=True, text=True, timeout=30)
        if res.returncode != 0 and not res.stdout.strip():
            return jsonify({"success": False, "error": res.stderr.strip() or "exiftool failed with no output."}), 500
        parsed = json.loads(res.stdout)
        metadata = parsed[0] if parsed else {}
        # exiftool reports the temp file's own name/path back as separate
        # File:FileName / File:Directory fields (not just embedded in
        # SourceFile) - correct both to the real in-image name so the
        # examiner never sees a meaningless tmp_xxxxx.jpg / /tmp instead of
        # the evidence file's actual identity.
        metadata.pop('SourceFile', None)
        if 'File:FileName' in metadata:
            metadata['File:FileName'] = name_hint
        metadata.pop('File:Directory', None)
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "exiftool timed out."}), 500
    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Could not parse exiftool output."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read metadata: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    log_chain_of_custody("exif_scan_image", {"image_path": image_path, "inode": str(inode), "name": name_hint})
    return jsonify({"success": True, "file_name": name_hint, "metadata": metadata})

# --- Filesystem-aware deleted file recovery, directly inside an acquired image ---
# Unlike PhotoRec/foremost/scalpel/extundelete (raw signature-based carving, no
# filesystem awareness - recovered files get generic renamed filenames with zero
# path context), this walks the filesystem's own directory structure the same way
# every other in-image tool above does, and recovers files that are still
# referenced by an intact (non-deleted) directory entry - preserving the file's
# real original name and path. Same concept as Sleuth Kit's own tsk_recover
# utility, built from the exact walk infrastructure the other four in-image
# tools already proved out.
#
# Recovery odds are NOT uniform across filesystem types - disclosed here and in
# the UI rather than oversold: NTFS keeps a deleted file's MFT entry (name,
# size, data runs) largely intact until that MFT slot is reused, so recovery is
# often good. FAT similarly retains the directory entry and starting cluster for
# a recently-deleted file. ext-family filesystems are the weak case - the kernel
# typically clears the inode's block pointers on deletion, so even though
# _tsk_walk can still see the directory entry and filename, the actual file
# data is very often already gone by the time an examiner gets to it. This tool
# surfaces whatever TSK can read regardless of filesystem type; it doesn't and
# can't claim recovery will succeed evenly across all of them.
#
# This is also the first in-image tool that writes real, potentially large file
# data to disk rather than a small text/manifest artifact, so it's capped more
# conservatively than the others: a hard file-count ceiling, a per-file size
# ceiling, and a running total-bytes budget checked *before* each write starts
# (a single oversized declared-size entry is skipped outright rather than
# writing a truncated, misleading partial file).
IMAGE_RECOVER_MAX_FILES = 1000
IMAGE_RECOVER_MAX_FILE_BYTES = 500 * 1024 * 1024
IMAGE_RECOVER_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
IMAGE_RECOVER_MAX_SECONDS = 600

@image_browser_bp.route('/api/image/recover_deleted', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_recover_deleted():
    req = request.get_json() or {}
    image_path = safe_path(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path or not os.path.isfile(image_path):
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    image_base = os.path.splitext(os.path.basename(image_path))[0]
    output_root = os.path.join(dest_dir, f"{image_base}_recovered_deleted")
    multi_fs = len(filesystems) > 1

    start_time = time.time()
    files_recovered = 0
    files_skipped_too_large = 0
    files_skipped_empty = 0
    files_errored = 0
    total_bytes = 0
    truncated = False

    for fsinfo in filesystems:
        try:
            fs = _tsk_open_fs(image_path, fsinfo['offset'])
        except Exception:
            continue
        # Only used to keep multiple filesystems' recovered output from colliding -
        # sanitized the same conservative way sanitize_case_slug() treats untrusted
        # strings elsewhere in this file, since the label comes from the volume
        # table, not something this app generated itself.
        fs_subdir = re.sub(r'[^A-Za-z0-9 ._-]+', '_', fsinfo['label']).strip() or 'filesystem' if multi_fs else None

        for entry, path in _tsk_walk(fs):
            if entry['is_dir'] or not entry['deleted'] or entry['is_virtual']:
                continue
            if files_recovered >= IMAGE_RECOVER_MAX_FILES or (time.time() - start_time) > IMAGE_RECOVER_MAX_SECONDS:
                truncated = True
                break
            size = entry['size'] or 0
            if size <= 0:
                files_skipped_empty += 1
                continue
            if size > IMAGE_RECOVER_MAX_FILE_BYTES or total_bytes + size > IMAGE_RECOVER_MAX_TOTAL_BYTES:
                files_skipped_too_large += 1
                continue

            rel_path = path.lstrip('/')
            dest_file = os.path.join(output_root, fs_subdir, rel_path) if fs_subdir else os.path.join(output_root, rel_path)
            if not safe_path(dest_file):
                files_errored += 1
                continue

            try:
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                tsk_file = fs.open_meta(inode=_tsk_parse_inode(entry['inode']))
                with open(dest_file, 'wb') as out:
                    written = _tsk_stream_file(tsk_file, out.write, max_bytes=IMAGE_RECOVER_MAX_FILE_BYTES)
                if written == 0:
                    os.remove(dest_file)
                    files_skipped_empty += 1
                    continue
                total_bytes += written
                files_recovered += 1
            except Exception:
                files_errored += 1
                try:
                    if os.path.exists(dest_file):
                        os.remove(dest_file)
                except OSError:
                    pass
                continue
        if truncated:
            break

    log_chain_of_custody("recover_deleted_files_image", {
        "image_path": image_path, "output_dir": output_root, "files_recovered": files_recovered,
        "total_bytes": total_bytes, "files_skipped_too_large": files_skipped_too_large,
        "files_skipped_empty": files_skipped_empty, "files_errored": files_errored, "truncated": truncated
    })
    return jsonify({
        "success": True, "output_dir": output_root if files_recovered else None,
        "files_recovered": files_recovered, "total_bytes": total_bytes,
        "files_skipped_too_large": files_skipped_too_large, "files_skipped_empty": files_skipped_empty,
        "files_errored": files_errored, "truncated": truncated
    })
