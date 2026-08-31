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
import glob
import time
import json
import base64
import hashlib
import shutil
import sqlite3
import tempfile
import subprocess
import threading

import pytsk3
from flask import Blueprint, jsonify, request, g

from core.auth import requires_auth, requires_permission
from core.paths import (
    safe_path, log_chain_of_custody, case_consolidated_path, classify_extension,
    is_valid_block_device_or_partition,
)
from core.config import EVIDENCE_ROOT, ALLOWED_HASH_ALGOS, load_hash_list_sets, load_yara_ruleset_sources, get_url_lists, load_url_list_sets
import yara
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job, _SERVICE_ACCOUNT_NAME,
    begin_suppress_active_false, end_suppress_active_false,
)
from core.tsk_utils import (
    _tsk_walk, _tsk_resolve_filesystems, _tsk_entry_dict,
    _tsk_open_fs, _tsk_list_dir, _tsk_stream_file, _tsk_parse_inode,
    TSK_MAX_TIMELINE_ENTRIES,
)
from core.geo_utils import GEO_IMAGE_EXTENSIONS, _geo_points_from_exiftool_entries, _build_geo_kml
from core.decrypted_sources import get_decrypted_source_kind
from core.case_index_db import (
    build_scan_patterns, resolve_scan_category_label,
    case_index_db_path, _case_index_connect, _record_analysis_result, _auto_tag_case_artifact,
    _record_parsed_artifacts,
)
from core.browser_artifacts import (
    BROWSER_ARTIFACT_FILENAMES, BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES, parse_browser_profile_file,
    _open_sqlite_readonly,
)
from core.registry_utils import REGISTRY_HIVE_FILENAMES, REGISTRY_SCAN_MAX_CANDIDATES, parse_registry_hive_file
from core.crypto_artifacts import (
    CRYPTO_WALLET_MAX_CANDIDATES, parse_crypto_wallet_file, is_crypto_wallet_candidate,
)
from core.mobile_artifacts import find_mobile_backup_manifest, parse_mobile_backup_manifest
from core.evtx_utils import EVTX_EXTENSION, EVTX_SCAN_MAX_CANDIDATES, parse_evtx_file
from core.prefetch_utils import PREFETCH_EXTENSION, PREFETCH_SCAN_MAX_CANDIDATES, parse_prefetch_file
from core.recyclebin_utils import RECYCLEBIN_SCAN_MAX_CANDIDATES, parse_recyclebin_file
from core.mft_utils import analyze_mft_file
from core.usnjrnl_utils import parse_usnjrnl_stream
from core.linux_artifacts import LINUX_ARTIFACT_IMAGE_MATCHERS, LINUX_ARTIFACT_DEFAULT_TYPES

LINUX_ARTIFACT_IMAGE_MAX_CANDIDATES = 100  # combined across whichever types are requested per run
from core.lnk_utils import parse_lnk_file

image_browser_bp = Blueprint('image_browser', __name__)

# --- Live Device Preview: browse a raw block device read-only, before it's
# ever acquired (FTK Imager's "Preview" feature). The unprivileged gunicorn
# worker this app runs as has no reliable read access to a block device
# node today - confirmed there's no existing privilege-bridging mechanism
# for it (the BitLocker dislocker mount does NOT solve this: its decrypted
# file is only ever read by another *sudo'd* tool, never by this
# unprivileged process itself). The bridge here is deliberately the
# smallest possible one: a temporary, reversible ACL read grant on exactly
# one device node (`sudo setfacl -m u:<service_user>:r <device>`), revoked
# again on exit or by the idle-sweep below - never a write grant, and the
# device is already hardware read-only via the existing udev
# `blockdev --setro` rule regardless, so even a bug here can't result in a
# write to evidence.
device_previews_lock = threading.Lock()
active_device_previews = {}  # device_path -> {granted_at, last_activity}
DEVICE_PREVIEW_IDLE_SECONDS = 20 * 60

def _grant_device_preview_acl(device_path):
    try:
        res = subprocess.run(
            ["sudo", "/usr/bin/setfacl", "-m", f"u:{_SERVICE_ACCOUNT_NAME}:r", device_path],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        return False, "setfacl timed out - the device may be unresponsive."
    except FileNotFoundError:
        return False, "setfacl is not installed on this station. Run 'sudo apt-get install acl' first."
    if res.returncode != 0:
        return False, (res.stderr or res.stdout or "Unknown setfacl error.").strip()[:300]
    return True, None

def _revoke_device_preview_acl(device_path):
    # Best-effort - a device that was unplugged mid-preview has nothing left
    # to revoke the ACL on, and that's fine (the ACL dies with the device
    # node); never let a revoke failure block the tracking-state cleanup.
    try:
        subprocess.run(
            ["sudo", "/usr/bin/setfacl", "-x", f"u:{_SERVICE_ACCOUNT_NAME}", device_path],
            capture_output=True, timeout=15,
        )
    except Exception:
        pass

def _device_preview_sweep_loop():
    while True:
        time.sleep(60)
        now = time.time()
        stale = []
        with device_previews_lock:
            for device_path, info in active_device_previews.items():
                if now - info["last_activity"] > DEVICE_PREVIEW_IDLE_SECONDS:
                    stale.append(device_path)
            for device_path in stale:
                del active_device_previews[device_path]
        for device_path in stale:
            _revoke_device_preview_acl(device_path)
            log_chain_of_custody("device_preview_auto_revoked", {"device": device_path, "reason": "idle_timeout"},
                                  source_ip=None, user="system-idle-sweep")

threading.Thread(target=_device_preview_sweep_loop, daemon=True).start()

def _device_preview_startup_reconciliation():
    """One-shot check at process start (not a recurring sweep - a leaked ACL
    grant only ever happens via a process crash/restart, which this only
    needs to check for once per process lifetime), found missing during the
    2026-08-22 security audit and mirroring LUKS's own startup loop-device
    reconciliation (routes/acquisition.py). active_device_previews is always
    empty at a fresh start, so any read-ACL grant for this app's own service
    account found on a candidate device at this point cannot be explained by
    this process's own state - logs a disclosure, never auto-revokes
    (matching this project's "disclose, don't silently act" posture used for
    the LUKS case), even though the risk here is unusually low to actually
    act on: this specific ACL entry can ONLY ever have been created by this
    app's own code - no other legitimate reason exists for the service
    account to hold an explicit read grant on a raw block device - unlike
    LUKS's loop-device case, where a genuinely unrelated legitimate use
    could theoretically exist.

    Enumerates every /dev/sd*, /dev/nvme*, /dev/mmcblk* node, filtered to
    exactly the whole-disk-or-partition whitelist
    is_valid_block_device_or_partition() already enforces everywhere else in
    this app, and runs plain UNPRIVILEGED `getfacl -p` against each - no sudo
    grant needed at all, confirmed live: Unix metadata visibility (which
    covers ACL/xattr reads) is governed separately from data-access
    permission, so this succeeds even against a root:disk-owned device node
    with no `other` access."""
    try:
        candidates = sorted(set(glob.glob('/dev/sd*') + glob.glob('/dev/nvme*') + glob.glob('/dev/mmcblk*')))
    except Exception:
        return
    for device_path in candidates:
        if not is_valid_block_device_or_partition(device_path):
            continue
        try:
            res = subprocess.run(['getfacl', '-p', device_path], capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        if res.returncode != 0:
            continue
        if any(line.startswith(f'user:{_SERVICE_ACCOUNT_NAME}:') for line in res.stdout.splitlines()):
            log_chain_of_custody(
                "device_preview_orphan_acl_detected",
                {"device": device_path,
                 "note": "Found a read-ACL grant for this app's own service account at process startup, not explained by this process's own state - likely leaked by a prior crash/restart. Not auto-revoked."},
                source_ip=None, user="system-startup",
            )

threading.Thread(target=_device_preview_startup_reconciliation, daemon=True).start()

def _touch_device_preview(device_path):
    """Bumps last_activity for an active preview grant - called by every
    /api/image/* route below once it resolves a request against a live
    device, so a genuinely in-use preview session is never swept as idle."""
    with device_previews_lock:
        if device_path in active_device_previews:
            active_device_previews[device_path]["last_activity"] = time.time()

def _resolve_browsable_source(raw_path):
    """Single point of truth for 'is this thing browsable via Sleuth Kit' -
    replaces the old safe_path()+os.path.isfile() two-liner every /api/image/*
    route used to repeat independently. Returns the real path to use, or
    None. Three cases: (a) an acquired image FILE under the evidence root
    (today's existing, unchanged behavior), (b) a raw device/partition path
    that exactly matches a currently-active Live Device Preview grant - only
    a device this app's own /api/image/preview/enter just ACL-granted can
    ever match, the same 'only a path we ourselves just created can be
    trusted' pattern _resolve_acquisition_source() already uses for
    BitLocker's dislocker mounts - or (c) a path currently registered in the
    shared core/decrypted_sources.py registry (a BitLocker dislocker-file or
    a LUKS dm-mapper device that routes/acquisition.py's own unlock
    machinery just created and registered).

    Case (c) fixes a real, previously-latent bug: a dislocker-file's path
    lives under DISLOCKER_MOUNT_ROOT (INSTALL_DIR/.bitlocker_mounts/...),
    outside EVIDENCE_ROOT entirely, so safe_path() has always rejected it
    (confirmed against both this refactored code and the original
    pre-refactor code via git history) - meaning "Unlock BitLocker &
    Browse..." could never actually reach a successful browse, even before
    today. Every existing acquired-image-file caller (case a) and every
    Live Device Preview caller (case b) is unaffected by this addition."""
    if not raw_path:
        return None
    validated_file = safe_path(raw_path)
    if validated_file and os.path.isfile(validated_file):
        return validated_file
    with device_previews_lock:
        is_active_preview = raw_path in active_device_previews
    if is_active_preview and is_valid_block_device_or_partition(raw_path):
        _touch_device_preview(raw_path)
        return raw_path
    if get_decrypted_source_kind(raw_path) is not None:
        return raw_path
    return None

@image_browser_bp.route('/api/image/preview/enter', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def image_preview_enter():
    req = request.get_json() or {}
    device_path = req.get('device_path', '')
    if not is_valid_block_device_or_partition(device_path):
        return jsonify({"success": False, "error": "Invalid or unrecognized device/partition path."}), 400

    granted, error = _grant_device_preview_acl(device_path)
    if not granted:
        return jsonify({"success": False, "error": f"Could not grant preview access: {error}"}), 500

    with device_previews_lock:
        active_device_previews[device_path] = {"granted_at": time.time(), "last_activity": time.time()}

    # Prove the grant actually works and the device holds a real,
    # recognizable filesystem before handing it back as "ready to browse" -
    # a bad/garbage/unsupported device should revoke the ACL immediately
    # rather than leaving a dangling grant the examiner then discovers is
    # useless only once they try to browse it. _tsk_resolve_filesystems()
    # never raises (it swallows every exception internally and returns []),
    # so an empty result is the only failure signal available here.
    partitions = _tsk_resolve_filesystems(device_path)
    if not partitions:
        with device_previews_lock:
            active_device_previews.pop(device_path, None)
        _revoke_device_preview_acl(device_path)
        return jsonify({"success": False, "error": "Could not read a recognized filesystem on this device - the ACL grant was reverted."}), 400

    log_chain_of_custody("device_preview_entered", {"device": device_path})
    return jsonify({"success": True, "device_path": device_path, "filesystem_count": len(partitions)})

@image_browser_bp.route('/api/image/preview/exit', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def image_preview_exit():
    req = request.get_json() or {}
    device_path = req.get('device_path', '')
    with device_previews_lock:
        was_active = active_device_previews.pop(device_path, None) is not None
    if was_active:
        _revoke_device_preview_acl(device_path)
        log_chain_of_custody("device_preview_exited", {"device": device_path})
    # Idempotent on an unknown/already-exited device, matching
    # _dislocker_lock()'s existing convention - a second exit call (or one
    # racing the idle-sweep) is a harmless no-op, not an error.
    return jsonify({"success": True})

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
# Same base64-embed technique already used for TSK_PREVIEW_IMAGE_EXT above -
# there's no real on-disk path for a still-in-image file to hand a browser's
# native PDF viewer via a plain URL (unlike the real-filesystem preview
# route, which just points an iframe at /api/files/raw), so the whole file
# has to be loaded and embedded as a data: URI instead. Same 8MB cap as
# images for the same reason: base64 + an in-memory JSON payload doesn't
# scale to an arbitrarily large file the way send_file()'s streaming does.
TSK_PREVIEW_PDF_MAX_BYTES = 8_000_000

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
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
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
                # Same TSK_VS_PART_FLAG_ALLOC check _tsk_resolve_filesystems()
                # already uses to decide which Volume_Info entries are real,
                # openable filesystems vs. unallocated/meta placeholder
                # regions - exposed here too so the File Explorer tree can
                # show unallocated gaps as informational (non-browsable)
                # entries instead of trying to open them as a filesystem.
                "is_allocated": int(part.flags) == pytsk3.TSK_VS_PART_FLAG_ALLOC,
            })
    except IOError:
        pass  # no partition table - normal for a single-filesystem image (phone/media card dd)

    return jsonify({"success": True, "partitions": partitions})

@image_browser_bp.route('/api/image/fls', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_fls():
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')  # empty = root of the filesystem at this offset

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    out_name = req.get('output_name', '')
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '')

    if not image_path:
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
        elif ext == '.pdf':
            if size > TSK_PREVIEW_PDF_MAX_BYTES:
                return jsonify({"success": True, "kind": "too_large", "size": size})
            buf = io.BytesIO()
            _tsk_stream_file(tsk_file, buf.write, max_bytes=TSK_PREVIEW_PDF_MAX_BYTES)
            return jsonify({"success": True, "kind": "pdf", "size": size,
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    query = (req.get('query') or '').strip().lower()
    start_inode = req.get('start_inode', '')

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    start_inode = req.get('start_inode', '')

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path:
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

def _run_hash_manifest_body(image_path, dest_dir, algo, hash_sets):
    """The actual walk-and-hash work, extracted verbatim out of
    image_hash_manifest() (Phase 2 of Linux Artifacts + Auto Analyze,
    2026-08-25) so Auto Analyze can call it directly, in-process, as one
    step of a sequenced run - this function has zero current_job/job_lock
    involvement either way (unlike the async whole-image tools, this one
    never touched job state at all even before this extraction), so no
    suppress-flag wrapping is needed to call it safely from an orchestrator.
    Request-parsing/validation and log_chain_of_custody() stay in the
    route below, unchanged - only the core loop and manifest-writing moved
    here. Returns a plain dict; the route builds its jsonify() response
    from it, Auto Analyze reads the same dict directly."""
    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return {"success": False, "error": "No recognized filesystem found in this image."}

    start_time = time.time()
    rows = []  # (hash_hex, size, in-image path)
    matches = []  # (hash_hex, path, [list_name, ...])
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
                digest = h.hexdigest()
                rows.append((digest, size, path))
                files_hashed += 1
                if hash_sets:
                    hit_lists = [s["name"] for s in hash_sets.values() if digest in s["hashes"]]
                    if hit_lists:
                        matches.append((digest, path, hit_lists))
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
    ]
    if hash_sets:
        checked_names = ', '.join(s["name"] for s in hash_sets.values())
        lines.append(f"# Checked against hash set(s): {checked_names} ({len(matches)} match(es))")
    lines += [
        "#",
        f"# {'hash'.ljust(len(rows[0][0]) if rows else 64)}  size(bytes)  path",
    ]
    for digest, size, path in rows:
        lines.append(f"{digest}  {size}  {path}")
    if matches:
        lines.append("")
        lines.append("# --- HASH LIST MATCHES ---")
        for digest, path, hit_lists in matches:
            lines.append(f"# MATCH  {digest}  {path}  <- {', '.join(hit_lists)}")
    try:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        return {"success": False, "error": f"Failed to write manifest file: {e}"}
    _auto_tag_case_artifact(dest_dir, manifest_path)

    return {
        "success": True, "manifest_path": manifest_path, "files_hashed": files_hashed,
        "files_errored": files_errored, "truncated": truncated,
        "hash_list_match_count": len(matches),
        "hash_list_matches": [{"hash": d, "path": p, "lists": ls} for d, p, ls in matches[:50]],
    }

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
    than just incomplete. Request-parsing here, real work in
    _run_hash_manifest_body() above."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    algo = req.get('algorithm', 'sha256').lower()
    hash_list_ids = req.get('hash_list_ids') or []

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400
    if algo not in ALLOWED_HASH_ALGOS:
        return jsonify({"success": False, "error": f"Unsupported algorithm '{algo}'. Use one of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    # D2 (hash-set filtering) - only a hash list whose OWN algorithm
    # matches this manifest's algorithm can meaningfully cross-reference
    # against it (a saved sha256 list can never match an md5 manifest) -
    # a mismatched list is silently skipped here rather than surfaced as
    # an error, since "check whichever of my selected lists actually
    # apply" is a more forgiving default than forcing the examiner to
    # re-select per algorithm.
    hash_sets = {lid: s for lid, s in load_hash_list_sets(hash_list_ids).items() if s["algorithm"] == algo}

    result = _run_hash_manifest_body(image_path, dest_dir, algo, hash_sets)
    if not result["success"]:
        # Both of _run_hash_manifest_body()'s own failure paths (no
        # recognized filesystem, manifest write failure) were already 500
        # in the pre-extraction code - preserved as-is here.
        return jsonify(result), 500

    log_chain_of_custody("hash_manifest_export_image", {
        "image_path": image_path, "algorithm": algo, "files_hashed": result["files_hashed"],
        "files_errored": result["files_errored"], "truncated": result["truncated"],
        "hash_list_matches": result["hash_list_match_count"],
    })
    return jsonify(result)

@image_browser_bp.route('/api/image/check_hash_lists', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_check_hash_lists():
    """In-image counterpart to routes/file_explorer.py's check_hash_lists()
    - one selected in-image file, hashed in memory (no temp-file extraction
    needed, unlike Binwalk/Strings/EXIF - hashlib can stream straight off
    the pytsk3 read the same way image_hash_manifest() above already does
    per-file) and checked against the requested lists' loaded sets."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    hash_list_ids = req.get('hash_list_ids') or []
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not hash_list_ids:
        return jsonify({"success": False, "error": "No hash sets selected."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    hash_sets = load_hash_list_sets(hash_list_ids)
    if not hash_sets:
        return jsonify({"success": False, "error": "None of the selected hash sets could be loaded."}), 400
    needed_algos = {s["algorithm"] for s in hash_sets.values()}

    try:
        fs = _tsk_open_fs(image_path, offset)
        tsk_file = fs.open_meta(inode=inode_num)
        computed = {}
        for algo in needed_algos:
            h = hashlib.new(algo)
            _tsk_stream_file(tsk_file, h.update)
            computed[algo] = h.hexdigest()
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500

    matches = []
    for list_id, s in hash_sets.items():
        digest = computed.get(s["algorithm"])
        if digest and digest in s["hashes"]:
            matches.append({"list_id": list_id, "list_name": s["name"], "label": s.get("label", "known_bad"),
                             "algorithm": s["algorithm"], "hash": digest})

    log_chain_of_custody("hash_list_check_image", {"image_path": image_path, "inode": str(inode),
                                                     "lists_checked": len(hash_sets), "matches": len(matches)})
    return jsonify({"success": True, "computed_hashes": computed, "matches": matches})

# --- Browser Artifacts (in-image): real per-app parsing (Chrome/Chromium
# family + Firefox), directly against an acquired image's filesystem ---
# Same core/browser_artifacts.py parsing as the real-directory route in
# routes/file_explorer.py - only candidate discovery differs (a pytsk3 walk
# here, matching by entry name, instead of os.walk over real files) and
# each match needs extracting to a short-lived temp file first (parsing
# needs a real path on disk - same reasoning image_binwalk()/image_strings()
# already established for this exact extract-to-temp-then-parse pattern).
IMAGE_BROWSER_ARTIFACT_MAX_WALKED_SECONDS = 300  # the walk itself is cheap (a name comparison per entry) - this is a backstop against a pathologically large/looping filesystem, not the normal case

@image_browser_bp.route('/api/image/parse_browser_artifacts', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_browser_artifacts():
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    # Automatic, not per-scan-selectable - see routes/file_explorer.py's
    # own parse_browser_artifacts() for the identical reasoning.
    url_list_sets = load_url_list_sets([r['id'] for r in get_url_lists()])

    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    start_time = time.time()
    candidates = []  # (fs, fsinfo, entry, in-image path)
    truncated = False
    for fsinfo in filesystems:
        try:
            fs = _tsk_open_fs(image_path, fsinfo['offset'])
        except Exception:
            continue
        for entry, path in _tsk_walk(fs):
            if entry['is_dir'] or entry['deleted'] or entry['is_virtual']:
                continue  # deleted-file data may already be partially overwritten - same exclusion every other in-image analysis tool in this app already applies
            if time.time() - start_time > IMAGE_BROWSER_ARTIFACT_MAX_WALKED_SECONDS:
                truncated = True
                break
            if entry['name'] in BROWSER_ARTIFACT_FILENAMES:
                candidates.append((fs, fsinfo, entry, path))
                if len(candidates) >= BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES:
                    truncated = True
                    break
        if truncated:
            break

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
            records = parse_browser_profile_file(tmp_path, entry['name'], url_list_sets=url_list_sets)
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("browser_artifacts_parsed_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

IMAGE_REGISTRY_EVTX_MAX_WALKED_SECONDS = 300  # same backstop image_parse_browser_artifacts() above already uses

def _image_scan_candidate_files(image_path, matcher, max_candidates):
    """Shared whole-image walk for Registry/EVTX/Prefetch/Recycle Bin
    in-image scans - matcher(entry_name, in_image_path) -> bool decides
    what counts as a candidate (exact hive basename match for Registry,
    extension match for EVTX/Prefetch, basename+parent-directory-name
    match for Recycle Bin - the second argument exists specifically for
    that last case, unused by every other matcher). Returns
    (candidates, truncated) where each candidate is
    (fs, fsinfo, entry, in-image path)."""
    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return None, False
    start_time = time.time()
    candidates = []
    truncated = False
    for fsinfo in filesystems:
        try:
            fs = _tsk_open_fs(image_path, fsinfo['offset'])
        except Exception:
            continue
        for entry, path in _tsk_walk(fs):
            if entry['is_dir'] or entry['deleted'] or entry['is_virtual']:
                continue
            if time.time() - start_time > IMAGE_REGISTRY_EVTX_MAX_WALKED_SECONDS:
                truncated = True
                break
            if matcher(entry['name'], path):
                candidates.append((fs, fsinfo, entry, path))
                if len(candidates) >= max_candidates:
                    truncated = True
                    break
        if truncated:
            break
    return candidates, truncated

@image_browser_bp.route('/api/image/parse_registry', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_registry():
    """In-image counterpart to parse_registry() (routes/file_explorer.py) -
    same extract-to-temp-then-parse pattern image_parse_browser_artifacts()
    above already established."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    upper_names = {n.upper() for n in REGISTRY_HIVE_FILENAMES}
    candidates, truncated = _image_scan_candidate_files(
        image_path, lambda name, path: name.upper() in upper_names, REGISTRY_SCAN_MAX_CANDIDATES)
    if candidates is None:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
            records = parse_registry_hive_file(tmp_path, entry['name'])
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("registry_hives_parsed_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/parse_crypto_wallets', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_crypto_wallets():
    """In-image counterpart to parse_crypto_wallets() (routes/
    file_explorer.py) - same extract-to-temp-then-parse pattern
    image_parse_registry() above already established."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    def _is_wallet_candidate(name, path):
        # path is the full in-image pytsk3 path (always '/'-separated,
        # includes the filename itself) - the containing directory is
        # everything before the last segment, mirroring
        # _is_recyclebin_candidate's own path.split('/') idiom above.
        containing_dir = path.rsplit('/', 1)[0] if '/' in path else ''
        return is_crypto_wallet_candidate(name, containing_dir)

    candidates, truncated = _image_scan_candidate_files(
        image_path, _is_wallet_candidate, CRYPTO_WALLET_MAX_CANDIDATES)
    if candidates is None:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
            records = parse_crypto_wallet_file(tmp_path, entry['name'])
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("crypto_wallets_scanned_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

MOBILE_BACKUP_IMAGE_MAX_FILES = 5  # Manifest.db/Info.plist/Manifest.plist + the (at most 3) resolved content files below
MOBILE_BACKUP_IMAGE_MAX_CONTENT_BYTES = 500 * 1024 * 1024  # generous per-content-file cap - sms.db/AddressBook/CallHistory are never remotely this large in practice

def _find_ios_backup_dir_in_image(fs, root_inode=None):
    """Walks a filesystem looking for a directory whose NAME is UDID-shaped
    and whose immediate children include both Manifest.db and Info.plist -
    the in-image counterpart to core/mobile_artifacts.py's
    find_mobile_backup_manifest() real-fs walk. Returns (dir_inode,
    in_image_path) or (None, None). Deliberately only checks directories
    (not every file, unlike _image_scan_candidate_files's matcher shape) -
    a full os.walk-equivalent over every directory in a large image is
    already what _tsk_walk provides, this just filters its output down to
    directory entries and probes each UDID-shaped one."""
    from core.mobile_artifacts import _udid_like
    for entry, path in _tsk_walk(fs, root_inode):
        if not entry['is_dir'] or entry['deleted'] or entry['is_virtual']:
            continue
        if not _udid_like(entry['name']):
            continue
        try:
            children = {c['name'] for c in _tsk_list_dir(fs, int(entry['inode']))}
        except Exception:
            continue
        if 'Manifest.db' in children and 'Info.plist' in children:
            return int(entry['inode']), path
    return None, None


def _extract_ios_backup_essentials_to_temp(fs, backup_dir_inode):
    """Extracts just Manifest.db/Info.plist/Manifest.plist (never the whole
    backup - photos/app data under a real backup can be many GB, and
    core/mobile_artifacts.py's parsers only ever need these 3 files plus
    whichever specific content files Manifest.db's own Files table resolves
    to for the target apps) into a fresh temp directory mirroring the
    backup folder's own top level, queries the extracted Manifest.db for
    the 3 target apps' fileIDs, then extracts exactly those resolved
    content files (if found) into the same temp dir at their real
    <fileID[0:2]>/<fileID> relative layout - so
    parse_mobile_backup_manifest() can run against this temp copy exactly
    as it would against a real-fs backup, zero parsing-logic duplication.
    Returns the temp dir path (caller must shutil.rmtree() it) or None if
    Manifest.db itself couldn't be extracted."""
    temp_dir = tempfile.mkdtemp(prefix="pif_ios_backup_")
    try:
        children = {c['name']: c for c in _tsk_list_dir(fs, backup_dir_inode)}
        for fname in ('Manifest.db', 'Info.plist', 'Manifest.plist'):
            entry = children.get(fname)
            if not entry or entry['is_dir']:
                continue
            try:
                tsk_file = fs.open_meta(inode=int(entry['inode']))
                with open(os.path.join(temp_dir, fname), 'wb') as out:
                    _tsk_stream_file(tsk_file, out.write, max_bytes=MOBILE_BACKUP_IMAGE_MAX_CONTENT_BYTES)
            except Exception:
                continue
        if not os.path.isfile(os.path.join(temp_dir, 'Manifest.db')):
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None

        from core.mobile_artifacts import _resolve_manifest_files_query_only, MOBILE_ARTIFACT_TARGET_PATHS
        for domain, relative_path in MOBILE_ARTIFACT_TARGET_PATHS.values():
            file_id = _resolve_manifest_files_query_only(temp_dir, domain, relative_path)
            if not file_id:
                continue
            try:
                subdir_entry = children.get(file_id[0:2])
                if not subdir_entry or not subdir_entry['is_dir']:
                    continue
                target_entry = None
                for c in _tsk_list_dir(fs, int(subdir_entry['inode'])):
                    if c['name'] == file_id and not c['is_dir']:
                        target_entry = c
                        break
                if not target_entry:
                    continue
                out_subdir = os.path.join(temp_dir, file_id[0:2])
                os.makedirs(out_subdir, exist_ok=True)
                tsk_file = fs.open_meta(inode=int(target_entry['inode']))
                with open(os.path.join(out_subdir, file_id), 'wb') as out:
                    _tsk_stream_file(tsk_file, out.write, max_bytes=MOBILE_BACKUP_IMAGE_MAX_CONTENT_BYTES)
            except Exception:
                continue
        return temp_dir
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None


@image_browser_bp.route('/api/image/parse_mobile_artifacts', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_mobile_artifacts():
    """In-image counterpart to parse_mobile_artifacts() (routes/
    file_explorer.py) - genuinely low relative value (an examiner virtually
    never has a mobile backup embedded inside a disk image rather than
    sitting as a real folder from this app's own mobile-acquisition
    output), implemented for consistency with the real-fs+in-image pair
    convention every other parser follows, not over-invested in. Extracts
    only the 3 target apps' essential files (never the whole backup - see
    _extract_ios_backup_essentials_to_temp()'s own docstring) into a
    short-lived temp dir, then reuses core/mobile_artifacts.py's real-fs
    parsing functions unmodified against that temp copy."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None
    requested_types = req.get('types') or None

    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    candidates_found = 0
    any_encrypted = False
    temp_dir = None
    try:
        for fsinfo in filesystems:
            try:
                fs = _tsk_open_fs(image_path, fsinfo['offset'])
            except Exception:
                continue
            backup_inode, backup_path = _find_ios_backup_dir_in_image(fs)
            if backup_inode is None:
                continue
            candidates_found += 1
            temp_dir = _extract_ios_backup_essentials_to_temp(fs, backup_inode)
            if not temp_dir:
                continue
            records, summary = parse_mobile_backup_manifest(temp_dir, requested_types)
            if summary.get("encrypted"):
                any_encrypted = True
            if not records:
                continue
            files_parsed += 1
            for r in records:
                counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
            if case_folder:
                _record_parsed_artifacts(case_folder, {
                    "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                    "inode": str(backup_inode), "path": backup_path,
                }, records)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)

    log_chain_of_custody("mobile_artifacts_parsed_image", {
        "image_path": image_path, "candidates_found": candidates_found,
        "files_parsed": files_parsed, "counts": counts, "any_encrypted": any_encrypted,
    })
    return jsonify({
        "success": True, "candidates_found": candidates_found, "files_parsed": files_parsed,
        "counts": counts, "truncated": False, "indexed": bool(case_folder), "any_encrypted": any_encrypted,
    })

@image_browser_bp.route('/api/image/parse_evtx', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_evtx():
    """In-image counterpart to parse_evtx() (routes/file_explorer.py)."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    candidates, truncated = _image_scan_candidate_files(
        image_path, lambda name, path: name.lower().endswith(EVTX_EXTENSION), EVTX_SCAN_MAX_CANDIDATES)
    if candidates is None:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']), suffix='.evtx')
            records = parse_evtx_file(tmp_path)
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("evtx_files_parsed_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/parse_prefetch', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_prefetch():
    """In-image counterpart to parse_prefetch() (routes/file_explorer.py)."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    candidates, truncated = _image_scan_candidate_files(
        image_path, lambda name, path: name.lower().endswith(PREFETCH_EXTENSION), PREFETCH_SCAN_MAX_CANDIDATES)
    if candidates is None:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']), suffix='.pf')
            records = parse_prefetch_file(tmp_path)
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("prefetch_files_parsed_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/parse_recyclebin', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_recyclebin():
    """In-image counterpart to parse_recyclebin() (routes/file_explorer.py) -
    the matcher checks both the entry's own name (starts with '$I') and
    whether '$Recycle.Bin' appears anywhere in its in-image ancestor path
    (a real $I file's immediate parent is always a per-SID subfolder, e.g.
    '$Recycle.Bin/S-1-5-21-.../$IABCDEF.txt', never '$Recycle.Bin' itself -
    the same real bug core/recyclebin_utils.py's find_recyclebin_files()
    was caught and fixed for before either was exercised against real
    data), which is exactly why _image_scan_candidate_files()'s matcher
    signature carries the full in-image path alongside the bare filename."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    def _is_recyclebin_candidate(name, path):
        if not name.upper().startswith('$I'):
            return False
        return any(p.lower() == '$recycle.bin' for p in path.split('/'))

    candidates, truncated = _image_scan_candidate_files(
        image_path, _is_recyclebin_candidate, RECYCLEBIN_SCAN_MAX_CANDIDATES)
    if candidates is None:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
            records = parse_recyclebin_file(tmp_path)
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)

    log_chain_of_custody("recyclebin_files_parsed_image", {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/analyze_mft', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_analyze_mft():
    """In-image counterpart to analyze_mft() (routes/file_explorer.py) - one
    selected in-image '$MFT' file, same specific-inode extract-to-temp-then-
    parse pattern image_parse_lnk() already uses for a single selected
    file, rather than a whole-image scan (the examiner has already found
    and right-clicked the exact $MFT entry via normal Browse-as-Image)."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None
    destination_dir = safe_path(req.get('destination_dir')) or case_folder
    if not destination_dir or not os.path.isdir(destination_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400
    compute_hashes = bool(req.get('compute_hashes'))

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num)
        result = analyze_mft_file(tmp_path, compute_hashes=compute_hashes)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    if not result["success"]:
        return jsonify(result), 500

    image_base = os.path.splitext(os.path.basename(image_path))[0]
    output_path = os.path.join(destination_dir, f"{image_base}_mft_analysis.json")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result["records"], f, indent=2, default=str)
    except OSError as e:
        return jsonify({"success": False, "error": f"Analyzed successfully but could not write output: {e}"}), 500

    identity = {"source_type": "image", "image_path": image_path, "fs_offset": offset, "inode": str(inode), "path": req.get('path')}
    if case_folder:
        _record_parsed_artifacts(case_folder, identity, result["records"])
        _auto_tag_case_artifact(case_folder, output_path)
    else:
        _auto_tag_case_artifact(destination_dir, output_path)

    summary = f"{result['total_records']} MFT record(s) parsed"
    if result["timestomp_count"]:
        summary += f" - {result['timestomp_count']} record(s) with suspected timestomping"
    log_chain_of_custody("mft_file_analyzed_image", {
        "image_path": image_path, "inode": str(inode), "output_path": output_path,
        "total_records": result["total_records"], "timestomp_count": result["timestomp_count"],
    })
    return jsonify({
        "success": True, "output_path": output_path, "total_records": result["total_records"],
        "timestomp_count": result["timestomp_count"], "summary": summary, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/parse_usnjrnl', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_usnjrnl():
    """In-image counterpart to parse_usnjrnl() (routes/file_explorer.py) -
    one selected in-image '$Extend/$UsnJrnl:$J' entry, same specific-inode
    extract-to-temp-then-parse pattern image_parse_lnk() already uses.

    Known, disclosed limitation: whether TSK/pytsk3's own directory walk
    actually surfaces '$UsnJrnl:$J' as a separate, directly-selectable
    'streamfile:streamname' entry the examiner can browse to and right-click
    (the documented convention its own `fls` CLI has always used for named/
    alternate data streams) has not been verified against a real NTFS image
    with an active change journal, since none exists in this project's own
    test fixtures as of this writing (see core/usnjrnl_utils.py's own
    docstring). The underlying byte-parser (core/usnjrnl_utils.py) is
    independently, fully verified against a hand-built synthetic
    USN_RECORD_V2 stream; only whether this stream is reachable/selectable
    at all via normal in-image browsing is unverified pending real data."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None
    destination_dir = safe_path(req.get('destination_dir')) or case_folder
    if not destination_dir or not os.path.isdir(destination_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num)
        with open(tmp_path, 'rb') as f:
            data = f.read()
        records = parse_usnjrnl_stream(data)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    image_base = os.path.splitext(os.path.basename(image_path))[0]
    output_path = os.path.join(destination_dir, f"{image_base}_usnjrnl_parsed.json")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(records, f, indent=2, default=str)
    except OSError as e:
        return jsonify({"success": False, "error": f"Parsed successfully but could not write output: {e}"}), 500

    identity = {"source_type": "image", "image_path": image_path, "fs_offset": offset, "inode": str(inode), "path": req.get('path')}
    if case_folder:
        _record_parsed_artifacts(case_folder, identity, records)
        _auto_tag_case_artifact(case_folder, output_path)
    else:
        _auto_tag_case_artifact(destination_dir, output_path)

    log_chain_of_custody("usnjrnl_file_parsed_image", {"image_path": image_path, "inode": str(inode), "output_path": output_path, "record_count": len(records)})
    return jsonify({"success": True, "output_path": output_path, "record_count": len(records), "indexed": bool(case_folder)})

@image_browser_bp.route('/api/image/parse_linux_artifacts', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_linux_artifacts():
    """In-image counterpart to parse_linux_artifacts() (routes/
    file_explorer.py). Loops once per requested artifact type (mirroring
    the real-fs route's own per-type find_fn() loop) rather than one
    combined walk with post-hoc type dispatch - each type gets its own
    _image_scan_candidate_files() call with that type's own specific
    matcher, keeping "which type did this candidate match" unambiguous."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    requested_types = req.get('types') or LINUX_ARTIFACT_DEFAULT_TYPES
    requested_types = [t for t in requested_types if t in LINUX_ARTIFACT_IMAGE_MATCHERS]

    counts = {}
    files_parsed = 0
    candidates_found_total = 0
    truncated = False
    filesystem_found = False
    for artifact_key in requested_types:
        matcher_fn, parse_fn = LINUX_ARTIFACT_IMAGE_MATCHERS[artifact_key]
        candidates, this_truncated = _image_scan_candidate_files(
            image_path, matcher_fn, LINUX_ARTIFACT_IMAGE_MAX_CANDIDATES)
        if candidates is None:
            continue  # no recognized filesystem - handled once, below, after the loop
        filesystem_found = True
        truncated = truncated or this_truncated
        candidates_found_total += len(candidates)
        for fs, fsinfo, entry, path in candidates:
            tmp_path = None
            try:
                tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
                records = parse_fn(tmp_path, entry['name'])
            except Exception:
                records = []
            finally:
                if tmp_path:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            if not records:
                continue
            files_parsed += 1
            for r in records:
                counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
            if case_folder:
                _record_parsed_artifacts(case_folder, {
                    "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                    "inode": entry['inode'], "path": path,
                }, records)

    if not filesystem_found:
        return jsonify({"success": False, "error": "No recognized filesystem found in this image."}), 500

    log_chain_of_custody("linux_artifacts_parsed_image", {
        "image_path": image_path, "types": requested_types, "candidates_found": candidates_found_total,
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    })
    return jsonify({
        "success": True, "candidates_found": candidates_found_total, "files_parsed": files_parsed,
        "counts": counts, "truncated": truncated, "indexed": bool(case_folder),
    })

@image_browser_bp.route('/api/image/parse_lnk', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_parse_lnk():
    """In-image counterpart to parse_lnk() (routes/file_explorer.py) - one
    selected in-image .lnk file, same extract-to-temp-then-parse pattern
    image_strings() below already uses for a single selected file."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file.lnk'
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix='.lnk')
        records = parse_lnk_file(tmp_path, name_hint=name_hint)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    if case_folder and records:
        _record_parsed_artifacts(case_folder, {
            "source_type": "image", "image_path": image_path, "fs_offset": offset,
            "inode": str(inode), "path": req.get('path'),
        }, records)

    log_chain_of_custody("lnk_file_parsed_image", {"image_path": image_path, "inode": str(inode), "name": name_hint, "parsed": bool(records)})
    return jsonify({
        "success": bool(records), "record": records[0] if records else None,
        "indexed": bool(case_folder and records),
        "error": None if records else "Could not parse this file as a valid .lnk shortcut.",
    })

SQLITE_QUERY_MAX_ROWS = 500  # matches routes/file_explorer.py's own real-fs cap

def _sqlite_list_tables(conn):
    """Local copy of routes/file_explorer.py's own helper - no cross-
    blueprint import exists anywhere in this app (confirmed before writing
    this), so a small duplicate here is lower-risk than introducing the
    first one for two small functions."""
    tables = []
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        try:
            count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.DatabaseError:
            count = None
        tables.append({"name": name, "row_count": count})
    return tables

@image_browser_bp.route('/api/image/sqlite/tables', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_sqlite_list_tables():
    """In-image counterpart to sqlite_list_tables() (routes/file_explorer.py)
    - one selected in-image .db/.sqlite/.sqlite3 file, extract-to-temp-then-
    open, same pattern image_strings()/image_exif() already use."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix='.db')
        conn = _open_sqlite_readonly(tmp_path)
        try:
            tables = _sqlite_list_tables(conn)
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        return jsonify({"success": False, "error": f"Not a readable SQLite database: {e}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return jsonify({"success": True, "tables": tables})

@image_browser_bp.route('/api/image/sqlite/query', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_sqlite_query_table():
    """In-image counterpart to sqlite_query_table() (routes/file_explorer.py)
    - same table-name-validated-against-a-live-listing safety, re-extracted
    fresh per call (matching every other in-image single-file tool's
    stateless extract-use-remove pattern - no session-held temp file)."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    table = req.get('table', '')
    try:
        row_offset = max(0, int(req.get('row_offset', 0)))
    except (TypeError, ValueError):
        row_offset = 0
    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not table:
        return jsonify({"success": False, "error": "No table specified."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    tmp_path = None
    try:
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix='.db')
        conn = _open_sqlite_readonly(tmp_path)
        try:
            real_tables = {t["name"] for t in _sqlite_list_tables(conn)}
            if table not in real_tables:
                return jsonify({"success": False, "error": "Not a real table in this database."}), 400
            cur = conn.execute(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (SQLITE_QUERY_MAX_ROWS, row_offset))
            columns = [d[0] for d in cur.description]
            rows = [list(r) for r in cur.fetchall()]
            total_rows = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        return jsonify({"success": False, "error": f"Query failed: {e}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return jsonify({
        "success": True, "columns": columns, "rows": rows, "total_rows": total_rows,
        "offset": row_offset, "returned": len(rows), "page_size": SQLITE_QUERY_MAX_ROWS,
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    keyword_list_ids = req.get('keyword_list_ids') or []

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'
    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'
    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    if not image_path:
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
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'

    if not image_path:
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

@image_browser_bp.route('/api/image/yara_scan', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_yara_scan():
    """In-image counterpart to routes/file_explorer.py's yara_scan() - same
    extract-to-temp-then-run pattern image_binwalk()/image_strings()/
    image_exif() above already use, since yara's match(filepath=) needs a
    real path on disk just like those tools' own subprocess calls do."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    offset = req.get('offset', 0)
    inode = req.get('inode', '')
    name_hint = req.get('name', '') or 'selected_file'
    ruleset_ids = req.get('ruleset_ids') or []
    case_folder = req.get('case_folder')  # optional, best-effort - see quick_triage_scan()

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not ruleset_ids:
        return jsonify({"success": False, "error": "No YARA rulesets selected."}), 400
    try:
        offset = int(offset)
        inode_num = _tsk_parse_inode(inode)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid offset or inode."}), 400

    sources = load_yara_ruleset_sources(ruleset_ids)
    if not sources:
        return jsonify({"success": False, "error": "None of the selected YARA rulesets could be loaded."}), 400

    tmp_path = None
    try:
        compiled = yara.compile(sources={rid: s['rule_text'] for rid, s in sources.items()})
        fs = _tsk_open_fs(image_path, offset)
        tmp_path = _tsk_extract_to_temp(fs, inode_num, suffix=os.path.splitext(name_hint)[1])
        raw_matches = compiled.match(filepath=tmp_path, timeout=60)
    except yara.Error as e:
        return jsonify({"success": False, "error": f"YARA scan failed: {e}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not scan file: {e}"}), 500
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    matches = [{"ruleset_id": m.namespace, "ruleset_name": sources[m.namespace]["name"],
                "rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)} for m in raw_matches]
    summary = f"{len(matches)} match(es)" if matches else "No matches"
    output = "\n".join(f"[{m['ruleset_name']}] {m['rule']}" + (f" (tags: {', '.join(m['tags'])})" if m['tags'] else "")
                        for m in matches) or "No matches against the selected ruleset(s)."
    log_chain_of_custody("yara_scan_image", {"image_path": image_path, "inode": str(inode),
                                              "rulesets_checked": len(sources), "matches": len(matches)})
    _record_analysis_result(case_folder, {"source_type": "image", "image_path": image_path, "fs_offset": offset,
                                           "inode": str(inode), "path": req.get('path'), "name": name_hint},
                             "YARA", summary, output)
    return jsonify({"success": True, "file_name": name_hint, "matches": matches})

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

def _run_recover_deleted_body(image_path, dest_dir):
    """The actual walk-and-recover work, extracted verbatim out of
    image_recover_deleted() (Phase 2 of Linux Artifacts + Auto Analyze,
    2026-08-25) so Auto Analyze can call it directly as one sequenced step
    - same reasoning/shape as _run_hash_manifest_body() above (this
    function never touched current_job/job_lock either, so no
    suppress-flag wrapping is needed). Request-parsing and
    log_chain_of_custody() stay in the route below, unchanged. Returns a
    plain dict; the route builds its jsonify() response from it."""
    filesystems = _tsk_resolve_filesystems(image_path)
    if not filesystems:
        return {"success": False, "error": "No recognized filesystem found in this image."}

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

    return {
        "success": True, "output_dir": output_root if files_recovered else None,
        "files_recovered": files_recovered, "total_bytes": total_bytes,
        "files_skipped_too_large": files_skipped_too_large, "files_skipped_empty": files_skipped_empty,
        "files_errored": files_errored, "truncated": truncated
    }

@image_browser_bp.route('/api/image/recover_deleted', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def image_recover_deleted():
    """Request-parsing here, real work in _run_recover_deleted_body() above."""
    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))

    if not image_path:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    result = _run_recover_deleted_body(image_path, dest_dir)
    if not result["success"]:
        return jsonify(result), 500

    log_chain_of_custody("recover_deleted_files_image", {
        "image_path": image_path, "output_dir": result["output_dir"], "files_recovered": result["files_recovered"],
        "total_bytes": result["total_bytes"], "files_skipped_too_large": result["files_skipped_too_large"],
        "files_skipped_empty": result["files_skipped_empty"], "files_errored": result["files_errored"],
        "truncated": result["truncated"],
    })
    return jsonify(result)

# --- Auto Analyze: Windows/Linux disk-image profiles (Phase 3, 2026-08-25) ---
# Detects an image's filesystem type (core.tsk_utils.classify_image_profile,
# examiner-confirmed before this ever runs - see routes/auto_analyze.py's
# own /api/auto_analyze/detect) and runs a curated, station-hardware-
# appropriate default set of already-existing tools against it sequentially,
# as ONE background job.
#
# Scoped down from the original design (confirmed with the user, per this
# session's own AskUserQuestion round): the three async whole-image tools
# that already have their own current_job-driven progress (Geolocation,
# Triage Scan, Memory Forensics) live in a DIFFERENT blueprint
# (routes/file_explorer.py's Memory Forensics; the other two are also in
# THIS file but still deliberately excluded here) - reaching them would
# have needed either a cross-blueprint import (a pattern this app has
# never used anywhere - confirmed via a full grep before deciding against
# it) or moving substantial already-shipped async workers into core/ (real
# regression risk to already-tested code). Narrowed instead: only tools
# with NO current_job involvement at all are sequenced here (Hash
# Manifest, the artifact parsers, optionally Recover Deleted) - Triage
# Scan/Geolocation stay one manual click away, just not automatic.
#
# Every step function below has the exact same (image_path, case_folder)
# -> dict signature the generic loop expects, and NONE of them touch
# current_job/update_job internally - this orchestrator is the only thing
# in the whole run that owns job-slot progress, unlike Auto Analyze's
# originally-designed (and since narrowed away) need to coexist with a
# step that manages its own progress.
AUTO_ANALYZE_STEP_LABELS = {
    "hash_manifest": "Hash Manifest (SHA256)",
    "registry": "Registry Hives (incl. Amcache)",
    "evtx": "Event Logs",
    "prefetch": "Prefetch Files",
    "recyclebin": "Recycle Bin",
    "browser_artifacts": "Browser Artifacts (Chrome/Firefox)",
    "linux_artifacts": "Linux Artifacts (shell history/passwd/cron/auth log)",
    "recover_deleted": "Recover Deleted Files (Filesystem-Aware)",
}
AUTO_ANALYZE_WINDOWS_DEFAULT_STEPS = ["hash_manifest", "registry", "evtx", "prefetch", "recyclebin", "browser_artifacts"]
AUTO_ANALYZE_LINUX_DEFAULT_STEPS = ["hash_manifest", "linux_artifacts"]
AUTO_ANALYZE_EXTRA_STEPS = ["recover_deleted"]  # opt-in, either profile
AUTO_ANALYZE_ALL_VALID_STEPS = set(AUTO_ANALYZE_STEP_LABELS.keys())


def _auto_analyze_run_generic_artifact_scan(image_path, case_folder, matcher_fn, parse_fn, max_candidates, coc_action,
                                             source_ip=None, user=None):
    """Shared whole-image discovery+extract+parse+record loop - the exact
    same shape every existing image_parse_X() route in this file already
    has (_image_scan_candidate_files + extract-to-temp + parse + tally +
    _record_parsed_artifacts), reused here instead of duplicated 5 times.
    Also logs its own chain-of-custody entry under the SAME action name
    the equivalent standalone route uses, so an Auto Analyze run produces
    the same granular per-tool audit trail running each tool individually
    would have, in addition to Auto Analyze's own rollup log entry.

    source_ip/user MUST be threaded through explicitly (not left to
    log_chain_of_custody()'s own request/g fallback) - this function runs
    inside execution_worker_auto_analyze_image()'s background daemon
    thread, which has no Flask application context at all. This is the
    exact same class of bug this project has hit and fixed before for
    other background-thread log calls (network config's delayed-revert
    thread, the image triage scan job) - caught live here via a real
    "Working outside of application context" exception on the very first
    end-to-end Auto Analyze run, not caught by design review."""
    candidates, truncated = _image_scan_candidate_files(image_path, matcher_fn, max_candidates)
    if candidates is None:
        return {"success": False, "error": "No recognized filesystem found in this image."}
    counts = {}
    files_parsed = 0
    for fs, fsinfo, entry, path in candidates:
        tmp_path = None
        try:
            tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
            try:
                records = parse_fn(tmp_path, entry['name'])
            except TypeError:
                records = parse_fn(tmp_path)  # a couple of the older parsers take no filename arg at all
        except Exception:
            records = []
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if not records:
            continue
        files_parsed += 1
        for r in records:
            counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
        if case_folder:
            _record_parsed_artifacts(case_folder, {
                "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                "inode": entry['inode'], "path": path,
            }, records)
    log_chain_of_custody(coc_action, {
        "image_path": image_path, "candidates_found": len(candidates),
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    }, source_ip=source_ip, user=user)
    return {"success": True, "candidates_found": len(candidates), "files_parsed": files_parsed,
            "counts": counts, "truncated": truncated}


def _auto_analyze_step_registry(image_path, case_folder, source_ip=None, user=None):
    upper_names = {n.upper() for n in REGISTRY_HIVE_FILENAMES}
    return _auto_analyze_run_generic_artifact_scan(
        image_path, case_folder, lambda name, path: name.upper() in upper_names,
        parse_registry_hive_file, REGISTRY_SCAN_MAX_CANDIDATES, "registry_hives_parsed_image",
        source_ip=source_ip, user=user)


def _auto_analyze_step_evtx(image_path, case_folder, source_ip=None, user=None):
    return _auto_analyze_run_generic_artifact_scan(
        image_path, case_folder, lambda name, path: name.lower().endswith(EVTX_EXTENSION),
        parse_evtx_file, EVTX_SCAN_MAX_CANDIDATES, "evtx_files_parsed_image",
        source_ip=source_ip, user=user)


def _auto_analyze_step_prefetch(image_path, case_folder, source_ip=None, user=None):
    return _auto_analyze_run_generic_artifact_scan(
        image_path, case_folder, lambda name, path: name.lower().endswith(PREFETCH_EXTENSION),
        parse_prefetch_file, PREFETCH_SCAN_MAX_CANDIDATES, "prefetch_files_parsed_image",
        source_ip=source_ip, user=user)


def _auto_analyze_step_recyclebin(image_path, case_folder, source_ip=None, user=None):
    def _is_recyclebin_candidate(name, path):
        if not name.upper().startswith('$I'):
            return False
        return any(p.lower() == '$recycle.bin' for p in path.split('/'))
    return _auto_analyze_run_generic_artifact_scan(
        image_path, case_folder, _is_recyclebin_candidate,
        parse_recyclebin_file, RECYCLEBIN_SCAN_MAX_CANDIDATES, "recyclebin_files_parsed_image",
        source_ip=source_ip, user=user)


def _auto_analyze_step_browser_artifacts(image_path, case_folder, source_ip=None, user=None):
    return _auto_analyze_run_generic_artifact_scan(
        image_path, case_folder, lambda name, path: name in BROWSER_ARTIFACT_FILENAMES,
        parse_browser_profile_file, BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES, "browser_artifacts_parsed_image",
        source_ip=source_ip, user=user)


def _auto_analyze_step_linux_artifacts(image_path, case_folder, source_ip=None, user=None):
    """Unlike the 5 Windows-artifact steps above (5 separate parser types,
    5 separate scan passes), core.linux_artifacts's own LINUX_ARTIFACT_
    DEFAULT_TYPES already bundles shell history/passwd/cron/auth log into
    one logical unit (matching /api/image/parse_linux_artifacts' own
    default behavior) - one combined result dict covering all 4, not 4
    separate calls."""
    counts = {}
    files_parsed = 0
    candidates_found_total = 0
    truncated = False
    filesystem_found = False
    for artifact_key in LINUX_ARTIFACT_DEFAULT_TYPES:
        matcher_fn, parse_fn = LINUX_ARTIFACT_IMAGE_MATCHERS[artifact_key]
        candidates, this_truncated = _image_scan_candidate_files(image_path, matcher_fn, LINUX_ARTIFACT_IMAGE_MAX_CANDIDATES)
        if candidates is None:
            continue
        filesystem_found = True
        truncated = truncated or this_truncated
        candidates_found_total += len(candidates)
        for fs, fsinfo, entry, path in candidates:
            tmp_path = None
            try:
                tmp_path = _tsk_extract_to_temp(fs, _tsk_parse_inode(entry['inode']))
                records = parse_fn(tmp_path, entry['name'])
            except Exception:
                records = []
            finally:
                if tmp_path:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            if not records:
                continue
            files_parsed += 1
            for r in records:
                counts[r["artifact_type"]] = counts.get(r["artifact_type"], 0) + 1
            if case_folder:
                _record_parsed_artifacts(case_folder, {
                    "source_type": "image", "image_path": image_path, "fs_offset": fsinfo['offset'],
                    "inode": entry['inode'], "path": path,
                }, records)
    if not filesystem_found:
        return {"success": False, "error": "No recognized filesystem found in this image."}
    log_chain_of_custody("linux_artifacts_parsed_image", {
        "image_path": image_path, "types": LINUX_ARTIFACT_DEFAULT_TYPES, "candidates_found": candidates_found_total,
        "files_parsed": files_parsed, "counts": counts, "truncated": truncated,
    }, source_ip=source_ip, user=user)
    return {"success": True, "candidates_found": candidates_found_total, "files_parsed": files_parsed,
            "counts": counts, "truncated": truncated}


def _auto_analyze_step_hash_manifest(image_path, case_folder, source_ip=None, user=None):
    result = _run_hash_manifest_body(image_path, case_folder, 'sha256', {})
    if result["success"]:
        log_chain_of_custody("hash_manifest_export_image", {
            "image_path": image_path, "algorithm": "sha256", "files_hashed": result["files_hashed"],
            "files_errored": result["files_errored"], "truncated": result["truncated"],
            "hash_list_matches": result["hash_list_match_count"],
        }, source_ip=source_ip, user=user)
    return result


def _auto_analyze_step_recover_deleted(image_path, case_folder, source_ip=None, user=None):
    result = _run_recover_deleted_body(image_path, case_folder)
    if result["success"]:
        log_chain_of_custody("recover_deleted_files_image", {
            "image_path": image_path, "output_dir": result["output_dir"], "files_recovered": result["files_recovered"],
            "total_bytes": result["total_bytes"], "files_skipped_too_large": result["files_skipped_too_large"],
            "files_skipped_empty": result["files_skipped_empty"], "files_errored": result["files_errored"],
            "truncated": result["truncated"],
        }, source_ip=source_ip, user=user)
    return result


_AUTO_ANALYZE_STEP_FUNCTIONS = {
    "hash_manifest": _auto_analyze_step_hash_manifest,
    "registry": _auto_analyze_step_registry,
    "evtx": _auto_analyze_step_evtx,
    "prefetch": _auto_analyze_step_prefetch,
    "recyclebin": _auto_analyze_step_recyclebin,
    "browser_artifacts": _auto_analyze_step_browser_artifacts,
    "linux_artifacts": _auto_analyze_step_linux_artifacts,
    "recover_deleted": _auto_analyze_step_recover_deleted,
}


def execution_worker_auto_analyze_image(image_path, case_folder, steps, source_ip=None, user=None):
    """Runs each requested step in turn against image_path, as ONE
    continuously-held job-slot claim. Each step gets its OWN try/except -
    a deliberate, pressure-test-driven design choice (see the plan this
    was built from): a naive one-big-try/except-around-the-whole-loop
    shape (the pattern execution_worker_verify_all_evidence uses) would
    silently abort every remaining step on the first unhandled exception,
    with no record distinguishing "never attempted" from "failed" - a
    materially misleading result for a tool whose whole point is a
    complete, auditable sweep.

    begin_suppress_active_false()/end_suppress_active_false() wrap the
    ENTIRE run (not just calls into a specific pre-existing async worker,
    which is what this mechanism was originally built for in Phase 2,
    before "narrow the defaults" removed Triage Scan/Geolocation - the two
    steps that would have needed it for that original reason - from Auto
    Analyze's step set entirely). A second, equally real need for it
    surfaced live during Stop-button testing on the very first real run:
    stop_imaging() (routes/acquisition.py) sets active=False the moment
    Stop is clicked, from a completely different HTTP request/thread than
    this one - with no suppression in place, that immediately released the
    shared job slot while THIS thread's current step (e.g. a multi-minute
    Hash Manifest walk over a real multi-GB image) was still genuinely
    running in the background, confirmed live via `ps`/`top` showing the
    orphaned thread still consuming real CPU/IO seconds after the job
    already read back as inactive - exactly the "another job could sneak
    in mid-run" failure this whole mechanism exists to prevent. Suppressing
    for the whole run (not just around individual step calls) closes both
    the original and the newly-found reason with one wrap: `status`/`log`
    still flip to "Stopped" immediately either way (only `active` is ever
    filtered), so the between-step Stop-check below is unaffected -
    Stop still take effect at the next step boundary, same latency this
    was always going to have, it just no longer also drops the job slot
    early."""
    global current_job
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-200:]))

    total = len(steps)
    step_results = []
    begin_suppress_active_false()
    try:
        update_job(format="auto_analyze_image", status="Starting Auto Analyze...", progress_percent=0.0,
                    transferred_bytes=0, total_bytes=total)
        append_log(f"[*] Auto Analyze starting against {image_path} - {total} step(s): "
                   + ", ".join(AUTO_ANALYZE_STEP_LABELS.get(s, s) for s in steps))

        for i, step_key in enumerate(steps):
            label = AUTO_ANALYZE_STEP_LABELS.get(step_key, step_key)
            if snapshot_job()["status"] == "Stopped":
                step_results.append({"step": step_key, "status": "skipped", "reason": "stopped by user"})
                continue
            append_log(f"=== Step {i + 1}/{total}: {label} ===")
            update_job(status=f"Step {i + 1}/{total}: {label}...")
            try:
                fn = _AUTO_ANALYZE_STEP_FUNCTIONS[step_key]
                result = fn(image_path, case_folder, source_ip=source_ip, user=user)
                if result.get("success"):
                    step_results.append({"step": step_key, "status": "ok", "detail": result})
                    append_log(f"[+] Step {i + 1}/{total} complete.")
                else:
                    step_results.append({"step": step_key, "status": "error", "detail": result.get("error")})
                    append_log(f"[-] Step {i + 1}/{total} reported an error: {result.get('error')}")
            except Exception as e:
                step_results.append({"step": step_key, "status": "error", "detail": str(e)})
                append_log(f"[-] Step {i + 1}/{total} raised an exception: {e}")
            update_job(transferred_bytes=i + 1, progress_percent=round((i + 1) / total * 100, 1))

        steps_ok = sum(1 for r in step_results if r["status"] == "ok")
        steps_failed = sum(1 for r in step_results if r["status"] == "error")
        steps_skipped = sum(1 for r in step_results if r["status"] == "skipped")

        if snapshot_job()["status"] == "Stopped":
            append_log(f"[!] Auto Analyze stopped by user - {steps_ok} of {total} step(s) completed before stopping.")
        else:
            update_job(status="Completed Successfully", progress_percent=100.0)
            append_log(f"[+] Auto Analyze complete - {steps_ok} ok, {steps_failed} failed, {steps_skipped} skipped, of {total} step(s).")

        log_chain_of_custody("auto_analyze_complete", {
            "image_path": image_path, "steps_requested": steps, "steps_ok": steps_ok,
            "steps_failed": steps_failed, "steps_skipped": steps_skipped, "results": step_results,
        }, source_ip=source_ip, user=user)
    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        # end_suppress_active_false() MUST run before this update_job(active=False)
        # or that call would itself still be suppressed - suppression is only
        # ever meant to hold while THIS run is genuinely still in flight.
        end_suppress_active_false()
        update_job(active=False)

@image_browser_bp.route('/api/image/auto_analyze/start', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def start_auto_analyze_image():
    global current_job
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Another job is already running station-wide - wait for it to finish or stop it first."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    image_path = _resolve_browsable_source(req.get('image_path'))
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    requested_steps = req.get('steps') or []
    steps = [s for s in requested_steps if s in AUTO_ANALYZE_ALL_VALID_STEPS]

    if not image_path:
        update_job(active=False)
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None
    if not steps:
        update_job(active=False)
        return jsonify({"success": False, "error": "No valid steps selected."}), 400

    # dest_dir for every step is EITHER the active case folder or, with no
    # case active, the image's own containing directory - matches this
    # app's own "case selection optional, nothing breaks if none is
    # active" convention (every other whole-image tool defaults to
    # EVIDENCE_ROOT via destination_dir; Auto Analyze uses the image's own
    # folder instead so its several output files land next to the image
    # rather than scattered at the evidence root).
    dest_dir = case_folder or os.path.dirname(image_path)

    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
    requester_user = getattr(g, 'forensic_user', None)

    thread = threading.Thread(
        target=execution_worker_auto_analyze_image,
        args=(image_path, dest_dir, steps, requester_ip, requester_user)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("auto_analyze_start", {"image_path": image_path, "steps": steps})
    return jsonify({"success": True, "message": f"Auto Analyze started - {len(steps)} step(s)."})
