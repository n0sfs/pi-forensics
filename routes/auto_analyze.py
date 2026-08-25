"""Auto Analyze detection (Phase 3 of Linux Artifacts + Auto Analyze,
2026-08-25) - given a selected evidence item, figures out what it actually
is (a Windows disk image, a Linux disk image, a memory image, an iOS mobile
backup, or an Android mobile backup) so File Explorer can offer the right
curated default tool set, confirmable/overridable by the examiner before
anything runs.

This is a deliberately small, standalone Blueprint - the ONLY thing it
does is detection, which needs nothing but core/ helpers (no
current_job/job_lock involvement at all - a fast, synchronous inspection,
not a background job). The actual orchestrated runs live where their own
underlying tools already live: /api/image/auto_analyze/start (Windows/
Linux profiles, routes/image_browser.py, next to Hash Manifest/Recover
Deleted/the artifact parsers it sequences) and, for Memory/Mobile
profiles, the ALREADY-EXISTING /api/files/start_memory_forensics_scan and
/api/files/mvt_scan routes (routes/file_explorer.py) - narrowed from an
earlier design that would have needed this module to import worker
functions from both of those blueprints directly, which a full-repo grep
confirmed this app has never done anywhere (every routes/*.py Blueprint
only ever imports from core/, never from another routes/*.py file) -
confirmed with the user this was worth avoiding rather than introducing
as a first exception.
"""
import os
import re

from flask import Blueprint, request, jsonify

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, case_consolidated_path, log_chain_of_custody
from core.jobs import _read_case_file
from core.tsk_utils import classify_image_profile

auto_analyze_bp = Blueprint('auto_analyze', __name__)

# Server-side mirror of static/js/main.js's isMemoryImageFile() -
# authoritative detection needs its own server-side copy, since Auto
# Analyze's /detect route can't rely on client-side JS. The .raw overlap
# with disk images is the same already-disclosed, already-accepted
# ambiguity documented at static/js/main.js's own isMemoryImageFile()
# (both WinPmem memory dumps and dc3dd/dd disk images commonly use .raw) -
# handled below by returning an explicit "ambiguous" profile for .raw,
# never a silent guess.
MEMORY_IMAGE_EXTENSIONS = {'.mem', '.vmem', '.dmp', '.lime'}  # unambiguous - no disk-imaging tool in this app ever produces these
DISK_IMAGE_EXTENSIONS = {'.dd', '.e01', '.img', '.aff', '.001'}  # unambiguous - never used for a memory capture
_AMBIGUOUS_EXTENSIONS = {'.raw'}

_UDID_RE = re.compile(r'^[a-fA-F0-9\-]{20,64}$')  # mirrors routes/mobile.py's own pattern - not imported (see this module's own docstring on why routes/*.py files don't import each other)


def _mobile_profile_from_case_event(path, case_folder):
    """Checks the active case's own event history for a COMPLETED mobile
    acquisition whose output_destination resolves to this exact path -
    mirrors routes/reporting.py's _collect_case_timeline() lookup pattern
    (status + safe_path() gating), just keyed on output_destination (the
    real field name mobile events use) instead of output_image_path (disk
    images) - confirmed these are genuinely different keys before writing
    this, not assumed. Returns 'mobile_ios'/'mobile_android' or None."""
    if not case_folder:
        return None
    case_file = case_consolidated_path(case_folder)
    if not case_file:
        return None
    case_record = _read_case_file(case_file)
    for event in case_record.get('events', []):
        if event.get('acquisition_status') != 'COMPLETED':
            continue
        raw_dest = event.get('acquisition_parameters', {}).get('output_destination')
        if not raw_dest:
            continue
        resolved = safe_path(raw_dest)
        if not resolved or resolved != path:
            continue
        tool = event.get('tool', '')
        if tool == 'ios_backup':
            return 'mobile_ios'
        if tool.startswith('android_'):
            return 'mobile_android'
    return None


def _looks_like_ios_backup_dir(path):
    """Structural fallback when no case event matches: idevicebackup2
    --full writes into <dest_dir>/<UDID>/ containing Manifest.db and
    Info.plist (routes/mobile.py's own execution_worker_ios_backup, which
    this module doesn't import - see this module's own docstring). Checks
    both "path IS the UDID folder" and "path CONTAINS a UDID folder"
    shapes, since an examiner could select either the backup's own
    top-level UDID directory or its parent."""
    def _has_backup_markers(d):
        return os.path.isfile(os.path.join(d, 'Manifest.db')) and os.path.isfile(os.path.join(d, 'Info.plist'))

    base = os.path.basename(path.rstrip('/\\'))
    if _UDID_RE.match(base) and _has_backup_markers(path):
        return True
    try:
        for entry in os.listdir(path):
            if _UDID_RE.match(entry):
                sub = os.path.join(path, entry)
                if os.path.isdir(sub) and _has_backup_markers(sub):
                    return True
    except OSError:
        pass
    return False


@auto_analyze_bp.route('/api/auto_analyze/detect', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def auto_analyze_detect():
    req = request.get_json() or {}
    path = safe_path(req.get('path'))
    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    if case_folder and not case_consolidated_path(case_folder):
        case_folder = None

    if not path or not os.path.exists(path):
        return jsonify({"success": False, "error": "File or folder not found or outside the permitted evidence directory."}), 400

    mobile_hint = _mobile_profile_from_case_event(path, case_folder)
    if mobile_hint:
        log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": mobile_hint, "signal": "case_event"})
        return jsonify({"success": True, "profile": mobile_hint, "signal": "case_event", "filesystems": []})

    if os.path.isdir(path):
        if _looks_like_ios_backup_dir(path):
            log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": "mobile_ios", "signal": "structural"})
            return jsonify({"success": True, "profile": "mobile_ios", "signal": "structural", "filesystems": []})
        # A directory that's neither a known case event's mobile output
        # nor iOS-backup-shaped (most commonly an ad-hoc Android `pull`
        # folder, which - per this app's own established documentation -
        # has no reliable structural signal at all) - never guessed.
        log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": "unknown_mobile", "signal": "none"})
        return jsonify({"success": True, "profile": "unknown_mobile", "signal": "none", "filesystems": []})

    ext = os.path.splitext(path)[1].lower()
    if ext in MEMORY_IMAGE_EXTENSIONS:
        log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": "memory", "signal": "extension"})
        return jsonify({"success": True, "profile": "memory", "signal": "extension", "filesystems": []})

    if ext in DISK_IMAGE_EXTENSIONS or ext in _AMBIGUOUS_EXTENSIONS:
        result = classify_image_profile(path)
        if ext in _AMBIGUOUS_EXTENSIONS and result["profile"] == "unknown":
            # .raw with no recognizable filesystem inside it - plausibly a
            # memory dump instead of a disk image. Never silently assumed
            # either way.
            log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": "ambiguous", "signal": "extension_raw"})
            return jsonify({"success": True, "profile": "ambiguous", "candidates": ["memory", "windows", "linux"],
                             "signal": "extension_raw", "filesystems": []})
        log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": result["profile"], "signal": "filesystem"})
        return jsonify({"success": True, "profile": result["profile"], "signal": "filesystem",
                         "filesystems": result["filesystems"]})

    log_chain_of_custody("auto_analyze_detect", {"path": path, "detected_profile": "unknown", "signal": "none"})
    return jsonify({"success": True, "profile": "unknown", "signal": "none", "filesystems": []})
