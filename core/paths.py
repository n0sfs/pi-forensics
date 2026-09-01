"""Path-safety, chain-of-custody logging, and file-classification helpers
shared across every routes/*.py module that touches the filesystem.

Part of the app.py -> core/ + routes/ split - pure code motion, no
behavior change. See the dated CLAUDE.md entry for this refactor.
"""
import os
import re
import time
import json
import threading
from flask import request, g

from core.config import EVIDENCE_ROOT, COC_LOG_FILE

coc_log_lock = threading.Lock()

# --- Block Device Path Validation ---
# Shared by routes/recovery.py, routes/acquisition.py (still inline in
# app.py pending its own extraction), and routes/settings.py's drive
# management - a genuinely cross-module helper, not recovery- or
# acquisition-specific despite living next to the acquisition-flavored
# BitLocker helpers in the original app.py.
_DEVICE_RE = re.compile(r'^/dev/(sd[a-z]|nvme\d+n\d+|mmcblk\d+)$')
_PARTITION_RE = re.compile(r'^/dev/(sd[a-z]\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$')

def is_valid_block_device(path_str):
    """Whitelist check for whole-disk device paths (no partitions, no shell metacharacters)."""
    return bool(path_str) and bool(_DEVICE_RE.match(path_str))

def is_valid_block_device_or_partition(path_str):
    """Whole-disk OR one-partition device path - originally BitLocker-unlock-
    specific (BitLocker most commonly encrypts a single partition, but some
    BitLocker-To-Go USB media format the whole device with no partition
    table at all, so both forms were accepted), generalized here now that
    Live Device Preview needs the exact same "whole disk or partition"
    check. Moved out of routes/acquisition.py rather than kept as a second,
    independent copy of the same regex - see is_valid_bitlocker_source()
    there, now a thin alias onto this function."""
    return bool(path_str) and (bool(_DEVICE_RE.match(path_str)) or bool(_PARTITION_RE.match(path_str)))

def log_chain_of_custody(action, details=None, source_ip=None, user=None):
    # source_ip/user let a caller running outside the original Flask request
    # context (e.g. a background daemon thread, like network config's
    # delayed auto-revert) supply values captured earlier - request/g are
    # request-context-bound proxies and raise RuntimeError if touched from a
    # thread that never received the HTTP request itself. Every existing
    # call site is unaffected (both default to None, falling back to the
    # live request context exactly as before).
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details or {},
        "source_ip": source_ip if source_ip is not None else (request.headers.get('X-Real-IP', request.remote_addr) if request else None),
        "user": user if user is not None else getattr(g, 'forensic_user', None),
    }
    with coc_log_lock:
        try:
            os.makedirs(os.path.dirname(COC_LOG_FILE), exist_ok=True)
            with open(COC_LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Error writing chain-of-custody log: {e}")

def safe_path(path_str):
    """
    Resolve a user-supplied path and confirm it stays within EVIDENCE_ROOT.

    Prevents path traversal (../..), absolute-path escapes, and symlink
    tricks in every endpoint that takes a path from the client (file
    browser, copy/delete, report load/save, hash verification, PDF export,
    dd/ddrescue acquisition source & destination).
    Returns the resolved absolute path, or None if it escapes the sandbox.
    """
    if not path_str:
        return None
    resolved = os.path.realpath(path_str)
    if resolved == EVIDENCE_ROOT or resolved.startswith(EVIDENCE_ROOT + os.sep):
        return resolved
    return None

_CASE_SLUG_INVALID_RE = re.compile(r'[^A-Za-z0-9_-]+')

def sanitize_case_slug(raw):
    """
    Turn an examiner-typed case number into a filesystem-safe folder name.
    Whitelist-based (like _DEVICE_RE elsewhere) rather than blacklisting bad
    characters, so this can never be tricked into producing '..' or an
    absolute-path-looking result. Returns None if nothing usable is left.
    """
    if not raw:
        return None
    slug = _CASE_SLUG_INVALID_RE.sub('_', raw.strip())
    slug = re.sub(r'_+', '_', slug).strip('_')
    return slug[:80] or None

def case_consolidated_path(dest_path):
    """Returns the case's consolidated-file path if `dest_path` IS a case
    folder root (checked directly, no ancestor walk - matches how the
    frontend sends `destination` as the case folder itself verbatim once a
    case is active), else None.

    Runs `dest_path` through safe_path() itself - this function is used
    throughout the app (core/jobs.py, core/case_index_db.py,
    routes/reporting.py, routes/image_browser.py, routes/file_explorer.py)
    as *the* gate for "is this a legitimate case folder," including several
    call sites that pass a raw, client-supplied `case_folder` straight here
    with no sandboxing of their own - found during the 2026-08-22 security
    audit to be trusting only os.path.isdir() + a marker-file-name match,
    neither of which implies the path is anywhere near EVIDENCE_ROOT. A
    downstream function (case_index_db_path()) happened to safe_path() its
    own derived path anyway, which is what kept this from being directly
    exploitable - but that was two functions incidentally agreeing, not a
    designed guarantee, and it left a directory-listing side channel open
    in at least one caller before that downstream check ever ran. Every
    real case folder already lives under EVIDENCE_ROOT by construction
    (create_case()), so this can never reject a legitimate one."""
    resolved = safe_path(dest_path)
    if not resolved or not os.path.isdir(resolved):
        return None
    slug = os.path.basename(resolved.rstrip(os.sep))
    case_file = os.path.join(resolved, f"{slug}_case.json")
    return case_file if os.path.isfile(case_file) else None

# --- Per-case analysis index (SQLite) extension/category classification ---
# A single small, queryable index living inside the case folder - what makes
# Autopsy-style "File Views" (By Extension counts, Deleted Files, Keyword
# Hits broken out per category) possible without re-walking every indexed
# image on every File Explorer load. Path derivation for the DB itself lives
# in core/case_index_db.py; this module only owns the extension/category
# classification used both there and by report attachment embedding.
EXTENSION_CATEGORY_MAP = {
    'jpg': 'images', 'jpeg': 'images', 'png': 'images', 'gif': 'images', 'bmp': 'images',
    'webp': 'images', 'tif': 'images', 'tiff': 'images', 'heic': 'images', 'heif': 'images',
    'mp4': 'videos', 'mov': 'videos', 'avi': 'videos', 'mkv': 'videos', 'wmv': 'videos',
    'flv': 'videos', 'm4v': 'videos', '3gp': 'videos',
    'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'm4a': 'audio', 'aac': 'audio', 'ogg': 'audio',
    'zip': 'archives', 'rar': 'archives', '7z': 'archives', 'tar': 'archives', 'gz': 'archives', 'bz2': 'archives',
    'pdf': 'documents', 'doc': 'documents', 'docx': 'documents', 'xls': 'documents', 'xlsx': 'documents',
    'ppt': 'documents', 'pptx': 'documents', 'txt': 'documents', 'rtf': 'documents', 'csv': 'documents',
    'exe': 'executables', 'dll': 'executables', 'bat': 'executables', 'sh': 'executables',
    'bin': 'executables', 'msi': 'executables', 'apk': 'executables',
}
FILE_VIEW_EXTENSION_CATEGORIES = ('images', 'videos', 'audio', 'archives', 'documents', 'executables', 'other')

_CASE_ROLE_BACKUP_SUFFIXES = ('.pre_consolidation_backup', '.pre_restore_backup')
_CASE_ROLE_REPORT_SUFFIXES = (
    '_case.json', '_case.pdf', '_case.html', '_case_index.db',
    '_case.json.sha256', '_case.pdf.sha256', '_case.html.sha256',
    '_report.json',  # legacy per-job report (pre-consolidated-schema cases)
)
_CASE_ROLE_ANALYSIS_LOG_RE = re.compile(
    r'(_hash_manifest_\w+\.txt|_triage_scan_report\.txt|_vol3_\w+\.json|_device_timestamps\.json'
    r'|_(aleapp|ileapp)_output|_sqlite_dissect_recovery|_apk_analysis\.json|_bugreport_parsed\.json'
    r'|_ios_crash_reports|_mft_analysis\.json|_usnjrnl_parsed\.json|_thumbcache_extracted'
    r'|^live_collection_import_\d{8}_\d{6})$')
_CASE_ROLE_BUNDLE_RE = re.compile(r'_case_bundle_\d{8}-\d{6}\.zip$')

def classify_case_role(name):
    """Best-effort classification of a filename (or, for the folder-shaped
    kinds below, a directory name) as one of this app's own generated
    case-artifact kinds - 'report' (the case JSON/PDF/HTML export
    and their .sha256 sidecars, the per-case SQLite index, a legacy per-job
    report), 'analysis_log' (a hash-manifest report, a triage-scan report,
    a Volatility3 memory-forensics plugin result, an android_pull's
    captured-on-device-timestamps manifest, an ALEAPP/iLEAPP mobile-artifact-parser output
    folder, a Thumbcache thumbnail-extraction output folder, or a Live
    Collection USB import folder - the same "derived/analysis output
    living in its own folder" shape ALEAPP/iLEAPP already established),
    'geolocation' (a
    .kml), 'backup' (a pre-consolidation/pre-restore snapshot), 'case_bundle'
    (a Case Bundle Export zip - matched by its own timestamped naming
    pattern, NOT the plain .zip extension, which classify_extension()
    already treats as a generic 'archives' file an examiner might have
    added themselves), or None for anything that isn't a recognized
    artifact kind (real evidence, an examiner-added note, etc.).
    Deliberately narrow and pattern-matched against this app's own actual
    naming conventions, not a general file-type classifier - see
    classify_extension() above for that. Used to visually group these
    files in File Explorer's folder tree (case_role dividers, separate
    from actual case data) and to auto-tag them into the per-case analysis
    index at the moment each is generated.
    """
    lower = name.lower()
    if _CASE_ROLE_BUNDLE_RE.search(name):
        return 'case_bundle'
    if lower.endswith(_CASE_ROLE_BACKUP_SUFFIXES):
        return 'backup'
    if name == 'case_info.json' or lower.endswith(tuple(s.lower() for s in _CASE_ROLE_REPORT_SUFFIXES)):
        return 'report'
    if _CASE_ROLE_ANALYSIS_LOG_RE.search(name) or lower.endswith('.log'):
        return 'analysis_log'
    if lower.endswith('.kml'):
        return 'geolocation'
    return None

def classify_extension(name):
    """Returns (category, extension) for a filename - extension is the bare,
    lowercased suffix with no leading dot ('' if none); category is one of
    FILE_VIEW_EXTENSION_CATEGORIES, defaulting to 'other' for anything not in
    EXTENSION_CATEGORY_MAP. Deliberately not exhaustive - documented as a
    reasonable, extensible starting set, not a claim of complete coverage."""
    ext = os.path.splitext(name)[1].lstrip('.').lower()
    return EXTENSION_CATEGORY_MAP.get(ext, 'other'), ext


def format_epoch(ts):
    """Formats a Unix timestamp as "%Y-%m-%d %H:%M:%S", or None for a falsy/
    missing/unrepresentable one - never guesses. Moved here from routes/
    file_explorer.py (2026-08-29) once routes/reporting.py's own folder-
    based timeline collection needed the exact same formatting a second
    routes/*.py module can't import from another; this is the shared home.

    time.localtime(None) silently defaults to the CURRENT time rather than
    raising - a falsy/missing timestamp must be rejected explicitly here,
    not left to the caller to remember to guard against, or a genuinely-
    unknown timestamp would render as "right now" instead of "Unknown"."""
    if not ts:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OSError, OverflowError, ValueError):
        return None
