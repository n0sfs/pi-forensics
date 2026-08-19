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

def is_valid_block_device(path_str):
    """Whitelist check for whole-disk device paths (no partitions, no shell metacharacters)."""
    return bool(path_str) and bool(_DEVICE_RE.match(path_str))

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
    case is active), else None."""
    if not dest_path or not os.path.isdir(dest_path):
        return None
    slug = os.path.basename(dest_path.rstrip(os.sep))
    case_file = os.path.join(dest_path, f"{slug}_case.json")
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

def classify_extension(name):
    """Returns (category, extension) for a filename - extension is the bare,
    lowercased suffix with no leading dot ('' if none); category is one of
    FILE_VIEW_EXTENSION_CATEGORIES, defaulting to 'other' for anything not in
    EXTENSION_CATEGORY_MAP. Deliberately not exhaustive - documented as a
    reasonable, extensible starting set, not a claim of complete coverage."""
    ext = os.path.splitext(name)[1].lstrip('.').lower()
    return EXTENSION_CATEGORY_MAP.get(ext, 'other'), ext
