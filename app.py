import os
import re
import io
import csv
import math
import secrets
import sqlite3
import html
import base64
import sys
import uuid
import pwd
import grp
import stat
import glob
import hmac
import time
import json
import fcntl
import signal
import mimetypes
import ipaddress
import urllib.request
import xml.etree.ElementTree as ET
import psutil
import pytsk3
import shutil
import hashlib
import tempfile
import textwrap
import subprocess
import threading
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response, send_file, g, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

# --- core/ - shared, cross-cutting state and helpers, pulled out of this
# file's own top-of-file block as part of the app.py -> core/ + routes/
# split (Step 0: extraction only, no routes physically moved yet). See the
# dated CLAUDE.md entry for this refactor for the full rationale.
from core.config import (
    ADMIN_USER, ADMIN_PASS, INSTALL_DIR, HISTORY_FILE, SCALPEL_CONF_PATH,
    MVT_BIN_DIR, MVT_IOS_BIN, MVT_ANDROID_BIN, TLS_CERT_PATH, TLS_KEY_PATH,
    RUNTIME_CONFIG_FILE, SECRET_KEY_FILE, MOUNT_KEY_FILE, COC_LOG_FILE,
    EVIDENCE_ROOT, ALLOWED_HASH_ALGOS,
    load_runtime_config, save_runtime_config, get_active_admin_pass,
    get_report_defaults, get_custom_case_fields,
    _get_or_create_secret_key, _get_or_create_mount_key,
    _encrypt_secret, _decrypt_secret,
)
from core.auth import (
    PERMISSION_KEYS, KIOSK_AUTH_BYPASS_ENABLED,
    MAX_AUTH_FAILURES, LOCKOUT_SECONDS,
    requires_auth, requires_permission, check_auth,
    is_local_kiosk_request, get_offline_tiles_info,
    find_user, find_group, get_user_groups, get_user_group_id,
    get_current_user_permissions, get_current_user_role,
    caller_reauth_ok, _session_user_still_valid, _safe_next_path,
    _record_last_login,
)
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job,
    get_active_proc, set_active_proc, clear_active_proc,
    _stream_subprocess, CaseEventTarget,
    build_report_target, write_initial_report, _write_report,
    _case_upsert_event, _read_case_file, _write_case_file,
    reclaim_ownership,
)
from core.paths import (
    safe_path, log_chain_of_custody, sanitize_case_slug,
    case_consolidated_path, classify_extension,
    EXTENSION_CATEGORY_MAP, FILE_VIEW_EXTENSION_CATEGORIES,
)
from core.case_index_db import (
    case_index_db_path, _CASE_INDEX_SCHEMA, _case_index_connect,
    _case_index_open_readonly, _case_index_open_write,
    _tags_for_paths, _analysis_results_for_paths, _record_analysis_result,
    TRIAGE_PATTERNS, TRIAGE_MAX_MATCHES_PER_CATEGORY, TRIAGE_CATEGORY_LABELS,
)
from core.tsk_utils import (
    _tsk_walk, _tsk_resolve_filesystems, _tsk_entry_dict,
    _tsk_open_fs, _tsk_list_dir, _tsk_stream_file, _tsk_parse_inode,
    TSK_DEFAULT_SECTOR_SIZE, TSK_READ_CHUNK_BYTES,
    TSK_MAX_WALK_DIRS, TSK_MAX_WALK_DEPTH, TSK_MAX_TIMELINE_ENTRIES,
)

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Deliberately left at Flask's default (False), not hardcoded True: this app
# supports both TLS-optional and plain-HTTP deployment (see install.py's TLS
# prompt, which already discloses "without TLS, credentials are sent over
# plain HTTP" as an accepted tradeoff for a LAN appliance), there's no
# ProxyFix/X-Forwarded-Proto handling here to reliably detect TLS at runtime,
# and Secure=False cookies are sent over both HTTP and HTTPS (Secure=True is
# the one that *restricts*, so leaving this False never regresses the
# HTTPS-configured case, only avoids silently breaking the HTTP-only one).
app.config['PERMANENT_SESSION_LIFETIME'] = 12 * 60 * 60  # 12h - a workstation shift, not a web app's short-lived token

# All of the above (ADMIN_USER/ADMIN_PASS, INSTALL_DIR and every path
# derived from it, the secret/mount key helpers, log_chain_of_custody(),
# load/save_runtime_config(), EVIDENCE_ROOT, etc.) now live in core/config.py
# and core/paths.py, imported at the top of this file - see the Step 0
# core/ extraction. The one thing that has to stay here rather than move
# into core/config.py itself: this exact call, in this exact position
# (right after `app = Flask(__name__)` above), since it does real
# filesystem I/O (creates/chmods the key file on first run) and must fire
# exactly once, at this module's own top level.
app.secret_key = _get_or_create_secret_key()

# job_lock/current_job/update_job/snapshot_job/active_proc, the auth
# lockout tracker, and _record_last_login now live in core/jobs.py and
# core/auth.py respectively (imported at the top of this file) - see the
# Step 0 core/ extraction.

last_net_check = {"time": time.time(), "bytes_sent": 0, "bytes_recv": 0}
# Per-interface equivalent of last_net_check above, keyed by interface name -
# used by get_network_interfaces() so each interface's hover tooltip shows
# its own real throughput instead of the station-wide aggregate repeated
# identically on every pill (including a down interface, which was showing
# the same nonzero figures as whichever interface was actually active).
last_pernic_check = {}

# --- Network Configuration (static IP / DHCP) pending-revert state ---
# Single shared state, station-wide, mirroring current_job's one-thing-at-a-
# time pattern above - only one network change can be pending confirmation
# at once. A background thread applies the change, a second background
# thread reverts it automatically unless confirmed within the window, which
# is the whole safety story for this feature: a bad static IP/gateway can
# lock the examiner out of the very page they'd use to fix it, the same way
# a plain DHCP reassignment already did once during development.
network_config_lock = threading.Lock()
pending_network_revert = None  # dict or None, see apply_network_config()
REVERT_WINDOW_SECONDS = 60

# --- Persistence Helpers ---
def load_mount_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading mount history: {e}")
            return []
    return []

def save_mount_history(entry):
    history = load_mount_history()
    history = [h for h in history if not (h.get("host") == entry.get("host") and h.get("share") == entry.get("share"))]
    history.insert(0, entry)
    history = history[:10]
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving mount history: {e}")

# --- Authentication Middleware ---
# Computed once at import time so check_auth() always has a real hash to
# compare against for a nonexistent username - without this, a lookup miss
# would return instantly while a real user takes as long as a scrypt hash
# comparison, a timing side-channel that leaks which usernames exist.
# _DUMMY_PASSWORD_HASH, find_user, check_auth, _session_user_still_valid,
# is_local_kiosk_request, get_offline_tiles_info, _plain_401,
# _is_locked_out/_record_auth_failure/_record_auth_success, requires_auth,
# PERMISSION_KEYS and its group/permission helpers, get_user_groups,
# find_group, get_user_group_id, get_current_user_permissions,
# get_current_user_role, caller_reauth_ok, requires_permission, and
# safe_path all now live in core/auth.py and core/paths.py (imported at the
# top of this file) - see the Step 0 core/ extraction.

# --- Block Device Path Validation ---
_DEVICE_RE = re.compile(r'^/dev/(sd[a-z]|nvme\d+n\d+|mmcblk\d+)$')

def is_valid_block_device(path_str):
    """Whitelist check for whole-disk device paths (no partitions, no shell metacharacters)."""
    return bool(path_str) and bool(_DEVICE_RE.match(path_str))

_PARTITION_RE = re.compile(r'^/dev/(sd[a-z]\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$')

def is_valid_bitlocker_source(path_str):
    """Whole-disk OR partition path - BitLocker most commonly encrypts a
    single partition, but some BitLocker-To-Go USB media format the whole
    device with no partition table at all, so both forms are accepted."""
    return bool(path_str) and (bool(_DEVICE_RE.match(path_str)) or bool(_PARTITION_RE.match(path_str)))

# --- BitLocker: unlock an encrypted source via dislocker, so it can be
# imaged decrypted instead of as raw encrypted bytes. A dislocker mount
# exposes the decrypted volume as a single virtual file ("dislocker-file")
# inside a FUSE mountpoint - once mounted, that file is used as the
# acquisition `source` exactly like a real block device would be (dc3dd/
# dcfldd/ewfacquire/plain dd all just read from whatever path they're given,
# real device or regular file). Recording the recovery key itself as case
# documentation (separate from this unlock mechanism) is handled by
# start_imaging()/start_ddrescue()'s own bitlocker_key field - see the
# comment there for why that's stored in plaintext rather than encrypted at
# rest, unlike network-mount credentials.
DISLOCKER_MOUNT_ROOT = os.path.join(INSTALL_DIR, ".bitlocker_mounts")
bitlocker_lock = threading.Lock()
active_bitlocker_mounts = {}  # mount_id -> {mount_dir, device, source_path, unlocked_at}

def _list_device_partitions(device):
    """Real partitions of a whole-disk device via lsblk - JSON output, not
    parsed text, so a device/label containing unusual characters can't
    confuse column-based parsing."""
    if not is_valid_block_device(device):
        return []
    try:
        res = subprocess.run(
            ['lsblk', '-J', '-o', 'NAME,SIZE,FSTYPE,TYPE', device],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode != 0:
            return []
        data = json.loads(res.stdout)
        partitions = []
        for dev in data.get('blockdevices', []):
            for child in dev.get('children', []):
                if child.get('type') == 'part':
                    partitions.append({
                        "path": f"/dev/{child['name']}",
                        "size": child.get('size'),
                        "fstype": child.get('fstype'),
                    })
        return partitions
    except Exception:
        return []

def _detect_bitlocker(partition):
    """Best-effort BitLocker signature check via blkid - not authoritative
    (a wrong/no answer here doesn't block trying to unlock anyway), just a
    helpful hint in the UI before the examiner types in a recovery key."""
    if not is_valid_bitlocker_source(partition):
        return None
    try:
        res = subprocess.run(
            ['sudo', '/sbin/blkid', '-o', 'value', '-s', 'TYPE', partition],
            capture_output=True, text=True, timeout=10
        )
        fstype = res.stdout.strip()
        return {"fstype": fstype, "is_bitlocker": fstype.lower() == 'bitlocker'}
    except Exception:
        return {"fstype": None, "is_bitlocker": False}

def _detect_bitlocker_image(image_path, offset=0):
    """Best-effort BitLocker signature check for an already-acquired evidence
    image (or a specific partition's byte offset within it) - a direct
    read of the on-disk BitLocker boot-sector signature ("-FVE-FS-",
    replacing NTFS's normal "NTFS    " signature at the same location, byte
    3 of the boot sector) rather than shelling out to blkid. No sudo
    needed: unlike a live device, an evidence image file is already owned
    by this app's own unprivileged service account (reclaim_ownership()
    already handed it back after acquisition), so a plain read is enough."""
    validated = safe_path(image_path)
    if not validated or not os.path.isfile(validated):
        return None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return None
    try:
        with open(validated, 'rb') as f:
            f.seek(offset + 3)
            sig = f.read(8)
        return {"is_bitlocker": sig == b'-FVE-FS-'}
    except OSError:
        return {"is_bitlocker": False}

def _dislocker_unlock(source_path, recovery_key, offset=None):
    """Mounts a BitLocker-encrypted volume via dislocker, given a 48-digit
    recovery key (dashes optional - dislocker accepts either form).
    Two modes, selected by whether `offset` is given:
      - offset=None: `source_path` is a live device/partition path (the
        pre-acquisition "unlock before imaging" flow) - validated via
        is_valid_bitlocker_source().
      - offset=<int>: `source_path` is an already-acquired evidence image
        file, and the encrypted volume starts at the given byte offset
        within it (dislocker's own -O/--offset flag - needed for a
        multi-partition raw disk image, e.g. EFI + Recovery + an
        encrypted C: partition all in one .dd file). Validated via
        safe_path() like every other image-accepting route in this app,
        not is_valid_bitlocker_source() (which only recognizes /dev/*
        paths).
    Returns (success, mount_id_or_None, source_path_or_None,
    error_or_None). The mountpoint is entirely server-controlled (a fresh
    directory under DISLOCKER_MOUNT_ROOT, never a client-supplied path) -
    this is what lets _resolve_acquisition_source() below safely trust a
    `source` path later: only a path this function itself just created and
    registered can ever match an active_bitlocker_mounts entry."""
    if offset is None:
        if not is_valid_bitlocker_source(source_path):
            return False, None, None, "Invalid or unrecognized device/partition path."
    else:
        validated = safe_path(source_path)
        if not validated or not os.path.isfile(validated):
            return False, None, None, "Image file not found or outside the permitted evidence directory."
        source_path = validated
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            return False, None, None, "Invalid partition offset."

    recovery_key = (recovery_key or '').strip()
    if not recovery_key:
        return False, None, None, "Recovery key/password is required."

    original_source = source_path  # captured before the local `source_path` name gets reused below for the *decrypted* file's path

    os.makedirs(DISLOCKER_MOUNT_ROOT, exist_ok=True)
    mount_id = uuid.uuid4().hex
    mount_dir = os.path.join(DISLOCKER_MOUNT_ROOT, mount_id)
    os.makedirs(mount_dir, exist_ok=False)

    cmd = ["sudo", "/sbin/dislocker", "-V", original_source]
    if offset:
        cmd += ["-O", str(offset)]
    cmd += [f"-p{recovery_key}", "--", mount_dir]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        return False, None, None, "dislocker timed out - the device may be unresponsive."
    except FileNotFoundError:
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        return False, None, None, "dislocker is not installed on this station. Run 'sudo apt-get install dislocker' first."

    decrypted_path = os.path.join(mount_dir, "dislocker-file")
    if res.returncode != 0 or not os.path.exists(decrypted_path):
        # dislocker's own FUSE mount can be left half-attached on failure -
        # try to clean it up either way before reporting the error. Plain
        # umount (not fusermount/fusermount3) works fine here since this
        # always runs as root via sudo already - the fusermount helper's
        # whole purpose is letting an *unprivileged* user unmount their own
        # FUSE mount, which doesn't apply here, and this also sidesteps
        # needing to guess whether this station's fuse3 package names the
        # binary fusermount or fusermount3.
        try:
            subprocess.run(["sudo", "/bin/umount", mount_dir], capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        err = (res.stderr or res.stdout or "Unknown dislocker error.").strip()
        return False, None, None, f"Unlock failed - check the recovery key/password: {err[:300]}"

    with bitlocker_lock:
        active_bitlocker_mounts[mount_id] = {
            "mount_dir": mount_dir,
            "device": original_source,
            "source_path": decrypted_path,
            "unlocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    return True, mount_id, decrypted_path, None

def _dislocker_lock(mount_id):
    """Unmounts and cleans up a dislocker mount. Safe to call more than
    once for the same id - a second call just finds nothing left to do."""
    if not mount_id:
        return True, None
    with bitlocker_lock:
        info = active_bitlocker_mounts.pop(mount_id, None)
    if not info:
        return True, None
    mount_dir = info["mount_dir"]
    try:
        # See the matching comment in _dislocker_unlock() above - plain
        # umount (already sudoers-granted, no new grant needed) instead of
        # fusermount/fusermount3, since this always runs as root.
        subprocess.run(["sudo", "/bin/umount", mount_dir], capture_output=True, timeout=15)
    except Exception as e:
        return False, f"Failed to unmount: {e}"
    try:
        os.rmdir(mount_dir)
    except OSError:
        pass
    return True, None

def _resolve_acquisition_source(source):
    """Returns (actual_source_path, is_real_block_device, bitlocker_mount_id).
    If `source` exactly matches a currently-registered dislocker mount's own
    decrypted virtual file path, it's trusted as a valid acquisition source
    without needing to pass is_valid_block_device() - only a path this app's
    own _dislocker_unlock() just created can ever match, since mountpoints
    live under DISLOCKER_MOUNT_ROOT and are never client-supplied."""
    with bitlocker_lock:
        for mount_id, info in active_bitlocker_mounts.items():
            if info["source_path"] == source:
                return source, False, mount_id
    return source, True, None

# sanitize_case_slug and reclaim_ownership now live in core/paths.py and
# core/jobs.py respectively (imported at the top of this file) - see the
# Step 0 core/ extraction.

# --- Hash & Recovery Output Parsers ---
def parse_dc3dd_hashes(log_path):
    hashes = {}
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                content = f.read()
                matches = re.findall(r'([a-fA-F0-9]{32,64})\s*\(\s*(\b(?:md5|sha1|sha256)\b)\s*\)', content, re.IGNORECASE)
                for val, algo in matches:
                    hashes[algo.lower()] = val
                    
                if not hashes:
                    fallback_matches = re.findall(r'(\b(?:md5|sha1|sha256)\b)[^\n:]*:\s*([a-fA-F0-9]{32,64})', content, re.IGNORECASE)
                    for algo, val in fallback_matches:
                        hashes[algo.lower()] = val
        except Exception as e:
            print(f"Error parsing dc3dd log: {e}")
    return hashes

def parse_ewf_hashes(console_log_text):
    hashes = {}
    try:
        matches = re.findall(r'(\b(?:MD5|SHA1|SHA256)\b)\s*(?:hash|hash stored in file)?:?\s*([a-fA-F0-9]{32,64})', console_log_text, re.IGNORECASE)
        for algo, val in matches:
            hashes[algo.lower()] = val
    except Exception as e:
        print(f"Error parsing ewf hashes: {e}")
    return hashes

def parse_dc3dd_line(line):
    m = re.search(r'(\d+)\s+bytes.*copied.*,\s*([\d\.]+)\s*(MB|MiB|KB|GB|M|K)/s', line, re.IGNORECASE)
    if m:
        bytes_copied = int(m.group(1))
        speed_val = float(m.group(2))
        unit = m.group(3).upper()
        
        if unit in ['KB', 'K']:
            speed_val /= 1024.0
        elif unit in ['GB', 'G']:
            speed_val *= 1024.0
            
        return bytes_copied, speed_val
    return None, None

def parse_ewf_line(line):
    m_pct = re.search(r'(\d+)%\s*(?:acquired|done|completed|verified)?', line, re.IGNORECASE)
    m_spd = re.search(r'([\d\.]+)\s*(?:MiB|MB|KiB|KB)/s', line, re.IGNORECASE)
    pct = float(m_pct.group(1)) if m_pct else None
    spd = float(m_spd.group(1)) if m_spd else None
    return pct, spd

def parse_ddrescue_line(line):
    rescued_bytes = None
    pct = None
    spd = None
    
    m_rescued = re.search(r'rescued:\s*([\d\.]+)\s*([KMGT]?B)', line, re.IGNORECASE)
    m_spd = re.search(r'current_rate:\s*([\d\.]+)\s*([KMGT]?B/s)', line, re.IGNORECASE)
    m_pct = re.search(r'pct_rescued:\s*([\d\.]+)\%', line, re.IGNORECASE)

    def to_bytes(val, unit):
        u = unit.upper()
        v = float(val)
        if 'K' in u: return int(v * 1024)
        if 'M' in u: return int(v * 1024**2)
        if 'G' in u: return int(v * 1024**3)
        if 'T' in u: return int(v * 1024**4)
        return int(v)

    if m_rescued:
        rescued_bytes = to_bytes(m_rescued.group(1), m_rescued.group(2))
    if m_pct:
        pct = float(m_pct.group(1))
    if m_spd:
        spd = to_bytes(m_spd.group(1), m_spd.group(2)) / (1024**2)

    return rescued_bytes, pct, spd

# TRIAGE_PATTERNS/TRIAGE_MAX_MATCHES_PER_CATEGORY/TRIAGE_CATEGORY_LABELS,
# EXTENSION_CATEGORY_MAP/FILE_VIEW_EXTENSION_CATEGORIES/classify_extension,
# and the whole per-case SQLite analysis index (case_index_db_path,
# _CASE_INDEX_SCHEMA, _case_index_connect) now live in core/case_index_db.py
# and core/paths.py (imported at the top of this file) - see the Step 0
# core/ extraction. ALLOWED_TAG_COLORS stays here - only routes/case_index.py
# (not yet split out) uses it.
ALLOWED_TAG_COLORS = ('primary', 'secondary', 'success', 'danger', 'warning', 'info')

HASH_HEX_LEN = {'md5': 32, 'sha1': 40, 'sha256': 64}

def read_hash_log_file(path, algo):
    """
    Extract a hex hash of the expected length for `algo` from a dcfldd-style
    hash log file (dcfldd writes one file per algorithm via <algo>log=).
    """
    expected_len = HASH_HEX_LEN.get(algo)
    if not expected_len or not path or not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            content = f.read()
        m = re.search(r'\b([a-fA-F0-9]{%d})\b' % expected_len, content)
        return m.group(1).lower() if m else None
    except Exception as e:
        print(f"Error reading hash log {path}: {e}")
        return None

def compute_file_hashes(file_path, algos, chunk_size=8 * 1024 * 1024):
    """
    Stream-hash a file for one or more algorithms. Used for plain GNU `dd`,
    which - unlike dc3dd/dcfldd/ewfacquire - has no built-in hashing at all.
    """
    hashers = {a: hashlib.new(a) for a in algos if a in ALLOWED_HASH_ALGOS}
    if not hashers or not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
        return {a: h.hexdigest() for a, h in hashers.items()}
    except Exception as e:
        print(f"Error computing hashes for {file_path}: {e}")
        return {}

def parse_affconvert_line(line):
    """affconvert prints progress as 'Converting page N of M'."""
    m = re.search(r'[Cc]onverting page (\d+) of (\d+)', line)
    if m:
        current, total_pages = int(m.group(1)), int(m.group(2))
        if total_pages > 0:
            return round((current / total_pages) * 100, 1)
    return None

def parse_ddrescue_mapfile(map_path):
    summary = {
        "rescued_bytes": 0,
        "non_tried_bytes": 0,
        "bad_sector_bytes": 0,
        "bad_blocks_count": 0
    }
    if os.path.exists(map_path):
        try:
            with open(map_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            size = int(parts[1], 16)
                            status = parts[2]
                            
                            if status == '+':
                                summary["rescued_bytes"] += size
                            elif status in ['?', '*', '/']:
                                summary["non_tried_bytes"] += size
                            elif status == '-':
                                summary["bad_sector_bytes"] += size
                                summary["bad_blocks_count"] += 1
                        except ValueError:
                            pass
        except Exception as e:
            print(f"Error reading mapfile: {e}")
    return summary

# _stream_subprocess now lives in core/jobs.py (imported at the top of this
# file) - see the Step 0 core/ extraction, including the active_proc
# accessor-function fix described there.

def poll_directory_size(path):
    """Ground-truth bytes-on-disk for a file or directory tree, used as a
    progress proxy for tools that don't report a parseable percentage."""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        total = 0
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return total
    except Exception:
        return 0

# --- Consolidated Per-Case Reporting ---
# A "case" started via /api/cases/create now gets exactly one JSON file
# ({slug}_case.json, at the case folder root) that every job run against
# any evidence item in that case appends an "event" to, instead of each of
# the 9 job-starting routes below writing its own separate {base}_report.json.
# No-case-active usage (a destination that isn't a real case folder) keeps
# writing the old flat per-job file, completely unchanged - see
# build_report_target(). Existing cases stay on the old scattered-files
# layout until explicitly migrated (see /api/cases/migrate_preview/_apply);
# there's no silent auto-upgrade, to avoid a case ending up half-migrated.
# CaseEventTarget, case_consolidated_path, _read_case_file/_write_case_file/
# _case_upsert_event, and build_report_target/write_initial_report/
# _write_report now live in core/jobs.py and core/paths.py (imported at the
# top of this file) - see the Step 0 core/ extraction.

# --- Mobile Device Discovery (iOS via libimobiledevice, Android via adb) ---
# These only talk to devices that are already unlocked and have already
# granted trust (iOS "Trust This Computer?") or USB debugging authorization
# (Android RSA key prompt) on-device. Nothing here bypasses a lockscreen,
# jailbreaks, or exploits a device - nothing in this app does.
_UDID_RE = re.compile(r'^[a-fA-F0-9\-]{20,64}$')
_ANDROID_SERIAL_RE = re.compile(r'^[a-zA-Z0-9_\-\.:]{4,64}$')

def list_ios_devices():
    devices = []
    try:
        res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=15)
        udids = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        for udid in udids:
            if not _UDID_RE.match(udid):
                continue
            info = {"udid": udid, "name": "Unknown", "model": "Unknown",
                     "ios_version": "Unknown", "serial": "Unknown", "trusted": True,
                     "build_version": "Unknown", "storage_capacity_gb": "Unknown",
                     "imei": "Unknown", "wifi_mac": "Unknown", "bluetooth_mac": "Unknown",
                     "activation_state": "Unknown"}
            try:
                # ideviceinfo's full dump is already being fetched for the 4
                # fields above - parsing more of it here is free (no extra
                # subprocess call), unlike the Android path below.
                info_res = subprocess.run(["ideviceinfo", "-u", udid], capture_output=True, text=True, timeout=15)
                if info_res.returncode == 0:
                    for line in info_res.stdout.splitlines():
                        if ':' not in line:
                            continue
                        key, _, val = line.partition(':')
                        key, val = key.strip(), val.strip()
                        if key == 'DeviceName':
                            info['name'] = val
                        elif key == 'ProductType':
                            info['model'] = val
                        elif key == 'ProductVersion':
                            info['ios_version'] = val
                        elif key == 'SerialNumber':
                            info['serial'] = val
                        elif key == 'BuildVersion':
                            info['build_version'] = val
                        elif key == 'TotalDiskCapacity':
                            try:
                                info['storage_capacity_gb'] = round(int(val) / (1024**3), 1)
                            except ValueError:
                                pass
                        elif key == 'InternationalMobileEquipmentIdentity':
                            info['imei'] = val
                        elif key == 'WiFiAddress':
                            info['wifi_mac'] = val
                        elif key == 'BluetoothAddress':
                            info['bluetooth_mac'] = val
                        elif key == 'ActivationState':
                            info['activation_state'] = val
                else:
                    # Device is plugged in (usbmuxd sees it) but hasn't
                    # granted "Trust This Computer?" yet - not a bypass
                    # target, just needs the examiner to tap Trust on-device.
                    info['trusted'] = False
            except Exception:
                info['trusted'] = False
            devices.append(info)
    except Exception as e:
        print(f"Error listing iOS devices: {e}")
    return devices

def list_android_devices():
    devices = []
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=15)
        lines = res.stdout.splitlines()
        for line in lines[1:]:  # first line is "List of devices attached"
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            if not _ANDROID_SERIAL_RE.match(serial):
                continue
            state = parts[1] if len(parts) > 1 else "unknown"
            model = "Unknown"
            for tok in parts[2:]:
                if tok.startswith("model:"):
                    model = tok.split(":", 1)[1]

            device = {
                "serial": serial,
                "state": state,  # 'device' = authorized, 'unauthorized' = waiting on RSA prompt, 'offline' = other
                "model": model,
                "authorized": (state == "device"),
                "android_version": "Unknown", "api_level": "Unknown",
                "manufacturer": "Unknown", "build_id": "Unknown",
            }
            # Only query an authorized device - `adb shell` against an
            # unauthorized/offline one just hangs waiting on the RSA prompt
            # or fails outright, unlike iOS where ideviceinfo already runs
            # unconditionally above.
            if device["authorized"]:
                try:
                    props_res = subprocess.run(["adb", "-s", serial, "shell", "getprop"], capture_output=True, text=True, timeout=15)
                    if props_res.returncode == 0:
                        props = {}
                        for line in props_res.stdout.splitlines():
                            m = re.match(r'^\[([^\]]+)\]:\s*\[([^\]]*)\]$', line.strip())
                            if m:
                                props[m.group(1)] = m.group(2)
                        device['android_version'] = props.get('ro.build.version.release', 'Unknown')
                        device['api_level'] = props.get('ro.build.version.sdk', 'Unknown')
                        device['manufacturer'] = props.get('ro.product.manufacturer', 'Unknown')
                        device['build_id'] = props.get('ro.build.display.id', 'Unknown')
                except Exception:
                    pass
            devices.append(device)
    except Exception as e:
        print(f"Error listing Android devices: {e}")
    return devices

def execution_worker(cmd, fmt, total_bytes, out_file, report_file_path, report_data, hashes=None):
    log_history = []
    hashes = hashes or []
    
    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    append_log(f"[*] Starting execution using [{fmt.upper()}] engine...")
    append_log(f"[*] Command: {' '.join(cmd)}")

    start_time = time.time()
    update_job(status="Processing Media...")

    try:
        def on_line(clean_line):
            append_log(clean_line)

            if fmt in ['raw', 'dd', 'dcfldd', 'plain_dd']:
                bytes_copied, speed = parse_dc3dd_line(clean_line)
                updates = {}
                if bytes_copied is not None:
                    updates["transferred_bytes"] = bytes_copied
                    if total_bytes > 0:
                        updates["progress_percent"] = round((bytes_copied / total_bytes) * 100, 1)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            elif fmt == 'e01':
                pct, speed = parse_ewf_line(clean_line)
                updates = {}
                if "verify" in clean_line.lower() or "verifying" in clean_line.lower():
                    updates["status"] = "Verifying Image Integrity..."

                if pct is not None:
                    updates["progress_percent"] = pct
                    if total_bytes > 0:
                        updates["transferred_bytes"] = int((pct / 100.0) * total_bytes)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            elif fmt == 'ddrescue':
                rescued_bytes, pct, speed = parse_ddrescue_line(clean_line)
                updates = {}
                if rescued_bytes is not None:
                    updates["transferred_bytes"] = rescued_bytes
                if pct is not None:
                    updates["progress_percent"] = pct
                elif rescued_bytes is not None and total_bytes > 0:
                    updates["progress_percent"] = round((rescued_bytes / total_bytes) * 100, 1)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

        proc = _stream_subprocess(cmd, on_line)

        time.sleep(1.0)
        computed_hashes = {}
        if fmt == 'e01':
            computed_hashes = parse_ewf_hashes(snapshot_job()["log"])
        elif fmt in ['raw', 'dd']:
            dc3dd_log = out_file.replace('.dd', '_dc3dd.log')
            computed_hashes = parse_dc3dd_hashes(dc3dd_log)
        elif fmt == 'dcfldd':
            for h in hashes:
                val = read_hash_log_file(out_file.replace('.dd', f'_{h}.log'), h)
                if val:
                    computed_hashes[h] = val
        elif fmt == 'plain_dd':
            reclaim_ownership(out_file)  # written by sudo'd dd - must reclaim before we can read it below
            append_log("[*] Computing hash(es) of output file (plain dd has no built-in hashing)...")
            computed_hashes = compute_file_hashes(out_file, hashes)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["computed_verification_hashes"] = computed_hashes

        # dc3dd's own process exit code is not reliable on its own - it can
        # exit 0/2 (treated as success below) while still self-reporting a
        # failure (e.g. an unrecovered read error partway through) via a
        # "dc3dd failed at <timestamp>" line in its own output, distinct
        # from "dc3dd completed at <timestamp>" on genuine success. Since
        # that line is already being streamed into log_history live, check
        # it directly rather than trusting returncode alone for this format.
        dc3dd_self_reported_failure = (
            fmt in ['raw', 'dd'] and 'dc3dd failed at' in "\n".join(log_history)
        )

        if proc.returncode in [0, 2] and not dc3dd_self_reported_failure:
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] Recovery/acquisition completed successfully.")
            report_data["acquisition_status"] = "COMPLETED"

        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            if dc3dd_self_reported_failure:
                append_log("[-] dc3dd reported its own failure (see 'dc3dd failed at ...' above) despite exiting with a code normally treated as success - treating this run as failed.")
            else:
                append_log(f"[-] Process exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # Every format this worker handles (dc3dd/dcfldd/dd/ewfacquire/
        # ddrescue) now runs via sudo to read the raw device - their output
        # lands owned by root. Reclaim regardless of success/failure/stop,
        # so even a partial/failed run's output can still be inspected or
        # deleted afterward by this unprivileged service account.
        reclaim_ownership(os.path.dirname(out_file))
        update_job(active=False)
        clear_active_proc()

def execution_worker_aff(source, dest_path, base_name, hashes, keep_raw, report_file_path, report_data, total_bytes):
    """
    Two-phase AFF acquisition: (1) raw acquisition via dc3dd, with on-the-fly
    hashing - these hashes are the forensic record of what was actually read
    off the device; (2) convert the raw image to .aff via affconvert, which
    repackages the same bytes (compression/segmentation only), so the phase-1
    hashes remain the authoritative acquisition hashes. Real device-to-AFF
    tools (e.g. the old `aimage`) are no longer part of the packaged
    afflib-tools, which only ships file-to-file converters - hence two phases.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    raw_file = os.path.join(dest_path, f"{base_name}.raw")
    dc3dd_log_file = os.path.join(dest_path, f"{base_name}_dc3dd.log")
    aff_file = os.path.join(dest_path, f"{base_name}.aff")

    try:
        # --- Phase 1: raw acquisition (dc3dd) ---
        update_job(format="aff", status="Phase 1/2: Raw Acquisition...",
                   progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=total_bytes)
        append_log(f"[*] Phase 1/2: Acquiring raw image to {raw_file}")

        cmd1 = ["sudo", "/usr/bin/dc3dd", f"if={source}", f"of={raw_file}", f"log={dc3dd_log_file}"]
        for h in hashes:
            cmd1.append(f"hash={h}")
        append_log(f"[*] Command: {' '.join(cmd1)}")

        def on_line_phase1(clean_line):
            append_log(clean_line)
            bytes_copied, speed = parse_dc3dd_line(clean_line)
            updates = {}
            if bytes_copied is not None:
                updates["transferred_bytes"] = bytes_copied
                if total_bytes > 0:
                    # Phase 1 is the first half of overall progress.
                    updates["progress_percent"] = round((bytes_copied / total_bytes) * 50.0, 1)
            if speed is not None:
                updates["speed_mbps"] = speed
            if updates:
                update_job(**updates)

        proc1 = _stream_subprocess(cmd1, on_line_phase1)
        time.sleep(1.0)

        if proc1.returncode not in [0, 2]:
            reclaim_ownership(dest_path)  # hand back whatever partial output exists, even on failure
            if snapshot_job()["status"] != "Stopped":
                update_job(status="Failed")
                append_log(f"[-] Phase 1 (raw acquisition) failed with exit code {proc1.returncode}")
                report_data["acquisition_status"] = "FAILED"
                report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                _write_report(report_file_path, report_data, append_log)
            return

        if snapshot_job()["status"] == "Stopped":
            reclaim_ownership(dest_path)  # hand back whatever phase 1 did produce, even though we're stopping
            return  # user aborted right after phase 1 finished

        # Phase 1 ran via sudo (root, for raw device access) - reclaim
        # before reading the log file directly in Python below, and before
        # phase 2 (affconvert, unprivileged) needs to read the raw file
        # phase 1 just wrote.
        reclaim_ownership(dest_path)

        raw_hashes = parse_dc3dd_hashes(dc3dd_log_file)
        append_log(f"[+] Phase 1 complete. Raw acquisition hashes: {raw_hashes}")
        report_data["computed_verification_hashes"] = raw_hashes

        # --- Phase 2: convert raw -> AFF ---
        update_job(status="Phase 2/2: Converting to AFF...", progress_percent=50.0)
        append_log(f"[*] Phase 2/2: Converting {raw_file} -> {aff_file}")

        cmd2 = ["affconvert", "-o", aff_file, raw_file]
        append_log(f"[*] Command: {' '.join(cmd2)}")

        def on_line_phase2(clean_line):
            append_log(clean_line)
            pct = parse_affconvert_line(clean_line)
            if pct is not None:
                update_job(progress_percent=round(50.0 + pct / 2.0, 1))

        proc2 = _stream_subprocess(cmd2, on_line_phase2)
        time.sleep(0.5)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if proc2.returncode == 0 and os.path.exists(aff_file):
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] AFF conversion completed successfully.")
            report_data["acquisition_status"] = "COMPLETED"

            if keep_raw:
                append_log(f"[*] Intermediate raw image retained per examiner selection: {raw_file}")
                report_data["acquisition_parameters"]["raw_image_retained"] = True
            else:
                try:
                    os.remove(raw_file)
                    append_log(f"[*] Intermediate raw image deleted per examiner selection: {raw_file}")
                    report_data["acquisition_parameters"]["raw_image_retained"] = False
                except Exception as e:
                    append_log(f"[-] Warning: Could not delete intermediate raw image: {e}")
                    report_data["acquisition_parameters"]["raw_image_retained"] = True

        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] Phase 2 (AFF conversion) failed with exit code {proc2.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()

def execution_worker_ios_backup(udid, dest_dir, encrypt_password, report_file_path, report_data):
    """
    idevicebackup2 gives per-file status lines but no global progress
    percentage (open upstream request, unresolved) - so progress here is
    shown as bytes-on-disk (polled from the backup folder), not a percent.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    udid_backup_dir = os.path.join(dest_dir, udid)

    try:
        if encrypt_password:
            append_log("[*] Enabling encrypted backup on device (confirm passcode on-screen if prompted)...")
            update_job(status="Waiting for on-device encryption confirmation...")
            try:
                enc_res = subprocess.run(
                    ["idevicebackup2", "-u", udid, "encryption", "on", encrypt_password],
                    capture_output=True, text=True, timeout=90
                )
                out = (enc_res.stdout + enc_res.stderr).strip()
                if out:
                    append_log(out)
                if enc_res.returncode != 0 and "already" not in out.lower() and "enabled" not in out.lower():
                    update_job(status="Failed")
                    append_log("[-] Could not enable backup encryption. If it's already on with a "
                               "different password, disable it on the device first "
                               "(Settings > General > Transfer or Reset iPhone) or supply that password.")
                    report_data["acquisition_status"] = "FAILED"
                    report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                    _write_report(report_file_path, report_data, append_log)
                    return
            except subprocess.TimeoutExpired:
                update_job(status="Failed")
                append_log("[-] Timed out waiting for encryption confirmation on the device.")
                report_data["acquisition_status"] = "FAILED"
                report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                _write_report(report_file_path, report_data, append_log)
                return

        cmd = ["idevicebackup2", "-u", udid, "backup", "--full", dest_dir]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(format="ios_backup", status="Backing Up Device...", progress_percent=0.0,
                   speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            size = poll_directory_size(udid_backup_dir) if os.path.isdir(udid_backup_dir) else 0
            update_job(transferred_bytes=size)

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=2.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if proc.returncode == 0 and os.path.isdir(udid_backup_dir):
            final_size = poll_directory_size(udid_backup_dir)
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] iOS backup completed successfully. Backup size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] idevicebackup2 exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()

def execution_worker_android(mode, serial, output_path, report_file_path, report_data):
    """
    mode 'backup': adb backup (deprecated/unreliable on Android 12+, requires
    on-device 'Back up my data' confirmation, produces a single .ab file).
    mode 'pull': adb pull of accessible shared storage (more universally
    reliable logical copy, no on-device confirmation needed beyond the
    original USB-debugging authorization).
    mode 'bugreport': adb bugreport (system logs/dumpstate snapshot - useful
    supplementary artifact, not a full acquisition).
    Like iOS, adb gives no clean aggregate percentage either way, so
    progress is bytes-on-disk, polled directly.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()

    try:
        update_job(format=f"android_{mode}", status="Initializing...", progress_percent=0.0,
                   speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

        if mode == 'backup':
            cmd = ["adb", "-s", serial, "backup", "-apk", "-shared", "-all", "-f", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            append_log("[*] Waiting for on-device confirmation ('Back up my data') - check the phone screen.")
            update_job(status="Waiting for device confirmation...")

            def on_poll():
                size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                update_job(transferred_bytes=size, status="Backing Up Device...")
        elif mode == 'bugreport':
            cmd = ["adb", "-s", serial, "bugreport", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            update_job(status="Capturing Bug Report (system logs/dumpstate)...")

            def on_poll():
                size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                update_job(transferred_bytes=size)
        else:
            cmd = ["adb", "-s", serial, "pull", "/sdcard/.", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            update_job(status="Pulling Accessible Storage...")

            def on_poll():
                update_job(transferred_bytes=poll_directory_size(output_path))

        def on_line(clean_line):
            append_log(clean_line)

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=2.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        output_exists = os.path.exists(output_path) and (
            os.path.getsize(output_path) > 0 if mode in ('backup', 'bugreport') else True
        )

        if proc.returncode == 0 and output_exists:
            final_size = poll_directory_size(output_path)
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] Android {mode} completed successfully. Size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] adb {mode} exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()

def execution_worker_photorec(source, dest_dir, report_file_path, report_data):
    """
    PhotoRec file-carving recovery. Only ever reads from `source` and writes
    recovered files to `dest_dir` - never writes back to the source, unlike
    TestDisk's partition-repair mode (which this project deliberately does
    NOT expose, since rewriting a partition table is a write to the
    evidence, conflicting with the write-blocking this whole app is built
    around).

    Scripted-mode syntax is per CGSecurity's own docs (cgsecurity.org/
    testdisk_doc/scripted_run.html): partition_none treats the source as a
    single unpartitioned blob to search (appropriate here since we already
    let the examiner point this at a specific device or a specific image
    file directly, rather than trying to auto-detect partitions).

    No detailed progress percentage is parsed from PhotoRec's output - its
    scripted-mode reporting isn't documented/stable enough to parse safely
    (unlike dc3dd's well-documented format). Progress is bytes recovered so
    far (polled from the destination directory) plus the live log, same
    conservative approach used for the mobile forensics jobs.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="photorec", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = [
            "sudo", "/usr/bin/photorec", "/log", "/d", dest_dir,
            "/cmd", source, "partition_none,options,fileopt,everything,enable,search"
        ]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (PhotoRec)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] PhotoRec recovery completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] photorec exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # photorec now runs via sudo for raw device access - reclaim
        # regardless of outcome, so recovered files can actually be
        # browsed/deleted/copied afterward by this unprivileged service.
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()

def execution_worker_extundelete(source, dest_dir, report_file_path, report_data):
    """
    extundelete recovers deleted files from ext2/3/4 filesystems by
    parsing the filesystem journal - can recover original filenames/paths
    where a normal carving tool (PhotoRec) can't, but only works on
    ext-family filesystems specifically, unlike PhotoRec's format-agnostic
    signature matching.

    Two things this tool needs that others here don't:
    - It writes to RECOVERED_FILES/ in its *working directory* - there's
      no output-path flag - so it's launched with cwd=dest_dir instead.
    - It can block on an interactive y/n safety confirmation about the
      filesystem's journal state - answered via stdin_yes rather than
      risking an indefinite hang.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="extundelete", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        os.makedirs(dest_dir, exist_ok=True)
        cmd = ["sudo", "/usr/bin/extundelete", source, "--restore-all"]
        append_log(f"[*] Command: {' '.join(cmd)} (run from {dest_dir})")
        update_job(status="Recovering Deleted Files (extundelete)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0, cwd=dest_dir, stdin_yes=True)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] extundelete completed. Recovered data in {dest_dir}/RECOVERED_FILES/")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] extundelete exited with code {proc.returncode} - is the source an ext2/3/4 filesystem?")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()

def execution_worker_foremost(source, dest_dir, report_file_path, report_data):
    """
    foremost - signature-based file carving, an alternative to PhotoRec.
    Older and narrower in supported types than PhotoRec, but sometimes
    faster for the common formats it does support.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="foremost", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = ["sudo", "/usr/bin/foremost", "-t", "all", "-i", source, "-o", dest_dir]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (foremost)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        # foremost refuses to run if the output directory already exists -
        # unlike PhotoRec (-Z) it has no flag to force/wipe it, so this
        # must not be pre-created (matches PhotoRec's route not
        # pre-creating job_dest_dir either).
        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] foremost completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] foremost exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()

def execution_worker_scalpel(source, dest_dir, report_file_path, report_data):
    """
    scalpel - signature-based file carving, another PhotoRec alternative,
    multithreaded so sometimes faster on larger images. Ships with every
    file signature disabled by default in its stock config - this uses a
    curated config file installed alongside this app (SCALPEL_CONF_PATH)
    covering common formats (jpg/png/gif/pdf/zip) rather than depending on
    the stock config, which would silently recover nothing if left as-is.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="scalpel", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = ["sudo", "/usr/bin/scalpel", "-c", SCALPEL_CONF_PATH, "-o", dest_dir, source]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (scalpel)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        # Like foremost, scalpel refuses to run against an existing output
        # directory - must not be pre-created.
        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] scalpel completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] scalpel exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()

def execution_worker_triage_scan(source, dest_dir, report_file_path, report_data, total_bytes):
    """
    Built-in triage scan for structured data (emails, URLs, IP addresses,
    credit-card-like numbers, phone numbers) - reads the source directly
    and regex-matches TRIAGE_PATTERNS against it, writing deduplicated
    results to one text file per category. No external tool dependency at
    all (see TRIAGE_PATTERNS above for why that matters), so this can never
    hit a "package not found" wall on any system this app runs on.
    Read-only against the source.

    Honest tradeoff: this is a straightforward single-threaded Python loop,
    not a highly-optimized C/C++ scanner - noticeably slower than a
    dedicated tool on a very large (multi-TB) image. It's well suited to
    the smaller targets (USB drives, phone backups, individual files) this
    project mostly deals with; for a full scan of a very large drive,
    expect it to take a while.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="triage_scan", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=total_bytes)

    CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB
    OVERLAP = 256  # bytes carried over between chunks so a match spanning a
                   # chunk boundary isn't missed

    results = {name: set() for name in TRIAGE_PATTERNS}
    truncated = {name: False for name in TRIAGE_PATTERNS}

    try:
        os.makedirs(dest_dir, exist_ok=True)
        append_log(f"[*] Scanning {source} for structured data (emails, URLs, IPs, card-like numbers, phone numbers)...")
        update_job(status="Scanning for Structured Data...")

        bytes_read = 0
        tail = b""
        last_update_time = time.time()

        # Raw block devices need root to read directly - pipe through a
        # privileged `dd` and read its stdout instead of opening the device
        # file directly (which would hit the same permission wall dc3dd/
        # ddrescue/etc. would without sudo). An already-acquired image file
        # is owned by this account already, so a direct Python open() is
        # simpler and faster there - no privilege elevation needed.
        read_proc = None
        if is_valid_block_device(source):
            read_proc = subprocess.Popen(
                ["sudo", "/usr/bin/dd", f"if={source}", f"bs={CHUNK_SIZE}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            source_stream = read_proc.stdout
        else:
            source_stream = open(source, 'rb')

        try:
            while True:
                if snapshot_job()["status"] == "Stopped":
                    append_log("[!] Scan stopped by user.")
                    break

                chunk = source_stream.read(CHUNK_SIZE)
                if not chunk:
                    break

                data = tail + chunk
                for name, pattern in TRIAGE_PATTERNS.items():
                    if truncated[name]:
                        continue
                    for m in pattern.finditer(data):
                        val = m.group(0)
                        if len(val) > 4:  # skip trivial/near-empty matches
                            results[name].add(val)
                            if len(results[name]) >= TRIAGE_MAX_MATCHES_PER_CATEGORY:
                                truncated[name] = True
                                append_log(f"[!] {name}: hit the {TRIAGE_MAX_MATCHES_PER_CATEGORY}-match cap, no longer collecting new ones.")
                                break

                tail = data[-OVERLAP:] if len(data) >= OVERLAP else data
                bytes_read += len(chunk)

                # Throttle UI updates rather than pushing on every chunk.
                if time.time() - last_update_time > 0.5:
                    updates = {"transferred_bytes": bytes_read}
                    if total_bytes > 0:
                        updates["progress_percent"] = round((bytes_read / total_bytes) * 100, 1)
                    update_job(**updates)
                    last_update_time = time.time()
        finally:
            try:
                source_stream.close()
            except Exception:
                pass
            if read_proc is not None:
                try:
                    if read_proc.poll() is None:
                        read_proc.terminate()
                        read_proc.wait(timeout=5)
                except Exception:
                    pass  # expected if it's already root-owned via sudo - the sudo pkill below is the real cleanup
                # sudo dd runs as root - an unprivileged terminate()/kill()
                # from this process can't touch it, so also sweep it via
                # the same sudo pkill pattern used to stop other privileged
                # acquisition tools.
                try:
                    subprocess.run(["sudo", "pkill", "-9", "-f", f"dd if={source}"], capture_output=True)
                except Exception:
                    pass

        update_job(transferred_bytes=bytes_read)

        total_hits = 0
        for name, matches in results.items():
            out_path = os.path.join(dest_dir, f"{name}.txt")
            with open(out_path, 'w') as out_f:
                for val in sorted(matches):
                    out_f.write(val.decode('utf-8', errors='replace') + "\n")
            total_hits += len(matches)
            note = " (capped)" if truncated[name] else ""
            append_log(f"[+] {name}: {len(matches)} unique match(es){note} -> {out_path}")

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["triage_summary"] = {name: len(matches) for name, matches in results.items()}

        if snapshot_job()["status"] == "Stopped":
            report_data["acquisition_status"] = "STOPPED"
        else:
            update_job(status="Completed Successfully", progress_percent=100.0)
            append_log(f"[+] Triage scan completed. {total_hits} total unique matches across all categories.")
            report_data["acquisition_status"] = "COMPLETED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()

# --- Web Routes & API Endpoints ---
# _safe_next_path now lives in core/auth.py (imported at the top of this
# file) - see the Step 0 core/ extraction.

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Already have a valid session - no need to show the form again.
        existing = session.get('username')
        if existing and _session_user_still_valid(existing):
            return redirect(_safe_next_path(request.args.get('next')))
        return render_template('login.html', next=_safe_next_path(request.args.get('next')))

    client_key = request.remote_addr or 'unknown'
    if _is_locked_out(client_key):
        return jsonify({
            "success": False,
            "error": "Too many failed login attempts. Try again in a few minutes.",
        }), 429

    req = request.get_json(silent=True) or {}
    username = (req.get('username') or '').strip()
    password = req.get('password') or ''

    if not check_auth(username, password):
        _record_auth_failure(client_key)
        return jsonify({"success": False, "error": "Incorrect username or password."}), 401

    _record_auth_success(client_key)
    _record_last_login(username)
    session.clear()  # drop any prior identity outright rather than merge state into it
    session['username'] = username
    session.permanent = True
    return jsonify({"success": True, "redirect": _safe_next_path(req.get('next'))})

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/')
@requires_auth
def index():
    return render_template(
        'index.html',
        is_local_kiosk=is_local_kiosk_request(),
        offline_tiles_json=json.dumps(get_offline_tiles_info()),
    )

@app.route('/api/system_info', methods=['GET'])
@requires_auth
def system_info():
    global last_net_check
    
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    root_disk = psutil.disk_usage('/')
    
    now = time.time()
    net_counters = psutil.net_io_counters()
    time_delta = max(now - last_net_check["time"], 0.001)
    
    sent_delta = net_counters.bytes_sent - last_net_check["bytes_sent"]
    recv_delta = net_counters.bytes_recv - last_net_check["bytes_recv"]
    
    if last_net_check["bytes_sent"] == 0:
        sent_delta = 0
        recv_delta = 0
        
    upload_mbps = round((sent_delta / (1024 * 1024)) / time_delta, 2)
    download_mbps = round((recv_delta / (1024 * 1024)) / time_delta, 2)
    
    last_net_check = {
        "time": now,
        "bytes_sent": net_counters.bytes_sent,
        "bytes_recv": net_counters.bytes_recv
    }

    target_drive = request.args.get('drive', '/dev/sda')
    if not target_drive or not target_drive.startswith('/dev/'):
        target_drive = '/dev/sda'

    wb_active = True
    if os.path.exists(target_drive):
        try:
            res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getro', target_drive], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip() == '0':
                wb_active = False
        except Exception:
            pass

    return jsonify({
        "cpu_percent": cpu,
        "memory": {
            "used_gb": round(mem.used / (1024**3), 2),
            "total_gb": round(mem.total / (1024**3), 2),
            "percent_used": mem.percent
        },
        "network_speed": {
            "upload_mbps": upload_mbps,
            "download_mbps": download_mbps
        },
        "local_storage": {
            "used_gb": round(root_disk.used / (1024**3), 2),
            "total_gb": round(root_disk.total / (1024**3), 2),
            "percent_used": root_disk.percent
        },
        "write_blocker_active": wb_active,
        "monitored_device": target_drive
    })

@app.route('/api/drives', methods=['GET'])
@requires_auth
def list_drives():
    drives = []
    try:
        res = subprocess.run(
            ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,MODEL,TRAN,TYPE,SERIAL,RO'],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') == 'disk' and not dev['name'].startswith('loop'):
                    bytes_size = int(dev.get('size', 0))
                    gb_size = round(bytes_size / (1024**3), 1)
                    dev_path = f"/dev/{dev['name']}"
                    
                    # Force read-only lock upon discovery
                    try:
                        subprocess.run(['sudo', '/usr/sbin/blockdev', '--setro', dev_path], capture_output=True)
                    except Exception:
                        pass

                    drives.append({
                        "name": dev['name'],
                        "device": dev_path,
                        "model": dev.get('model') or 'Generic Disk',
                        "size": f"{gb_size} GB",
                        "bytes": bytes_size,
                        "transport": dev.get('tran') or 'usb',
                        "serial": dev.get('serial') or 'N/A',
                        "read_only": True
                    })
    except Exception as e:
        print(f"Error executing lsblk: {e}")
        
    return jsonify(drives)

@app.route('/api/smart_check', methods=['POST'])
@requires_auth
def smart_check():
    req = request.get_json() or {}
    drive = req.get('drive', '')
    
    if not drive or not drive.startswith('/dev/'):
        return jsonify({"success": False, "error": "Invalid drive selection"})

    try:
        total_bytes = 0
        try:
            res_sz = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', drive], capture_output=True, text=True)
            if res_sz.returncode == 0:
                total_bytes = int(res_sz.stdout.strip())
        except Exception:
            pass

        capacity_str = f"{round(total_bytes / (1024**3), 2)} GB" if total_bytes > 0 else "N/A"

        res = subprocess.run(['sudo', 'smartctl', '-a', '-j', drive], capture_output=True, text=True)
        data = json.loads(res.stdout) if res.stdout else {}
        
        healthy = data.get('smart_status', {}).get('passed', True)
        family = data.get('model_family') or data.get('family_name')
        model = data.get('model_name') or data.get('device', {}).get('name')
        
        if family and model and family.lower() not in model.lower():
            vendor_model_str = f"{family} ({model})"
        elif family:
            vendor_model_str = family
        else:
            vendor_model_str = model or "Generic Media"

        serial = data.get('serial_number', 'N/A')
        temp = data.get('temperature', {}).get('current')
        
        dev_type = data.get('device', {}).get('type', '')
        protocol = data.get('device', {}).get('protocol', '')
        media_type = f"{protocol.upper()} / {dev_type.upper()} Storage" if protocol else "USB / ATA Storage"

        reallocated = 0
        pending = 0
        power_on = None
        
        for attr in data.get('ata_smart_attributes', {}).get('table', []):
            attr_id = attr.get('id')
            if attr_id == 5:
                reallocated = attr.get('raw', {}).get('value', 0)
            elif attr_id == 197:
                pending = attr.get('raw', {}).get('value', 0)
            elif attr_id == 9:
                power_on = attr.get('raw', {}).get('value')

        return jsonify({
            "success": True,
            "healthy": healthy,
            "vendor_model": vendor_model_str,
            "media_type": media_type,
            "capacity": capacity_str,
            "serial": serial,
            "temperature": temp,
            "reallocated_sectors": reallocated,
            "pending_sectors": pending,
            "power_on_hours": power_on
        })

    except Exception:
        return jsonify({
            "success": True,
            "healthy": True,
            "vendor_model": "Generic Media Device",
            "media_type": "USB / Storage Media",
            "capacity": "N/A",
            "serial": "N/A",
            "temperature": None,
            "reallocated_sectors": 0,
            "pending_sectors": 0,
            "power_on_hours": None
        })

@app.route('/api/mount_history', methods=['GET'])
@requires_auth
def get_mount_history():
    return jsonify(load_mount_history())

@app.route('/api/list_server_shares', methods=['POST'])
@requires_auth
def list_server_shares():
    req = request.get_json() or {}
    protocol = req.get('protocol', 'smb').lower()
    host = req.get('host', '').strip()

    if not host:
        return jsonify({"success": False, "error": "Server IP required."}), 400

    shares = []
    try:
        if protocol == 'nfs':
            res = subprocess.run(['showmount', '-e', '--no-headers', host], capture_output=True, text=True, timeout=8)
            if res.returncode == 0:
                for line in res.stdout.strip().split('\n'):
                    if line.strip():
                        export_path = line.split()[0]
                        shares.append(export_path)
                return jsonify({"success": True, "shares": shares})
            else:
                return jsonify({"success": False, "error": res.stderr.strip() or "No NFS exports found."}), 500
        elif protocol == 'sftp':
            # SFTP has no share-enumeration equivalent to showmount/smbclient
            # -L - there's no "list exported paths" concept over plain SSH.
            # Not an error, just nothing to list - the examiner enters the
            # remote path directly in the Mount form instead.
            return jsonify({"success": True, "shares": [], "info": "SFTP has no share-listing equivalent - enter the remote path directly."})
        else:
            user = req.get('user', '')
            pass_val = req.get('pass', '')

            if user:
                cmd = ['smbclient', '-L', host, '-I', host, '-U', f"{user}%{pass_val}", '-g']
            else:
                cmd = ['smbclient', '-L', host, '-I', host, '-N', '-g']

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)

            if res.returncode != 0 and not user:
                cmd_guest = ['smbclient', '-L', host, '-I', host, '-U', 'guest%', '-g']
                res = subprocess.run(cmd_guest, capture_output=True, text=True, timeout=8)

            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith('Disk|'):
                        parts = line.split('|')
                        if len(parts) > 1:
                            share_name = parts[1].strip()
                            if share_name and not share_name.endswith('$'):
                                shares.append(share_name)
                return jsonify({"success": True, "shares": shares})
            else:
                err_msg = res.stderr.strip() or res.stdout.strip() or "Failed to query SMB shares."
                return jsonify({"success": False, "error": err_msg}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def _do_network_mount(protocol, host, share_path, mount_point, user, password, ssh_key):
    """Actually performs the mount (NFS/SFTP/SMB), shared by the live
    /api/mount_network route and attempt_startup_auto_mounts() below - one
    real implementation so the two can never drift apart. Returns
    (success: bool, error_message: str|None)."""
    # The service runs as an unprivileged user (see install.py), so
    # directories under /mnt must be created via sudo rather than
    # os.makedirs(), which would otherwise fail with a permission error.
    subprocess.run(['sudo', 'mkdir', '-p', mount_point], capture_output=True)

    # Mounted files should be owned by the service account (not root) so
    # dc3dd/ewfacquire/ddrescue and the file explorer, which also run
    # unprivileged, can read/write into the mounted share.
    service_uid, service_gid = os.getuid(), os.getgid()

    try:
        subprocess.run(['sudo', 'umount', '-l', mount_point], capture_output=True)

        if protocol == 'nfs':
            nfs_source = f"{host}:{share_path}"
            cmd_v3 = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,soft,timeo=30,retrans=2,vers=3', nfs_source, mount_point]
            res = subprocess.run(cmd_v3, capture_output=True, text=True)

            if res.returncode == 0:
                return True, None

            cmd_v4 = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,soft,timeo=30,retrans=2,vers=4', nfs_source, mount_point]
            res_v4 = subprocess.run(cmd_v4, capture_output=True, text=True)

            if res_v4.returncode == 0:
                return True, None

            return False, f"NFS Mount Failed: {res_v4.stderr.strip() or res.stderr.strip()}"

        elif protocol == 'sftp':
            # sshfs (FUSE) has no CIFS-style credentials=file option, so the
            # two auth mechanisms differ: a pasted private key goes to a
            # temp IdentityFile (same mkstemp/chmod 0600/remove-in-finally
            # hygiene as the CIFS credentials file below), otherwise the
            # password is piped over stdin via -o password_stdin rather
            # than ever appearing in the command line (readable via `ps`).
            #
            # allow_other is required so the mount is usable by every other
            # unprivileged process in this app (dc3dd, the file explorer,
            # etc.) even though the mount itself runs as root via sudo -
            # install.py enables user_allow_other in /etc/fuse.conf for
            # this. StrictHostKeyChecking=no is necessary for a
            # non-interactive first connection (there's no TTY here to
            # answer a host-key prompt, so without this the mount would
            # simply hang) - this app's NFS/CIFS mounting has no equivalent
            # server-authenticity check either, so this isn't a new
            # departure from this feature's existing trust model.
            sftp_source = f"{user or 'root'}@{host}:{share_path}"
            opts_parts = [f"uid={service_uid}", f"gid={service_gid}", "allow_other", "StrictHostKeyChecking=no"]

            if ssh_key:
                key_fd, key_path = tempfile.mkstemp(prefix="pif_sftp_key_")
                try:
                    os.chmod(key_path, 0o600)
                    with os.fdopen(key_fd, 'w') as f:
                        f.write(ssh_key if ssh_key.endswith('\n') else ssh_key + '\n')
                    opts_parts.append(f"IdentityFile={key_path}")
                    cmd_sftp = ['sudo', 'sshfs', sftp_source, mount_point, '-o', ",".join(opts_parts)]
                    res_sftp = subprocess.run(cmd_sftp, capture_output=True, text=True)
                finally:
                    try:
                        os.remove(key_path)
                    except OSError:
                        pass
            else:
                opts_parts.append("password_stdin")
                cmd_sftp = ['sudo', 'sshfs', sftp_source, mount_point, '-o', ",".join(opts_parts)]
                res_sftp = subprocess.run(cmd_sftp, input=password, capture_output=True, text=True)

            if res_sftp.returncode == 0:
                return True, None

            return False, f"SFTP Mount Failed: {res_sftp.stderr.strip()}"

        else:
            unc_source = f"//{host}/{share_path.lstrip('/')}"
            user_arg = user if user else 'guest'
            pass_arg = password if password else ''

            # Write credentials to a private temp file instead of putting
            # "password=..." directly on the mount command line, where any
            # local user could read it via `ps aux` while the mount runs.
            cred_fd, cred_path = tempfile.mkstemp(prefix="pif_cifs_cred_")
            try:
                os.chmod(cred_path, 0o600)
                with os.fdopen(cred_fd, 'w') as f:
                    f.write(f"username={user_arg}\npassword={pass_arg}\n")

                opts = f"credentials={cred_path},uid={service_uid},gid={service_gid},noperm,iocharset=utf8"
                cmd_smb = ['sudo', 'mount', '-t', 'cifs', unc_source, mount_point, '-o', opts]
                res_smb = subprocess.run(cmd_smb, capture_output=True, text=True)
            finally:
                try:
                    os.remove(cred_path)
                except OSError:
                    pass

            if res_smb.returncode == 0:
                return True, None

            return False, f"SMB Mount Failed: {res_smb.stderr.strip()}"

    except Exception as e:
        return False, str(e)


def _save_auto_mount_share(protocol, host, share_path, mount_point, user, password, ssh_key):
    """Persists a share for automatic reconnection on every future app
    startup (see attempt_startup_auto_mounts()). Only ever called after a
    real successful mount, never speculatively - a broken/unreachable share
    should never end up in this list. Any secret is Fernet-encrypted before
    it touches disk (see _encrypt_secret's docstring above for the honest
    scope of what that protects)."""
    cfg = load_runtime_config()
    shares = cfg.get('auto_mount_shares', [])
    shares = [s for s in shares if s.get('mount_point') != mount_point]
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    shares.append({
        "id": uuid.uuid4().hex,
        "protocol": protocol,
        "host": host,
        "share": share_path,
        "mount_point": mount_point,
        "user": user or "",
        "password_enc": _encrypt_secret(password),
        "key_enc": _encrypt_secret(ssh_key),
        "created_at": now,
        "updated_at": now,
    })
    cfg['auto_mount_shares'] = shares
    save_runtime_config(cfg)
    log_chain_of_custody("auto_mount_share_added", {"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})


def attempt_startup_auto_mounts():
    """Runs once when the app process starts (see the threading.Thread call
    near the bottom of this file) - replays every saved auto-mount share so
    a station reboot (or even just a `systemctl restart`) doesn't strand an
    examiner's cases on a share that silently didn't come back, the exact
    gap that prompted this feature. Runs in a background thread specifically
    so a slow/unreachable NFS/SMB/SFTP server can't delay the whole app from
    becoming ready."""
    shares = load_runtime_config().get('auto_mount_shares', [])
    if not shares:
        return
    for entry in shares:
        password = _decrypt_secret(entry.get('password_enc'))
        ssh_key = _decrypt_secret(entry.get('key_enc'))
        success, error = _do_network_mount(
            entry.get('protocol', 'nfs'), entry.get('host', ''), entry.get('share', ''),
            entry.get('mount_point', ''), entry.get('user', ''), password, ssh_key
        )
        # Explicit source_ip/user overrides, not the request-context fallback -
        # this runs in a background thread with no active Flask request, and
        # log_chain_of_custody() would raise trying to read request/g outside
        # one (the exact bug already fixed once for network-config's own
        # delayed-revert thread - same pattern applied here from the start).
        log_chain_of_custody(
            "auto_mount_startup",
            {"mount_point": entry.get('mount_point'), "host": entry.get('host'), "success": success, "error": error},
            source_ip=None, user="system-startup"
        )


@app.route('/api/mount_network', methods=['POST'])
@requires_auth
@requires_permission('settings')
def mount_network():
    req = request.get_json() or {}
    protocol = req.get('protocol', 'smb').lower()
    host = req.get('host', '').strip()
    share = req.get('share', '').strip()
    user = req.get('user', '').strip()
    password = req.get('pass', '').strip()
    ssh_key = req.get('key', '').strip()
    auto_connect = bool(req.get('auto_connect'))

    if not host or not share:
        return jsonify({"success": False, "error": "Server IP and Share/Path are required."}), 400

    share_path = f"/{share.lstrip('/')}"
    safe_folder_name = share_path.replace('/', '_').strip('_')
    mount_point = f"/mnt/network_{protocol}_{safe_folder_name}"

    success, error = _do_network_mount(protocol, host, share_path, mount_point, user, password, ssh_key)

    if not success:
        return jsonify({"success": False, "error": error}), 500

    save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
    if auto_connect:
        _save_auto_mount_share(protocol, host, share_path, mount_point, user, password, ssh_key)

    return jsonify({"success": True, "mount_point": mount_point})


@app.route('/api/network/auto_mounts', methods=['GET'])
@requires_auth
def list_auto_mount_shares():
    shares = load_runtime_config().get('auto_mount_shares', [])
    return jsonify({"success": True, "shares": [
        {
            "id": s.get('id'), "protocol": s.get('protocol'), "host": s.get('host'),
            "share": s.get('share'), "mount_point": s.get('mount_point'), "user": s.get('user', ''),
            "has_password": bool(s.get('password_enc')), "has_key": bool(s.get('key_enc')),
            "created_at": s.get('created_at'),
        } for s in shares
    ]})


@app.route('/api/network/auto_mounts/<entry_id>', methods=['DELETE'])
@requires_auth
@requires_permission('settings')
def remove_auto_mount_share(entry_id):
    cfg = load_runtime_config()
    shares = cfg.get('auto_mount_shares', [])
    remaining = [s for s in shares if s.get('id') != entry_id]
    if len(remaining) == len(shares):
        return jsonify({"success": False, "error": "No auto-connect share found with that id."}), 404
    removed = next((s for s in shares if s.get('id') == entry_id), None)
    cfg['auto_mount_shares'] = remaining
    save_runtime_config(cfg)
    log_chain_of_custody("auto_mount_share_removed", {"mount_point": removed.get('mount_point') if removed else None})
    return jsonify({"success": True})

@app.route('/api/toggle_write_block', methods=['POST'])
@requires_auth
@requires_permission('settings')
def toggle_write_block():
    req = request.get_json() or {}
    enable = req.get('enable', True)
    drive = req.get('drive', '/dev/sda')

    # Strict whitelist instead of startswith('/dev/'), which previously let
    # values like "/dev/sda; rm -rf /" through into a shell=True call below.
    if not is_valid_block_device(drive):
        return jsonify({"success": False, "error": f"'{drive}' is not a recognized whole-disk device."}), 400

    action_flag = '--setro' if enable else '--setrw'

    try:
        # Expand partitions in Python (no shell globbing) and unmount each
        # with argv-list subprocess calls, so nothing reaches a shell.
        for part in sorted(glob.glob(f"{drive}*")):
            subprocess.run(['sudo', 'udevil', 'unmount', '-b', part], capture_output=True)
            subprocess.run(['sudo', 'umount', part], capture_output=True)

        res = subprocess.run(['sudo', '/usr/sbin/blockdev', action_flag, drive], capture_output=True, text=True)

        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr.strip() or "blockdev execution failed"}), 500

        chk = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getro', drive], capture_output=True, text=True)
        is_ro = (chk.returncode == 0 and chk.stdout.strip() == '1')

        return jsonify({"success": True, "write_blocker_active": is_ro, "device": drive})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/bitlocker/partitions', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_partitions():
    req = request.get_json() or {}
    device = req.get('device', '')
    if not is_valid_block_device(device):
        return jsonify({"success": False, "error": "Not a recognized whole-disk device."}), 400
    return jsonify({"success": True, "partitions": _list_device_partitions(device)})

@app.route('/api/bitlocker/detect', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_detect():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    result = _detect_bitlocker(partition)
    if result is None:
        return jsonify({"success": False, "error": "Invalid or unrecognized device/partition path."}), 400
    return jsonify({"success": True, **result})

@app.route('/api/bitlocker/unlock', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_unlock():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    recovery_key = req.get('recovery_key', '')
    success, mount_id, source_path, error = _dislocker_unlock(partition, recovery_key)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("bitlocker_unlock", {"device": partition, "mount_id": mount_id})
    return jsonify({"success": True, "mount_id": mount_id, "source_path": source_path})

@app.route('/api/bitlocker/detect_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def bitlocker_detect_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    result = _detect_bitlocker_image(image_path, offset)
    if result is None:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    return jsonify({"success": True, **result})

@app.route('/api/bitlocker/unlock_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def bitlocker_unlock_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    recovery_key = req.get('recovery_key', '')
    success, mount_id, source_path, error = _dislocker_unlock(image_path, recovery_key, offset=offset)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("bitlocker_unlock_image", {"image_path": image_path, "offset": offset, "mount_id": mount_id})
    return jsonify({"success": True, "mount_id": mount_id, "source_path": source_path})

@app.route('/api/bitlocker/lock', methods=['POST'])
@requires_auth
@requires_permission('acquisition', 'file_explorer')
def bitlocker_lock_route():
    req = request.get_json() or {}
    mount_id = req.get('mount_id', '')
    success, error = _dislocker_lock(mount_id)
    if not success:
        return jsonify({"success": False, "error": error}), 500
    log_chain_of_custody("bitlocker_lock", {"mount_id": mount_id})
    return jsonify({"success": True})

@app.route('/api/bitlocker/status', methods=['GET'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_status():
    with bitlocker_lock:
        mounts = [{"mount_id": mid, **{k: v for k, v in info.items() if k != 'mount_dir'}}
                  for mid, info in active_bitlocker_mounts.items()]
    return jsonify({"success": True, "mounts": mounts})

@app.route('/api/start_imaging', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_imaging():
    global current_job

    # Atomically check-and-reserve the job slot so two concurrent requests
    # can't both pass the check and start simultaneous acquisitions.
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    fmt = req.get('format', 'dd')
    hashes = [h.lower() for h in req.get('hashes', ['sha256'])]
    metadata = req.get('metadata', {})
    keep_raw = bool(req.get('keep_raw', True))  # only relevant when fmt == 'aff'
    # Documentation only, never used to decrypt anything - imaging still
    # captures the source exactly as found (encrypted or not). Recorded in
    # plaintext in the case report (like every other case_metadata field),
    # deliberately NOT Fernet-encrypted at rest the way network-mount
    # credentials are - this key's whole value is traveling with the
    # exported PDF/HTML report as documentation for whoever needs to
    # decrypt the image later, so encrypting it with a station-local key
    # would make it useless the moment the report leaves this station.
    bitlocker_key = (req.get('bitlocker_key') or '').strip()
    
    compression = req.get('compression', 'fast')
    split_size = req.get('split_size', '2000M')

    VALID_FORMATS = {'dd', 'raw', 'dcfldd', 'plain_dd', 'e01', 'aff'}
    if fmt not in VALID_FORMATS:
        update_job(active=False)
        return jsonify({"error": f"Unrecognized format '{fmt}'. Use one of {sorted(VALID_FORMATS)}."}), 400

    # A `source` matching a currently-registered dislocker mount (see
    # /api/bitlocker/unlock) is a decrypted virtual file, not a real block
    # device - trusted because only this app's own _dislocker_unlock() can
    # ever create a path that matches (mountpoints live under the
    # server-controlled DISLOCKER_MOUNT_ROOT, never client-supplied).
    source, source_is_real_device, bitlocker_mount_id = _resolve_acquisition_source(source)
    if source_is_real_device:
        if not is_valid_block_device(source) or not os.path.exists(source):
            update_job(active=False)
            return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400
    elif not os.path.exists(source):
        update_job(active=False)
        return jsonify({"error": "The unlocked BitLocker volume is no longer available - it may have been locked/unmounted."}), 400

    invalid_hashes = set(hashes) - ALLOWED_HASH_ALGOS
    if invalid_hashes:
        update_job(active=False)
        return jsonify({"error": f"Unsupported hash algorithm(s): {sorted(invalid_hashes)}. Use any of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    if not os.path.exists(dest_path):
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    total_bytes = 0
    if source_is_real_device:
        try:
            res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
            if res.returncode == 0:
                total_bytes = int(res.stdout.strip())
        except Exception:
            pass
    else:
        # A dislocker-file is a regular file, not a block device - a plain
        # stat gives its real decrypted size directly, no blockdev needed.
        try:
            total_bytes = os.path.getsize(source)
        except OSError:
            pass

    dest_disk_usage = shutil.disk_usage(dest_path)
    if total_bytes > 0 and dest_disk_usage.free < total_bytes:
        free_gb = round(dest_disk_usage.free / (1024**3), 2)
        required_gb = round(total_bytes / (1024**3), 2)
        update_job(active=False)
        return jsonify({"error": f"Pre-flight storage check failed: Destination has only {free_gb} GB free, but source requires {required_gb} GB."}), 400

    # SMART telemetry only exists for a real physical device - a decrypted
    # dislocker-file has none of its own (it's a virtual file backed by the
    # already-encrypted partition), so this is skipped entirely rather than
    # querying smartctl against a path it was never meant to see.
    smart_data = {}
    if source_is_real_device:
        try:
            res_smart = subprocess.run(['sudo', 'smartctl', '-a', '-j', source], capture_output=True, text=True)
            if res_smart.stdout:
                smart_data = json.loads(res_smart.stdout)
        except Exception:
            pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    vendor_model = f"{family} ({model})" if (family and family.lower() not in model.lower()) else model
    if not source_is_real_device:
        vendor_model = "BitLocker-Decrypted Volume (via dislocker)"

    serial = smart_data.get('serial_number', 'N/A')
    healthy = smart_data.get('smart_status', {}).get('passed', True)
    temp = smart_data.get('temperature', {}).get('current')
    power_hours = smart_data.get('power_on_time', {}).get('hours')
    
    reallocated = 0
    pending = 0
    for attr in smart_data.get('ata_smart_attributes', {}).get('table', []):
        attr_id = attr.get('id')
        if attr_id == 5:
            reallocated = attr.get('raw', {}).get('value', 0)
        elif attr_id == 197:
            pending = attr.get('raw', {}).get('value', 0)

    drive_telemetry = {
        # Displays the real encrypted device/partition path for a BitLocker
        # acquisition, not the internal dislocker mountpoint - the mountpoint
        # is implementation detail, the original device is what belongs in
        # the case record.
        "device_path": active_bitlocker_mounts.get(bitlocker_mount_id, {}).get("device", source) if bitlocker_mount_id else source,
        "vendor_model": vendor_model,
        "serial_number": serial,
        "capacity_bytes": total_bytes,
        "capacity_gb": round(total_bytes / (1024**3), 2),
        "smart_healthy": healthy,
        "temperature_celsius": temp,
        "power_on_hours": power_hours,
        "reallocated_sectors": reallocated,
        "pending_sectors": pending
    }

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    examiner = metadata.get('examiner', 'UNSPECIFIED')
    notes = metadata.get('notes', 'None')
    base_name = f"{case_num}_{evidence_id}"

    if fmt == 'e01':
        ewf_hash_type = "sha256" if "sha256" in hashes else ("sha1" if "sha1" in hashes else "md5")
        out_file = f"{dest_path}/{base_name}.E01"
        cmd = [
            "sudo", "/usr/bin/ewfacquire", "-u",
            "-t", f"{dest_path}/{base_name}",
            "-C", case_num,
            "-E", evidence_id,
            "-e", examiner,
            "-N", notes,
            "-f", "encase6",
            "-d", ewf_hash_type,
            "-c", compression,
            "-S", split_size,
            source
        ]

    elif fmt == 'dcfldd':
        out_file = f"{dest_path}/{base_name}.dd"
        cmd = [
            "sudo", "/usr/bin/dcfldd",
            f"if={source}",
            f"of={out_file}",
            "conv=noerror,sync",
        ]
        if hashes:
            cmd.append(f"hash={','.join(hashes)}")
            for h in hashes:
                cmd.append(f"{h}log={out_file.replace('.dd', f'_{h}.log')}")

    elif fmt == 'plain_dd':
        out_file = f"{dest_path}/{base_name}.dd"
        # Unlike dc3dd, GNU dd genuinely supports iflag=direct - this
        # bypasses the page cache on the *read* side, which is the actual
        # forensic concern (avoiding cache pollution/buffer dirtying from
        # reading the source device). oflag=direct is deliberately omitted:
        # it requires block-aligned writes and can fail outright on some
        # destination filesystems (e.g. mounted network shares), which
        # would break the acquisition entirely for a benefit that mostly
        # matters on the read side anyway.
        cmd = [
            "sudo", "/usr/bin/dd",
            f"if={source}",
            f"of={out_file}",
            "bs=4M",
            "conv=noerror,sync",
            "status=progress",
        ]
        # iflag=direct bypasses the page cache on the read side - meaningful
        # for a real physical device, but O_DIRECT is frequently unsupported
        # (or outright rejected) by FUSE-backed regular files, which a
        # dislocker-unlocked BitLocker source is. Only add it for a real
        # block device.
        if source_is_real_device:
            cmd.append("iflag=direct")
        # dd itself has no built-in hashing; computed_hashes is filled in
        # after completion by streaming the output file through hashlib.

    elif fmt == 'aff':
        # Two-phase (raw acquisition -> AFF conversion); see
        # execution_worker_aff for why, and cmd/out_file here are only used
        # for the report's "requested command" field, not actually launched
        # via the generic execution_worker thread below.
        out_file = f"{dest_path}/{base_name}.aff"
        dc3dd_cmd_preview = ["sudo", "/usr/bin/dc3dd", f"if={source}", f"of={dest_path}/{base_name}.raw"] + [f"hash={h}" for h in hashes]
        affconvert_cmd_preview = ["affconvert", "-o", out_file, f"{dest_path}/{base_name}.raw"]
        cmd = dc3dd_cmd_preview + ["&&"] + affconvert_cmd_preview

    else:  # 'dd' / 'raw' -> dc3dd (original default engine)
        out_file = f"{dest_path}/{base_name}.dd"
        dc3dd_log_file = f"{dest_path}/{base_name}_dc3dd.log"
        # NOTE: dc3dd is a fork of the old-style `dd`, not GNU coreutils dd -
        # it does not support iflag=/oflag= at all (confirmed against its
        # own --help: only if=, of=, hash=, log=, ssz=, bufsz=, etc. are
        # recognized). The previous iflag=direct/oflag=direct here were
        # silently doing nothing. dc3dd has no O_DIRECT equivalent; the
        # closest actual performance/memory knob it exposes is bufsz=,
        # which sets the internal read buffer size. Use format=plain_dd
        # instead if genuine O_DIRECT behavior matters for your hardware.
        cmd = [
            "sudo", "/usr/bin/dc3dd",
            f"if={source}",
            f"of={out_file}",
            f"log={dc3dd_log_file}",
        ]
        for h in hashes:
            cmd.append(f"hash={h}")

    update_job(
        format=fmt,
        progress_percent=0.0,
        speed_mbps=0.0,
        transferred_bytes=0,
        total_bytes=total_bytes,
        status="Initializing...",
        log=f"[*] Initializing {fmt.upper()} acquisition ({', '.join(hashes).upper()}) for {source} -> {dest_path}..."
    )

    report_data = {
        "tool": fmt,
        "case_metadata": metadata,
        "source_drive_telemetry": drive_telemetry,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": fmt,
            "output_image_path": out_file,
            "compression": compression if fmt == 'e01' else 'N/A',
            "split_size": split_size if fmt == 'e01' else 'N/A',
            "requested_hashes": hashes,
            "execution_command": " ".join(cmd),
            **({"raw_image_retained": None} if fmt == 'aff' else {}),
            **({"bitlocker_key": bitlocker_key} if bitlocker_key else {}),
            **({"bitlocker_decrypted": True} if bitlocker_mount_id else {}),
        },
        "attachments": {
            "files": [],
            "reference_urls": []
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    if fmt == 'aff':
        thread = threading.Thread(
            target=execution_worker_aff,
            args=(source, dest_path, base_name, hashes, keep_raw, report_target, report_data, total_bytes)
        )
    else:
        thread = threading.Thread(
            target=execution_worker,
            args=(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes)
        )
    thread.daemon = True
    thread.start()

    # A dislocker mount must stay live for the whole acquisition (dc3dd/
    # dcfldd/etc. read from it throughout the job), then gets torn down as
    # soon as it's no longer needed - a decrypted mount is sensitive and
    # shouldn't linger any longer than the job that actually needed it.
    # This runs in its own thread (not execution_worker's own finally
    # block) specifically to avoid threading a new parameter through that
    # already-large, multi-caller function; thread.join() here blocks only
    # this cleanup thread, not the request that already returned above.
    if bitlocker_mount_id:
        requester_ip = request.remote_addr
        requester_user = getattr(g, 'forensic_user', None)

        def _cleanup_bitlocker_after_job(worker_thread, mid, src_ip, user):
            worker_thread.join()
            _dislocker_lock(mid)
            log_chain_of_custody("bitlocker_lock", {"mount_id": mid, "reason": "acquisition_complete"},
                                 source_ip=src_ip, user=user)

        cleanup_thread = threading.Thread(
            target=_cleanup_bitlocker_after_job, args=(thread, bitlocker_mount_id, requester_ip, requester_user)
        )
        cleanup_thread.daemon = True
        cleanup_thread.start()

    log_chain_of_custody("acquisition_start", {"format": fmt, "source": source, "destination": dest_path,
                                                **({"bitlocker_decrypted": True} if bitlocker_mount_id else {})})
    return jsonify({"success": True, "message": "Acquisition started."})

@app.route('/api/ddrescue/inspect_map', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def inspect_ddrescue_map():
    req = request.get_json() or {}
    map_path = safe_path(req.get('map_path', ''))
    if not map_path or not os.path.exists(map_path):
        return jsonify({"success": False, "error": "Mapfile not found or outside the permitted evidence directory."}), 404

    summary = parse_ddrescue_mapfile(map_path)
    return jsonify({
        "success": True,
        "map_path": map_path,
        "rescued_gb": round(summary["rescued_bytes"] / (1024**3), 3),
        "non_tried_mb": round(summary["non_tried_bytes"] / (1024**2), 2),
        "bad_sector_kb": round(summary["bad_sector_bytes"] / 1024, 2),
        "bad_blocks_count": summary["bad_blocks_count"]
    })

@app.route('/api/start_ddrescue', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_ddrescue():
    global current_job

    # Atomically check-and-reserve the job slot, same as start_imaging.
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    strategy = req.get('strategy', 'stage1_fast')
    retry_passes = str(req.get('retry_passes', '3'))
    direct_mode = req.get('direct_mode', True)
    input_pos = req.get('input_position', '')
    max_size = req.get('max_size', '')
    metadata = req.get('metadata', {})
    # Documentation only here (see start_imaging()'s own comment on why
    # plaintext) - ddrescue itself deliberately does NOT support acquiring
    # from an unlocked dislocker mount the way start_imaging()'s other
    # formats do. ddrescue exists specifically for physically failing
    # drives - direct-I/O sector-level retry/skip logic against a raw
    # block device - which doesn't apply to an already-decrypted FUSE
    # virtual file sitting on top of a drive that (by definition, since it
    # unlocked successfully) is already being read fine. `-d`/--idirect
    # would likely just fail outright against a non-block-device source.
    # If a genuinely failing BitLocker-encrypted drive ever needs
    # sector-level recovery, that has to happen at the raw encrypted layer
    # (ddrescue the raw partition first, decrypt the resulting image
    # afterward with dislocker) - a different workflow than this route.
    bitlocker_key = (req.get('bitlocker_key') or '').strip()

    # This runs ddrescue via a passwordless sudo rule (see install.py), so
    # source/destination MUST be tightly validated - otherwise any caller
    # could point ddrescue at an arbitrary file (e.g. /etc/shadow) and have
    # it copied out as root.
    if not is_valid_block_device(source) or not os.path.exists(source):
        update_job(active=False)
        return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    if strategy not in ('stage1_fast', 'stage2_trim', 'stage3_intensive', 'reverse'):
        update_job(active=False)
        return jsonify({"error": f"Unrecognized strategy '{strategy}'."}), 400

    if not retry_passes.isdigit():
        update_job(active=False)
        return jsonify({"error": "retry_passes must be a positive integer."}), 400

    if not os.path.exists(dest_path):
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    case_num = metadata.get('case_number', 'RECOVERY')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_ddrescue"
    
    out_file = os.path.join(dest_path, f"{base_name}.dd")
    map_file = os.path.join(dest_path, f"{base_name}.map")

    cmd = ["sudo", "/usr/bin/ddrescue", "--force"]

    if strategy == 'stage1_fast':
        cmd.extend(["--no-scrape", "--no-trim"])
    elif strategy == 'stage2_trim':
        cmd.append("--no-scrape")
    elif strategy == 'stage3_intensive':
        cmd.append(f"--retry-passes={retry_passes}")
    elif strategy == 'reverse':
        cmd.extend(["--reverse", f"--retry-passes={retry_passes}"])

    if direct_mode:
        cmd.append("-d")

    # input_pos/max_size are ddrescue byte-offset/size arguments (e.g. "512MiB").
    # Restrict to digits + a small unit-suffix alphabet so a stray value can't
    # smuggle an extra flag through as a single argv token.
    _SIZE_RE = re.compile(r'^\d+[KMGTP]?i?B?$', re.IGNORECASE)
    if input_pos:
        if not _SIZE_RE.match(input_pos):
            update_job(active=False)
            return jsonify({"error": f"Invalid input_position '{input_pos}'."}), 400
        cmd.append(f"--input-position={input_pos}")
    if max_size:
        if not _SIZE_RE.match(max_size):
            update_job(active=False)
            return jsonify({"error": f"Invalid max_size '{max_size}'."}), 400
        cmd.append(f"--max-size={max_size}")

    cmd.extend([source, out_file, map_file])

    total_bytes = 0
    try:
        res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    update_job(
        format="ddrescue",
        progress_percent=0.0,
        speed_mbps=0.0,
        transferred_bytes=0,
        total_bytes=total_bytes,
        status=f"ddrescue [{strategy.upper()}]...",
        log=f"[*] Initializing ddrescue ({strategy}) pass for {source} -> {out_file}\n[*] Mapfile: {map_file}..."
    )

    report_data = {
        "tool": "ddrescue",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": "ddrescue_raw",
            "output_image_path": out_file,
            "mapfile": map_file,
            "strategy": strategy,
            "retry_passes": retry_passes,
            "direct_mode": direct_mode,
            "execution_command": " ".join(cmd),
            **({"bitlocker_key": bitlocker_key} if bitlocker_key else {}),
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    report_target = build_report_target(dest_path, dest_path, base_name)

    thread = threading.Thread(
        target=execution_worker,
        args=(cmd, "ddrescue", total_bytes, out_file, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("ddrescue_start", {"strategy": strategy, "source": source, "destination": dest_path})
    return jsonify({"success": True, "message": f"ddrescue ({strategy}) started."})

# --- Mobile Forensics Endpoints ---
@app.route('/api/mobile/devices', methods=['GET'])
@requires_auth
def get_mobile_devices():
    return jsonify({"ios": list_ios_devices(), "android": list_android_devices()})

@app.route('/api/mobile/ios/pair', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def pair_ios_device():
    req = request.get_json() or {}
    udid = req.get('udid', '')
    if not _UDID_RE.match(udid or ''):
        return jsonify({"success": False, "error": "Invalid or missing device UDID."}), 400

    try:
        res = subprocess.run(["idevicepair", "-u", udid, "pair"], capture_output=True, text=True, timeout=15)
        output = (res.stdout + res.stderr).strip()
        if res.returncode == 0:
            return jsonify({"success": True, "message": output or "Pairing request sent - accept 'Trust This Computer?' on the device if prompted."})
        return jsonify({"success": False, "error": output or "Pairing failed."}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Timed out waiting for the device."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/mobile/start_ios_backup', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def start_ios_backup():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    udid = req.get('udid', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    encrypt_password = req.get('encrypt_password') or None
    metadata = req.get('metadata', {})

    if not _UDID_RE.match(udid or ''):
        update_job(active=False)
        return jsonify({"error": "Invalid or missing device UDID. Refresh the device list and select a connected, trusted iOS device."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_ios_backup"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="ios_backup", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing iOS backup for UDID {udid} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "ios_backup",
        "case_metadata": metadata,
        "device_udid": udid,
        "acquisition_parameters": {
            "platform": "iOS",
            "method": "idevicebackup2 full backup",
            "encrypted": bool(encrypt_password),
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_ios_backup,
        args=(udid, job_dest_dir, encrypt_password, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("ios_backup_start", {"udid": udid, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "iOS backup started."})

@app.route('/api/mobile/start_android', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def start_android_acquisition():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    serial = req.get('serial', '')
    mode = req.get('mode', 'pull')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if not _ANDROID_SERIAL_RE.match(serial or ''):
        update_job(active=False)
        return jsonify({"error": "Invalid or missing device serial. Refresh the device list and select a connected, authorized Android device."}), 400

    if mode not in ('backup', 'pull', 'bugreport'):
        update_job(active=False)
        return jsonify({"error": "mode must be 'backup', 'pull', or 'bugreport'."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_android_{mode}"

    if mode == 'backup':
        output_path = os.path.join(dest_path, f"{base_name}.ab")
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400
    elif mode == 'bugreport':
        output_path = os.path.join(dest_path, f"{base_name}.zip")
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400
    else:
        output_path = os.path.join(dest_path, base_name)
        try:
            os.makedirs(output_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {output_path} is inaccessible: {str(e)}"}), 400

    update_job(
        format=f"android_{mode}", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing Android {mode} for {serial} -> {output_path}..."
    )

    report_data = {
        "tool": f"android_{mode}",
        "case_metadata": metadata,
        "device_serial": serial,
        "acquisition_parameters": {
            "platform": "Android",
            "method": f"adb {mode}",
            "output_destination": output_path,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_android,
        args=(mode, serial, output_path, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("android_acquisition_start", {"mode": mode, "serial": serial, "destination": output_path})
    return jsonify({"success": True, "message": f"Android {mode} started."})

# --- File Carving / Recovery (PhotoRec) ---
@app.route('/api/recovery/start_photorec', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_photorec():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    # Source can be either a whole-disk device (recovering directly from a
    # damaged drive) or an already-sandboxed image file (recovering from a
    # .dd/.img acquired earlier, e.g. after a ddrescue pass) - never an
    # arbitrary path outside EVIDENCE_ROOT either way.
    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_photorec"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="photorec", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing PhotoRec recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "photorec",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "photorec (file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_photorec,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("photorec_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "PhotoRec recovery started."})

@app.route('/api/recovery/start_extundelete', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_extundelete():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_extundelete"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        # Must pre-create (unlike foremost/scalpel below) - extundelete is
        # launched with cwd=job_dest_dir, which requires the directory to
        # already exist.
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="extundelete", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing extundelete recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "extundelete",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "extundelete (ext2/3/4 journal-based deleted file recovery)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_extundelete,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("extundelete_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "extundelete recovery started."})

@app.route('/api/recovery/start_foremost', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_foremost():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_foremost"
    job_dest_dir = os.path.join(dest_path, base_name)
    # Deliberately NOT pre-created - foremost refuses to run if its output
    # directory already exists. The report lives in the parent dest_path
    # instead, since job_dest_dir won't exist until foremost itself creates it.

    update_job(
        format="foremost", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing foremost recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "foremost",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "foremost (signature-based file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_foremost,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("foremost_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "foremost recovery started."})

@app.route('/api/recovery/start_scalpel', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_scalpel():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_scalpel"
    job_dest_dir = os.path.join(dest_path, base_name)
    # Deliberately NOT pre-created - same reason as foremost above.

    update_job(
        format="scalpel", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing scalpel recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "scalpel",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "scalpel (signature-based file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_scalpel,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("scalpel_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "scalpel recovery started."})

@app.route('/api/recovery/start_triage_scan', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_triage_scan():
    global current_job

    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_triagescan"
    job_dest_dir = os.path.join(dest_path, base_name)

    total_bytes = 0
    try:
        if is_valid_block_device(source):
            res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
            if res.returncode == 0:
                total_bytes = int(res.stdout.strip())
        else:
            total_bytes = os.path.getsize(source)
    except Exception:
        pass

    update_job(
        format="triage_scan", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=total_bytes, status="Initializing...",
        log=f"[*] Initializing triage scan of {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "triage_scan",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "built-in triage scan (emails/URLs/IPs/card-like numbers/phone numbers)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_triage_scan,
        args=(source, job_dest_dir, report_target, report_data, total_bytes)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("triage_scan_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "Triage scan started."})

@app.route('/api/stop_imaging', methods=['POST'])
@requires_auth
def stop_imaging():
    if current_job["active"]:
        try:
            proc = get_active_proc()
            if proc and proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception as e:
            print(f"Error killing process group: {e}")

        # These now run via sudo (root) to get raw device access, so killing
        # them also needs sudo - an unprivileged kill/pkill can't signal a
        # root-owned process. The existing /usr/bin/pkill sudoers grant is
        # already unrestricted, so no new sudoers entry is needed here.
        # "dd" gets matched via -f with a distinguishing substring rather
        # than a bare name match - "dd" is too generic a process name to
        # pkill by bare name without risking killing an unrelated process
        # elsewhere on the system.
        for tool in ["dc3dd", "dcfldd", "ewfacquire", "ddrescue", "photorec", "extundelete", "foremost", "scalpel"]:
            try:
                subprocess.run(["sudo", "pkill", "-9", tool], capture_output=True)
            except Exception:
                pass
        try:
            subprocess.run(["sudo", "pkill", "-9", "-f", "dd if="], capture_output=True)
        except Exception:
            pass

        with job_lock:
            current_job["status"] = "Stopped"
            current_job["active"] = False
            current_job["log"] += "\n[!] Acquisition manually terminated by user."
        return jsonify({"success": True, "message": "Acquisition stopped."})
        
    return jsonify({"error": "No active job running."}), 400

@app.route('/api/progress', methods=['GET'])
@requires_auth
def get_progress():
    job = snapshot_job()
    return jsonify({
        "active": job["active"],
        "format": job["format"],
        "progress_percent": job["progress_percent"],
        "speed_mbps": job["speed_mbps"],
        "transferred_bytes": job["transferred_bytes"],
        "total_bytes": job["total_bytes"],
        "status": job["status"],
        "log": job["log"]
    })

# --- Advanced System Management Endpoints ---

# SAFE alternative to a free-text shell terminal: a fixed allowlist of
# read-only diagnostic commands, each a literal argv list (never shell=True,
# never user-supplied text). A previous version of this feature accepted
# arbitrary shell strings from the client - that's a full remote-code-
# execution backdoor over the web API and is deliberately not implemented
# here. If you need something a command in this list doesn't cover, SSH in.
DIAGNOSTIC_COMMANDS = {
    "dmesg": ["dmesg"],
    "lsusb": ["lsusb"],
    "df": ["df", "-h"],
    "ip_a": ["ip", "a"],
    "uptime": ["uptime"],
    "lsblk": ["lsblk", "-f"],
    "free": ["free", "-h"],
    "mounts": ["mount"],
}

@app.route('/api/system/diagnostics', methods=['POST'])
@requires_auth
@requires_permission('settings')
def run_diagnostic_command():
    req = request.get_json() or {}
    key = req.get('command', '')
    argv = DIAGNOSTIC_COMMANDS.get(key)
    if not argv:
        return jsonify({"success": False, "error": f"Unknown diagnostic '{key}'. Allowed: {sorted(DIAGNOSTIC_COMMANDS)}"}), 400

    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        output = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
        return jsonify({"success": True, "command": " ".join(argv), "output": output.strip() or "[no output]"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Each entry: (display name, argv to get its version string). Covers every
# external tool this app invokes, so "what produced this evidence" is
# always answerable from the station itself, not just from memory.
# Each entry: display name, argv to get its version string, and the apt
# package that provides it (None = part of the base OS, not something to
# offer installing - e.g. GNU dd is always present via coreutils).
TOOL_VERSION_COMMANDS = [
    {"tool": "dc3dd", "cmd": ["dc3dd", "--version"], "package": "dc3dd"},
    {"tool": "dcfldd", "cmd": ["dcfldd", "--version"], "package": "dcfldd"},
    {"tool": "dd (GNU coreutils)", "cmd": ["dd", "--version"], "package": None},
    {"tool": "ddrescue", "cmd": ["ddrescue", "--version"], "package": "gddrescue"},
    {"tool": "ewfacquire", "cmd": ["ewfacquire", "-V"], "package": "ewf-tools"},
    {"tool": "affconvert", "cmd": ["affconvert", "-V"], "package": "afflib-tools"},
    {"tool": "photorec (via testdisk pkg)", "cmd": ["dpkg-query", "-W", "-f=${Version}", "testdisk"], "package": "testdisk"},
    {"tool": "sleuthkit (mmls)", "cmd": ["mmls", "-V"], "package": "sleuthkit"},
    {"tool": "exiftool", "cmd": ["exiftool", "-ver"], "package": "libimage-exiftool-perl"},
    {"tool": "binwalk", "cmd": ["dpkg-query", "-W", "-f=${Version}", "binwalk"], "package": "binwalk"},
    {"tool": "clamscan", "cmd": ["clamscan", "--version"], "package": "clamav"},
    {"tool": "hashdeep", "cmd": ["hashdeep", "-V"], "package": "hashdeep"},
    {"tool": "adb", "cmd": ["adb", "--version"], "package": "adb"},
    {"tool": "idevicebackup2", "cmd": ["idevicebackup2", "-v"], "package": "libimobiledevice-utils"},
    {"tool": "smartctl", "cmd": ["smartctl", "-V"], "package": "smartmontools"},
    {"tool": "wvkbd-mobintl", "cmd": ["wvkbd-mobintl", "-v"], "package": "wvkbd"},
    {"tool": "extundelete", "cmd": ["dpkg-query", "-W", "-f=${Version}", "extundelete"], "package": "extundelete"},
    {"tool": "foremost", "cmd": ["dpkg-query", "-W", "-f=${Version}", "foremost"], "package": "foremost"},
    {"tool": "scalpel", "cmd": ["scalpel", "-v"], "package": "scalpel"},
    # package=None (not apt): mvt is a pip package (see requirements.txt),
    # installed/upgraded via the venv, not the Tool Versions "Install" button.
    {"tool": "mvt-ios", "cmd": [MVT_IOS_BIN, "version"], "package": None},
    {"tool": "mvt-android", "cmd": [MVT_ANDROID_BIN, "version"], "package": None},
]
# Every installable package this endpoint will ever run apt-get for - the
# same allowlist install.py's sudoers file grants exact NOPASSWD entries
# for, so this can't be used to install anything beyond what's already a
# known, reviewed part of this project.
TOOL_INSTALLABLE_PACKAGES = {t["package"] for t in TOOL_VERSION_COMMANDS if t["package"]}

def _apt_candidate_version(package):
    """
    Read-only, no sudo needed (unlike apt-get install/update) - just queries
    apt's already-cached package index for what it currently considers
    installed vs. the newest candidate available. Reflects whatever that
    index was last refreshed to (via install.py's initial `apt-get update`
    or the Settings > Service Controls "Update OS Packages" button), not a
    live network check - a stale index can under-report a newer release
    upstream, same caveat as running `apt list --upgradable` by hand.
    """
    try:
        res = subprocess.run(['apt-cache', 'policy', package], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return None, None
        installed = candidate = None
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith('Installed:'):
                v = line.split(':', 1)[1].strip()
                installed = None if v == '(none)' else v
            elif line.startswith('Candidate:'):
                v = line.split(':', 1)[1].strip()
                candidate = None if v == '(none)' else v
        return installed, candidate
    except Exception:
        return None, None

@app.route('/api/system/tool_versions', methods=['GET'])
@requires_auth
def get_tool_versions():
    results = []
    for entry in TOOL_VERSION_COMMANDS:
        name, argv, package = entry["tool"], entry["cmd"], entry["package"]

        # apt's own candidate version - independent of whether the tool's
        # own --version invocation below succeeds, since a broken PATH entry
        # or similar shouldn't hide "there's a newer package available".
        latest_version = None
        update_available = False
        if package:
            apt_installed, apt_candidate = _apt_candidate_version(package)
            latest_version = apt_candidate
            if apt_installed and apt_candidate and apt_installed != apt_candidate:
                update_available = True

        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                # A non-zero exit (e.g. dpkg-query reporting "no packages
                # found matching X") means the underlying check failed, not
                # that we found a real version string in stderr - treat it
                # the same as "not installed" rather than displaying the
                # raw error text as if it were version output.
                results.append({"tool": name, "version": "Not installed", "installed": False, "package": package,
                                 "latest_version": latest_version, "update_available": update_available})
                continue
            raw = res.stdout.strip() or res.stderr.strip() or "(no version output)"
            lines = raw.splitlines()
            # MVT's `version` subcommand buries the actual version number a
            # few lines into a banner rather than putting it on line 1 like
            # every other tool here - prefer a line that actually says
            # "Version:" when one exists, instead of showing the banner text.
            version_line = next((l.strip() for l in lines if 'version:' in l.lower()), lines[0])
            results.append({"tool": name, "version": version_line, "installed": True, "package": package,
                             "latest_version": latest_version, "update_available": update_available})
        except FileNotFoundError:
            results.append({"tool": name, "version": "Not installed", "installed": False, "package": package,
                             "latest_version": latest_version, "update_available": update_available})
        except subprocess.TimeoutExpired:
            results.append({"tool": name, "version": "timed out", "installed": True, "package": package,
                             "latest_version": latest_version, "update_available": update_available})
        except Exception as e:
            results.append({"tool": name, "version": f"error: {e}", "installed": False, "package": package,
                             "latest_version": latest_version, "update_available": update_available})

    return jsonify({"success": True, "tools": results})

@app.route('/api/system/install_tool', methods=['POST'])
@requires_auth
@requires_permission('settings')
def install_tool():
    req = request.get_json() or {}
    package = req.get('package', '')

    if package not in TOOL_INSTALLABLE_PACKAGES:
        return jsonify({"success": False, "error": f"'{package}' isn't a recognized installable package for this station."}), 400

    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')

    def do_install():
        return subprocess.run(
            ['sudo', '/usr/bin/apt-get', 'install', '-y', package],
            capture_output=True, text=True, timeout=300, env=env
        )

    try:
        # Try the direct install first - most of the time the package is
        # already resolvable from the existing index, and skipping the
        # update step here makes the common case noticeably faster (an
        # unconditional "apt-get update" before every single click was
        # adding real, sometimes slow, network-dependent time to installs
        # that didn't need it). Only fall back to update+retry if the
        # first attempt specifically failed because the package couldn't
        # be found - that's the one case a stale index actually explains.
        res = do_install()

        if res.returncode != 0 and 'unable to locate package' in res.stderr.lower():
            subprocess.run(['sudo', '/usr/bin/apt-get', 'update'], capture_output=True, timeout=120, env=env)
            res = do_install()

        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr.strip()[-800:] or "apt-get install failed."}), 500

        log_chain_of_custody("tool_package_installed", {"package": package})
        return jsonify({"success": True, "message": f"{package} installed successfully."})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Install timed out - check your network connection and try again."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/change_password', methods=['POST'])
@requires_auth
def change_password():
    req = request.get_json() or {}
    curr_pass = req.get('current_password', '')
    new_pass = req.get('new_password', '')

    if not new_pass or len(new_pass) < 8:
        return jsonify({"success": False, "error": "New password must be at least 8 characters long."}), 400

    cfg = load_runtime_config()
    users = cfg.get('users')

    if users:
        # Multi-user mode: self-service only - this always targets whoever
        # is actually logged in (g.forensic_user), never a username picked
        # from the request body, so one user can never change another's
        # password through this route (that's /api/users/reset_password,
        # admin-only, with its own re-auth requirement).
        username = getattr(g, 'forensic_user', None)
        user = find_user(username, users)
        if not user or not check_password_hash(user.get('password_hash', ''), curr_pass):
            return jsonify({"success": False, "error": "Current password is incorrect."}), 400
        user['password_hash'] = generate_password_hash(new_pass)
        save_runtime_config(cfg)
        return jsonify({"success": True, "message": "Password changed successfully. This takes effect immediately."})

    # Legacy single-shared-account path - unchanged.
    if not hmac.compare_digest(curr_pass, get_active_admin_pass()):
        return jsonify({"success": False, "error": "Current password is incorrect."}), 400
    cfg['pass'] = new_pass
    save_runtime_config(cfg)
    return jsonify({"success": True, "message": "Password changed successfully. This takes effect immediately."})

@app.route('/api/whoami', methods=['GET'])
@requires_auth
def whoami():
    username = getattr(g, 'forensic_user', None)
    perms = get_current_user_permissions()
    return jsonify({
        "username": username,
        "role": get_current_user_role(),
        "permissions": perms,
    })

@app.route('/api/users/list', methods=['GET'])
@requires_auth
@requires_permission('manage_users')
def users_list():
    users = load_runtime_config().get('users') or []
    groups_by_id = {grp['id']: grp for grp in get_user_groups()}
    out = []
    for u in users:
        gid = get_user_group_id(u)
        grp = groups_by_id.get(gid)
        out.append({
            "username": u.get('username'),
            "group_id": gid,
            "group_name": grp['name'] if grp else gid,
            "created_at": u.get('created_at'),
            "last_login": u.get('last_login'),
        })
    return jsonify({"success": True, "users": out})

@app.route('/api/users/create', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def users_create():
    req = request.get_json() or {}
    username = (req.get('username') or '').strip()
    password = req.get('password') or ''
    group_id = req.get('group_id') or 'analyst'

    if not username:
        return jsonify({"success": False, "error": "Username is required."}), 400
    if not password or len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters long."}), 400
    if not find_group(group_id):
        return jsonify({"success": False, "error": f"'{group_id}' is not a recognized user group."}), 400

    cfg = load_runtime_config()
    users = cfg.setdefault('users', [])
    if find_user(username, users):
        return jsonify({"success": False, "error": f"A user named '{username}' already exists."}), 409

    users.append({
        "username": username,
        "password_hash": generate_password_hash(password),
        "group_id": group_id,
        # Kept in sync only for any external tooling that might still read
        # the pre-groups field directly - nothing in this app reads it
        # anymore (get_user_group_id() always prefers group_id when present).
        "role": "admin" if group_id == "admin" else "standard",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_runtime_config(cfg)
    log_chain_of_custody("user_create", {"username": username, "group_id": group_id})
    return jsonify({"success": True, "message": f"User '{username}' created."})

@app.route('/api/users/delete', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def users_delete():
    req = request.get_json() or {}
    username = (req.get('username') or '').strip()
    current_password = req.get('current_password') or ''

    if not caller_reauth_ok(current_password):
        return jsonify({"success": False, "error": "Your current password is incorrect."}), 400

    cfg = load_runtime_config()
    users = cfg.get('users') or []

    target = find_user(username, users)
    if not target:
        return jsonify({"success": False, "error": f"No user named '{username}' exists."}), 404

    admin_count = sum(1 for u in users if get_user_group_id(u) == 'admin')
    if get_user_group_id(target) == 'admin' and admin_count <= 1:
        return jsonify({"success": False, "error": "Cannot delete the last remaining Admin-group account."}), 409

    cfg['users'] = [u for u in users if not hmac.compare_digest(u.get('username', ''), username)]
    save_runtime_config(cfg)
    log_chain_of_custody("user_delete", {"username": username})
    return jsonify({"success": True, "message": f"User '{username}' deleted."})

@app.route('/api/users/reset_password', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def users_reset_password():
    # Deliberately does NOT require the caller's own password (unlike
    # users_delete(), which still does) - the manage_users permission check
    # above is already the real access-control boundary here, and deleting
    # an account is a materially more consequential/irreversible action
    # than resetting a password, so the two don't need identical friction.
    req = request.get_json() or {}
    username = (req.get('username') or '').strip()
    new_password = req.get('new_password') or ''

    if not new_password or len(new_password) < 8:
        return jsonify({"success": False, "error": "New password must be at least 8 characters long."}), 400

    cfg = load_runtime_config()
    users = cfg.get('users') or []

    target = find_user(username, users)
    if not target:
        return jsonify({"success": False, "error": f"No user named '{username}' exists."}), 404

    target['password_hash'] = generate_password_hash(new_password)
    save_runtime_config(cfg)
    log_chain_of_custody("user_reset_password", {"username": username})
    return jsonify({"success": True, "message": f"Password for '{username}' reset."})

@app.route('/api/user_groups', methods=['GET', 'POST'])
@requires_auth
@requires_permission('manage_users')
def user_groups_collection():
    if request.method == 'GET':
        return jsonify({
            "success": True,
            "groups": get_user_groups(),
            # Single source of truth for the frontend's checkbox list, so it
            # never hardcodes the permission-key/label pairs itself.
            "permission_keys": [{"key": k, "label": label} for k, label in PERMISSION_KEYS],
        })

    req = request.get_json() or {}
    name = (req.get('name') or '').strip()[:60]
    if not name:
        return jsonify({"success": False, "error": "Group name is required."}), 400
    if name.lower() in ('admin', 'analyst'):
        return jsonify({"success": False, "error": "That name is reserved for a built-in group."}), 400

    cfg = load_runtime_config()
    groups = cfg.setdefault('user_groups', [])

    # Soft-dedupe on id collision (numeric suffix), matching this app's
    # existing precedent for custom report templates - there's no on-disk
    # artifact at stake for a duplicate group *name*, just a cosmetic label.
    base_id = re.sub(r'[^a-z0-9_]+', '_', name.lower()).strip('_') or 'group'
    existing_ids = {g['id'] for g in get_user_groups()}
    group_id = base_id
    n = 2
    while group_id in existing_ids:
        group_id = f"{base_id}_{n}"
        n += 1

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "id": group_id, "name": name,
        "permissions": _normalize_permissions(req.get('permissions')),
        "created_at": now, "updated_at": now,
    }
    groups.append(record)
    save_runtime_config(cfg)
    log_chain_of_custody("user_group_create", {"group_id": group_id, "name": name, "permissions": record['permissions']})
    return jsonify({"success": True, "group": dict(record, is_builtin=False)})

@app.route('/api/user_groups/<group_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('manage_users')
def user_groups_detail(group_id):
    if group_id == 'admin':
        return jsonify({"success": False, "error": "The Admin group always has full access and can't be modified or deleted."}), 400

    cfg = load_runtime_config()
    groups = cfg.setdefault('user_groups', [])

    if request.method == 'DELETE':
        if group_id == 'analyst':
            return jsonify({"success": False, "error": "The built-in Analyst group can't be deleted."}), 400
        idx = next((i for i, g_ in enumerate(groups) if g_.get('id') == group_id), None)
        if idx is None:
            return jsonify({"success": False, "error": "That group doesn't exist."}), 404
        groups.pop(idx)
        # Any user pointed at the deleted group falls back to Analyst rather
        # than being left with a dangling group_id - matches this app's
        # existing "reset to a sane default" precedent (e.g. deleting a
        # custom report template resets the station default to 'standard').
        reassigned = 0
        for u in cfg.get('users', []):
            if u.get('group_id') == group_id:
                u['group_id'] = 'analyst'
                reassigned += 1
        save_runtime_config(cfg)
        log_chain_of_custody("user_group_delete", {"group_id": group_id, "users_reassigned_to_analyst": reassigned})
        return jsonify({"success": True})

    # PUT (update name/permissions). Analyst's name is fixed (it's the
    # built-in default new users land in) but its permissions ARE editable -
    # a custom group's name and permissions are both fully editable.
    req = request.get_json() or {}
    permissions = _normalize_permissions(req.get('permissions'))

    if group_id == 'analyst':
        idx = next((i for i, g_ in enumerate(groups) if g_.get('id') == 'analyst'), None)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        record = {"id": "analyst", "name": "Analyst", "permissions": permissions, "updated_at": now}
        if idx is None:
            record['created_at'] = now
            groups.append(record)
        else:
            record['created_at'] = groups[idx].get('created_at', now)
            groups[idx] = record
        save_runtime_config(cfg)
        log_chain_of_custody("user_group_update", {"group_id": "analyst", "permissions": permissions})
        return jsonify({"success": True, "group": dict(record, is_builtin=True)})

    idx = next((i for i, g_ in enumerate(groups) if g_.get('id') == group_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "That group doesn't exist."}), 404

    name = (req.get('name') or '').strip()[:60] or groups[idx].get('name')
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "id": group_id, "name": name, "permissions": permissions,
        "created_at": groups[idx].get('created_at', now), "updated_at": now,
    }
    groups[idx] = record
    save_runtime_config(cfg)
    log_chain_of_custody("user_group_update", {"group_id": group_id, "name": name, "permissions": permissions})
    return jsonify({"success": True, "group": dict(record, is_builtin=False)})

@app.route('/api/system/tls_status', methods=['GET'])
@requires_auth
def tls_status():
    if not os.path.exists(TLS_CERT_PATH):
        return jsonify({"success": True, "configured": False})
    try:
        res = subprocess.run(
            ["openssl", "x509", "-in", TLS_CERT_PATH, "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr.strip() or "Failed to read certificate."}), 500

        # openssl's -subject/-issuer/-dates/-fingerprint output is one
        # "key=value" line per field, but the exact key casing has drifted
        # across OpenSSL versions (e.g. "SHA256 Fingerprint" vs "sha256
        # Fingerprint") - normalize to lowercase for a stable lookup.
        fields = {}
        for line in res.stdout.splitlines():
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            fields[key.strip().lower()] = value.strip()

        return jsonify({
            "success": True,
            "configured": True,
            "subject": fields.get("subject"),
            "issuer": fields.get("issuer"),
            "not_before": fields.get("notbefore"),
            "not_after": fields.get("notafter"),
            "fingerprint_sha256": fields.get("sha256 fingerprint"),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Shared by tls_upload (examiner-provided files) and tls_generate (a freshly
# openssl-generated pair) - both end up with a cert/key sitting at some temp
# path that needs the same install-and-reload treatment. Assumes the caller
# has already validated the cert/key are a genuinely matching pair.
def _install_tls_pair(tmp_cert_path, tmp_key_path, coc_action, coc_details=None):
    cp_cert = subprocess.run(["sudo", "cp", tmp_cert_path, TLS_CERT_PATH], capture_output=True, text=True)
    if cp_cert.returncode != 0:
        return jsonify({"success": False, "error": f"Failed to install certificate: {cp_cert.stderr.strip()}"}), 500
    cp_key = subprocess.run(["sudo", "cp", tmp_key_path, TLS_KEY_PATH], capture_output=True, text=True)
    if cp_key.returncode != 0:
        return jsonify({"success": False, "error": f"Failed to install private key: {cp_key.stderr.strip()}"}), 500
    subprocess.run(["sudo", "chmod", "600", TLS_KEY_PATH], capture_output=True)

    log_chain_of_custody(coc_action, coc_details or {})

    # "TLS never configured" is a normal, expected state (TLS setup is
    # optional at install time) - install the cert/key regardless (useful
    # prep work) but don't try to reload a proxy that was never enabled.
    if not os.path.exists("/etc/nginx/sites-enabled/pi-forensics"):
        return jsonify({"success": True, "message": "Certificate installed. nginx is not currently configured as a "
                         "reverse proxy for this station - run install.py's TLS setup or configure nginx manually "
                         "for this to take effect."})

    reload_res = subprocess.run(["sudo", "systemctl", "reload", "nginx"], capture_output=True, text=True)
    if reload_res.returncode != 0:
        return jsonify({"success": True, "message": f"Certificate installed, but reloading nginx failed: "
                         f"{reload_res.stderr.strip()}. Reload it manually."})

    return jsonify({"success": True, "message": "Certificate installed and nginx reloaded successfully."})

@app.route('/api/system/tls_upload', methods=['POST'])
@requires_auth
@requires_permission('settings')
def tls_upload():
    cert_file = request.files.get('cert_file')
    key_file = request.files.get('key_file')
    if not cert_file or not key_file:
        return jsonify({"success": False, "error": "Both a certificate file and a private key file are required."}), 400

    tmp_cert_fd, tmp_cert_path = tempfile.mkstemp(prefix="pif_tls_cert_")
    tmp_key_fd, tmp_key_path = tempfile.mkstemp(prefix="pif_tls_key_")
    try:
        os.close(tmp_cert_fd)
        os.close(tmp_key_fd)
        cert_file.save(tmp_cert_path)
        key_file.save(tmp_key_path)
        os.chmod(tmp_cert_path, 0o600)
        os.chmod(tmp_key_path, 0o600)

        parse_res = subprocess.run(["openssl", "x509", "-noout", "-in", tmp_cert_path], capture_output=True, text=True)
        if parse_res.returncode != 0:
            return jsonify({"success": False, "error": f"Invalid certificate file: {parse_res.stderr.strip()}"}), 400

        # Cert/key must be a genuinely matching pair BEFORE anything gets
        # installed - compare RSA modulus hashes rather than trusting the
        # two uploaded files at face value. RSA only for v1 (matches what
        # install.py's own self-signed generation produces); an EC key
        # here fails this check cleanly rather than silently mismatching.
        cert_mod = subprocess.run(["openssl", "x509", "-noout", "-modulus", "-in", tmp_cert_path], capture_output=True, text=True)
        key_mod = subprocess.run(["openssl", "rsa", "-noout", "-modulus", "-in", tmp_key_path], capture_output=True, text=True)
        if cert_mod.returncode != 0 or key_mod.returncode != 0:
            return jsonify({"success": False, "error": "Could not read an RSA modulus from the certificate/key - only RSA key/cert pairs are supported."}), 400
        if cert_mod.stdout.strip() != key_mod.stdout.strip():
            return jsonify({"success": False, "error": "Certificate and private key do not match - nothing was installed."}), 400

        return _install_tls_pair(tmp_cert_path, tmp_key_path, "tls_cert_replaced")
    finally:
        for p in (tmp_cert_path, tmp_key_path):
            try:
                os.remove(p)
            except OSError:
                pass

# Same self-signed recipe install.py's own TLS setup uses (rsa:4096, 825
# days, openssl req -x509), but runnable from the UI so an examiner doesn't
# need a terminal to regenerate one - e.g. after the Pi's IP changes and the
# SAN-less/wrong-IP cert install.py originally generated no longer matches,
# or just to get a fresh cert without re-running the whole installer.
# Includes real subjectAltName entries (install.py's CN-only cert predates
# this and can trip stricter modern browsers that ignore CN entirely) -
# every non-loopback IPv4 address psutil finds, plus pi-forensics.local and
# any examiner-supplied extra hostname.
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$')

@app.route('/api/system/tls_generate', methods=['POST'])
@requires_auth
@requires_permission('settings')
def tls_generate():
    data = request.get_json(silent=True) or {}
    extra_hostname = (data.get('extra_hostname') or '').strip()

    if extra_hostname and not _HOSTNAME_RE.match(extra_hostname):
        return jsonify({"success": False, "error": "Additional hostname contains characters that aren't valid in a hostname."}), 400

    san_entries = ["DNS:pi-forensics.local"]
    if extra_hostname:
        san_entries.append(f"DNS:{extra_hostname}")

    seen_ips = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == 2 and addr.address != "127.0.0.1" and addr.address not in seen_ips:  # AF_INET (IPv4)
                seen_ips.add(addr.address)
                san_entries.append(f"IP:{addr.address}")

    common_name = extra_hostname or (sorted(seen_ips)[0] if seen_ips else "pi-forensics.local")

    tmp_cert_fd, tmp_cert_path = tempfile.mkstemp(prefix="pif_tls_gen_cert_")
    tmp_key_fd, tmp_key_path = tempfile.mkstemp(prefix="pif_tls_gen_key_")
    try:
        os.close(tmp_cert_fd)
        os.close(tmp_key_fd)

        gen_res = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
            "-keyout", tmp_key_path, "-out", tmp_cert_path,
            "-days", "825", "-subj", f"/CN={common_name}",
            "-addext", f"subjectAltName={','.join(san_entries)}",
            # openssl req -x509 leaves these off by default, which is fine
            # for a cert only ever inspected by openssl itself but not for
            # real browsers - Chrome/Windows increasingly enforce that a
            # certificate presented for TLS carries an Extended Key Usage
            # with serverAuth, and reject (or silently distrust) one that's
            # also marked CA:TRUE (the openssl req -x509 default) without
            # it, even after it's correctly imported into Trusted Root.
            # Confirmed as the actual cause of a real "still shows not
            # secure after installing the cert on Windows" report - adding
            # these two fixed it.
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-addext", "extendedKeyUsage=serverAuth"
        ], capture_output=True, text=True, timeout=60)
        if gen_res.returncode != 0:
            return jsonify({"success": False, "error": f"Certificate generation failed: {gen_res.stderr.strip()}"}), 500

        return _install_tls_pair(tmp_cert_path, tmp_key_path, "tls_cert_generated",
                                  {"common_name": common_name, "subject_alt_names": san_entries})
    finally:
        for p in (tmp_cert_path, tmp_key_path):
            try:
                os.remove(p)
            except OSError:
                pass

# Public certificate only - the private key never leaves the station, by
# design, regardless of who's authenticated. An examiner downloads this to
# import into a client device's trust store (browser/OS), following the
# instructions the frontend shows alongside this button - trusting the cert
# locally is what actually removes the "not trusted" warning; nothing this
# app does server-side can change what a client's own browser trusts.
@app.route('/api/system/tls_download_cert', methods=['GET'])
@requires_auth
def tls_download_cert():
    if not os.path.exists(TLS_CERT_PATH):
        return jsonify({"success": False, "error": "No certificate is currently installed."}), 404
    return send_file(TLS_CERT_PATH, as_attachment=True, download_name="pi-forensics.crt", mimetype="application/x-x509-ca-cert")

@app.route('/api/settings/case_reporting', methods=['GET', 'POST'])
@requires_auth
def settings_case_reporting():
    if request.method == 'GET':
        cfg = load_runtime_config()
        return jsonify({
            "success": True,
            "report_defaults": cfg.get('report_defaults', {}),
            "custom_case_fields": cfg.get('custom_case_fields', []),
        })

    # GET is left ungated above - Reporting's Export pane reads these
    # defaults too, not just Settings - only the write path is
    # Settings-exclusive.
    if not get_current_user_permissions().get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    req = request.get_json() or {}
    cfg = load_runtime_config()

    if 'report_defaults' in req:
        incoming = req['report_defaults'] or {}
        # logo_path is deliberately not settable here - it's managed only
        # by /api/settings/report_logo (upload) and its /clear counterpart,
        # so this save path can never point it at an arbitrary path string.
        existing_logo = cfg.get('report_defaults', {}).get('branding', {}).get('logo_path', '')
        # A station default must never persist a dangling custom:<id>
        # reference (e.g. the template was deleted, or the value is just
        # garbage) - _resolve_template_ref() is the single source of truth
        # for what a template string resolves to, shared with export_report().
        incoming_template = incoming.get('template')
        if incoming_template in REPORT_TEMPLATES:
            stored_template = incoming_template
        elif isinstance(incoming_template, str) and incoming_template.startswith('custom:'):
            try:
                _resolve_template_ref(incoming_template, cfg)
                stored_template = incoming_template
            except ValueError:
                stored_template = 'standard'
        else:
            stored_template = 'standard'
        cfg['report_defaults'] = {
            "template": stored_template,
            "sections": {k: bool(v) for k, v in (incoming.get('sections') or {}).items()},
            "job_fields": {k: bool(v) for k, v in (incoming.get('job_fields') or {}).items()},
            "branding": {
                "header_text": (incoming.get('branding', {}).get('header_text') or '').strip()[:200],
                "logo_path": existing_logo,
            },
        }

    if 'custom_case_fields' in req:
        # Each field's key is derived from its label (whitelisted charset,
        # matching sanitize_case_slug()'s approach elsewhere) rather than
        # accepted from the client directly, and de-duplicated - this is
        # what every case record's custom_fields dict gets keyed by, so it
        # must stay a safe, stable identifier even if two examiners pick
        # the same display label.
        fields = []
        seen_keys = set()
        for f in (req['custom_case_fields'] or []):
            label = (f.get('label') or '').strip()[:60]
            if not label:
                continue
            base_key = re.sub(r'[^a-z0-9_]+', '_', label.lower()).strip('_') or 'field'
            key = base_key
            n = 2
            while key in seen_keys:
                key = f"{base_key}_{n}"
                n += 1
            seen_keys.add(key)
            fields.append({"key": key, "label": label})
        cfg['custom_case_fields'] = fields

    save_runtime_config(cfg)
    return jsonify({"success": True})

CUSTOM_REPORT_TEMPLATE_NAME_MAX = 80

def _custom_report_template_from_payload(req):
    """Validates and normalizes a create/update payload for a custom report
    template into the stored record shape (minus id/created_at, which the
    caller fills in - id in particular never changes across an update, see
    the PUT handler below). Returns (record_dict, None) or (None,
    error_message) - caller decides the HTTP status for an error.

    Unknown section keys are rejected outright (400) rather than silently
    dropped, since accepting them would let stale/malformed client state
    corrupt storage. Any of the 13 known blocks missing from the payload is
    defensively auto-filled (default title, enabled) rather than rejected -
    every stored record is expected to always cover all 13 keys (what the
    builder UI edits, and what _resolve_section_order() reads), so this is
    a self-healing default a slightly-out-of-date client shouldn't be
    punished for."""
    name = (req.get('name') or '').strip()[:CUSTOM_REPORT_TEMPLATE_NAME_MAX]
    if not name:
        return None, "Template name is required."

    by_key = {}
    for entry in (req.get('sections') or []):
        key = entry.get('key')
        if key not in _REPORT_SECTION_BLOCK_MAP:
            return None, f"Unknown report section '{key}'."
        by_key[key] = {
            "key": key,
            "title": (entry.get('title') or '').strip()[:120],
            "enabled": bool(entry.get('enabled', True)),
        }
    # Preserve the payload's own order for keys it included, then append
    # any of the 13 registry blocks it left out, in the registry's own
    # default order.
    sections = list(by_key.values())
    for block in REPORT_SECTION_BLOCKS:
        if block['key'] not in by_key:
            sections.append({"key": block['key'], "title": block['default_title'], "enabled": True})

    job_fields_in = req.get('job_fields') or {}
    job_fields = {
        "telemetry": bool(job_fields_in.get('telemetry', True)),
        "params": bool(job_fields_in.get('params', True)),
        "hashes": bool(job_fields_in.get('hashes', True)),
    }

    return {
        "name": name,
        "sections": sections,
        "job_fields": job_fields,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, None

@app.route('/api/report_templates/custom', methods=['GET', 'POST'])
@requires_auth
def report_templates_custom():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({
            "success": True,
            "templates": cfg.get('custom_report_templates', []),
            # Single source of truth for the frontend builder's palette -
            # it never hardcodes the 13-block list itself.
            "blocks": [{"key": b["key"], "default_title": b["default_title"]} for b in REPORT_SECTION_BLOCKS],
        })

    # GET is left ungated above - both the Reporting Export pane and
    # Settings > Case & Reporting need the template list - only creating a
    # new one is gated, and by either area since the builder is reachable
    # from both.
    perms = get_current_user_permissions()
    if not (perms.get('settings', False) or perms.get('reporting', False)):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    req = request.get_json() or {}
    record, error = _custom_report_template_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400

    templates = cfg.setdefault('custom_report_templates', [])
    # Soft-dedupe on name collision (numeric suffix), not a hard 409 like
    # case-folder creation - there's no on-disk artifact at stake for a
    # duplicate template *name*, just a cosmetic label.
    base_id = re.sub(r'[^a-z0-9_]+', '_', record['name'].lower()).strip('_') or 'template'
    existing_ids = {r['id'] for r in templates}
    template_id = base_id
    n = 2
    while template_id in existing_ids:
        template_id = f"{base_id}_{n}"
        n += 1

    record['id'] = template_id
    record['created_at'] = record['updated_at']
    templates.append(record)
    save_runtime_config(cfg)
    return jsonify({"success": True, "template": record})

@app.route('/api/report_templates/custom/<template_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings', 'reporting')
def report_templates_custom_detail(template_id):
    cfg = load_runtime_config()
    templates = cfg.get('custom_report_templates', [])
    idx = next((i for i, r in enumerate(templates) if r.get('id') == template_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "Custom report template not found."}), 404

    if request.method == 'DELETE':
        templates.pop(idx)
        # id never changes across an update (see below), so this exact
        # match is reliable - a station default that was pointing at the
        # just-deleted template must not be left dangling.
        if cfg.get('report_defaults', {}).get('template') == f'custom:{template_id}':
            cfg.setdefault('report_defaults', {})['template'] = 'standard'
        save_runtime_config(cfg)
        return jsonify({"success": True})

    req = request.get_json() or {}
    record, error = _custom_report_template_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400
    # id is fixed at creation and never regenerated from a new name - a
    # rename must not silently invalidate a station default (or a bookmarked
    # per-export selection) already pointing at 'custom:<id>'.
    record['id'] = template_id
    record['created_at'] = templates[idx].get('created_at', record['updated_at'])
    templates[idx] = record
    save_runtime_config(cfg)
    return jsonify({"success": True, "template": record})

REPORT_LOGO_MAX_BYTES = 2_000_000

@app.route('/api/settings/report_logo', methods=['POST'])
@requires_auth
@requires_permission('settings')
def upload_report_logo():
    logo_file = request.files.get('logo')
    if not logo_file or not logo_file.filename:
        return jsonify({"success": False, "error": "No logo file provided."}), 400

    ext = os.path.splitext(logo_file.filename)[1].lower()
    if ext not in ATTACHMENT_IMAGE_EXT:
        return jsonify({"success": False, "error": f"Unsupported image type '{ext}'. Use one of: {', '.join(sorted(ATTACHMENT_IMAGE_EXT))}"}), 400

    logo_file.seek(0, os.SEEK_END)
    size = logo_file.tell()
    logo_file.seek(0)
    if size > REPORT_LOGO_MAX_BYTES:
        return jsonify({"success": False, "error": f"Logo file too large ({size} bytes) - max {REPORT_LOGO_MAX_BYTES} bytes."}), 400

    logo_path = os.path.join(INSTALL_DIR, f"report_logo{ext}")
    # Remove any previously-saved logo under a different extension so
    # switching image types doesn't leave a stale, unreferenced file behind.
    for other_ext in ATTACHMENT_IMAGE_EXT:
        stale_path = os.path.join(INSTALL_DIR, f"report_logo{other_ext}")
        if stale_path != logo_path and os.path.exists(stale_path):
            try:
                os.remove(stale_path)
            except OSError:
                pass

    logo_file.save(logo_path)

    cfg = load_runtime_config()
    cfg.setdefault('report_defaults', {}).setdefault('branding', {})['logo_path'] = logo_path
    save_runtime_config(cfg)
    return jsonify({"success": True, "message": "Logo uploaded."})

@app.route('/api/settings/report_logo/clear', methods=['POST'])
@requires_auth
@requires_permission('settings')
def clear_report_logo():
    cfg = load_runtime_config()
    logo_path = cfg.get('report_defaults', {}).get('branding', {}).get('logo_path', '')
    if logo_path and os.path.exists(logo_path):
        try:
            os.remove(logo_path)
        except OSError:
            pass
    if 'report_defaults' in cfg and 'branding' in cfg['report_defaults']:
        cfg['report_defaults']['branding']['logo_path'] = ''
    save_runtime_config(cfg)
    return jsonify({"success": True})

@app.route('/api/system/power', methods=['POST'])
@requires_auth
@requires_permission('settings')
def system_power_control():
    req = request.get_json() or {}
    action = req.get('action')

    if action == 'reboot':
        subprocess.Popen(['sudo', '/sbin/reboot'])
        return jsonify({"success": True, "message": "System reboot initiated."})
    elif action == 'poweroff':
        subprocess.Popen(['sudo', '/sbin/poweroff'])
        return jsonify({"success": True, "message": "System shutdown initiated."})

    return jsonify({"success": False, "error": "Invalid power action."}), 400

@app.route('/api/system/restart_service', methods=['POST'])
@requires_auth
@requires_permission('settings')
def restart_forensic_service():
    def delayed_restart():
        time.sleep(1)
        subprocess.run(['sudo', '/bin/systemctl', 'restart', 'pi-forensics.service'])

    threading.Thread(target=delayed_restart, daemon=True).start()
    return jsonify({"success": True, "message": "Forensic service restart initiated - this page will disconnect briefly."})

@app.route('/api/system/restart_kiosk', methods=['POST'])
@requires_auth
@requires_permission('settings')
def restart_touch_kiosk():
    # install.py's labwc autostart script (started once, automatically, at
    # kiosk desktop login - not by this route) already runs its own
    # persistent "while true; relaunch chromium whenever it exits" respawn
    # loop in the background for the lifetime of the kiosk session. Killing
    # chromium is enough on its own to make that already-running loop
    # relaunch it fresh within a few seconds - the exact same recovery path
    # a real chromium crash already goes through.
    #
    # This route must NOT also re-launch the whole autostart script (a
    # previous version did, via subprocess.Popen(['bash', autostart_path])
    # after the pkill below) - doing so starts a SECOND, fully independent
    # copy of that same respawn loop (plus its own 30-minute watchdog loop),
    # racing the original. Both loops then repeatedly kill and relaunch
    # chromium against each other forever, which is what a rapid white-
    # flash/flicker back to the UI on the touchscreen actually was - a real
    # bug, not a hypothetical, found live 2026-08-15. Every click of this
    # button used to add yet another competing loop into that race, making
    # it worse each time rather than fixing anything.
    autostart_path = os.path.join(os.path.expanduser('~'), '.config', 'labwc', 'autostart')
    if not os.path.exists(autostart_path):
        return jsonify({"success": False, "error": f"Kiosk autostart script not found at {autostart_path}."}), 404

    try:
        subprocess.run(['pkill', '-9', '-f', 'chromium'], capture_output=True, timeout=10)
        return jsonify({"success": True, "message": "Touchscreen kiosk display restarting - the running autostart watchdog will relaunch it within a few seconds."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/git_update', methods=['POST'])
@requires_auth
@requires_permission('settings')
def git_update_application():
    try:
        res = subprocess.run(['git', 'pull', 'origin', 'main'], cwd=INSTALL_DIR, capture_output=True, text=True, timeout=60)
        output = res.stdout.strip() or res.stderr.strip()

        if res.returncode == 0:
            def delayed_restart():
                time.sleep(2)
                subprocess.run(['sudo', '/bin/systemctl', 'restart', 'pi-forensics.service'])
            threading.Thread(target=delayed_restart, daemon=True).start()
            return jsonify({"success": True, "message": f"Git update successful:\n{output}\n\nRestarting service..."})
        else:
            return jsonify({"success": False, "error": f"git pull failed: {output}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "git pull timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/os_update', methods=['POST'])
@requires_auth
@requires_permission('settings')
def update_operating_system():
    def run_update():
        try:
            subprocess.run(['sudo', '/usr/bin/apt-get', 'update'], capture_output=True, timeout=300)
            subprocess.run(['sudo', '/usr/bin/apt-get', 'upgrade', '-y'], capture_output=True, timeout=1800)
        except Exception as e:
            print(f"OS update error: {e}")

    threading.Thread(target=run_update, daemon=True).start()
    return jsonify({"success": True, "message": "OS update started in the background (apt-get update && upgrade -y). This can take a while - check journalctl or SSH in to monitor."})

@app.route('/api/system/eject_drive', methods=['POST'])
@requires_auth
@requires_permission('settings')
def eject_usb_drive():
    req = request.get_json() or {}
    drive = req.get('drive', '').strip()

    if not is_valid_block_device(drive):
        return jsonify({"success": False, "error": f"'{drive}' is not a recognized whole-disk device."}), 400

    try:
        subprocess.run(['sync'], timeout=30)
        for part in sorted(glob.glob(f"{drive}*")):
            subprocess.run(['sudo', 'udevil', 'unmount', '-b', part], capture_output=True)
            subprocess.run(['sudo', 'umount', part], capture_output=True)
        subprocess.run(['sudo', '/usr/sbin/blockdev', '--flushbufs', drive], capture_output=True)

        return jsonify({"success": True, "message": f"Drive {drive} safely unmounted and flushed. You can now disconnect it."})
    except Exception as e:
        return jsonify({"success": False, "error": f"Eject failed: {str(e)}"}), 500

@app.route('/api/system/interfaces', methods=['GET'])
@requires_auth
def get_network_interfaces():
    global last_pernic_check
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    pernic_counters = psutil.net_io_counters(pernic=True)
    now = time.time()
    new_pernic_check = {}

    for iface, addr_list in addrs.items():
        ip_addr = "Unassigned"
        mac_addr = "N/A"
        for addr in addr_list:
            if addr.family == 2:  # AF_INET (IPv4)
                ip_addr = addr.address
            elif addr.family == 17:  # AF_PACKET (MAC, Linux)
                mac_addr = addr.address

        is_up = stats[iface].isup if iface in stats else False

        # Real per-interface throughput, computed the same delta-over-time
        # way system_info()'s station-wide network_speed already is, just
        # keyed per interface instead of summed across all of them - a down
        # interface naturally deltas to ~0 since its counters stop moving,
        # but is forced to exactly 0 below regardless as a safety net against
        # any driver quirk reporting phantom traffic on a down link.
        upload_mbps = 0.0
        download_mbps = 0.0
        counters = pernic_counters.get(iface)
        if counters is not None:
            prev = last_pernic_check.get(iface)
            if prev is not None:
                time_delta = max(now - prev["time"], 0.001)
                sent_delta = max(counters.bytes_sent - prev["bytes_sent"], 0)
                recv_delta = max(counters.bytes_recv - prev["bytes_recv"], 0)
                upload_mbps = round((sent_delta / (1024 * 1024)) / time_delta, 2)
                download_mbps = round((recv_delta / (1024 * 1024)) / time_delta, 2)
            new_pernic_check[iface] = {"time": now, "bytes_sent": counters.bytes_sent, "bytes_recv": counters.bytes_recv}

        if not is_up:
            upload_mbps = 0.0
            download_mbps = 0.0

        interfaces.append({
            "interface": iface,
            "ip": ip_addr,
            "mac": mac_addr,
            "active": is_up,
            "upload_mbps": upload_mbps,
            "download_mbps": download_mbps
        })

    last_pernic_check = new_pernic_check
    return jsonify({"success": True, "interfaces": interfaces})

# --- Network Configuration (static IP / DHCP via NetworkManager) ---
# Confirmed live against the deployed station: NetworkManager (nmcli) is the
# active network stack on Debian trixie here, not dhcpcd/systemd-networkd
# (both inactive). Reading nmcli state works unprivileged (confirmed live);
# only *modifying* a connection needs sudo ("Insufficient privileges"
# without it) - so only apply_network_config() below runs anything via sudo.
_NMCLI_DEVICE_TYPES = {"ethernet", "wifi"}

def _nmcli_terse(args, timeout=15):
    res = subprocess.run(['nmcli'] + args, capture_output=True, text=True, timeout=timeout)
    return res.returncode, res.stdout, res.stderr

def _nmcli_list_devices():
    """Physical ethernet/wifi devices only - excludes loopback and the
    wifi-p2p virtual device, neither of which an examiner would configure."""
    rc, out, _ = _nmcli_terse(['-t', '-f', 'DEVICE,TYPE,STATE', 'device', 'status'])
    devices = []
    if rc != 0:
        return devices
    for line in out.strip().splitlines():
        parts = line.split(':')
        if len(parts) < 3:
            continue
        device, dtype, state = parts[0], parts[1], parts[2]
        if dtype in _NMCLI_DEVICE_TYPES:
            devices.append({"device": device, "type": dtype, "state": state})
    return devices

def _nmcli_resolve_connection(device):
    """The connection profile name for a device - found via the currently
    active device->connection mapping first, falling back to scanning every
    saved profile's interface-name so a currently unavailable/unplugged
    device (no active mapping) can still be configured ahead of time."""
    rc, out, _ = _nmcli_terse(['-t', '-f', 'DEVICE,CONNECTION', 'device', 'status'])
    if rc == 0:
        for line in out.strip().splitlines():
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[0] == device and parts[1]:
                return parts[1]

    rc, out, _ = _nmcli_terse(['-t', '-f', 'NAME', 'connection', 'show'])
    if rc != 0:
        return None
    for name in out.strip().splitlines():
        if not name:
            continue
        rc2, out2, _ = _nmcli_terse(['-g', 'connection.interface-name', 'connection', 'show', name])
        if rc2 == 0 and out2.strip() == device:
            return name
    return None

def _nmcli_get_ipv4(conn_name):
    rc, out, _ = _nmcli_terse(['-t', '-f', 'ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns', 'connection', 'show', conn_name])
    result = {"method": "auto", "address": "", "prefix": "", "gateway": "", "dns": []}
    if rc != 0:
        return result
    for line in out.strip().splitlines():
        if ':' not in line:
            continue
        field, _, value = line.partition(':')
        if field == 'ipv4.method':
            result["method"] = value or "auto"
        elif field == 'ipv4.addresses' and value:
            addr = re.split(r'[,\s]+', value)[0]
            if '/' in addr:
                ip_part, prefix_part = addr.split('/', 1)
                result["address"], result["prefix"] = ip_part, prefix_part
            else:
                result["address"] = addr
        elif field == 'ipv4.gateway':
            result["gateway"] = value
        elif field == 'ipv4.dns' and value:
            result["dns"] = [d for d in re.split(r'[,\s]+', value) if d]
    return result

def _apply_network_ipv4(conn_name, method, address=None, prefix=None, gateway=None, dns=None):
    """The actual sudo nmcli modify+up sequence - shared by both a real
    examiner-requested apply and the auto-revert restoring a snapshot,
    since both are just "set these ipv4.* properties and reactivate"."""
    if method == 'manual':
        cmd = ['sudo', 'nmcli', 'connection', 'modify', conn_name,
               'ipv4.method', 'manual',
               'ipv4.addresses', f"{address}/{prefix}",
               'ipv4.gateway', gateway or '',
               'ipv4.dns', " ".join(dns or [])]
    else:
        cmd = ['sudo', 'nmcli', 'connection', 'modify', conn_name,
               'ipv4.method', 'auto',
               'ipv4.addresses', '',
               'ipv4.gateway', '',
               'ipv4.dns', '']
    res_modify = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    res_up = subprocess.run(['sudo', 'nmcli', 'connection', 'up', conn_name], capture_output=True, text=True, timeout=30)
    return res_modify, res_up

@app.route('/api/network/config', methods=['GET'])
@requires_auth
def get_network_config():
    devices = []
    for dev in _nmcli_list_devices():
        conn_name = _nmcli_resolve_connection(dev["device"])
        ipv4 = _nmcli_get_ipv4(conn_name) if conn_name else {"method": "auto", "address": "", "prefix": "", "gateway": "", "dns": []}
        devices.append({**dev, "connection": conn_name, "ipv4": ipv4})

    with network_config_lock:
        pending = None
        if pending_network_revert:
            pending = {
                "device": pending_network_revert["device"],
                "revert_token": pending_network_revert["token"],
                "revert_at": pending_network_revert["revert_at"],
                "confirmed": pending_network_revert["confirmed"],
            }

    return jsonify({"success": True, "devices": devices, "pending_revert": pending, "revert_window_seconds": REVERT_WINDOW_SECONDS})

@app.route('/api/network/apply', methods=['POST'])
@requires_auth
@requires_permission('settings')
def apply_network_config():
    global pending_network_revert
    req = request.get_json() or {}
    device = req.get('device', '').strip()
    method = req.get('method', '').strip()

    known_devices = {d["device"] for d in _nmcli_list_devices()}
    if device not in known_devices:
        return jsonify({"success": False, "error": "Unknown network device."}), 400
    if method not in ('auto', 'manual'):
        return jsonify({"success": False, "error": "Method must be 'auto' or 'manual'."}), 400

    address = prefix = gateway = None
    dns_list = []
    if method == 'manual':
        try:
            address = str(ipaddress.ip_address(req.get('address', '').strip()))
            prefix = int(req.get('prefix', ''))
            if not (1 <= prefix <= 32):
                raise ValueError("Prefix length must be between 1 and 32.")
            gateway_raw = req.get('gateway', '').strip()
            gateway = str(ipaddress.ip_address(gateway_raw)) if gateway_raw else ''
            dns_raw = req.get('dns', '').strip()
            if dns_raw:
                for token in re.split(r'[,\s]+', dns_raw):
                    if token:
                        dns_list.append(str(ipaddress.ip_address(token)))
        except (ValueError, TypeError) as e:
            return jsonify({"success": False, "error": f"Invalid static IP configuration: {e}"}), 400

    conn_name = _nmcli_resolve_connection(device)
    if not conn_name:
        return jsonify({"success": False, "error": f"No connection profile found for {device}."}), 404

    snapshot = _nmcli_get_ipv4(conn_name)
    token = uuid.uuid4().hex
    revert_at = time.time() + REVERT_WINDOW_SECONDS

    with network_config_lock:
        pending_network_revert = {
            "token": token, "device": device, "connection": conn_name,
            "snapshot": snapshot, "revert_at": revert_at, "confirmed": False,
        }

    log_chain_of_custody("network_config_changed", {
        "device": device, "connection": conn_name, "method": method,
        "address": address, "prefix": prefix, "gateway": gateway, "dns": dns_list,
    })

    # Captured now, in the real request thread - delayed_revert() below runs
    # in a background daemon thread with no Flask request context, where
    # request/g would raise RuntimeError if touched directly.
    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
    requester_user = getattr(g, 'forensic_user', None)

    def delayed_apply():
        time.sleep(1)
        _apply_network_ipv4(conn_name, method, address, prefix, gateway, dns_list)
    threading.Thread(target=delayed_apply, daemon=True).start()

    def delayed_revert():
        global pending_network_revert
        time.sleep(max(revert_at - time.time(), 0))
        with network_config_lock:
            current = pending_network_revert
            if not current or current["token"] != token:
                return
            if current["confirmed"]:
                # Confirmed - no revert needed, but still clear the pending
                # state now that its window has passed, so GET /api/network/config
                # stops reporting a stale "confirmed: true" entry forever.
                pending_network_revert = None
                return
            snap = current["snapshot"]
            pending_network_revert = None
        _apply_network_ipv4(conn_name, snap["method"], snap["address"], snap["prefix"], snap["gateway"], snap["dns"])
        log_chain_of_custody("network_config_reverted", {"device": device, "connection": conn_name}, source_ip=requester_ip, user=requester_user)
    threading.Thread(target=delayed_revert, daemon=True).start()

    return jsonify({
        "success": True, "revert_token": token, "revert_at": revert_at,
        "message": f"Applying new network settings to {device}. This station will automatically revert to its previous settings in {REVERT_WINDOW_SECONDS} seconds unless you confirm.",
    })

@app.route('/api/network/confirm', methods=['POST'])
@requires_auth
@requires_permission('settings')
def confirm_network_config():
    req = request.get_json() or {}
    token = req.get('revert_token', '').strip()

    with network_config_lock:
        if not pending_network_revert or pending_network_revert["token"] != token:
            return jsonify({"success": False, "error": "This confirmation has expired or no longer matches the current pending change."}), 404
        pending_network_revert["confirmed"] = True
        device = pending_network_revert["device"]

    log_chain_of_custody("network_config_confirmed", {"device": device})
    return jsonify({"success": True, "message": "Network settings confirmed - the automatic revert has been cancelled."})

@app.route('/api/system/maintenance/purge_logs', methods=['POST'])
@requires_auth
@requires_permission('settings')
def purge_system_logs():
    update_job(log="[System log buffer purged by examiner.]")
    return jsonify({"success": True, "message": "Console log buffer cleared."})

@app.route('/api/system/toggle_keyboard', methods=['POST'])
@requires_auth
@requires_permission('settings')
def toggle_onscreen_keyboard():
    # wvkbd-mobintl starts VISIBLE (see install.py's kiosk autostart
    # script) so it's usable immediately for the browser's native Basic
    # Auth login prompt, which appears before any of this app's own HTML/JS
    # loads - a button inside the dashboard can't help with that screen,
    # since you can't reach the dashboard until you're already past it.
    # Signalled rather than clicked/focus-detected: SIGUSR2 shows, SIGUSR1
    # hides, SIGRTMIN toggles (per `man wvkbd`). Runs as the same account
    # as this web service, so no sudo is needed to signal it.
    req = request.get_json(silent=True) or {}
    action = req.get('action', 'toggle')
    signal_map = {'show': '-SIGUSR2', 'hide': '-SIGUSR1', 'toggle': '-SIGRTMIN'}
    sig = signal_map.get(action)
    if not sig:
        return jsonify({"success": False, "error": f"Unknown action '{action}'. Use show, hide, or toggle."}), 400

    try:
        res = subprocess.run(['pkill', sig, '-f', 'wvkbd-mobintl'], capture_output=True, timeout=5)
        if res.returncode not in (0, 1):  # 1 = "no matching process" from pkill, not a real error here
            return jsonify({"success": False, "error": "Could not signal the on-screen keyboard process."}), 500
        return jsonify({"success": True, "message": f"On-screen keyboard: {action}."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- File Explorer Endpoints ---
@app.route('/api/files/browse', methods=['POST'])
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
                })
            except Exception:
                pass
        return jsonify({"path": path, "items": sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/copy', methods=['POST'])
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

@app.route('/api/files/delete', methods=['POST'])
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

@app.route('/api/files/raw', methods=['GET'])
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

@app.route('/api/files/preview_text', methods=['POST'])
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

@app.route('/api/files/hex', methods=['POST'])
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

# --- Report Modifier & Attachment Endpoints ---
@app.route('/api/report/load', methods=['POST'])
@requires_auth
def load_report_json():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report file not found or outside the permitted evidence directory."}), 404

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        return jsonify({"success": True, "report": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/report/save', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def save_report_json():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    data = req.get('report_data')

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report target file not found or outside the permitted evidence directory."}), 404

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
        log_chain_of_custody("report_edit", {"report_path": report_file})
        return jsonify({"success": True, "message": "Report JSON updated successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Post-Acquisition Hash Verifier ---
@app.route('/api/verify_hash', methods=['POST'])
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
@app.route('/api/files/exif', methods=['POST'])
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
@app.route('/api/files/stat_info', methods=['POST'])
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
@app.route('/api/files/binwalk', methods=['POST'])
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

# --- TestDisk: Read-Only Partition Analysis ---
@app.route('/api/recovery/testdisk_analyze', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def testdisk_analyze():
    req = request.get_json() or {}
    source_raw = req.get('source', '')

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            return jsonify({"success": False, "error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    try:
        # -l is TestDisk's dedicated read-only partition listing flag - a
        # genuinely separate, simpler command from the /cmd scripting
        # syntax (which supports write-capable actions like rebuildbs).
        # Using -l specifically, rather than /cmd with a hand-picked
        # read-only subset of keywords, means this can never accidentally
        # grow a write action later - the flag itself is incapable of one.
        res = subprocess.run(['sudo', '/usr/bin/testdisk', '-l', source], capture_output=True, text=True, timeout=60)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        log_chain_of_custody("testdisk_analyze", {"source": source})
        return jsonify({"success": True, "source": source, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "testdisk timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- ClamAV: Malware Scan ---
@app.route('/api/files/clamscan', methods=['POST'])
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
@app.route('/api/files/hashdeep', methods=['POST'])
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

        file_count = sum(1 for line in res.stdout.splitlines() if line and not line.startswith('%') and not line.startswith('#'))
        log_chain_of_custody("hashdeep_manifest", {"directory": target_dir, "algorithm": algo, "file_count": file_count})
        return jsonify({"success": True, "manifest_path": manifest_path, "file_count": file_count})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "hashdeep timed out (large directory - consider a subdirectory instead)."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Geolocation: Extract GPS EXIF Data as a KML File ---
# Scoped to camera-native still-image formats that reliably carry GPS EXIF tags -
# not every file in a case folder (raw acquisition images, logs, etc. would just be
# wasted exiftool calls). Video GPS extraction is a real gap but out of scope for v1.
GEO_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'tiff', 'tif', 'dng', 'heic', 'heif']


def _kml_escape(text):
    return html.escape(str(text), quote=True)


def _geo_points_from_exiftool_entries(entries):
    """Shared by both the real-directory and in-image geolocation routes -
    turns exiftool -j -n JSON output into a filtered list of GPS points."""
    points = []
    for entry in entries:
        lat, lon = entry.get('GPSLatitude'), entry.get('GPSLongitude')
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue  # most photos have no GPS tags at all - normal, not an error
        points.append({
            "name": entry.get('FileName', '(unknown)'),
            "directory": entry.get('Directory', ''),
            "lat": lat, "lon": lon,
            "alt": entry.get('GPSAltitude') if isinstance(entry.get('GPSAltitude'), (int, float)) else None,
            "timestamp": entry.get('DateTimeOriginal'),
        })
    return points


def _build_geo_kml(points, doc_title):
    """Builds a KML document from a list of {name, directory, lat, lon, alt,
    timestamp} points - built in Python rather than exiftool's own -kml/
    kml.fmt template mechanism, which is a separate example asset in
    exiftool's upstream distribution not guaranteed present in the Debian
    package. Returns None if there are no points - an empty KML with zero
    placemarks isn't a meaningful forensic artifact worth writing."""
    if not points:
        return None
    placemarks = []
    for p in points:
        alt_str = f"{p['alt']:.1f} m" if p['alt'] is not None else "Unknown"
        desc = f"File: {p['name']}\nPath: {p['directory']}\nCaptured: {p['timestamp'] or 'Unknown'}\nAltitude: {alt_str}"
        # KML <coordinates> order is lon,lat,alt - the reverse of how
        # latitude/longitude are normally said out loud, easy to get backwards.
        placemarks.append(
            "<Placemark>"
            f"<name>{_kml_escape(p['name'])}</name>"
            f"<description>{_kml_escape(desc)}</description>"
            f"<Point><coordinates>{p['lon']:.7f},{p['lat']:.7f},{p['alt'] or 0}</coordinates></Point>"
            "</Placemark>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        f'<name>{_kml_escape(doc_title)}</name>'
        + "".join(placemarks) +
        '</Document></kml>'
    )


@app.route('/api/files/geolocation_kml', methods=['POST'])
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

    log_chain_of_custody("geolocation_kml_export", {
        "directory": target_dir, "files_scanned": len(entries), "points_found": len(points)
    })
    return jsonify({"success": True, "kml_path": kml_path, "files_scanned": len(entries), "points_found": len(points)})

# --- strings: Extract Printable Text From a Binary File ---
@app.route('/api/files/strings', methods=['POST'])
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
# Reuses TRIAGE_PATTERNS/the same regex-per-chunk-with-overlap technique
# execution_worker_triage_scan() (File Recovery's background job) already
# uses - this is deliberately NOT a second scanning implementation, just a
# capped, synchronous entry point into the same category matching, for a
# quick right-click look at a .dd/.E01 image (or any other file) without
# configuring and running the full background job. Only scans the first
# QUICK_TRIAGE_MAX_BYTES of the file - large/exhaustive scans still belong
# to the File Recovery tab's Triage Scan tool.
QUICK_TRIAGE_MAX_BYTES = 32 * 1024 * 1024  # 32 MB - fast enough to stay synchronous within one request
QUICK_TRIAGE_MAX_MATCHES_PER_CATEGORY = 500  # smaller than the background job's 50000 - this is a quick preview, not an exhaustive collection
# TRIAGE_CATEGORY_LABELS now lives in core/case_index_db.py (imported at the
# top of this file) - see the Step 0 core/ extraction.

@app.route('/api/files/quick_triage_scan', methods=['POST'])
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

    CHUNK_SIZE = 8 * 1024 * 1024
    OVERLAP = 256  # bytes carried over between chunks so a match spanning a chunk boundary isn't missed
    results = {name: set() for name in TRIAGE_PATTERNS}
    truncated = {name: False for name in TRIAGE_PATTERNS}

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
                for name, pattern in TRIAGE_PATTERNS.items():
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
    for name in TRIAGE_PATTERNS:
        matches = sorted(results[name])
        label = TRIAGE_CATEGORY_LABELS.get(name, name)
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
@app.route('/api/files/mvt_scan', methods=['POST'])
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

@app.route('/api/tools/mvt_update_iocs', methods=['POST'])
@requires_auth
def mvt_update_iocs():
    results = {}
    ran_any = False
    for platform, mvt_bin in (('ios', MVT_IOS_BIN), ('android', MVT_ANDROID_BIN)):
        if not os.path.isfile(mvt_bin):
            results[platform] = "not installed"
            continue
        ran_any = True
        try:
            res = subprocess.run([mvt_bin, 'download-iocs'], capture_output=True, text=True, timeout=180)
            results[platform] = (res.stdout.strip() or res.stderr.strip() or "(no output)")
        except subprocess.TimeoutExpired:
            results[platform] = "timed out"
        except Exception as e:
            results[platform] = f"error: {e}"

    if not ran_any:
        return jsonify({"success": False, "error": "Neither mvt-ios nor mvt-android is installed."}), 400

    log_chain_of_custody("mvt_update_iocs", {})
    return jsonify({"success": True, "results": results})

# --- Chain of Custody Log ---
def _read_coc_entries(limit=None):
    """Read chain-of-custody log entries, most recent first. limit=None reads the whole file."""
    entries = []
    if os.path.exists(COC_LOG_FILE):
        with open(COC_LOG_FILE, 'r') as f:
            lines = f.readlines()
        if limit:
            lines = lines[-limit:]
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    entries.reverse()
    return entries

@app.route('/api/coc/log', methods=['GET'])
@requires_auth
def get_chain_of_custody_log():
    limit = request.args.get('limit', 200, type=int)
    try:
        return jsonify({"success": True, "entries": _read_coc_entries(limit)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Case-scoped view of the same log, for the Reporting tab's History sub-tab -
# distinct from /api/coc/log above, which is the station-wide Audit Log in
# Settings. No log entries are tagged with a case_number field (retrofitting
# that onto every one of the ~20 log_chain_of_custody() call sites would be
# a much larger change), so this filters by substring match against every
# logged detail value instead - covers both old flat-file evidence (case
# number was always the filename prefix) and new case-folder evidence (case
# number is the folder name) with one heuristic, no directory resolution
# needed.
def _case_history_entries(case_number, limit=200):
    """Same substring-match filter used by /api/coc/case_history below,
    factored out so the report exporter's Audit Trail section can reuse it
    without an extra HTTP round-trip."""
    matched = []
    for entry in _read_coc_entries(limit=None):
        details = entry.get("details", {})
        if any(case_number in str(v) for v in details.values()):
            matched.append(entry)
        if len(matched) >= limit:
            break
    return matched

@app.route('/api/coc/case_history', methods=['GET'])
@requires_auth
def get_case_history():
    case_number = request.args.get('case_number', '').strip()
    limit = request.args.get('limit', 200, type=int)
    if not case_number:
        return jsonify({"success": False, "error": "case_number is required."}), 400

    try:
        return jsonify({"success": True, "entries": _case_history_entries(case_number, limit)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/coc/export_csv', methods=['GET'])
@requires_auth
def export_chain_of_custody_csv():
    # Unlike /api/coc/log above (capped to the most recent `limit` entries
    # for the on-screen view), an export is expected to be the complete
    # record - no limit here.
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "action", "source_ip", "details"])

    try:
        if os.path.exists(COC_LOG_FILE):
            with open(COC_LOG_FILE, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # `details` is a free-form dict that varies by action
                    # type - flatten it to a single JSON string column
                    # rather than guessing at a fixed set of sub-columns.
                    writer.writerow([
                        entry.get("timestamp", ""),
                        entry.get("action", ""),
                        entry.get("source_ip", ""),
                        json.dumps(entry.get("details", {})),
                    ])
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    filename = f"chain_of_custody_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# --- Case / Report Index ---
# --- Case Management: create/discover case folders ---
# A "case" here is a folder (identified by a case_info.json marker file at
# its root) that examiners point every acquisition/recovery/mobile tool's
# Destination field at, so one case's evidence never lands as a sibling of
# another case's files. No server-side "active case" state is kept here -
# every job-starting route already takes `destination` per-request, so
# selecting a case is purely a frontend concern (send its folder as the
# destination); these routes only handle creating and discovering the case
# folders themselves.
@app.route('/api/cases/create', methods=['POST'])
@requires_auth
def create_case():
    req = request.get_json() or {}
    case_number_raw = req.get('case_number', '').strip()
    examiner = req.get('examiner', '').strip()
    notes = req.get('notes', '').strip()
    parent_dir = safe_path(req.get('parent_dir', EVIDENCE_ROOT).strip())

    if not parent_dir or not os.path.isdir(parent_dir):
        return jsonify({"success": False, "error": "Parent location is not a valid directory in the permitted evidence directory."}), 400

    slug = sanitize_case_slug(case_number_raw)
    if not slug:
        return jsonify({"success": False, "error": "Case number must contain at least one letter, number, underscore, or hyphen."}), 400

    # Belt-and-suspenders: slug is already whitelisted to [A-Za-z0-9_-] so
    # os.path.join(parent_dir, slug) can't escape parent_dir on its own, but
    # re-validating through safe_path matches the posture every other
    # path-accepting endpoint in this app uses.
    case_dir = safe_path(os.path.join(parent_dir, slug))
    if not case_dir:
        return jsonify({"success": False, "error": "Resulting case path is outside the permitted evidence directory."}), 400

    if os.path.exists(case_dir):
        return jsonify({"success": False, "error": f"A case folder named '{slug}' already exists at this location. Choose a different case number or parent location."}), 409

    try:
        os.makedirs(case_dir)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        # New cases go straight onto the consolidated one-file-per-case
        # format (see "Consolidated Per-Case Reporting" above) - only cases
        # created before this existed need the explicit migration path
        # (/api/cases/migrate_preview / _apply) to get folded in.
        case_record = {
            "schema_version": 1,
            "case_number": case_number_raw,
            "case_folder": case_dir,
            "examiner": examiner,
            "notes": notes,
            "created_at": now,
            "updated_at": now,
            "attachments": {"files": [], "reference_urls": []},
            # Pre-populated (empty values) from the station's currently
            # configured custom-field *definitions* (Settings > Case &
            # Reporting) so this dict is always fully shaped rather than
            # sparse - definitions live station-wide, values live per-case.
            "custom_fields": {f["key"]: "" for f in get_custom_case_fields()},
            "events": [],
        }
        _write_case_file(os.path.join(case_dir, f"{slug}_case.json"), case_record)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not create case folder: {e}"}), 500

    log_chain_of_custody("case_create", {"case_number": case_number_raw, "examiner": examiner, "case_folder": case_dir})
    return jsonify({"success": True, "case": case_record})

@app.route('/api/cases/list', methods=['GET'])
@requires_auth
def list_cases():
    cases = []
    try:
        for root, dirs, files in os.walk(EVIDENCE_ROOT):
            # Bound the scan depth so this can't turn into a very slow crawl
            # of a huge or deeply-mounted evidence tree.
            depth = root[len(EVIDENCE_ROOT):].count(os.sep)
            if depth >= 6:
                dirs[:] = []
                continue

            # A case folder's marker filename is always derived from its own
            # basename (see case_consolidated_path) - check for that exact
            # name first (new consolidated schema), falling back to the old
            # generic case_info.json for cases created before this existed
            # and not yet migrated (see /api/cases/migrate_preview/_apply).
            consolidated_name = f"{os.path.basename(root)}_case.json"
            if consolidated_name in files:
                try:
                    with open(os.path.join(root, consolidated_name), 'r') as f:
                        data = json.load(f)
                    cases.append({
                        "case_number": data.get('case_number', '--'),
                        "examiner": data.get('examiner', '--'),
                        "case_folder": data.get('case_folder', root),
                        "created_at": data.get('created_at', '--'),
                        "notes": data.get('notes', ''),
                        "event_count": len(data.get('events', [])),
                        "schema": "consolidated",
                    })
                except (json.JSONDecodeError, OSError):
                    pass
                dirs[:] = []  # a case folder never contains another case folder
            elif 'case_info.json' in files:
                try:
                    with open(os.path.join(root, 'case_info.json'), 'r') as f:
                        data = json.load(f)
                    cases.append({
                        "case_number": data.get('case_number', '--'),
                        "examiner": data.get('examiner', '--'),
                        "case_folder": data.get('case_folder', root),
                        "created_at": data.get('created_at', '--'),
                        "notes": data.get('notes', ''),
                        "event_count": None,
                        "schema": "legacy",
                    })
                except (json.JSONDecodeError, OSError):
                    pass
                dirs[:] = []

        cases.sort(key=lambda c: c.get('created_at', ''), reverse=True)
        return jsonify({"success": True, "cases": cases})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cases/log_select', methods=['POST'])
@requires_auth
def log_case_select():
    # No state is stored here - this exists purely so selecting a case
    # leaves a chain-of-custody entry, same as every other significant
    # action in this app.
    req = request.get_json() or {}
    log_chain_of_custody("case_select", {
        "case_number": req.get('case_number', ''),
        "case_folder": req.get('case_folder', ''),
    })
    return jsonify({"success": True})

# --- Legacy Case Migration: fold scattered case_info.json + *_report.json
# files into the new one-file-per-case consolidated schema ---
# Non-destructive by design: originals are renamed with a
# ".pre_consolidation_backup" suffix (never deleted), and only after the new
# consolidated file has been written and confirmed. One-shot per case - if
# it already has a *_case.json, both routes below refuse rather than risk
# merging/duplicating; picking up reports created after a migration is a
# known, documented limitation, not handled here.
def _scan_case_folder_for_migration(case_dir):
    """Read-only: returns (case_info_data_or_None, [(path, parsed_report_dict), ...], [unreadable_paths])."""
    case_info = None
    case_info_path = os.path.join(case_dir, "case_info.json")
    if os.path.isfile(case_info_path):
        try:
            with open(case_info_path, 'r') as f:
                case_info = json.load(f)
        except Exception:
            pass

    reports = []
    unreadable = []
    for root, dirs, files in os.walk(case_dir):
        for fname in files:
            if fname.endswith('_report.json'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r') as f:
                        reports.append((fpath, json.load(f)))
                except Exception:
                    unreadable.append(fpath)
    return case_info, reports, unreadable

@app.route('/api/cases/migrate_preview', methods=['POST'])
@requires_auth
def migrate_case_preview():
    req = request.get_json() or {}
    case_dir = safe_path(req.get('case_folder', ''))
    if not case_dir or not os.path.isdir(case_dir):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404

    slug = os.path.basename(case_dir.rstrip(os.sep))
    already_migrated = os.path.isfile(os.path.join(case_dir, f"{slug}_case.json"))

    case_info, reports, unreadable = _scan_case_folder_for_migration(case_dir)
    return jsonify({
        "success": True,
        "already_migrated": already_migrated,
        "case_info_found": case_info is not None,
        "reports": [{
            "path": p,
            "case_number": r.get("case_metadata", {}).get("case_number", "--"),
            "evidence_id": r.get("case_metadata", {}).get("evidence_id", "--"),
            "tool": r.get("tool", "--"),
            "status": r.get("acquisition_status", "--"),
            "timestamp_start": r.get("timestamp_start", "--"),
        } for p, r in reports],
        "unreadable": unreadable,
    })

@app.route('/api/cases/migrate_apply', methods=['POST'])
@requires_auth
def migrate_case_apply():
    req = request.get_json() or {}
    case_dir = safe_path(req.get('case_folder', ''))
    if not case_dir or not os.path.isdir(case_dir):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404

    slug = os.path.basename(case_dir.rstrip(os.sep))
    case_file = os.path.join(case_dir, f"{slug}_case.json")
    if os.path.isfile(case_file):
        return jsonify({"success": False, "error": "This case is already on the consolidated format."}), 409

    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Wait for the current job to finish before migrating - migration renames files a running job may still be writing to."}), 409

    case_info, reports, unreadable = _scan_case_folder_for_migration(case_dir)

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    events = []
    migrated_paths = []
    for path, data in reports:
        event = dict(data)
        event["event_id"] = uuid.uuid4().hex
        events.append(event)
        migrated_paths.append(path)
    events.sort(key=lambda e: e.get("timestamp_start", ""))

    case_record = {
        "schema_version": 1,
        "case_number": (case_info or {}).get("case_number", slug),
        "case_folder": case_dir,
        "examiner": (case_info or {}).get("examiner", ""),
        "notes": (case_info or {}).get("notes", ""),
        "created_at": (case_info or {}).get("created_at") or (events[0]["timestamp_start"] if events else now),
        "updated_at": now,
        "attachments": {"files": [], "reference_urls": []},
        "events": events,
    }

    try:
        _write_case_file(case_file, case_record)
        if not os.path.isfile(case_file):
            raise IOError("consolidated file did not appear on disk after write")
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed writing consolidated case file - nothing was renamed: {e}"}), 500

    # Only rename originals after the new file is confirmed written - if the
    # process dies partway through renaming, worst case is duplicate data on
    # disk (old files still present next to a complete new one), never loss.
    case_info_path = os.path.join(case_dir, "case_info.json")
    if case_info is not None and os.path.isfile(case_info_path):
        try:
            os.rename(case_info_path, case_info_path + ".pre_consolidation_backup")
        except Exception:
            pass
    for path in migrated_paths:
        try:
            os.rename(path, path + ".pre_consolidation_backup")
        except Exception:
            pass

    log_chain_of_custody("case_migrate", {"case_folder": case_dir, "events_migrated": len(events), "skipped": len(unreadable)})
    return jsonify({"success": True, "case_file": case_file, "events_migrated": len(events), "skipped": unreadable})

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

@app.route('/api/image/format_support', methods=['GET'])
@requires_auth
def image_format_support():
    return jsonify({"success": True, "support": detect_image_format_support()})

# _tsk_parse_inode/_tsk_open_fs/_tsk_entry_dict/_tsk_list_dir/_tsk_walk/
# _tsk_stream_file now live in core/tsk_utils.py (imported at the top of
# this file) - see the Step 0 core/ extraction.

@app.route('/api/image/mmls', methods=['POST'])
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

@app.route('/api/image/fls', methods=['POST'])
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

@app.route('/api/image/extract', methods=['POST'])
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

@app.route('/api/image/preview', methods=['POST'])
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

@app.route('/api/image/hex', methods=['POST'])
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

@app.route('/api/image/search', methods=['POST'])
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

@app.route('/api/image/timeline', methods=['POST'])
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

@app.route('/api/image/start_geolocation_kml', methods=['POST'])
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

@app.route('/api/image/hash_manifest', methods=['POST'])
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

def execution_worker_image_triage_scan(image_path, dest_dir, source_ip=None, user=None):
    global current_job
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    results = {name: [] for name in TRIAGE_PATTERNS}       # list of (path, value) tuples, in match order
    seen = {name: set() for name in TRIAGE_PATTERNS}       # dedupe by (path, value)
    truncated = {name: False for name in TRIAGE_PATTERNS}
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
                        for name, pattern in TRIAGE_PATTERNS.items():
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
                                    append_log(f"[!] {TRIAGE_CATEGORY_LABELS.get(name, name)}: hit the {IMAGE_TRIAGE_MAX_MATCHES_PER_CATEGORY}-match cap, no longer collecting new ones.")
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
        for name in TRIAGE_PATTERNS:
            label = TRIAGE_CATEGORY_LABELS.get(name, name)
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

@app.route('/api/image/start_triage_scan', methods=['POST'])
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
        args=(image_path, dest_dir, requester_ip, requester_user)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("image_triage_scan_start", {"image_path": image_path, "destination": dest_dir})
    return jsonify({"success": True, "message": "Filesystem-aware triage scan started."})

# _case_index_open_readonly/_case_index_open_write/_tags_for_paths/
# _analysis_results_for_paths/_record_analysis_result (and
# ANALYSIS_RESULT_MAX_PER_PATH/ANALYSIS_RESULT_MAX_OUTPUT_CHARS) now live in
# core/case_index_db.py (imported at the top of this file) - see the Step 0
# core/ extraction.

@app.route('/api/case_index/tags_for_paths', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def case_index_tags_for_paths():
    req = request.get_json() or {}
    paths = [safe_path(p) for p in (req.get('paths') or [])]
    paths = [p for p in paths if p]
    return jsonify({"success": True, "tags": _tags_for_paths(req.get('case_folder'), paths)})

@app.route('/api/case_index/analysis_for_paths', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def case_index_analysis_for_paths():
    req = request.get_json() or {}
    paths = [safe_path(p) for p in (req.get('paths') or [])]
    paths = [p for p in paths if p]
    return jsonify({"success": True, "results": _analysis_results_for_paths(req.get('case_folder'), paths)})

@app.route('/api/case_index/summary', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_summary():
    req = request.get_json() or {}
    conn = _case_index_open_readonly(req.get('case_folder'))
    by_extension = {cat: 0 for cat in FILE_VIEW_EXTENSION_CATEGORIES}
    keyword_hits = {name: 0 for name in TRIAGE_PATTERNS}
    deleted_files = 0
    total_files = 0
    tags = []
    if conn:
        try:
            for row in conn.execute("SELECT category, COUNT(*) FROM indexed_files WHERE deleted=0 GROUP BY category"):
                if row[0] in by_extension:
                    by_extension[row[0]] = row[1]
            deleted_files = conn.execute("SELECT COUNT(*) FROM indexed_files WHERE deleted=1").fetchone()[0]
            total_files = conn.execute("SELECT COUNT(*) FROM indexed_files WHERE deleted=0").fetchone()[0]
            for row in conn.execute("SELECT category, COUNT(*) FROM triage_hits GROUP BY category"):
                if row[0] in keyword_hits:
                    keyword_hits[row[0]] = row[1]
            for row in conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, t.is_default, "
                    "(SELECT COUNT(*) FROM tagged_items WHERE tag_id=t.id) "
                    "FROM tags t ORDER BY t.is_default DESC, t.name"):
                tags.append({"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3]),
                             "is_default": bool(row[4]), "count": row[5]})
        finally:
            conn.close()
    return jsonify({
        "success": True,
        "indexed": conn is not None,
        "total_files": total_files,
        "by_extension": by_extension,
        "deleted_files": deleted_files,
        "keyword_hits": {"total": sum(keyword_hits.values()), **keyword_hits},
        "tags": tags,
    })

@app.route('/api/case_index/files', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_files():
    req = request.get_json() or {}
    category = req.get('category', '')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn:
        try:
            if category == '__deleted__':
                cur = conn.execute(
                    "SELECT image_path, fs_offset, inode, path, name, size, deleted, mtime, atime, ctime, crtime FROM indexed_files WHERE deleted=1 ORDER BY path LIMIT 2000")
            elif category in FILE_VIEW_EXTENSION_CATEGORIES:
                cur = conn.execute(
                    "SELECT image_path, fs_offset, inode, path, name, size, deleted, mtime, atime, ctime, crtime FROM indexed_files WHERE category=? AND deleted=0 ORDER BY path LIMIT 2000",
                    (category,))
            else:
                cur = None
            if cur:
                for r in cur:
                    rows.append({"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "name": r[4], "size": r[5], "deleted": bool(r[6]),
                                 "mtime": r[7], "atime": r[8], "ctime": r[9], "crtime": r[10]})
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

@app.route('/api/case_index/hits', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_hits():
    req = request.get_json() or {}
    category = req.get('category', '')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn and category in TRIAGE_PATTERNS:
        try:
            # LEFT JOIN indexed_files for MACB timestamps/size/deleted-status -
            # triage_hits itself never duplicates that data (the same walk
            # that finds a hit always indexes the file too, see
            # execution_worker_image_triage_scan), so this is a read-time
            # enrichment, not a second copy that could drift out of sync.
            cur = conn.execute(
                "SELECT h.image_path, h.fs_offset, h.inode, h.path, h.value, h.source_type, "
                "f.size, f.deleted, f.mtime, f.atime, f.ctime, f.crtime "
                "FROM triage_hits h LEFT JOIN indexed_files f "
                "ON h.image_path = f.image_path AND h.fs_offset = f.fs_offset AND h.inode = f.inode "
                "WHERE h.category=? ORDER BY h.path LIMIT 2000",
                (category,))
            for r in cur:
                row = {"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "value": r[4], "source_type": r[5],
                       "size": r[6], "deleted": bool(r[7]) if r[7] is not None else False,
                       "mtime": r[8], "atime": r[9], "ctime": r[10], "crtime": r[11]}
                if row["image_path"] is None:
                    # A real_fs hit (Quick Triage Scan against a real file) has
                    # no matching indexed_files row - those scans are
                    # deliberately never indexed there (see quick_triage_scan).
                    # Best-effort a live os.stat() instead of leaving these
                    # rows perpetually blank; harmless if the file has since
                    # moved/been deleted.
                    try:
                        st = os.stat(row["path"])
                        row["mtime"], row["atime"], row["ctime"] = int(st.st_mtime), int(st.st_atime), int(st.st_ctime)
                    except OSError:
                        pass
                rows.append(row)
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

# --- Tagging: flag a real filesystem or in-image file as evidence of
# interest (Bookmark/Follow Up/Notable Item by default, custom tags
# supported), modeled on Autopsy's tagging feature. Lives in the same
# per-case SQLite index File Views already reads/writes - tagging is just
# one more analysis-index concern, not a separate subsystem. ---

def _resolve_tag_identity(req):
    """Validates and normalizes the item-identity fields tag_item/
    untag_item/item_tags all take: {source_type, image_path, fs_offset,
    inode, path, name}. Returns the normalized dict, or None if invalid.
    Every path-shaped field is safe_path()-sandboxed - even though most of
    these routes never read the file's content, this app's rule is that any
    endpoint accepting a path from the client goes through safe_path(), and
    the real_fs os.stat() fallback below does read filesystem metadata at
    that path, so the validation is load-bearing there specifically."""
    source_type = req.get('source_type')
    name = (req.get('name') or '').strip()
    if not name:
        return None
    if source_type == 'real_fs':
        path = safe_path(req.get('path')) if req.get('path') else None
        if not path:
            return None
        return {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": path, "name": name}
    elif source_type == 'image':
        image_path = safe_path(req.get('image_path')) if req.get('image_path') else None
        inode = str(req.get('inode') or '').strip()
        if not image_path or not inode:
            return None
        try:
            fs_offset = int(req.get('fs_offset') or 0)
        except (TypeError, ValueError):
            fs_offset = 0
        # Best-effort only - not every in-image call site (full image-mode
        # browsing, inline-nested tree browsing) has a full path string on
        # hand the way a File Views result row does; None here just means
        # this tagged item displays by name alone rather than a full path.
        path = req.get('path') or None
        return {"source_type": "image", "image_path": image_path, "fs_offset": fs_offset, "inode": inode,
                "path": path, "name": name}
    return None

@app.route('/api/case_index/tag_item', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_tag_item():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    if not identity:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_write(req.get('case_folder'))
    if not conn:
        return jsonify({"success": False, "error": "No active, consolidated case selected."}), 400

    comment = (req.get('comment') or '').strip() or None
    try:
        tag_id = req.get('tag_id')
        if tag_id:
            row = conn.execute("SELECT id, name, color, notable FROM tags WHERE id=?", (tag_id,)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Tag not found."}), 404
        else:
            new_name = (req.get('new_tag_name') or '').strip()[:60]
            if not new_name:
                return jsonify({"success": False, "error": "Provide either tag_id or new_tag_name."}), 400
            color = req.get('new_tag_color') if req.get('new_tag_color') in ALLOWED_TAG_COLORS else 'secondary'
            notable = 1 if req.get('new_tag_notable') else 0
            # Soft-dedupe by name (INSERT OR IGNORE against the UNIQUE
            # constraint), matching this app's existing precedent for
            # custom report templates/case fields - "creating" a tag whose
            # name already exists just resolves to the existing one rather
            # than erroring or silently making a second copy.
            conn.execute(
                "INSERT OR IGNORE INTO tags (name, color, notable, is_default, created_at) VALUES (?,?,?,0,?)",
                (new_name, color, notable, time.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            row = conn.execute("SELECT id, name, color, notable FROM tags WHERE name=?", (new_name,)).fetchone()
        tag_id, tag_name, tag_color, tag_notable = row[0], row[1], row[2], bool(row[3])

        if identity["source_type"] == "real_fs":
            existing = conn.execute(
                "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
                (tag_id, identity["path"])).fetchone()
        else:
            existing = conn.execute(
                "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='image' AND image_path=? AND fs_offset=? AND inode=?",
                (tag_id, identity["image_path"], identity["fs_offset"], identity["inode"])).fetchone()

        already_tagged = existing is not None
        if already_tagged:
            if comment is not None:
                conn.execute("UPDATE tagged_items SET comment=? WHERE id=?", (comment, existing[0]))
        else:
            conn.execute(
                "INSERT INTO tagged_items (tag_id, source_type, image_path, fs_offset, inode, path, name, comment, tagged_by, tagged_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (tag_id, identity["source_type"], identity["image_path"], identity["fs_offset"], identity["inode"],
                 identity["path"], identity["name"], comment, getattr(g, 'forensic_user', None),
                 time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        log_chain_of_custody("item_tagged", {
            "tag": tag_name, "name": identity["name"],
            "path": identity["path"] or identity.get("image_path"),
        })
    finally:
        conn.close()

    return jsonify({"success": True, "already_tagged": already_tagged,
                     "tag": {"id": tag_id, "name": tag_name, "color": tag_color, "notable": tag_notable}})

@app.route('/api/case_index/untag_item', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_untag_item():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    tag_id = req.get('tag_id')
    if not identity or not tag_id:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn:
        return jsonify({"success": True, "removed": False})
    removed = False
    try:
        if identity["source_type"] == "real_fs":
            cur = conn.execute(
                "DELETE FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
                (tag_id, identity["path"]))
        else:
            cur = conn.execute(
                "DELETE FROM tagged_items WHERE tag_id=? AND source_type='image' AND image_path=? AND fs_offset=? AND inode=?",
                (tag_id, identity["image_path"], identity["fs_offset"], identity["inode"]))
        removed = cur.rowcount > 0
        conn.commit()
        if removed:
            log_chain_of_custody("item_untagged", {"tag_id": tag_id, "name": identity["name"],
                                                     "path": identity["path"] or identity.get("image_path")})
    finally:
        conn.close()
    return jsonify({"success": True, "removed": removed})

@app.route('/api/case_index/item_tags', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_item_tags():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    if not identity:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_readonly(req.get('case_folder'))
    tags = []
    if conn:
        try:
            if identity["source_type"] == "real_fs":
                cur = conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, ti.comment FROM tagged_items ti "
                    "JOIN tags t ON ti.tag_id=t.id WHERE ti.source_type='real_fs' AND ti.path=?",
                    (identity["path"],))
            else:
                cur = conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, ti.comment FROM tagged_items ti "
                    "JOIN tags t ON ti.tag_id=t.id WHERE ti.source_type='image' AND ti.image_path=? AND ti.fs_offset=? AND ti.inode=?",
                    (identity["image_path"], identity["fs_offset"], identity["inode"]))
            for row in cur:
                tags.append({"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3]), "comment": row[4]})
        finally:
            conn.close()
    return jsonify({"success": True, "tags": tags})

@app.route('/api/case_index/tagged_files', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_tagged_files():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn and tag_id:
        try:
            cur = conn.execute(
                "SELECT ti.image_path, ti.fs_offset, ti.inode, ti.path, ti.name, ti.comment, ti.source_type, "
                "f.size, f.deleted, f.mtime, f.atime, f.ctime, f.crtime "
                "FROM tagged_items ti LEFT JOIN indexed_files f "
                "ON ti.image_path = f.image_path AND ti.fs_offset = f.fs_offset AND ti.inode = f.inode "
                "WHERE ti.tag_id=? ORDER BY ti.tagged_at DESC LIMIT 2000",
                (tag_id,))
            for r in cur:
                row = {"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "name": r[4],
                       "comment": r[5], "source_type": r[6],
                       "size": r[7], "deleted": bool(r[8]) if r[8] is not None else False,
                       "mtime": r[9], "atime": r[10], "ctime": r[11], "crtime": r[12]}
                if row["image_path"] is None and row["path"]:
                    try:
                        st = os.stat(row["path"])
                        row["mtime"], row["atime"], row["ctime"] = int(st.st_mtime), int(st.st_atime), int(st.st_ctime)
                    except OSError:
                        pass
                rows.append(row)
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

# --- Tag management: create/rename/recolor/delete tags themselves (distinct
# from tag_item/untag_item above, which apply/remove a tag on one specific
# file). Reached from Settings > Case & Reporting > Manage Tags, scoped to
# whichever case is active there - tags are per-case data, not a station-wide
# default like the rest of that Settings section. ---

@app.route('/api/case_index/tags/create', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_create_tag():
    req = request.get_json() or {}
    conn = _case_index_open_write(req.get('case_folder'))
    if not conn:
        return jsonify({"success": False, "error": "No active, consolidated case selected."}), 400
    try:
        name = (req.get('name') or '').strip()[:60]
        if not name:
            return jsonify({"success": False, "error": "Tag name can't be empty."}), 400
        color = req.get('color') if req.get('color') in ALLOWED_TAG_COLORS else 'secondary'
        notable = 1 if req.get('notable') else 0
        try:
            conn.execute(
                "INSERT INTO tags (name, color, notable, is_default, created_at) VALUES (?,?,?,0,?)",
                (name, color, notable, time.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "error": f'A tag named "{name}" already exists.'}), 409
        row = conn.execute("SELECT id, name, color, notable FROM tags WHERE name=?", (name,)).fetchone()
        log_chain_of_custody("tag_created", {"tag_id": row[0], "name": name})
    finally:
        conn.close()
    return jsonify({"success": True, "tag": {"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3])}})

@app.route('/api/case_index/tags/update', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_update_tag():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn or not tag_id:
        return jsonify({"success": False, "error": "No case index found, or missing tag_id."}), 400
    try:
        row = conn.execute("SELECT id, name FROM tags WHERE id=?", (tag_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Tag not found."}), 404
        new_name = (req.get('name') or '').strip()[:60]
        if not new_name:
            return jsonify({"success": False, "error": "Tag name can't be empty."}), 400
        color = req.get('color') if req.get('color') in ALLOWED_TAG_COLORS else 'secondary'
        notable = 1 if req.get('notable') else 0
        try:
            conn.execute("UPDATE tags SET name=?, color=?, notable=? WHERE id=?", (new_name, color, notable, tag_id))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "error": f'A tag named "{new_name}" already exists.'}), 409
        log_chain_of_custody("tag_updated", {"tag_id": tag_id, "old_name": row[1], "new_name": new_name})
    finally:
        conn.close()
    return jsonify({"success": True})

@app.route('/api/case_index/tags/delete', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_delete_tag():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn or not tag_id:
        return jsonify({"success": False, "error": "No case index found, or missing tag_id."}), 400
    try:
        row = conn.execute("SELECT id, name, is_default FROM tags WHERE id=?", (tag_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Tag not found."}), 404
        if row[2]:
            return jsonify({"success": False, "error": "Default tags can't be deleted - you can still rename or recolor them."}), 400
        # No FK enforcement in this DB (matches the rest of this schema) -
        # cascade the delete manually so a removed tag doesn't leave orphaned
        # tagged_items rows with a dangling tag_id behind.
        conn.execute("DELETE FROM tagged_items WHERE tag_id=?", (tag_id,))
        conn.execute("DELETE FROM tags WHERE id=?", (tag_id,))
        conn.commit()
        log_chain_of_custody("tag_deleted", {"tag_id": tag_id, "name": row[1]})
    finally:
        conn.close()
    return jsonify({"success": True})

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

@app.route('/api/image/binwalk', methods=['POST'])
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

@app.route('/api/image/strings', methods=['POST'])
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

@app.route('/api/image/exif', methods=['POST'])
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

@app.route('/api/image/recover_deleted', methods=['POST'])
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

# --- Filesystem Timeline report block: reuses the pytsk3 walk above against
# a case's already-acquired disk image(s), rather than the interactive,
# single-image-at-a-time /api/image/timeline route. First real entry in the
# "feature module" pattern discussed for this app - see REPORT_SECTION_BLOCKS
# and FEATURE_MODULES further below.
TIMELINE_MIN_PER_FS_BUDGET = 200

# _tsk_resolve_filesystems now lives in core/tsk_utils.py (imported at the
# top of this file) - see the Step 0 core/ extraction.

def _collect_case_timeline(events):
    """Builds a combined MACB timeline across every acquired disk image in a
    case's events, for the 'timeline' report block below. Returns
    {"events": [...], "notes": [...], "truncated": bool}.

    Three correctness fixes folded in here that a naive version of this
    would not have had:

    1. Status + existence gating: only a COMPLETED event's output_image_path
       is considered, and only after routing it through safe_path() (matching
       this file's existing pattern for every other image-path input) and
       confirming the file still exists - a FAILED/IN_PROGRESS event's path
       can point at a partial image that might still open "successfully" and
       walk garbage without pytsk3 raising anything.
    2. Dedup by resolved path, not by event: ddrescue's base_name has no
       per-run component, and its own multi-pass design (stage1_fast/
       stage2_trim/stage3_intensive/reverse, each a separate POST against the
       same source/destination) means multiple distinct COMPLETED events can
       legitimately share one on-disk file, each overwriting the last. Only
       the event with the latest timestamp_start per unique resolved path is
       kept; how many earlier events were superseded is recorded so the
       report can disclose it rather than silently drop or (worse) triple-
       walk the same bytes.
    3. Per-(image, filesystem) budget, not one shared global cap:
       image_timeline() above truncates in walk order, before sorting by
       time - so a single real filesystem can consume the entire
       TSK_MAX_TIMELINE_ENTRIES cap by itself. Splitting the budget across
       every qualifying (image, filesystem) pair means one large acquired
       image can't silently reduce every other evidence item in the case to
       zero timeline entries."""
    candidates = {}  # resolved image_path -> {"event": event, "superseded_count": int}
    for event in events:
        if event.get('acquisition_status') != 'COMPLETED':
            continue
        raw_path = event.get('acquisition_parameters', {}).get('output_image_path')
        if not raw_path:
            continue
        image_path = safe_path(raw_path)
        if not image_path or not os.path.isfile(image_path):
            continue
        existing = candidates.get(image_path)
        if existing is None:
            candidates[image_path] = {"event": event, "superseded_count": 0}
        elif event.get('timestamp_start', '') > existing["event"].get('timestamp_start', ''):
            existing["event"] = event
            existing["superseded_count"] += 1
        else:
            existing["superseded_count"] += 1

    notes = []
    per_image_filesystems = {}
    for image_path in candidates:
        filesystems = _tsk_resolve_filesystems(image_path)
        per_image_filesystems[image_path] = filesystems
        evidence_id = candidates[image_path]["event"].get('case_metadata', {}).get('evidence_id', 'N/A')
        if not filesystems:
            notes.append(f"{evidence_id}: no recognized filesystem found in the acquired image - skipped.")
        superseded = candidates[image_path]["superseded_count"]
        if superseded:
            plural = "es" if superseded != 1 else ""
            verb = "share" if superseded != 1 else "shares"
            notes.append(f"{evidence_id}: {superseded} earlier completed acquisition pass{plural} {verb} this "
                         f"same output file; showing the most recent only.")

    total_filesystems = sum(len(fss) for fss in per_image_filesystems.values())
    if total_filesystems == 0:
        return {"events": [], "notes": notes, "truncated": False}
    per_fs_budget = max(TSK_MAX_TIMELINE_ENTRIES // total_filesystems, TIMELINE_MIN_PER_FS_BUDGET)

    all_events = []
    truncated = False
    for image_path, filesystems in per_image_filesystems.items():
        evidence_id = candidates[image_path]["event"].get('case_metadata', {}).get('evidence_id', 'N/A')
        for fs_info in filesystems:
            try:
                fs = _tsk_open_fs(image_path, fs_info['offset'])
            except Exception as e:
                notes.append(f"{evidence_id} ({fs_info['label']}): could not open filesystem - {e}")
                continue
            count = 0
            for entry, path in _tsk_walk(fs):
                if entry['is_virtual']:
                    continue  # TSK's own $MBR/$FAT1/$FAT2/$OrphanFiles pseudo-entries, not real evidence
                for ts_field, label in (('mtime', 'M'), ('atime', 'A'), ('ctime', 'C'), ('crtime', 'B')):
                    ts = entry.get(ts_field)
                    if ts:
                        all_events.append({"timestamp": ts, "activity": label, "path": path,
                                            "evidence_id": evidence_id, "filesystem": fs_info['label']})
                        count += 1
                if count >= per_fs_budget:
                    truncated = True
                    break

    all_events.sort(key=lambda e: e['timestamp'], reverse=True)
    if len(all_events) > TSK_MAX_TIMELINE_ENTRIES:
        truncated = True
    return {"events": all_events[:TSK_MAX_TIMELINE_ENTRIES], "notes": notes, "truncated": truncated}

# --- Forensic Audit Report Exporter (PDF / HTML, configurable sections) ---
def _draw_pdf_job_section(c, y, event, job_fields=None):
    """Draws one job/event's telemetry + acquisition params + hashes block,
    each independently toggleable via job_fields - shared between the
    single-legacy-report path and the per-event loop for a consolidated case
    file below. Returns the y position after drawing."""
    job_fields = job_fields if job_fields is not None else {'telemetry': True, 'params': True, 'hashes': True}

    if job_fields.get('telemetry', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Source Media Telemetry")
        y -= 15
        c.setFont("Helvetica", 10)
        drive = event.get('source_drive_telemetry', {})
        c.drawString(50, y, f"Device: {drive.get('device_path')} ({drive.get('capacity_gb')} GB)")
        c.drawString(300, y, f"Model: {drive.get('vendor_model')}")
        y -= 15
        c.drawString(50, y, f"Serial: {drive.get('serial_number')}")
        c.drawString(300, y, f"SMART Status: {'PASSED' if drive.get('smart_healthy') else 'FAILING'}")
        y -= 30

    if job_fields.get('params', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Acquisition Parameters")
        y -= 15
        c.setFont("Helvetica", 10)
        params = event.get('acquisition_parameters', {})
        c.drawString(50, y, f"Format: {params.get('output_format', event.get('tool', 'N/A')).upper()}")
        c.drawString(300, y, f"Status: {event.get('acquisition_status')}")
        y -= 15
        if params.get('bitlocker_key'):
            c.drawString(50, y, f"BitLocker Recovery Key/Password: {params['bitlocker_key']}")
            y -= 15
        y -= 10

    if job_fields.get('hashes', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Verification Hashes")
        y -= 15
        c.setFont("Helvetica", 10)
        hashes = event.get('computed_verification_hashes', {})
        if hashes:
            for k, v in hashes.items():
                c.drawString(50, y, f"{k.upper()}: {v}")
                y -= 15
        else:
            c.drawString(50, y, "No hashes recorded.")
            y -= 15
        y -= 5
    return y

def _draw_pdf_acquisition_method(c, y, events, job_fields, title="Acquisition Method"):
    """Renders the per-event acquisition loop - factored out of what used to
    be inlined directly in _build_pdf_report_standard so the registry-driven
    draw loop (see REPORT_SECTION_BLOCKS/_resolve_section_order) can treat
    it as one dispatchable block like every other section. `title` is used
    only for the block's bookmark/Report Contents label - there is no
    on-page heading for the block as a whole, each event draws its own
    "Evidence Item: ..." heading, matching this block's existing behavior.
    Every event after the first always starts on a fresh page (unchanged
    from before); the *first* event does NOT force its own page break here -
    the caller (the registry-driven loop) is responsible for that via this
    block's force_page_break=True registry entry, since _draw_pdf_job_section
    has no internal pagination guard of its own and would otherwise risk
    drawing past the bottom margin if this block isn't first in a custom
    template's order."""
    for i, event in enumerate(events):
        if i > 0:
            c.showPage()
            y = 750
        meta = event.get('case_metadata', {})
        c.setFont("Helvetica-Bold", 13)
        c.drawString(50, y, f"Evidence Item: {meta.get('evidence_id', 'N/A')} ({event.get('tool', 'N/A')})")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Date: {event.get('timestamp_start', 'N/A')}")
        y -= 25
        y = _draw_pdf_job_section(c, y, event, job_fields)
    return y

def _draw_pdf_header(c, header, title="Case Information"):
    c.setFont("Helvetica-Bold", 12)
    y = 730
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Case Number: {header['case_number']}")
    c.drawString(300, y, f"Examiner: {header['examiner']}")
    y -= 20
    c.drawString(50, y, f"Created: {header['created_at']}")
    y -= 20
    c.drawString(50, y, f"Notes: {header['notes'] or 'None'}")
    y -= 20
    for field in header.get('custom_fields', []):
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = 750
        c.drawString(50, y, f"{field['label']}: {field['value']}"[:110])
        y -= 15
    y -= 15
    return y

def _draw_pdf_audit_trail(c, y, entries, title="Case Activity Log (Audit Trail)"):
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 8)
    if not entries:
        c.drawString(50, y, "No activity log entries found for this case.")
        y -= 12
    for entry in entries:
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 8)
        c.drawString(50, y, f"{entry.get('timestamp', '')}  {entry.get('action', '')}"[:120])
        y -= 11
        details = entry.get('details') or {}
        if details:
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(60, y, ', '.join(f'{k}={v}' for k, v in details.items())[:130])
            c.setFillColorRGB(0, 0, 0)
            y -= 11
    return y

# --- Case File Attachments: discovery + embedding ---
# Images and small text-ish files get their actual content embedded into
# the exported report (not just listed by path), since the point of
# attaching a photo or a note to a case is that it shows up IN the report
# an examiner hands off - a bare file path is not useful to someone who
# doesn't have filesystem access to the Pi.
ATTACHMENT_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
ATTACHMENT_TEXT_EXT = {'.txt', '.log', '.md', '.csv', '.json', '.eml', '.msg', '.rtf', '.xml', '.yaml', '.yml'}
ATTACHMENT_EXCLUDE_EXT = {'.dd', '.e01', '.aff', '.001', '.raw', '.img'}
ATTACHMENT_MAX_TEXT_EMBED_BYTES = 100_000
ATTACHMENT_MAX_IMAGE_EMBED_BYTES = 8_000_000
ATTACHMENT_DISCOVERY_MAX_FILES = 200
ATTACHMENT_DISCOVERY_SKIP_DIRS = {'RECOVERED_FILES'}  # extundelete's fixed output dir name

def _discover_case_files(case_folder):
    """Find files physically present in a case folder that are candidates
    for attaching to a report (photos, notes, extracted emails, etc.) but
    weren't necessarily added via the explicit 'Add File Attachment' flow -
    e.g. dropped in via File Explorer's Copy-to action. Skips this case's
    own report artifacts, raw acquisition images (too large, already
    represented via the Jobs section), and recovery tools' bulk carved-file
    output directories (could be thousands of tiny files, impractical to
    list individually). Returns (files, truncated)."""
    slug = os.path.basename(case_folder.rstrip(os.sep))
    own_artifact_names = {f"{slug}_case.json", f"{slug}_case.pdf", f"{slug}_case.html", "case_info.json"}

    results = []
    truncated = False
    for root, dirs, files in os.walk(case_folder):
        dirs[:] = [d for d in dirs if d not in ATTACHMENT_DISCOVERY_SKIP_DIRS
                   and not d.endswith(('_photorec', '_foremost', '_scalpel', '_triagescan'))]
        for fname in files:
            if fname in own_artifact_names or fname.endswith(('.pre_consolidation_backup', '_report.json')):
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in ATTACHMENT_EXCLUDE_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            kind = 'image' if ext in ATTACHMENT_IMAGE_EXT else ('text' if ext in ATTACHMENT_TEXT_EXT else 'other')
            results.append({"path": fpath, "name": fname, "size_bytes": size, "kind": kind})
            if len(results) >= ATTACHMENT_DISCOVERY_MAX_FILES:
                return results, True
    return results, truncated


def _kml_find_local(elem, tag_name):
    """First descendant of elem whose tag's local name (namespace prefix
    stripped) matches tag_name, in document order - the closest ElementTree
    equivalent of a namespace-agnostic querySelector() lookup, since KML's
    default namespace makes exact-tag matching fragile."""
    for child in elem.iter():
        if child is elem:
            continue
        if child.tag.rsplit('}', 1)[-1] == tag_name:
            return child
    return None


def _parse_kml_placemarks(kml_text):
    """Mirrors parseKmlPlacemarks() (main.js) - stdlib ElementTree,
    namespace-agnostic tag matching, Placemark -> Point -> coordinates
    (lon,lat[,alt]) + name + description. Skips any Placemark without valid
    parseable coordinates. Returns [] (never raises) on malformed/
    unparseable XML, matching the JS side's own try/except-and-return-
    whatever-was-collected behavior - this may be a hand-edited or
    third-party KML file, not necessarily one this app generated itself."""
    placemarks = []
    try:
        root = ET.fromstring(kml_text)
    except ET.ParseError:
        return placemarks

    for elem in root.iter():
        if elem.tag.rsplit('}', 1)[-1] != 'Placemark':
            continue
        point = _kml_find_local(elem, 'Point')
        coords_el = _kml_find_local(point, 'coordinates') if point is not None else None
        if coords_el is None or not (coords_el.text or '').strip():
            continue
        parts = coords_el.text.strip().split(',')
        if len(parts) < 2:
            continue
        try:
            lon, lat = float(parts[0]), float(parts[1])
        except ValueError:
            continue
        name_el = _kml_find_local(elem, 'name')
        desc_el = _kml_find_local(elem, 'description')
        placemarks.append({
            "name": (name_el.text or '').strip() if name_el is not None else '',
            "description": (desc_el.text or '').strip() if desc_el is not None else '',
            "lat": lat, "lon": lon,
        })
    return placemarks


def _collect_case_kml_files(case_folder, attachment_files):
    """Mirrors renderReportGeolocationList()'s (main.js) union logic: every
    .kml path already in the case's explicit attachments.files list, plus
    every .kml file _discover_case_files() finds sitting in the case folder
    that wasn't necessarily added through the explicit attach flow. Returns
    a de-duplicated, sorted list of absolute paths."""
    paths = set()
    for p in (attachment_files or []):
        if str(p).lower().endswith('.kml'):
            paths.add(p)
    if case_folder and os.path.isdir(case_folder):
        discovered, _truncated = _discover_case_files(case_folder)
        for f in discovered:
            if f['path'].lower().endswith('.kml'):
                paths.add(f['path'])
    return sorted(paths)


def _collect_case_geolocation(case_folder, attachment_files):
    """Reads every case KML file (_collect_case_kml_files) and parses its
    placemarks (_parse_kml_placemarks), returning one entry per file that
    has at least one valid placemark. A KML with zero parseable points
    contributes nothing to a 'map with pins' export section, so it's
    silently skipped here - the same reasoning _build_geo_kml() already
    applies to its own KML *generation* (refuses to write an empty KML with
    zero placemarks in the first place)."""
    results = []
    for path in _collect_case_kml_files(case_folder, attachment_files):
        real_path = safe_path(path)
        if not real_path or not os.path.isfile(real_path):
            continue
        try:
            with open(real_path, 'r', encoding='utf-8', errors='replace') as f:
                kml_text = f.read()
        except OSError:
            continue
        placemarks = _parse_kml_placemarks(kml_text)
        if not placemarks:
            continue
        results.append({"name": os.path.basename(real_path), "path": real_path, "placemarks": placemarks})
    return results


@app.route('/api/cases/discover_files', methods=['GET'])
@requires_auth
@requires_permission('reporting')
def discover_case_files():
    case_folder = safe_path(request.args.get('case_folder', ''))
    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404
    files, truncated = _discover_case_files(case_folder)
    return jsonify({"success": True, "files": files, "truncated": truncated})

@app.route('/api/cases/attach_file', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def attach_file_to_case():
    """Lets File Explorer's "Attach to Case" context-menu action bookmark a
    file the moment an examiner is looking at it, rather than requiring a
    separate trip to Reporting > Files to browse back to the same path -
    the same "tag it where you find it" model AXIOM/Autopsy use, adapted to
    this app's file-path-based attachment model. Writes straight to the
    case JSON on disk (unlike Reporting's own attachment editing, which is
    staged client-side and only persisted on "Save Report Changes") since
    File Explorer has no loaded-report state or Save button to stage
    through - matches how every other File Explorer action (hash, extract,
    scan) already commits immediately rather than queuing a pending edit."""
    req = request.get_json() or {}
    case_folder = safe_path(req.get('case_folder'))
    file_path = safe_path(req.get('file_path'))
    # Optional provenance note - populated automatically by call sites that
    # know something worth recording (e.g. "extracted from inside an
    # acquired image"), which is otherwise lost the moment the file lands on
    # disk as just another path. Only ever applied on first attach and only
    # if no caption already exists for this path - never overwrites an
    # examiner's own edit made since.
    caption = (req.get('caption') or '').strip() or None

    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 400
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    case_file = case_consolidated_path(case_folder)
    if not case_file:
        return jsonify({"success": False, "error": "This case hasn't been migrated to the consolidated report format yet - attach files from the Reporting tab instead."}), 400

    data = _read_case_file(case_file)
    attachments = data.setdefault('attachments', {})
    files = attachments.setdefault('files', [])
    already_attached = file_path in files
    if not already_attached:
        files.append(file_path)
        if caption:
            captions = attachments.setdefault('file_captions', {})
            if file_path not in captions:
                captions[file_path] = caption
        data['updated_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
        _write_case_file(case_file, data)
        log_chain_of_custody("file_attached_to_case", {"case_folder": case_folder, "file_path": file_path})

    return jsonify({"success": True, "already_attached": already_attached, "file_count": len(files)})

# --- Case Notes: timestamped, append-only journal entries ---
# Inspired by forensicnotes.com's contemporaneous-notes model, adapted to
# what this appliance can honestly provide: there's no real cryptographic
# timestamp authority here, so instead each note gets a local SHA-256
# integrity hash (detects local tampering, not a legal notarization
# service) and edits are append-only - a note's original text/timestamp/
# author is never overwritten, only superseded with the prior version kept
# in edit_history. This is what the "Forensic Analysis / Steps Taken"
# report section renders (see _draw_pdf_case_notes below).
def _hash_note_content(text, attachment_paths):
    h = hashlib.sha256()
    h.update((text or '').encode('utf-8'))
    for path in attachment_paths:
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
        except OSError:
            pass
    return h.hexdigest()

@app.route('/api/cases/notes/add', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def add_case_note():
    report_file = safe_path(request.form.get('report_path', ''))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report/case file not found or outside the permitted evidence directory."}), 404

    text = request.form.get('text', '').strip()
    category = request.form.get('category', 'General').strip() or 'General'
    if not text:
        return jsonify({"success": False, "error": "Note text cannot be empty."}), 400

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read report: {e}"}), 500

    # Optional links to already-attached exhibit files, so a note can say
    # "found in DCIM, see Exhibit 3" with a real reference instead of just
    # prose. Add-time only - not editable via /api/cases/notes/edit, since
    # editing is for correcting text, not changing which files a note
    # references. Sent as a JSON-encoded string in a form field (this route
    # is multipart, unlike the JSON-bodied edit route). Any path not
    # currently a real attached exhibit is silently dropped - a note
    # shouldn't fail to save over a stale reference.
    try:
        requested_links = json.loads(request.form.get('linked_files', '[]'))
    except (TypeError, ValueError):
        requested_links = []
    attached_files = set((data.get('attachments') or {}).get('files', []))
    linked_files = [p for p in requested_links if isinstance(p, str) and p in attached_files]

    note_id = uuid.uuid4().hex
    saved_attachments = []
    uploaded_files = request.files.getlist('files')
    if uploaded_files and any(f.filename for f in uploaded_files):
        note_dir = safe_path(os.path.join(os.path.dirname(report_file), "case_notes_attachments", note_id))
        if not note_dir:
            return jsonify({"success": False, "error": "Could not resolve a safe attachment directory for this note."}), 500
        os.makedirs(note_dir, exist_ok=True)
        for uf in uploaded_files:
            if not uf.filename:
                continue
            fname = os.path.basename(uf.filename)
            if not fname:
                continue
            fpath = os.path.join(note_dir, fname)
            uf.save(fpath)
            ext = os.path.splitext(fname)[1].lower()
            kind = 'image' if ext in ATTACHMENT_IMAGE_EXT else ('text' if ext in ATTACHMENT_TEXT_EXT else 'other')
            saved_attachments.append({
                "filename": fname,
                "path": fpath,
                "size_bytes": os.path.getsize(fpath),
                "kind": kind,
            })

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    note = {
        "note_id": note_id,
        "timestamp": now,
        "author": getattr(g, 'forensic_user', None),
        "category": category,
        "text": text,
        "attachments": saved_attachments,
        "linked_files": linked_files,
        "content_hash": _hash_note_content(text, [a["path"] for a in saved_attachments]),
        "edited_at": None,
        "edit_history": [],
    }

    data.setdefault('case_notes', []).append(note)
    if 'updated_at' in data:
        data['updated_at'] = now

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not save note: {e}"}), 500

    log_chain_of_custody("case_note_add", {"report_path": report_file, "note_id": note_id, "category": category})
    return jsonify({"success": True, "note": note})

@app.route('/api/cases/notes/edit', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def edit_case_note():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    note_id = req.get('note_id', '')
    new_text = (req.get('text') or '').strip()

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report/case file not found or outside the permitted evidence directory."}), 404
    if not new_text:
        return jsonify({"success": False, "error": "Note text cannot be empty."}), 400

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read report: {e}"}), 500

    notes = data.get('case_notes', [])
    note = next((n for n in notes if n.get('note_id') == note_id), None)
    if not note:
        return jsonify({"success": False, "error": "Note not found on this case/report."}), 404

    # Append-only: the prior text/hash/edited_at is preserved in
    # edit_history rather than overwritten - note_id/timestamp/author never
    # change, so a note's contemporaneous origin stays provable after edits.
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    note.setdefault('edit_history', []).append({
        "text": note["text"],
        "content_hash": note["content_hash"],
        "edited_at": note.get("edited_at"),
    })
    note["text"] = new_text
    note["content_hash"] = _hash_note_content(new_text, [a["path"] for a in note.get("attachments", [])])
    note["edited_at"] = now

    if 'updated_at' in data:
        data['updated_at'] = now

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not save note edit: {e}"}), 500

    log_chain_of_custody("case_note_edit", {"report_path": report_file, "note_id": note_id})
    return jsonify({"success": True, "note": note})

def _embed_file_into_pdf(c, y, file_path, caption=None, exhibit_number=None, category=None, tags=None, analysis_summary=None):
    """Draws one file's content (image/text embedded, or a path+size
    fallback) at the current y and returns the new y. Shared by Exhibits
    (case attachments) and the Case Notes journal so the per-extension
    embedding dispatch isn't duplicated a third time. caption is
    examiner-entered free text, rendered as a small italic line under the
    filename heading when present.

    exhibit_number/category/tags/analysis_summary are Exhibits-only
    enrichment - the Case Notes journal's own call to this function never
    passes them (its attachments aren't exhibits), so they default to None
    and add nothing there. exhibit_number is the file's 1-based position in
    attachments.files; category is a plain string from classify_extension();
    tags is a list of {name, notable, comment} dicts; analysis_summary is a
    pre-formatted string of recent tool-run results. All render via
    _draw_pdf_wrapped_text (self-paginating), never a raw drawString, since
    an exhibit with several tags/analysis runs can genuinely run past one
    page's remaining room."""
    name = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        size = 0

    label_prefix = f"Exhibit {exhibit_number}: " if exhibit_number else ""
    category_suffix = f" [{category}]" if category else ""

    def _draw_meta(y):
        c.setFont("Helvetica-Oblique", 8)
        if caption:
            y = _draw_pdf_wrapped_text(c, y, caption, x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        if tags:
            tag_line = "Tags: " + "; ".join(
                (f"* {t['name']}" if t.get('notable') else t['name']) + (f' - "{t["comment"]}"' if t.get('comment') else "")
                for t in tags)
            y = _draw_pdf_wrapped_text(c, y, tag_line, x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        if analysis_summary:
            y = _draw_pdf_wrapped_text(c, y, f"Analysis: {analysis_summary}", x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        c.setFont("Helvetica", 10)
        return y

    if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
        if y < 280:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{label_prefix}Image: {name}{category_suffix}"[:110])
        y -= 14
        y = _draw_meta(y)
        y -= 131
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(file_path), 60, y, width=220, height=140, preserveAspectRatio=True, anchor='sw')
        except Exception as img_err:
            c.setFont("Helvetica", 9)
            c.drawString(60, y + 130, f"(could not render image: {img_err})"[:100])
        y -= 15
        c.setFont("Helvetica", 10)
    elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
        if y < 160:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{label_prefix}Text File: {name}{category_suffix}"[:110])
        y -= 14
        y = _draw_meta(y)
        c.setFont("Courier", 7.5)
        try:
            with open(file_path, 'r', errors='replace') as tf:
                text_content = tf.read(ATTACHMENT_MAX_TEXT_EMBED_BYTES)
        except OSError as e:
            text_content = f"(could not read file: {e})"
        for line in text_content.splitlines()[:400]:
            if y < 50:
                c.showPage()
                y = 750
                c.setFont("Courier", 7.5)
            c.drawString(55, y, line[:130])
            y -= 9
        y -= 10
        c.setFont("Helvetica", 10)
    else:
        if y < 110:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 10)
        size_note = f" ({size:,} bytes)" if size else ""
        c.drawString(60, y, f"* {label_prefix}Document: {name}{category_suffix}{size_note} - {file_path}"[:140])
        y -= 15
        y = _draw_meta(y)
    return y

def _draw_pdf_wrapped_text(c, y, text, x=50, width_chars=95, font="Helvetica", size=9, leading=12):
    """Word-wraps and paginates a block of examiner-entered narrative text -
    shared by the narrative sections and the Case Notes journal, since both
    can run to multiple paragraphs (unlike the header's single-line fields,
    which stay truncated)."""
    c.setFont(font, size)
    for para in (text or '').splitlines() or ['']:
        for line in (textwrap.wrap(para, width_chars) or ['']):
            if y < 60:
                c.showPage()
                y = 750
                c.setFont(font, size)
            c.drawString(x, y, line)
            y -= leading
    return y

def _draw_pdf_narrative_section(c, y, title, text):
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18
    if not (text or '').strip():
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "(Not provided)")
        c.setFillColorRGB(0, 0, 0)
        y -= 14
        return y
    y = _draw_pdf_wrapped_text(c, y, text)
    y -= 8
    return y

_HASH_DISPLAY_PRIORITY = ('sha256', 'sha1', 'md5')

def _pick_display_hash(hashes):
    """Evidence Inventory's summary table shows one hash per item - picking
    silently via next(iter(hashes.values())) (the old behavior) shows a bare,
    unlabeled value with no way to tell which algorithm it is, which defeats
    the point of a verification hash. Always label the algorithm, and prefer
    the strongest one actually computed rather than whichever happened to be
    first in the dict. The full labeled set is always available in each
    item's own Verification Hashes section further down - this is only the
    at-a-glance summary column."""
    if not hashes:
        return "N/A"
    for algo in _HASH_DISPLAY_PRIORITY:
        if hashes.get(algo):
            return f"{algo.upper()}: {hashes[algo]}"
    algo, value = next(iter(hashes.items()))
    return f"{algo.upper()}: {value}"

def _draw_pdf_evidence_inventory(c, y, events, title="Evidence Inventory"):
    if not events:
        return y
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    headers = ["Evidence ID", "Device", "Model", "Serial", "Capacity", "Acquisition Hash"]
    xpos = [50, 130, 225, 320, 400, 460]
    c.setFont("Helvetica-Bold", 8)
    for label, x in zip(headers, xpos):
        c.drawString(x, y, label)
    y -= 4
    c.line(50, y, 550, y)
    y -= 12
    c.setFont("Helvetica", 7.5)
    for event in events:
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 7.5)
        meta = event.get('case_metadata', {})
        drive = event.get('source_drive_telemetry', {})
        hash_display = _pick_display_hash(event.get('computed_verification_hashes', {}))
        row = [
            str(meta.get('evidence_id', 'N/A'))[:14],
            str(drive.get('device_path', 'N/A'))[:16],
            str(drive.get('vendor_model', 'N/A'))[:15],
            str(drive.get('serial_number', 'N/A'))[:13],
            f"{drive.get('capacity_gb', 'N/A')} GB",
            str(hash_display)[:26],
        ]
        for val, x in zip(row, xpos):
            c.drawString(x, y, val)
        y -= 11
    y -= 12
    return y

def _draw_pdf_case_notes(c, y, notes, title="Forensic Analysis / Steps Taken (Case Notes)", exhibit_numbers=None):
    exhibit_numbers = exhibit_numbers or {}
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 16
    c.setFont("Helvetica-Oblique", 7)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(50, y, "Chronological case notes, each with a local SHA-256 integrity hash (tamper-evidence only, not a legal timestamp authority).")
    c.setFillColorRGB(0, 0, 0)
    y -= 16
    if not notes:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No case notes recorded.")
        y -= 15
        return y
    for note in notes:
        if y < 100:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"[{note.get('category', 'General')}] {note.get('timestamp', '')} — {note.get('author') or 'unknown'}"[:110])
        y -= 13
        if note.get('edited_at'):
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(50, y, f"(edited {note['edited_at']})")
            c.setFillColorRGB(0, 0, 0)
            y -= 11
        y = _draw_pdf_wrapped_text(c, y, note.get('text') or '', x=60, width_chars=90)
        y -= 4
        linked = [p for p in (note.get('linked_files') or []) if p in exhibit_numbers]
        if linked:
            link_line = "Linked Exhibit(s): " + "; ".join(
                f"Exhibit {exhibit_numbers[p]} - {os.path.basename(p)}" for p in linked)
            y = _draw_pdf_wrapped_text(c, y, link_line, x=60, width_chars=90, font="Helvetica-Oblique", size=8, leading=10)
            y -= 2
        for att in note.get('attachments', []):
            file_path = safe_path(att.get('path', ''))
            if file_path and os.path.exists(file_path):
                y = _embed_file_into_pdf(c, y, file_path)
        y -= 10
    return y

def _format_analysis_summary(results):
    """Turns the list of {tool, summary, run_by, run_at} dicts from
    _analysis_results_for_paths() into one compact string, e.g. "Binwalk: 3
    signature(s) found (2026-08-18 13:10); Strings: 142 line(s) extracted
    (2026-08-18 12:05)". Returns None for an empty/missing list so callers
    can skip the "Analysis:" line entirely rather than rendering an empty
    one."""
    if not results:
        return None
    return "; ".join(f"{r['tool']}: {r['summary']} ({r['run_at']})" for r in results)

def _draw_pdf_attachments(c, y, urls, files, title="Exhibits", captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    captions = captions or {}
    tags_by_path = tags_by_path or {}
    analysis_by_path = analysis_by_path or {}
    # Looked up, not enumerated from `files` - `files` here can be a
    # per-export FILTERED subset of the case's real attachments.files list
    # (attachment_selection), and a number must stay stable against the
    # FULL list regardless of which subset any one export includes, since
    # Case Notes' "Linked Exhibit(s)" references and the Reporting gallery
    # both key off the same full-list numbering. export_report() computes
    # this dict once from the unfiltered list.
    exhibit_numbers = exhibit_numbers or {}
    if not (urls or files):
        return y

    if y < 150:
        c.showPage()
        y = 730

    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 10)

    if urls:
        c.drawString(50, y, "Reference Links / URLs:")
        y -= 15
        for url in urls:
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 10)
            c.setFillColorRGB(0, 0, 0.8)
            c.drawString(60, y, f"• {url}"[:110])
            c.setFillColorRGB(0, 0, 0)
            y -= 15
        y -= 5

    # Exhibit numbers are each file's 1-based position in the case's FULL,
    # order-preserved attachments.files list (not this possibly-filtered
    # `files` subset) - a deliberately simple scheme, not a
    # permanently-retired Bates number: removing an exhibit and re-exporting
    # shifts later numbers down.
    if files:
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "Exhibit numbers reflect this case's current attachment order.")
        c.setFillColorRGB(0, 0, 0)
        y -= 12
        c.setFont("Helvetica", 10)

    for raw_path in files:
        file_path = safe_path(raw_path)
        if not file_path or not os.path.exists(file_path):
            continue
        category, _ext = classify_extension(os.path.basename(file_path))
        y = _embed_file_into_pdf(
            c, y, file_path, caption=captions.get(raw_path),
            exhibit_number=exhibit_numbers.get(raw_path), category=category,
            tags=tags_by_path.get(raw_path), analysis_summary=_format_analysis_summary(analysis_by_path.get(raw_path)))
    return y

# Shared by the DFIR and Police report templates below - not used by the
# Standard template, which keeps its existing journal-style Case Notes
# rendering (_draw_pdf_case_notes above) instead of a table.
_METHODOLOGY_STATIC_TEXT = (
    "This examination followed a standard write-blocked digital forensic acquisition and analysis "
    "workflow: source media was write-protected before connection, imaged using a forensically "
    "sound bit-for-bit acquisition tool with on-the-fly or post-acquisition cryptographic hashing, "
    "and the resulting image verified against its recorded hash before analysis began."
)
_SIGNOFF_STATIC_TEXT = (
    "I hereby affirm that the forensic examination detailed in this report was conducted in "
    "accordance with established procedures and forensic standards. The findings presented above "
    "are a true and accurate reflection of the data recovered from the submitted evidence."
)

def _draw_pdf_timeline_table(c, y, case_notes, title="Incident Timeline"):
    """Renders case_notes as a Timestamp/Category/Description table instead
    of the Standard template's narrative-journal style (_draw_pdf_case_notes)
    - the DFIR and Police reference templates both ask for a chronological
    timeline table, and the case notes journal is this app's only source of
    examiner-authored chronological entries, so it's reused here in a
    different shape rather than collecting a second, separate timeline."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 16
    c.setFont("Helvetica-Oblique", 7)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(50, y, "Chronological entries from the examiner's case notes journal.")
    c.setFillColorRGB(0, 0, 0)
    y -= 14
    if not case_notes:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No timeline entries recorded.")
        y -= 15
        return y

    headers = ["Timestamp", "Category", "Description"]
    xpos = [50, 160, 230]
    c.setFont("Helvetica-Bold", 8)
    for label, x in zip(headers, xpos):
        c.drawString(x, y, label)
    y -= 4
    c.line(50, y, 550, y)
    y -= 12
    c.setFont("Helvetica", 7.5)
    for note in sorted(case_notes, key=lambda n: n.get('timestamp', '')):
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 7.5)
        row = [
            str(note.get('timestamp', 'N/A'))[:19],
            str(note.get('category', 'General'))[:14],
            str(note.get('text', '')).replace('\n', ' ')[:62],
        ]
        for val, x in zip(row, xpos):
            c.drawString(x, y, val)
        y -= 11
    y -= 12
    return y

def _draw_pdf_timeline_block(c, y, events, title="Filesystem Timeline (MACB)"):
    """Renders a real filesystem MACB timeline for the case's acquired
    disk image(s) - see _collect_case_timeline() for how the underlying
    events are gathered (dedup/status-gating/per-image budget). Unlike
    _draw_pdf_timeline_table() above (a much shorter, case-notes-sourced
    table reused by the DFIR/Police templates), this table can legitimately
    run to thousands of rows across many pages, so - deliberately, not by
    silently copying that function's behavior - the column headers are
    redrawn after every page break rather than only once at the top."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18

    result = _collect_case_timeline(events)
    timeline_events = result["events"]

    headers = ["Timestamp", "Act.", "Evidence ID", "Path"]
    xpos = [50, 155, 195, 270]

    def _draw_header_row(y):
        c.setFont("Helvetica-Bold", 8)
        for label, x in zip(headers, xpos):
            c.drawString(x, y, label)
        y -= 4
        c.line(50, y, 550, y)
        y -= 12
        c.setFont("Helvetica", 7.5)
        return y

    if not timeline_events:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No filesystem timeline available for this case's evidence items.")
        y -= 15
    else:
        y = _draw_header_row(y)
        for entry in timeline_events:
            if y < 60:
                c.showPage()
                y = 750
                y = _draw_header_row(y)
            row = [
                str(entry.get('timestamp', 'N/A'))[:19],
                str(entry.get('activity', '')),
                str(entry.get('evidence_id', 'N/A'))[:14],
                str(entry.get('path', ''))[:58],
            ]
            for val, x in zip(row, xpos):
                c.drawString(x, y, val)
            y -= 11
        y -= 6
        if result["truncated"]:
            c.setFont("Helvetica-Oblique", 7)
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(50, y, "Timeline truncated - not every timestamped filesystem event fit within the report's size limits.")
            c.setFillColorRGB(0, 0, 0)
            y -= 12

    if result["notes"]:
        if y < 100:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 8)
        c.drawString(50, y, "Notes:")
        y -= 12
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColorRGB(0.4, 0.4, 0.4)
        for note in result["notes"]:
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica-Oblique", 7)
                c.setFillColorRGB(0.4, 0.4, 0.4)
            y = _draw_pdf_wrapped_text(c, y, note, x=55, width_chars=100, font="Helvetica-Oblique", size=7, leading=10)
        c.setFillColorRGB(0, 0, 0)

    y -= 12
    return y

def _draw_pdf_methodology_tools(c, y, events):
    """Static description of this app's standard acquisition workflow, plus
    a 'tools used in this case' list derived from the distinct event.tool
    values already recorded per job - zero new data entry, zero live
    subprocess/version-check calls added to report export."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Forensic Methodology & Tools")
    y -= 18
    c.setFont("Helvetica", 9.5)
    y = _draw_pdf_wrapped_text(c, y, _METHODOLOGY_STATIC_TEXT, width_chars=95)
    y -= 10

    tools = sorted({str(e.get('tool')).upper() for e in events if e.get('tool')})
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Tools Used in This Case:")
    y -= 14
    c.setFont("Helvetica", 10)
    c.drawString(60, y, ", ".join(tools) if tools else "No acquisition/recovery tool recorded.")
    y -= 20
    return y

def _draw_pdf_signoff(c, y, examiner):
    """Static sign-off block - examiner name (already-collected data) plus
    blank signature/date lines. No new data entry."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Sign-off & Signatures")
    y -= 18
    c.setFont("Helvetica", 9.5)
    y = _draw_pdf_wrapped_text(c, y, _SIGNOFF_STATIC_TEXT, width_chars=95)
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Examiner: {examiner}")
    y -= 35
    c.line(50, y, 250, y)
    c.drawString(50, y - 12, "Signature")
    c.line(320, y, 520, y)
    c.drawString(320, y - 12, "Date")
    y -= 25
    return y

# --- Geolocation report section: static tile-mosaic map image + placemark table ---
# Tile math ported (not imported) from install.py's _latlon_to_tile_xy/_tile_range_for_bbox -
# this file and install.py deliberately never import from each other (separate deployment
# contexts, e.g. TOOL_INSTALLABLE_PACKAGES is already duplicated the same way), so this is a
# second, independent copy of the same standard slippy-map-tilenames formula, not a shared import.
GEO_MAP_PX_WIDTH = 480
GEO_MAP_PX_HEIGHT = 300
GEO_MAP_ZOOM_MIN = 1
GEO_MAP_ZOOM_MAX = 16
GEO_TILE_FETCH_TIMEOUT = 6
GEO_TILE_MAX_COUNT = 40
GEO_TILE_USER_AGENT = "PiForensicsSuite/1.0 (report export map; +https://github.com/n0sfs/pi-forensics)"

def _latlon_to_global_pixel(lat, lon, zoom):
    """WGS84 lat/lon -> continuous (not tile-floored) global pixel coordinates
    at a zoom level, standard OSM 256px-tile Web Mercator projection - used
    both to size/position the tile grid and to project each placemark onto
    it at the exact same scale."""
    lat = max(min(lat, 85.05112878), -85.05112878)
    lat_rad = math.radians(lat)
    n = 2 ** zoom
    x = (lon + 180.0) / 360.0 * n * 256.0
    y = (1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n * 256.0
    return x, y

def _choose_geo_map_zoom(placemarks):
    """Picks the highest zoom level (most detail) at which this placemark
    set's bounding box still fits within the target map image size (minus a
    small margin) - starts at the max and steps down, matching how a normal
    map viewer auto-fits a bounds. Falls back to the minimum zoom for a
    genuinely widescattered set (e.g. evidence from two continents)."""
    lats = [p['lat'] for p in placemarks]
    lons = [p['lon'] for p in placemarks]
    min_lat, max_lat = min(lats), max(lats)
    min_lon, max_lon = min(lons), max(lons)
    for zoom in range(GEO_MAP_ZOOM_MAX, GEO_MAP_ZOOM_MIN - 1, -1):
        x1, y1 = _latlon_to_global_pixel(max_lat, min_lon, zoom)
        x2, y2 = _latlon_to_global_pixel(min_lat, max_lon, zoom)
        if abs(x2 - x1) <= GEO_MAP_PX_WIDTH - 40 and abs(y2 - y1) <= GEO_MAP_PX_HEIGHT - 40:
            return zoom
    return GEO_MAP_ZOOM_MIN

def _fetch_osm_tile(z, x, y):
    """Fetches one 256x256 OSM tile's raw PNG bytes - live first (with a
    real, honest User-Agent per OSM's tile usage policy), falling back to
    install.py's optional local offline-tile cache per tile if present -
    mirrors the live app's own online-first/offline-fallback tile behavior
    (_createGeoTileLayer() in main.js), just server-side and per-request
    instead of a persistent map widget. Returns None (never raises) if both
    sources come up empty or the server signals a policy block (the same
    X-Blocked detection install.py's own bulk tile-cache downloader already
    uses) - the map image simply leaves that tile blank, matching the
    interactive viewer's own graceful per-tile degradation."""
    try:
        req = urllib.request.Request(
            f"https://tile.openstreetmap.org/{z}/{x}/{y}.png",
            headers={"User-Agent": GEO_TILE_USER_AGENT})
        with urllib.request.urlopen(req, timeout=GEO_TILE_FETCH_TIMEOUT) as resp:
            if not resp.headers.get("X-Blocked"):
                return resp.read()
    except Exception:
        pass
    local_path = os.path.join(app.static_folder, 'vendor', 'osm_tiles', str(z), str(x), f"{y}.png")
    if os.path.exists(local_path):
        try:
            with open(local_path, 'rb') as f:
                return f.read()
        except OSError:
            pass
    return None

def _draw_pdf_geo_map_image(c, x0, y0, placemarks):
    """Draws a static tile-mosaic map (live-fetched or offline-cache-
    fallback tiles, see _fetch_osm_tile) with small pin markers at (x0, y0)
    (bottom-left corner, PDF points) sized GEO_MAP_PX_WIDTH x
    GEO_MAP_PX_HEIGHT - a reference-quality on-page map, not a print-
    resolution figure. Each 256x256 tile is drawn individually via
    reportlab's own drawImage (which decodes the PNG via Pillow internally,
    already a working dependency in this app via existing photo-exhibit
    embedding) at its correct projected position - reportlab composites the
    mosaic on the page itself, no separate image-compositing library
    needed. Returns True if at least one tile was actually drawn, so the
    caller can fall back to a disclosed 'map imagery unavailable' note
    instead of leaving a silently blank box when every tile fetch/fallback
    came up empty (no internet, no offline cache)."""
    from reportlab.lib.utils import ImageReader

    zoom = _choose_geo_map_zoom(placemarks)
    lats = [p['lat'] for p in placemarks]
    lons = [p['lon'] for p in placemarks]
    center_px, center_py = _latlon_to_global_pixel((min(lats) + max(lats)) / 2.0, (min(lons) + max(lons)) / 2.0, zoom)
    window_left = center_px - GEO_MAP_PX_WIDTH / 2.0
    window_top = center_py - GEO_MAP_PX_HEIGHT / 2.0
    n = 2 ** zoom

    c.saveState()
    clip = c.beginPath()
    clip.rect(x0, y0, GEO_MAP_PX_WIDTH, GEO_MAP_PX_HEIGHT)
    c.clipPath(clip, stroke=0, fill=0)

    any_drawn = False
    tile_count = 0
    tile_x_min = int(window_left // 256)
    tile_x_max = int((window_left + GEO_MAP_PX_WIDTH) // 256)
    tile_y_min = int(window_top // 256)
    tile_y_max = int((window_top + GEO_MAP_PX_HEIGHT) // 256)
    for tx in range(tile_x_min, tile_x_max + 1):
        for ty in range(tile_y_min, tile_y_max + 1):
            tile_count += 1
            if tile_count > GEO_TILE_MAX_COUNT or tx < 0 or ty < 0 or tx >= n or ty >= n:
                continue
            tile_bytes = _fetch_osm_tile(zoom, tx, ty)
            if not tile_bytes:
                continue
            try:
                img = ImageReader(io.BytesIO(tile_bytes))
                draw_x = x0 + (tx * 256 - window_left)
                draw_y = y0 + (GEO_MAP_PX_HEIGHT - (ty * 256 - window_top) - 256)
                c.drawImage(img, draw_x, draw_y, width=256, height=256, mask='auto')
                any_drawn = True
            except Exception:
                continue

    if any_drawn:
        for placemark in placemarks:
            px, py = _latlon_to_global_pixel(placemark['lat'], placemark['lon'], zoom)
            mx = x0 + (px - window_left)
            my = y0 + (GEO_MAP_PX_HEIGHT - (py - window_top))
            c.setFillColorRGB(0.85, 0.15, 0.1)
            c.setStrokeColorRGB(1, 1, 1)
            c.circle(mx, my, 4, stroke=1, fill=1)

    c.restoreState()
    c.setStrokeColorRGB(0.6, 0.6, 0.6)
    c.rect(x0, y0, GEO_MAP_PX_WIDTH, GEO_MAP_PX_HEIGHT, stroke=1, fill=0)
    return any_drawn

def _draw_pdf_geolocation_block(c, y, kml_data, title="Geolocation / GPS Evidence"):
    """Renders each case KML file with >=1 valid placemark (see
    _collect_case_geolocation) as a static tile-mosaic map image with pin
    markers, followed by a Name/Latitude/Longitude/Description placemark
    table - the PDF counterpart to the live app's interactive Leaflet
    viewer. A file whose tile fetch comes up completely empty still gets
    its table, just with a disclosed note in place of the map image - the
    underlying coordinate data is never hidden behind a map that failed to
    render."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18

    if not kml_data:
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "No geolocation (KML) evidence with GPS placemarks found for this case.")
        c.setFillColorRGB(0, 0, 0)
        y -= 14
        return y

    for entry in kml_data:
        min_needed = GEO_MAP_PX_HEIGHT + 30 + 40
        if y < min_needed:
            c.showPage()
            y = 750

        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, entry['name'][:90])
        y -= 13
        c.setFont("Helvetica-Oblique", 7.5)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, entry['path'][:115])
        c.setFillColorRGB(0, 0, 0)
        y -= 14

        map_y0 = y - GEO_MAP_PX_HEIGHT
        drawn = _draw_pdf_geo_map_image(c, 50, map_y0, entry['placemarks'])
        if not drawn:
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColorRGB(0.5, 0.5, 0.5)
            c.drawCentredString(50 + GEO_MAP_PX_WIDTH / 2.0, map_y0 + GEO_MAP_PX_HEIGHT / 2.0,
                                 "Map imagery unavailable for this evidence item - showing coordinates only.")
            c.setFillColorRGB(0, 0, 0)
        y = map_y0 - 12

        headers = ["Name", "Latitude", "Longitude", "Description"]
        xpos = [50, 200, 270, 340]

        def _draw_geo_header_row(y):
            c.setFont("Helvetica-Bold", 8)
            for label, x in zip(headers, xpos):
                c.drawString(x, y, label)
            y -= 4
            c.line(50, y, 550, y)
            y -= 12
            c.setFont("Helvetica", 7.5)
            return y

        y = _draw_geo_header_row(y)
        for p in entry['placemarks']:
            if y < 60:
                c.showPage()
                y = 750
                y = _draw_geo_header_row(y)
            c.drawString(xpos[0], y, (p['name'] or '(unnamed)')[:26])
            c.drawString(xpos[1], y, f"{p['lat']:.6f}")
            c.drawString(xpos[2], y, f"{p['lon']:.6f}")
            c.drawString(xpos[3], y, (p['description'] or '').replace('\n', ' ')[:38])
            y -= 10
        y -= 14

    return y

def _draw_pdf_contents_page(c, resolved_sections, event_count):
    """A plain Report Contents listing, not page-number cross-referenced -
    this renderer draws in a single streaming pass with no forward
    knowledge of final page numbers, so a real "Executive Summary ... 4"
    style TOC would need a second pass. This still gives the upfront
    section outline the DFIR report structure this feature was built
    against calls for; real point-and-click navigation is handled
    separately via the PDF outline/bookmarks added at each section below,
    which don't need page numbers at all.

    `resolved_sections` is the already-filtered, already-ordered list from
    _resolve_section_order() - this function only decides how to *display*
    each entry (the one special case: acquisition_method gets an evidence-
    item-count suffix here, matching its pre-existing behavior, while its
    bookmark/on-page label elsewhere stays plain)."""
    y = 700
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Report Contents")
    y -= 25
    c.setFont("Helvetica", 10.5)

    for i, entry in enumerate(resolved_sections, start=1):
        display = entry["title"]
        if entry["key"] == "acquisition_method" and event_count > 0:
            plural = "s" if event_count != 1 else ""
            display = f"{display} ({event_count} evidence item{plural})"
        c.drawString(60, y, f"{i}.  {display}")
        y -= 18

def _numbered_canvas_class():
    """Returns a reportlab Canvas subclass that stamps a 'Page N' footer on
    every page as it's flushed, without needing to touch every individual
    showPage() call site scattered across the drawing helpers above -
    showPage() is the one choke point they all already go through. save()
    doesn't need its own override: reportlab's own Canvas.save() calls
    showPage() internally for whatever page is still pending when save()
    runs, so the last page gets stamped through this same override
    automatically. Shared by all three report-template PDF builders below;
    reportlab is imported here rather than at module level, matching this
    file's existing lazy-import convention for it (routes that never touch
    PDF generation shouldn't need the dependency)."""
    from reportlab.pdfgen import canvas

    class _NumberedCanvas(canvas.Canvas):
        def showPage(self):
            self.setFont("Helvetica", 8)
            self.setFillColorRGB(0.45, 0.45, 0.45)
            self.drawRightString(550, 30, f"Page {self.getPageNumber()}")
            self.setFillColorRGB(0, 0, 0)
            canvas.Canvas.showPage(self)

    return _NumberedCanvas

def _draw_pdf_fixed_contents_page(c, entries):
    """Simpler counterpart to _draw_pdf_contents_page for the DFIR/Police
    templates below, which have a fixed section list (no per-section
    sections dict to check) - entries is just the final ordered list of
    section titles to print, already resolved by the caller (e.g.
    conditionally including "Exhibits" only when there are attachments)."""
    y = 700
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Report Contents")
    y -= 25
    c.setFont("Helvetica", 10.5)
    for i, entry in enumerate(entries, start=1):
        c.drawString(60, y, f"{i}.  {entry}")
        y -= 18

# Registry of selectable report shapes (Settings > Case & Reporting sets a
# station default; the Export pane can override it per-export). Only used
# for display labels/descriptions and to validate incoming 'template'
# values - 'dfir'/'police' each still have their own dedicated, fixed-
# structure builder-function pair (clearer and lower-risk than forcing an
# intentionally rigid, reference-document-matched shape through a generic
# loop). 'standard' and any user-defined 'custom:<id>' template (see
# REPORT_SECTION_BLOCKS/_resolve_section_order below) share ONE
# registry-driven builder pair instead - a custom template is really just a
# saved, reordered/renamed/filtered configuration of the same building
# blocks Standard's own section checkboxes already expose.
REPORT_TEMPLATES = {
    'standard': {
        'label': 'Standard',
        'description': 'The default configurable report - toggle sections and job fields freely.',
    },
    'dfir': {
        'label': 'DFIR Report',
        'description': 'Fixed-structure incident response report: Executive Summary, Incident Timeline, Indicators of Compromise, Containment & Next Steps.',
    },
    'police': {
        'label': 'Forensics Report',
        'description': 'Fixed-structure law-enforcement examination report: Administrative Information, Evidence Collection & Chain of Custody, Sign-off & Signatures.',
    },
    'caseuco': {
        'label': 'CASE/UCO Report',
        'description': 'Fixed-structure investigation report aligned with the CASE/UCO cyber-forensic ontology (Investigation, Observable Objects, Investigative Actions, Provenance Records) - the only built-in template that also includes Geolocation/GPS evidence.',
    },
}

# The building blocks available to the Standard template and to
# user-defined custom templates (Report Template Builder, Settings > Case &
# Reporting) - a custom template is a saved, ordered subset of these with
# optional per-block title overrides. Every field below is REQUIRED (no
# .get(key, True)-style implicit default anywhere this registry is read) so
# a future 15th block that forgets a field fails loudly at import time
# instead of silently drifting what every station's default report shows.
#
#   default_title     - shown on the page (where the block has an on-page
#                        heading) and used as the Report Contents/TOC label
#                        and PDF bookmark title unless a custom template
#                        overrides it.
#   in_legacy_default  - included when a report uses the plain sections:{key:
#                        bool} dict (today's Export-modal checkboxes/Settings
#                        station defaults, i.e. no custom template selected).
#                        False for iocs/recommendations - Standard never
#                        showed these before (only DFIR did), so they stay
#                        opt-in-only via a custom template rather than
#                        silently appearing in every station's existing
#                        default export.
#   requires_events    - skipped entirely (not merely rendered empty) when
#                        the case has zero acquisition/recovery events,
#                        regardless of whether it's enabled - there is
#                        nothing to show either way.
#   force_page_break   - the registry-driven draw loop unconditionally
#                        starts this block on a fresh page (unless it's the
#                        very first block rendered, which is already on one)
#                        rather than trusting the block's own drawer to be
#                        pagination-safe at an arbitrary position. Needed
#                        because _draw_pdf_header ignores its y argument
#                        entirely (always draws at a hardcoded y=730) and
#                        _draw_pdf_job_section (the per-event acquisition
#                        loop's first event) has no internal pagination
#                        guard at all - both are safe today only because
#                        case_info/acquisition_method are always drawn in a
#                        fixed, page-fresh position; a reordered custom
#                        template could otherwise silently overlap/clip
#                        content.
REPORT_SECTION_BLOCKS = [
    {"key": "case_info", "default_title": "Case Information",
     "in_legacy_default": True, "requires_events": False, "force_page_break": True},
    {"key": "executive_summary", "default_title": "Executive Summary",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "objectives", "default_title": "Objectives",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "evidence_inventory", "default_title": "Evidence Inventory",
     "in_legacy_default": True, "requires_events": True, "force_page_break": False},
    {"key": "acquisition_method", "default_title": "Acquisition Method",
     "in_legacy_default": True, "requires_events": True, "force_page_break": True},
    {"key": "forensic_analysis", "default_title": "Forensic Analysis / Steps Taken (Case Notes)",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "relevant_findings", "default_title": "Relevant Findings",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "limitations", "default_title": "Limitations & Statement of Uncertainty",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "conclusion", "default_title": "Conclusion",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "iocs", "default_title": "Indicators of Compromise",
     "in_legacy_default": False, "requires_events": False, "force_page_break": False},
    {"key": "recommendations", "default_title": "Recommendations / Next Steps",
     "in_legacy_default": False, "requires_events": False, "force_page_break": False},
    {"key": "attachments", "default_title": "Exhibits",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    # Unlike timeline/iocs/recommendations (in_legacy_default=False, custom-
    # template-only - _expand_legacy_sections_dict() unconditionally skips
    # any False-flagged block, so there is no other way for a block to be
    # checkbox-controlled on the Standard template), Geolocation deliberately
    # gets a real checkbox on the plain Export pane / Settings station
    # defaults - the actual <input> elements just start unchecked in the
    # markup, so a case with no GPS evidence doesn't grow an empty section
    # by default.
    {"key": "geolocation", "default_title": "Geolocation / GPS Evidence",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "audit_trail", "default_title": "Case Activity Log (Audit Trail)",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False},
    {"key": "timeline", "default_title": "Filesystem Timeline (MACB)",
     "in_legacy_default": False, "requires_events": True, "force_page_break": True},
]
assert all(
    {"key", "default_title", "in_legacy_default", "requires_events", "force_page_break"} <= b.keys()
    for b in REPORT_SECTION_BLOCKS
), "every REPORT_SECTION_BLOCKS entry needs all 5 fields - see the docstring above"

_REPORT_SECTION_BLOCK_MAP = {b["key"]: b for b in REPORT_SECTION_BLOCKS}

# Lightweight capability registry - documents what a "feature module" needs
# (apt packages, sudo, where its UI lives) without any dynamic loading,
# dependency isolation, or versioning machinery. Nothing in this app reads
# this dict yet; it exists to establish one consistent shape for describing
# a module's requirements, so install.py can eventually turn a module with
# real optional apt_packages into an install-time checklist item (falling
# back to the existing Settings > Tool Versions "Install" button for anyone
# who skips it - that mechanism already exists and needs no changes).
# Timeline is a deliberately light first entry: it needs no new packages
# (pytsk3/sleuthkit/libewf-dev are already required for the Sleuth Kit
# Image Browser this reuses), so this entry mostly documents linkage
# rather than driving any new install-time gating - that part of the
# pattern will actually get exercised by a future module with real
# optional dependencies (e.g. video thumbnail extraction needing ffmpeg).
FEATURE_MODULES = {
    "timeline": {
        "label": "Filesystem Timeline",
        "category": "analysis",
        "apt_packages": [],
        "needs_sudo": False,
        "ui_hooks": ["file_explorer_image_browser", "report_block:timeline"],
    },
}

def _expand_legacy_sections_dict(sections_dict):
    """Converts the plain sections:{key: bool} dict (today's Export-modal
    checkboxes / Settings station defaults, used only when no custom
    template is selected) into the canonical ordered {key, title} list
    _resolve_section_order()/the registry-driven builders consume - in
    REPORT_SECTION_BLOCKS' own fixed order, default titles only (no
    per-block custom titles are possible via this legacy checkbox path).
    'objectives' has no checkbox of its own - the single existing
    'executive_summary' checkbox continues to control both blocks together,
    unchanged from before this refactor. iocs/recommendations are always
    excluded here (in_legacy_default=False) - Standard's default output
    never showed these before this feature, only DFIR/Police did; they're
    opt-in-only via a custom template."""
    sections_dict = sections_dict or {}
    result = []
    for block in REPORT_SECTION_BLOCKS:
        if not block["in_legacy_default"]:
            continue
        legacy_key = "executive_summary" if block["key"] == "objectives" else block["key"]
        if sections_dict.get(legacy_key, True):
            result.append({"key": block["key"], "title": block["default_title"]})
    return result

def _resolve_section_order(mode, sections_dict, custom_record, event_count):
    """Single source of truth for 'which blocks render, in what order, with
    what title' - used by both the plain Standard export path (mode=
    'legacy', driven by the checkbox dict) and any user-defined custom
    template (mode='custom', driven by a saved runtime_config record). Also
    the single place that filters out blocks needing events the case
    doesn't have, so the draw loop / PDF Contents page / HTML TOC never
    need to separately re-derive that condition (see REPORT_SECTION_BLOCKS'
    requires_events docstring) - a future duplicated copy of this check
    silently drifting out of sync is exactly the fragility this centralizes
    away."""
    if mode == "custom":
        raw = [
            {"key": e["key"], "title": (e.get("title") or "").strip() or _REPORT_SECTION_BLOCK_MAP[e["key"]]["default_title"]}
            for e in custom_record.get("sections", [])
            if e.get("enabled", True) and e.get("key") in _REPORT_SECTION_BLOCK_MAP
        ]
    else:
        raw = _expand_legacy_sections_dict(sections_dict)
    return [e for e in raw if not _REPORT_SECTION_BLOCK_MAP[e["key"]]["requires_events"] or event_count > 0]

def _resolve_template_ref(value, cfg):
    """Single source of truth for turning a 'template' string (from an
    export request or a saved station default) into what to actually
    render - used by both export_report() and settings_case_reporting(),
    which previously each had their own copy of this check (and neither
    knew about custom:<id> references at all). Returns ('standard'|'dfir'|
    'police', None) or ('custom', <template record dict>). Raises
    ValueError if value looks like a custom:<id> reference but that id
    doesn't currently exist in cfg['custom_report_templates'] - callers
    decide what that means for them (export_report() turns it into a 400
    rather than silently rendering something else; settings_case_reporting()
    catches it and stores 'standard' instead, since a station default
    should never be allowed to persist a dangling reference). Any other
    unrecognized value (missing, garbage, an old/bogus string) falls back
    to ('standard', None) silently, matching this app's existing lenient
    behavior for that case."""
    value = value or 'standard'
    if value in REPORT_TEMPLATES:
        return value, None
    if value.startswith('custom:'):
        template_id = value[len('custom:'):]
        for rec in cfg.get('custom_report_templates', []):
            if rec.get('id') == template_id:
                return 'custom', rec
        raise ValueError(f"Selected custom template '{template_id}' no longer exists.")
    return 'standard', None

def _build_pdf_report_standard(pdf_path, header, events, urls, files, audit_entries, case_notes, resolved_sections, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "PI FORENSICS SUITE ACQUISITION AUDIT REPORT")

    # Station branding (Settings > Case & Reporting) renders as an ADDED
    # subtitle line and/or a small top-right logo, never replacing the
    # fixed title above - keeps every report immediately recognizable as
    # coming from this app regardless of what a station has customized.
    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass

    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    # Report Contents gets its own page, right after the title - so the
    # title page reads as a title page and the outline reads as an outline,
    # rather than blending into the Case Information that follows.
    c.showPage()
    _draw_pdf_contents_page(c, resolved_sections, len(events))
    c.showPage()
    y = 750

    # Per-key dispatch table - each entry knows how to draw its own block
    # given the current y and its (possibly custom) title. Built fresh per
    # call so each closure captures this call's own header/events/etc.
    dispatch = {
        "case_info": lambda y, title: _draw_pdf_header(c, header, title=title),
        "executive_summary": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("executive_summary")),
        "objectives": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("objectives")),
        "evidence_inventory": lambda y, title: _draw_pdf_evidence_inventory(c, y, events, title=title),
        "acquisition_method": lambda y, title: _draw_pdf_acquisition_method(c, y, events, job_fields, title=title),
        "forensic_analysis": lambda y, title: _draw_pdf_case_notes(c, y, case_notes, title=title, exhibit_numbers=exhibit_numbers),
        "relevant_findings": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("findings_summary")),
        "limitations": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("limitations")),
        "conclusion": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("conclusion")),
        "iocs": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("iocs")),
        "recommendations": lambda y, title: _draw_pdf_narrative_section(c, y, title, header.get("recommendations_next_steps")),
        "attachments": lambda y, title: _draw_pdf_attachments(c, y, urls, files, title=title, captions=captions,
                                                                tags_by_path=tags_by_path, analysis_by_path=analysis_by_path,
                                                                exhibit_numbers=exhibit_numbers),
        "audit_trail": lambda y, title: _draw_pdf_audit_trail(c, y, audit_entries, title=title),
        "timeline": lambda y, title: _draw_pdf_timeline_block(c, y, events, title=title),
        "geolocation": lambda y, title: _draw_pdf_geolocation_block(c, y, geo_data or [], title=title),
    }

    for i, entry in enumerate(resolved_sections):
        key, title = entry["key"], entry["title"]
        # Some blocks (case_info, acquisition_method) draw at a fixed
        # y/page-fresh position internally and have no pagination guard of
        # their own - safe today only because they're always drawn first,
        # unsafe at an arbitrary custom-template position unless the loop
        # itself forces a fresh page before them. See REPORT_SECTION_BLOCKS'
        # force_page_break docstring.
        if i > 0 and _REPORT_SECTION_BLOCK_MAP[key]["force_page_break"]:
            c.showPage()
            y = 750
        c.bookmarkPage(key)
        c.addOutlineEntry(title, key, level=0)
        y = dispatch[key](y, title)

    c.save()

def _build_pdf_report_dfir(pdf_path, header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """Fixed-structure DFIR Incident Report - no sections/job_fields dict,
    since a template's whole point is a defined shape. Reuses the same
    low-level drawing helpers the Standard template uses; only the section
    list, order, and labels differ, matching the reference DFIR report
    structure this was built against (see the plan's field-mapping table -
    most sections reuse existing narrative fields under a different label
    for this template, only Indicators of Compromise and Containment/Next
    Steps are genuinely new fields)."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "DIGITAL FORENSICS AND INCIDENT RESPONSE REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    entries = ["Case Information", "Executive Summary", "Incident Overview & Scope",
               "Incident Timeline", "Technical Analysis & Forensic Findings",
               "Indicators of Compromise", "Containment, Eradication & Next Steps"]
    has_exhibits = bool(urls or files)
    if has_exhibits:
        entries.append("Exhibits")
    entries.append("Audit Trail")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('case_info')
    c.addOutlineEntry("Case Information", 'case_info', level=0)
    y = _draw_pdf_header(c, header)

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('overview_scope')
    c.addOutlineEntry("Incident Overview & Scope", 'overview_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Incident Overview & Scope", header.get('objectives'))

    c.bookmarkPage('timeline')
    c.addOutlineEntry("Incident Timeline", 'timeline', level=0)
    y = _draw_pdf_timeline_table(c, y, case_notes, title="Incident Timeline")

    c.bookmarkPage('technical_analysis')
    c.addOutlineEntry("Technical Analysis & Forensic Findings", 'technical_analysis', level=0)
    y = _draw_pdf_narrative_section(c, y, "Technical Analysis & Forensic Findings", header.get('findings_summary'))

    c.bookmarkPage('iocs')
    c.addOutlineEntry("Indicators of Compromise", 'iocs', level=0)
    y = _draw_pdf_narrative_section(c, y, "Indicators of Compromise", header.get('iocs'))

    c.bookmarkPage('containment')
    c.addOutlineEntry("Containment, Eradication & Next Steps", 'containment', level=0)
    y = _draw_pdf_narrative_section(c, y, "Containment, Eradication & Next Steps", header.get('recommendations_next_steps'))

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('audit_trail')
    c.addOutlineEntry("Audit Trail", 'audit_trail', level=0)
    y = _draw_pdf_audit_trail(c, y, audit_entries)

    c.save()

def _build_pdf_report_police(pdf_path, header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """Fixed-structure Forensics (Police) Report, modeled on the reference
    law-enforcement examination report. Reuses the same low-level drawing
    helpers as the other two templates - see the plan's field-mapping table
    for what's reused vs. genuinely new.

    One disclosed gap: the reference report's "Chain of Custody Log" is
    about physical evidence handoffs between people (officer to analyst to
    evidence vault) - this app has no concept of that. Reusing this app's
    Audit Trail (a log of actions taken in the software) under that heading
    is the closest real fit, not a literal personnel custody-transfer log -
    labeled "Chain of Custody / Activity Log" rather than silently passed
    off as the real thing."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "POLICE FORENSICS INVESTIGATION REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    has_exhibits = bool(urls or files)
    entries = ["Administrative Information", "Executive Summary", "Case Background & Scope",
               "Evidence Collection & Chain of Custody", "Forensic Methodology & Tools",
               "Detailed Findings & Analysis", "Conclusion & Summary", "Sign-off & Signatures"]
    if has_exhibits:
        entries.append("Exhibits & Appendices")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('admin_info')
    c.addOutlineEntry("Administrative Information", 'admin_info', level=0)
    y = _draw_pdf_header(c, header, title="Administrative Information")

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('background_scope')
    c.addOutlineEntry("Case Background & Scope", 'background_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Case Background & Scope", header.get('objectives'))

    c.bookmarkPage('evidence_coc')
    c.addOutlineEntry("Evidence Collection & Chain of Custody", 'evidence_coc', level=0)
    y = _draw_pdf_evidence_inventory(c, y, events, title="Itemized Evidence & Integrity Hashing")
    y = _draw_pdf_audit_trail(c, y, audit_entries, title="Chain of Custody / Activity Log")

    c.bookmarkPage('methodology')
    c.addOutlineEntry("Forensic Methodology & Tools", 'methodology', level=0)
    y = _draw_pdf_methodology_tools(c, y, events)

    c.bookmarkPage('findings')
    c.addOutlineEntry("Detailed Findings & Analysis", 'findings', level=0)
    y = _draw_pdf_timeline_table(c, y, case_notes, title="Chronological Timeline of Events")
    y = _draw_pdf_narrative_section(c, y, "Artifact Analysis", header.get('findings_summary'))

    c.bookmarkPage('conclusion')
    c.addOutlineEntry("Conclusion & Summary", 'conclusion', level=0)
    y = _draw_pdf_narrative_section(c, y, "Conclusion", header.get('conclusion'))
    y = _draw_pdf_narrative_section(c, y, "Recommendations", header.get('recommendations_next_steps'))

    c.bookmarkPage('signoff')
    c.addOutlineEntry("Sign-off & Signatures", 'signoff', level=0)
    y = _draw_pdf_signoff(c, y, header['examiner'])

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits & Appendices", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.save()

def _build_pdf_report_caseuco(pdf_path, header, events, urls, files, audit_entries, case_notes, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    """Fixed-structure report aligned with the CASE/UCO cyber-forensic
    ontology (caseontology.org) - Investigation, ObservableObject,
    InvestigativeAction, ProvenanceRecord, Analysis, Tool, Location. Reuses
    the same low-level drawing helpers as the other two fixed templates;
    every section maps onto an existing data source or shared helper, no
    new schema fields were needed - see the plan's section-mapping table.

    Two disclosed simplifications, matching the honesty already established
    for DFIR/Police: (1) the ontology models distinct Examiner/Investigator/
    Subject/Attorney roles - this app has one Examiner field, not separate
    per-role records, so "Investigation Overview" only ever shows the one
    Examiner; a station that wants Authorization/Investigation Status/Form
    captured can add them as Custom Case Fields, the same mechanism Police's
    Administrative Information already relies on. (2) "Provenance Record /
    Chain of Custody" reuses this app's Audit Trail (a software-action log),
    not a literal ProvenanceRecord graph of wasDerivedFrom/wasInformedBy
    relationships - same substitution reasoning as Police's own Chain of
    Custody section.

    Unlike DFIR/Police, this template always includes a Geolocation section
    (maps directly onto the ontology's Location module) - geo_data is
    computed unconditionally for this template in export_report(), not
    gated behind a checkbox like Standard's opt-in version.

    Pagination note: _draw_pdf_header has no internal page-break guard, but
    it's always safe here as the very first section drawn right after the
    contents page's own showPage(). _draw_pdf_acquisition_method also has
    no internal guard and is NOT first, so it needs an explicit showPage()
    immediately before it - see _draw_pdf_acquisition_method's own
    docstring for why. Every other helper below already guards its own
    pagination internally."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "CASE/UCO CYBER-INVESTIGATION REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    has_exhibits = bool(urls or files)
    entries = ["Investigation Overview", "Investigation Focus & Scope", "Executive Summary",
               "Observable Objects (Digital Evidence)", "Investigative Actions",
               "Analysis & Analytic Results (Case Notes)", "Relevant Findings",
               "Tools & Configured Tools", "Geolocation / Location Evidence", "Conclusion",
               "Limitations & Data Handling Markings", "Provenance Record / Chain of Custody"]
    if has_exhibits:
        entries.append("Exhibits (Evidence Provenance Records)")
    entries.append("Sign-off & Signatures")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('investigation_overview')
    c.addOutlineEntry("Investigation Overview", 'investigation_overview', level=0)
    y = _draw_pdf_header(c, header, title="Investigation Overview")

    c.bookmarkPage('focus_scope')
    c.addOutlineEntry("Investigation Focus & Scope", 'focus_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Investigation Focus & Scope", header.get('objectives'))

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('observable_objects')
    c.addOutlineEntry("Observable Objects (Digital Evidence)", 'observable_objects', level=0)
    y = _draw_pdf_evidence_inventory(c, y, events, title="Observable Objects (Digital Evidence)")

    c.showPage()
    y = 750
    c.bookmarkPage('investigative_actions')
    c.addOutlineEntry("Investigative Actions", 'investigative_actions', level=0)
    y = _draw_pdf_acquisition_method(c, y, events, job_fields, title="Investigative Actions")

    c.bookmarkPage('analysis_findings')
    c.addOutlineEntry("Analysis & Analytic Results (Case Notes)", 'analysis_findings', level=0)
    y = _draw_pdf_case_notes(c, y, case_notes, title="Analysis & Analytic Results (Case Notes)", exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('relevant_findings')
    c.addOutlineEntry("Relevant Findings", 'relevant_findings', level=0)
    y = _draw_pdf_narrative_section(c, y, "Relevant Findings", header.get('findings_summary'))

    c.bookmarkPage('tools')
    c.addOutlineEntry("Tools & Configured Tools", 'tools', level=0)
    y = _draw_pdf_methodology_tools(c, y, events)

    c.bookmarkPage('geolocation')
    c.addOutlineEntry("Geolocation / Location Evidence", 'geolocation', level=0)
    y = _draw_pdf_geolocation_block(c, y, geo_data or [], title="Geolocation / Location Evidence")

    c.bookmarkPage('conclusion')
    c.addOutlineEntry("Conclusion", 'conclusion', level=0)
    y = _draw_pdf_narrative_section(c, y, "Conclusion", header.get('conclusion'))

    c.bookmarkPage('limitations')
    c.addOutlineEntry("Limitations & Data Handling Markings", 'limitations', level=0)
    y = _draw_pdf_narrative_section(c, y, "Limitations & Data Handling Markings", header.get('limitations'))

    c.bookmarkPage('provenance_coc')
    c.addOutlineEntry("Provenance Record / Chain of Custody", 'provenance_coc', level=0)
    y = _draw_pdf_audit_trail(c, y, audit_entries, title="Provenance Record / Chain of Custody")

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits (Evidence Provenance Records)", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, title="Exhibits (Evidence Provenance Records)", captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('signoff')
    c.addOutlineEntry("Sign-off & Signatures", 'signoff', level=0)
    y = _draw_pdf_signoff(c, y, header['examiner'])

    c.save()

def _embed_file_into_html(file_path, caption=None, exhibit_number=None, category=None, tags=None, analysis_summary=None):
    """HTML counterpart to _embed_file_into_pdf - shared by Exhibits (case
    attachments) and the Case Notes journal. caption is examiner-entered
    free text. exhibit_number/category/tags/analysis_summary are
    Exhibits-only enrichment - the Case Notes journal's own call never
    passes them, so they default to None and add nothing there. Every value
    is examiner/evidence-derived (filename, tag comment, analysis summary),
    so everything goes through html.escape() before interpolation, same
    discipline as every other untrusted string this app embeds into a
    report that might later be reopened in a browser."""
    esc = html.escape
    name = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        size = 0

    heading = (f"Exhibit {exhibit_number}: " if exhibit_number else "") + esc(name) + (f" [{esc(category)}]" if category else "")
    caption_html = f'<p class="muted"><em>{esc(caption)}</em></p>' if caption else ''
    tags_html = ''
    if tags:
        tag_bits = [
            ('&#9733; ' if t.get('notable') else '') + esc(t['name']) + (f' &mdash; &quot;{esc(t["comment"])}&quot;' if t.get('comment') else '')
            for t in tags
        ]
        tags_html = f'<p class="muted"><strong>Tags:</strong> {"; ".join(tag_bits)}</p>'
    analysis_html = f'<p class="muted"><strong>Analysis:</strong> {esc(analysis_summary)}</p>' if analysis_summary else ''
    meta_html = caption_html + tags_html + analysis_html

    if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
        mime = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
        }.get(ext, 'application/octet-stream')
        try:
            with open(file_path, 'rb') as imf:
                b64 = base64.b64encode(imf.read()).decode('ascii')
            return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<img src="data:{mime};base64,{b64}"></div>'
        except OSError as e:
            return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<p class="muted">Could not read image: {esc(str(e))}</p></div>'
    elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
        try:
            with open(file_path, 'r', errors='replace') as tf:
                text_content = tf.read(ATTACHMENT_MAX_TEXT_EMBED_BYTES)
        except OSError as e:
            text_content = f"(could not read file: {e})"
        return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<pre>{esc(text_content)}</pre></div>'
    else:
        size_note = f" ({size:,} bytes)" if size else ""
        return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<p class="muted mono">{esc(file_path)}{esc(size_note)}</p></div>'

def _html_timeline_table(case_notes, title="Incident Timeline", anchor_id=None):
    """HTML counterpart to _draw_pdf_timeline_table - same case_notes source,
    rendered as a table instead of the Standard template's journal style."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [
        f'<h2{id_attr}>{esc(title)}</h2>',
        '<p class="muted">Chronological entries from the examiner\'s case notes journal.</p>',
    ]
    if not case_notes:
        parts.append('<p class="muted">No timeline entries recorded.</p>')
        return ''.join(parts)
    parts.append('<table><tr><th>Timestamp</th><th>Category</th><th>Description</th></tr>')
    for note in sorted(case_notes, key=lambda n: n.get('timestamp', '')):
        parts.append(
            f'<tr><td>{esc(str(note.get("timestamp", "N/A")))}</td>'
            f'<td>{esc(str(note.get("category", "General")))}</td>'
            f'<td>{esc(str(note.get("text", "")))}</td></tr>'
        )
    parts.append('</table>')
    return ''.join(parts)

def _html_timeline_block(events, title="Filesystem Timeline (MACB)", anchor_id=None):
    """HTML counterpart to _draw_pdf_timeline_block - see
    _collect_case_timeline() for how these events are gathered (dedup/
    status-gating/per-image budget)."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    result = _collect_case_timeline(events)
    timeline_events = result["events"]

    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if not timeline_events:
        parts.append('<p class="muted">No filesystem timeline available for this case\'s evidence items.</p>')
    else:
        parts.append('<table><tr><th>Timestamp</th><th>Activity</th><th>Evidence ID</th><th>Path</th></tr>')
        for entry in timeline_events:
            parts.append(
                f'<tr><td>{esc(str(entry.get("timestamp", "N/A")))}</td>'
                f'<td>{esc(str(entry.get("activity", "")))}</td>'
                f'<td>{esc(str(entry.get("evidence_id", "N/A")))}</td>'
                f'<td class="mono">{esc(str(entry.get("path", "")))}</td></tr>'
            )
        parts.append('</table>')
        if result["truncated"]:
            parts.append('<p class="muted">Timeline truncated - not every timestamped filesystem event fit within the report\'s size limits.</p>')

    if result["notes"]:
        parts.append('<p class="muted"><strong>Notes:</strong></p><ul>')
        for note in result["notes"]:
            parts.append(f'<li class="muted">{esc(note)}</li>')
        parts.append('</ul>')

    return ''.join(parts)

_LEAFLET_CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'vendor', 'leaflet', 'leaflet.css')
_LEAFLET_JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'vendor', 'leaflet', 'leaflet.js')

def _html_leaflet_assets_block():
    """Inlines the vendored Leaflet library as literal <style>/<script>
    content - not a <link>/<script src> pointing at a server-relative path
    - so an exported HTML report stays genuinely self-contained and
    reopenable months later with this app's server long gone, matching
    every other embedded asset in this export (attachment images, the
    branding logo). Live OSM tile *imagery* still needs a real network
    connection at view time regardless - that part can't be vendored into a
    static file, the same already-accepted tradeoff the live in-app
    Leaflet viewer has. Only called when the Geolocation section is
    actually being rendered (see _build_html_report_standard), so every
    export that doesn't use it stays exactly as small as before this
    feature. Leaflet's own CSS references its default marker-icon PNGs via
    relative url(...) paths that won't resolve once inlined this way - not
    fixed here since _html_geolocation_block below only ever uses
    L.circleMarker pins, which never need those default icons."""
    try:
        with open(_LEAFLET_CSS_PATH, 'r', encoding='utf-8') as f:
            css = f.read()
        with open(_LEAFLET_JS_PATH, 'r', encoding='utf-8') as f:
            js = f.read()
    except OSError:
        return ''
    return f'<style>{css}</style><script>{js}</script>'

def _html_geolocation_block(kml_data, title="Geolocation / GPS Evidence", anchor_id=None):
    """HTML counterpart to _draw_pdf_geolocation_block - a real interactive
    Leaflet map (live OSM tiles only; no offline-cache fallback attempt,
    since this exported file may be reopened completely disconnected from
    this app's own server, where a /static/vendor/osm_tiles/... URL
    wouldn't resolve anyway) per KML file, followed by the same
    Name/Latitude/Longitude/Description placemark table PDF renders.
    Placemark name/description are untrusted KML content (an examiner can
    open ANY .kml, not just one this app generated) - the table cells go
    through html.escape() like every other field in this document, and the
    popup content is built via textContent (never innerHTML) in the inline
    script below, matching this app's existing untrusted-content discipline
    for the live Leaflet viewer (escapeHtmlForPopup() in main.js)."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']

    if not kml_data:
        parts.append('<p class="muted">No geolocation (KML) evidence with GPS placemarks found for this case.</p>')
        return ''.join(parts)

    for i, entry in enumerate(kml_data):
        map_id = f'geomap_{i}'
        parts.append('<div class="job">')
        parts.append(f'<h3>{esc(entry["name"])}</h3>')
        parts.append(f'<div class="muted mono">{esc(entry["path"])}</div>')
        parts.append(f'<div id="{esc(map_id)}" style="height:340px;width:100%;margin:.6em 0;border:1px solid #ccc;border-radius:6px;"></div>')

        parts.append('<table><tr><th>Name</th><th>Latitude</th><th>Longitude</th><th>Description</th></tr>')
        for p in entry['placemarks']:
            parts.append(
                f'<tr><td>{esc(p["name"] or "(unnamed)")}</td>'
                f'<td class="mono">{p["lat"]:.6f}</td><td class="mono">{p["lon"]:.6f}</td>'
                f'<td>{esc(p["description"])}</td></tr>'
            )
        parts.append('</table>')

        # Placemark data is passed to the browser as a JSON literal, not raw
        # JS interpolation - untrusted name/description text could otherwise
        # contain a literal </script> sequence that would prematurely close
        # this tag, so every '</' is escaped to '<\/' (a standard, safe fix
        # for embedding arbitrary JSON inside an inline <script> block).
        points = [{"lat": p["lat"], "lon": p["lon"], "name": p["name"], "description": p["description"]} for p in entry['placemarks']]
        points_json = json.dumps(points).replace('</', '<\\/')
        parts.append(
            '<script>(function(){'
            f'var pts={points_json};'
            f'var mapDiv=document.getElementById("{map_id}");'
            'if(!mapDiv||typeof L==="undefined"||!pts.length)return;'
            'var map=L.map(mapDiv);'
            'L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",'
            '{attribution:"&copy; OpenStreetMap contributors",maxZoom:19}).addTo(map);'
            'var bounds=[];'
            'pts.forEach(function(p){'
            'var m=L.circleMarker([p.lat,p.lon],{radius:7,color:"#c0392b",weight:2,fillColor:"#e74c3c",fillOpacity:0.9}).addTo(map);'
            'var div=document.createElement("div");'
            'var b=document.createElement("b");b.textContent=p.name||"(unnamed)";div.appendChild(b);'
            'div.appendChild(document.createElement("br"));'
            'var span=document.createElement("span");span.textContent=p.description||"";div.appendChild(span);'
            'm.bindPopup(div);'
            'bounds.push([p.lat,p.lon]);'
            '});'
            'if(bounds.length===1){map.setView(bounds[0],14);}else{map.fitBounds(bounds,{padding:[20,20]});}'
            'setTimeout(function(){map.invalidateSize();},50);'
            '})();</script>'
        )
        parts.append('</div>')
    return ''.join(parts)

def _html_methodology_tools(events, anchor_id=None):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    tools = sorted({str(e.get('tool')).upper() for e in events if e.get('tool')})
    tools_str = ', '.join(tools) if tools else 'No acquisition/recovery tool recorded.'
    return (
        f'<h2{id_attr}>Forensic Methodology &amp; Tools</h2>'
        f'<p>{esc(_METHODOLOGY_STATIC_TEXT)}</p>'
        f'<p><strong>Tools Used in This Case:</strong> {esc(tools_str)}</p>'
    )

def _html_signoff(examiner, anchor_id=None):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    return (
        f'<h2{id_attr}>Sign-off &amp; Signatures</h2>'
        f'<p>{esc(_SIGNOFF_STATIC_TEXT)}</p>'
        f'<p>Examiner: {esc(str(examiner))}</p>'
        '<div style="display:flex;gap:60px;margin-top:2em;max-width:600px;">'
        '<div style="flex:1;border-top:1px solid #333;padding-top:4px;">Signature</div>'
        '<div style="flex:1;border-top:1px solid #333;padding-top:4px;">Date</div>'
        '</div>'
    )

def _html_narrative_block(title, text, anchor_id=None):
    esc = html.escape
    text = (text or '').strip()
    body = f'<span style="white-space:pre-wrap;">{esc(text)}</span>' if text else '<span class="muted">(Not provided)</span>'
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    return f'<h2{id_attr}>{esc(title)}</h2><p>{body}</p>'

def _build_html_toc(resolved_sections, has_exhibits):
    """Mirrors the PDF's Report Contents page - a plain section list, but as
    real anchor links since HTML doesn't have the PDF's single-pass-render
    page-number problem to work around. resolved_sections is the same
    already-filtered/ordered list the draw loop below consumes (see
    _resolve_section_order) - the one condition not modeled there, since
    it's a property of this specific export's data rather than a fixed
    property of the block itself, is 'attachments': skipped here (and in
    the draw loop) when there's nothing to attach, matching this section's
    pre-existing behavior."""
    esc = html.escape
    entries = []
    for entry in resolved_sections:
        if entry["key"] == "attachments" and not has_exhibits:
            continue
        anchor = "sec-" + entry["key"].replace("_", "-")
        entries.append((anchor, esc(entry["title"])))

    if not entries:
        return ''
    items = ''.join(f'<li><a href="#{anchor}">{label}</a></li>' for anchor, label in entries)
    return f'<nav class="toc"><h2>Report Contents</h2><ol>{items}</ol></nav>'

def _html_evidence_inventory_table(events, title="Evidence Inventory", anchor_id=None):
    """HTML counterpart to _draw_pdf_evidence_inventory - shared by all
    three templates. The Police template reuses this under a different
    title ("Itemized Evidence & Integrity Hashing")."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2><table>']
    parts.append('<tr><th>Evidence ID</th><th>Device</th><th>Model</th><th>Serial</th><th>Capacity</th><th>Acquisition Hash</th></tr>')
    for event in events:
        meta = event.get('case_metadata', {})
        drive = event.get('source_drive_telemetry', {})
        hash_display = _pick_display_hash(event.get('computed_verification_hashes', {}))
        parts.append(
            f'<tr><td>{esc(str(meta.get("evidence_id", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("device_path", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("vendor_model", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("serial_number", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("capacity_gb", "N/A")))} GB</td>'
            f'<td class="mono">{esc(str(hash_display))}</td></tr>'
        )
    parts.append('</table>')
    return ''.join(parts)

def _html_exhibits_block(urls, files, anchor_id=None, title="Exhibits", captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _draw_pdf_attachments - shared by all three
    templates' Exhibits section. Caller already checks whether there's
    anything to show (urls or files) before calling this."""
    captions = captions or {}
    tags_by_path = tags_by_path or {}
    analysis_by_path = analysis_by_path or {}
    # Looked up against the case's FULL attachments.files list, not
    # enumerated from `files` (a possibly-filtered per-export subset) - see
    # the matching comment in _draw_pdf_attachments.
    exhibit_numbers = exhibit_numbers or {}
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if urls:
        parts.append('<p><strong>Reference Links / URLs:</strong></p><ul>')
        for url in urls:
            parts.append(f'<li><a href="{esc(str(url))}">{esc(str(url))}</a></li>')
        parts.append('</ul>')
    if files:
        parts.append('<p class="muted"><em>Exhibit numbers reflect this case\'s current attachment order.</em></p>')
    for raw_path in files:
        file_path = safe_path(raw_path)
        if not file_path or not os.path.exists(file_path):
            continue
        category, _ext = classify_extension(os.path.basename(file_path))
        parts.append(_embed_file_into_html(
            file_path, caption=captions.get(raw_path), exhibit_number=exhibit_numbers.get(raw_path), category=category,
            tags=tags_by_path.get(raw_path), analysis_summary=_format_analysis_summary(analysis_by_path.get(raw_path))))
    return ''.join(parts)

def _html_audit_trail_block(audit_entries, anchor_id=None, title="Case Activity Log (Audit Trail)"):
    """HTML counterpart to _draw_pdf_audit_trail - shared by all three
    templates. The Police template reuses this under a different title
    ("Chain of Custody / Activity Log") since this app's audit trail is the
    closest real substitute it has for that section, not a literal personnel
    custody-transfer log - see _build_pdf_report_police's own comment."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if audit_entries:
        parts.append('<table><tr><th>Timestamp</th><th>Action</th><th>Details</th></tr>')
        for entry in audit_entries:
            details_str = ', '.join(f'{k}={v}' for k, v in (entry.get('details') or {}).items())
            parts.append(f'<tr><td>{esc(str(entry.get("timestamp", "")))}</td><td>{esc(str(entry.get("action", "")))}</td><td>{esc(details_str)}</td></tr>')
        parts.append('</table>')
    else:
        parts.append('<p class="muted">No activity log entries found for this case.</p>')
    return ''.join(parts)

def _html_report_style_block():
    """Shared CSS for all three report-template HTML builders below - one
    definition, so restyling the report format doesn't mean editing it in
    three places."""
    return (
        '<style>'
        'body{font-family:Arial,Helvetica,sans-serif;color:#111;max-width:900px;margin:2em auto;padding:0 1em;}'
        'h1{font-size:1.4em;border-bottom:2px solid #333;padding-bottom:.3em;}'
        'h2{font-size:1.15em;margin-top:1.6em;border-bottom:1px solid #999;padding-bottom:.2em;}'
        'h3{font-size:1em;margin:.8em 0 .3em;}'
        'table{border-collapse:collapse;width:100%;margin:.4em 0;}'
        'td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:.9em;vertical-align:top;}'
        '.job{margin-top:1.2em;padding:.8em;border:1px solid #ccc;border-radius:6px;}'
        '.muted{color:#666;font-size:.85em;}'
        '.mono{font-family:"Courier New",monospace;}'
        '.attach-item{margin-top:1em;padding:.7em;border:1px solid #ddd;border-radius:6px;}'
        '.attach-item img{max-width:100%;border:1px solid #ccc;display:block;margin-top:.4em;}'
        '.attach-item pre{background:#f5f5f5;padding:.6em;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.8em;margin-top:.4em;}'
        '.branding-header{display:flex;justify-content:space-between;align-items:flex-start;gap:1em;border-bottom:2px solid #333;padding-bottom:.3em;}'
        '.branding-header h1{border-bottom:none;padding-bottom:0;margin:0;}'
        '.branding-header img{max-height:50px;max-width:160px;}'
        '.branding-subtitle{color:#444;font-size:.9em;margin:.2em 0 1em;}'
        '.toc{background:#f7f7f7;border:1px solid #ddd;border-radius:6px;padding:.8em 1.2em;margin:1em 0;}'
        '.toc h2{margin-top:0;font-size:1em;border-bottom:none;padding-bottom:0;}'
        '.toc ol{margin:.3em 0 0;padding-left:1.4em;}'
        '.toc li{margin:.25em 0;}'
        '.toc a{color:#1a4d8f;text-decoration:none;}'
        '.toc a:hover{text-decoration:underline;}'
        '</style>'
    )

def _html_report_branding_header(header, title):
    """Renders the branding-header block (fixed template title + station's
    optional added subtitle/logo from Settings > Case & Reporting) - shared
    by all three HTML builders, only the title text differs per template."""
    esc = html.escape
    branding = header.get('branding', {})
    logo_path = branding.get('logo_path') or ''
    logo_html = ''
    if logo_path and os.path.exists(logo_path):
        ext = os.path.splitext(logo_path)[1].lower()
        mime = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
        }.get(ext, 'application/octet-stream')
        try:
            with open(logo_path, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode('ascii')
            logo_html = f'<img src="data:{mime};base64,{logo_b64}" alt="station logo">'
        except OSError:
            logo_html = ''
    parts = [f'<div class="branding-header"><h1>{esc(title)}</h1>{logo_html}</div>']
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        parts.append(f'<div class="branding-subtitle">{esc(header_text)}</div>')
    return ''.join(parts)

def _html_case_info_block(header, event_count, anchor_id=None, title="Case Information"):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2><table>']
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Created</th><td>{esc(str(header["created_at"]))}</td><th>Evidence Items</th><td>{event_count}</td></tr>')
    parts.append(f'<tr><th>Notes</th><td colspan="3">{esc(str(header["notes"] or "None"))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')
    return ''.join(parts)

def _html_acquisition_method(events, job_fields, anchor_id=None):
    """HTML counterpart to _draw_pdf_acquisition_method - no title param,
    since (matching the PDF side) there's no single on-page heading for
    this block, only per-event headings; the anchor lands on the first
    event's div."""
    esc = html.escape
    parts = []
    for i, event in enumerate(events):
        meta = event.get('case_metadata', {})
        anchor_attr = f' id="{esc(anchor_id)}"' if (i == 0 and anchor_id) else ''
        parts.append(f'<div class="job"{anchor_attr}>')
        parts.append(f'<h2>Evidence Item: {esc(str(meta.get("evidence_id", "N/A")))} ({esc(str(event.get("tool", "N/A")))})</h2>')
        parts.append(f'<div class="muted">Date: {esc(str(event.get("timestamp_start", "N/A")))} &middot; Status: {esc(str(event.get("acquisition_status", "N/A")))}</div>')

        if job_fields.get('telemetry', True):
            drive = event.get('source_drive_telemetry', {})
            parts.append('<h3>Source Media Telemetry</h3><table>')
            parts.append(f'<tr><th>Device</th><td>{esc(str(drive.get("device_path")))}</td><th>Capacity</th><td>{esc(str(drive.get("capacity_gb")))} GB</td></tr>')
            parts.append(f'<tr><th>Model</th><td>{esc(str(drive.get("vendor_model")))}</td><th>Serial</th><td>{esc(str(drive.get("serial_number")))}</td></tr>')
            parts.append(f'<tr><th>SMART Status</th><td colspan="3">{"PASSED" if drive.get("smart_healthy") else "FAILING"}</td></tr>')
            parts.append('</table>')

        if job_fields.get('params', True):
            params = event.get('acquisition_parameters', {})
            parts.append('<h3>Acquisition Parameters</h3><table>')
            parts.append(f'<tr><th>Format</th><td>{esc(str(params.get("output_format", event.get("tool", "N/A"))).upper())}</td><th>Status</th><td>{esc(str(event.get("acquisition_status")))}</td></tr>')
            if params.get('bitlocker_key'):
                parts.append(f'<tr><th>BitLocker Recovery Key/Password</th><td class="mono" colspan="3">{esc(str(params["bitlocker_key"]))}</td></tr>')
            parts.append('</table>')

        if job_fields.get('hashes', True):
            hashes = event.get('computed_verification_hashes', {})
            parts.append('<h3>Verification Hashes</h3><table>')
            if hashes:
                for k, v in hashes.items():
                    parts.append(f'<tr><th>{esc(k.upper())}</th><td class="mono">{esc(str(v))}</td></tr>')
            else:
                parts.append('<tr><td colspan="2" class="muted">No hashes recorded.</td></tr>')
            parts.append('</table>')

        parts.append('</div>')
    return ''.join(parts)

def _html_case_notes_block(case_notes, anchor_id=None, title="Forensic Analysis / Steps Taken (Case Notes)", exhibit_numbers=None):
    exhibit_numbers = exhibit_numbers or {}
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    parts.append('<p class="muted">Chronological case notes, each with a local SHA-256 integrity hash (tamper-evidence only, not a legal timestamp authority).</p>')
    if not case_notes:
        parts.append('<p class="muted">No case notes recorded.</p>')
    for note in case_notes:
        parts.append('<div class="job">')
        author = esc(str(note.get('author') or 'unknown'))
        parts.append(f'<h3>[{esc(str(note.get("category", "General")))}] {esc(str(note.get("timestamp", "")))} &mdash; {author}</h3>')
        if note.get('edited_at'):
            parts.append(f'<div class="muted">(edited {esc(str(note["edited_at"]))})</div>')
        parts.append(f'<p style="white-space:pre-wrap;">{esc(str(note.get("text", "")))}</p>')
        linked = [p for p in (note.get('linked_files') or []) if p in exhibit_numbers]
        if linked:
            link_bits = [f'Exhibit {exhibit_numbers[p]} &mdash; {esc(os.path.basename(p))}' for p in linked]
            parts.append(f'<p class="muted"><strong>Linked Exhibit(s):</strong> {"; ".join(link_bits)}</p>')
        for att in note.get('attachments', []):
            file_path = safe_path(att.get('path', ''))
            if file_path and os.path.exists(file_path):
                parts.append(_embed_file_into_html(file_path))
        parts.append('</div>')
    return ''.join(parts)

def _build_html_report_standard(header, events, urls, files, audit_entries, case_notes, resolved_sections, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    """Self-contained HTML report - every value is escaped since it may
    contain examiner-entered text or evidence-derived strings (filenames,
    device paths) that this file could later be reopened/served from disk.
    resolved_sections (see _resolve_section_order) is the already-filtered,
    already-ordered {key, title} list this registry-driven loop dispatches
    over - shared with the PDF builder's own version of this same loop."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    # The vendored Leaflet library is only inlined into <head> when the
    # Geolocation section is both selected AND actually has real placemark
    # data to render - every export that doesn't use it stays exactly as
    # small as before this feature (see _html_leaflet_assets_block).
    needs_leaflet = bool(geo_data) and any(e["key"] == "geolocation" for e in resolved_sections)
    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>Case Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        _html_leaflet_assets_block() if needs_leaflet else '',
        '</head><body>',
        _html_report_branding_header(header, "Pi Forensics Suite Acquisition Audit Report"),
    ]

    parts.append(_build_html_toc(resolved_sections, has_exhibits))

    dispatch = {
        "case_info": lambda anchor, title: _html_case_info_block(header, len(events), anchor_id=anchor, title=title),
        "executive_summary": lambda anchor, title: _html_narrative_block(title, header.get("executive_summary"), anchor),
        "objectives": lambda anchor, title: _html_narrative_block(title, header.get("objectives"), anchor),
        "evidence_inventory": lambda anchor, title: _html_evidence_inventory_table(events, title=title, anchor_id=anchor),
        "acquisition_method": lambda anchor, title: _html_acquisition_method(events, job_fields, anchor_id=anchor),
        "forensic_analysis": lambda anchor, title: _html_case_notes_block(case_notes, anchor_id=anchor, title=title, exhibit_numbers=exhibit_numbers),
        "relevant_findings": lambda anchor, title: _html_narrative_block(title, header.get("findings_summary"), anchor),
        "limitations": lambda anchor, title: _html_narrative_block(title, header.get("limitations"), anchor),
        "conclusion": lambda anchor, title: _html_narrative_block(title, header.get("conclusion"), anchor),
        "iocs": lambda anchor, title: _html_narrative_block(title, header.get("iocs"), anchor),
        "recommendations": lambda anchor, title: _html_narrative_block(title, header.get("recommendations_next_steps"), anchor),
        "attachments": lambda anchor, title: _html_exhibits_block(urls, files, anchor_id=anchor, title=title, captions=captions,
                                                                    tags_by_path=tags_by_path, analysis_by_path=analysis_by_path,
                                                                    exhibit_numbers=exhibit_numbers),
        "audit_trail": lambda anchor, title: _html_audit_trail_block(audit_entries, anchor_id=anchor, title=title),
        "timeline": lambda anchor, title: _html_timeline_block(events, title=title, anchor_id=anchor),
        "geolocation": lambda anchor, title: _html_geolocation_block(geo_data or [], title=title, anchor_id=anchor),
    }

    for entry in resolved_sections:
        key, title = entry["key"], entry["title"]
        if key == "attachments" and not has_exhibits:
            continue
        anchor = "sec-" + key.replace("_", "-")
        parts.append(dispatch[key](anchor, title))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_dfir(header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _build_pdf_report_dfir - same fixed section list,
    same reused data sources, see that function's docstring."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-case-info', 'Case Information'), ('sec-exec-summary', 'Executive Summary'),
        ('sec-overview-scope', 'Incident Overview &amp; Scope'), ('sec-timeline', 'Incident Timeline'),
        ('sec-technical-analysis', 'Technical Analysis &amp; Forensic Findings'),
        ('sec-iocs', 'Indicators of Compromise'),
        ('sec-containment', 'Containment, Eradication &amp; Next Steps'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits'))
    toc_entries.append(('sec-audit-trail', 'Audit Trail'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>DFIR Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        '</head><body>',
        _html_report_branding_header(header, "Digital Forensics and Incident Response Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append('<h2 id="sec-case-info">Case Information</h2><table>')
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Created</th><td colspan="3">{esc(str(header["created_at"]))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')

    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_narrative_block('Incident Overview & Scope', header.get('objectives'), 'sec-overview-scope'))
    parts.append(_html_timeline_table(case_notes, title="Incident Timeline", anchor_id='sec-timeline'))
    parts.append(_html_narrative_block('Technical Analysis & Forensic Findings', header.get('findings_summary'), 'sec-technical-analysis'))
    parts.append(_html_narrative_block('Indicators of Compromise', header.get('iocs'), 'sec-iocs'))
    parts.append(_html_narrative_block('Containment, Eradication & Next Steps', header.get('recommendations_next_steps'), 'sec-containment'))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append(_html_audit_trail_block(audit_entries, anchor_id='sec-audit-trail'))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_police(header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _build_pdf_report_police - same fixed section
    list, same reused data sources, same disclosed Chain-of-Custody-vs-
    Audit-Trail caveat, see that function's docstring."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-admin-info', 'Administrative Information'), ('sec-exec-summary', 'Executive Summary'),
        ('sec-background-scope', 'Case Background &amp; Scope'),
        ('sec-evidence-coc', 'Evidence Collection &amp; Chain of Custody'),
        ('sec-methodology', 'Forensic Methodology &amp; Tools'),
        ('sec-findings', 'Detailed Findings &amp; Analysis'),
        ('sec-conclusion', 'Conclusion &amp; Summary'),
        ('sec-signoff', 'Sign-off &amp; Signatures'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits &amp; Appendices'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>Police Forensics Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        '</head><body>',
        _html_report_branding_header(header, "Police Forensics Investigation Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append('<h2 id="sec-admin-info">Administrative Information</h2><table>')
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Created</th><td colspan="3">{esc(str(header["created_at"]))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')

    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_narrative_block('Case Background & Scope', header.get('objectives'), 'sec-background-scope'))

    parts.append(f'<h2 id="sec-evidence-coc">Evidence Collection &amp; Chain of Custody</h2>')
    if events:
        parts.append(_html_evidence_inventory_table(events, title="Itemized Evidence & Integrity Hashing"))
    parts.append(_html_audit_trail_block(audit_entries, title="Chain of Custody / Activity Log"))

    parts.append(_html_methodology_tools(events, anchor_id='sec-methodology'))

    parts.append(f'<h2 id="sec-findings">Detailed Findings &amp; Analysis</h2>')
    parts.append(_html_timeline_table(case_notes, title="Chronological Timeline of Events"))
    parts.append(_html_narrative_block('Artifact Analysis', header.get('findings_summary')))

    parts.append(f'<h2 id="sec-conclusion">Conclusion &amp; Summary</h2>')
    parts.append(_html_narrative_block('Conclusion', header.get('conclusion')))
    parts.append(_html_narrative_block('Recommendations', header.get('recommendations_next_steps')))

    parts.append(_html_signoff(header['examiner'], anchor_id='sec-signoff'))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_caseuco(header, events, urls, files, audit_entries, case_notes, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    """HTML counterpart to _build_pdf_report_caseuco - same fixed section
    list, same reused data sources, same disclosed role/provenance
    simplifications, see that function's docstring.

    Deliberate departure from DFIR/Police's HTML builders: reuses
    _html_case_info_block() wholesale for "Investigation Overview" instead
    of hand-inlining a stripped-down case-info table like they do - this
    template's Investigation Overview benefits from that helper's existing
    Notes row (investigation description) and Evidence Items count, and
    reusing it outright is less code than a third hand-inlined copy of the
    same loop."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-investigation-overview', 'Investigation Overview'),
        ('sec-focus-scope', 'Investigation Focus &amp; Scope'),
        ('sec-exec-summary', 'Executive Summary'),
        ('sec-observable-objects', 'Observable Objects (Digital Evidence)'),
        ('sec-investigative-actions', 'Investigative Actions'),
        ('sec-analysis-findings', 'Analysis &amp; Analytic Results (Case Notes)'),
        ('sec-relevant-findings', 'Relevant Findings'),
        ('sec-tools', 'Tools &amp; Configured Tools'),
        ('sec-geolocation', 'Geolocation / Location Evidence'),
        ('sec-conclusion', 'Conclusion'),
        ('sec-limitations', 'Limitations &amp; Data Handling Markings'),
        ('sec-provenance-coc', 'Provenance Record / Chain of Custody'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits (Evidence Provenance Records)'))
    toc_entries.append(('sec-signoff', 'Sign-off &amp; Signatures'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    # Only inlined when this export actually has real placemark data to
    # render - every export that doesn't use it stays exactly as small as
    # before, matching _build_html_report_standard's own condition.
    needs_leaflet = bool(geo_data)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>CASE/UCO Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        _html_leaflet_assets_block() if needs_leaflet else '',
        '</head><body>',
        _html_report_branding_header(header, "CASE/UCO Cyber-Investigation Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append(_html_case_info_block(header, len(events), anchor_id='sec-investigation-overview', title="Investigation Overview"))
    parts.append(_html_narrative_block('Investigation Focus & Scope', header.get('objectives'), 'sec-focus-scope'))
    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_evidence_inventory_table(events, title="Observable Objects (Digital Evidence)", anchor_id='sec-observable-objects'))
    parts.append(f'<h2 id="sec-investigative-actions">Investigative Actions</h2>')
    parts.append(_html_acquisition_method(events, job_fields))
    parts.append(_html_case_notes_block(case_notes, anchor_id='sec-analysis-findings', title="Analysis & Analytic Results (Case Notes)", exhibit_numbers=exhibit_numbers))
    parts.append(_html_narrative_block('Relevant Findings', header.get('findings_summary'), 'sec-relevant-findings'))
    parts.append(_html_methodology_tools(events, anchor_id='sec-tools'))
    parts.append(_html_geolocation_block(geo_data or [], title="Geolocation / Location Evidence", anchor_id='sec-geolocation'))
    parts.append(_html_narrative_block('Conclusion', header.get('conclusion'), 'sec-conclusion'))
    parts.append(_html_narrative_block('Limitations & Data Handling Markings', header.get('limitations'), 'sec-limitations'))
    parts.append(_html_audit_trail_block(audit_entries, anchor_id='sec-provenance-coc', title="Provenance Record / Chain of Custody"))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', title="Exhibits (Evidence Provenance Records)", captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append(_html_signoff(header['examiner'], anchor_id='sec-signoff'))

    parts.append('</body></html>')
    return ''.join(parts)

@app.route('/api/export_report', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def export_report():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"error": "Report file not found or outside the permitted evidence directory."}), 404

    fmt = req.get('format', 'pdf')
    if fmt not in ('pdf', 'html'):
        return jsonify({"error": "format must be 'pdf' or 'html'."}), 400

    cfg = load_runtime_config()
    report_defaults = cfg.get('report_defaults', {})
    requested_event_ids = req.get('event_ids')
    attachment_selection = req.get('attachment_selection')

    # Falls back to the station's configured default template the same way
    # sections/job_fields below fall back to their own station defaults. A
    # custom:<id> reference that doesn't resolve is a hard error (400), not
    # a silent substitution - re-rendering a report under a materially
    # different structure than what was explicitly requested is exactly the
    # kind of surprise this app avoids elsewhere (case-folder collisions are
    # a 409, never an auto-rename).
    template_value = req.get('template') or report_defaults.get('template') or 'standard'
    try:
        template, custom_record = _resolve_template_ref(template_value, cfg)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # sections/job_fields (the Export modal's checkboxes / station defaults)
    # only ever apply to the 'standard' template - reading them regardless
    # of which template is selected let stale, CSS-hidden-but-still-checked
    # checkbox state leak into a custom-template export. DFIR/Police never
    # used these at all; 'custom' sources its own section list/job_fields
    # exclusively from the saved template record instead.
    if template == 'standard':
        sections = req.get('sections') or report_defaults.get('sections') or {}
        job_fields = req.get('job_fields') or report_defaults.get('job_fields') or {}
    elif template == 'custom':
        sections = None
        job_fields = custom_record.get('job_fields') or {}
    else:
        sections = None
        job_fields = {}

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Could not read report: {e}"}), 500

    # Custom-field *definitions* are station-wide; a case's custom-field
    # *values* live on the case record itself (top-level for consolidated,
    # nested under case_metadata for legacy - same split every other
    # per-case field already uses). Join the two here into simple
    # label/value pairs so the drawing functions don't need to know
    # anything about where definitions are stored - empty values are
    # skipped rather than rendered blank.
    field_defs = get_custom_case_fields()

    def _custom_field_pairs(values_dict):
        values_dict = values_dict or {}
        return [
            {"label": f["label"], "value": values_dict[f["key"]]}
            for f in field_defs
            if values_dict.get(f["key"])
        ]

    # A consolidated case file (has "events") exposes a case-level header +
    # a filterable list of job events; a legacy single-job report (no
    # "events" key - either never migrated, or a genuine no-case ad-hoc job)
    # is always treated as its own single, always-included event.
    if isinstance(data.get('events'), list):
        all_events = data['events']
        if requested_event_ids:
            events = [e for e in all_events if e.get('event_id') in requested_event_ids]
        else:
            events = all_events
        header = {
            "case_number": data.get('case_number', 'N/A'),
            "examiner": data.get('examiner', 'N/A'),
            "notes": data.get('notes', ''),
            "created_at": data.get('created_at', 'N/A'),
            "custom_fields": _custom_field_pairs(data.get('custom_fields')),
            "executive_summary": data.get('executive_summary', ''),
            "objectives": data.get('objectives', ''),
            "findings_summary": data.get('findings_summary', ''),
            "limitations": data.get('limitations', ''),
            "conclusion": data.get('conclusion', ''),
            "iocs": data.get('iocs', ''),
            "recommendations_next_steps": data.get('recommendations_next_steps', ''),
        }
        attachments = data.get('attachments', {})
    else:
        events = [data]
        meta = data.get('case_metadata', {})
        header = {
            "case_number": meta.get('case_number', 'N/A'),
            "examiner": meta.get('examiner', 'N/A'),
            "notes": meta.get('notes', ''),
            "created_at": data.get('timestamp_start', 'N/A'),
            "custom_fields": _custom_field_pairs(meta.get('custom_fields')),
            "executive_summary": meta.get('executive_summary', ''),
            "objectives": meta.get('objectives', ''),
            "findings_summary": meta.get('findings_summary', ''),
            "limitations": meta.get('limitations', ''),
            "conclusion": meta.get('conclusion', ''),
            "iocs": meta.get('iocs', ''),
            "recommendations_next_steps": meta.get('recommendations_next_steps', ''),
        }
        attachments = data.get('attachments', {})

    # case_notes is top-level in both schemas (same precedent as
    # attachments) - not nested under case_metadata for the legacy branch.
    case_notes = data.get('case_notes', [])

    # Examiner-entered per-attachment captions, keyed by the same path string
    # used in attachments['files'] - looked up at render time regardless of
    # whether a file came from the full explicit list or a per-export
    # checked subset (attachment_selection.files below), since it's a
    # superset lookup table either way.
    captions = attachments.get('file_captions', {})

    header["branding"] = report_defaults.get('branding', {})

    # attachment_selection lets the export modal pick a subset of
    # explicitly-attached files/URLs plus any extra files discovered in the
    # case folder (via /api/cases/discover_files) that weren't necessarily
    # added through the "Add File Attachment" flow. If the caller doesn't
    # supply one, fall back to everything in the report's own attachments
    # dict (today's behavior, and the sane default for non-UI callers).
    if attachment_selection is not None:
        sel_urls = attachment_selection.get('urls') or []
        sel_files = attachment_selection.get('files') or []
    else:
        sel_urls = attachments.get('reference_urls', [])
        sel_files = attachments.get('files', [])
        if not sel_files and attachments.get('image_path'):
            sel_files = [attachments.get('image_path')]

    # DFIR/Police always include an Audit Trail section (part of their
    # fixed structure); for 'standard'/'custom', consult the same resolved
    # block list the draw loop itself will use, so this can never drift
    # from what the export actually renders.
    resolved_sections = None
    if template in ('standard', 'custom'):
        mode = 'legacy' if template == 'standard' else 'custom'
        resolved_sections = _resolve_section_order(mode, sections, custom_record, len(events))
        needs_audit_trail = any(e['key'] == 'audit_trail' for e in resolved_sections)
    else:
        needs_audit_trail = True

    audit_entries = []
    if needs_audit_trail and header['case_number'] not in (None, '', 'N/A'):
        audit_entries = _case_history_entries(header['case_number'], limit=500)

    # Unified evidence-item enrichment - tags and persisted analysis results
    # for whichever files this particular export actually includes
    # (sel_files), plus exhibit numbers derived from the case's FULL
    # attachments list (not sel_files) so a number stays stable regardless
    # of which subset any one export selects - see the matching comment on
    # _draw_pdf_attachments/_html_exhibits_block. case_folder here is just
    # this report's own containing directory; both helpers gracefully
    # return {} if it isn't actually a real, indexed, consolidated case.
    case_folder = os.path.dirname(report_file)
    tags_by_path = _tags_for_paths(case_folder, sel_files)
    analysis_by_path = _analysis_results_for_paths(case_folder, sel_files)
    exhibit_numbers = {p: i for i, p in enumerate(attachments.get('files', []), start=1)}

    # Geolocation section data (KML files + parsed placemarks) - walked/
    # parsed when the section is either always-on (the caseuco template,
    # which has no opt-out checkbox - Geolocation is a fixed part of its
    # structure, mapping onto the ontology's Location module) or reachable
    # and selected (standard/custom templates via their checkbox; DFIR/
    # Police never include it at all, matching their fixed structure), same
    # "compute once before dispatch" pattern as tags_by_path/
    # analysis_by_path/exhibit_numbers above.
    geo_data = None
    if template == 'caseuco' or (resolved_sections is not None and any(e['key'] == 'geolocation' for e in resolved_sections)):
        geo_data = _collect_case_geolocation(case_folder, attachments.get('files', []))

    # preview=True renders the exact same document a real export would
    # produce, but returns it inline (no Content-Disposition, so a browser
    # shows it in an iframe rather than downloading it) and skips writing
    # anything to disk - no out_path write, no .sha256 sidecar. Every other
    # part of this route above (template resolution, sections, event
    # filtering, attachment selection, tags/analysis/exhibit numbers,
    # geolocation data) is identical for both modes.
    preview = bool(req.get('preview'))

    try:
        pdf_buf = io.BytesIO() if fmt == 'pdf' else None
        html_content = None

        if template == 'dfir':
            if fmt == 'html':
                html_content = _build_html_report_dfir(header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                                         tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
            else:
                _build_pdf_report_dfir(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                        tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
        elif template == 'police':
            if fmt == 'html':
                html_content = _build_html_report_police(header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
            else:
                _build_pdf_report_police(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                          tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
        elif template == 'caseuco':
            if fmt == 'html':
                html_content = _build_html_report_caseuco(header, events, sel_urls, sel_files, audit_entries, case_notes, job_fields, captions=captions,
                                                            tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)
            else:
                _build_pdf_report_caseuco(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, job_fields, captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)
        elif fmt == 'html':
            html_content = _build_html_report_standard(header, events, sel_urls, sel_files, audit_entries, case_notes, resolved_sections, job_fields, captions=captions,
                                                         tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)
        else:
            _build_pdf_report_standard(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, resolved_sections, job_fields, captions=captions,
                                        tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)

        if fmt == 'html':
            content_bytes = html_content.encode('utf-8')
            mimetype = 'text/html; charset=utf-8'
        else:
            content_bytes = pdf_buf.getvalue()
            mimetype = 'application/pdf'

        if preview:
            return Response(content_bytes, mimetype=mimetype)

        out_path = report_file.rsplit('.json', 1)[0] + ('.html' if fmt == 'html' else '.pdf')
        with open(out_path, 'wb') as f:
            f.write(content_bytes)

        # A report-level integrity hash - computed over the exported file's
        # actual bytes (already in memory, the same bytes just written to
        # disk above), not the source case JSON, so it verifies the specific
        # PDF/HTML artifact an examiner hands off, not just the data behind
        # it. Written as a standard sha256sum-format sidecar file (so
        # `sha256sum -c` works directly against it later) and also returned
        # as a response header so the examiner sees it immediately, not only
        # by going and finding the sidecar file afterward.
        digest = hashlib.sha256(content_bytes).hexdigest()
        with open(out_path + '.sha256', 'w') as f:
            f.write(f"{digest}  {os.path.basename(out_path)}\n")

        resp = send_file(out_path, as_attachment=True)
        resp.headers['X-Report-Sha256'] = digest
        return resp
    except Exception as e:
        return jsonify({"error": f"Report export failed: {str(e)}"}), 500

# Replay saved auto-mount shares once per process start - module-level (not
# inside the __main__ guard below) so this also runs under gunicorn, which
# imports this module rather than executing it as __main__. Backgrounded so
# a slow/unreachable share can't delay the app from becoming ready; harmless
# no-op when no auto-mount shares are configured (the common case).
threading.Thread(target=attempt_startup_auto_mounts, daemon=True).start()

if __name__ == '__main__':
    # This dev-mode entrypoint is only used for `python3 app.py` directly.
    # The production installer (install.py) runs this app under gunicorn
    # instead - see install.py / README.md for how to add TLS there
    # (reverse proxy, or gunicorn's --certfile/--keyfile).
    tls_cert = os.environ.get('FORENSIC_TLS_CERT')
    tls_key = os.environ.get('FORENSIC_TLS_KEY')
    ssl_context = (tls_cert, tls_key) if tls_cert and tls_key else None

    if not ssl_context:
        print("[SECURITY WARNING] No FORENSIC_TLS_CERT/FORENSIC_TLS_KEY configured - "
              "serving plain HTTP. Basic Auth credentials will be sent unencrypted.")

    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
