import os
import re
import io
import csv
import html
import base64
import sys
import uuid
import pwd
import glob
import hmac
import time
import json
import fcntl
import signal
import psutil
import pytsk3
import shutil
import hashlib
import tempfile
import subprocess
import threading
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response, send_file

app = Flask(__name__)

# Authentication Config
ADMIN_USER = os.environ.get('FORENSIC_USER', 'admin')
ADMIN_PASS = os.environ.get('FORENSIC_PASS', 'forensics')

if ADMIN_USER == 'admin' and ADMIN_PASS == 'forensics':
    print("[SECURITY WARNING] FORENSIC_USER/FORENSIC_PASS are still set to the default "
          "admin/forensics credentials. Set unique values via environment variables "
          "(see install.py / the generated systemd unit) before deploying this on any network.")

# INSTALL_DIR mirrors install.py's INSTALL_DIR so this stays correct regardless
# of which system user the installer's service account ends up being.
INSTALL_DIR = os.environ.get('FORENSIC_INSTALL_DIR', '/opt/pi-forensics')
HISTORY_FILE = os.path.join(INSTALL_DIR, "mount_history.json")

# scalpel ships with every file signature disabled in its stock config -
# this curated one (jpg/png/gif/pdf/zip, common formats) is written to
# INSTALL_DIR by install.py, so scalpel actually recovers something by
# default rather than silently finding nothing.
SCALPEL_CONF_PATH = os.path.join(INSTALL_DIR, "scalpel.conf")

# mvt-ios/mvt-android are pip console-scripts (see requirements.txt),
# installed into the same Python environment app.py itself runs in - not on
# system PATH like every other tool this app shells out to (those are all
# apt packages). Resolve their path from sys.executable rather than a bare
# command name, so this works whether running under the venv (production)
# or a plain `python3 app.py` dev invocation.
MVT_BIN_DIR = os.path.dirname(sys.executable)
MVT_IOS_BIN = os.path.join(MVT_BIN_DIR, "mvt-ios")
MVT_ANDROID_BIN = os.path.join(MVT_BIN_DIR, "mvt-android")

# Password changes made from the Advanced Settings tab are persisted here
# (0600, owned by the service account) so they survive a restart without
# requiring the examiner to edit the systemd unit. Falls back to
# FORENSIC_PASS above if this file doesn't exist yet.
RUNTIME_CONFIG_FILE = os.path.join(INSTALL_DIR, "runtime_config.json")
runtime_config_lock = threading.Lock()

# Append-only chain-of-custody log: one JSON object per line, covering
# acquisitions, file deletes/copies, hash verifications, PhotoRec runs,
# image extractions, and report edits. NOTE on what this can and can't
# attest to: this station has a single shared login (see FORENSIC_USER/
# FORENSIC_PASS above), not per-examiner accounts, so entries record what
# happened and when, plus the client IP - not reliably *who*, beyond
# whoever had the shared credentials (or physical kiosk access, if
# FORENSIC_KIOSK_AUTH_BYPASS is on). If your process needs per-examiner
# attribution, that requires separate accounts this project doesn't have.
COC_LOG_FILE = os.path.join(INSTALL_DIR, "chain_of_custody.log")
coc_log_lock = threading.Lock()

def log_chain_of_custody(action, details=None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details or {},
        "source_ip": request.headers.get('X-Real-IP', request.remote_addr) if request else None,
    }
    with coc_log_lock:
        try:
            os.makedirs(os.path.dirname(COC_LOG_FILE), exist_ok=True)
            with open(COC_LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Error writing chain-of-custody log: {e}")

def load_runtime_config():
    with runtime_config_lock:
        if os.path.exists(RUNTIME_CONFIG_FILE):
            try:
                with open(RUNTIME_CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading runtime config: {e}")
        return {}

def save_runtime_config(cfg):
    with runtime_config_lock:
        try:
            with open(RUNTIME_CONFIG_FILE, 'w') as f:
                json.dump(cfg, f, indent=2)
            os.chmod(RUNTIME_CONFIG_FILE, 0o600)
        except Exception as e:
            print(f"Error saving runtime config: {e}")

def get_active_admin_pass():
    return load_runtime_config().get('pass', ADMIN_PASS)

# Root directory that all file-explorer / report / attachment / imaging-destination
# endpoints are sandboxed to. Nothing outside this tree can be browsed, read,
# written, or deleted via the API, regardless of what path a client sends.
EVIDENCE_ROOT = os.path.realpath(os.environ.get('FORENSIC_ROOT', '/mnt'))

# Guards access to the shared current_job / active_proc state, which is
# written from the background acquisition thread and read/written from
# request-handling threads.
job_lock = threading.Lock()

# --- Basic brute-force throttling for Basic Auth ---
# In-memory only (resets on restart) and keyed by source IP, so it's not a
# substitute for a real WAF/fail2ban setup on a network you don't control -
# but it closes the "unlimited guesses" gap in the meantime.
auth_fail_lock = threading.Lock()
auth_fail_tracker = {}  # ip -> {"count": int, "locked_until": float|None}
MAX_AUTH_FAILURES = 5
LOCKOUT_SECONDS = 300

# Skips login for the physical kiosk touchscreen only (see requires_auth and
# is_local_kiosk_request below) - remote/LAN/WiFi access always still
# requires authentication regardless of this setting. Defaults on since a
# working on-screen keyboard for the native Basic Auth prompt has proven
# unreliable in this project's Wayland/labwc kiosk environment. Set
# FORENSIC_KIOSK_AUTH_BYPASS=0 to require login locally too.
KIOSK_AUTH_BYPASS_ENABLED = os.environ.get('FORENSIC_KIOSK_AUTH_BYPASS', '1') != '0'
if KIOSK_AUTH_BYPASS_ENABLED:
    print("[SECURITY] Local kiosk login is bypassed (FORENSIC_KIOSK_AUTH_BYPASS=1, the default). "
          "Anyone with physical access to the touchscreen has full control of this station without "
          "a password. Remote/LAN access still requires login. Set FORENSIC_KIOSK_AUTH_BYPASS=0 "
          "in the systemd unit to disable this.")

ALLOWED_HASH_ALGOS = {'md5', 'sha1', 'sha256'}

def update_job(**kwargs):
    """Atomically update one or more fields of the shared current_job dict."""
    with job_lock:
        current_job.update(kwargs)

def snapshot_job():
    """Return a consistent point-in-time copy of current_job for reading."""
    with job_lock:
        return dict(current_job)

# Global State for Live Acquisition Job
current_job = {
    "active": False,
    "format": "dd",
    "progress_percent": 0.0,
    "speed_mbps": 0.0,
    "transferred_bytes": 0,
    "total_bytes": 0,
    "status": "IDLE",
    "log": "[System initialized and idle. Ready for disk acquisition job.]"
}

active_proc = None
last_net_check = {"time": time.time(), "bytes_sent": 0, "bytes_recv": 0}

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
def check_auth(username, password):
    # Constant-time comparison to avoid leaking credential info via timing.
    user_ok = hmac.compare_digest(username or '', ADMIN_USER)
    pass_ok = hmac.compare_digest(password or '', get_active_admin_pass())
    return user_ok and pass_ok

def is_local_kiosk_request():
    """
    True if this request is coming from the Pi's own local kiosk session,
    not a remote LAN/WiFi client. The kiosk's chromium always talks to
    gunicorn directly over loopback (http://127.0.0.1:5000), regardless of
    whether TLS/nginx is set up - see install.py's autostart script.

    When nginx is in front of gunicorn (TLS setup), gunicorn only ever sees
    connections from nginx itself (also loopback), so a naive remote_addr
    check would misidentify every remote client as local. nginx forwards
    the real client IP via X-Real-IP (see nginx/pi-forensics.conf), so that
    takes priority when present.
    """
    real_ip = request.headers.get('X-Real-IP', request.remote_addr)
    return real_ip in ('127.0.0.1', '::1', 'localhost')

def authenticate():
    return Response(
        'Authentication required to access ARM Forensic Station.\n',
        401,
        {'WWW-Authenticate': 'Basic realm="Forensic Station Login Required"'}
    )

def _is_locked_out(client_key):
    with auth_fail_lock:
        entry = auth_fail_tracker.get(client_key)
        return bool(entry and entry["locked_until"] and time.time() < entry["locked_until"])

def _record_auth_failure(client_key):
    with auth_fail_lock:
        entry = auth_fail_tracker.get(client_key, {"count": 0, "locked_until": None})
        entry["count"] += 1
        if entry["count"] >= MAX_AUTH_FAILURES:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
        auth_fail_tracker[client_key] = entry

def _record_auth_success(client_key):
    with auth_fail_lock:
        auth_fail_tracker.pop(client_key, None)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Physical-kiosk-only auth bypass. Deliberately narrow: this only
        # matches genuine loopback origin with no X-Real-IP header (see
        # is_local_kiosk_request() above) - a remote client proxied through
        # nginx always has X-Real-IP set to their real address, so this does
        # NOT bypass auth for LAN/WiFi/remote access, which stays fully
        # authenticated exactly as before. The remaining risk is narrow but
        # real: anyone with physical access to the touchscreen gets full
        # control of the station, including destructive actions in Advanced
        # Settings (those still have confirmation dialogs). Set
        # FORENSIC_KIOSK_AUTH_BYPASS=0 to disable this and require login
        # locally too.
        if KIOSK_AUTH_BYPASS_ENABLED and is_local_kiosk_request():
            return f(*args, **kwargs)

        client_key = request.remote_addr or 'unknown'

        if _is_locked_out(client_key):
            return Response(
                'Too many failed login attempts. Try again in a few minutes.\n',
                429,
                {'Retry-After': str(LOCKOUT_SECONDS)}
            )

        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            _record_auth_failure(client_key)
            return authenticate()

        _record_auth_success(client_key)
        return f(*args, **kwargs)
    return decorated

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

# --- Block Device Path Validation ---
_DEVICE_RE = re.compile(r'^/dev/(sd[a-z]|nvme\d+n\d+|mmcblk\d+)$')

def is_valid_block_device(path_str):
    """Whitelist check for whole-disk device paths (no partitions, no shell metacharacters)."""
    return bool(path_str) and bool(_DEVICE_RE.match(path_str))

# --- Case Folder Name Sanitization ---
_CASE_SLUG_INVALID_RE = re.compile(r'[^A-Za-z0-9_-]+')

def sanitize_case_slug(raw):
    """
    Turn an examiner-typed case number into a filesystem-safe folder name.
    Whitelist-based (like _DEVICE_RE above) rather than blacklisting bad
    characters, so this can never be tricked into producing '..' or an
    absolute-path-looking result. Returns None if nothing usable is left.
    """
    if not raw:
        return None
    slug = _CASE_SLUG_INVALID_RE.sub('_', raw.strip())
    slug = re.sub(r'_+', '_', slug).strip('_')
    return slug[:80] or None

_SERVICE_ACCOUNT_NAME = pwd.getpwuid(os.getuid()).pw_name

def reclaim_ownership(path):
    """
    dc3dd/dcfldd/dd/ewfacquire/photorec/ddrescue all run via sudo (root) to
    get raw read access to the source device - their output files land
    owned by root as a side effect. Without handing ownership back, every
    later operation on those files (delete, hash verify, copy, ExifTool,
    etc.) run as this unprivileged service account would fail with
    permission denied. Safe to grant broadly in sudoers: the target
    user:group is fixed at install time, not attacker-controllable, so this
    can only ever hand a file back to the unprivileged account, never
    escalate ownership to root or anyone else.
    """
    if not path or not os.path.exists(path):
        return
    try:
        subprocess.run(['sudo', '/bin/chown', '-R', _SERVICE_ACCOUNT_NAME, path], capture_output=True, timeout=30)
        subprocess.run(['sudo', '/bin/chgrp', '-R', _SERVICE_ACCOUNT_NAME, path], capture_output=True, timeout=30)
    except Exception as e:
        print(f"Warning: could not reclaim ownership of {path}: {e}")

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

# --- Quick Triage Scan: pattern definitions ---
# Deliberately built in-house rather than depending on bulk_extractor,
# which isn't in Debian's mainline archive (see README) - this needs no
# external tool at all, so it can never hit a "package not found" wall on
# any system this app runs on. Patterns are intentionally loose (especially
# the credit-card one) - a triage scan is meant to over-flag for a human to
# review, not to be a precise validator.
TRIAGE_PATTERNS = {
    "emails": re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    "urls": re.compile(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+'),
    "ip_addresses": re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'),
    "credit_card_numbers": re.compile(rb'\b(?:\d[ -]?){13,19}\b'),
    "phone_numbers": re.compile(rb'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
}
TRIAGE_MAX_MATCHES_PER_CATEGORY = 50000  # protects memory on very large images

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

# --- Direct Real-time Asynchronous Execution Engine ---
def _stream_subprocess(cmd, on_line, on_poll=None, poll_interval=2.0, cwd=None, stdin_yes=False):
    """
    Launch cmd, non-blockingly stream stdout+stderr line by line (ANSI-
    stripped) into on_line(clean_line), and return the finished Popen
    object. Sets the module-level active_proc so /api/stop_imaging can
    kill it. Shared by execution_worker (single-phase formats),
    execution_worker_aff (raw acquisition + AFF conversion phases), and
    the mobile workers.

    If on_poll is given, it's called every poll_interval seconds
    regardless of stdout activity - some tools (idevicebackup2, adb
    backup) go long stretches with no output while still working, so
    line-triggered progress alone isn't enough to show the job is alive.

    cwd: run the process in this working directory - needed for tools
    like extundelete that write output relative to their cwd rather than
    accepting an explicit output-path flag.

    stdin_yes: pipe "y\\n" to the process immediately, then close stdin -
    needed for extundelete, which can block on an interactive
    confirmation prompt about filesystem safety warnings. Without an
    explicit pipe here, stdin would be whatever the parent service
    process has (typically /dev/null under systemd), which doesn't
    reliably answer that prompt.
    """
    global active_proc
    active_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin_yes else None,
        text=False,
        bufsize=0,
        cwd=cwd,
        preexec_fn=os.setsid
    )

    if stdin_yes:
        try:
            active_proc.stdin.write(b'y\n')
            active_proc.stdin.close()
        except Exception:
            pass

    fd = active_proc.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    byte_buffer = b""
    last_poll = time.time()

    while True:
        time.sleep(0.1)
        try:
            raw_chunk = os.read(fd, 1024)
            if raw_chunk:
                byte_buffer += raw_chunk

                while b'\r' in byte_buffer or b'\n' in byte_buffer:
                    r_idx = byte_buffer.find(b'\r')
                    n_idx = byte_buffer.find(b'\n')
                    indices = [i for i in (r_idx, n_idx) if i != -1]
                    cut_idx = min(indices)

                    line_bytes = byte_buffer[:cut_idx]
                    byte_buffer = byte_buffer[cut_idx + 1:]

                    line_str = line_bytes.decode('utf-8', errors='ignore')
                    clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line_str).replace('\r', '').strip()
                    if clean_line:
                        on_line(clean_line)

            elif active_proc.poll() is not None:
                break
        except (OSError, IOError):
            pass

        if on_poll and (time.time() - last_poll) >= poll_interval:
            try:
                on_poll()
            except Exception:
                pass
            last_poll = time.time()

    active_proc.wait()
    return active_proc

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
class CaseEventTarget:
    """Marks a report write as 'append/update one event inside a case's
    consolidated file' rather than 'overwrite a standalone _report.json'."""
    __slots__ = ("case_file", "event_id")
    def __init__(self, case_file, event_id):
        self.case_file = case_file
        self.event_id = event_id

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

def _read_case_file(case_file):
    try:
        with open(case_file, 'r') as f:
            return json.load(f)
    except Exception:
        return {"schema_version": 1, "events": [], "attachments": {"files": [], "reference_urls": []}}

def _write_case_file(case_file, case_record):
    with open(case_file, 'w') as f:
        json.dump(case_record, f, indent=2)

def _case_upsert_event(case_file, event_id, event_data):
    """Replaces the event matching event_id if present, else appends it -
    this is what makes a job's start-write and later complete-write update
    the SAME array entry instead of appending a duplicate."""
    case_record = _read_case_file(case_file)
    events = case_record.setdefault("events", [])
    events[:] = [e for e in events if e.get("event_id") != event_id]
    payload = dict(event_data)
    payload["event_id"] = event_id
    events.append(payload)
    case_record["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_case_file(case_file, case_record)

def build_report_target(dest_path, legacy_dir, base_name):
    """Returns a CaseEventTarget if `dest_path` is an active case folder,
    else the plain flat-file path this route would have used before this
    change existed (legacy_dir is job_dest_dir for tools that write into
    their own subfolder, dest_path itself for the rest)."""
    case_file = case_consolidated_path(dest_path)
    if case_file:
        return CaseEventTarget(case_file, uuid.uuid4().hex)
    return os.path.join(legacy_dir, f"{base_name}_report.json")

def write_initial_report(report_target, report_data):
    """First write at job start (status IN_PROGRESS) - mirrors what every
    route used to do with a bare open()/json.dump() against its own file."""
    try:
        if isinstance(report_target, CaseEventTarget):
            _case_upsert_event(report_target.case_file, report_target.event_id, report_data)
        else:
            with open(report_target, 'w') as f:
                json.dump(report_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not write report JSON: {e}")

def _write_report(report_target, report_data, append_log):
    """Second write at job completion (status COMPLETED/FAILED/etc) - called
    from inside the worker threads, unchanged at every call site; only the
    type of report_target (flat path vs CaseEventTarget) changed upstream."""
    try:
        if isinstance(report_target, CaseEventTarget):
            _case_upsert_event(report_target.case_file, report_target.event_id, report_data)
            append_log(f"[+] Forensic case report updated: {report_target.case_file} (event {report_target.event_id[:8]})")
        else:
            with open(report_target, 'w') as f:
                json.dump(report_data, f, indent=2)
            append_log(f"[+] Forensic case report updated: {report_target}")
    except Exception as e:
        append_log(f"[-] Warning: Failed updating report JSON: {e}")

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
                     "ios_version": "Unknown", "serial": "Unknown", "trusted": True}
            try:
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
            devices.append({
                "serial": serial,
                "state": state,  # 'device' = authorized, 'unauthorized' = waiting on RSA prompt, 'offline' = other
                "model": model,
                "authorized": (state == "device")
            })
    except Exception as e:
        print(f"Error listing Android devices: {e}")
    return devices

def execution_worker(cmd, fmt, total_bytes, out_file, report_file_path, report_data, hashes=None):
    global current_job, active_proc
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
        active_proc = None

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
    global current_job, active_proc
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
        active_proc = None

def execution_worker_ios_backup(udid, dest_dir, encrypt_password, report_file_path, report_data):
    """
    idevicebackup2 gives per-file status lines but no global progress
    percentage (open upstream request, unresolved) - so progress here is
    shown as bytes-on-disk (polled from the backup folder), not a percent.
    """
    global current_job, active_proc
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
        active_proc = None

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
    global current_job, active_proc
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
        active_proc = None

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
    global current_job, active_proc
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
        active_proc = None

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
    global current_job, active_proc
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
        active_proc = None

def execution_worker_foremost(source, dest_dir, report_file_path, report_data):
    """
    foremost - signature-based file carving, an alternative to PhotoRec.
    Older and narrower in supported types than PhotoRec, but sometimes
    faster for the common formats it does support.
    """
    global current_job, active_proc
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
        active_proc = None

def execution_worker_scalpel(source, dest_dir, report_file_path, report_data):
    """
    scalpel - signature-based file carving, another PhotoRec alternative,
    multithreaded so sometimes faster on larger images. Ships with every
    file signature disabled by default in its stock config - this uses a
    curated config file installed alongside this app (SCALPEL_CONF_PATH)
    covering common formats (jpg/png/gif/pdf/zip) rather than depending on
    the stock config, which would silently recover nothing if left as-is.
    """
    global current_job, active_proc
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
        active_proc = None

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
    global current_job, active_proc
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
        active_proc = None

# --- Web Routes & API Endpoints ---
@app.route('/')
@requires_auth
def index():
    return render_template('index.html', is_local_kiosk=is_local_kiosk_request())

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

@app.route('/api/mount_network', methods=['POST'])
@requires_auth
def mount_network():
    req = request.get_json() or {}
    protocol = req.get('protocol', 'smb').lower()
    host = req.get('host', '').strip()
    share = req.get('share', '').strip()
    user = req.get('user', '').strip()
    password = req.get('pass', '').strip()

    if not host or not share:
        return jsonify({"success": False, "error": "Server IP and Share path are required."}), 400

    share_path = f"/{share.lstrip('/')}"
    safe_folder_name = share_path.replace('/', '_').strip('_')
    mount_point = f"/mnt/network_{protocol}_{safe_folder_name}"

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
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            cmd_v4 = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,soft,timeo=30,retrans=2,vers=4', nfs_source, mount_point]
            res_v4 = subprocess.run(cmd_v4, capture_output=True, text=True)

            if res_v4.returncode == 0:
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            return jsonify({"success": False, "error": f"NFS Mount Failed: {res_v4.stderr.strip() or res.stderr.strip()}"}), 500

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
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            return jsonify({"success": False, "error": f"SMB Mount Failed: {res_smb.stderr.strip()}"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/toggle_write_block', methods=['POST'])
@requires_auth
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

@app.route('/api/start_imaging', methods=['POST'])
@requires_auth
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
    
    compression = req.get('compression', 'fast')
    split_size = req.get('split_size', '2000M')

    VALID_FORMATS = {'dd', 'raw', 'dcfldd', 'plain_dd', 'e01', 'aff'}
    if fmt not in VALID_FORMATS:
        update_job(active=False)
        return jsonify({"error": f"Unrecognized format '{fmt}'. Use one of {sorted(VALID_FORMATS)}."}), 400

    if not is_valid_block_device(source) or not os.path.exists(source):
        update_job(active=False)
        return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400

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
    try:
        res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    dest_disk_usage = shutil.disk_usage(dest_path)
    if total_bytes > 0 and dest_disk_usage.free < total_bytes:
        free_gb = round(dest_disk_usage.free / (1024**3), 2)
        required_gb = round(total_bytes / (1024**3), 2)
        update_job(active=False)
        return jsonify({"error": f"Pre-flight storage check failed: Destination has only {free_gb} GB free, but source requires {required_gb} GB."}), 400

    smart_data = {}
    try:
        res_smart = subprocess.run(['sudo', 'smartctl', '-a', '-j', source], capture_output=True, text=True)
        if res_smart.stdout:
            smart_data = json.loads(res_smart.stdout)
    except Exception:
        pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    vendor_model = f"{family} ({model})" if (family and family.lower() not in model.lower()) else model

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
        "device_path": source,
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
            "iflag=direct",
        ]
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
            "compression": compression if fmt == 'e01' else 'N/A',
            "split_size": split_size if fmt == 'e01' else 'N/A',
            "requested_hashes": hashes,
            "execution_command": " ".join(cmd),
            **({"raw_image_retained": None} if fmt == 'aff' else {})
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

    log_chain_of_custody("acquisition_start", {"format": fmt, "source": source, "destination": dest_path})
    return jsonify({"success": True, "message": "Acquisition started."})

@app.route('/api/ddrescue/inspect_map', methods=['POST'])
@requires_auth
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
            "mapfile": map_file,
            "strategy": strategy,
            "retry_passes": retry_passes,
            "direct_mode": direct_mode,
            "execution_command": " ".join(cmd)
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
    global current_job, active_proc
    if current_job["active"]:
        try:
            if active_proc and active_proc.poll() is None:
                os.killpg(os.getpgid(active_proc.pid), signal.SIGKILL)
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

@app.route('/api/system/tool_versions', methods=['GET'])
@requires_auth
def get_tool_versions():
    results = []
    for entry in TOOL_VERSION_COMMANDS:
        name, argv, package = entry["tool"], entry["cmd"], entry["package"]
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                # A non-zero exit (e.g. dpkg-query reporting "no packages
                # found matching X") means the underlying check failed, not
                # that we found a real version string in stderr - treat it
                # the same as "not installed" rather than displaying the
                # raw error text as if it were version output.
                results.append({"tool": name, "version": "Not installed", "installed": False, "package": package})
                continue
            raw = res.stdout.strip() or res.stderr.strip() or "(no version output)"
            lines = raw.splitlines()
            # MVT's `version` subcommand buries the actual version number a
            # few lines into a banner rather than putting it on line 1 like
            # every other tool here - prefer a line that actually says
            # "Version:" when one exists, instead of showing the banner text.
            version_line = next((l.strip() for l in lines if 'version:' in l.lower()), lines[0])
            results.append({"tool": name, "version": version_line, "installed": True, "package": package})
        except FileNotFoundError:
            results.append({"tool": name, "version": "Not installed", "installed": False, "package": package})
        except subprocess.TimeoutExpired:
            results.append({"tool": name, "version": "timed out", "installed": True, "package": package})
        except Exception as e:
            results.append({"tool": name, "version": f"error: {e}", "installed": False, "package": package})

    return jsonify({"success": True, "tools": results})

@app.route('/api/system/install_tool', methods=['POST'])
@requires_auth
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

    if not hmac.compare_digest(curr_pass, get_active_admin_pass()):
        return jsonify({"success": False, "error": "Current password is incorrect."}), 400

    if not new_pass or len(new_pass) < 8:
        return jsonify({"success": False, "error": "New password must be at least 8 characters long."}), 400

    cfg = load_runtime_config()
    cfg['pass'] = new_pass
    save_runtime_config(cfg)
    return jsonify({"success": True, "message": "Password changed successfully. This takes effect immediately."})

@app.route('/api/system/power', methods=['POST'])
@requires_auth
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
def restart_forensic_service():
    def delayed_restart():
        time.sleep(1)
        subprocess.run(['sudo', '/bin/systemctl', 'restart', 'pi-forensics.service'])

    threading.Thread(target=delayed_restart, daemon=True).start()
    return jsonify({"success": True, "message": "Forensic service restart initiated - this page will disconnect briefly."})

@app.route('/api/system/restart_kiosk', methods=['POST'])
@requires_auth
def restart_touch_kiosk():
    # install.py sets up the kiosk via a labwc autostart script in this
    # account's home directory, not a systemd unit - the web service
    # already runs as that same account, so no sudo/su is needed here.
    autostart_path = os.path.join(os.path.expanduser('~'), '.config', 'labwc', 'autostart')
    if not os.path.exists(autostart_path):
        return jsonify({"success": False, "error": f"Kiosk autostart script not found at {autostart_path}."}), 404

    try:
        subprocess.run(['pkill', '-9', '-f', 'chromium'], capture_output=True, timeout=10)
        time.sleep(1)
        subprocess.Popen(['bash', autostart_path])
        return jsonify({"success": True, "message": "Touchscreen kiosk display restarting..."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/git_update', methods=['POST'])
@requires_auth
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
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        ip_addr = "Unassigned"
        mac_addr = "N/A"
        for addr in addr_list:
            if addr.family == 2:  # AF_INET (IPv4)
                ip_addr = addr.address
            elif addr.family == 17:  # AF_PACKET (MAC, Linux)
                mac_addr = addr.address

        is_up = stats[iface].isup if iface in stats else False
        speed = stats[iface].speed if iface in stats else 0

        interfaces.append({
            "interface": iface,
            "ip": ip_addr,
            "mac": mac_addr,
            "active": is_up,
            "speed_mbps": speed
        })

    return jsonify({"success": True, "interfaces": interfaces})

@app.route('/api/system/maintenance/purge_logs', methods=['POST'])
@requires_auth
def purge_system_logs():
    update_job(log="[System log buffer purged by examiner.]")
    return jsonify({"success": True, "message": "Console log buffer cleared."})

@app.route('/api/system/toggle_keyboard', methods=['POST'])
@requires_auth
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
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "path": entry.path,
                    "is_dir": entry.is_dir(),
                    "size_bytes": stat.st_size if not entry.is_dir() else 0,
                    "size_str": f"{round(stat.st_size / (1024**2), 2)} MB" if not entry.is_dir() else "--",
                    "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                })
            except Exception:
                pass
        return jsonify({"path": path, "items": sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/copy', methods=['POST'])
@requires_auth
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

# --- File Preview (image src / text content) ---
_PREVIEWABLE_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
_PREVIEWABLE_TEXT_EXT = {'.txt', '.json', '.log', '.md', '.csv', '.xml', '.html', '.htm', '.py', '.js', '.sh', '.conf', '.ini', '.cfg', '.yaml', '.yml'}
_PREVIEW_TEXT_MAX_BYTES = 200 * 1024  # 200 KB - enough for a meaningful preview without loading huge files into memory

@app.route('/api/files/raw', methods=['GET'])
@requires_auth
def get_raw_file():
    path = safe_path(request.args.get('path', ''))
    if not path or not os.path.isfile(path):
        return jsonify({"error": "File not found or outside the permitted evidence directory."}), 404

    ext = os.path.splitext(path)[1].lower()
    if ext not in _PREVIEWABLE_IMAGE_EXT:
        return jsonify({"error": "Only image files can be served this way."}), 400

    return send_file(path)

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

# --- Binwalk: Embedded Filesystem / Firmware Signature Scan ---
@app.route('/api/files/binwalk', methods=['POST'])
@requires_auth
def run_binwalk():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    try:
        # Signature scan only - deliberately not using -e (extract), which
        # would write files into the evidence directory automatically.
        # Extraction can be added as an explicit, separate action later if
        # needed, with its own destination picker rather than happening
        # silently as a side effect of scanning.
        res = subprocess.run(['binwalk', file_path], capture_output=True, text=True, timeout=120)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        log_chain_of_custody("binwalk_scan", {"path": file_path})
        return jsonify({"success": True, "file_name": os.path.basename(file_path), "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "binwalk timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- TestDisk: Read-Only Partition Analysis ---
@app.route('/api/recovery/testdisk_analyze', methods=['POST'])
@requires_auth
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
def run_clamscan():
    req = request.get_json() or {}
    target_path = safe_path(req.get('path'))
    if not target_path or not os.path.exists(target_path):
        return jsonify({"success": False, "error": "Path not found or outside the permitted evidence directory."}), 400

    try:
        # -r = recursive (harmless no-op on a single file), --no-summary
        # keeps output focused on actual findings rather than a stats block.
        res = subprocess.run(['clamscan', '-r', '--no-summary', target_path], capture_output=True, text=True, timeout=300)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        # clamscan exit codes: 0 = clean, 1 = virus(es) found, 2 = error
        infected = res.returncode == 1
        log_chain_of_custody("clamav_scan", {"path": target_path, "infected": infected})
        return jsonify({"success": True, "path": target_path, "infected": infected, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "clamscan timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- hashdeep: Recursive Directory Hash Manifest ---
@app.route('/api/files/hashdeep', methods=['POST'])
@requires_auth
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

# --- strings: Extract Printable Text From a Binary File ---
@app.route('/api/files/strings', methods=['POST'])
@requires_auth
def run_strings():
    req = request.get_json() or {}
    file_path = safe_path(req.get('path'))
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    try:
        res = subprocess.run(['strings', '-n', '6', file_path], capture_output=True, text=True, timeout=60)
        lines = res.stdout.splitlines()
        truncated = len(lines) > 1000
        output = "\n".join(lines[:1000])
        if truncated:
            output += f"\n\n[... truncated, {len(lines) - 1000} more lines not shown ...]"
        return jsonify({"success": True, "file_name": os.path.basename(file_path), "output": output or "[no printable strings found]"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "strings timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

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
            # Same bounded-depth pattern as /api/reports/index below.
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

@app.route('/api/reports/index', methods=['GET'])
@requires_auth
def get_reports_index():
    # One row per CASE for cases on the consolidated schema (summarized
    # from their events, not walked into further - nothing report-related
    # lives in a case's job subfolders anymore once it's on this schema).
    # Standalone *_report.json files are still walked and listed exactly as
    # before - this covers both genuine no-case/ad-hoc jobs (a permanent,
    # not just transitional, code path) and any case not yet migrated,
    # which stays visible here as a signal that it still needs migrating.
    reports = []
    try:
        for root, dirs, files in os.walk(EVIDENCE_ROOT):
            # Bound the scan depth so this can't turn into a very slow crawl
            # of a huge or deeply-mounted evidence tree.
            depth = root[len(EVIDENCE_ROOT):].count(os.sep)
            if depth >= 6:
                dirs[:] = []
                continue

            consolidated_name = f"{os.path.basename(root)}_case.json"
            if consolidated_name in files:
                try:
                    with open(os.path.join(root, consolidated_name), 'r') as f:
                        data = json.load(f)
                    events = data.get('events', [])
                    latest = max(events, key=lambda e: e.get('timestamp_start', ''), default=None)
                    reports.append({
                        "path": os.path.join(root, consolidated_name),
                        "case_number": data.get('case_number', '--'),
                        "evidence_id": f"{len(events)} item(s)" if events else "--",
                        "examiner": data.get('examiner', '--'),
                        "status": latest.get('acquisition_status', '--') if latest else '--',
                        "timestamp_start": (latest.get('timestamp_start') if latest else None) or data.get('created_at', '--'),
                        "method": "case (consolidated)",
                        "is_case": True,
                    })
                except (json.JSONDecodeError, OSError):
                    pass
                dirs[:] = []  # a case folder never contains another case folder
                continue

            for fname in files:
                if fname.endswith('_report.json'):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r') as f:
                            data = json.load(f)
                        meta = data.get('case_metadata', {})
                        reports.append({
                            "path": fpath,
                            "case_number": meta.get('case_number', '--'),
                            "evidence_id": meta.get('evidence_id', '--'),
                            "examiner": meta.get('examiner', '--'),
                            "status": data.get('acquisition_status', '--'),
                            "timestamp_start": data.get('timestamp_start', '--'),
                            "method": data.get('acquisition_parameters', {}).get('method', data.get('acquisition_parameters', {}).get('output_format', '--')),
                            "is_case": False,
                        })
                    except (json.JSONDecodeError, OSError):
                        continue

        reports.sort(key=lambda r: r.get('timestamp_start', ''), reverse=True)
        return jsonify({"success": True, "reports": reports})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

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
TSK_DEFAULT_SECTOR_SIZE = 512  # matches the sector size this app's images have always assumed (mmls/fls/dc3dd never handled 4Kn-native source drives specially either - not a new limitation)
TSK_READ_CHUNK_BYTES = 1024 * 1024
TSK_MAX_SEARCH_RESULTS = 500
TSK_MAX_TIMELINE_ENTRIES = 5000
TSK_MAX_WALK_DIRS = 5000   # safety cap against pathological/looping directory structures
TSK_MAX_WALK_DEPTH = 25
TSK_PREVIEW_TEXT_MAX_BYTES = 200_000
TSK_PREVIEW_IMAGE_MAX_BYTES = 8_000_000
TSK_PREVIEW_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
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

def _tsk_parse_inode(raw):
    """Directory/file navigation uses the base inode address only - NTFS's
    optional '-type-id' attribute-selector suffix (for alternate data
    streams) isn't chased here, same scope the old fls-based version had."""
    return int(str(raw).split('-')[0])

def _tsk_open_fs(image_path, offset_sectors):
    img = pytsk3.Img_Info(image_path)
    return pytsk3.FS_Info(img, offset=int(offset_sectors) * TSK_DEFAULT_SECTOR_SIZE)

def _tsk_entry_dict(entry):
    name = entry.info.name.name.decode('utf-8', errors='replace')
    meta = entry.info.meta
    return {
        "name": name,
        "inode": str(entry.info.name.meta_addr),
        "is_dir": entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR,
        "deleted": bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC),
        "size": meta.size if meta else None,
        "mtime": meta.mtime if meta else None,
        "atime": meta.atime if meta else None,
        "ctime": meta.ctime if meta else None,
        "crtime": getattr(meta, 'crtime', None) if meta else None,
    }

def _tsk_list_dir(fs, inode_num):
    tsk_dir = fs.open_dir(inode=inode_num) if inode_num is not None else fs.open_dir(path='/')
    entries = []
    for entry in tsk_dir:
        if not entry.info.name or entry.info.name.name in (b'.', b'..'):
            continue
        try:
            entries.append(_tsk_entry_dict(entry))
        except Exception:
            continue  # one corrupt/unreadable directory entry shouldn't fail the whole listing
    return entries

def _tsk_walk(fs, start_inode_num=None, max_dirs=TSK_MAX_WALK_DIRS, max_depth=TSK_MAX_WALK_DEPTH):
    """Recursively walks a filesystem from start_inode_num (or root),
    yielding (entry_dict, path) for every entry found - shared by search and
    timeline below. Deliberately does not recurse into deleted directories:
    a deleted directory's inode may already have been reallocated to
    something unrelated, and walking it can loop or return garbage on a live
    evidence filesystem. Capped on both directories visited and depth as a
    safety net against reused-inode loops."""
    visited = [0]

    def _walk(inode_num, path, depth):
        if visited[0] >= max_dirs or depth > max_depth:
            return
        try:
            entries = _tsk_list_dir(fs, inode_num)
        except Exception:
            return
        visited[0] += 1
        for d in entries:
            entry_path = f"{path}/{d['name']}"
            yield d, entry_path
            if d['is_dir'] and not d['deleted']:
                yield from _walk(int(d['inode']), entry_path, depth + 1)

    yield from _walk(start_inode_num, '', 0)

def _tsk_stream_file(tsk_file, write_fn, max_bytes=None):
    size = tsk_file.info.meta.size if tsk_file.info.meta else 0
    if max_bytes is not None:
        size = min(size, max_bytes)
    read_offset = 0
    while read_offset < size:
        chunk = tsk_file.read_random(read_offset, min(TSK_READ_CHUNK_BYTES, size - read_offset))
        if not chunk:
            break
        write_fn(chunk)
        read_offset += len(chunk)
    return read_offset

@app.route('/api/image/mmls', methods=['POST'])
@requires_auth
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

@app.route('/api/image/search', methods=['POST'])
@requires_auth
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
        y -= 25

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

def _draw_pdf_header(c, header):
    c.setFont("Helvetica", 10)
    y = 710
    c.drawString(50, y, f"Case Number: {header['case_number']}")
    c.drawString(300, y, f"Examiner: {header['examiner']}")
    y -= 20
    c.drawString(50, y, f"Created: {header['created_at']}")
    y -= 20
    c.drawString(50, y, f"Notes: {header['notes'] or 'None'}")
    y -= 30
    return y

def _draw_pdf_audit_trail(c, y, entries):
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Case Activity Log (Audit Trail)")
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

@app.route('/api/cases/discover_files', methods=['GET'])
@requires_auth
def discover_case_files():
    case_folder = safe_path(request.args.get('case_folder', ''))
    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404
    files, truncated = _discover_case_files(case_folder)
    return jsonify({"success": True, "files": files, "truncated": truncated})

def _draw_pdf_attachments(c, y, urls, files):
    if not (urls or files):
        return y

    if y < 150:
        c.showPage()
        y = 730

    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Case Attachments & References")
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

    for raw_path in files:
        file_path = safe_path(raw_path)
        if not file_path or not os.path.exists(file_path):
            continue

        name = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        try:
            size = os.path.getsize(file_path)
        except OSError:
            size = 0

        if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
            if y < 220:
                c.showPage()
                y = 750
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, f"Image: {name}"[:100])
            y -= 145
            try:
                from reportlab.lib.utils import ImageReader
                c.drawImage(ImageReader(file_path), 60, y, width=220, height=140, preserveAspectRatio=True, anchor='sw')
            except Exception as img_err:
                c.setFont("Helvetica", 9)
                c.drawString(60, y + 130, f"(could not render image: {img_err})"[:100])
            y -= 15
            c.setFont("Helvetica", 10)
        elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
            if y < 100:
                c.showPage()
                y = 750
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, f"Text File: {name}"[:100])
            y -= 14
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
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 10)
            size_note = f" ({size:,} bytes)" if size else ""
            c.drawString(60, y, f"• Document: {name}{size_note} - {file_path}"[:130])
            y -= 15
    return y

def _build_pdf_report(pdf_path, header, events, urls, files, audit_entries, sections, job_fields):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "ARM FORENSIC ACQUISITION AUDIT REPORT")
    c.setLineWidth(1)
    c.line(50, 740, 550, 740)

    y = _draw_pdf_header(c, header) if sections.get('case_info', True) else 710

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

    if sections.get('attachments', True):
        y = _draw_pdf_attachments(c, y, urls, files)
    if sections.get('audit_trail', True):
        y = _draw_pdf_audit_trail(c, y, audit_entries)

    c.save()

def _build_html_report(header, events, urls, files, audit_entries, sections, job_fields):
    """Self-contained HTML report - every value is escaped since it may
    contain examiner-entered text or evidence-derived strings (filenames,
    device paths) that this file could later be reopened/served from disk."""
    esc = html.escape
    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>Case Report - {esc(str(header["case_number"]))}</title>',
        '<style>',
        'body{font-family:Arial,Helvetica,sans-serif;color:#111;max-width:900px;margin:2em auto;padding:0 1em;}',
        'h1{font-size:1.4em;border-bottom:2px solid #333;padding-bottom:.3em;}',
        'h2{font-size:1.15em;margin-top:1.6em;border-bottom:1px solid #999;padding-bottom:.2em;}',
        'h3{font-size:1em;margin:.8em 0 .3em;}',
        'table{border-collapse:collapse;width:100%;margin:.4em 0;}',
        'td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:.9em;vertical-align:top;}',
        '.job{margin-top:1.2em;padding:.8em;border:1px solid #ccc;border-radius:6px;}',
        '.muted{color:#666;font-size:.85em;}',
        '.mono{font-family:"Courier New",monospace;}',
        '.attach-item{margin-top:1em;padding:.7em;border:1px solid #ddd;border-radius:6px;}',
        '.attach-item img{max-width:100%;border:1px solid #ccc;display:block;margin-top:.4em;}',
        '.attach-item pre{background:#f5f5f5;padding:.6em;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.8em;margin-top:.4em;}',
        '</style></head><body>',
        '<h1>ARM Forensic Acquisition Audit Report</h1>',
    ]

    if sections.get('case_info', True):
        parts.append('<table>')
        parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
        parts.append(f'<tr><th>Created</th><td>{esc(str(header["created_at"]))}</td><th>Evidence Items</th><td>{len(events)}</td></tr>')
        parts.append(f'<tr><th>Notes</th><td colspan="3">{esc(str(header["notes"] or "None"))}</td></tr>')
        parts.append('</table>')

    for event in events:
        meta = event.get('case_metadata', {})
        parts.append('<div class="job">')
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

    if sections.get('attachments', True) and (urls or files):
        parts.append('<h2>Case Attachments &amp; References</h2>')
        if urls:
            parts.append('<p><strong>Reference Links / URLs:</strong></p><ul>')
            for url in urls:
                parts.append(f'<li><a href="{esc(str(url))}">{esc(str(url))}</a></li>')
            parts.append('</ul>')

        for raw_path in files:
            file_path = safe_path(raw_path)
            if not file_path or not os.path.exists(file_path):
                continue
            name = os.path.basename(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            try:
                size = os.path.getsize(file_path)
            except OSError:
                size = 0

            if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
                mime = {
                    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
                    '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
                }.get(ext, 'application/octet-stream')
                try:
                    with open(file_path, 'rb') as imf:
                        b64 = base64.b64encode(imf.read()).decode('ascii')
                    parts.append(f'<div class="attach-item"><h3>{esc(name)}</h3><img src="data:{mime};base64,{b64}"></div>')
                except OSError as e:
                    parts.append(f'<div class="attach-item"><h3>{esc(name)}</h3><p class="muted">Could not read image: {esc(str(e))}</p></div>')
            elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
                try:
                    with open(file_path, 'r', errors='replace') as tf:
                        text_content = tf.read(ATTACHMENT_MAX_TEXT_EMBED_BYTES)
                except OSError as e:
                    text_content = f"(could not read file: {e})"
                parts.append(f'<div class="attach-item"><h3>{esc(name)}</h3><pre>{esc(text_content)}</pre></div>')
            else:
                size_note = f" ({size:,} bytes)" if size else ""
                parts.append(f'<div class="attach-item"><h3>{esc(name)}</h3><p class="muted mono">{esc(file_path)}{esc(size_note)}</p></div>')

    if sections.get('audit_trail', True):
        parts.append('<h2>Case Activity Log (Audit Trail)</h2>')
        if audit_entries:
            parts.append('<table><tr><th>Timestamp</th><th>Action</th><th>Details</th></tr>')
            for entry in audit_entries:
                details_str = ', '.join(f'{k}={v}' for k, v in (entry.get('details') or {}).items())
                parts.append(f'<tr><td>{esc(str(entry.get("timestamp", "")))}</td><td>{esc(str(entry.get("action", "")))}</td><td>{esc(details_str)}</td></tr>')
            parts.append('</table>')
        else:
            parts.append('<p class="muted">No activity log entries found for this case.</p>')

    parts.append('</body></html>')
    return ''.join(parts)

@app.route('/api/export_report', methods=['POST'])
@requires_auth
def export_report():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"error": "Report file not found or outside the permitted evidence directory."}), 404

    fmt = req.get('format', 'pdf')
    if fmt not in ('pdf', 'html'):
        return jsonify({"error": "format must be 'pdf' or 'html'."}), 400

    sections = req.get('sections') or {}
    job_fields = req.get('job_fields') or {}
    requested_event_ids = req.get('event_ids')
    attachment_selection = req.get('attachment_selection')

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Could not read report: {e}"}), 500

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
        }
        attachments = data.get('attachments', {})

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

    audit_entries = []
    if sections.get('audit_trail', True) and header['case_number'] not in (None, '', 'N/A'):
        audit_entries = _case_history_entries(header['case_number'], limit=500)

    try:
        if fmt == 'html':
            out_path = report_file.rsplit('.json', 1)[0] + '.html'
            with open(out_path, 'w') as f:
                f.write(_build_html_report(header, events, sel_urls, sel_files, audit_entries, sections, job_fields))
        else:
            out_path = report_file.rsplit('.json', 1)[0] + '.pdf'
            _build_pdf_report(out_path, header, events, sel_urls, sel_files, audit_entries, sections, job_fields)
        return send_file(out_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": f"Report export failed: {str(e)}"}), 500

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
