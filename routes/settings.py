"""Settings: system telemetry, network share mounting + auto-mount
persistence, diagnostics/tool-versions/install, password change, user +
user-group management, TLS certificate view/upload/generate/download,
power/service/kiosk-restart/git-update/OS-update controls, drive eject,
network interface telemetry, static-IP/DHCP network configuration (with
its auto-revert safety net), log purging, on-screen keyboard toggle, and
the MVT IOC-indicator updater. The most physically scattered cluster in
the original app.py, and the last blueprint extracted in this refactor -
every other blueprint has already validated the process.

attempt_startup_auto_mounts() (called once, at module import time, from
app.py) lives here too, since it's this file's own mount-replay logic.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import re
import io
import csv
import time
import json
import hmac
import glob
import stat
import uuid
import shutil
import secrets
import tempfile
import subprocess
import threading
import ipaddress

import base64

import psutil
from flask import Blueprint, jsonify, request, g, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.auth import (
    PERMISSION_KEYS, KIOSK_AUTH_BYPASS_ENABLED,
    requires_auth, requires_permission, check_auth,
    find_user, find_group, get_user_groups, get_user_group_id,
    get_current_user_permissions, get_current_user_role,
    caller_reauth_ok, _normalize_permissions,
)
from core.paths import safe_path, log_chain_of_custody, is_valid_block_device
import core.config as config
from core.config import (
    ADMIN_USER, ADMIN_PASS, INSTALL_DIR, HISTORY_FILE,
    TLS_CERT_PATH, TLS_KEY_PATH, MVT_BIN_DIR, MVT_IOS_BIN, MVT_ANDROID_BIN,
    VOL3_PIP_BIN, MQUIRE_BIN,
    EVIDENCE_ROOT, ALLOWED_HASH_ALGOS,
    load_runtime_config, save_runtime_config, get_active_admin_pass,
    _get_or_create_mount_key, _encrypt_secret, _decrypt_secret,
    get_app_version,
)
from core.jobs import job_lock, current_job, update_job
from core.case_index_db import check_regex_pattern_for_redos
import yara

settings_bp = Blueprint('settings', __name__)

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

# _DEVICE_RE/is_valid_block_device now live in core/paths.py (imported at
# the top of this file) - shared by recovery/acquisition/settings routes,
# not specific to the BitLocker cluster below.

# _PARTITION_RE, is_valid_bitlocker_source, and the whole BitLocker
# unlock/mount machinery (DISLOCKER_MOUNT_ROOT, bitlocker_lock,
# active_bitlocker_mounts, _list_device_partitions, _detect_bitlocker,
# _detect_bitlocker_image, _dislocker_unlock, _dislocker_lock,
# _resolve_acquisition_source) now live in routes/acquisition.py - see the
# dated CLAUDE.md entry for this refactor.

# sanitize_case_slug and reclaim_ownership now live in core/paths.py and
# core/jobs.py respectively (imported at the top of this file) - see the
# Step 0 core/ extraction.

# parse_dc3dd_hashes, parse_ewf_hashes, parse_dc3dd_line, parse_ewf_line,
# and parse_ddrescue_line now live in routes/acquisition.py - see the dated
# CLAUDE.md entry for this refactor.

# TRIAGE_PATTERNS/TRIAGE_MAX_MATCHES_PER_CATEGORY/TRIAGE_CATEGORY_LABELS,
# EXTENSION_CATEGORY_MAP/FILE_VIEW_EXTENSION_CATEGORIES/classify_extension,
# and the whole per-case SQLite analysis index (case_index_db_path,
# _CASE_INDEX_SCHEMA, _case_index_connect) now live in core/case_index_db.py
# and core/paths.py (imported at the top of this file) - see the Step 0
# core/ extraction. ALLOWED_TAG_COLORS moved to routes/case_index.py (Step 7)
# - single-consumer, only that file's routes ever used it.

# HASH_HEX_LEN, read_hash_log_file, compute_file_hashes,
# parse_affconvert_line, and parse_ddrescue_mapfile now live in
# routes/acquisition.py - see the dated CLAUDE.md entry for this refactor.

# _stream_subprocess and poll_directory_size now live in core/jobs.py
# (imported at the top of this file) - see the Step 0 core/ extraction,
# including the active_proc accessor-function fix described there.

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

# _UDID_RE/_ANDROID_SERIAL_RE, list_ios_devices, and list_android_devices now
# live in routes/mobile.py - see the dated CLAUDE.md entry for this refactor.

# execution_worker and execution_worker_aff now live in
# routes/acquisition.py - see the dated CLAUDE.md entry for this refactor.
# execution_worker_ios_backup and execution_worker_android now live in
# routes/mobile.py - see the dated CLAUDE.md entry for this refactor.

# execution_worker_photorec, execution_worker_extundelete,
# execution_worker_foremost, execution_worker_scalpel, and
# execution_worker_triage_scan now live in routes/recovery.py - see the
# dated CLAUDE.md entry for this refactor.

# --- Web Routes & API Endpoints ---
# /login, /logout, /, and /api/whoami now live in routes/auth_routes.py
# (registered as a Blueprint below) - see the dated CLAUDE.md entry for
# this refactor.

@settings_bp.route('/api/system_info', methods=['GET'])
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

# /api/drives now lives in routes/acquisition.py - see the dated CLAUDE.md
# entry for this refactor.

# /api/smart_check now lives in routes/acquisition.py - see the dated
# CLAUDE.md entry for this refactor.

@settings_bp.route('/api/mount_history', methods=['GET'])
@requires_auth
def get_mount_history():
    return jsonify(load_mount_history())

@settings_bp.route('/api/list_server_shares', methods=['POST'])
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
    # host/share_path/user are examiner-typed free text that ends up
    # combined into a single argv element for the mount tool (e.g.
    # sftp_source = f"{user}@{host}:{share_path}" below) - list-form
    # subprocess calls mean this was never a shell-injection risk, but a
    # value starting with '-' could still be misread as a flag by sshfs/
    # mount/smbclient's own argument parser rather than the positional data
    # it's meant to be. Found during the 2026-08-22 security audit; checked
    # once here for all three protocols rather than patching each branch
    # separately, since they all build the same shape of combined argument.
    for value, field_name in ((host, "Host"), (share_path, "Share path"), (user, "Username")):
        if value and value.startswith('-'):
            return False, f"{field_name} cannot start with '-'."

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


@settings_bp.route('/api/mount_network', methods=['POST'])
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


# --- Keyword Lists: examiner-defined, saved search terms selectable at
# Triage Scan time (Quick Triage Scan, the File Recovery job, and the
# filesystem-aware whole-image job), additive to the 5 built-in structured-
# data categories (see core/case_index_db.py's TRIAGE_PATTERNS/
# build_scan_patterns()). Same CRUD shape as report_templates_custom() in
# routes/reporting.py (GET ungated - every Triage Scan launcher across 3
# tabs needs to read the list regardless of whether that account has
# 'settings'; writes gated 'settings' since this is station-wide config).
KEYWORD_LIST_NAME_MAX = 100
KEYWORD_LIST_TERM_MAX = 500  # a single term/pattern's own max length
KEYWORD_LIST_MAX_TERMS = 200  # per list
KEYWORD_LIST_MAX_LISTS = 100  # station-wide

def _keyword_list_from_payload(req):
    """Validates and normalizes a create/update payload into the stored
    record shape (minus id/created_at, which the caller fills in). Returns
    (record_dict, None) or (None, error_message). Regex-mode terms are
    compile-checked up front and rejected with a specific error naming the
    bad pattern - unlike a plain-term list (always safe, every term is
    re.escape()'d at scan time), a broken regex here would otherwise fail
    silently mid-scan (build_scan_patterns() swallows a compile error and
    just drops that list rather than failing a long-running job), which
    would be a confusing way for an examiner to discover a typo."""
    name = (req.get('name') or '').strip()[:KEYWORD_LIST_NAME_MAX]
    if not name:
        return None, "List name is required."

    raw_terms = req.get('terms')
    if not isinstance(raw_terms, list):
        return None, "Terms must be a list of strings."
    terms = [t.strip()[:KEYWORD_LIST_TERM_MAX] for t in raw_terms if isinstance(t, str) and t.strip()]
    if not terms:
        return None, "At least one term is required."
    if len(terms) > KEYWORD_LIST_MAX_TERMS:
        return None, f"Too many terms - max {KEYWORD_LIST_MAX_TERMS} per list."

    is_regex = bool(req.get('is_regex'))
    if is_regex:
        for t in terms:
            try:
                re.compile(t)
            except re.error as e:
                return None, f"'{t}' is not a valid regular expression: {e}"

        # ReDoS check, found missing entirely during the 2026-08-22 security
        # audit: a syntactically-valid regex can still exhibit catastrophic
        # backtracking, and this list's compiled pattern later runs directly
        # against raw, attacker-influenced evidence bytes in 3 different scan
        # workers with no per-match timeout. Build and test the exact same
        # combined pattern build_scan_patterns() would actually compile and
        # use (not each term in isolation), so this check reflects what a
        # real scan would run - see core/case_index_db.py's
        # check_regex_pattern_for_redos() for the mechanism and its disclosed
        # limitations.
        try:
            combined = re.compile('|'.join(f'(?:{t})' for t in terms).encode('utf-8'), re.IGNORECASE)
            redos_error = check_regex_pattern_for_redos(combined)
            if redos_error:
                return None, redos_error
        except re.error as e:
            return None, f"Combined pattern is not valid: {e}"

    return {
        "name": name,
        "terms": terms,
        "is_regex": is_regex,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, None

@settings_bp.route('/api/settings/keyword_lists', methods=['GET', 'POST'])
@requires_auth
def keyword_lists():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({"success": True, "lists": cfg.get('keyword_lists', [])})

    perms = get_current_user_permissions()
    if not perms.get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    lists = cfg.setdefault('keyword_lists', [])
    if len(lists) >= KEYWORD_LIST_MAX_LISTS:
        return jsonify({"success": False, "error": f"Station already has the maximum of {KEYWORD_LIST_MAX_LISTS} keyword lists."}), 400

    req = request.get_json() or {}
    record, error = _keyword_list_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400

    # Soft-dedupe on name collision (numeric suffix), same precedent as
    # custom report templates - no on-disk artifact at stake for a
    # duplicate list *name*.
    base_id = re.sub(r'[^a-z0-9_]+', '_', record['name'].lower()).strip('_') or 'keywords'
    existing_ids = {r['id'] for r in lists}
    list_id = base_id
    n = 2
    while list_id in existing_ids:
        list_id = f"{base_id}_{n}"
        n += 1

    record['id'] = list_id
    record['created_at'] = record['updated_at']
    lists.append(record)
    save_runtime_config(cfg)
    log_chain_of_custody("keyword_list_created", {"id": list_id, "name": record['name'], "term_count": len(record['terms'])})
    return jsonify({"success": True, "list": record})

@settings_bp.route('/api/settings/keyword_lists/<list_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings')
def keyword_list_detail(list_id):
    cfg = load_runtime_config()
    lists = cfg.get('keyword_lists', [])
    idx = next((i for i, r in enumerate(lists) if r.get('id') == list_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "Keyword list not found."}), 404

    if request.method == 'DELETE':
        removed = lists.pop(idx)
        cfg['keyword_lists'] = lists
        save_runtime_config(cfg)
        log_chain_of_custody("keyword_list_deleted", {"id": list_id, "name": removed.get('name')})
        return jsonify({"success": True})

    req = request.get_json() or {}
    record, error = _keyword_list_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400
    # id is fixed at creation and never regenerated from a new name - a
    # rename must not invalidate a scan launcher's already-checked
    # keyword_list_ids selection or any other stored reference.
    record['id'] = list_id
    record['created_at'] = lists[idx].get('created_at', record['updated_at'])
    lists[idx] = record
    cfg['keyword_lists'] = lists
    save_runtime_config(cfg)
    log_chain_of_custody("keyword_list_updated", {"id": list_id, "name": record['name'], "term_count": len(record['terms'])})
    return jsonify({"success": True, "list": record})

# --- Hash-set filtering (D2): station-wide known-good/known-bad hash lists ---
# Mirrors the Keyword Lists feature above structurally (CRUD, save-time
# validation, a station-wide list an examiner picks from at scan time) -
# the one deliberate difference: a hash list can run to thousands of
# lines, so only metadata lives inline in runtime_config.json (id/name/
# algorithm/label/hash_count/timestamps); the actual hash values live in
# their own flat file under config.HASH_LISTS_DIR, one hash per line -
# same "large blob gets its own file" precedent report_logo.<ext> already
# established, referenced via the module-qualified config.HASH_LISTS_DIR
# (not a bare imported name) for the same test-safety reason
# config.INSTALL_DIR/config.RUNTIME_CONFIG_FILE/config.MOUNT_KEY_FILE are
# already accessed that way elsewhere in this file - see this file's own
# comment on that near the top of the Configuration Backup section.
HASH_LIST_MAX_HASHES = 500_000  # station-appropriate, not NSRL-scale
HASH_LIST_MAX_LISTS = 50
_HASH_LEN_BY_ALGO = {'md5': 32, 'sha1': 40, 'sha256': 64}
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def _parse_hash_list_text(text, algorithm):
    """Validates and normalizes a pasted/uploaded hash blob - one hash per
    line (blank lines and a leading '#' comment line both tolerated, since
    many real-world hash-set exports use one or the other), each must be a
    plausible hex string of exactly the length the declared algorithm
    produces. Returns (hashes, error) - error is a string naming the first
    bad line if validation fails, so an examiner pasting a garbled/wrong-
    algorithm list gets a clear reason rather than a silent partial import."""
    expected_len = _HASH_LEN_BY_ALGO.get(algorithm)
    if not expected_len:
        return None, f"Unsupported algorithm '{algorithm}'. Use any of {sorted(_HASH_LEN_BY_ALGO)}."
    hashes = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if len(line) != expected_len or not _HEX_RE.match(line):
            return None, f"Line {i} ('{line[:40]}') is not a valid {expected_len}-character {algorithm} hash."
        hashes.append(line.lower())
        if len(hashes) > HASH_LIST_MAX_HASHES:
            return None, f"Too many hashes - max {HASH_LIST_MAX_HASHES} per list."
    if not hashes:
        return None, "No valid hashes found in the pasted text."
    return hashes, None

@settings_bp.route('/api/settings/hash_lists', methods=['GET', 'POST'])
@requires_auth
def hash_lists():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({"success": True, "lists": cfg.get('hash_lists', [])})

    perms = get_current_user_permissions()
    if not perms.get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    lists = cfg.setdefault('hash_lists', [])
    if len(lists) >= HASH_LIST_MAX_LISTS:
        return jsonify({"success": False, "error": f"Station already has the maximum of {HASH_LIST_MAX_LISTS} hash sets."}), 400

    req = request.get_json() or {}
    name = (req.get('name') or '').strip()
    algorithm = (req.get('algorithm') or '').strip().lower()
    label = req.get('label') if req.get('label') in ('known_good', 'known_bad') else 'known_bad'
    if not name:
        return jsonify({"success": False, "error": "Name is required."}), 400
    hashes, error = _parse_hash_list_text(req.get('hashes_text') or '', algorithm)
    if error:
        return jsonify({"success": False, "error": error}), 400

    base_id = re.sub(r'[^a-z0-9_]+', '_', name.lower()).strip('_') or 'hashlist'
    existing_ids = {r['id'] for r in lists}
    list_id = base_id
    n = 2
    while list_id in existing_ids:
        list_id = f"{base_id}_{n}"
        n += 1

    os.makedirs(config.HASH_LISTS_DIR, exist_ok=True)
    with open(config.hash_list_file_path(list_id), 'w') as f:
        f.write('\n'.join(hashes) + '\n')

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    # source added 2026-08-26 alongside MalwareBazaar's own feed-backed list
    # below (mirrors url_lists' identical field) - every list created
    # through this route is examiner-pasted, hence "manual"; a pre-existing
    # list from before this field existed just reads as source: None, which
    # the frontend already treats the same way ("not malwarebazaar_recent").
    record = {"id": list_id, "name": name, "algorithm": algorithm, "label": label, "source": "manual",
              "hash_count": len(hashes), "created_at": now, "updated_at": now}
    lists.append(record)
    save_runtime_config(cfg)
    log_chain_of_custody("hash_list_created", {"id": list_id, "name": name, "algorithm": algorithm, "hash_count": len(hashes)})
    return jsonify({"success": True, "list": record})

@settings_bp.route('/api/settings/hash_lists/<list_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings')
def hash_list_detail(list_id):
    cfg = load_runtime_config()
    lists = cfg.get('hash_lists', [])
    idx = next((i for i, r in enumerate(lists) if r.get('id') == list_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "Hash list not found."}), 404

    if request.method == 'DELETE':
        removed = lists.pop(idx)
        cfg['hash_lists'] = lists
        save_runtime_config(cfg)
        try:
            os.remove(config.hash_list_file_path(list_id))
        except OSError:
            pass
        log_chain_of_custody("hash_list_deleted", {"id": list_id, "name": removed.get('name')})
        return jsonify({"success": True})

    req = request.get_json() or {}
    name = (req.get('name') or '').strip() or lists[idx]['name']
    label = req.get('label') if req.get('label') in ('known_good', 'known_bad') else lists[idx].get('label', 'known_bad')
    algorithm = lists[idx]['algorithm']  # algorithm is fixed at creation, matching every hash already on disk
    hashes_text = req.get('hashes_text')
    if hashes_text is not None:
        hashes, error = _parse_hash_list_text(hashes_text, algorithm)
        if error:
            return jsonify({"success": False, "error": error}), 400
        with open(config.hash_list_file_path(list_id), 'w') as f:
            f.write('\n'.join(hashes) + '\n')
        hash_count = len(hashes)
    else:
        hash_count = lists[idx]['hash_count']  # name/label-only edit - hashes on disk untouched

    lists[idx] = {**lists[idx], "name": name, "label": label, "hash_count": hash_count,
                  "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    cfg['hash_lists'] = lists
    save_runtime_config(cfg)
    log_chain_of_custody("hash_list_updated", {"id": list_id, "name": name, "hash_count": hash_count})
    return jsonify({"success": True, "list": lists[idx]})


# --- MalwareBazaar (abuse.ch) hash feed for Hash Sets (2026-08-26,
# Linux-DFIR-tools follow-up) ---
# Unlike URLhaus above, MalwareBazaar's exports genuinely require a free,
# personal Auth-Key (confirmed live against bazaar.abuse.ch/export/ before
# building this: "In order to access the datasets... you need to obtain an
# Auth-Key first... required") - registered by the EXAMINER themselves at
# https://auth.abuse.ch/, never by this app or its own account creation
# would be needed to test that, which this project is not in a position to
# do (account creation on the user's behalf is explicitly out of scope).
# The Auth-Key is a per-station operator secret, so it's Fernet-encrypted
# at rest via the exact same _encrypt_secret()/_decrypt_secret() helpers
# already established for network-mount credentials - never displayed back
# once saved, only a "configured: yes/no" indicator.
#
# Endpoint/response shape confirmed from bazaar.abuse.ch's own official API
# docs plus a corroborating third-party client library's documented usage
# (mb-api.abuse.ch/api/v1/, POST, header Auth-Key: <key>, form data
# query=get_recent&selector=100 -> {"query_status": "ok", "data": [{...,
# "sha256_hash": "..."}, ...]}), NOT empirically verified end-to-end
# against a real key (this app has none to test with) - disclosed as an
# open item rather than silently assumed correct.
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
MALWAREBAZAAR_LIST_ID = "malwarebazaar_recent"
MALWAREBAZAAR_FETCH_TIMEOUT_SECONDS = 30


@settings_bp.route('/api/settings/malwarebazaar_key', methods=['GET', 'POST'])
@requires_auth
def malwarebazaar_key():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({"success": True, "configured": bool(cfg.get('malwarebazaar_auth_key_enc'))})

    perms = get_current_user_permissions()
    if not perms.get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    req = request.get_json() or {}
    auth_key = (req.get('auth_key') or '').strip()
    cfg['malwarebazaar_auth_key_enc'] = _encrypt_secret(auth_key) if auth_key else None
    save_runtime_config(cfg)
    log_chain_of_custody("malwarebazaar_key_updated", {"configured": bool(auth_key)})
    return jsonify({"success": True, "configured": bool(auth_key)})


@settings_bp.route('/api/settings/hash_lists/refresh_malwarebazaar', methods=['POST'])
@requires_auth
@requires_permission('settings')
def refresh_malwarebazaar_hash_list():
    import urllib.request
    import urllib.error

    cfg = load_runtime_config()
    auth_key = _decrypt_secret(cfg.get('malwarebazaar_auth_key_enc'))
    if not auth_key:
        return jsonify({"success": False, "error": "No MalwareBazaar Auth-Key configured. Get a free one at "
                        "https://auth.abuse.ch/ and enter it above first."}), 400

    body = "query=get_recent&selector=100".encode('ascii')
    req = urllib.request.Request(
        MALWAREBAZAAR_API_URL, data=body, method='POST',
        headers={"Auth-Key": auth_key, "User-Agent": "pi-forensics-suite/1.0 (DFIR appliance, station-operated)"})
    try:
        with urllib.request.urlopen(req, timeout=MALWAREBAZAAR_FETCH_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return jsonify({"success": False, "error": "MalwareBazaar rejected the configured Auth-Key (401 Unauthorized) - check it's correct and still active."}), 401
        return jsonify({"success": False, "error": f"MalwareBazaar returned HTTP {e.code}."}), 502
    except (urllib.error.URLError, OSError) as e:
        return jsonify({"success": False, "error": f"Could not reach mb-api.abuse.ch: {e}"}), 502

    try:
        payload = json.loads(raw)
    except ValueError:
        return jsonify({"success": False, "error": "MalwareBazaar returned a response that wasn't valid JSON - the API may have changed."}), 502

    if payload.get('query_status') != 'ok':
        return jsonify({"success": False, "error": f"MalwareBazaar query_status was '{payload.get('query_status')}', not 'ok'."}), 502

    hashes = sorted({row['sha256_hash'].lower() for row in (payload.get('data') or [])
                      if isinstance(row, dict) and row.get('sha256_hash')})
    if not hashes:
        return jsonify({"success": False, "error": "MalwareBazaar responded successfully but returned no hashes."}), 502

    os.makedirs(config.HASH_LISTS_DIR, exist_ok=True)
    with open(config.hash_list_file_path(MALWAREBAZAAR_LIST_ID), 'w') as f:
        f.write('\n'.join(hashes) + '\n')

    lists = cfg.setdefault('hash_lists', [])
    idx = next((i for i, r in enumerate(lists) if r.get('id') == MALWAREBAZAAR_LIST_ID), None)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {"id": MALWAREBAZAAR_LIST_ID, "name": "MalwareBazaar Recent Hashes", "algorithm": "sha256",
              "label": "known_bad", "source": "malwarebazaar_recent", "hash_count": len(hashes),
              "updated_at": now, "created_at": lists[idx]['created_at'] if idx is not None else now}
    if idx is not None:
        lists[idx] = record
    else:
        if len(lists) >= HASH_LIST_MAX_LISTS:
            return jsonify({"success": False, "error": f"Station already has the maximum of {HASH_LIST_MAX_LISTS} hash sets - delete one first."}), 400
        lists.append(record)
    cfg['hash_lists'] = lists
    save_runtime_config(cfg)
    log_chain_of_custody("hash_list_refreshed_from_malwarebazaar", {"hash_count": len(hashes)})
    return jsonify({"success": True, "list": record})


# --- URL lists (2026-08-26, Linux-DFIR-tools follow-up): station-wide
# known-bad URL lists, checked automatically against every URL a browser-
# artifact scan extracts (core/browser_artifacts.py's own
# _match_urls_against_lists()). Mirrors Hash Sets' exact CRUD shape (large
# blob gets its own file under INSTALL_DIR, only metadata inline in
# runtime_config.json) - the one real difference is a plain URL has no
# "algorithm" concept and no fixed length the way a hex hash does, so
# validation here is a plausibility check (a real http(s) scheme, a sane
# max length), not a byte-exact format check.
URL_LIST_MAX_URLS = 100_000
URL_LIST_MAX_LISTS = 20
URL_LIST_MAX_URL_LENGTH = 2048  # generous - real-world URLs are almost always far shorter; a much longer "URL" is more likely garbage/binary than a real one
_URL_SCHEME_RE = re.compile(r'^https?://', re.IGNORECASE)


def _parse_url_list_text(text):
    """Same shape as _parse_hash_list_text() above - one URL per line,
    blank lines and '#'-prefixed comment lines tolerated. Returns
    (urls, error)."""
    urls = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if len(line) > URL_LIST_MAX_URL_LENGTH or not _URL_SCHEME_RE.match(line):
            return None, f"Line {i} ('{line[:60]}') doesn't look like a real http(s) URL."
        urls.append(line)
        if len(urls) > URL_LIST_MAX_URLS:
            return None, f"Too many URLs - max {URL_LIST_MAX_URLS} per list."
    if not urls:
        return None, "No valid URLs found in the pasted text."
    return urls, None


@settings_bp.route('/api/settings/url_lists', methods=['GET', 'POST'])
@requires_auth
def url_lists():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({"success": True, "lists": cfg.get('url_lists', [])})

    perms = get_current_user_permissions()
    if not perms.get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    lists = cfg.setdefault('url_lists', [])
    if len(lists) >= URL_LIST_MAX_LISTS:
        return jsonify({"success": False, "error": f"Station already has the maximum of {URL_LIST_MAX_LISTS} URL lists."}), 400

    req = request.get_json() or {}
    name = (req.get('name') or '').strip()
    if not name:
        return jsonify({"success": False, "error": "Name is required."}), 400
    urls, error = _parse_url_list_text(req.get('urls_text') or '')
    if error:
        return jsonify({"success": False, "error": error}), 400

    base_id = re.sub(r'[^a-z0-9_]+', '_', name.lower()).strip('_') or 'urllist'
    existing_ids = {r['id'] for r in lists}
    list_id = base_id
    n = 2
    while list_id in existing_ids:
        list_id = f"{base_id}_{n}"
        n += 1

    os.makedirs(config.URL_LISTS_DIR, exist_ok=True)
    with open(config.url_list_file_path(list_id), 'w', encoding='utf-8') as f:
        f.write('\n'.join(urls) + '\n')

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {"id": list_id, "name": name, "source": "manual", "url_count": len(urls), "created_at": now, "updated_at": now}
    lists.append(record)
    save_runtime_config(cfg)
    log_chain_of_custody("url_list_created", {"id": list_id, "name": name, "url_count": len(urls)})
    return jsonify({"success": True, "list": record})


@settings_bp.route('/api/settings/url_lists/<list_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings')
def url_list_detail(list_id):
    cfg = load_runtime_config()
    lists = cfg.get('url_lists', [])
    idx = next((i for i, r in enumerate(lists) if r.get('id') == list_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "URL list not found."}), 404

    if request.method == 'DELETE':
        removed = lists.pop(idx)
        cfg['url_lists'] = lists
        save_runtime_config(cfg)
        try:
            os.remove(config.url_list_file_path(list_id))
        except OSError:
            pass
        log_chain_of_custody("url_list_deleted", {"id": list_id, "name": removed.get('name')})
        return jsonify({"success": True})

    req = request.get_json() or {}
    name = (req.get('name') or '').strip() or lists[idx]['name']
    urls_text = req.get('urls_text')
    if urls_text is not None:
        urls, error = _parse_url_list_text(urls_text)
        if error:
            return jsonify({"success": False, "error": error}), 400
        with open(config.url_list_file_path(list_id), 'w', encoding='utf-8') as f:
            f.write('\n'.join(urls) + '\n')
        url_count = len(urls)
    else:
        url_count = lists[idx]['url_count']  # name-only edit - urls on disk untouched

    lists[idx] = {**lists[idx], "name": name, "url_count": url_count,
                  "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    cfg['url_lists'] = lists
    save_runtime_config(cfg)
    log_chain_of_custody("url_list_updated", {"id": list_id, "name": name, "url_count": url_count})
    return jsonify({"success": True, "list": lists[idx]})


URLHAUS_RECENT_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_LIST_ID = "urlhaus_recent"
URLHAUS_FETCH_TIMEOUT_SECONDS = 30
URLHAUS_MAX_URLS = 50_000  # the real recent-URLs feed runs a few thousand entries (48h window) - generous headroom, not expected to ever actually hit this


@settings_bp.route('/api/settings/url_lists/refresh_urlhaus', methods=['POST'])
@requires_auth
@requires_permission('settings')
def refresh_urlhaus_url_list():
    """Creates (first run) or refreshes (every run after) one fixed,
    idempotent list - "URLhaus Recent Malicious URLs" - from abuse.ch's
    OPEN bulk CSV dump (confirmed live before building this: unlike
    MalwareBazaar's hash exports below, this specific endpoint needs no
    Auth-Key at all - only URLhaus's own per-URL *query* API does).
    Deliberately a plain urllib.request call, not the `requests` package -
    matches install.py's own established precedent for outbound HTTP here
    (the offline OSM tile downloader), and `requests` isn't a declared
    dependency of this app anywhere (only pulled in transitively by mvt),
    so using it directly would be an undeclared-dependency risk."""
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(
            URLHAUS_RECENT_CSV_URL,
            headers={"User-Agent": "pi-forensics-suite/1.0 (DFIR appliance, station-operated)"})
        with urllib.request.urlopen(req, timeout=URLHAUS_FETCH_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError) as e:
        return jsonify({"success": False, "error": f"Could not reach urlhaus.abuse.ch: {e}"}), 502

    # The dump's own format (confirmed live 2026-08-25): a handful of
    # '#'-prefixed comment/header lines, then real quoted-CSV rows -
    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter.
    urls = []
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith('#'):
            continue
        if len(row) < 3:
            continue
        url = row[2].strip()
        if _URL_SCHEME_RE.match(url) and len(url) <= URL_LIST_MAX_URL_LENGTH:
            urls.append(url)
        if len(urls) >= URLHAUS_MAX_URLS:
            break

    if not urls:
        return jsonify({"success": False, "error": "URLhaus responded, but no valid URL rows were found in the feed - it may have changed format."}), 502

    os.makedirs(config.URL_LISTS_DIR, exist_ok=True)
    with open(config.url_list_file_path(URLHAUS_LIST_ID), 'w', encoding='utf-8') as f:
        f.write('\n'.join(urls) + '\n')

    cfg = load_runtime_config()
    lists = cfg.setdefault('url_lists', [])
    idx = next((i for i, r in enumerate(lists) if r.get('id') == URLHAUS_LIST_ID), None)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    record = {"id": URLHAUS_LIST_ID, "name": "URLhaus Recent Malicious URLs", "source": "urlhaus_recent",
              "url_count": len(urls), "updated_at": now, "created_at": lists[idx]['created_at'] if idx is not None else now}
    if idx is not None:
        lists[idx] = record
    else:
        if len(lists) >= URL_LIST_MAX_LISTS:
            return jsonify({"success": False, "error": f"Station already has the maximum of {URL_LIST_MAX_LISTS} URL lists - delete one first."}), 400
        lists.append(record)
    cfg['url_lists'] = lists
    save_runtime_config(cfg)
    log_chain_of_custody("url_list_refreshed_from_urlhaus", {"url_count": len(urls)})
    return jsonify({"success": True, "list": record})

# --- YARA rule scanning (D3): station-wide rulesets ---
# Mirrors Keyword Lists structurally, not Hash Lists - a YARA ruleset's rule
# text is typically small (a few KB, unlike a hash list's thousands of
# lines), so it stays fully inline in runtime_config.json rather than
# getting its own file under INSTALL_DIR. Save-time validation compiles the
# rule text via yara.compile() itself (the real thing that will run it
# later), so a syntax error is caught immediately at save time, not
# discovered mid-scan.
YARA_RULESET_NAME_MAX = 100
YARA_RULESET_MAX_RULE_TEXT = 50_000  # a station-appropriate cap, not a real limit YARA itself imposes
YARA_RULESET_MAX_RULESETS = 100

def _yara_ruleset_from_payload(req):
    """Validates and normalizes a create/update payload into the stored
    record shape (minus id/created_at, which the caller fills in). Returns
    (record_dict, None) or (None, error_message). Compiling here (not just
    checking the text looks plausible) is deliberate - it's the exact same
    compile step the scan routes themselves will run, so a rule that's
    accepted here is guaranteed to actually compile at scan time too."""
    name = (req.get('name') or '').strip()[:YARA_RULESET_NAME_MAX]
    if not name:
        return None, "Ruleset name is required."

    rule_text = req.get('rule_text') or ''
    if not rule_text.strip():
        return None, "Rule text is required."
    if len(rule_text) > YARA_RULESET_MAX_RULE_TEXT:
        return None, f"Rule text too long - max {YARA_RULESET_MAX_RULE_TEXT} characters."

    try:
        yara.compile(source=rule_text)
    except yara.Error as e:
        return None, f"YARA rule did not compile: {e}"

    return {
        "name": name,
        "rule_text": rule_text,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, None

@settings_bp.route('/api/settings/yara_rules', methods=['GET', 'POST'])
@requires_auth
def yara_rules():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({"success": True, "rulesets": cfg.get('yara_rulesets', [])})

    perms = get_current_user_permissions()
    if not perms.get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    rulesets = cfg.setdefault('yara_rulesets', [])
    if len(rulesets) >= YARA_RULESET_MAX_RULESETS:
        return jsonify({"success": False, "error": f"Station already has the maximum of {YARA_RULESET_MAX_RULESETS} YARA rulesets."}), 400

    req = request.get_json() or {}
    record, error = _yara_ruleset_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400

    # Soft-dedupe on name collision (numeric suffix), same precedent as
    # keyword lists / custom report templates - no on-disk artifact at
    # stake for a duplicate ruleset *name*.
    base_id = re.sub(r'[^a-z0-9_]+', '_', record['name'].lower()).strip('_') or 'yara_ruleset'
    existing_ids = {r['id'] for r in rulesets}
    ruleset_id = base_id
    n = 2
    while ruleset_id in existing_ids:
        ruleset_id = f"{base_id}_{n}"
        n += 1

    record['id'] = ruleset_id
    record['created_at'] = record['updated_at']
    rulesets.append(record)
    save_runtime_config(cfg)
    log_chain_of_custody("yara_ruleset_created", {"id": ruleset_id, "name": record['name']})
    return jsonify({"success": True, "ruleset": record})

@settings_bp.route('/api/settings/yara_rules/<ruleset_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings')
def yara_rule_detail(ruleset_id):
    cfg = load_runtime_config()
    rulesets = cfg.get('yara_rulesets', [])
    idx = next((i for i, r in enumerate(rulesets) if r.get('id') == ruleset_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "YARA ruleset not found."}), 404

    if request.method == 'DELETE':
        removed = rulesets.pop(idx)
        cfg['yara_rulesets'] = rulesets
        save_runtime_config(cfg)
        log_chain_of_custody("yara_ruleset_deleted", {"id": ruleset_id, "name": removed.get('name')})
        return jsonify({"success": True})

    req = request.get_json() or {}
    record, error = _yara_ruleset_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400
    # id is fixed at creation and never regenerated from a new name - a
    # rename must not invalidate a scan launcher's already-checked
    # yara_ruleset_ids selection or any other stored reference.
    record['id'] = ruleset_id
    record['created_at'] = rulesets[idx].get('created_at', record['updated_at'])
    rulesets[idx] = record
    cfg['yara_rulesets'] = rulesets
    save_runtime_config(cfg)
    log_chain_of_custody("yara_ruleset_updated", {"id": ruleset_id, "name": record['name']})
    return jsonify({"success": True, "ruleset": record})

@settings_bp.route('/api/network/auto_mounts', methods=['GET'])
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


@settings_bp.route('/api/network/auto_mounts/<entry_id>', methods=['DELETE'])
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

# /api/toggle_write_block, the whole /api/bitlocker/* cluster,
# /api/start_imaging, and /api/ddrescue/inspect_map now live in
# routes/acquisition.py - see the dated CLAUDE.md entry for this refactor.
# /api/start_ddrescue now lives in routes/acquisition.py - see the dated
# CLAUDE.md entry for this refactor.

# /api/mobile/devices, /api/mobile/ios/pair, /api/mobile/start_ios_backup,
# and /api/mobile/start_android now live in routes/mobile.py (registered as
# a Blueprint below) - see the dated CLAUDE.md entry for this refactor.

# /api/recovery/start_photorec, start_extundelete, start_foremost,
# start_scalpel, and start_triage_scan now live in routes/recovery.py
# (registered as a Blueprint below) - see the dated CLAUDE.md entry for
# this refactor.

# /api/stop_imaging and /api/progress now live in routes/acquisition.py
# (registered as a Blueprint below) - see the dated CLAUDE.md entry for
# this refactor.

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

@settings_bp.route('/api/system/diagnostics', methods=['POST'])
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
    # package=None (not apt): volatility3 is a pip package (see
    # requirements.txt), same as mvt above. `vol` itself has no --version
    # flag (confirmed live - it errors "unrecognized arguments"), so this
    # asks the venv's own pip instead - `pip show` output happens to already
    # fit the existing "prefer a 'Version:' line, else line 1" parsing logic
    # below with zero special-casing needed.
    {"tool": "volatility3", "cmd": [VOL3_PIP_BIN, "show", "volatility3"], "package": None},
    # package=None (not apt): mquire is built from source at install time
    # (see install.py's own MQUIRE_VERSION step) - no apt package exists for
    # it, and Trail of Bits publishes no binary releases either.
    {"tool": "mquire", "cmd": [MQUIRE_BIN, "--version"], "package": None},
    # package=None (not apt): UAC is vendored from a pinned GitHub release
    # tag (see install.py's own UAC_TAG step), no apt package exists for it.
    # Confirmed live it has a real --version flag (unlike several of this
    # app's other vendored shell-script tools) - but a real, live-caught
    # gotcha found while wiring this up: UAC's own script uses `pwd` (the
    # CALLER's current working directory), not its own script location, to
    # find its artifacts/bin/config/lib/profiles subdirectories - invoking
    # it via a bare absolute path from an arbitrary cwd fails with "Required
    # files not found," even though the binary itself runs fine. This
    # doesn't affect the real Live Collection USB feature at all (its own
    # on-USB launcher, live_collection_assets/run_collector.sh, already
    # `cd`s into UAC's own directory before invoking it), only this Tool
    # Versions check - wrapped in `sh -c 'cd ... && ...'` here rather than
    # adding a per-entry cwd= field to the shared, generic TOOL_VERSION_
    # COMMANDS/get_tool_versions() mechanism every other tool already uses
    # with no such need.
    {"tool": "UAC (Live Collection USB)",
     "cmd": ["sh", "-c", f"cd {os.path.join(INSTALL_DIR, 'live_collection', 'uac')} && ./uac --version"],
     "package": None},
    # package=None (not apt): sqlite-dissect is a pip package (see
    # requirements.txt), same MVT_BIN_DIR resolution as mvt-ios/mvt-android/
    # volatility3 above - it's a pip console-script, not on PATH under
    # gunicorn. Unlike volatility3/mvt, it DOES have a real, confirmed-
    # working -v/--version flag (its own --help documents it directly), so
    # no pip-show fallback is needed here.
    {"tool": "sqlite_dissect", "cmd": [os.path.join(MVT_BIN_DIR, "sqlite_dissect"), "--version"], "package": None},
    # package=None (not apt): androguard is a pip package (see
    # requirements.txt), same MVT_BIN_DIR resolution as the others above.
    # It has no confirmed --version CLI flag of its own, so this uses the
    # same pip-show fallback volatility3 already established.
    {"tool": "androguard", "cmd": [VOL3_PIP_BIN, "show", "androguard"], "package": None},
    # package=None (not apt): wa-crypt-tools is a pip package (see
    # requirements.txt), same MVT_BIN_DIR resolution as the others above.
    # `wadecrypt --version` has no real effect (confirmed live - it does
    # not print a version string, it errors trying to open its default
    # "encrypted" positional argument's file), so this uses the same
    # pip-show fallback volatility3/androguard already established.
    {"tool": "wa-crypt-tools", "cmd": [VOL3_PIP_BIN, "show", "wa-crypt-tools"], "package": None},
    # package=None (not apt): lief is a pip package (see requirements.txt),
    # imported directly by core/ipa_utils.py rather than shelled out to -
    # no CLI to check --version against at all, so this uses the same
    # pip-show fallback the other pip-installed tools above already use.
    {"tool": "lief", "cmd": [VOL3_PIP_BIN, "show", "lief"], "package": None},
    # package=None (not apt): dumpstate-py is installed via
    # `pip install git+https://...` pinned to a specific commit (see
    # install.py) - never on PyPI, no --version flag confirmed, so this
    # uses the same pip-show fallback the other pip-installed tools above
    # already use (works identically for a git-sourced install - pip
    # still records a real version string, e.g. "0.1.1.dev4+g56b70934f").
    {"tool": "dumpstate-py", "cmd": [VOL3_PIP_BIN, "show", "dumpstate-py"], "package": None},
    # 2026-08-30 tool-survey follow-up (5 more pip-only tools, same
    # pip-show fallback pattern established above - none has a --version
    # flag confirmed, and none is apt-installable).
    {"tool": "analyzeMFT", "cmd": [VOL3_PIP_BIN, "show", "analyzeMFT"], "package": None},
    {"tool": "python-registry", "cmd": [VOL3_PIP_BIN, "show", "python-registry"], "package": None},
    {"tool": "libpff-python", "cmd": [VOL3_PIP_BIN, "show", "libpff-python"], "package": None},
    {"tool": "py-tlsh", "cmd": [VOL3_PIP_BIN, "show", "py-tlsh"], "package": None},
    {"tool": "libvshadow-python", "cmd": [VOL3_PIP_BIN, "show", "libvshadow-python"], "package": None},
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

@settings_bp.route('/api/system/tool_versions', methods=['GET'])
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

@settings_bp.route('/api/system/install_tool', methods=['POST'])
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

@settings_bp.route('/api/system/change_password', methods=['POST'])
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

@settings_bp.route('/api/users/list', methods=['GET'])
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

@settings_bp.route('/api/users/create', methods=['POST'])
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

@settings_bp.route('/api/users/delete', methods=['POST'])
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

@settings_bp.route('/api/users/reset_password', methods=['POST'])
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

@settings_bp.route('/api/user_groups', methods=['GET', 'POST'])
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

@settings_bp.route('/api/user_groups/<group_id>', methods=['PUT', 'DELETE'])
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

@settings_bp.route('/api/system/tls_status', methods=['GET'])
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

@settings_bp.route('/api/system/tls_upload', methods=['POST'])
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

@settings_bp.route('/api/system/tls_generate', methods=['POST'])
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
@settings_bp.route('/api/system/tls_download_cert', methods=['GET'])
@requires_auth
def tls_download_cert():
    if not os.path.exists(TLS_CERT_PATH):
        return jsonify({"success": False, "error": "No certificate is currently installed."}), 404
    return send_file(TLS_CERT_PATH, as_attachment=True, download_name="pi-forensics.crt", mimetype="application/x-x509-ca-cert")

# --- Configuration Backup & Restore ---
# A single encrypted, passphrase-protected file capturing this station's own
# identity: runtime_config.json in full (user accounts + password hashes,
# groups, custom report templates, custom case fields, report branding
# defaults, network auto-mount share entries), the Fernet key those auto-mount
# entries' saved credentials are encrypted under (without it, restoring
# runtime_config.json alone would leave every saved share password/key as
# permanently undecryptable garbage - see core/config.py's _get_or_create_
# mount_key), and the report-branding logo file if one is configured. Meant
# for disaster recovery (a botched OS reinstall, a failed SD card) or cloning
# one station's accounts/templates onto a freshly-installed second one.
#
# Deliberately does NOT include the TLS private key: this app's own service
# account can't read it (root-only, chmod 600 - see core/config.py's
# TLS_KEY_PATH comment) without a new sudo grant just to serve a file back to
# the browser, and no route in this app has ever done that. A restored
# station regenerates or re-uploads its own certificate instead (Settings >
# Security > HTTPS Certificate, already fully self-service) - a disclosed,
# deliberate scope boundary, not an oversight.
#
# Encrypted with a passphrase the examiner supplies at backup time (PBKDF2-
# SHA256 -> Fernet), not this station's own mount key - the whole point is a
# file that's still meaningful once it's off this station (a USB stick, a
# second station), where the original mount key isn't available to derive
# from. File format: b"PIFB1" + 16-byte salt + Fernet token.
_BACKUP_MAGIC = b"PIFB1"
_BACKUP_KDF_ITERATIONS = 600_000

# Referenced as config.RUNTIME_CONFIG_FILE / config.MOUNT_KEY_FILE /
# config.INSTALL_DIR below, deliberately not via `from core.config import
# RUNTIME_CONFIG_FILE` like every other constant in this file - a bare
# `from X import CONSTANT` copies the value into this module's own namespace
# once, at import time, which is harmless for values that genuinely never
# change in production but breaks under a test suite that monkeypatches
# core.config's own attributes to redirect I/O at a temp file per test (this
# module's stale copy keeps pointing at the real path regardless). A real
# instance of exactly this bug was caught live by tests/test_config_backup.py
# on its first run against the deployed Pi: with RUNTIME_CONFIG_FILE/
# MOUNT_KEY_FILE still bare, a test run copied the *actual* production
# runtime_config.json/.mount_key into *.pre_restore_backup files sitting
# right next to them; with INSTALL_DIR still bare, a second pass silently
# overwrote the station's real report_logo.png (with identical bytes, since
# the same file was read then written back unchanged - no data was lost,
# but it's still a live-filesystem write a test run should never cause).
# Both fixed the same way: read through the config module object instead of
# a copied name. Same root cause as the active_proc bug already documented
# and fixed once in core/jobs.py during the app.py -> core/ + routes/ split
# - see that dated CLAUDE.md entry.

def _derive_backup_key(passphrase, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_BACKUP_KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))

@settings_bp.route('/api/settings/config_backup', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def config_backup():
    data = request.get_json(silent=True) or {}
    passphrase = data.get('passphrase') or ''
    if len(passphrase) < 8:
        return jsonify({"success": False, "error": "Choose a backup passphrase of at least 8 characters - you'll need it again to restore this file."}), 400

    manifest = {
        "version": 1,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "runtime_config": load_runtime_config(),
        "mount_key": None,
        "report_logo": None,
    }

    if os.path.exists(config.MOUNT_KEY_FILE):
        with open(config.MOUNT_KEY_FILE, 'r') as f:
            manifest["mount_key"] = f.read().strip()

    logo_matches = glob.glob(os.path.join(config.INSTALL_DIR, "report_logo.*"))
    if logo_matches:
        with open(logo_matches[0], 'rb') as f:
            manifest["report_logo"] = {
                "filename": os.path.basename(logo_matches[0]),
                "data_b64": base64.b64encode(f.read()).decode(),
            }

    salt = secrets.token_bytes(16)
    key = _derive_backup_key(passphrase, salt)
    token = Fernet(key).encrypt(json.dumps(manifest).encode('utf-8'))
    body = _BACKUP_MAGIC + salt + token

    log_chain_of_custody("config_backup_exported", {})
    filename = f"pi-forensics-backup-{time.strftime('%Y%m%d-%H%M%S')}.pfback"
    return send_file(io.BytesIO(body), as_attachment=True, download_name=filename, mimetype="application/octet-stream")

@settings_bp.route('/api/settings/config_restore', methods=['POST'])
@requires_auth
@requires_permission('manage_users')
def config_restore():
    backup_file = request.files.get('backup_file')
    passphrase = request.form.get('passphrase') or ''
    if not backup_file:
        return jsonify({"success": False, "error": "Choose a backup file to restore."}), 400
    if not passphrase:
        return jsonify({"success": False, "error": "Enter the passphrase this backup was created with."}), 400

    raw = backup_file.read()
    if not raw.startswith(_BACKUP_MAGIC) or len(raw) < len(_BACKUP_MAGIC) + 16:
        return jsonify({"success": False, "error": "This doesn't look like a Pi Forensics Suite backup file."}), 400

    salt = raw[len(_BACKUP_MAGIC):len(_BACKUP_MAGIC) + 16]
    token = raw[len(_BACKUP_MAGIC) + 16:]
    key = _derive_backup_key(passphrase, salt)
    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken:
        return jsonify({"success": False, "error": "Wrong passphrase, or this backup file is corrupted."}), 400

    try:
        manifest = json.loads(plaintext)
    except ValueError:
        return jsonify({"success": False, "error": "Backup file contents are corrupted."}), 400
    if manifest.get("version") != 1 or "runtime_config" not in manifest:
        return jsonify({"success": False, "error": "Unrecognized backup file format."}), 400

    # Never overwrite silently and irreversibly - the pre-restore state is
    # kept under a .pre_restore_backup suffix, matching this app's own
    # established non-destructive-migration convention (e.g. legacy case
    # format migration keeps originals under .pre_consolidation_backup).
    if os.path.exists(config.RUNTIME_CONFIG_FILE):
        shutil.copy2(config.RUNTIME_CONFIG_FILE, config.RUNTIME_CONFIG_FILE + ".pre_restore_backup")
    save_runtime_config(manifest["runtime_config"])

    if manifest.get("mount_key"):
        if os.path.exists(config.MOUNT_KEY_FILE):
            shutil.copy2(config.MOUNT_KEY_FILE, config.MOUNT_KEY_FILE + ".pre_restore_backup")
        with open(config.MOUNT_KEY_FILE, 'w') as f:
            f.write(manifest["mount_key"])
        os.chmod(config.MOUNT_KEY_FILE, 0o600)

    logo = manifest.get("report_logo") or {}
    if logo.get("filename") and logo.get("data_b64"):
        # Same-basename collision guard already established by the upload
        # route (upload_report_logo) doesn't apply here since we're writing
        # back the exact filename this backup itself recorded - just write it.
        with open(os.path.join(config.INSTALL_DIR, os.path.basename(logo["filename"])), 'wb') as f:
            f.write(base64.b64decode(logo["data_b64"]))

    log_chain_of_custody("config_restored", {"backup_created_at": manifest.get("created_at")})
    return jsonify({
        "success": True,
        "message": "Configuration restored. Your previous configuration was saved alongside it with a "
                    ".pre_restore_backup suffix. If your own account's credentials changed, you'll need to log back in.",
    })

# --- Settings > Case & Reporting (station-wide report export defaults,
# Report Template Builder CRUD, report branding logo) moved to
# routes/reporting.py, even though it's reached from the Settings tab -
# see the dated CLAUDE.md entry for this refactor.

@settings_bp.route('/api/system/power', methods=['POST'])
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

@settings_bp.route('/api/system/restart_service', methods=['POST'])
@requires_auth
@requires_permission('settings')
def restart_forensic_service():
    def delayed_restart():
        time.sleep(1)
        subprocess.run(['sudo', '/bin/systemctl', 'restart', 'pi-forensics.service'])

    threading.Thread(target=delayed_restart, daemon=True).start()
    return jsonify({"success": True, "message": "Forensic service restart initiated - this page will disconnect briefly."})

@settings_bp.route('/api/system/restart_kiosk', methods=['POST'])
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

@settings_bp.route('/api/system/check_update', methods=['GET'])
@requires_auth
@requires_permission('settings')
def check_for_update():
    """Read-only equivalent of git_update_application() below - `git fetch`
    then compare local HEAD against origin/main, never pull/merge anything.
    Gated behind the same 'settings' permission as the rest of this Updates
    section (not left open to every logged-in account) since only an account
    that can actually run the real update would ever act on this - which
    also means the auto-popup this powers on the frontend only ever fires
    for someone who can do something about it.

    A short, explicit timeout on both git calls matters here specifically:
    this station is frequently deployed with no internet access at all (see
    CLAUDE.md), and this route is polled periodically in the background from
    the frontend, not just on a manual click - a hung `git fetch` blocking
    that background poll indefinitely would be a real regression, not a
    theoretical one."""
    try:
        fetch_res = subprocess.run(
            ['git', 'fetch', 'origin', 'main', '--quiet'],
            cwd=INSTALL_DIR, capture_output=True, text=True, timeout=15,
        )
        if fetch_res.returncode != 0:
            err = fetch_res.stderr.strip() or "git fetch failed."
            return jsonify({"success": False, "error": err}), 502

        count_res = subprocess.run(
            ['git', 'rev-list', '--count', 'HEAD..origin/main'],
            cwd=INSTALL_DIR, capture_output=True, text=True, timeout=10,
        )
        try:
            commits_behind = int(count_res.stdout.strip()) if count_res.returncode == 0 else 0
        except ValueError:
            commits_behind = 0

        # Best-effort only - a missing/unreadable VERSION on the remote tip
        # (or the git show call itself failing) still reports
        # update_available correctly, just without a friendly version
        # string to show alongside the commit count.
        latest_version = None
        if commits_behind > 0:
            ver_res = subprocess.run(
                ['git', 'show', 'origin/main:VERSION'],
                cwd=INSTALL_DIR, capture_output=True, text=True, timeout=10,
            )
            if ver_res.returncode == 0 and ver_res.stdout.strip():
                latest_version = ver_res.stdout.strip()

        return jsonify({
            "success": True,
            "update_available": commits_behind > 0,
            "current_version": get_app_version(),
            "latest_version": latest_version,
            "commits_behind": commits_behind,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Timed out reaching the git remote (no internet access?)."}), 504
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@settings_bp.route('/api/system/git_update', methods=['POST'])
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

@settings_bp.route('/api/system/os_update', methods=['POST'])
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

@settings_bp.route('/api/system/eject_drive', methods=['POST'])
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

@settings_bp.route('/api/system/interfaces', methods=['GET'])
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

@settings_bp.route('/api/network/config', methods=['GET'])
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

@settings_bp.route('/api/network/apply', methods=['POST'])
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

@settings_bp.route('/api/network/confirm', methods=['POST'])
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

@settings_bp.route('/api/system/maintenance/purge_logs', methods=['POST'])
@requires_auth
@requires_permission('settings')
def purge_system_logs():
    update_job(log="[System log buffer purged by examiner.]")
    return jsonify({"success": True, "message": "Console log buffer cleared."})

@settings_bp.route('/api/system/toggle_keyboard', methods=['POST'])
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

# --- File Explorer core endpoints (browse/copy/delete/raw/preview_text/hex)
# moved to routes/file_explorer.py - see the dated CLAUDE.md entry for this
# refactor. /api/report/load and /api/report/save (below) stay here for now,
# reclassified into routes/reporting.py in a later step.
# --- Report Modifier & Attachment Endpoints ---
# /api/report/load and /api/report/save moved to routes/reporting.py -
# see the dated CLAUDE.md entry for this refactor.

# --- File Explorer analysis-tool actions (verify_hash, exif, stat_info,
# binwalk, clamscan, hashdeep, geolocation_kml, strings, quick_triage_scan,
# mvt_scan) moved to routes/file_explorer.py - see the dated CLAUDE.md entry
# for this refactor.
@settings_bp.route('/api/tools/mvt_update_iocs', methods=['POST'])
@requires_auth
# Found missing during the 2026-08-22 security audit - its sibling
# install_tool() above already requires this; this one let any
# authenticated account trigger a network fetch regardless of group.
@requires_permission('settings')
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
