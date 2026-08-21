"""Station-wide configuration constants and runtime_config.json I/O.

Pulled out of app.py's top-of-file block as part of splitting that
11,000+ line file into core/ (shared, cross-cutting) + routes/ (one
module per feature area) - pure code motion, no behavior change. See
the dated CLAUDE.md entry for this refactor for the full rationale.
"""
import os
import sys
import json
import threading
import secrets
from cryptography.fernet import Fernet, InvalidToken

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

# Written by install.py's optional TLS setup (self-signed, via openssl) at
# a fixed path also hardcoded in nginx/pi-forensics.conf's ssl_certificate/
# ssl_certificate_key directives - keep all three in sync if this ever
# changes. The .crt is left world-readable by install.py (no explicit
# chmod), so this app can read/parse it directly with no sudo; the .key is
# root-only (chmod 600), never read directly - only replaced, via sudo.
TLS_CERT_PATH = "/etc/ssl/pi-forensics/pi-forensics.crt"
TLS_KEY_PATH = "/etc/ssl/pi-forensics/pi-forensics.key"

# Password changes made from the Advanced Settings tab are persisted here
# (0600, owned by the service account) so they survive a restart without
# requiring the examiner to edit the systemd unit. Falls back to
# FORENSIC_PASS above if this file doesn't exist yet.
RUNTIME_CONFIG_FILE = os.path.join(INSTALL_DIR, "runtime_config.json")
runtime_config_lock = threading.Lock()

# Symmetric key for encrypting auto-mount share credentials at rest (see
# "Auto-Connect Shares" below) - deliberately a separate file from
# runtime_config.json itself, so the key and the ciphertext it protects
# never sit in the same document. Lazily generated on first use (0600,
# service-account owned) rather than requiring an install.py step, so a
# station that only ever upgrades via `git pull` still gets one the first
# time this feature is used.
#
# Honest scope of what this protects: an examiner reconnecting a share
# unattended at boot means the decryption key MUST be locally readable by
# the same account doing the mounting - there is no human typing a
# passphrase at boot to gate access to it. This defends against casual
# plaintext exposure (someone reading runtime_config.json directly, a
# backup/screen-share leak, an accidental git-add), not against an
# attacker who already has root or physical disk access to this station -
# that limitation is inherent to any unattended auto-reconnect, not a gap
# specific to this implementation.
# Signs the Flask session cookie (see requires_auth()/the /login, /logout
# routes below). Persisted to disk, not generated fresh in memory each run,
# specifically so `systemctl restart pi-forensics` - this project's own
# routine step after nearly every deploy - doesn't silently log out every
# open browser tab by invalidating the signing key underneath them.
SECRET_KEY_FILE = os.path.join(INSTALL_DIR, ".flask_secret_key")
secret_key_lock = threading.Lock()

def _get_or_create_secret_key():
    with secret_key_lock:
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, 'r') as f:
                return f.read().strip()
        key = secrets.token_hex(32)
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)
        return key

MOUNT_KEY_FILE = os.path.join(INSTALL_DIR, ".mount_key")
mount_key_lock = threading.Lock()

def _get_or_create_mount_key():
    with mount_key_lock:
        if os.path.exists(MOUNT_KEY_FILE):
            with open(MOUNT_KEY_FILE, 'rb') as f:
                return f.read().strip()
        key = Fernet.generate_key()
        with open(MOUNT_KEY_FILE, 'wb') as f:
            f.write(key)
        os.chmod(MOUNT_KEY_FILE, 0o600)
        return key

def _encrypt_secret(plaintext):
    if not plaintext:
        return None
    return Fernet(_get_or_create_mount_key()).encrypt(plaintext.encode()).decode()

def _decrypt_secret(token):
    if not token:
        return ""
    try:
        return Fernet(_get_or_create_mount_key()).decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""

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

# Station-wide report export defaults and custom case-field definitions,
# both edited together from Settings > Case & Reporting. Stored in the same
# schema-agnostic runtime_config.json as the admin password/users above -
# load_runtime_config()/save_runtime_config() need no changes to support
# these additional top-level keys.
def get_report_defaults():
    return load_runtime_config().get('report_defaults', {})

def get_custom_case_fields():
    return load_runtime_config().get('custom_case_fields', [])

# Station-wide, examiner-defined keyword/regex lists (Settings > Case &
# Reporting) - selectable at scan time by Quick/Full Triage Scan, additive
# to the 5 built-in structured-data categories (see
# core/case_index_db.py's TRIAGE_PATTERNS/build_scan_patterns()). Same
# schema-agnostic runtime_config.json storage as everything else above.
def get_keyword_lists():
    return load_runtime_config().get('keyword_lists', [])

# Root directory that all file-explorer / report / attachment / imaging-destination
# endpoints are sandboxed to. Nothing outside this tree can be browsed, read,
# written, or deleted via the API, regardless of what path a client sends.
EVIDENCE_ROOT = os.path.realpath(os.environ.get('FORENSIC_ROOT', '/mnt'))

# Append-only chain-of-custody log path. The lock guarding writes to it lives
# in core/paths.py alongside log_chain_of_custody(), the only function that
# uses it - this is just the file-path constant.
COC_LOG_FILE = os.path.join(INSTALL_DIR, "chain_of_custody.log")

# Needed by both routes/acquisition.py (hash selection at acquisition time)
# and routes/file_explorer.py (verify_hash/hashdeep) - lives in core since
# more than one routes/*.py module needs it.
ALLOWED_HASH_ALGOS = {'md5', 'sha1', 'sha256'}
