"""Station-wide configuration constants and runtime_config.json I/O.

Pulled out of app.py's top-of-file block as part of splitting that
11,000+ line file into core/ (shared, cross-cutting) + routes/ (one
module per feature area) - pure code motion, no behavior change. See
the dated CLAUDE.md entry for this refactor for the full rationale.
"""
import os
import sys
import json
import html
import threading
import secrets
import markdown
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

# volatility3 ("vol") is the same kind of pip console-script as mvt-ios/
# mvt-android above - same MVT_BIN_DIR, same reasoning.
VOL3_BIN = os.path.join(MVT_BIN_DIR, "vol")
VOL3_PIP_BIN = os.path.join(MVT_BIN_DIR, "pip")

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

# Semantic version of this application (see CHANGELOG.md for what changed in
# each release, and `git tag -l` for the exact commit each version was cut
# from). Read from a plain VERSION file at the repo root - deliberately
# located via this module's own __file__, not INSTALL_DIR, so it resolves
# correctly both in production (INSTALL_DIR == the repo root, /opt/pi-
# forensics) and in a bare dev checkout on a machine that never set
# FORENSIC_INSTALL_DIR at all (this module has to import cleanly on a
# non-POSIX dev machine, unlike core/jobs.py). A missing/unreadable VERSION
# file (a stripped-down checkout, a packaging mistake) degrades to a clearly-
# marked placeholder rather than crashing app startup over a cosmetic value.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(_REPO_ROOT, "VERSION")

def get_app_version():
    try:
        with open(VERSION_FILE, 'r') as f:
            return f.read().strip() or "0.0.0-unknown"
    except Exception:
        return "0.0.0-unknown"


# Static, shipped-with-the-repo documentation viewable from inside the app
# (Help > User Manual/Quick-Start, Settings > Diagnostics > Release Notes) -
# so an examiner on an air-gapped station can read them without leaving the
# app or needing GitHub access. Same _REPO_ROOT-relative resolution as
# VERSION_FILE above, for the same reason (works in both production and a
# bare dev checkout). Deliberately a small fixed allowlist, not an arbitrary
# filename - the route reading this never accepts a client-supplied path.
DOC_FILES = {
    "quickstart": os.path.join(_REPO_ROOT, "docs", "quickstart.md"),
    "user-manual": os.path.join(_REPO_ROOT, "docs", "user-manual.md"),
    "changelog": os.path.join(_REPO_ROOT, "CHANGELOG.md"),
}


def get_doc_content(doc_id):
    """Returns the raw Markdown text for a known doc_id, or None if the id
    isn't recognized or the file can't be read (a stripped-down checkout,
    a packaging mistake) - the caller turns None into a clean 404 rather
    than this ever raising into a 500."""
    path = DOC_FILES.get(doc_id)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


DOC_TITLES = {
    "quickstart": "Quick-Start Guide",
    "user-manual": "User Manual",
    "changelog": "Release Notes",
}

# Self-contained inline CSS (no external stylesheet/font/CDN dependency) so
# these pages read correctly on a station with no internet access, matching
# every other doc/report this app produces (the exported HTML report is the
# same self-contained-on-purpose pattern). Palette/font-stack mirror the
# main app's own :root variables (templates/index.html) so the doc reads as
# part of the same product, not a jarring light-mode page bolted on.
_DOC_HTML_STYLE = """
:root {
    --bg-dark: #090b10; --card-bg: #131722; --border-color: #2e364f;
    --accent-cyan: #00f2fe; --text-bright: #ffffff; --text-subtle: #cbd5e1;
}
* { box-sizing: border-box; }
body {
    background: var(--bg-dark); color: var(--text-bright);
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    margin: 0; padding: 0;
}
.doc-topbar {
    position: sticky; top: 0; z-index: 10;
    background: linear-gradient(90deg, #07090e 0%, #161b26 100%);
    border-bottom: 1px solid var(--border-color);
    padding: 10px 24px; display: flex; align-items: center; gap: 10px;
}
.doc-topbar a { color: var(--accent-cyan); text-decoration: none; font-weight: 700; font-size: 0.85rem; }
.doc-topbar a:hover { text-decoration: underline; }
.doc-topbar .doc-topbar-title { color: var(--text-subtle); font-size: 0.85rem; margin-left: auto; }
article {
    max-width: 780px; margin: 0 auto; padding: 32px 24px 80px;
    line-height: 1.65; font-size: 1rem;
}
article h1, article h2, article h3, article h4 {
    color: var(--accent-cyan); font-weight: 700; line-height: 1.3;
    margin-top: 2em; margin-bottom: 0.6em;
}
article h1 { font-size: 1.9rem; margin-top: 0; border-bottom: 1px solid var(--border-color); padding-bottom: 0.4em; }
article h2 { font-size: 1.4rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.3em; }
article h3 { font-size: 1.15rem; color: var(--text-bright); }
article h4 { font-size: 1rem; color: var(--text-subtle); }
article p, article ul, article ol { color: var(--text-subtle); margin-bottom: 1em; }
article strong { color: var(--text-bright); }
article a { color: var(--accent-cyan); }
article ul, article ol { padding-left: 1.4em; }
article li { margin-bottom: 0.35em; }
article li > ul, article li > ol { margin-top: 0.35em; }
article code {
    background: var(--card-bg); border: 1px solid var(--border-color);
    border-radius: 4px; padding: 0.1em 0.4em; font-size: 0.88em;
    font-family: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
    color: #7dd3fc;
}
article pre {
    background: var(--card-bg); border: 1px solid var(--border-color);
    border-radius: 6px; padding: 14px 16px; overflow-x: auto; margin-bottom: 1.2em;
}
article pre code { background: none; border: none; padding: 0; color: var(--text-bright); }
article blockquote {
    border-left: 3px solid var(--accent-cyan); margin: 1.2em 0; padding: 0.4em 1em;
    background: rgba(0, 242, 254, 0.06); color: var(--text-subtle);
}
article blockquote p:last-child { margin-bottom: 0; }
article table { border-collapse: collapse; width: 100%; margin-bottom: 1.4em; font-size: 0.92rem; }
article th, article td { border: 1px solid var(--border-color); padding: 8px 12px; text-align: left; vertical-align: top; }
article th { background: var(--card-bg); color: var(--accent-cyan); }
article tr:nth-child(even) td { background: rgba(255,255,255,0.02); }
article hr { border: none; border-top: 1px solid var(--border-color); margin: 2em 0; }
"""


def render_doc_html(doc_id):
    """Renders a known doc_id's Markdown into a full, self-contained styled
    HTML page. Returns None (same contract as get_doc_content()) when the
    id is unrecognized or the file can't be read, so the route can turn
    that into a clean 404. Markdown is trusted, first-party content shipped
    with the repo, never user-supplied - the html.escape() below is only
    for the page <title>, which is built from a fixed dict this module
    controls, not derived from the markdown text itself."""
    raw = get_doc_content(doc_id)
    if raw is None:
        return None
    body_html = markdown.markdown(raw, extensions=["extra", "sane_lists", "toc"])
    title = html.escape(DOC_TITLES.get(doc_id, "Documentation"))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - Pi Forensics Suite</title>
<style>{_DOC_HTML_STYLE}</style>
</head>
<body>
<div class="doc-topbar">
<a href="/">&larr; Back to Pi Forensics Suite</a>
<span class="doc-topbar-title">{title}</span>
</div>
<article>
{body_html}
</article>
</body>
</html>"""
