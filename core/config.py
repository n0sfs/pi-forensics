"""Station-wide configuration constants and runtime_config.json I/O.

Pulled out of app.py's top-of-file block as part of splitting that
11,000+ line file into core/ (shared, cross-cutting) + routes/ (one
module per feature area) - pure code motion, no behavior change. See
the dated CLAUDE.md entry for this refactor for the full rationale.
"""
import os
import re
import sys
import json
import html
import threading
import secrets
import tempfile
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

# mquire (Linux memory forensics, x86_64-only - see its own worker docstring
# in routes/file_explorer.py for why) is a compiled Rust binary, not a pip
# package - Trail of Bits publishes zero binary assets on any GitHub release
# (confirmed directly against the API before deciding this), so install.py
# builds it from source via the Debian-packaged cargo/rustc and drops the
# result here, inside the managed install tree - not a venv-relative path
# like MVT/Volatility3 above, since it's not part of that Python environment
# at all.
MQUIRE_BIN = os.path.join(INSTALL_DIR, "bin", "mquire")

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
        # os.open() with an explicit mode creates the file with that mode
        # atomically - no window where it briefly exists world/group-
        # readable before a later chmod() catches up (2026-08-22 security
        # audit, Informational finding, closed 2026-08-25). O_EXCL also
        # means a second process racing to create this same file (this
        # station runs gunicorn with a single worker, so that race can't
        # happen here today, but the code shouldn't assume it never will)
        # gets a clean FileExistsError instead of silently overwriting a
        # key another process already generated and started signing with.
        try:
            fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with open(SECRET_KEY_FILE, 'r') as f:
                return f.read().strip()
        with os.fdopen(fd, 'w') as f:
            f.write(key)
        return key

MOUNT_KEY_FILE = os.path.join(INSTALL_DIR, ".mount_key")
mount_key_lock = threading.Lock()

def _get_or_create_mount_key():
    with mount_key_lock:
        if os.path.exists(MOUNT_KEY_FILE):
            with open(MOUNT_KEY_FILE, 'rb') as f:
                return f.read().strip()
        key = Fernet.generate_key()
        # Same atomic-create-with-mode fix as _get_or_create_secret_key()
        # above, for the same reason - this key encrypts every saved
        # network-share password/SSH key in runtime_config.json, so the
        # same brief world/group-readable window mattered here too.
        try:
            fd = os.open(MOUNT_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            with open(MOUNT_KEY_FILE, 'rb') as f:
                return f.read().strip()
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
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
            # Write-to-temp-then-atomic-rename, not write-then-chmod - this
            # file holds password hashes and Fernet-encrypted network-mount
            # credentials, and unlike the two secret-key files above (create
            # once, ever), this one rewrites on *every* settings save, so a
            # plain open()-then-chmod() window would reopen every single
            # time, not just once at first boot (2026-08-22 security audit,
            # a third instance of the same Informational finding found while
            # fixing the other two, closed 2026-08-25). The temp file is
            # created with its final 0600 mode from the start (no window of
            # its own), and os.replace() is atomic on POSIX - whatever lands
            # at RUNTIME_CONFIG_FILE is always either the complete old
            # content or the complete new content, never a partial write and
            # never briefly world/group-readable, and always in the same
            # directory so the rename can't cross filesystems. mkstemp()
            # itself already creates the file atomically at mode 0600 (a
            # documented CPython guarantee), so no separate chmod is needed.
            tmp_dir = os.path.dirname(RUNTIME_CONFIG_FILE) or '.'
            fd, tmp_path = tempfile.mkstemp(dir=tmp_dir, prefix='.runtime_config_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(cfg, f, indent=2)
                os.replace(tmp_path, RUNTIME_CONFIG_FILE)
            except Exception:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                raise
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

# Station-wide known-good/known-bad hash lists (Settings > Case &
# Reporting) - checked at scan time by File Explorer's "Check Against
# Hash Lists" action and by Hash Manifest. Unlike keyword_lists/custom_
# report_templates (small, structured, stay fully inline in
# runtime_config.json), a hash list can run to thousands of lines - only
# metadata (id/name/algorithm/label/hash_count/timestamps) lives inline
# here; the actual hash values live in their own flat file under
# HASH_LISTS_DIR, one hash per line, matching the same "large blob
# gets its own file, only a path/id stored inline" precedent
# report_logo.<ext> already established for the branding logo.
def get_hash_lists():
    return load_runtime_config().get('hash_lists', [])

HASH_LISTS_DIR = os.path.join(INSTALL_DIR, "hash_lists")

def hash_list_file_path(list_id):
    return os.path.join(HASH_LISTS_DIR, f"{list_id}.txt")

def load_hash_list_sets(hash_list_ids):
    """Loads the requested hash lists' actual hash values into memory as
    {list_id: {"name", "label", "algorithm", "hashes": set(...)}} - lives in
    core/ (not routes/settings.py, where the CRUD routes for these lists
    live) since both routes/file_explorer.py's single-file Check-Against-
    Hash-Lists action and routes/image_browser.py's Hash Manifest cross-
    reference need it, and this app has no cross-blueprint import between
    routes/*.py modules anywhere (confirmed before writing this) - matches
    this project's own stated rule that anything more than one routes/*.py
    module needs belongs in core/. A missing/unreadable list file is
    skipped (not a fatal error for the caller's whole scan)."""
    if not hash_list_ids:
        return {}
    cfg = load_runtime_config()
    by_id = {r['id']: r for r in cfg.get('hash_lists', [])}
    result = {}
    for list_id in hash_list_ids:
        record = by_id.get(list_id)
        if not record:
            continue
        try:
            with open(hash_list_file_path(list_id)) as f:
                hashes = {line.strip().lower() for line in f if line.strip()}
        except OSError:
            continue
        result[list_id] = {"name": record["name"], "label": record.get("label", "known_bad"),
                            "algorithm": record["algorithm"], "hashes": hashes}
    return result

# Station-wide YARA rulesets (Settings > Case & Reporting, D3) - selectable
# at scan time by File Explorer's "Scan with YARA Rules" action. Unlike
# hash_lists (can run to thousands of lines, stored in a separate file per
# list), a YARA ruleset's rule text is typically a few KB at most, so it
# stays fully inline in runtime_config.json - same precedent as
# keyword_lists/custom_report_templates, no separate-file mechanism needed.
def get_yara_rulesets():
    return load_runtime_config().get('yara_rulesets', [])

def load_yara_ruleset_sources(ruleset_ids):
    """Loads the requested rulesets' {id: name} + rule text as a
    {ruleset_id: {"name", "rule_text"}} dict, ready to hand straight to
    yara.compile(sources=...) - lives in core/ (not routes/settings.py,
    where the CRUD routes live) for the same cross-blueprint reason
    load_hash_list_sets() above does: both routes/file_explorer.py's
    single-file "Scan with YARA Rules" action and routes/image_browser.py's
    in-image equivalent need it, and this app has no cross-blueprint import
    between routes/*.py modules anywhere. A ruleset id with no matching
    record is silently skipped (not a fatal error for the caller's scan)."""
    if not ruleset_ids:
        return {}
    by_id = {r['id']: r for r in load_runtime_config().get('yara_rulesets', [])}
    return {rid: {"name": by_id[rid]['name'], "rule_text": by_id[rid]['rule_text']}
            for rid in ruleset_ids if rid in by_id}

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
.doc-topbar .doc-topbar-title { color: var(--text-subtle); font-size: 0.85rem; font-weight: 700; }

/* Two-column layout (User Manual's table-of-contents / Release Notes'
   version list) - only present when render_doc_html() found real <h2>
   sections to link to; Quick-Start renders as a plain single column with
   neither of these wrapping it. */
.doc-layout { display: flex; align-items: flex-start; }
.doc-sidenav {
    width: 250px; flex: 0 0 250px;
    position: sticky; top: 48px; align-self: flex-start;
    max-height: calc(100vh - 48px); overflow-y: auto;
    border-right: 1px solid var(--border-color);
    padding: 24px 12px 40px;
}
.doc-sidenav-title {
    text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.6px;
    color: var(--text-subtle); font-weight: 700; padding: 0 10px 10px;
}
.doc-sidenav a {
    display: block; padding: 7px 10px; border-radius: 5px;
    color: var(--text-subtle); text-decoration: none; font-size: 0.85rem;
    font-weight: 600; line-height: 1.35; margin-bottom: 1px;
}
.doc-sidenav a:hover { background: rgba(255,255,255,0.05); color: var(--text-bright); }
.doc-sidenav a.active { background: rgba(0, 242, 254, 0.09); color: var(--accent-cyan); }

/* Release Notes' collapsible version entries - native <details>/<summary>,
   no JS required for the expand/collapse itself (only for auto-opening one
   on a left-nav click / deep link, and for highlighting the active nav
   item - see _DOC_NAV_SCRIPT). Most recent version ships with the `open`
   attribute; every other version starts collapsed. */
.doc-entry {
    border: 1px solid var(--border-color); border-radius: 8px;
    margin-bottom: 14px; overflow: hidden; background: rgba(255,255,255,0.015);
}
.doc-entry > summary {
    cursor: pointer; padding: 14px 18px; list-style: none;
    display: flex; align-items: center; gap: 10px;
    background: rgba(255,255,255,0.025);
}
.doc-entry > summary::-webkit-details-marker { display: none; }
.doc-entry > summary::before {
    content: "\25B8"; color: var(--accent-cyan); font-size: 0.9em;
    display: inline-block; transition: transform 0.15s ease; flex-shrink: 0;
}
.doc-entry[open] > summary::before { transform: rotate(90deg); }
.doc-entry > summary h2 { margin: 0; padding: 0; border: none; font-size: 1.1rem; display: inline; }
.doc-entry > .doc-entry-body { padding: 2px 18px 20px; }
.doc-entry > .doc-entry-body > *:first-child { margin-top: 0; }

article {
    flex: 1; min-width: 0;
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

@media (max-width: 767.98px) {
    .doc-layout { flex-direction: column; }
    .doc-sidenav {
        width: 100%; flex: 0 0 auto; position: static; max-height: none;
        border-right: none; border-bottom: 1px solid var(--border-color);
        padding: 14px 16px;
    }
}
"""


# Every top-level <h2 id="..."> the toc extension produced, in document
# order - the single source both the left-nav links and (for Release
# Notes only) the collapsible-entry rewrap below are built from, so the
# two can never drift out of sync with each other.
_H2_RE = re.compile(r"<h2([^>]*)>(.*?)</h2>", re.S)


def _split_html_by_h2(body_html):
    """Splits rendered HTML at each top-level <h2> boundary. Returns
    (intro_html, sections) - intro_html is everything before the first
    <h2> (verbatim, untouched); sections is a list of dicts, one per <h2>
    found, each {"id", "heading_html" (the full <h2>...</h2> tag, used
    as-is inside a <summary> so its own id stays the real anchor target -
    no second id is ever introduced), "heading_text" (tags stripped, for
    the left-nav link label), "body_html" (everything up to the next <h2>,
    or end of document for the last one)}."""
    matches = list(_H2_RE.finditer(body_html))
    if not matches:
        return body_html, []
    intro_html = body_html[:matches[0].start()]
    sections = []
    for i, m in enumerate(matches):
        attrs, inner = m.group(1), m.group(2)
        id_match = re.search(r'id="([^"]*)"', attrs)
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body_html)
        sections.append({
            "id": id_match.group(1) if id_match else None,
            "heading_html": m.group(0),
            "heading_text": re.sub(r"<[^>]+>", "", inner).strip(),
            "body_html": body_html[m.end():end],
        })
    return intro_html, sections


# This is what actually opens a collapsed Release Notes entry when its
# left-nav link is clicked or a deep link is followed - relying on modern
# browsers' own "auto-open a closed <details> ancestor of a navigated-to
# fragment" behavior alone was tried and did NOT reliably fire in live
# testing, so this is load-bearing, not just a nice-to-have polish layer.
# Also adds the active-nav-item highlight, which has no native equivalent.
#
# Real bug caught live: version ids like "100-2026-08-22" start with a
# digit, which is syntactically INVALID as a bare CSS id-selector
# ("#100-..." throws "not a valid selector", confirmed directly) - the
# original version of this script used document.querySelector(hash) inside
# a try/catch that silently swallowed exactly that exception, so the whole
# auto-expand feature quietly no-op'd for every single changelog entry.
# getElementById() has no such restriction (ids are looked up as plain
# strings, never parsed as a selector) - use that instead of querySelector
# for anything derived from a fragment/hash.
_DOC_NAV_SCRIPT = """
<script>
(function() {
    function activate() {
        var hash = location.hash;
        var links = document.querySelectorAll('.doc-sidenav a');
        links.forEach(function(a) {
            a.classList.toggle('active', a.getAttribute('href') === hash);
        });
        if (!hash) { if (links[0]) links[0].classList.add('active'); return; }
        var target = document.getElementById(hash.slice(1));
        if (!target) return;
        for (var el = target; el; el = el.parentElement) {
            if (el.tagName === 'DETAILS') el.open = true;
        }
        target.scrollIntoView();
    }
    window.addEventListener('hashchange', activate);
    activate();
})();
</script>
"""


def render_doc_html(doc_id):
    """Renders a known doc_id's Markdown into a full, self-contained styled
    HTML page. Returns None (same contract as get_doc_content()) when the
    id is unrecognized or the file can't be read, so the route can turn
    that into a clean 404. Markdown is trusted, first-party content shipped
    with the repo, never user-supplied - the html.escape() below is only
    for the page <title>/left-nav labels, which are either a fixed dict
    this module controls or tag-stripped heading text from that same
    trusted source, not user-submitted content.

    Release Notes and the User Manual additionally get a left-hand nav
    built from their own <h2> sections (Versions / Contents respectively);
    Release Notes' sections are also rewrapped into collapsible <details>,
    most-recent-first-and-open, everything else collapsed. Quick-Start has
    no <h2> sections worth a nav for and renders as a plain single column,
    unchanged."""
    raw = get_doc_content(doc_id)
    if raw is None:
        return None
    body_html = markdown.markdown(raw, extensions=["extra", "sane_lists", "toc"])
    title = html.escape(DOC_TITLES.get(doc_id, "Documentation"))

    layout_open, sidenav_html, layout_close, script_html = "", "", "", ""

    if doc_id in ("changelog", "user-manual"):
        intro_html, sections = _split_html_by_h2(body_html)
        linkable = [s for s in sections if s["id"]]
        if linkable:
            nav_label = "Versions" if doc_id == "changelog" else "Contents"
            nav_links = "".join(
                f'<a href="#{s["id"]}">{html.escape(s["heading_text"])}</a>'
                for s in linkable
            )
            sidenav_html = f'<nav class="doc-sidenav"><div class="doc-sidenav-title">{nav_label}</div>{nav_links}</nav>'
            layout_open, layout_close = '<div class="doc-layout">', "</div>"
            script_html = _DOC_NAV_SCRIPT
            if doc_id == "changelog":
                entries = "".join(
                    f'<details class="doc-entry"{" open" if i == 0 else ""}>'
                    f'<summary>{s["heading_html"]}</summary>'
                    f'<div class="doc-entry-body">{s["body_html"]}</div>'
                    f"</details>"
                    for i, s in enumerate(sections)
                )
                body_html = intro_html + entries
            # user-manual: body_html is left exactly as rendered - only a
            # nav derived from its existing headings is added alongside it,
            # the flowing document itself is untouched.

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
<span class="doc-topbar-title">{title}</span>
</div>
{layout_open}{sidenav_html}
<article>
{body_html}
</article>
{layout_close}
{script_html}
</body>
</html>"""
