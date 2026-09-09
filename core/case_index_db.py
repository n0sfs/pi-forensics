"""Per-case SQLite analysis index (tags, analysis results, triage hits) -
schema, connection helpers, and the batch tag/analysis-result lookups
needed by more than one routes/*.py module (routes/case_index.py,
routes/file_explorer.py, routes/image_browser.py, and routes/reporting.py's
export_report(), which calls _tags_for_paths()/_analysis_results_for_paths()
directly as plain Python functions, not via HTTP).

Part of the app.py -> core/ + routes/ split - pure code motion, no
behavior change. See the dated CLAUDE.md entry for this refactor.
"""
import os
import re
import json
import time
import sqlite3
import multiprocessing
import email.utils
from flask import g

from core.paths import safe_path, case_consolidated_path, classify_case_role, is_bulk_tool_output_dir
from core.config import get_keyword_lists
import core.config as config

# --- Quick Triage Scan: pattern definitions ---
# Deliberately built in-house rather than depending on bulk_extractor,
# which isn't in Debian's mainline archive (see README) - this needs no
# external tool at all, so it can never hit a "package not found" wall on
# any system this app runs on. Patterns are intentionally loose (especially
# the credit-card one) - a triage scan is meant to over-flag for a human to
# review, not to be a precise validator. Lives in core (not any one
# routes/*.py file) since it's needed by routes/recovery.py's
# execution_worker_triage_scan, routes/file_explorer.py's quick_triage_scan,
# routes/image_browser.py's execution_worker_image_triage_scan, and
# routes/case_index.py's summary/hits routes.
TRIAGE_PATTERNS = {
    "emails": re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    "urls": re.compile(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+'),
    "ip_addresses": re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'),
    "credit_card_numbers": re.compile(rb'\b(?:\d[ -]?){13,19}\b'),
    "phone_numbers": re.compile(rb'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
    # Same "loose pattern, over-flag for a human to review" philosophy as
    # credit_card_numbers above - neither is a strict validator. Bitcoin's
    # legacy/P2SH pattern is reasonably precise (base58 already excludes
    # 0/O/I/l); Bech32 doesn't verify the real checksum, just the charset/
    # length shape. Ethereum's pattern (0x + 40 hex chars) is genuinely loose
    # - any 40-hex-char string prefixed 0x matches, so this will false-
    # positive against unrelated hex blobs coincidentally starting with "0x"
    # far more than the other categories here - disclosed, not silently
    # shipped as precise.
    "btc_addresses": re.compile(rb'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b'),
    "eth_addresses": re.compile(rb'\b0x[a-fA-F0-9]{40}\b'),
}
TRIAGE_MAX_MATCHES_PER_CATEGORY = 50000  # protects memory on very large images
TRIAGE_CATEGORY_LABELS = {
    "emails": "Email Addresses", "urls": "URLs", "ip_addresses": "IP Addresses",
    "credit_card_numbers": "Credit Card-like Numbers", "phone_numbers": "Phone Numbers",
    "btc_addresses": "Bitcoin Addresses (Legacy/Bech32)", "eth_addresses": "Ethereum Addresses",
}

# --- Examiner-defined keyword lists (Settings > Case & Reporting) ---
# Selectable, additive scan categories on top of the 5 built-in ones above -
# closer to AXIOM's Keyword Lists. Every triage-scan worker
# (execution_worker_triage_scan, quick_triage_scan,
# execution_worker_image_triage_scan) already iterates whatever dict of
# {name: compiled_pattern} it's handed generically by name, with zero
# knowledge of what backs each entry - so build_scan_patterns() is the ONLY
# change any of them need: swap the module-level TRIAGE_PATTERNS constant
# for this function's return value, locally, and every downstream line
# (results/truncated dict construction, the finditer loop, the per-category
# report/log lines) keeps working unchanged. Internal keys use 'kw_<id>'
# (underscore, not the ':' a display label might use) since every worker
# also uses the key directly in an output filename
# (f"{name}.txt")/DB column - never assume '_'-only names are literal
# scan-category-derived, though; a keyword list's own id is already
# slug-shaped from _custom_report_template_from_payload()'s own precedent.
KEYWORD_CATEGORY_PREFIX = "kw_"

def build_scan_patterns(keyword_list_ids=None):
    """Returns {name: compiled_regex} - always the 5 built-in TRIAGE_PATTERNS,
    plus one compiled pattern per selected keyword list (get_keyword_lists()
    in core/config.py), keyed 'kw_<list_id>'. A list with no usable terms,
    whose terms fail to compile as a regex (only relevant when is_regex=True
    - a plain-term list is always safe, since every term is re.escape()'d),
    or whose combined pattern fails the ReDoS canary check below, is
    silently skipped rather than failing the whole scan - matches this app's
    established tolerance for a broken/stale config elsewhere over
    hard-failing a long-running job for it. keyword_list_ids is opt-in per
    scan (None/empty = built-ins only, unchanged from every call site's
    pre-existing behavior) - a keyword list is never force-included just
    because it exists.

    The ReDoS check runs here - once per scan job, when the pattern set is
    first assembled - rather than per chunk inside each scan worker's
    finditer() loop. This is deliberate, not a shortcut: it catches every
    caller (including a keyword list saved before this check existed, since
    there's no separate "already validated" flag to trust) with a single,
    genuinely robust subprocess-based check (see check_regex_pattern_for_
    redos()) instead of needing that heavier mechanism to also run at
    per-chunk frequency, which would add real overhead across a large scan
    for comparatively little extra safety - a pattern that's fast against
    the canary probes is essentially never going to develop catastrophic
    behavior only against longer real evidence data (backtracking blowup is
    a property of the pattern's structure, not the specific input)."""
    patterns = dict(TRIAGE_PATTERNS)
    if not keyword_list_ids:
        return patterns
    wanted = set(keyword_list_ids)
    for kw_list in get_keyword_lists():
        if kw_list.get('id') not in wanted:
            continue
        terms = [t for t in (kw_list.get('terms') or []) if t and t.strip()]
        if not terms:
            continue
        try:
            if kw_list.get('is_regex'):
                combined = '|'.join(f'(?:{t})' for t in terms)
            else:
                combined = '|'.join(re.escape(t) for t in terms)
            compiled = re.compile(combined.encode('utf-8'), re.IGNORECASE)
        except re.error:
            continue
        if kw_list.get('is_regex') and check_regex_pattern_for_redos(compiled) is not None:
            continue
        patterns[f"{KEYWORD_CATEGORY_PREFIX}{kw_list['id']}"] = compiled
    return patterns

# --- ReDoS defense for examiner-defined regex keyword-list patterns ---
# Found during the 2026-08-22 security audit: an is_regex=True keyword list
# (plain-term lists are always safe - every term is re.escape()'d) compiled
# fine but was never checked for catastrophic backtracking, and was then run
# via pattern.finditer() against raw, attacker-influenced evidence bytes
# with no bound on how long a single call could take - Python's re module
# has no built-in match timeout, and one bad pattern could hang this app's
# single shared job slot indefinitely, blocking every other acquisition/
# recovery job station-wide.
#
# The first version of this fix used a background THREAD (join(timeout),
# abandon if still alive) - the usual approach when signal.alarm() isn't an
# option (it only works in the main thread, and every scan worker here runs
# in its own background thread). That turned out to be actively unsafe, not
# just a partial mitigation: CPython's re engine runs its backtracking loop
# as a tight C-level loop that does not release the GIL, so an "abandoned"
# thread doesn't quietly leak in the background - it can starve the ENTIRE
# process of CPU time via the GIL, including the calling thread that
# supposedly already "got control back". This was caught empirically, not
# just reasoned about: testing the classic (a+)+ pattern against a 28-byte
# adversarial string hung the *entire test session*, not just one thread.
#
# The only way to genuinely reclaim CPU from a runaway backtracking match is
# to run it in a real, separate OS process that can be terminated - a
# thread cannot be forcibly killed in Python. check_regex_pattern_for_redos()
# below does exactly that (multiprocessing.Process + terminate()/kill() on
# timeout), and is deliberately kept to LOW-FREQUENCY call sites where a
# real process-spawn cost is a non-issue: save-time validation of a new/
# edited keyword list (routes/settings.py) and build_scan_patterns() itself
# (once per scan job, not per chunk - see that function's own docstring for
# why per-chunk frequency isn't needed once this gate exists there).
REDOS_PROBE_STRINGS = [
    b"a" * 32 + b"!",
    b"0" * 32 + b"!",
    b" " * 32 + b"!",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX",
]
# Prefer 'fork' when available (every real deployment - this app is Linux-
# only in production): the child inherits already-imported module state
# directly, so the timeout below mostly measures the actual regex match,
# not process startup. The default context on a fork-less platform
# (Windows, dev-only for this project) re-imports this whole module chain
# from scratch per probe - confirmed empirically to cost real, HIGHLY
# variable time under any concurrent system load (a full local test-suite
# run repeatedly outran even a 3-second budget, for probes that individually
# complete in well under a second in isolation), which without a much wider
# margin shows up as false positives - a perfectly safe pattern rejected
# only because process startup itself outran the timeout, nothing to do
# with the pattern being tested. So the timeout itself is platform-aware:
# tight and meaningful on fork (production), generous on the spawn-only
# fallback (Windows dev testing only) where the cost of extra margin is
# purely local-test wall-clock time, never examiner-facing latency.
try:
    _mp_ctx = multiprocessing.get_context('fork')
    REGEX_VALIDATION_TIMEOUT_SECONDS = 1.5  # per probe string
except ValueError:
    _mp_ctx = multiprocessing.get_context()
    REGEX_VALIDATION_TIMEOUT_SECONDS = 10.0  # per probe string - Windows spawn() overhead only

def _redos_probe_worker(pattern_bytes, flags, probe, out_queue):
    # Runs in the child process - re-compiles from the pattern's own source/
    # flags rather than trying to pass a compiled re.Pattern across the
    # process boundary, avoiding any doubt about whether that pickles
    # correctly.
    try:
        compiled = re.compile(pattern_bytes, flags)
        list(compiled.finditer(probe))
        out_queue.put(True)
    except Exception:
        out_queue.put(True)  # a compile/match error here isn't this check's concern

def check_regex_pattern_for_redos(compiled_pattern):
    """Runs compiled_pattern against REDOS_PROBE_STRINGS, each in its own
    subprocess with a short hard timeout - genuinely terminated (not just
    abandoned) if it runs long, so a catastrophic match can never starve
    this app's own process. Returns None if every probe finishes cleanly,
    or an error string describing the concern - meant to be surfaced
    directly to the examiner at save time, before the pattern is ever used
    against real evidence."""
    for probe in REDOS_PROBE_STRINGS:
        out_queue = _mp_ctx.Queue()
        proc = _mp_ctx.Process(
            target=_redos_probe_worker,
            args=(compiled_pattern.pattern, compiled_pattern.flags, probe, out_queue),
        )
        proc.start()
        proc.join(REGEX_VALIDATION_TIMEOUT_SECONDS)
        if proc.is_alive():
            proc.terminate()
            proc.join(1.0)
            if proc.is_alive():
                proc.kill()
                proc.join()
            out_queue.close()
            return ("This pattern is too slow against a simple test string and risks hanging a real scan "
                    "(catastrophic backtracking) - try simplifying it, e.g. avoiding nested repetition "
                    "like (x+)+ or overlapping alternation like (x|xx)+.")
        out_queue.close()
    return None

def resolve_scan_category_label(category):
    """Human label for a scan category name, for the report/log lines every
    triage-scan worker already writes - a built-in category (TRIAGE_
    CATEGORY_LABELS) or a keyword list's own saved name (re-derived at
    display time, not stored at scan time, so a later rename is reflected
    retroactively); a keyword list deleted since the scan ran still shows
    something meaningful rather than the raw internal key."""
    if category in TRIAGE_CATEGORY_LABELS:
        return TRIAGE_CATEGORY_LABELS[category]
    if category.startswith(KEYWORD_CATEGORY_PREFIX):
        list_id = category[len(KEYWORD_CATEGORY_PREFIX):]
        for kw_list in get_keyword_lists():
            if kw_list.get('id') == list_id:
                return kw_list.get('name', list_id)
        return f"Keyword List (deleted): {list_id}"
    return category

def case_index_db_path(case_dir):
    """Fixed per-case SQLite index path, e.g. <case_dir>/<slug>_case_index.db -
    same derivation as case_consolidated_path() (slug = the case folder's own
    basename), but unconditional (doesn't check the file exists yet - the DB
    is created lazily on first write via _case_index_connect()). The
    safe_path() re-check here is belt-and-suspenders only, matching
    create_case()'s own stated convention - `case_dir` is expected to already
    be a validated case folder by the time any caller reaches this point."""
    if not case_dir or not os.path.isdir(case_dir):
        return None
    slug = os.path.basename(case_dir.rstrip(os.sep))
    return safe_path(os.path.join(case_dir, f"{slug}_case_index.db"))

_CASE_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS indexed_files (
    id INTEGER PRIMARY KEY,
    image_path TEXT NOT NULL,
    fs_offset INTEGER NOT NULL,
    inode TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    extension TEXT,
    category TEXT NOT NULL,
    size INTEGER,
    deleted INTEGER NOT NULL,
    is_virtual INTEGER NOT NULL,
    mtime INTEGER, atime INTEGER, ctime INTEGER, crtime INTEGER,
    indexed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_cat ON indexed_files(category, deleted);
CREATE INDEX IF NOT EXISTS idx_files_image ON indexed_files(image_path);

CREATE TABLE IF NOT EXISTS triage_hits (
    id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL,
    image_path TEXT,
    fs_offset INTEGER,
    inode TEXT,
    path TEXT NOT NULL,
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    found_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hits_cat ON triage_hits(category);
CREATE INDEX IF NOT EXISTS idx_hits_image ON triage_hits(image_path);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL,
    notable INTEGER NOT NULL DEFAULT 0,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'none'
);
-- Seeded every time this schema runs (idempotent via INSERT OR IGNORE on the
-- UNIQUE name) - mirrors Autopsy's default tag set: Bookmark/Follow Up are
-- plain organizational tags, Notable Item is the one flagged `notable` (its
-- own examiner-facing meaning is "evidence of interest", surfaced with its
-- own icon/color everywhere a tag renders, same convention Autopsy uses it
-- for). A fresh case's tags table exists with these three the moment
-- anything first touches the index, tagging included - not gated behind an
-- image ever having been triage-scanned.
-- The remaining four defaults are never applied by an examiner clicking
-- Tag... - only by this app itself (see _auto_tag_case_artifact /
-- CASE_ROLE_TAG_NAMES below), one per classify_case_role() outcome, the
-- moment it generates a report export, hash manifest/analysis log,
-- geolocation KML, or a pre-consolidation/pre-restore backup snapshot -
-- self-classifying labels so File Explorer's File Views can group this
-- app's own housekeeping output apart from real evidence, split by kind,
-- without a separate mechanism. (Originally one lump 'Case Artifact' tag -
-- split into these four; see _migrate_legacy_case_artifact_tag below for
-- the one-time per-case migration off the old name.) 'Case Bundle Export'
-- is a genuinely separate fifth role, not a reuse of 'Backup Snapshot' -
-- classify_case_role() only recognizes the two exact
-- .pre_consolidation_backup/.pre_restore_backup suffixes as 'backup', which
-- a bundle zip's own timestamped filename never matches, so reusing that
-- tag would have silently no-op'd (confirmed before this was added).
INSERT OR IGNORE INTO tags (name, color, notable, is_default, created_at) VALUES
    ('Bookmark', 'info', 0, 1, datetime('now')),
    ('Follow Up', 'warning', 0, 1, datetime('now')),
    ('Notable Item', 'danger', 1, 1, datetime('now')),
    ('Report Export', 'secondary', 0, 1, datetime('now')),
    ('Analysis Log / Hash', 'secondary', 0, 1, datetime('now')),
    ('Geolocation Export', 'secondary', 0, 1, datetime('now')),
    ('Backup Snapshot', 'secondary', 0, 1, datetime('now')),
    ('Case Bundle Export', 'secondary', 0, 1, datetime('now'));

CREATE TABLE IF NOT EXISTS tagged_items (
    id INTEGER PRIMARY KEY,
    tag_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    image_path TEXT,
    fs_offset INTEGER,
    inode TEXT,
    path TEXT,
    name TEXT NOT NULL,
    comment TEXT,
    tagged_by TEXT,
    tagged_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tagged_items_tag ON tagged_items(tag_id);

-- Persists Binwalk/ClamAV/Strings tool output (previously ephemeral - shown
-- once in toolOutputModal and lost on close) so it can be cited as
-- documented analysis methodology and surfaced on a file's Exhibits entry
-- in the exported report. Shaped like tagged_items (same source_type/
-- image_path/fs_offset/inode/path/name identity columns) since a scan can
-- run against either a real filesystem file or an in-image entry.
CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL,
    image_path TEXT,
    fs_offset INTEGER,
    inode TEXT,
    path TEXT,
    name TEXT NOT NULL,
    tool TEXT NOT NULL,
    summary TEXT,
    output TEXT,
    run_by TEXT,
    run_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_path ON analysis_results(path);
CREATE INDEX IF NOT EXISTS idx_analysis_image ON analysis_results(image_path);

-- Real per-app artifact parsing (core/browser_artifacts.py) - Chrome/
-- Chromium History/Downloads/Bookmarks/Cookies, one row per parsed record
-- (a single visited URL, a single download, a single bookmark, a single
-- cookie), not one row per source file the way analysis_results is.
-- source_path is the History/Cookies/Bookmarks file this record came from;
-- extra_json holds whatever type-specific fields don't fit the generic
-- title/url/value/timestamp shape (visit_count, download state/bytes,
-- bookmark folder, cookie secure/httponly/expiry), kept as JSON rather than
-- a wide sparse column set since every artifact_type uses a different
-- subset.
CREATE TABLE IF NOT EXISTS parsed_artifacts (
    id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL,
    image_path TEXT,
    fs_offset INTEGER,
    inode TEXT,
    source_path TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    title TEXT,
    url TEXT,
    value TEXT,
    timestamp REAL,
    extra_json TEXT,
    found_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_parsed_artifacts_type ON parsed_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_parsed_artifacts_source ON parsed_artifacts(source_path);

-- Examiner-reviewed manual contact merges (2026-09-08) - the actionable
-- follow-up to correlate_contacts()'s own passive "possible_duplicate_keys"
-- hint. NEVER auto-populated - every row here was created by a real click
-- through /api/case_index/contacts/merge, with a required justification
-- note. primary_key/merged_key are whatever key space correlate_contacts()
-- itself uses (a normalized phone number, or a normalized email for an
-- email-only contact) - not a foreign key into any other table, since
-- "contacts" here are a computed, in-memory concept, not a real row
-- anywhere. UNIQUE(merged_key) is what keeps every merge a simple depth-1
-- pair rather than a chain - a contact can only ever be someone's "merged
-- child" once; the write-side route additionally refuses to let a key that's
-- already a merged_key become a primary_key (or vice versa) for exactly the
-- same reason - see case_index_merge_contacts()'s own comment for why a
-- chain would break correlate_contacts()'s one-hop remap-through logic. A
-- single primary_key CAN have multiple merged children (multiple rows
-- sharing one primary_key is fine and expected - e.g. one real person's
-- phone-only, WhatsApp-only, and email-only identities all folded into one
-- canonical entry).
CREATE TABLE IF NOT EXISTS contact_merges (
    id INTEGER PRIMARY KEY,
    primary_key TEXT NOT NULL,
    merged_key TEXT NOT NULL UNIQUE,
    justification TEXT NOT NULL,
    merged_by TEXT,
    merged_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_merges_primary ON contact_merges(primary_key);
"""

def _ensure_tags_severity_column(conn):
    """Adds `tags.severity` to a case index built before this feature
    shipped (2026-09-09) - `CREATE TABLE IF NOT EXISTS` in _CASE_INDEX_SCHEMA
    is a silent no-op against a table that already exists, so re-running the
    schema script alone never retrofits a new column onto an existing
    per-case tags table (any case that's ever been tagged before now).
    `PRAGMA table_info` is a cheap, in-memory metadata read (not a data
    scan), safe to call on every connect - the ALTER itself only actually
    runs once per case, the first time its DB is opened under this
    version."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(tags)").fetchall()}
    if 'severity' not in cols:
        conn.execute("ALTER TABLE tags ADD COLUMN severity TEXT NOT NULL DEFAULT 'none'")
        conn.commit()

def _case_index_connect(db_path):
    """Opens (creating if absent) the per-case analysis index, in WAL mode
    so a running scan job's writes and a concurrent File Explorer read don't
    block each other. Caller is responsible for closing the connection."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_CASE_INDEX_SCHEMA)
    _ensure_tags_severity_column(conn)
    return conn

# --- Case analysis index queries (read-only, File Explorer's File Views tree) ---
# Case-wide - deliberately query across every image_path in the case's index
# rather than filtering to one, so results cover every image that's ever been
# triage-scanned in the case, not just whichever one happens to be open right
# now. All three return graceful zero/empty results if the case has never
# been indexed (no DB file yet) rather than erroring - matches this app's
# "case selection optional, nothing breaks if none is active" convention.

def _case_index_open_readonly(case_folder):
    """Returns an open connection for read-only querying, or None if
    case_folder isn't a real consolidated case or has never been indexed
    (no DB file exists yet - not an error, just nothing to show)."""
    case_folder = safe_path(case_folder) if case_folder else None
    if not case_folder or not case_consolidated_path(case_folder):
        return None
    db_path = case_index_db_path(case_folder)
    if not db_path or not os.path.isfile(db_path):
        return None
    return _case_index_connect(db_path)

def _case_index_open_write(case_folder):
    """Like _case_index_open_readonly, but for actions that need to write
    (tagging) and so must be able to create the index DB on first use rather
    than requiring an image to have been triage-scanned first - tagging is a
    manual, image-scan-independent action. Still requires a real,
    consolidated case folder; returns None otherwise."""
    case_folder = safe_path(case_folder) if case_folder else None
    if not case_folder or not case_consolidated_path(case_folder):
        return None
    db_path = case_index_db_path(case_folder)
    if not db_path:
        return None
    return _case_index_connect(db_path)

# --- Unified evidence-item lookups: tags and persisted analysis results for
# a batch of real-filesystem paths at once (not one identity at a time like
# case_index_item_tags()/nothing, respectively) - shared by the Reporting >
# Files gallery (JSON round-trip) and export_report() (called directly,
# server-side, no round-trip). Both are read-only and always scoped to
# source_type='real_fs' - Exhibits/attachments are always real filesystem
# paths (already-extracted files), never in-image identities, so neither
# helper needs the image_path/fs_offset/inode branch case_index_item_tags()
# has to handle for File Explorer's own per-item lookups. ---

def _tags_for_paths(case_folder, paths):
    """Returns {path: [{id, name, color, notable, severity, comment}, ...]}
    for every real-fs path in `paths` that has at least one tag. Empty dict
    if the case isn't indexed/consolidated, or paths is empty - never an
    error. `severity` rides along here specifically so Reporting's Exhibits
    list (the one real "linked-finding record" a report actually exports)
    can surface a Critical/High-flagged tag on the exhibit itself, not just
    in the in-app File Views tree - the concrete gap this field exists to
    close (see ALLOWED_TAG_SEVERITIES's own docstring in routes/case_
    index.py)."""
    result = {}
    if not paths:
        return result
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return result
    try:
        placeholders = ",".join("?" * len(paths))
        cur = conn.execute(
            f"SELECT ti.path, t.id, t.name, t.color, t.notable, t.severity, ti.comment "
            f"FROM tagged_items ti JOIN tags t ON ti.tag_id=t.id "
            f"WHERE ti.source_type='real_fs' AND ti.path IN ({placeholders})",
            paths)
        for row in cur:
            result.setdefault(row[0], []).append(
                {"id": row[1], "name": row[2], "color": row[3], "notable": bool(row[4]),
                 "severity": row[5], "comment": row[6]})
    finally:
        conn.close()
    return result

def tagged_real_fs_paths_for_case(case_folder):
    """Returns the set of every real-fs path currently tagged in this case's
    index - used by add_case_note()'s own linked_files validation (2026-09-09)
    so a Case Note can reference something the examiner tagged Notable/
    Critical even before it's ever attached as a report exhibit, not just an
    already-attached one. Scoped to source_type='real_fs' only, matching
    _tags_for_paths()'s own identical scope - an in-image tagged item has no
    real on-disk path to link a note to until it's extracted (a separate,
    known gap). Empty set if the case isn't indexed/consolidated - never an
    error."""
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return set()
    try:
        cur = conn.execute("SELECT DISTINCT path FROM tagged_items WHERE source_type='real_fs'")
        return {row[0] for row in cur}
    finally:
        conn.close()

ANALYSIS_RESULT_MAX_PER_PATH = 5  # most recent N runs shown per exhibit - a documented history, not an unbounded log dump
ANALYSIS_RESULT_MAX_OUTPUT_CHARS = 20000  # caps one stored row - same capping discipline used throughout this app

def _analysis_results_for_paths(case_folder, paths):
    """Returns {path: [{tool, summary, run_by, run_at}, ...]} (most recent
    first, capped to ANALYSIS_RESULT_MAX_PER_PATH per path) for every
    real-fs path in `paths` that has at least one recorded analysis run.
    Deliberately omits the full `output` text here - the gallery/export only
    need the summary line; the full output was already shown in
    toolOutputModal at scan time and isn't re-fetched for this enrichment."""
    result = {}
    if not paths:
        return result
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return result
    try:
        placeholders = ",".join("?" * len(paths))
        cur = conn.execute(
            f"SELECT path, tool, summary, run_by, run_at FROM analysis_results "
            f"WHERE source_type='real_fs' AND path IN ({placeholders}) ORDER BY run_at DESC",
            paths)
        for row in cur:
            bucket = result.setdefault(row[0], [])
            if len(bucket) < ANALYSIS_RESULT_MAX_PER_PATH:
                bucket.append({"tool": row[1], "summary": row[2], "run_by": row[3], "run_at": row[4]})
    finally:
        conn.close()
    return result

def _record_analysis_result(case_folder, identity, tool, summary, output, run_by=None):
    """Best-effort persistence of one analysis-tool run, mirroring
    quick_triage_scan()'s exact optional/non-blocking case-index write
    pattern: `case_folder` is optional (None/invalid just means "don't
    persist"), and any failure here is swallowed and logged, never raised -
    a broken or locked index write must never turn a successful scan into a
    reported tool failure. `identity` is the same shape
    _resolve_tag_identity() produces: {source_type, image_path, fs_offset,
    inode, path, name}.

    run_by lets a caller running outside a Flask request context (a
    background-job worker thread, like the Volatility3/mquire memory-
    forensics scans) supply the username captured earlier - g is a
    request-context-bound proxy and raises "Working outside of application
    context" if touched from a thread that never received the HTTP request
    itself. This was a REAL, pre-existing bug (not something new to
    mquire): both memory-forensics workers already called this from their
    own background thread with no override, so the exception was silently
    caught by this function's own try/except below and printed as a
    warning - every "FAILED"/success analysis-result row either worker ever
    tried to record was silently dropped, confirmed live via a direct
    reproduction (a background thread calling this function really does
    raise RuntimeError on the bare `getattr(g, ...)` read) before deciding
    this needed a real fix, not just a mquire-specific workaround. Every
    other (synchronous, request-thread) caller of this function is
    unaffected - they never pass run_by, so the fallback below reads the
    exact same g.forensic_user they always have."""
    if not case_folder:
        return
    if not case_consolidated_path(case_folder):
        return
    db_path = case_index_db_path(case_folder)
    if not db_path:
        return
    try:
        conn = _case_index_connect(db_path)
        conn.execute(
            "INSERT INTO analysis_results (source_type, image_path, fs_offset, inode, path, name, tool, summary, output, run_by, run_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (identity["source_type"], identity.get("image_path"), identity.get("fs_offset"), identity.get("inode"),
             identity.get("path"), identity["name"], tool, summary, (output or "")[:ANALYSIS_RESULT_MAX_OUTPUT_CHARS],
             run_by if run_by is not None else getattr(g, 'forensic_user', None), time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: could not record analysis result ({tool}) to case index: {e}")

PARSED_ARTIFACTS_MAX_PER_SOURCE = 10_000  # backstop above core/browser_artifacts.py's own per-type caps combined

def _record_parsed_artifacts(case_folder, identity, records):
    """Persists a batch of records already parsed by core/browser_artifacts.py
    (each shaped {artifact_type, title, url, value, timestamp, extra}) - the
    write side of routes/file_explorer.py's/routes/image_browser.py's
    browser-artifact-parsing routes. `identity` describes the SOURCE FILE
    (the History/Cookies/Bookmarks file these records came from), same
    shape _record_analysis_result() takes minus 'name' (not needed here -
    every stored row already carries its own title/url).

    Re-scan safety: deletes this exact source_path's prior rows before
    inserting fresh ones, same pattern execution_worker_image_triage_scan()
    already uses for indexed_files/triage_hits - re-parsing the same
    History file (an examiner re-running the scan after copying a newer
    profile snapshot in) replaces its rows rather than duplicating them.
    Best-effort like every other case-index write in this module: a broken/
    locked index must never turn a successful parse into a reported
    failure. Returns the number of rows actually written (0 on any
    failure or if case_folder isn't real/active)."""
    if not case_folder or not case_consolidated_path(case_folder):
        return 0
    db_path = case_index_db_path(case_folder)
    if not db_path:
        return 0
    source_path = identity.get("path")
    found_at = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = _case_index_connect(db_path)
        conn.execute("DELETE FROM parsed_artifacts WHERE source_path=?", (source_path,))
        rows = [
            (identity["source_type"], identity.get("image_path"), identity.get("fs_offset"), identity.get("inode"),
             source_path, r["artifact_type"], r.get("title") or "", r.get("url") or "", r.get("value") or "",
             r.get("timestamp"), json.dumps(r.get("extra") or {}), found_at)
            for r in records[:PARSED_ARTIFACTS_MAX_PER_SOURCE]
        ]
        conn.executemany(
            "INSERT INTO parsed_artifacts (source_type, image_path, fs_offset, inode, source_path, artifact_type, "
            "title, url, value, timestamp, extra_json, found_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows)
        conn.commit()
        conn.close()
        return len(rows)
    except Exception as e:
        print(f"Warning: could not record parsed artifacts from {source_path} to case index: {e}")
        return 0

def _parsed_artifact_counts(case_folder):
    """Returns {artifact_type: count} for whatever's actually been parsed
    into this case's index so far (empty dict if never indexed) - feeds
    case_index_summary()'s response, which File Views' tree renders as a
    per-type child under a new 'Web Artifacts' category. Dynamically
    discovered (not a fixed key set like TRIAGE_PATTERNS) since which
    artifact_types exist depends entirely on what's actually been parsed -
    a case with only a Bookmarks file scanned never shows a chrome_cookies
    entry at all, rather than a permanent 0."""
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return {}
    try:
        return {row[0]: row[1] for row in conn.execute(
            "SELECT artifact_type, COUNT(*) FROM parsed_artifacts GROUP BY artifact_type")}
    finally:
        conn.close()


def has_case_analysis_activity(analysis_results_count, total_files, keyword_hit_total, parsed_artifact_counts, tags):
    """The Home tab's Guided Workflow checklist (main.js's refreshGuidedWorkflow())
    needs one boolean answering "has any analysis tool actually been run against
    this case yet" - this is that composite, factored out of routes/case_index.py's
    case_index_summary() as a plain function so it's unit-testable without a Flask
    app/DB (core.jobs, which routes/case_index.py needs to import at all, is
    POSIX-only and can't load on a Windows dev machine).

    Deliberately excludes the four self-applied "Case Artifact" role tags
    (Report Export / Analysis Log & Hash / Geolocation Export / Backup Snapshot,
    see classify_case_role()/CASE_ROLE_TAG_NAMES) from counting as activity -
    those get auto-tagged the instant ANY report/hash-manifest/KML/backup file
    exists, which would make a case that's only ever had an acquisition (never an
    examiner-run analysis action) look like it had tool activity too. Only a real
    examiner-applied tag (is_default=0) with at least one item under it counts.
    `tags` is the same list case_index_summary() already builds - dicts with
    `is_default` and `count` keys."""
    return bool(
        analysis_results_count > 0 or total_files > 0 or keyword_hit_total > 0
        or parsed_artifact_counts or any((not t['is_default']) and t['count'] > 0 for t in tags)
    )

# One default tag per classify_case_role() outcome - see the schema seed
# comment above for why this exists as four tags instead of one lump one.
CASE_ROLE_TAG_NAMES = {
    'report': 'Report Export',
    'analysis_log': 'Analysis Log / Hash',
    'geolocation': 'Geolocation Export',
    'backup': 'Backup Snapshot',
    'case_bundle': 'Case Bundle Export',
}

def _auto_tag_case_artifact(case_folder, file_path):
    """Applies the role-specific default tag (CASE_ROLE_TAG_NAMES, keyed by
    classify_case_role() of file_path's own name) to a real file this app
    itself just generated - a report export, hash manifest/analysis log,
    geolocation KML, or backup snapshot - so File Explorer's File Views tree
    and any future tag-aware view can find "everything this station
    produced for this case", split by kind, as easily as an examiner's own
    manually-tagged items. A no-op (not an error) if file_path's name isn't
    a recognized artifact - every real call site only ever passes a known
    one, but this makes the function safe to call speculatively too (see
    _backfill_case_artifact_tags below). Mirrors _record_analysis_result()'s
    best-effort, non-blocking contract exactly: case_folder being absent/
    not-a-real-case, or any DB error, is silently swallowed - a broken
    index write must never turn a successful export into a reported
    failure. Deduped the same way case_index_tag_item() dedupes a real_fs
    identity (by tag_id + path), so repeatedly overwriting the same export
    filename (this app's own documented convention - a report export
    always overwrites, never accumulates timestamped copies) tags it once,
    not once per re-export."""
    if not case_folder or not case_consolidated_path(case_folder):
        return
    tag_name = CASE_ROLE_TAG_NAMES.get(classify_case_role(os.path.basename(file_path)))
    if not tag_name:
        return
    db_path = case_index_db_path(case_folder)
    if not db_path:
        return
    try:
        conn = _case_index_connect(db_path)
        row = conn.execute("SELECT id FROM tags WHERE name=?", (tag_name,)).fetchone()
        if not row:
            return  # schema seed above didn't run for some reason - fail quiet, don't create a duplicate
        tag_id = row[0]
        existing = conn.execute(
            "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
            (tag_id, file_path)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO tagged_items (tag_id, source_type, image_path, fs_offset, inode, path, name, comment, tagged_by, tagged_at) "
                "VALUES (?,'real_fs',NULL,NULL,NULL,?,?,NULL,?,?)",
                (tag_id, file_path, os.path.basename(file_path), 'system', time.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: could not auto-tag case artifact {file_path}: {e}")

def carry_over_image_tags_to_extracted_file(case_folder, image_path, fs_offset, inode, extracted_path):
    """Tagging works identically on a real filesystem file and on a file
    still living inside an unmounted acquired image (source_type='image',
    keyed by image_path/fs_offset/inode) - but an in-image identity has no
    real on-disk path, so it could never reach an exhibit/export before this
    (a real, previously-disclosed gap). Called from routes/image_browser.py's
    /api/image/extract (2026-09-09) right after a genuinely new extraction
    succeeds: looks up every tag already applied to that exact in-image
    identity and re-applies each one (same tag_id, so name/color/notable/
    severity all come from the tag DEFINITION - nothing is re-derived or
    guessable-wrong) to the freshly-extracted real-fs path, closing the gap
    without needing a second, parallel tagging UI for images. Best-effort,
    non-fatal, matching _auto_tag_case_artifact()'s own established
    contract for exactly this class of side-effect-only helper - a case
    that isn't indexed, or an item with no tags at all, is a silent no-op,
    never an error that could turn a successful extraction into a reported
    failure. Returns the number of tags carried over (0 if none)."""
    try:
        conn = _case_index_open_readonly(case_folder)
        if not conn:
            return 0
        try:
            rows = conn.execute(
                "SELECT tag_id, comment FROM tagged_items WHERE source_type='image' "
                "AND image_path=? AND fs_offset=? AND inode=?",
                (image_path, fs_offset, str(inode))).fetchall()
        finally:
            conn.close()
        if not rows:
            return 0

        write_conn = _case_index_open_write(case_folder)
        if not write_conn:
            return 0
        carried = 0
        try:
            extracted_name = os.path.basename(extracted_path)
            tagged_by = getattr(g, 'forensic_user', None)  # a real request-thread call, g is genuinely valid here
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            for tag_id, comment in rows:
                existing = write_conn.execute(
                    "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
                    (tag_id, extracted_path)).fetchone()
                if existing:
                    continue  # already tagged (e.g. re-extracting the same file) - never a duplicate row
                write_conn.execute(
                    "INSERT INTO tagged_items (tag_id, source_type, image_path, fs_offset, inode, path, name, comment, tagged_by, tagged_at) "
                    "VALUES (?,'real_fs',NULL,NULL,NULL,?,?,?,?,?)",
                    (tag_id, extracted_path, extracted_name, comment, tagged_by, now))
                carried += 1
            write_conn.commit()
        finally:
            write_conn.close()
        return carried
    except Exception as e:
        print(f"Warning: could not carry over in-image tags to {extracted_path}: {e}")
        return 0

def _migrate_legacy_case_artifact_tag(conn):
    """One-time-per-case migration off the original single lump 'Case
    Artifact' tag (split into the four CASE_ROLE_TAG_NAMES tags above).
    Re-derives each already-tagged file's role from its own name (the same
    thing a fresh tag call would compute today) and moves its tagged_items
    row onto the correct new tag; a row whose name no longer classifies to
    a known role (shouldn't happen - only ever added by
    _auto_tag_case_artifact/_backfill_case_artifact_tags in the first
    place) is dropped rather than left dangling. Deletes the now-empty
    legacy tag afterward so it stops appearing as a permanent 0-count 5th
    bucket. No-op once no case has the old tag left. Caller owns the
    connection (opened only when the DB already exists - see
    _backfill_case_artifact_tags)."""
    old = conn.execute("SELECT id FROM tags WHERE name='Case Artifact'").fetchone()
    if not old:
        return
    old_id = old[0]
    for row_id, path, name in conn.execute(
            "SELECT id, path, name FROM tagged_items WHERE tag_id=?", (old_id,)).fetchall():
        new_name = CASE_ROLE_TAG_NAMES.get(classify_case_role(name or (os.path.basename(path) if path else '')))
        new_tag = conn.execute("SELECT id FROM tags WHERE name=?", (new_name,)).fetchone() if new_name else None
        if not new_tag:
            conn.execute("DELETE FROM tagged_items WHERE id=?", (row_id,))
            continue
        dupe = conn.execute(
            "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
            (new_tag[0], path)).fetchone()
        if dupe:
            conn.execute("DELETE FROM tagged_items WHERE id=?", (row_id,))
        else:
            conn.execute("UPDATE tagged_items SET tag_id=? WHERE id=?", (new_tag[0], row_id))
    conn.execute("DELETE FROM tags WHERE id=?", (old_id,))
    conn.commit()

# Every call site above tags a report export / hash manifest / geolocation
# KML the moment THIS app generates it - real, but forward-only: anything
# already on disk before that call site existed (or written some other way -
# a migrated legacy case, a manual copy) never gets caught. This sweep closes
# that gap by re-deriving the same answer from the filesystem itself instead
# of trusting whatever happened to get tagged at write time.
_ARTIFACT_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}  # extundelete's fixed output dir name
_ARTIFACT_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')  # bulk carved-file output - same skip-list convention as reporting.py's _discover_case_files()
_ARTIFACT_SCAN_MAX_FILES = 5000  # safety cap on one sweep - a case folder is typically small; only guards a pathological one

# Throttle, added 2026-09-01 after a real, live-measured performance bug -
# see _backfill_case_artifact_tags()'s own docstring below for the full
# story (a real 6+ minute case_index_summary() response, live-measured
# against this app's own long-lived production case folder).
_ARTIFACT_BACKFILL_INTERVAL_SECONDS = 300  # same interval/reasoning as core/auth.py's LAST_LOGIN_PERSIST_INTERVAL
_artifact_backfill_last_run = {}  # case_folder -> epoch seconds of last completed sweep, in-memory (resets on restart - a restart just means the next request re-sweeps once, harmless)


def _backfill_case_artifact_tags(case_folder):
    """Best-effort sweep: walk the case folder and apply the correct
    role-specific tag (CASE_ROLE_TAG_NAMES) to anything classify_case_role()
    recognizes but hasn't been tagged yet - self-heals those four buckets so
    they always reflect everything this app has ever generated for the
    case, not just what's been tagged since each individual write site
    started calling _auto_tag_case_artifact(). Also runs the one-time
    legacy-tag migration first (see _migrate_legacy_case_artifact_tag),
    but only if the case's index DB already exists - never eagerly creates
    one just to check, so a case with no artifacts yet and no prior index
    still gets no DB file, matching this module's existing laziness.

    Called from case_index_summary() on every fetch - THROTTLED to once per
    _ARTIFACT_BACKFILL_INTERVAL_SECONDS per case_folder (added 2026-09-01,
    same interval/reasoning as core/auth.py's LAST_LOGIN_PERSIST_INTERVAL).
    This function's own original docstring called the walk "cheap," which
    is true in isolation (a shallow os.walk() + a filename check per file),
    but that assumption broke down for real, not hypothetically: a live
    timing test against this app's own long-lived, heavily-test-populated
    production case folder measured case_index_summary() taking over 6
    MINUTES to respond - re-running this full walk on literally every File
    Views load, over a real NFS-backed evidence mount, at a scale this
    sweep's own 5000-file cap doesn't meaningfully bound once a case
    accumulates enough subfolders (each real directory listing over NFS
    costs real round-trip latency, independent of how few files are in it).
    The throttle preserves the exact same eventual-consistency guarantee
    (a file this sweep would have caught still gets tagged, just up to 5
    minutes later instead of on literally every single page load) while
    fixing the actual reported cost. Errors are swallowed exactly like
    every other best-effort write in this module - this must never break a
    File Views load."""
    if not case_folder or not case_consolidated_path(case_folder):
        return
    now = time.time()
    if now - _artifact_backfill_last_run.get(case_folder, 0) < _ARTIFACT_BACKFILL_INTERVAL_SECONDS:
        return
    _artifact_backfill_last_run[case_folder] = now  # set before the walk, not after - a slow sweep in flight must not let a concurrent request pile a second one on top of it
    try:
        db_path = case_index_db_path(case_folder)
        if db_path and os.path.isfile(db_path):
            conn = _case_index_connect(db_path)
            try:
                _migrate_legacy_case_artifact_tag(conn)
            finally:
                conn.close()
        scanned = 0
        for root, dirs, files in os.walk(case_folder):
            dirs[:] = [d for d in dirs if d not in _ARTIFACT_SCAN_SKIP_DIR_NAMES
                       and not d.endswith(_ARTIFACT_SCAN_SKIP_DIR_SUFFIXES)]
            for fname in files:
                if scanned >= _ARTIFACT_SCAN_MAX_FILES:
                    return
                scanned += 1
                if classify_case_role(fname):
                    _auto_tag_case_artifact(case_folder, os.path.join(root, fname))
    except Exception as e:
        print(f"Warning: case artifact backfill sweep failed for {case_folder}: {e}")


# --- Cross-case search (2026-08-26, gap-closing round) ---
# "Has this hash shown up in any OTHER case on this station?" - v1 scoped
# to exact hash-lookup only (unambiguous, high-value); free-text/keyword/
# tag cross-case search is an explicitly-deferred v2, not built here (fuzzy
# matching across cases needs its own relevance-ranking design this
# doesn't need). Reads each case's own case JSON directly rather than the
# per-case SQLite index - confirmed indexed_files has NO hash column at
# all (its schema is image_path/fs_offset/inode/path/name/extension/
# category/size/deleted/is_virtual/mtime/atime/ctime/crtime, above) -
# acquisition hashes live only in each case's own
# events[].computed_verification_hashes inside its case JSON, so there is
# nothing to migrate/index here, this just reads what's already on disk.
CROSS_CASE_SEARCH_MAX_CASES = 200
CROSS_CASE_SEARCH_MAX_RESULTS = 500


def list_case_folders():
    """Walks EVIDENCE_ROOT for every real case folder (both the modern
    consolidated {slug}_case.json schema and the legacy case_info.json one
    not yet migrated) - factored out of routes/case_management.py's
    list_cases() (which now just calls this and jsonify()s the result
    unchanged - pure code motion, zero behavior change) once this became a
    2nd caller (cross_case_hash_search() below), matching this project's
    own established bar for factoring something out of a single inline
    route body. Returns a list of dicts: {case_number, examiner,
    case_folder, created_at, notes, case_status, event_count, schema},
    sorted newest-created-first.

    Reads config.EVIDENCE_ROOT module-qualified (not a bare imported name)
    - the exact same "read through config.X, not a copied binding" fix
    already applied once before in this codebase (routes/settings.py's
    config-backup functions, after a bare import there caused a real test
    run to write to the live station's actual config files instead of a
    test temp dir) - here it's what makes this function's own new test
    suite able to genuinely redirect EVIDENCE_ROOT via monkeypatch."""
    root_dir = config.EVIDENCE_ROOT
    cases = []
    for root, dirs, files in os.walk(root_dir):
        # Bound the scan depth so this can't turn into a very slow crawl of
        # a huge or deeply-mounted evidence tree.
        depth = root[len(root_dir):].count(os.sep)
        if depth >= 6:
            dirs[:] = []
            continue

        # Prune known-never-a-case directories (recovery-tool bulk output,
        # NAS-internal trash folders) before descending into them - a real,
        # live-measured cost on this app's own deployed station (2026-09-05):
        # loose recovery-tool test output sitting directly under the
        # evidence root, never itself a case and never containing one
        # nested inside it, was still being fully walked on every single
        # call, each directory a real round-trip over what can be slow
        # network-attached storage. Deliberately does NOT reduce the depth-6
        # cap above to something shallower to "fix" this the easy way -
        # create_case() accepts an arbitrary parent_dir, so a real case can
        # legitimately be nested deeper than 1-2 levels, and a depth cut
        # would silently stop discovering those cases at all. This prune is
        # safe regardless of depth, since neither of these directory kinds
        # can ever contain a case marker.
        dirs[:] = [d for d in dirs if not is_bulk_tool_output_dir(d)]

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
                    "case_status": data.get('case_status') or 'Open',
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
                    "case_status": data.get('case_status') or 'Open',
                    "event_count": None,
                    "schema": "legacy",
                })
            except (json.JSONDecodeError, OSError):
                pass
            dirs[:] = []

    cases.sort(key=lambda c: c.get('created_at', ''), reverse=True)
    return cases


def cross_case_hash_search(hash_value):
    """Searches every case's own case JSON for an event whose
    computed_verification_hashes contains hash_value (case-insensitive
    exact match against any recorded algorithm's value). One corrupt/
    unreadable case JSON is skipped, not fatal to the whole search - the
    same per-case failure isolation list_case_folders() itself already has
    via its own try/except per case. Returns (results, truncated) where
    each result is {case_number, examiner, case_folder, evidence_id,
    algorithm, matched_hash}."""
    hash_value_lower = (hash_value or '').strip().lower()
    if not hash_value_lower:
        return [], False
    results = []
    truncated = False
    cases = list_case_folders()
    if len(cases) > CROSS_CASE_SEARCH_MAX_CASES:
        cases = cases[:CROSS_CASE_SEARCH_MAX_CASES]
        truncated = True
    for case in cases:
        if case.get('schema') != 'consolidated':
            continue  # legacy single-job reports have their own report JSON shape, out of scope for this pass
        case_file = case_consolidated_path(case['case_folder'])
        if not case_file:
            continue
        try:
            with open(case_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for event in data.get('events', []):
            hashes = event.get('computed_verification_hashes') or {}
            for algorithm, matched_hash in hashes.items():
                if isinstance(matched_hash, str) and matched_hash.strip().lower() == hash_value_lower:
                    results.append({
                        "case_number": case['case_number'], "examiner": case['examiner'],
                        "case_folder": case['case_folder'],
                        "evidence_id": event.get('case_metadata', {}).get('evidence_id')
                            or event.get('evidence_id') or '--',
                        "algorithm": algorithm, "matched_hash": matched_hash,
                    })
                    if len(results) >= CROSS_CASE_SEARCH_MAX_RESULTS:
                        return results, True
    return results, truncated


# --- Contact correlation (Android/iOS pattern-of-life, 2026-09-04) ---
# Cross-references every already-indexed contact source in a case against
# every already-indexed communication source, so a raw phone number/JID
# sitting in an SMS/call-log/WhatsApp record can be resolved to a real
# name - and, just as valuable, a number independently confirmed by more
# than one contact source (the phone's own contacts AND WhatsApp's own
# contacts both naming the same number "Jane Doe") is itself a real
# corroboration signal worth surfacing.
#
# Deliberately read-only against the already-indexed parsed_artifacts
# table (like Evidence Timeline - core/case_index_db.py has no write path
# here at all): never mutates an already-recorded evidentiary row, and
# needs no new schema/table, matching this app's "compute a case-wide
# report fresh from the existing index, don't touch original data"
# convention already established by /api/cases/timeline.
#
# Scoped to contact types and communication types whose real extra_json
# shape is directly grounded in this app's own already-shipped, already-
# tested parser code (core/android_artifacts.py, core/android_companion_
# *_utils.py, core/android_backup_utils.py, core/mobile_artifacts.py,
# core/apple_export_utils.py/core/takeout_utils.py, core/whatsapp_utils.py)
# - every one of them stores a real phone-number-shaped string (or, for
# android_companion_contact, a real ContactsContract mimetype-gated value)
# in a known extra_json key. Still deliberately EXCLUDES every leapp_*
# contact/communication type NOT individually curated below (chiefly the
# generic leapp_module_finding fallback bucket, and any curated module
# whose own real column names were never individually confirmed) - those
# store ALEAPP's own raw TSV columns generically under extra_json["row"]
# with no way to know in advance which real column holds a phone number,
# so guessing here risks silently matching the wrong field. The curated
# leapp_contact/leapp_whatsapp_contact/leapp_sms_message/leapp_mms_
# message/leapp_call_log/leapp_whatsapp_message/leapp_whatsapp_call_log
# types ARE now correlated (2026-09-08, closing a real, previously-
# disclosed gap - see LEAPP_CONTACT_TYPES/LEAPP_COMM_TYPES further down
# this file), via their own dedicated extraction shape rather than being
# forced into this dict, since every real column name they read was
# individually confirmed against this app's own pinned ALEAPP source
# first, the same discipline core/leapp_tsv_utils.py's own LEAPP_
# TIMESTAMP_COLUMNS already established.
# emails_key (2026-09-07) - confirmed directly by reading each parser's own
# extra_json construction, not assumed uniform: android_contact/apple_
# contact/takeout_contact/mobile_contact all already store a real "emails"
# list right alongside "phones" in the exact same record (core/android_
# artifacts.py, core/apple_export_utils.py's parse_vcard_file(), core/
# mobile_artifacts.py) - a phone-known and email-known identity for the
# same real person are very often literally the same row, which is what
# makes phone/email entity-linking below possible with no new join at all
# for these four. whatsapp_contact genuinely has no email concept in its
# own source table (extra is only {"jid", "number"}) - correctly given no
# emails_key, not an oversight. android_companion_contact is deliberately
# NOT in this dict at all - unlike the five below, it's one record per
# ContactsContract.Data ROW (phone_v2/email_v2/... each their own row),
# not one per real person, so it doesn't fit this dict's "one row IS one
# contact" shape. It's handled by its own dedicated grouping pass inside
# correlate_contacts() instead (2026-09-08), which groups every row
# sharing the same real extra["contact_id"] and links whatever phones/
# emails that group contains - closing what was a real, disclosed gap in
# an earlier pass (this source could only ever contribute a phone before,
# and had no companion-contact-specific entity linking at all).
CONTACT_CORRELATION_SOURCE_TYPES = {
    "android_contact": {"phones_key": "phones", "emails_key": "emails", "kind": "contact"},
    "apple_contact": {"phones_key": "phones", "emails_key": "emails", "kind": "contact"},
    "takeout_contact": {"phones_key": "phones", "emails_key": "emails", "kind": "contact"},
    "mobile_contact": {"phones_key": "phones", "emails_key": "emails", "kind": "contact"},
    "whatsapp_contact": {"phones_key": None, "single_key": "number", "kind": "contact"},
}
# The two real, stable ContactsContract.CommonDataKinds mimetype strings
# android_companion_contact rows carry - confirmed directly against core/
# android_companion_contacts_calllog_utils.py's own already-verified
# constants (CONTACTS_MIMETYPE_LABELS), not re-guessed here.
_COMPANION_CONTACT_PHONE_MIMETYPE = "vnd.android.cursor.item/phone_v2"
_COMPANION_CONTACT_EMAIL_MIMETYPE = "vnd.android.cursor.item/email_v2"
# direction_field/incoming_values/outgoing_values and duration_field below
# (2026-09-07) were each individually confirmed against the real parser
# source that writes extra_json for that exact artifact_type - not
# guessed from the artifact_type's name - since two genuinely different
# storage conventions are in play: android_sms_message/android_call_log/
# android_mms_message/mobile_*/whatsapp_* all store an ALREADY-RESOLVED
# string label under "direction" (e.g. "Incoming"/"Sent"), while the two
# .ab-backup-sourced types store the RAW numeric Telephony.*.MESSAGE_BOX_*
# code under "type"/"msg_box" instead (core/android_backup_utils.py never
# resolves it to a string before writing extra_json) - hence the mixed
# string/int value sets below. A row whose direction value isn't in
# either set (a Draft/Failed/Queued SMS, a Missed/Voicemail/Rejected/
# Blocked call) is correctly left unclassified rather than forced into
# incoming/outgoing - see _classify_comm_direction(). duration_field is
# only present on the 4 call-log-shaped types that actually carry a real
# per-row call duration in seconds; every other type has none to read.
CONTACT_CORRELATION_COMM_TYPES = {
    "android_sms_message": {
        "counterpart_key": "address", "channel": "SMS",
        "direction_field": "direction", "incoming_values": {"Inbox"}, "outgoing_values": {"Sent", "Outbox"},
    },
    "android_call_log": {
        "counterpart_key": "number", "channel": "Call",
        "direction_field": "direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
        "duration_field": "duration_seconds",
    },
    # android_mms_message's own "counterpart" field is already comma-joined
    # for a group MMS with more than one participant (core/android_
    # artifacts.py's ", ".join(counterpart_list)) - the shared counterpart-
    # splitting logic below (see the ", " check) resolves each real
    # participant separately rather than gluing two numbers into one bogus
    # digit string.
    "android_mms_message": {
        "counterpart_key": "counterpart", "channel": "MMS",
        "direction_field": "direction", "incoming_values": {"Inbox"}, "outgoing_values": {"Sent", "Outbox"},
    },
    "mobile_sms_message": {
        "counterpart_key": "counterpart", "channel": "SMS/iMessage",
        "direction_field": "direction", "incoming_values": {"Received"}, "outgoing_values": {"Sent"},
    },
    "mobile_call_log": {
        "counterpart_key": "address", "channel": "Call",
        "direction_field": "direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
        "duration_field": "duration_seconds",
    },
    "whatsapp_message": {
        "counterpart_key": "sender_jid", "channel": "WhatsApp Message",
        "direction_field": "direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
    },
    "whatsapp_call_log": {
        "counterpart_key": "caller_jid", "channel": "WhatsApp Call",
        "direction_field": "direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
        "duration_field": "duration_seconds",
    },
    # Companion-app relay (adb shell content query, non-rooted) - the exact
    # same real signal as the native rooted-parser types just above, just a
    # different extraction path (core/android_companion_sms_utils.py,
    # core/android_companion_contacts_calllog_utils.py). These two store the
    # resolved label under "type_label", not "direction".
    "android_companion_sms_message": {
        "counterpart_key": "address", "channel": "SMS",
        "direction_field": "type_label", "incoming_values": {"Inbox"}, "outgoing_values": {"Sent", "Outbox"},
    },
    "android_companion_call_log_entry": {
        "counterpart_key": "number", "channel": "Call",
        "direction_field": "type_label", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
        "duration_field": "duration_seconds",
    },
    # .ab (Android Backup File) - sourced SMS/MMS (core/android_
    # backup_utils.py). android_ab_mms_message's "addresses" field is a
    # genuine list (one string per MMS participant, not comma-joined) -
    # the shared list-vs-string handling below covers both shapes. Both
    # store the RAW numeric MESSAGE_BOX_* code under "type"/"msg_box",
    # never a resolved string label - confirmed directly against core/
    # android_backup_utils.py's own two separate label dicts (its
    # _SMS_TYPE_LABELS reads 1="Received"/2="Sent"/4="Outbox"; its
    # _MMS_MSG_BOX_LABELS reads 1="Inbox"/2="Sent"/4="Outbox" - a
    # genuinely different string at value 1 between the two, both
    # confirmed against real AOSP source in that module's own docstring -
    # but semantically identical for incoming/outgoing purposes, which is
    # why 1 maps to "incoming" for both despite the differing label text).
    "android_ab_sms_message": {
        "counterpart_key": "address", "channel": "SMS",
        "direction_field": "type", "incoming_values": {1}, "outgoing_values": {2, 4},
    },
    "android_ab_mms_message": {
        "counterpart_key": "addresses", "channel": "MMS",
        "direction_field": "msg_box", "incoming_values": {1}, "outgoing_values": {2, 4},
    },
}
# Email-address-keyed communication sources (2026-09-07) - a genuinely
# different identity space from the phone-keyed dict above (see
# CONTACT_CORRELATION_SOURCE_TYPES's own comment on emails_key for how the
# two get linked when the same contact-source row names both). Deliberately
# NOT the same spec shape as CONTACT_CORRELATION_COMM_TYPES - a phone-based
# comm row always has exactly one counterpart_key to read, but email_
# message's own From/To/Cc are raw RFC 2822 header strings needing real
# address parsing (email.utils.getaddresses(), not a naive split - see
# _extract_email_counterparts()'s own docstring for why), and android_
# companion_calendar_event's attendees are an already-structured list, not
# a header string at all - genuinely different extraction logic per type,
# dispatched by artifact_type inside that one function rather than forced
# into a shared spec shape that would fit neither well.
#
# Direction and duration are both deliberately NOT tracked for either type
# this pass, disclosed rather than guessed: an email_message row has no
# reliable way to know which of From/To/Cc is the device owner's OWN
# address (nothing in this app's data model records that), so "incoming
# vs outgoing" can't be inferred at all; a calendar event's own start/end
# time could in principle be summed as "time spent," but doing that
# correctly needs its own verified epoch/unit confirmation this pass
# didn't do - real, disclosed future work, not attempted here.
CONTACT_CORRELATION_EMAIL_COMM_TYPES = {
    "email_message": "Email",
    "android_companion_calendar_event": "Calendar Invite",
}
# --- ALEAPP/iLEAPP contact + communication correlation (2026-09-08) ---
# Closes this app's own single biggest previously-disclosed Pattern-of-
# Life gap (see the "Deliberately EXCLUDES every leapp_*" comment above,
# and core/leapp_tsv_utils.py's own docstring) - ALEAPP is what handles a
# non-rooted Android pull AND every iOS extraction, so excluding it meant
# Contact Correlation/the Relationship Graph showed close to nothing for
# the most common real-world phone acquisition path. Real column names
# below were confirmed the SAME way core/leapp_tsv_utils.py's own
# LEAPP_TIMESTAMP_COLUMNS dict already was - by reading each real, pinned-
# commit ALEAPP module's own source directly off the deployed station
# (smsmms.py, calllog.py/calllogs.py, contacts.py, WhatsApp.py), never
# guessed. Every leapp_* record stores its columns generically under
# extra["row"] (a {real TSV column name: value} dict - core/leapp_tsv_
# utils.py's own design), so this needs its own extraction shape entirely
# separate from CONTACT_CORRELATION_SOURCE_TYPES/CONTACT_CORRELATION_
# COMM_TYPES above (which assume a fixed, semantic extra_json key name
# every native parser already agrees on) - values are looked up by real
# column name, and more than one real module can feed the SAME
# artifact_type under a DIFFERENT column name for the same concept (e.g.
# two independently-authored real "Call Logs" modules), so counterpart_
# keys/direction_field below are tuples tried in order, first one
# actually PRESENT in that specific row wins - mirroring LEAPP_TIMESTAMP_
# COLUMNS's own established multi-candidate design exactly.
LEAPP_CONTACT_TYPES = {
    # contacts.py's own real query has NO contact-grouping id anywhere in
    # its TSV output (confirmed directly - its data_headers is Mimetype/
    # Data 1/Display Name/Phone Number/Email Address/Source File, nothing
    # else): one ROW per phone-OR-email ContactsContract.Data item, never
    # both on the same row, with no reliable way to link a phone-row to an
    # email-row for the same real contact the way android_companion_
    # contact's own extra["contact_id"] already lets it. Each row is
    # therefore indexed independently here (a phone-only OR email-only
    # entry per row, keyed off Display Name for the name) - two rows
    # coincidentally sharing the same real name still get the existing
    # possible_duplicate_keys hint for free below, just never a verified
    # Pass-3-style merge, which would be an unearned guess for this
    # specific source.
    "leapp_contact": {"row_phone_key": "Phone Number", "row_email_key": "Email Address", "row_name_key": "Display Name"},
    # get_whatsapp_contacts()'s own SQL already resolves to one clean value
    # per row (a real phone number, or the bare JID as a fallback when no
    # number is known) - single_key, no grouping needed, mirroring the
    # native whatsapp_contact spec above exactly.
    "leapp_whatsapp_contact": {"single_key": "Number", "row_name_key": "Name"},
}
LEAPP_COMM_TYPES = {
    "leapp_sms_message": {
        "counterpart_keys": ("Address",), "channel": "SMS",
        # smsmms.py's own get_sms_mms() writes the RAW Telephony.Sms.
        # MESSAGE_TYPE_* int straight from SQLite into 'Type' with zero
        # resolution (confirmed directly - no lookup dict wraps r['type']
        # the way MMS's own 'direction' does a few lines below it in the
        # same file) - the same raw-int convention this app's own
        # android_ab_sms_message already handles, just arriving here as a
        # STRING (every TSV cell is str()'d by ilapfuncs.py's own writer),
        # so the comparison sets below are strings, not ints.
        "direction_field": "Type", "incoming_values": {"1"}, "outgoing_values": {"2"},
    },
    # From/To/Cc/Bcc are 4 DIFFERENT real participants on the same row,
    # not 4 alternative names for one field - handled by a dedicated
    # branch in _extract_leapp_counterparts() below, not the shared
    # first-candidate-wins path every other entry here uses.
    "leapp_mms_message": {
        "counterpart_keys": ("From Address", "To Address", "Cc", "Bcc"), "channel": "MMS",
        "direction_field": "Direction", "incoming_values": {"Inbox"}, "outgoing_values": {"Sent", "Outbox"},
    },
    "leapp_call_log": {
        "counterpart_keys": ("Partner", "number"), "channel": "Call",
        # Only calllogs.py's own 'direction' column is used - a clean,
        # already-resolved "Incoming"/"Outgoing"/"" string (confirmed
        # directly). calllog.py's sibling 'Type' column also carries a
        # real resolved label but with an HTML <i data-feather=...> icon
        # tag string appended to it (confirmed directly in its own
        # source, e.g. "Incoming <i data-feather=\"phone-incoming\" ...")
        # - not a clean exact-match value, and deliberately not used here
        # rather than guess at parsing it out; a calllog.py-sourced row's
        # direction stays correctly unclassified (None) rather than risk
        # a wrong match. Counterpart resolution is unaffected either way,
        # since 'Partner'/'number' are both clean phone-number values.
        "direction_field": "direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
    },
    "leapp_whatsapp_message": {
        # 'Recipients' (get_whatsapp_messages(), comma-joined via that
        # module's own SQL group_concat - the existing comma-splitter
        # already handles this shape) vs 'Sending Party JID'
        # (get_whatsapp_one_to_one_messages()/get_whatsapp_group_
        # messages()) - all 3 real modules confirmed directly, all 3 feed
        # this one artifact_type per CURATED_LEAPP_MODULES.
        "counterpart_keys": ("Sending Party JID", "Recipients"), "channel": "WhatsApp Message",
        "direction_field": ("Message Direction", "Direction"),
        "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
    },
    "leapp_whatsapp_call_log": {
        "counterpart_keys": ("Caller JID",), "channel": "WhatsApp Call",
        "direction_field": "Call Direction", "incoming_values": {"Incoming"}, "outgoing_values": {"Outgoing"},
        # Call Duration is a real value here (get_whatsapp_call_logs()'s
        # own 'Call Duration' column) but stored as an HH:MM:SS string
        # (strftime('%H:%M:%S', duration, 'unixepoch'), confirmed
        # directly) - a genuinely different format from every other
        # duration_field in this app (always raw integer seconds), not
        # parsed this pass - disclosed, not silently guessed at.
        # Counterpart/direction resolution (the higher-value signal) is
        # unaffected either way.
    },
}


def _leapp_row_value(row, keys):
    """Tries each candidate real TSV column name in `keys` (a single
    string or tuple of strings) against one leapp_*-sourced row's own
    extra["row"] dict, in order - the first one actually present with a
    real non-empty value wins. More than one real ALEAPP/iLEAPP module
    can feed the same artifact_type under a different literal column name
    for the same concept (see LEAPP_COMM_TYPES's own comments for
    confirmed examples), mirroring core/leapp_tsv_utils.py's own
    LEAPP_TIMESTAMP_COLUMNS multi-candidate design exactly. Returns None,
    never a guessed/fabricated value, when none of the candidates are
    present or all are empty."""
    if isinstance(keys, str):
        keys = (keys,)
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return value
    return None


def _extract_leapp_counterparts(artifact_type, spec, row):
    """Returns every raw counterpart candidate string for one leapp_*
    comm row. leapp_mms_message is a real, disclosed exception to the
    usual "first candidate column present wins" rule: its 4 candidate
    columns (From/To/Cc/Bcc Address) are 4 DIFFERENT real participants on
    the same row, not 4 alternative names for one field - every one of
    them that's actually populated contributes its own separate
    candidate, the same "union every real participant, never glue two
    into one bogus string" principle _extract_raw_counterpart_
    candidates() already established for a comma-joined field. Every
    other type here uses that shared splitter against whichever single
    candidate column _leapp_row_value() found present (which itself
    already handles a comma-joined value, e.g. leapp_whatsapp_message's
    own 'Recipients')."""
    if artifact_type == "leapp_mms_message":
        return [row[k] for k in spec["counterpart_keys"] if row.get(k) and str(row[k]).strip()]
    return _extract_raw_counterpart_candidates(_leapp_row_value(row, spec["counterpart_keys"]))


def _classify_leapp_comm_direction(spec, row):
    """The leapp_* row-dict equivalent of _classify_comm_direction()
    above - kept as its own small function rather than reusing that one
    directly, since a leapp_* spec's direction_field can be a tuple of
    column-name candidates (LEAPP_COMM_TYPES's own real multi-module
    reality), not the single fixed extra_json key every native comm
    type's spec already is."""
    raw_value = _leapp_row_value(row, spec.get("direction_field", ()))
    if raw_value in spec.get("incoming_values", ()):
        return "incoming"
    if raw_value in spec.get("outgoing_values", ()):
        return "outgoing"
    return None


CONTACT_CORRELATION_MAX_ROWS_PER_TYPE = 20_000
CONTACT_CORRELATION_MAX_CONTACTS = 2_000
CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT = 8
# Unresolved-communication detail (2026-09-07) - a communication whose own
# counterpart never resolves to any known contact was previously visible
# ONLY as a bare aggregate count (unresolved_communication_count), with zero
# detail about which number/address, when, or via which channel - a real
# investigative blind spot found via a live crime-scenario test: an
# unidentified caller/sender right before an incident is exactly the kind of
# lead an examiner most needs to see, not the least. Capped the same way
# every other unbounded-list field in this module already is.
UNRESOLVED_COMM_MAX_RECORDS = 50
# Co-occurrence (2026-09-08) - a communication ROW naming 2+ resolved
# participants (a group MMS, a multi-attendee calendar event, a multi-
# recipient email) is real, observable evidence those people were in the
# same conversation/meeting/thread together, not just each individually in
# contact with the device owner. Every unique pair on such a row counts
# once per occurrence - capped so a single very-large group thread can't
# produce an unbounded pair list (a real risk: an N-person group produces
# N*(N-1)/2 pairs per single message).
CONTACT_CORRELATION_MAX_CO_OCCURRENCE_PAIRS = 500
# Relationship-tier thresholds for the Pattern of Life relationship graph
# (2026-09-07) - deliberately a plain, explainable rule rather than a
# statistical anomaly score: "Frequent Contact" is the smallest, highest-
# volume prefix of a case's contacts (in descending communication-count
# order) whose combined volume reaches this share of the device's total
# communications - the exact sentence an examiner can state in a report
# ("these N contacts account for 80% of this device's total communication
# volume"), not a hidden/black-box cutoff. FREQUENT_MIN_COUNT is a floor
# guarding the degenerate small-dataset case (e.g. a single contact with
# only 1 real communication would otherwise be "100% of total volume" and
# get mislabeled frequent purely from having almost no data at all).
# "Outlier" is deliberately never used as a tier name or label anywhere -
# it can read as an accusation of significance this app has no basis to
# assert; "one-off"/"low-frequency" states the fact without the framing.
CONTACT_CORRELATION_FREQUENT_CUMULATIVE_SHARE = 0.80
CONTACT_CORRELATION_FREQUENT_MIN_COUNT = 3


def normalize_phone_number(raw):
    """Strips every non-digit character, then - a deliberate, disclosed,
    US/NANP-biased heuristic, not a universal E.164 normalizer - drops a
    leading '1' country-code digit from an 11-digit result (matching this
    app's only real sample data, a real Pixel 8a on a US carrier). Returns
    None for anything that isn't plausibly a phone number once stripped
    (too short - a 3-4 digit short code or a stray non-numeric JID like a
    WhatsApp group's own g.us identifier - or implausibly long), so a
    non-phone value never silently becomes a false-positive match. This
    is intentionally an EXACT-match key only: no last-N-digit fuzzy
    fallback across different lengths, since that risks correlating two
    genuinely different people who happen to share a suffix - a real,
    disclosed scope boundary, not silently handled."""
    if not raw:
        return None
    digits = re.sub(r'\D', '', str(raw))
    if len(digits) == 11 and digits.startswith('1'):
        digits = digits[1:]
    if 7 <= len(digits) <= 15:
        return digits
    return None


_EMAIL_PLAUSIBLE_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def normalize_email(raw):
    """The email-address counterpart to normalize_phone_number() above
    (2026-09-07, built to extend contact correlation to email/calendar
    sources) - lowercases and strips whitespace, strips a leading
    'mailto:' prefix (case-insensitive; a real iCalendar ATTENDEE/
    ORGANIZER value is a mailto: URI, not a bare address, per RFC 5545),
    then a plausibility check (exactly the shape local@domain.tld, no
    embedded whitespace) rather than a full RFC 5322 validator - this
    app only needs "is this worth treating as an identity key," not "is
    this a deliverable address." Returns None for anything implausible,
    matching normalize_phone_number()'s own "never silently produce a
    false-positive match" contract. Deliberately an EXACT-match key only
    (no alias/plus-addressing collapsing, e.g. treating jane+test@x.com
    the same as jane@x.com) - a real, disclosed scope boundary, matching
    normalize_phone_number()'s own identical stance on fuzzy matching."""
    if not raw:
        return None
    value = str(raw).strip()
    if value.lower().startswith('mailto:'):
        value = value[len('mailto:'):]
    value = value.strip().lower()
    if _EMAIL_PLAUSIBLE_RE.match(value):
        return value
    return None


def _extract_raw_counterpart_candidates(raw_field):
    """A comm row can name more than one real counterpart - a group MMS's
    comma-joined "addr1, addr2" string (android_mms_message/mobile_sms_
    message's own ", ".join() convention) or a genuine list (android_ab_
    mms_message's "addresses"). Returns each real candidate separately,
    never the whole joined/list value as one string - gluing two real
    numbers/addresses together into one bogus, coincidentally-plausible
    value would otherwise silently misattribute a group message to a
    party nobody on it actually is. Factored out (2026-09-07) from
    correlate_contacts()'s own Pass 2 so /api/cases/timeline's per-row
    counterpart enrichment (for the Evidence Timeline's own entity filter)
    uses the exact same splitting rule, not a second copy that could
    silently drift from this one."""
    if isinstance(raw_field, list):
        return raw_field
    if isinstance(raw_field, str) and ", " in raw_field:
        return raw_field.split(", ")
    return [raw_field] if raw_field else []


def _classify_comm_direction(spec, extra):
    """Returns 'incoming', 'outgoing', or None (unclassified - a Draft/
    Failed/Queued SMS, a Missed/Voicemail/Rejected/Blocked call, a
    malformed/unrecognized value, or a comm type with no direction concept
    at all) for one already-parsed communication row, using the per-
    artifact_type direction_field/incoming_values/outgoing_values already
    confirmed against each parser's own real extra_json shape - see
    CONTACT_CORRELATION_COMM_TYPES's own comments for how each was
    sourced. Never raises - an unhashable/list-shaped raw_value (should
    never happen for a real direction field, but this reads untrusted
    evidence-derived JSON) just falls through to None."""
    field = spec.get("direction_field")
    if not field:
        return None
    raw_value = extra.get(field)
    try:
        if raw_value in spec.get("incoming_values", ()):
            return "incoming"
        if raw_value in spec.get("outgoing_values", ()):
            return "outgoing"
    except TypeError:
        pass
    return None


def _extract_comm_duration_seconds(spec, extra):
    """Returns a non-negative float duration in seconds for one comm row,
    or 0.0 if this comm type has no duration concept (spec has no
    duration_field) or the stored value isn't a real number. Never
    raises, never returns a negative value (a corrupted/garbage source
    value shouldn't be able to silently subtract from a contact's own
    running total)."""
    field = spec.get("duration_field")
    if not field:
        return 0.0
    try:
        return max(0.0, float(extra.get(field)))
    except (TypeError, ValueError):
        return 0.0


def _extract_email_counterparts(artifact_type, value, extra):
    """Returns a list of normalized email addresses this row names as a
    counterpart to the device owner - the email-side equivalent of
    _extract_raw_counterpart_candidates() + normalize_phone_number() for
    the phone-based comm types above, but genuinely different extraction
    per type rather than one shared spec shape (see CONTACT_CORRELATION_
    EMAIL_COMM_TYPES's own comment for why).

    email_message: "From" lives in the row's own `value` column (not
    extra - a real, confirmed difference from every phone-based comm
    type, all of which keep their counterpart in extra_json), and extra's
    "to"/"cc" are each a single raw, possibly multi-address, comma-joined
    RFC 2822 header string. Parsed via the stdlib email.utils.
    getaddresses() rather than a naive comma-split - this app has already
    been bitten once this session by a naive-split bug (MediaStore's
    bucket_display_name/_display_name column collision), and a display
    name containing a literal comma ("Doe, Jane <jane@x.com>") is a real,
    valid RFC 2822 construct getaddresses() already handles correctly,
    unlike a bare split(','). PST/OST-sourced email_message rows have no
    to/cc at all (core/email_utils.py never queries pypff for
    recipients) - those rows correctly contribute zero candidates here,
    not a guessed empty match.

    android_companion_calendar_event: attendees is already a list of
    {"email": ...} dicts (core/android_companion_calendar_utils.py) - no
    header parsing needed, just a direct extraction - plus the event's
    own separate "organizer" field."""
    candidates_raw = []
    if artifact_type == "email_message":
        header_values = [v for v in (value, extra.get("to"), extra.get("cc")) if v]
        if header_values:
            candidates_raw = [addr for _display_name, addr in email.utils.getaddresses(header_values) if addr]
    elif artifact_type == "android_companion_calendar_event":
        for attendee in (extra.get("attendees") or []):
            if isinstance(attendee, dict) and attendee.get("email"):
                candidates_raw.append(attendee["email"])
        if extra.get("organizer"):
            candidates_raw.append(extra["organizer"])
    return [e for e in (normalize_email(c) for c in candidates_raw) if e]


# Comm types with no real message-content concept at all - their own
# `value` column is a duration/status string (e.g. "45s", "Incoming call"),
# never text a person actually wrote. Confirmed directly against each
# parser's own record-construction code (core/android_artifacts.py,
# core/mobile_artifacts.py, core/whatsapp_utils.py, core/android_companion_
# contacts_calllog_utils.py) before excluding them here, not assumed.
_CALL_LOG_ARTIFACT_TYPES = frozenset({
    "android_call_log", "mobile_call_log", "whatsapp_call_log",
    "android_companion_call_log_entry",
})
COMM_CONTENT_PREVIEW_MAX_CHARS = 500


def _comm_content_preview(artifact_type, value, extra):
    """Best-effort real message/body text for one comm-type row (2026-09-08,
    built for the Evidence Timeline/Contact Correlation "preview the actual
    content" feature). For nearly every comm type, parsed_artifacts' own
    `value` column already IS the real message text - confirmed directly
    against each parser's own real record-construction code before relying
    on this uniformly, not assumed: android_sms_message/mobile_sms_message/
    android_ab_sms_message all store the literal SMS body in `value`;
    android_mms_message/android_ab_mms_message store a best-effort joined
    text representation; whatsapp_message/android_companion_sms_message
    both store the real text with a short "[direction, type]"/"type_label:"
    prefix. email_message is the one real exception - its own `value`
    column holds the FROM address, not the body (confirmed against core/
    email_utils.py); the real, already-truncated body lives in
    extra['body_preview'] instead. A call-log row (_CALL_LOG_ARTIFACT_TYPES)
    has no message-content concept at all and correctly returns None here,
    never a fabricated "preview" built from its duration string. Always
    capped at COMM_CONTENT_PREVIEW_MAX_CHARS regardless of source, as a
    defensive ceiling even though every known source is already short or
    itself pre-truncated at parse time."""
    if artifact_type == "email_message":
        text = extra.get("body_preview")
    elif artifact_type in _CALL_LOG_ARTIFACT_TYPES:
        text = None
    else:
        text = value
    if not text:
        return None
    text = str(text)
    return text[:COMM_CONTENT_PREVIEW_MAX_CHARS]


def _record_row_co_occurrences(store, resolved_keys, channel):
    """Given the set of contact keys resolved for ONE communication row,
    records one co-occurrence increment for every unique pair among them -
    an ordinary 1:1 row's single resolved key produces zero pairs; only a
    row naming 2+ resolved participants (a group MMS, a multi-attendee
    calendar event, a multi-recipient email) ever contributes anything.
    `store` keys are a plain sorted 2-tuple of the raw (pre-Pass-3-merge)
    contact keys - correlate_contacts() remaps these through the same
    email->phone merge every node/edge in the final output goes through,
    after both resolution passes finish, so a pair recorded here can still
    correctly end up referencing a merged (post-Pass-3) identity."""
    keys = sorted(resolved_keys)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            entry = store.setdefault((keys[i], keys[j]), {"count": 0, "channels": set()})
            entry["count"] += 1
            entry["channels"].add(channel)


def correlate_contacts(case_folder):
    """Builds a case-wide contact correlation report, now spanning TWO
    identity spaces (2026-09-07) - phone numbers (the original scope) and
    email addresses (WhatsApp was already phone-based and needed no
    extension; Calendar and Email genuinely need a second identity key,
    since a calendar attendee or email correspondent is identified by
    address, not phone number). The two are linked, not just concatenated:
    when a single already-known contact-source row names BOTH a phone and
    an email (android_contact/apple_contact/takeout_contact/mobile_contact
    all already store "phones" and "emails" side by side in the same
    record), that real person's phone-side and email-side activity is
    merged into ONE contact entry rather than shown twice under two
    unrelated-looking keys - see the Pass 3 merge step below for exactly
    how. android_companion_contact gets the identical treatment via a
    dedicated grouping pass (2026-09-08) keyed by its own real extra
    ["contact_id"] instead of a shared row, since that source is one row
    per ContactsContract.Data FIELD rather than one row per person. An
    email-only contact (only ever emailed or calendar-invited, never
    texted or called, or simply not linked to a known phone) still gets
    its own entry, keyed by its own email address instead of a phone
    number - a normalized phone is always all-digits and a normalized
    email always contains "@", so the two key spaces can never collide in
    the same `contacts` list.

    Returns a dict with contacts_indexed_count (known phone numbers),
    email_identities_indexed_count (known email addresses - a person
    linking both counts once in each, by design, not double-counted into
    one combined number), unresolved_communication_count, truncated (hit
    CONTACT_CORRELATION_MAX_CONTACTS), frequent_contact_count and
    frequent_cumulative_share_threshold (the tiering rule's own actual
    inputs for this case, so a caller can state the exact rule that
    produced the tiers rather than a canned/static description), and a
    'contacts' list sorted by total communication count descending (the
    most-contacted people surface first - the highest pattern-of-life
    signal). Each contact carries normalized_number AND normalized_email
    (either may be None depending on which identity space it was found
    in), direction_counts ({"incoming": N, "outgoing": M} - a comm row
    this app can't classify either way, or has no direction concept at
    all for - every email/calendar row, disclosed rather than guessed -
    is counted in total_communications but not toward either direction),
    total_duration_seconds (0.0 for a contact with no call-type
    communications at all - never inferred/estimated), tier
    ("frequent"/"regular"/"one_off" - see CONTACT_CORRELATION_FREQUENT_*
    above for the exact rule, applied uniformly regardless of which
    identity space a contact was found in), and possible_duplicate_keys
    (2026-09-08 - a list, always present, empty when there's nothing to
    flag - of OTHER contacts' own keys sharing this contact's exact
    normalized display name with no verified same-row/same-contact_id
    link; a disclosed hint only, NEVER auto-merged, since merging on a
    shared name alone risks conflating two genuinely different people),
    and merged_from (2026-09-08 - a list, always present, empty unless an
    examiner has actually merged another contact into this one via /api/
    case_index/contacts/merge; each entry is {key, display_names,
    justification, merged_by, merged_at} for one folded-in contact - the
    permanent, disclosed record of a real manual merge decision, distinct
    from possible_duplicate_keys' own passive, unconfirmed hint).
    Each contact's `samples` entries (up to CONTACT_CORRELATION_MAX_
    SAMPLES_PER_CONTACT) also carry `content_preview` (2026-09-08 - the
    real message/body text for that one communication where this app can
    recover it, via _comm_content_preview(); None for a comm type with no
    text-content concept, e.g. a call log entry). Returns a correctly-
    shaped all-empty result (never None/raises) for a case that's never
    been indexed, matching this module's own established "nothing to
    show yet, not an error" convention.

    Also returns co_occurrences (2026-09-08) - a list of {contacts:
    [key_a, key_b], count, channels}, sorted by count descending, capped
    at CONTACT_CORRELATION_MAX_CO_OCCURRENCE_PAIRS (co_occurrences_
    truncated discloses if more existed) - every unique pair of contacts
    that were BOTH named on the same communication row at least once (a
    group MMS thread, a multi-attendee calendar event, a multi-recipient
    email) - real, observable evidence those two people were in contact
    with EACH OTHER, not just each individually with the device owner.
    An ordinary 1:1 row contributes nothing here; only a row naming 2+
    resolved participants does. Never a confirmed relationship claim, only
    a disclosed "seen together in the same thread/meeting" signal - the
    Relationship Graph's own UI is responsible for labeling it as such."""
    result = {"contacts_indexed_count": 0, "email_identities_indexed_count": 0,
              "unresolved_communication_count": 0,
              "truncated": False, "contacts": [],
              "frequent_contact_count": 0,
              "frequent_cumulative_share_threshold": CONTACT_CORRELATION_FREQUENT_CUMULATIVE_SHARE,
              "co_occurrences": [], "co_occurrences_truncated": False}
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return result
    try:
        # Pass 1: every known contact source -> known[normalized_phone] /
        # known_emails[normalized_email], each {names: set, sources: set}.
        # A number/address seen under more than one contact source (e.g.
        # both android_contact and whatsapp_contact) is a real
        # corroboration signal, kept as multiple entries in "sources".
        # phone_email_links[normalized_email] = {normalized_phone, ...}
        # records every phone this exact email was seen alongside on the
        # SAME contact-source row - the one real "these belong to the same
        # person" signal this app can actually observe, used by Pass 3.
        known = {}
        known_emails = {}
        phone_email_links = {}

        def _remember(store, normalized, name, source_type):
            if not normalized:
                return
            entry = store.setdefault(normalized, {"names": set(), "sources": set()})
            if name:
                entry["names"].add(name)
            entry["sources"].add(source_type)

        # android_companion_contact rows are grouped by their own real
        # extra["contact_id"] as they're read (contact_id -> {"phones": [...],
        # "emails": [...], "name": str}), then flushed into known/known_emails/
        # phone_email_links AFTER the loop below - exactly mirroring what a
        # same-row phone+email pair from any other contact source already
        # does, just linked via a shared contact_id instead of a shared row.
        companion_groups = {}

        contact_types = (tuple(CONTACT_CORRELATION_SOURCE_TYPES.keys()) + ("android_companion_contact",)
                         + tuple(LEAPP_CONTACT_TYPES.keys()))
        placeholders = ",".join("?" * len(contact_types))
        cur = conn.execute(
            f"SELECT artifact_type, title, extra_json FROM parsed_artifacts "
            f"WHERE artifact_type IN ({placeholders}) LIMIT ?",
            contact_types + (CONTACT_CORRELATION_MAX_ROWS_PER_TYPE * len(contact_types),))
        for artifact_type, title, extra_json in cur:
            try:
                extra = json.loads(extra_json) if extra_json else {}
            except (TypeError, ValueError):
                extra = {}
            if artifact_type in LEAPP_CONTACT_TYPES:
                leapp_spec = LEAPP_CONTACT_TYPES[artifact_type]
                row = extra.get("row") or {}
                name = row.get(leapp_spec.get("row_name_key")) or title
                if leapp_spec.get("single_key"):
                    normalized = normalize_phone_number(row.get(leapp_spec["single_key"]))
                    if normalized:
                        _remember(known, normalized, name, artifact_type)
                else:
                    normalized_phone = normalize_phone_number(row.get(leapp_spec.get("row_phone_key")))
                    if normalized_phone:
                        _remember(known, normalized_phone, name, artifact_type)
                    normalized_email = normalize_email(row.get(leapp_spec.get("row_email_key")))
                    if normalized_email:
                        _remember(known_emails, normalized_email, name, artifact_type)
                    # leapp_contact's own per-row shape has no reliable
                    # same-row phone+email link at all (see LEAPP_CONTACT_
                    # TYPES's own comment) - correctly never populates
                    # phone_email_links here, unlike every native contact
                    # source above.
                continue
            if artifact_type == "android_companion_contact":
                contact_id = extra.get("contact_id")
                if contact_id is None:
                    continue
                group = companion_groups.setdefault(contact_id, {"phones": [], "emails": [], "name": title})
                mimetype = extra.get("mimetype")
                if mimetype == _COMPANION_CONTACT_PHONE_MIMETYPE:
                    normalized = normalize_phone_number(extra.get("data1"))
                    if normalized:
                        group["phones"].append(normalized)
                elif mimetype == _COMPANION_CONTACT_EMAIL_MIMETYPE:
                    normalized_email = normalize_email(extra.get("data1"))
                    if normalized_email:
                        group["emails"].append(normalized_email)
                continue
            spec = CONTACT_CORRELATION_SOURCE_TYPES[artifact_type]
            row_phones = []
            row_emails = []
            if spec.get("phones_key"):
                for raw in (extra.get(spec["phones_key"]) or []):
                    normalized = normalize_phone_number(raw)
                    if normalized:
                        row_phones.append(normalized)
                        _remember(known, normalized, title, artifact_type)
            elif spec.get("single_key"):
                mimetype_key = spec.get("mimetype_key")
                if mimetype_key and extra.get(mimetype_key) != spec.get("mimetype_value"):
                    continue
                normalized = normalize_phone_number(extra.get(spec["single_key"]))
                if normalized:
                    row_phones.append(normalized)
                    _remember(known, normalized, title, artifact_type)
            if spec.get("emails_key"):
                for raw in (extra.get(spec["emails_key"]) or []):
                    normalized_email = normalize_email(raw)
                    if normalized_email:
                        row_emails.append(normalized_email)
                        _remember(known_emails, normalized_email, title, artifact_type)
            for normalized_email in row_emails:
                phone_email_links.setdefault(normalized_email, set()).update(row_phones)

        for group in companion_groups.values():
            for phone in group["phones"]:
                _remember(known, phone, group["name"], "android_companion_contact")
            for normalized_email in group["emails"]:
                _remember(known_emails, normalized_email, group["name"], "android_companion_contact")
                phone_email_links.setdefault(normalized_email, set()).update(group["phones"])

        # Pass 2a: every phone-keyed communication row -> resolve its
        # counterpart against `known`, aggregate per-contact counts/
        # timestamps/samples. Unchanged logic from before email support.
        by_contact = {}
        unresolved = 0
        unresolved_communications = []
        # Raw (pre-Pass-3-merge) co-occurrence pair counts, keyed by a
        # sorted 2-tuple of contact keys - see _record_row_co_occurrences()
        # and the remap step right after Pass 3 below for how these end up
        # attached to the final, post-merge identities in the response.
        co_occurrence_counts = {}
        comm_types = tuple(CONTACT_CORRELATION_COMM_TYPES.keys()) + tuple(LEAPP_COMM_TYPES.keys())
        placeholders = ",".join("?" * len(comm_types))
        cur = conn.execute(
            f"SELECT artifact_type, title, value, timestamp, source_path, extra_json "
            f"FROM parsed_artifacts WHERE artifact_type IN ({placeholders}) "
            f"ORDER BY timestamp DESC LIMIT ?",
            comm_types + (CONTACT_CORRELATION_MAX_ROWS_PER_TYPE * len(comm_types),))
        for artifact_type, title, value, timestamp, source_path, extra_json in cur:
            is_leapp = artifact_type in LEAPP_COMM_TYPES
            spec = LEAPP_COMM_TYPES[artifact_type] if is_leapp else CONTACT_CORRELATION_COMM_TYPES[artifact_type]
            try:
                extra = json.loads(extra_json) if extra_json else {}
            except (TypeError, ValueError):
                extra = {}
            if is_leapp:
                row = extra.get("row") or {}
                raw_candidates = _extract_leapp_counterparts(artifact_type, spec, row)
            else:
                raw_candidates = _extract_raw_counterpart_candidates(extra.get(spec["counterpart_key"]))
            resolved_any = False
            resolved_keys_this_row = set()
            for raw_counterpart in raw_candidates:
                normalized = normalize_phone_number(raw_counterpart)
                if not normalized or normalized not in known:
                    continue
                resolved_any = True
                resolved_keys_this_row.add(normalized)
                entry = by_contact.setdefault(normalized, {
                    "normalized_number": normalized, "normalized_email": None,
                    "display_names": sorted(known[normalized]["names"]),
                    "contact_sources": sorted(known[normalized]["sources"]),
                    "communication_counts": {},
                    "direction_counts": {"incoming": 0, "outgoing": 0},
                    "total_duration_seconds": 0.0,
                    "first_seen": timestamp, "last_seen": timestamp,
                    "total_communications": 0, "samples": [],
                })
                entry["communication_counts"][spec["channel"]] = entry["communication_counts"].get(spec["channel"], 0) + 1
                entry["total_communications"] += 1
                direction = _classify_leapp_comm_direction(spec, row) if is_leapp else _classify_comm_direction(spec, extra)
                if direction:
                    entry["direction_counts"][direction] += 1
                if not is_leapp:
                    entry["total_duration_seconds"] += _extract_comm_duration_seconds(spec, extra)
                if timestamp is not None:
                    if entry["last_seen"] is None or timestamp > entry["last_seen"]:
                        entry["last_seen"] = timestamp
                    if entry["first_seen"] is None or timestamp < entry["first_seen"]:
                        entry["first_seen"] = timestamp
                if len(entry["samples"]) < CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT:
                    entry["samples"].append({
                        "artifact_type": artifact_type, "title": title, "value": value,
                        "timestamp": timestamp, "source_path": source_path,
                        "content_preview": _comm_content_preview(artifact_type, value, extra),
                    })
            if not resolved_any:
                unresolved += 1
                if len(unresolved_communications) < UNRESOLVED_COMM_MAX_RECORDS * 4:
                    # A generous over-collection cap (4x the final display
                    # cap) so the later sort-by-timestamp-then-truncate step
                    # below can still surface the MOST RECENT unresolved
                    # leads even when there are far more than the display
                    # cap - collecting only up to the final cap here would
                    # silently keep whichever rows happened to be scanned
                    # first, not the most recent ones.
                    raw_counterpart = raw_candidates[0] if raw_candidates else None
                    unresolved_communications.append({
                        "counterpart": normalize_phone_number(raw_counterpart) or raw_counterpart,
                        "artifact_type": artifact_type, "channel": spec["channel"],
                        "timestamp": timestamp,
                        "direction": _classify_leapp_comm_direction(spec, row) if is_leapp else _classify_comm_direction(spec, extra),
                        "content_preview": _comm_content_preview(artifact_type, value, extra),
                    })
            elif len(resolved_keys_this_row) >= 2:
                _record_row_co_occurrences(co_occurrence_counts, resolved_keys_this_row, spec["channel"])

        # Pass 2b: every email-keyed communication row (email_message's
        # From/To/Cc, android_companion_calendar_event's attendees/
        # organizer) -> resolve against `known_emails`, aggregate into a
        # SEPARATE by_email_contact dict with the identical entry shape -
        # merged into by_contact in Pass 3 below, rather than during this
        # loop, so the merge logic can be reasoned about and tested
        # completely independently of this extraction.
        by_email_contact = {}
        email_comm_types = tuple(CONTACT_CORRELATION_EMAIL_COMM_TYPES.keys())
        placeholders = ",".join("?" * len(email_comm_types))
        cur = conn.execute(
            f"SELECT artifact_type, title, value, timestamp, source_path, extra_json "
            f"FROM parsed_artifacts WHERE artifact_type IN ({placeholders}) "
            f"ORDER BY timestamp DESC LIMIT ?",
            email_comm_types + (CONTACT_CORRELATION_MAX_ROWS_PER_TYPE * len(email_comm_types),))
        for artifact_type, title, value, timestamp, source_path, extra_json in cur:
            channel = CONTACT_CORRELATION_EMAIL_COMM_TYPES[artifact_type]
            try:
                extra = json.loads(extra_json) if extra_json else {}
            except (TypeError, ValueError):
                extra = {}
            candidates = _extract_email_counterparts(artifact_type, value, extra)
            resolved_any = False
            resolved_keys_this_row = set()
            for normalized_email in candidates:
                if normalized_email not in known_emails:
                    continue
                resolved_any = True
                resolved_keys_this_row.add(normalized_email)
                entry = by_email_contact.setdefault(normalized_email, {
                    "normalized_number": None, "normalized_email": normalized_email,
                    "display_names": sorted(known_emails[normalized_email]["names"]),
                    "contact_sources": sorted(known_emails[normalized_email]["sources"]),
                    "communication_counts": {},
                    "direction_counts": {"incoming": 0, "outgoing": 0},
                    "total_duration_seconds": 0.0,
                    "first_seen": timestamp, "last_seen": timestamp,
                    "total_communications": 0, "samples": [],
                })
                entry["communication_counts"][channel] = entry["communication_counts"].get(channel, 0) + 1
                entry["total_communications"] += 1
                if timestamp is not None:
                    if entry["last_seen"] is None or timestamp > entry["last_seen"]:
                        entry["last_seen"] = timestamp
                    if entry["first_seen"] is None or timestamp < entry["first_seen"]:
                        entry["first_seen"] = timestamp
                if len(entry["samples"]) < CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT:
                    entry["samples"].append({
                        "artifact_type": artifact_type, "title": title, "value": value,
                        "timestamp": timestamp, "source_path": source_path,
                        "content_preview": _comm_content_preview(artifact_type, value, extra),
                    })
            if not resolved_any:
                unresolved += 1
                if len(unresolved_communications) < UNRESOLVED_COMM_MAX_RECORDS * 4:
                    raw_counterpart = candidates[0] if candidates else None
                    unresolved_communications.append({
                        "counterpart": raw_counterpart, "artifact_type": artifact_type, "channel": channel,
                        "timestamp": timestamp, "direction": None,  # email/calendar rows have no direction concept
                        "content_preview": _comm_content_preview(artifact_type, value, extra),
                    })
            elif len(resolved_keys_this_row) >= 2:
                _record_row_co_occurrences(co_occurrence_counts, resolved_keys_this_row, channel)

        # Pass 3 (merge): fold each email-keyed contact into its linked
        # phone-keyed entry when one exists (the two identities came from
        # the SAME real contact-source row, per phone_email_links) - this
        # is what makes a phone-only view and an email-only view of the
        # same real person collapse into one node instead of two, the
        # actual "entity linking" this extension exists for. An email
        # contact with no linked phone (only ever emailed/invited, never
        # texted or called) stays its own entry, keyed by the email
        # address itself.
        # email_key -> the final by_contact key it ended up under (itself,
        # if it never merged) - used right below to remap co_occurrence_
        # counts' pair keys through the same merge, so a co-occurrence
        # recorded against a since-merged email identity still correctly
        # points at the final, merged phone entry rather than a key that
        # no longer exists in by_contact.
        email_key_remap = {}
        for email_key, email_entry in by_email_contact.items():
            linked_phone = None
            for phone in sorted(phone_email_links.get(email_key, ())):
                if phone in by_contact:
                    linked_phone = phone
                    break
            email_key_remap[email_key] = linked_phone or email_key
            if linked_phone:
                target = by_contact[linked_phone]
                target["normalized_email"] = target["normalized_email"] or email_key
                target["display_names"] = sorted(set(target["display_names"]) | set(email_entry["display_names"]))
                target["contact_sources"] = sorted(set(target["contact_sources"]) | set(email_entry["contact_sources"]))
                for channel, count in email_entry["communication_counts"].items():
                    target["communication_counts"][channel] = target["communication_counts"].get(channel, 0) + count
                target["total_communications"] += email_entry["total_communications"]
                target["direction_counts"]["incoming"] += email_entry["direction_counts"]["incoming"]
                target["direction_counts"]["outgoing"] += email_entry["direction_counts"]["outgoing"]
                target["total_duration_seconds"] += email_entry["total_duration_seconds"]
                if email_entry["first_seen"] is not None and (target["first_seen"] is None or email_entry["first_seen"] < target["first_seen"]):
                    target["first_seen"] = email_entry["first_seen"]
                if email_entry["last_seen"] is not None and (target["last_seen"] is None or email_entry["last_seen"] > target["last_seen"]):
                    target["last_seen"] = email_entry["last_seen"]
                remaining = CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT - len(target["samples"])
                if remaining > 0:
                    target["samples"].extend(email_entry["samples"][:remaining])
            else:
                by_contact[email_key] = email_entry

        # Pass 3.5 (manual merge, 2026-09-08): applies any real, examiner-
        # created merges from contact_merges - a deliberate, disclosed,
        # EXAMINER-REVIEWED action (never automatic - see possible_
        # duplicate_keys' own docstring above for why this app never
        # auto-merges on a shared name alone), each one carrying a REQUIRED
        # justification note recorded permanently with the case. Runs AFTER
        # the automatic same-row Pass 3 merge above (so a merged_key/
        # primary_key that was itself an email already auto-merged into its
        # own linked phone resolves correctly through the same
        # email_key_remap dict, one hop) and BEFORE the possible-duplicate-
        # name-match pass below (so a contact just merged away correctly
        # stops being flagged as its own separate "possible duplicate" of
        # the contact it was just folded into). The write-side route
        # (case_index_merge_contacts()) refuses to let a merged_key also
        # become a primary_key (or vice versa) specifically so this loop
        # never needs to resolve more than one hop through email_key_remap -
        # a real chain (A absorbs B, B absorbs C) would need transitive
        # resolution this single .get(key, key) lookup doesn't do.
        cur = conn.execute("SELECT primary_key, merged_key, justification, merged_by, merged_at FROM contact_merges")
        for m_primary, m_merged, m_justification, m_merged_by, m_merged_at in cur:
            resolved_primary = email_key_remap.get(m_primary, m_primary)
            resolved_merged = email_key_remap.get(m_merged, m_merged)
            if resolved_primary == resolved_merged:
                continue  # already the same entity (e.g. both auto-merged into one phone via Pass 3) - nothing to do
            if resolved_merged not in by_contact or resolved_primary not in by_contact:
                continue  # the underlying data has shifted since this merge was created - skip gracefully, never crash
            merged_entry = by_contact.pop(resolved_merged)
            target = by_contact[resolved_primary]
            target["display_names"] = sorted(set(target["display_names"]) | set(merged_entry["display_names"]))
            target["contact_sources"] = sorted(set(target["contact_sources"]) | set(merged_entry["contact_sources"]))
            for channel, count in merged_entry["communication_counts"].items():
                target["communication_counts"][channel] = target["communication_counts"].get(channel, 0) + count
            target["total_communications"] += merged_entry["total_communications"]
            target["direction_counts"]["incoming"] += merged_entry["direction_counts"]["incoming"]
            target["direction_counts"]["outgoing"] += merged_entry["direction_counts"]["outgoing"]
            target["total_duration_seconds"] += merged_entry["total_duration_seconds"]
            if merged_entry["first_seen"] is not None and (target["first_seen"] is None or merged_entry["first_seen"] < target["first_seen"]):
                target["first_seen"] = merged_entry["first_seen"]
            if merged_entry["last_seen"] is not None and (target["last_seen"] is None or merged_entry["last_seen"] > target["last_seen"]):
                target["last_seen"] = merged_entry["last_seen"]
            remaining = CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT - len(target["samples"])
            if remaining > 0:
                target["samples"].extend(merged_entry["samples"][:remaining])
            target.setdefault("merged_from", []).append({
                "key": resolved_merged,
                "display_names": merged_entry["display_names"],
                "justification": m_justification,
                "merged_by": m_merged_by,
                "merged_at": m_merged_at,
            })
            email_key_remap[m_merged] = resolved_primary
            email_key_remap[resolved_merged] = resolved_primary

        # Remap co_occurrence_counts' raw (Pass 2a/2b) pair keys through the
        # Pass 3 merge - a phone key is already final and passes through
        # unchanged (email_key_remap only ever maps email keys); an email
        # key that merged into a phone entry is remapped to that phone's
        # key so the pair correctly references the one final, merged
        # identity every contact/node in the response uses.
        final_co_occurrences = {}
        for (key_a, key_b), info in co_occurrence_counts.items():
            final_a = email_key_remap.get(key_a, key_a)
            final_b = email_key_remap.get(key_b, key_b)
            if final_a == final_b or final_a not in by_contact or final_b not in by_contact:
                continue  # a self-pair or a reference to an identity that never made it into by_contact - shouldn't happen structurally, but never surface a broken edge
            pair_key = tuple(sorted((final_a, final_b)))
            entry = final_co_occurrences.setdefault(pair_key, {"count": 0, "channels": set()})
            entry["count"] += info["count"]
            entry["channels"] |= info["channels"]
        co_occurrences = sorted(
            ({"contacts": list(pair), "count": info["count"], "channels": sorted(info["channels"])}
             for pair, info in final_co_occurrences.items()),
            key=lambda e: e["count"], reverse=True)
        co_occurrences_truncated = len(co_occurrences) > CONTACT_CORRELATION_MAX_CO_OCCURRENCE_PAIRS
        co_occurrences = co_occurrences[:CONTACT_CORRELATION_MAX_CO_OCCURRENCE_PAIRS]

        # Unconfirmed name-match suggestions (2026-09-08) - a deliberately
        # WEAKER, separate signal from the Pass-3 same-row/same-contact_id
        # merge above: two DIFFERENT, un-merged contact entries that happen
        # to share a normalized display name (case/whitespace-insensitive)
        # MIGHT be the same real person under a third identity this app has
        # no way to verifiably link (e.g. a WhatsApp-only JID and a separate
        # Email-only address, both saved as "Jane Doe" but never observed on
        # the same contact-source row or companion contact_id) - or they
        # might just be two different people who happen to share a common
        # name. This is NEVER auto-merged - doing so risks conflating two
        # real, different people into one incorrect entity, a materially
        # worse error than leaving them separate. Surfaced only as a
        # disclosed, examiner-reviewable "possible_duplicate_keys" hint on
        # each affected contact - always an empty list when there's nothing
        # to flag, never omitted, so a caller never has to guess whether the
        # absence of the key means "checked, none found" vs "not computed".
        for c in by_contact.values():
            c["possible_duplicate_keys"] = []
            c.setdefault("merged_from", [])
        by_normalized_name = {}
        for c in by_contact.values():
            for name in c["display_names"]:
                normalized_name = " ".join(name.strip().lower().split())
                if normalized_name:
                    by_normalized_name.setdefault(normalized_name, []).append(c)
        for candidates in by_normalized_name.values():
            if len(candidates) < 2:
                continue
            keys = [(c["normalized_number"] or c["normalized_email"]) for c in candidates]
            for c, own_key in zip(candidates, keys):
                merged = set(c["possible_duplicate_keys"]) | {k for k in keys if k != own_key}
                c["possible_duplicate_keys"] = sorted(merged)

        contacts = sorted(by_contact.values(), key=lambda c: c["total_communications"], reverse=True)
        truncated = len(contacts) > CONTACT_CORRELATION_MAX_CONTACTS
        contacts = contacts[:CONTACT_CORRELATION_MAX_CONTACTS]

        # Tiering (2026-09-07) - see CONTACT_CORRELATION_FREQUENT_* above
        # for the exact rule. Only ever run over already-sorted `contacts`
        # (descending by total_communications), so the cumulative-share
        # walk below always finds the smallest possible high-volume prefix.
        # Applies uniformly regardless of which identity space (phone,
        # email, or a merged both) a contact was ultimately keyed under -
        # tiering only ever looks at total_communications, which is
        # already correctly combined by the Pass 3 merge above.
        grand_total = sum(c["total_communications"] for c in contacts)
        frequent_cutoff_index = 0
        if grand_total > 0:
            cumulative = 0
            for i, c in enumerate(contacts):
                cumulative += c["total_communications"]
                if cumulative >= grand_total * CONTACT_CORRELATION_FREQUENT_CUMULATIVE_SHARE:
                    frequent_cutoff_index = i + 1
                    break
            else:
                frequent_cutoff_index = len(contacts)
        actual_frequent_count = 0
        for i, c in enumerate(contacts):
            if i < frequent_cutoff_index and c["total_communications"] >= CONTACT_CORRELATION_FREQUENT_MIN_COUNT:
                c["tier"] = "frequent"
                actual_frequent_count += 1
            elif c["total_communications"] == 1:
                c["tier"] = "one_off"
            else:
                c["tier"] = "regular"

        result["contacts"] = contacts
        result["contacts_indexed_count"] = len(known)
        result["email_identities_indexed_count"] = len(known_emails)
        result["unresolved_communication_count"] = unresolved
        # Most-recent-first, matching every other "what should I look at
        # first" ordering already used throughout this module (contacts,
        # samples, Evidence Timeline). A missing timestamp sorts last, not
        # first, so a genuinely dated (and therefore more actionable) lead
        # is never buried behind an undated one.
        unresolved_communications.sort(key=lambda r: (r["timestamp"] is None, -(r["timestamp"] or 0)))
        result["unresolved_communications"] = unresolved_communications[:UNRESOLVED_COMM_MAX_RECORDS]
        result["unresolved_communications_truncated"] = len(unresolved_communications) > UNRESOLVED_COMM_MAX_RECORDS
        result["truncated"] = truncated
        result["frequent_contact_count"] = actual_frequent_count
        # A pair referencing a contact that got cut off by the (very high,
        # 2_000-contact) CONTACT_CORRELATION_MAX_CONTACTS cap above would
        # otherwise dangle - filtered out rather than left for the frontend
        # to defensively skip, so co_occurrences always only references
        # keys genuinely present in the returned contacts list.
        final_contact_keys = {(c["normalized_number"] or c["normalized_email"]) for c in contacts}
        result["co_occurrences"] = [e for e in co_occurrences if e["contacts"][0] in final_contact_keys and e["contacts"][1] in final_contact_keys]
        result["co_occurrences_truncated"] = co_occurrences_truncated
        return result
    finally:
        conn.close()


# --- Case-wide analysis-coverage dashboard (2026-09-09, item 6 of the
# DFIR-comparison backlog - see the dated CLAUDE.md entry) ---
#
# "What's been run against each evidence item, what hasn't" - the coverage
# gap CLAUDE.md's own backlog entry described: refreshCtxMenuAlreadyRunBadges()
# (static/js/main.js) already answers this for the single file currently
# selected in File Explorer's context menu, one right-click at a time -
# nothing answers it case-wide, across every acquired evidence item, at a
# glance, the way Belkasoft's own Dashboard+Tasks-window pair does (the
# strongest real precedent this research found across 6 competitor tools).
#
# Deliberately does NOT try to reverse-engineer which parsed_artifacts
# artifact_type values "belong to" which Auto Analyze step key - a single
# step like "registry" alone produces 15+ distinct artifact_types
# (recentdocs/typedpaths/runmru/usbhistory/installedprograms/amcache/
# shellbags/shimcache/bam/rdp_server/rdp_mru/office_mru_file/
# office_mru_place/wordwheelquery/userassist), and "browser_artifacts"
# covers Chrome+Firefox+Safari's own distinct type sets - keeping a mapping
# like that in sync forever would be exactly the same fragile-hardcoded-
# mirror bug class this app already found and fixed once (2026-09-01,
# fetchAutoAnalyzeStepsRegistry()'s own docstring tells that story).
#
# Instead, this reads the REAL, already-authoritative record of "which
# steps ran and succeeded against this exact evidence item": the
# auto_analyze_complete / auto_analyze_mobile_complete chain-of-custody log
# entries execution_worker_auto_analyze_image()/_mobile() already write on
# every completed run, each carrying the exact target path plus a
# results[] list with a real per-step ok/error/skipped/not_applicable
# outcome. A step is only ever counted as "covered" if some run against
# this exact path reached status "ok" - a failed or skipped attempt does
# not count, matching this app's own established "disclose gaps honestly"
# posture rather than crediting a step that never actually completed.
#
# Deliberately returns raw step-key lists only, never labels or the full
# step catalog - core/case_index_db.py has no import of routes/
# image_browser.py's AUTO_ANALYZE_STEP_LABELS/routes/file_explorer.py's
# AUTO_ANALYZE_MOBILE_STEP_LABELS (this app's own hard "no routes/*.py
# module imports another" rule, with one narrow documented exception
# elsewhere - this isn't it). The frontend already fetches both of those
# registries itself (fetchAutoAnalyzeStepsRegistry() / the mobile steps
# route) for the Auto Analyze modal's own checklist and reuses that same
# cached data here to label/diff against - no duplicate Python-side copy
# of either dict to let drift out of sync a third time.
def compute_case_analysis_coverage(case_folder):
    """For every COMPLETED acquisition event in this case with a walkable
    output path, returns which Auto Analyze steps have actually succeeded
    against it at least once (from the real chain-of-custody log), plus a
    hash-verification status and a tag count scoped to that exact path -
    everything an examiner needs to see, case-wide, which evidence items
    still need attention. Returns {"items": [...]}; never raises - a
    missing/unreadable case file or log just means an empty item list, the
    same graceful-degradation posture every other case-wide read in this
    module already has."""
    case_file = case_consolidated_path(case_folder)
    if not case_file:
        return {"items": []}
    try:
        with open(case_file, 'r') as f:
            case_data = json.load(f)
    except Exception:
        return {"items": []}

    events = case_data.get('events', [])
    last_verification = case_data.get('last_verification') or {}
    lv_by_event = {r.get('event_id'): r for r in last_verification.get('results', [])}

    coc_entries = []
    try:
        if os.path.exists(config.COC_LOG_FILE):
            with open(config.COC_LOG_FILE, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get('action') in ('auto_analyze_complete', 'auto_analyze_mobile_complete'):
                        coc_entries.append(entry)
    except Exception:
        pass  # a missing/unreadable COC log just means "no steps known covered yet", not a hard failure

    items = []
    for event in events:
        if event.get('acquisition_status') != 'COMPLETED':
            continue
        params = event.get('acquisition_parameters') or {}
        image_path = params.get('output_image_path')
        output_dest = params.get('output_destination')
        target_path = image_path or output_dest
        if not target_path:
            continue  # e.g. a companion-app extraction event - nothing walkable to report coverage for

        is_image = bool(image_path)
        completed_steps = set()
        for entry in coc_entries:
            details = entry.get('details', {})
            entry_path = details.get('image_path') if is_image else details.get('path')
            if entry_path != target_path:
                continue
            for r in details.get('results', []):
                if r.get('status') == 'ok':
                    completed_steps.add(r.get('step'))

        recorded_hashes = event.get('computed_verification_hashes') or {}
        lv = lv_by_event.get(event.get('event_id'))
        if lv:
            hash_status = lv.get('status', 'unverifiable')
        elif recorded_hashes:
            hash_status = 'not_yet_reverified'
        else:
            hash_status = 'no_hash_recorded'

        tag_info = _tags_for_paths(case_folder, [target_path])
        tag_count = len(tag_info.get(target_path, []))

        items.append({
            "event_id": event.get('event_id'),
            "evidence_id": (event.get('case_metadata') or {}).get('evidence_id') or 'UNKNOWN',
            "tool": event.get('tool') or 'unknown',
            "kind": "disk_image" if is_image else "mobile_or_folder",
            "target_path": target_path,
            "steps_completed": sorted(completed_steps),
            "hash_status": hash_status,
            "tag_count": tag_count,
        })

    return {"items": items}
