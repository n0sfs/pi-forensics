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
from flask import g

from core.paths import safe_path, case_consolidated_path, classify_case_role
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
    created_at TEXT NOT NULL
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
"""

def _case_index_connect(db_path):
    """Opens (creating if absent) the per-case analysis index, in WAL mode
    so a running scan job's writes and a concurrent File Explorer read don't
    block each other. Caller is responsible for closing the connection."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_CASE_INDEX_SCHEMA)
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
    """Returns {path: [{id, name, color, notable, comment}, ...]} for every
    real-fs path in `paths` that has at least one tag. Empty dict if the
    case isn't indexed/consolidated, or paths is empty - never an error."""
    result = {}
    if not paths:
        return result
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return result
    try:
        placeholders = ",".join("?" * len(paths))
        cur = conn.execute(
            f"SELECT ti.path, t.id, t.name, t.color, t.notable, ti.comment "
            f"FROM tagged_items ti JOIN tags t ON ti.tag_id=t.id "
            f"WHERE ti.source_type='real_fs' AND ti.path IN ({placeholders})",
            paths)
        for row in cur:
            result.setdefault(row[0], []).append(
                {"id": row[1], "name": row[2], "color": row[3], "notable": bool(row[4]), "comment": row[5]})
    finally:
        conn.close()
    return result

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
# Scoped to the 5 contact types and 6 communication types whose real
# extra_json shape is directly grounded in this app's own already-shipped,
# already-tested parser code (core/android_artifacts.py, core/mobile_
# artifacts.py, core/apple_export_utils.py/core/takeout_utils.py, core/
# whatsapp_utils.py) - every one of them stores a real phone-number-
# shaped string in a known extra_json key. Deliberately EXCLUDES every
# leapp_* contact/communication type (leapp_contact, leapp_sms_message,
# leapp_call_log, leapp_whatsapp_*, etc.): those store ALEAPP's own raw
# TSV columns generically under extra_json["row"], and this station has
# never once seen a real ALEAPP hit to confirm which real column name
# actually holds a phone number for any of them (see core/leapp_tsv_
# utils.py's own docstring) - guessing a column name here risks silently
# matching the wrong field and producing a confidently wrong correlation,
# which this app's own established discipline treats as worse than not
# covering it yet. A future session with real ALEAPP hit data to check
# against should extend this, not guess now.
CONTACT_CORRELATION_SOURCE_TYPES = {
    "android_contact": {"phones_key": "phones", "kind": "contact"},
    "apple_contact": {"phones_key": "phones", "kind": "contact"},
    "takeout_contact": {"phones_key": "phones", "kind": "contact"},
    "mobile_contact": {"phones_key": "phones", "kind": "contact"},
    "whatsapp_contact": {"phones_key": None, "single_key": "number", "kind": "contact"},
}
CONTACT_CORRELATION_COMM_TYPES = {
    "android_sms_message": {"counterpart_key": "address", "channel": "SMS"},
    "android_call_log": {"counterpart_key": "number", "channel": "Call"},
    "mobile_sms_message": {"counterpart_key": "counterpart", "channel": "SMS/iMessage"},
    "mobile_call_log": {"counterpart_key": "address", "channel": "Call"},
    "whatsapp_message": {"counterpart_key": "sender_jid", "channel": "WhatsApp Message"},
    "whatsapp_call_log": {"counterpart_key": "caller_jid", "channel": "WhatsApp Call"},
}
CONTACT_CORRELATION_MAX_ROWS_PER_TYPE = 20_000
CONTACT_CORRELATION_MAX_CONTACTS = 2_000
CONTACT_CORRELATION_MAX_SAMPLES_PER_CONTACT = 8


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


def correlate_contacts(case_folder):
    """Builds a case-wide {normalized_number: {...}} correlation report -
    see the module comment above for scope. Returns a dict with
    contacts_indexed_count, unresolved_communication_count, truncated
    (hit CONTACT_CORRELATION_MAX_CONTACTS), and a 'contacts' list sorted
    by total communication count descending (the most-contacted people
    surface first - the highest pattern-of-life signal). Returns a
    correctly-shaped all-empty result (never None/raises) for a case
    that's never been indexed, matching this module's own established
    "nothing to show yet, not an error" convention."""
    result = {"contacts_indexed_count": 0, "unresolved_communication_count": 0,
              "truncated": False, "contacts": []}
    conn = _case_index_open_readonly(case_folder)
    if not conn:
        return result
    try:
        # Pass 1: every known contact source -> {normalized: {names: set,
        # sources: set}}. A number seen under more than one contact
        # source (e.g. both android_contact and whatsapp_contact) is a
        # real corroboration signal, kept as multiple entries in "sources".
        known = {}

        def _remember(normalized, name, source_type):
            if not normalized:
                return
            entry = known.setdefault(normalized, {"names": set(), "sources": set()})
            if name:
                entry["names"].add(name)
            entry["sources"].add(source_type)

        contact_types = tuple(CONTACT_CORRELATION_SOURCE_TYPES.keys())
        placeholders = ",".join("?" * len(contact_types))
        cur = conn.execute(
            f"SELECT artifact_type, title, extra_json FROM parsed_artifacts "
            f"WHERE artifact_type IN ({placeholders}) LIMIT ?",
            contact_types + (CONTACT_CORRELATION_MAX_ROWS_PER_TYPE * len(contact_types),))
        for artifact_type, title, extra_json in cur:
            spec = CONTACT_CORRELATION_SOURCE_TYPES[artifact_type]
            try:
                extra = json.loads(extra_json) if extra_json else {}
            except (TypeError, ValueError):
                extra = {}
            if spec.get("phones_key"):
                for raw in (extra.get(spec["phones_key"]) or []):
                    _remember(normalize_phone_number(raw), title, artifact_type)
            elif spec.get("single_key"):
                _remember(normalize_phone_number(extra.get(spec["single_key"])), title, artifact_type)

        # Pass 2: every communication row -> resolve its counterpart
        # against `known`, aggregate per-contact counts/timestamps/samples.
        by_contact = {}
        unresolved = 0
        comm_types = tuple(CONTACT_CORRELATION_COMM_TYPES.keys())
        placeholders = ",".join("?" * len(comm_types))
        cur = conn.execute(
            f"SELECT artifact_type, title, value, timestamp, source_path, extra_json "
            f"FROM parsed_artifacts WHERE artifact_type IN ({placeholders}) "
            f"ORDER BY timestamp DESC LIMIT ?",
            comm_types + (CONTACT_CORRELATION_MAX_ROWS_PER_TYPE * len(comm_types),))
        for artifact_type, title, value, timestamp, source_path, extra_json in cur:
            spec = CONTACT_CORRELATION_COMM_TYPES[artifact_type]
            try:
                extra = json.loads(extra_json) if extra_json else {}
            except (TypeError, ValueError):
                extra = {}
            raw_counterpart = extra.get(spec["counterpart_key"])
            normalized = normalize_phone_number(raw_counterpart)
            if not normalized or normalized not in known:
                unresolved += 1
                continue
            entry = by_contact.setdefault(normalized, {
                "normalized_number": normalized,
                "display_names": sorted(known[normalized]["names"]),
                "contact_sources": sorted(known[normalized]["sources"]),
                "communication_counts": {},
                "first_seen": timestamp, "last_seen": timestamp,
                "total_communications": 0, "samples": [],
            })
            entry["communication_counts"][spec["channel"]] = entry["communication_counts"].get(spec["channel"], 0) + 1
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
                })

        contacts = sorted(by_contact.values(), key=lambda c: c["total_communications"], reverse=True)
        truncated = len(contacts) > CONTACT_CORRELATION_MAX_CONTACTS
        result["contacts"] = contacts[:CONTACT_CORRELATION_MAX_CONTACTS]
        result["contacts_indexed_count"] = len(known)
        result["unresolved_communication_count"] = unresolved
        result["truncated"] = truncated
        return result
    finally:
        conn.close()
