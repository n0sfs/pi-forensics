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
import time
import sqlite3
from flask import g

from core.paths import safe_path, case_consolidated_path

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
}
TRIAGE_MAX_MATCHES_PER_CATEGORY = 50000  # protects memory on very large images
TRIAGE_CATEGORY_LABELS = {
    "emails": "Email Addresses", "urls": "URLs", "ip_addresses": "IP Addresses",
    "credit_card_numbers": "Credit Card-like Numbers", "phone_numbers": "Phone Numbers",
}

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
INSERT OR IGNORE INTO tags (name, color, notable, is_default, created_at) VALUES
    ('Bookmark', 'info', 0, 1, datetime('now')),
    ('Follow Up', 'warning', 0, 1, datetime('now')),
    ('Notable Item', 'danger', 1, 1, datetime('now'));

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

def _record_analysis_result(case_folder, identity, tool, summary, output):
    """Best-effort persistence of one analysis-tool run, mirroring
    quick_triage_scan()'s exact optional/non-blocking case-index write
    pattern: `case_folder` is optional (None/invalid just means "don't
    persist"), and any failure here is swallowed and logged, never raised -
    a broken or locked index write must never turn a successful scan into a
    reported tool failure. `identity` is the same shape
    _resolve_tag_identity() produces: {source_type, image_path, fs_offset,
    inode, path, name}."""
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
             getattr(g, 'forensic_user', None), time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: could not record analysis result ({tool}) to case index: {e}")
