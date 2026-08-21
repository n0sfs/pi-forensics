"""Real per-app artifact parsing: Chrome/Chromium-family browser artifacts
(History, Downloads, Bookmarks, Cookie metadata) - the first genuine
"parsed artifact" capability in this app, distinct from everything File
Views already offered (file-type buckets, tags, regex-matched triage hits).
Scoped deliberately to the Chrome/Chromium family (Chrome, Edge, Brave,
Opera, Vivaldi all share the same History/Cookies SQLite schema and
Bookmarks JSON format) - Firefox (places.sqlite) and Safari use genuinely
different formats and are a real, separate follow-up, not silently bundled
in here.

Shared by both the real-directory scan (routes/file_explorer.py) and the
in-image scan (routes/image_browser.py) - only how each candidate file's
bytes reach this module differs (a real path on disk vs. one extracted out
of an unmounted image to a temp file first); the parsing itself is
identical either way.
"""
import os
import re
import json
import sqlite3

# --- Chromium's own timestamp epoch ---
# Chrome/Chromium (and therefore every Chromium-family browser) stores
# History/Cookies/Bookmarks timestamps as microseconds since 1601-01-01
# 00:00:00 UTC (the Windows FILETIME epoch, just in microseconds instead of
# 100ns ticks) - NOT the Unix epoch. Getting this wrong silently produces
# timestamps ~369 years off, a well-known gotcha in this exact space.
WEBKIT_EPOCH_OFFSET_SECONDS = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01


def webkit_time_to_unix(value):
    """Converts a Chrome/WebKit microsecond timestamp (int, or a numeric
    string - Bookmarks JSON stores it as a string) to Unix epoch seconds.
    Returns None for 0/empty/unparseable - Chrome uses 0 to mean "no
    timestamp recorded", not the epoch itself."""
    if not value:
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds == 0:
        return None
    return (microseconds / 1_000_000) - WEBKIT_EPOCH_OFFSET_SECONDS


# --- Candidate-file detection ---
# Chrome/Chromium profile files have fixed, extensionless names, always
# sitting under a "User Data/<Profile>/" style folder - matched by exact
# basename, not by location, since a real evidence acquisition can have
# that folder nested arbitrarily deep (a user's own AppData tree, an
# extracted phone backup, etc.).
CHROME_ARTIFACT_FILENAMES = {'History', 'Cookies', 'Bookmarks'}

BROWSER_ARTIFACT_MAX_HISTORY = 5000
BROWSER_ARTIFACT_MAX_DOWNLOADS = 2000
BROWSER_ARTIFACT_MAX_COOKIES = 3000
BROWSER_ARTIFACT_MAX_BOOKMARKS = 2000

# Real-filesystem candidate discovery only - in-image discovery (routes/
# image_browser.py) walks via pytsk3's own _tsk_walk() instead, a
# completely different mechanism, so it isn't shared here.
BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES = 50  # a case folder can hold multiple users'/profiles' worth
BROWSER_ARTIFACT_SCAN_MAX_WALKED = 20_000  # safety cap on the walk itself, independent of matches found
_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}  # extundelete's fixed output dir name
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')  # bulk carved-file output - same skip-list convention as this app's other whole-folder scanners (reporting.py's _discover_case_files, core/case_index_db.py's artifact-tag backfill sweep)


def find_chrome_artifact_files(root_dir):
    """Recursively finds real files whose basename exactly matches a known
    Chrome/Chromium profile filename (CHROME_ARTIFACT_FILENAMES) anywhere
    under root_dir - these live arbitrarily deep in a real acquisition (a
    user's own AppData tree, an extracted phone backup, etc.), so location
    is never assumed, only the filename. Returns (paths, truncated) -
    truncated is True if either cap (candidates found, or total files
    walked) was hit before the walk finished, so a caller can disclose an
    incomplete scan rather than silently presenting it as exhaustive."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > BROWSER_ARTIFACT_SCAN_MAX_WALKED:
                return found, True
            if fname in CHROME_ARTIFACT_FILENAMES:
                found.append(os.path.join(root, fname))
                if len(found) >= BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _open_sqlite_readonly(path):
    """Opens a SQLite file strictly read-only and 'immutable' (tells SQLite
    the file won't change and to skip its own locking entirely) - this is
    always a static evidence copy (a real file, or something just extracted
    from an unmounted image to a short-lived temp path), never a live
    database something else might be writing to."""
    return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)


def _evidence_path_basename(path_str):
    """os.path.basename() only recognizes the RUNNING process's own OS path
    separator - on this app's real deployment target (Linux), a backslash
    is just an ordinary filename character, not a separator. Chrome's
    downloads.target_path column stores whatever OS the browser itself ran
    on - overwhelmingly Windows in a real acquisition - so os.path.basename()
    would silently return the entire Windows path unchanged instead of just
    the filename. Splits on both '/' and '\\' regardless of platform.
    (Caught by this app's own test suite: passed on the Windows dev machine,
    where os.path.basename() happens to accept both separators, and failed
    the moment the exact same test ran on the Pi's real Linux venv.)"""
    if not path_str:
        return ""
    return re.split(r'[\\/]', path_str)[-1]


def parse_chrome_history_db(path):
    """Returns {"history": [...], "downloads": [...]}, each capped. Both
    live in the same 'History' SQLite file. Column sets are queried
    defensively (try the modern schema, catch and skip on failure) since
    Chrome's exact download-table columns have shifted across versions -
    a version mismatch degrades to an empty downloads list rather than
    failing the whole parse."""
    history, downloads = [], []
    conn = _open_sqlite_readonly(path)
    try:
        try:
            cur = conn.execute(
                "SELECT u.url, u.title, u.visit_count, u.last_visit_time "
                "FROM urls u ORDER BY u.last_visit_time DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_HISTORY,))
            for url, title, visit_count, last_visit_time in cur:
                history.append({
                    "artifact_type": "chrome_history",
                    "title": title or "",
                    "url": url or "",
                    "value": f"{visit_count} visit(s)" if visit_count else "",
                    "timestamp": webkit_time_to_unix(last_visit_time),
                    "extra": {"visit_count": visit_count},
                })
        except sqlite3.OperationalError:
            pass  # not a real/recognizable History table - leave history empty, still try downloads

        try:
            cur = conn.execute(
                "SELECT target_path, tab_url, start_time, end_time, received_bytes, total_bytes, state "
                "FROM downloads ORDER BY start_time DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_DOWNLOADS,))
        except sqlite3.OperationalError:
            cur = []  # older Chrome used different column names - skip rather than guess
        for target_path, tab_url, start_time, end_time, received_bytes, total_bytes, state in cur:
            downloads.append({
                "artifact_type": "chrome_downloads",
                "title": _evidence_path_basename(target_path),
                "url": tab_url or "",
                "value": target_path or "",
                "timestamp": webkit_time_to_unix(start_time),
                "extra": {
                    "end_time": webkit_time_to_unix(end_time),
                    "received_bytes": received_bytes, "total_bytes": total_bytes,
                    "state": {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}.get(state, state),
                },
            })
    finally:
        conn.close()
    return {"history": history, "downloads": downloads}


def parse_chrome_cookies_db(path):
    """Returns a capped list of cookie *metadata* rows - host, name, path,
    expiry, secure/httponly flags. Modern Chrome encrypts each cookie's
    real value with an OS-level key (Windows DPAPI / macOS Keychain / Linux
    libsecret) that isn't recoverable from the evidence file alone, so this
    deliberately does NOT attempt decryption (out of scope, and platform-
    dependent even if attempted) - a cookie whose value is only in the
    encrypted_value column is reported with value '[encrypted]', clearly
    disclosed rather than silently blank or guessed at. Metadata alone
    (which sites set cookies, when, for how long) is still real forensic
    signal even without the value."""
    cookies = []
    conn = _open_sqlite_readonly(path)
    try:
        try:
            cur = conn.execute(
                "SELECT host_key, name, value, LENGTH(encrypted_value), path, expires_utc, "
                "is_secure, is_httponly, creation_utc "
                "FROM cookies ORDER BY creation_utc DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_COOKIES,))
        except sqlite3.OperationalError:
            return cookies  # not a real/recognizable Cookies table
        for host_key, name, value, enc_len, path_, expires_utc, is_secure, is_httponly, creation_utc in cur:
            display_value = value if value else ("[encrypted]" if enc_len else "")
            cookies.append({
                "artifact_type": "chrome_cookies",
                "title": name or "",
                "url": host_key or "",
                "value": display_value,
                "timestamp": webkit_time_to_unix(creation_utc),
                "extra": {
                    "path": path_, "expires": webkit_time_to_unix(expires_utc),
                    "secure": bool(is_secure), "httponly": bool(is_httponly),
                },
            })
    finally:
        conn.close()
    return cookies


def _walk_bookmark_node(node, folder_path, out, limit):
    """Recursive walk of Chrome's Bookmarks JSON tree - 'type':'url' leaves
    are real bookmarks, 'type':'folder' nodes just nest deeper. folder_path
    is a '/'-joined breadcrumb (e.g. 'Bookmarks Bar/Work') carried along so
    each bookmark's own location in the tree is preserved, not just its
    name/URL."""
    if len(out) >= limit:
        return
    node_type = node.get('type')
    if node_type == 'url':
        out.append({
            "artifact_type": "chrome_bookmarks",
            "title": node.get('name', ''),
            "url": node.get('url', ''),
            "value": folder_path,
            "timestamp": webkit_time_to_unix(node.get('date_added')),
            "extra": {"folder": folder_path},
        })
    elif node_type == 'folder':
        child_path = f"{folder_path}/{node.get('name', '')}" if folder_path else node.get('name', '')
        for child in node.get('children', []):
            if len(out) >= limit:
                return
            _walk_bookmark_node(child, child_path, out, limit)


def parse_chrome_bookmarks_json(path):
    """Returns a capped list of bookmarks from Chrome's 'Bookmarks' file -
    plain JSON (no SQLite involved), with a 'roots' dict whose top-level
    keys (bookmark_bar, other, synced, ...) are themselves folder nodes."""
    bookmarks = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return bookmarks
    roots = data.get('roots', {})
    if not isinstance(roots, dict):
        return bookmarks
    for root_name, root_node in roots.items():
        if not isinstance(root_node, dict):
            continue
        if len(bookmarks) >= BROWSER_ARTIFACT_MAX_BOOKMARKS:
            break
        # The root itself (bookmark_bar/other/synced) is never a real
        # bookmark to record - only walk ITS children, seeded with the
        # root's own display name as the starting breadcrumb. Calling
        # _walk_bookmark_node() on the root node directly would double up
        # the root's name the first time a child folder appends its own
        # name (folder_path already contains it once from here, then
        # again from the recursive call treating the root as an ordinary
        # folder) - a real bug this test file's own fixture caught.
        label = root_node.get('name', root_name)
        for child in root_node.get('children', []):
            if len(bookmarks) >= BROWSER_ARTIFACT_MAX_BOOKMARKS:
                break
            _walk_bookmark_node(child, label, bookmarks, BROWSER_ARTIFACT_MAX_BOOKMARKS)
    return bookmarks


def parse_chrome_profile_file(path, filename):
    """Dispatches a candidate file (matched by exact basename against
    CHROME_ARTIFACT_FILENAMES) to the right parser, returning a flat list
    of records (each already shaped {artifact_type, title, url, value,
    timestamp, extra}) - 'History' yields two artifact_types at once
    (chrome_history + chrome_downloads) since both live in that one file.
    Any parse failure (corrupted/truncated/not actually a Chrome file
    despite the matching name) is swallowed and returns an empty list -
    matches this app's established best-effort tolerance for a single bad
    input during a broader scan (e.g. _backfill_case_artifact_tags)."""
    try:
        if filename == 'History':
            parsed = parse_chrome_history_db(path)
            return parsed["history"] + parsed["downloads"]
        if filename == 'Cookies':
            return parse_chrome_cookies_db(path)
        if filename == 'Bookmarks':
            return parse_chrome_bookmarks_json(path)
    except Exception as e:
        print(f"Warning: could not parse Chrome artifact file {path} ({filename}): {e}")
    return []
