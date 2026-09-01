"""Real per-app artifact parsing: Chrome/Chromium-family, Firefox, AND
Safari browser artifacts (History, Downloads, Bookmarks, Cookie metadata) -
the first genuine "parsed artifact" capability in this app, distinct from
everything File Views already offered (file-type buckets, tags, regex-
matched triage hits). Three families, three schemas, one shared output
shape ({artifact_type, title, url, value, timestamp, extra}) so File Views/
the case index never need to know which browser produced a record:
  - Chrome/Chromium family (Chrome, Edge, Brave, Opera, Vivaldi all share
    the same History/Cookies SQLite schema and Bookmarks JSON format) -
    matched by the fixed, extensionless filenames History/Cookies/Bookmarks.
  - Firefox - a real, separate parser (places.sqlite for History+Bookmarks,
    cookies.sqlite for cookies), added 2026-08-21.
  - Safari - a real, separate parser added 2026-09-01, closing a gap this
    module's own docstring previously flagged as "still explicitly out of
    scope." Grounded via real research before writing any code (real
    forensic-tool source - ydkhatri/mac_apt's safari.py plugin - plus the
    Velociraptor MacOS.Applications.Safari.Downloads artifact definition
    and a 2024 peer-reviewed paper on the .binarycookies format, not
    guessed): History.db (SQLite, dominant schema since Safari 8/Yosemite,
    2014 - the older History.plist is legacy and out of scope, matching
    this module's own "target a reasonably modern, common schema"
    convention), Bookmarks.plist and Downloads.plist (property lists -
    binary or XML, plistlib reads both transparently), and
    Cookies.binarycookies (a genuinely proprietary but well-reverse-
    engineered, unencrypted, stable binary format - closer in risk profile
    to this app's own hand-rolled Recycle Bin $I/wtmp/USN-journal parsers
    than to something needing a live-device dependency, so it's built
    here rather than scoped out).

Shared by both the real-directory scan (routes/file_explorer.py) and the
in-image scan (routes/image_browser.py) - only how each candidate file's
bytes reach this module differs (a real path on disk vs. one extracted out
of an unmounted image to a temp file first); the parsing itself is
identical either way.
"""
import os
import re
import json
import struct
import sqlite3
import plistlib
import datetime

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


# --- Firefox's own timestamp epoch ---
# Firefox stores places.sqlite/cookies.sqlite timestamps as PRTime -
# microseconds since the Unix epoch (1970-01-01), NOT the WebKit epoch
# Chrome uses above - a real, distinct gotcha in this exact space (easy to
# copy-paste the WebKit conversion and be ~52 years off instead of ~369).
# The one exception: moz_cookies.expiry is stored in whole SECONDS since
# the Unix epoch, not PRTime microseconds - handled separately below, never
# routed through this function.
def firefox_time_to_unix(value):
    """Converts a Firefox PRTime microsecond timestamp (int, or numeric
    string) to Unix epoch seconds. Returns None for 0/empty/unparseable -
    same "0 means unset" convention Chrome's own timestamps use."""
    if not value:
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds == 0:
        return None
    return microseconds / 1_000_000


# --- Safari's own timestamp epoch (Mac Absolute Time / Cocoa Core Data
# epoch) ---
# Safari's History.db (visit_time, a SQLite REAL) and Cookies.binarycookies
# (expiration/creation, 8-byte little-endian doubles) both store
# timestamps as SECONDS (with fractional precision) since 2001-01-01
# 00:00:00 UTC - a FOURTH distinct epoch shape from webkit_time_to_unix()/
# firefox_time_to_unix() above. Confirmed via real forensic-tool source
# (ydkhatri/mac_apt's own safari.py plugin) and independently corroborated
# by several DFIR writeups with worked conversion examples - not guessed.
# This is the SAME reference epoch (2001-01-01) already used for iOS's
# message.date via core/mobile_artifacts.py's cocoa_time_to_unix() - but
# deliberately a separate, simpler function here, not a reuse of that one:
# Safari's values are unambiguously seconds-with-fraction (a plain float),
# with no equivalent to iOS's seconds-vs-nanoseconds magnitude
# disambiguation cocoa_time_to_unix() exists specifically to resolve -
# applying that disambiguation logic to an already-unambiguous Safari
# value would be needless complexity carried over from a different
# problem, not genuine safety.
SAFARI_EPOCH_OFFSET_SECONDS = 978_307_200  # seconds between 2001-01-01 and 1970-01-01


def safari_time_to_unix(value):
    """Converts a Safari Mac-epoch timestamp (float/int seconds since
    2001-01-01, or a numeric string) to Unix epoch seconds. Returns None
    for 0/empty/unparseable, matching the "0 means no timestamp" convention
    webkit_time_to_unix()/firefox_time_to_unix() already use (a
    Cookies.binarycookies expiration of 0 is this format's own convention
    for a session cookie with no fixed expiry)."""
    if not value:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds == 0:
        return None
    return seconds + SAFARI_EPOCH_OFFSET_SECONDS


def _plist_date_to_unix(value):
    """A plist <date> field (Downloads.plist's DownloadEntryDate*Key
    values) is already a native Python datetime once plistlib decodes it -
    NOT a raw epoch number needing manual math the way History.db's SQLite
    REAL column does. A REAL, CONFIRMED GOTCHA caught by this module's own
    test suite (not assumed): plistlib.load() always returns a TIMEZONE-
    NAIVE datetime for a plist <date> - even though the plist/NSDate spec
    defines every such value as UTC - so a naive value's own .timestamp()
    silently treats it as LOCAL time instead (confirmed directly: a real
    2024-01-01 00:00:00 UTC plist date round-tripped through plistlib and
    called .timestamp() without this fix landed 5 hours off on this exact
    dev machine's own timezone, an 18000-second silent error that would
    have shipped as a genuinely wrong Evidence Timeline entry). Fixed by
    explicitly stamping UTC before converting - never relying on plistlib
    or Python's own datetime defaults to have already done this."""
    if not hasattr(value, 'timestamp'):
        return None
    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


# --- Candidate-file detection ---
# Chrome/Chromium profile files have fixed, extensionless names, always
# sitting under a "User Data/<Profile>/" style folder - matched by exact
# basename, not by location, since a real evidence acquisition can have
# that folder nested arbitrarily deep (a user's own AppData tree, an
# extracted phone backup, etc.). Firefox profile files (places.sqlite,
# cookies.sqlite) sit directly under a randomly-named profile folder
# (<hash>.default-release/) - the profile folder's own name is never
# assumed or parsed, since basename-only matching (identical to the Chrome
# approach) already finds them regardless of what the containing folder is
# called or how deep it's nested.
CHROME_ARTIFACT_FILENAMES = {'History', 'Cookies', 'Bookmarks'}
FIREFOX_ARTIFACT_FILENAMES = {'places.sqlite', 'cookies.sqlite'}
# Safari's own fixed filenames all carry a real extension, unlike Chrome's
# bare 'History'/'Cookies'/'Bookmarks' - no basename collision with either
# other family is possible.
SAFARI_ARTIFACT_FILENAMES = {'History.db', 'Bookmarks.plist', 'Downloads.plist', 'Cookies.binarycookies'}
BROWSER_ARTIFACT_FILENAMES = CHROME_ARTIFACT_FILENAMES | FIREFOX_ARTIFACT_FILENAMES | SAFARI_ARTIFACT_FILENAMES

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


def find_browser_artifact_files(root_dir):
    """Recursively finds real files whose basename exactly matches a known
    Chrome/Chromium, Firefox, OR Safari profile filename
    (BROWSER_ARTIFACT_FILENAMES) anywhere under root_dir - these live
    arbitrarily deep in a real acquisition (a user's own AppData/.mozilla/
    Library tree, an extracted phone backup, etc.), so location is never
    assumed, only the filename. Returns
    (paths, truncated) - truncated is True if either cap (candidates found,
    or total files walked) was hit before the walk finished, so a caller
    can disclose an incomplete scan rather than silently presenting it as
    exhaustive."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > BROWSER_ARTIFACT_SCAN_MAX_WALKED:
                return found, True
            if fname in BROWSER_ARTIFACT_FILENAMES:
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


def parse_firefox_places_db(path):
    """Returns {"history": [...], "bookmarks": [...], "downloads": [...]},
    each capped - all three live in the one 'places.sqlite' file, unlike
    Chrome's separate History/Bookmarks files. Every timestamp column here
    is PRTime (Firefox's own microseconds-since-Unix-epoch), never the
    WebKit epoch - see firefox_time_to_unix()."""
    history, bookmarks, downloads = [], [], []
    conn = _open_sqlite_readonly(path)
    try:
        try:
            cur = conn.execute(
                "SELECT p.url, p.title, p.visit_count, p.last_visit_date "
                "FROM moz_places p WHERE p.last_visit_date IS NOT NULL "
                "ORDER BY p.last_visit_date DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_HISTORY,))
            for url, title, visit_count, last_visit_date in cur:
                history.append({
                    "artifact_type": "firefox_history",
                    "title": title or "",
                    "url": url or "",
                    "value": f"{visit_count} visit(s)" if visit_count else "",
                    "timestamp": firefox_time_to_unix(last_visit_date),
                    "extra": {"visit_count": visit_count},
                })
        except sqlite3.OperationalError:
            pass  # not a real/recognizable moz_places table - leave history empty, still try bookmarks/downloads

        try:
            # type=1 is a real bookmark (fk references moz_places.id); a
            # single left join to the immediate parent folder's own title
            # gives a one-level location breadcrumb - not the full nested
            # path Chrome's JSON walk can reconstruct (moz_bookmarks.parent
            # is a self-referencing hierarchy, arbitrarily deep), but a
            # reasonable, honest approximation rather than a second
            # recursive-CTE query for marginal extra depth.
            cur = conn.execute(
                "SELECT p.url, b.title, b.dateAdded, folder.title "
                "FROM moz_bookmarks b "
                "JOIN moz_places p ON b.fk = p.id "
                "LEFT JOIN moz_bookmarks folder ON b.parent = folder.id "
                "WHERE b.type = 1 ORDER BY b.dateAdded DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_BOOKMARKS,))
            for url, title, date_added, folder_title in cur:
                bookmarks.append({
                    "artifact_type": "firefox_bookmarks",
                    "title": title or "",
                    "url": url or "",
                    "value": folder_title or "",
                    "timestamp": firefox_time_to_unix(date_added),
                    "extra": {"folder": folder_title or ""},
                })
        except sqlite3.OperationalError:
            pass  # not a real/recognizable moz_bookmarks table

        try:
            # Modern Firefox has no dedicated downloads table - a download is
            # a moz_places entry with two annotations attached
            # ('downloads/destinationFileURI' holding a file:// URI,
            # optionally 'downloads/metaData' holding a JSON blob with
            # state/bytes). Best-effort and more version-dependent than
            # Chrome's own dedicated downloads table - degrades to an empty
            # list (not a parse failure) on any older/newer schema this
            # query doesn't match, same defensive pattern as Chrome's own
            # downloads try/except below.
            cur = conn.execute(
                "SELECT p.url, a.content, a.dateAdded "
                "FROM moz_annos a "
                "JOIN moz_places p ON a.place_id = p.id "
                "JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id "
                "WHERE attr.name = 'downloads/destinationFileURI' "
                "ORDER BY a.dateAdded DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_DOWNLOADS,))
            for url, dest_uri, date_added in cur:
                # file:///C:/Users/x/Downloads/y.zip -> y.zip - the same
                # basename-only display Chrome's own downloads list uses,
                # via the same cross-platform-separator-safe helper (a
                # file:// URI's path can itself be Windows- or POSIX-style
                # depending on which OS the browser ran on).
                local_path = re.sub(r'^file:///?', '', dest_uri or '')
                downloads.append({
                    "artifact_type": "firefox_downloads",
                    "title": _evidence_path_basename(local_path),
                    "url": url or "",
                    "value": local_path,
                    "timestamp": firefox_time_to_unix(date_added),
                    "extra": {},
                })
        except sqlite3.OperationalError:
            pass  # older/newer Firefox schema this query doesn't match - skip rather than guess
    finally:
        conn.close()
    return {"history": history, "bookmarks": bookmarks, "downloads": downloads}


def parse_firefox_cookies_db(path):
    """Returns a capped list of cookie rows from Firefox's 'cookies.sqlite'.
    Unlike Chrome, Firefox does NOT encrypt cookie values with an OS-level
    key by default - moz_cookies.value is real plaintext, so (unlike
    parse_chrome_cookies_db's deliberate '[encrypted]' placeholder) the
    actual value is included directly. moz_cookies.expiry is the one
    column on this table stored in whole SECONDS since the Unix epoch, not
    PRTime microseconds like every other Firefox timestamp - never routed
    through firefox_time_to_unix()."""
    cookies = []
    conn = _open_sqlite_readonly(path)
    try:
        try:
            cur = conn.execute(
                "SELECT host, name, value, path, expiry, isSecure, isHttpOnly, creationTime "
                "FROM moz_cookies ORDER BY creationTime DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_COOKIES,))
        except sqlite3.OperationalError:
            return cookies  # not a real/recognizable moz_cookies table
        for host, name, value, path_, expiry, is_secure, is_httponly, creation_time in cur:
            cookies.append({
                "artifact_type": "firefox_cookies",
                "title": name or "",
                "url": host or "",
                "value": value or "",
                "timestamp": firefox_time_to_unix(creation_time),
                "extra": {
                    "path": path_, "expires": expiry if expiry else None,
                    "secure": bool(is_secure), "httponly": bool(is_httponly),
                },
            })
    finally:
        conn.close()
    return cookies


def parse_safari_history_db(path):
    """Returns a capped list of History records from Safari's 'History.db'
    - the dominant schema since Safari 8/Yosemite (2014), replacing the
    much older, much less useful 'History.plist' (a single
    lastVisitedDate per URL, overwritten on every revisit - out of scope
    here, matching this app's own "target a reasonably modern, common
    schema" convention already used for Chrome/Firefox). Confirmed
    against real forensic-tool source (ydkhatri/mac_apt's safari.py),
    not guessed: history_visits.visit_time (a SQLite REAL, seconds-with-
    fraction since 2001-01-01) joined against history_items for the URL -
    see safari_time_to_unix()."""
    history = []
    conn = _open_sqlite_readonly(path)
    try:
        try:
            cur = conn.execute(
                "SELECT i.url, v.title, i.visit_count, v.visit_time "
                "FROM history_visits v JOIN history_items i ON v.history_item = i.id "
                "ORDER BY v.visit_time DESC LIMIT ?",
                (BROWSER_ARTIFACT_MAX_HISTORY,))
            for url, title, visit_count, visit_time in cur:
                history.append({
                    "artifact_type": "safari_history",
                    "title": title or "",
                    "url": url or "",
                    "value": f"{visit_count} visit(s)" if visit_count else "",
                    "timestamp": safari_time_to_unix(visit_time),
                    "extra": {"visit_count": visit_count},
                })
        except sqlite3.OperationalError:
            pass  # not a real/recognizable history_visits/history_items schema
    finally:
        conn.close()
    return history


def _walk_safari_bookmark_node(node, folder_path, out, limit):
    """Recursive walk of Safari's Bookmarks.plist tree - keyed by
    WebBookmarkType, not Chrome's own 'type'/Chrome-shaped keys:
    WebBookmarkTypeLeaf is a real bookmark (URLString + a nested
    URIDictionary.title for its display title); WebBookmarkTypeList is a
    folder, nesting via a Children array; WebBookmarkTypeProxy is a
    synthetic entry (Reading List container, a History pseudo-folder) with
    no real URL of its own - walked for its own Children (a Reading List
    proxy's children are real bookmarks) but never itself recorded as a
    bookmark. Confirmed key names against real forensic-tool source
    (ydkhatri/mac_apt's safari.py) and independently corroborated by a
    Safari-bookmark-writing script using the identical keys."""
    if len(out) >= limit or not isinstance(node, dict):
        return
    node_type = node.get('WebBookmarkType')
    if node_type == 'WebBookmarkTypeLeaf':
        uri_dict = node.get('URIDictionary')
        title = uri_dict.get('title', '') if isinstance(uri_dict, dict) else ''
        out.append({
            "artifact_type": "safari_bookmarks",
            "title": title,
            "url": node.get('URLString', ''),
            "value": folder_path,
            "timestamp": None,  # no reliable per-bookmark date field in this format
            "extra": {"folder": folder_path},
        })
    elif node_type in ('WebBookmarkTypeList', 'WebBookmarkTypeProxy'):
        folder_title = node.get('Title', '')
        child_path = f"{folder_path}/{folder_title}" if folder_path and folder_title else (folder_path or folder_title)
        for child in node.get('Children', []) or []:
            if len(out) >= limit:
                return
            _walk_safari_bookmark_node(child, child_path, out, limit)


def parse_safari_bookmarks_plist(path):
    """Returns a capped list of bookmarks from Safari's 'Bookmarks.plist' -
    binary or XML property list (plistlib.load() reads either
    transparently, no format detection needed), a nested WebBookmarkType
    tree rooted at a top-level WebBookmarkTypeList - see
    _walk_safari_bookmark_node(). A single top-down recursive call from
    the real root (unlike Chrome's own parser, which has to specifically
    skip its root node and manually seed a starting breadcrumb to avoid a
    real double-naming bug this app's own test suite already caught once -
    see _walk_bookmark_node()'s docstring) - Safari's tree has no
    equivalent seeding step needed, since the root's own (usually empty)
    Title naturally becomes the first, harmless breadcrumb segment."""
    bookmarks = []
    try:
        with open(path, 'rb') as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return bookmarks
    if not isinstance(data, dict):
        return bookmarks
    _walk_safari_bookmark_node(data, '', bookmarks, BROWSER_ARTIFACT_MAX_BOOKMARKS)
    return bookmarks


def parse_safari_downloads_plist(path):
    """Returns a capped list of downloads from Safari's 'Downloads.plist' -
    a small, highly volatile artifact by Safari's own design: at most the
    last 20 entries, purged after 24 hours (confirmed via a real forensic-
    tool field list - Velociraptor's MacOS.Applications.Safari.Downloads
    artifact - and independently corroborated by a DFIR writeup showing
    the same retention behavior). Date fields are native plist <date>
    values (NSDate) - plistlib decodes these directly into timezone-aware
    Python datetime objects, unlike History.db's raw SQLite REAL column,
    so no manual epoch conversion is applied here - see
    _plist_date_to_unix()."""
    downloads = []
    try:
        with open(path, 'rb') as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return downloads
    if not isinstance(data, dict):
        return downloads
    entries = data.get('DownloadHistory')
    if not isinstance(entries, list):
        return downloads
    for entry in entries[:BROWSER_ARTIFACT_MAX_DOWNLOADS]:
        if not isinstance(entry, dict):
            continue
        target_path = entry.get('DownloadEntryPath', '') or ''
        downloads.append({
            "artifact_type": "safari_downloads",
            "title": _evidence_path_basename(target_path),
            "url": entry.get('DownloadEntryURL', '') or '',
            "value": target_path,
            "timestamp": _plist_date_to_unix(entry.get('DownloadEntryDateAddedKey')),
            "extra": {
                "finished": _plist_date_to_unix(entry.get('DownloadEntryDateFinishedKey')),
                "bytes_so_far": entry.get('DownloadEntryProgressBytesSoFar'),
                "total_bytes": entry.get('DownloadEntryProgressTotalToLoad'),
                # True means this download's own record is meant to be
                # auto-removed once complete - Safari's actual signal for
                # "this came from a Private Browsing window" (confirmed via
                # a DFIR writeup documenting this exact field's real-world
                # meaning), a genuinely useful forensic flag to surface.
                "private_browsing": bool(entry.get('DownloadEntryRemoveWhenDoneKey')),
            },
        })
    return downloads


# --- Safari Cookies.binarycookies: a genuinely proprietary but well-
# reverse-engineered, unencrypted, stable binary format - triangulated
# across four independent sources (a 2013-era Python parser still cited as
# authoritative, a modern actively-maintained Go implementation, a
# technical gist by a credentialed engineer, and a 2024 peer-reviewed
# academic paper - J. Forensic Sci. 69(3):1075-1087) before writing a
# single line of this parser, not guessed at from a vague description.
# Layout: 4-byte magic b'cook', then a BIG-ENDIAN file header (page count +
# a page-size table); every PAGE and every COOKIE RECORD after that is
# LITTLE-ENDIAN - a real, confirmed endianness split within the same file,
# not a mistake to "fix". One genuine open question found during research
# (a newer parser reads an optional 5th "comment" string offset an older
# one doesn't) is sidestepped entirely here by design: this parser only
# ever reads the 4 confirmed offsets (domain/name/path/value) it actually
# needs at their confirmed fixed positions, and resolves every string via
# its own absolute offset + the record's own declared size as a bound,
# rather than assuming a fixed field count runs to the end of the record -
# the same self-describing-offset approach every source above already
# uses, which tolerates an optional trailing field it never reads.
_BINARYCOOKIES_PAGE_HEADER_MARKER = b'\x00\x00\x01\x00'


def _read_binarycookies_cstring(page_bytes, rec_start, rec_end, field_offset):
    """field_offset is relative to rec_start (0 means "field not present" -
    a real, valid convention in this format, not a parse error). Bounds
    every read to [rec_start, rec_end) - the record's own declared size -
    so a corrupted/truncated offset can never read past this record into
    an unrelated one. Returns "" (not None) for a missing/out-of-bounds
    field, matching this app's established best-effort tolerance."""
    if not field_offset:
        return ""
    abs_offset = rec_start + field_offset
    if abs_offset < rec_start or abs_offset >= rec_end or abs_offset >= len(page_bytes):
        return ""
    search_end = min(rec_end, len(page_bytes))
    terminator = page_bytes.find(b'\x00', abs_offset, search_end)
    if terminator == -1:
        terminator = search_end
    return page_bytes[abs_offset:terminator].decode('utf-8', errors='replace')


def _parse_binarycookies_record(page_bytes, rec_start):
    """One cookie record within an already-sliced page's raw bytes,
    rec_start relative to the page. Returns None (never raises) for a
    truncated/malformed record - this app's established per-item best-
    effort tolerance, so one bad record can never abort the rest of the
    page/file."""
    try:
        if rec_start + 56 > len(page_bytes):
            return None
        rec_size = struct.unpack_from('<I', page_bytes, rec_start)[0]
        flags = struct.unpack_from('<I', page_bytes, rec_start + 8)[0]
        domain_off, name_off, path_off, value_off = struct.unpack_from('<IIII', page_bytes, rec_start + 16)
        expiry_raw, creation_raw = struct.unpack_from('<dd', page_bytes, rec_start + 40)
    except struct.error:
        return None
    rec_end = (rec_start + rec_size) if rec_size and rec_start + rec_size <= len(page_bytes) else len(page_bytes)
    domain = _read_binarycookies_cstring(page_bytes, rec_start, rec_end, domain_off)
    name = _read_binarycookies_cstring(page_bytes, rec_start, rec_end, name_off)
    cookie_path = _read_binarycookies_cstring(page_bytes, rec_start, rec_end, path_off)
    value = _read_binarycookies_cstring(page_bytes, rec_start, rec_end, value_off)
    return {
        "artifact_type": "safari_cookies",
        "title": name,
        "url": domain,
        "value": value,
        "timestamp": safari_time_to_unix(creation_raw),
        "extra": {
            "path": cookie_path,
            "expires": safari_time_to_unix(expiry_raw),
            # 1=Secure, 4=HttpOnly, 5=both, 0=neither - a real bit-flag
            # convention confirmed across every source, not a boolean.
            "secure": bool(flags & 1),
            "httponly": bool(flags & 4),
        },
    }


def _parse_binarycookies_page(page_bytes, limit_remaining):
    records = []
    if len(page_bytes) < 8 or page_bytes[:4] != _BINARYCOOKIES_PAGE_HEADER_MARKER:
        return records  # not a real page (corrupted page-size table entry)
    try:
        cookie_count = struct.unpack_from('<I', page_bytes, 4)[0]
    except struct.error:
        return records
    offset_table_start = 8
    for i in range(cookie_count):
        if len(records) >= limit_remaining:
            break
        table_pos = offset_table_start + (i * 4)
        if table_pos + 4 > len(page_bytes):
            break
        try:
            rec_offset = struct.unpack_from('<I', page_bytes, table_pos)[0]
        except struct.error:
            continue
        record = _parse_binarycookies_record(page_bytes, rec_offset)
        if record:
            records.append(record)
    return records


def parse_safari_cookies_binarycookies(path):
    """Returns a capped list of cookie rows from Safari's
    'Cookies.binarycookies'. Unlike Chrome, this format is NOT encrypted -
    the real cookie value is directly readable, same as Firefox's own
    plaintext cookies.sqlite (confirmed across every source consulted for
    this parser, incl. a 2024 peer-reviewed paper specifically studying
    this exact format)."""
    cookies = []
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return cookies
    if len(data) < 8 or data[:4] != b'cook':
        return cookies  # not a real Cookies.binarycookies file despite the matching name
    try:
        num_pages = struct.unpack_from('>I', data, 4)[0]
    except struct.error:
        return cookies
    read_pos = 8
    page_sizes = []
    for _ in range(num_pages):
        if read_pos + 4 > len(data):
            break
        page_sizes.append(struct.unpack_from('>I', data, read_pos)[0])
        read_pos += 4
    for page_size in page_sizes:
        if len(cookies) >= BROWSER_ARTIFACT_MAX_COOKIES:
            break
        if page_size <= 0 or read_pos + page_size > len(data):
            break  # a corrupted/truncated size table entry - stop rather than misread the rest
        page_bytes = data[read_pos:read_pos + page_size]
        read_pos += page_size
        cookies.extend(_parse_binarycookies_page(page_bytes, BROWSER_ARTIFACT_MAX_COOKIES - len(cookies)))
    return cookies


def _match_urls_against_lists(records, url_list_sets):
    """Cross-references every record's own url field (history/bookmark/
    download entries only - cookie records never have one, so they're
    naturally skipped) against the loaded URL lists, emitting one new
    browser_url_ioc_match record per match rather than mutating the
    original record - keeps the original browser-artifact record exactly
    as every other consumer (File Views, Reporting) already expects it,
    while a flagged match gets its own distinct, filterable category
    instead of being buried inside another record's extra field."""
    ioc_records = []
    for r in records:
        url = r.get("url")
        if not url:
            continue
        matched_names = [info["name"] for info in url_list_sets.values() if url in info["urls"]]
        if not matched_names:
            continue
        ioc_records.append({
            "artifact_type": "browser_url_ioc_match",
            "title": f"Known-Bad URL Match: {', '.join(matched_names)}",
            "url": url, "value": r.get("value") or url, "timestamp": r.get("timestamp"),
            "extra": {"matched_lists": matched_names, "source_artifact_type": r["artifact_type"]},
        })
    return ioc_records


def parse_browser_profile_file(path, filename, url_list_sets=None):
    """Dispatches a candidate file (matched by exact basename against
    BROWSER_ARTIFACT_FILENAMES) to the right parser, returning a flat list
    of records (each already shaped {artifact_type, title, url, value,
    timestamp, extra}) - Chrome's 'History' and Firefox's 'places.sqlite'
    each yield more than one artifact_type at once, since more than one
    concept lives in that one file. Any parse failure (corrupted/truncated/
    not actually a browser file despite the matching name) is swallowed and
    returns an empty list - matches this app's established best-effort
    tolerance for a single bad input during a broader scan (e.g.
    _backfill_case_artifact_tags).

    url_list_sets (optional, {list_id: {"name", "urls": set(...)}} from
    core/config.py's load_url_list_sets()) cross-references every
    extracted url-bearing record against loaded known-bad URL lists (2026-
    08-26, Linux-DFIR-tools follow-up) - post-processing after the normal
    dispatch, not threaded into each individual sub-parser, since every
    sub-parser already funnels into this one shared return point."""
    records = []
    try:
        if filename == 'History':
            parsed = parse_chrome_history_db(path)
            records = parsed["history"] + parsed["downloads"]
        elif filename == 'Cookies':
            records = parse_chrome_cookies_db(path)
        elif filename == 'Bookmarks':
            records = parse_chrome_bookmarks_json(path)
        elif filename == 'places.sqlite':
            parsed = parse_firefox_places_db(path)
            records = parsed["history"] + parsed["bookmarks"] + parsed["downloads"]
        elif filename == 'cookies.sqlite':
            records = parse_firefox_cookies_db(path)
        elif filename == 'History.db':
            records = parse_safari_history_db(path)
        elif filename == 'Bookmarks.plist':
            records = parse_safari_bookmarks_plist(path)
        elif filename == 'Downloads.plist':
            records = parse_safari_downloads_plist(path)
        elif filename == 'Cookies.binarycookies':
            records = parse_safari_cookies_binarycookies(path)
    except Exception as e:
        print(f"Warning: could not parse browser artifact file {path} ({filename}): {e}")
        return []

    if url_list_sets and records:
        records = records + _match_urls_against_lists(records, url_list_sets)
    return records
