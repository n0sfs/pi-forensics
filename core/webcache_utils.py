"""Legacy Internet Explorer 10/11 and pre-Chromium ("EdgeHTML") Microsoft
Edge browser history/cookies - WebCacheV01.dat / WebCacheV24.dat, at
%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\. A genuine 4th real browser
family this app hadn't covered - Chrome/Firefox/Safari (core/
browser_artifacts.py) are already built, and modern Chromium-based Edge
already falls under that same Chrome-family parser (identical History/
Cookies SQLite schema), but old IE10/11 and pre-Chromium EdgeHTML Edge
never got picked up anywhere, and both are still real, common finds on
older Windows images.

Grounded via real research (2026-09-01), a follow-up to the SRUM/Windows
Search work the same day: cross-validated the real correlation mechanism
against log2timeline/plaso's own real, actively-maintained production
parser (msie_webcache.py) plus a real, independent 3-part hands-on blog
series (jon.glass, "Misadventures/Adventure in Parsing the
WebCacheV01.dat"). The mechanism is deterministic, the same shape as
SRUM's/Windows Search's own ID-resolution chains: a master `Containers`
table maps a container's own `Name` (e.g. "History", "Cookies",
"DOMStore") to a `ContainerId`, which is then opened directly as a
dynamically-named table `Container_<id>` via pyesedb's own
get_table_by_name() - no fuzzy matching, a real, confirmed lookup.

Scoped to the History, Cookies, and DOMStore containers specifically -
the three container types explicitly named in the research as real,
forensically-interesting targets - not every container this master table
lists (WebCache also tracks raw disk-cache blob metadata and other
lower-value internal bookkeeping containers this module doesn't attempt
to parse).

**A genuine, disclosed residual uncertainty, handled the identical
defensive way core/winsearch_utils.py already established the same day
for its own PropertyStore table**: the exact real column names inside a
Container_<id> table (Url, AccessedTime, ModifiedTime, ExpiryTime,
AccessCount) are well-known from general WebCache forensic-tooling
experience, but weren't independently re-confirmed against a real
on-disk file's own column names this session (no genuine WebCacheV01.dat
was available - see this module's own disclosed-gap note below).
Matched via substring search against each expected fragment, the same
technique already proven correct for Windows Search's own PropertyStore
column-naming uncertainty.

A well-known, real WebCache convention worth recording: the `Url` column
value is commonly prefixed with a colon-tagged marker indicating which
kind of entry it is (e.g. 'Visited: https://example.com/',
'Cookie:user@example.com/', a raw cache-fetch URL with no prefix at all)
- the prefix, when present, is stripped for the record's own title/value
display but preserved verbatim in extra['raw_url'] so nothing is lost.

Disclosed, not silently skipped, matching this app's now-repeated pattern
for a native-dependency parser with no practical way to hand-construct a
valid test file (Prefetch's .pf, SRUM's SRUDB.dat, and Windows Search's
Windows.edb all hit the identical problem the same way): no genuine
WebCacheV01.dat/WebCacheV24.dat was available to parse end-to-end this
session. Field-extraction logic is unit-tested against a stand-in object
mirroring pyesedb's real, live-confirmed API (the same technique already
proven for core/srum_utils.py's and core/winsearch_utils.py's own test
suites). Flagged as an open item for the next time a real sample is
available - any real Windows 10/11 machine's own
%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat would work,
even on a modern machine, since the legacy IE stack's own cache/cookie
jar can still exist there independent of which browser is the current
default.
"""
import os

import pyesedb

from core.registry_utils import filetime_to_unix

WEBCACHE_FILENAMES = {'webcachev01.dat', 'webcachev24.dat'}
WEBCACHE_SCAN_MAX_CANDIDATES = 10
WEBCACHE_SCAN_MAX_WALKED = 20_000
WEBCACHE_MAX_RECORDS_PER_CONTAINER = 5_000

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

_CONTAINERS_TABLE_NAME = 'Containers'
_TARGET_CONTAINER_NAMES = {'history', 'cookies', 'domstore'}

_ROW_FIELD_FRAGMENTS = {
    "url": ("Url", "string"),
    "accessed_time": ("AccessedTime", "int"),
    "modified_time": ("ModifiedTime", "int"),
    "expiry_time": ("ExpiryTime", "int"),
    "access_count": ("AccessCount", "int"),
}
_CONTAINER_ID_FRAGMENT = "ContainerId"
_CONTAINER_NAME_FRAGMENT = "Name"

# The real, well-known 'Visited: '/'Cookie:' style tag prefixes some
# WebCache Url values carry (see this module's own docstring) - stripped
# for display, preserved verbatim in extra['raw_url'].
_URL_TAG_PREFIXES = ('visited: ', 'cookie:', 'downloaded:')


def find_webcache_files(root_dir):
    """Recursively finds real WebCacheV01.dat/WebCacheV24.dat files
    (matched by exact basename, case-insensitive) anywhere under
    root_dir. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > WEBCACHE_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() in WEBCACHE_FILENAMES:
                found.append(os.path.join(root, fname))
                if len(found) >= WEBCACHE_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _column_index_map(table):
    out = {}
    for i in range(table.get_number_of_columns()):
        try:
            out[table.get_column(i).get_name()] = i
        except Exception:
            continue
    return out


def _get_value(record, idx, kind):
    if idx is None:
        return None
    try:
        if kind == 'int':
            return record.get_value_data_as_integer(idx)
        if kind == 'string':
            return record.get_value_data_as_string(idx)
        return record.get_value_data(idx)
    except Exception:
        return None


def _find_column(all_column_names, fragment):
    return next((name for name in all_column_names if fragment.lower() in name.lower()), None)


def _strip_url_tag(raw_url):
    if not raw_url:
        return raw_url
    lowered = raw_url.lower()
    for prefix in _URL_TAG_PREFIXES:
        if lowered.startswith(prefix):
            return raw_url[len(prefix):].strip()
    return raw_url


def _list_target_containers(esedb_file):
    """Reads the master Containers table, returns
    [(container_id, container_name), ...] for every container whose real
    Name matches one of _TARGET_CONTAINER_NAMES (case-insensitive
    substring, e.g. a real 'Content' or 'History' variant name). Returns
    [] if the Containers table itself is missing/unreadable - not a real
    WebCache file, or a genuinely different schema version this module's
    column-fragment matching can't recognize."""
    try:
        table = esedb_file.get_table_by_name(_CONTAINERS_TABLE_NAME)
    except Exception:
        table = None
    if table is None:
        return []
    col_map = _column_index_map(table)
    id_col = col_map.get(_find_column(list(col_map.keys()), _CONTAINER_ID_FRAGMENT))
    name_col = col_map.get(_find_column(list(col_map.keys()), _CONTAINER_NAME_FRAGMENT))
    if id_col is None or name_col is None:
        return []

    try:
        record_count = table.get_number_of_records()
    except Exception:
        return []

    targets = []
    for i in range(record_count):
        try:
            record = table.get_record(i)
        except Exception:
            continue
        container_id = _get_value(record, id_col, 'int')
        container_name = _get_value(record, name_col, 'string')
        if container_id is None or not container_name:
            continue
        name_lower = container_name.lower()
        if any(target in name_lower for target in _TARGET_CONTAINER_NAMES):
            targets.append((container_id, container_name))
    return targets


def _parse_container_rows(esedb_file, container_id, container_name):
    try:
        table = esedb_file.get_table_by_name(f"Container_{container_id}")
    except Exception:
        table = None
    if table is None:
        return []
    col_map = _column_index_map(table)
    all_names = list(col_map.keys())
    resolved = {key: _find_column(all_names, frag) for key, (frag, _kind) in _ROW_FIELD_FRAGMENTS.items()}

    try:
        record_count = table.get_number_of_records()
    except Exception:
        return []

    records = []
    for i in range(min(record_count, WEBCACHE_MAX_RECORDS_PER_CONTAINER)):
        try:
            record = table.get_record(i)
        except Exception:
            continue
        values = {}
        for key, (frag, kind) in _ROW_FIELD_FRAGMENTS.items():
            col_name = resolved.get(key)
            idx = col_map.get(col_name) if col_name else None
            values[key] = _get_value(record, idx, kind)

        raw_url = values.get("url")
        display_url = _strip_url_tag(raw_url)
        if not display_url:
            continue

        timestamp = filetime_to_unix(values.get("modified_time"))
        if timestamp is None:
            timestamp = filetime_to_unix(values.get("accessed_time"))

        records.append({
            "artifact_type": "webcache_entry", "title": display_url, "url": display_url,
            "value": display_url, "timestamp": timestamp,
            "extra": {
                "container": container_name,
                "raw_url": raw_url,
                "accessed_timestamp": filetime_to_unix(values.get("accessed_time")),
                "modified_timestamp": filetime_to_unix(values.get("modified_time")),
                "expiry_timestamp": filetime_to_unix(values.get("expiry_time")),
                "access_count": values.get("access_count"),
            },
        })
    return records


def parse_webcache_file(path, filename=None):
    """Parses a real WebCacheV01.dat/WebCacheV24.dat into a list of
    {artifact_type: "webcache_entry"} records across every real target
    container found (History/Cookies/DOMStore) - each record's
    extra['container'] discloses which one it came from. Returns [] on
    any failure to open the file at all (not a real ESE database,
    corrupted, wrong format) - the same best-effort tolerance every other
    parser in this app already applies."""
    esedb_file = pyesedb.file()
    try:
        esedb_file.open(path)
    except Exception:
        return []
    try:
        targets = _list_target_containers(esedb_file)
        records = []
        for container_id, container_name in targets:
            records.extend(_parse_container_rows(esedb_file, container_id, container_name))
        return records
    finally:
        try:
            esedb_file.close()
        except Exception:
            pass
