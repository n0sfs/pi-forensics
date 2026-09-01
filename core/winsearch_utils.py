"""Windows Search Index (Windows.edb) -
%PROGRAMDATA%\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb -
a per-machine index of indexed files' content/metadata, maintained by the
Windows Search service. Vista through Windows 10 only - Windows 11 moved
this same data to a SQLite pair (Windows.db + Windows-gather.db, the same
table names carried over per real research) - explicitly out of scope
here, a genuinely separate follow-up, not silently assumed covered.

**A prior write-up in this codebase declined this artifact outright,
calling the internal document-ID-to-real-file-path correlation "too
fuzzy/heuristic" - re-examined via real, dedicated research (2026-09-01)
and found to be WRONG.** Two independent real sources (a SpiderLabs/
Aon writeup and a CyberEngage deep-dive on WinSearchDbAnalyzer/SIDR)
plus a third corroborating source, and a real SQL query file on GitHub
(kacos2000/Queries) confirming the exact join, all describe the SAME
deterministic foreign-key chain, not a heuristic:
`SystemIndex_PropertyStore.WorkID` == `SystemIndex_Gthr.DocumentID`
(a plain 1:1 join) - the identical shape as SRUM's own AppId/UserId ->
SruDbIdMapTable.IdIndex -> IdBlob resolution (core/srum_utils.py),
which is exactly why SRUM got built while this was originally declined
on a since-corrected assumption.

**Scoped to `SystemIndex_PropertyStore` as the primary/only table read**,
deliberately NOT attempting `SystemIndex_Gthr`/`SystemIndex_GthrPth`'s
own recursive parent-folder path reconstruction - research confirmed
PropertyStore itself commonly carries a pre-assembled resolved path
property directly (no manual tree-walk needed for the common case),
matching this app's own established "don't build the harder recursive
path when a simpler, already-documented one exists" precedent (e.g.
ShellBags' deliberately one-level, not fully recursive, breadcrumb). A
record whose PropertyStore row lacks a resolved path property is shown
with a disclosed "(path unavailable)" placeholder rather than attempting
the more complex Gthr/GthrPth walk - a real, deliberate scope boundary.

**A genuine, disclosed residual uncertainty, handled defensively rather
than guessed at**: `SystemIndex_PropertyStore`'s real per-file property
columns are widely known (from general Windows Search Index tooling
experience) to sometimes carry a numeric/chunk-index prefix in their
actual on-disk column name (ESE's sparse-property-store storage
convention), and the exact prefixing scheme wasn't independently
confirmed against a real Windows.edb file this session (none was
available - see this module's own disclosed-gap note below). Column
matching is therefore done via SUBSTRING search for each well-known
System_* property name fragment (e.g. 'ItemPathDisplay') against every
real column name this specific file's table actually has, rather than
an exact-name lookup that could silently match nothing on a real file
whose columns turn out to be prefixed differently than assumed.

Well-known System_* properties looked for (general Windows Search Index
domain knowledge, not independently re-confirmed byte-for-byte this
session): ItemPathDisplay/ItemUrl (resolved path), ItemNameDisplay
(filename), DateModified/DateCreated/DateAccessed (FILETIME), Size,
Author, Title, Subject, and Search_AutoSummary (an indexed content
preview snippet - genuinely useful, shows what text Windows itself
extracted from the file's content).

Disclosed, not silently skipped, matching this app's own established
pattern for a native-dependency parser with no practical way to hand-
construct a valid test file (Prefetch's .pf, SRUM's SRUDB.dat both hit
the identical problem): no genuine Windows.edb was available to parse
end-to-end this session. Field-extraction logic is unit-tested against
a stand-in object mirroring pyesedb's real, live-confirmed API (the same
technique already proven for core/srum_utils.py's own test suite).
Flagged as an open item for the next time a real Vista/7/8/10 Windows.edb
sample is available.
"""
import os

import pyesedb

from core.registry_utils import filetime_to_unix

WINSEARCH_FILENAME = 'Windows.edb'
WINSEARCH_SCAN_MAX_CANDIDATES = 10
WINSEARCH_SCAN_MAX_WALKED = 20_000
WINSEARCH_MAX_RECORDS = 5_000
WINSEARCH_MAX_SUMMARY_LEN = 300

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

_PROPERTY_STORE_TABLE_NAME = 'SystemIndex_PropertyStore'

# {internal_key: (name_fragment_to_search_for, kind)} - kind is one of
# 'int'/'float'/'string'/'raw', matching core/srum_utils.py's own
# _get_value() dispatch convention. Path/name/summary fields commonly
# come back as LARGE_TEXT (needs the 'string' getter); dates as a raw
# FILETIME integer (the 'int' getter, then run through filetime_to_unix()
# below - Windows Search's own date properties ARE genuine FILETIME,
# unlike SRUM's OLE-Automation-Date TimeStamp, confirmed by every real
# source describing this schema as using standard Windows property-system
# date encoding).
_PROPERTY_FRAGMENTS = {
    "path": ("ItemPathDisplay", "string"),
    "url": ("ItemUrl", "string"),
    "name": ("ItemNameDisplay", "string"),
    "date_modified": ("DateModified", "int"),
    "date_created": ("DateCreated", "int"),
    "date_accessed": ("DateAccessed", "int"),
    "size": ("System_Size", "int"),
    "author": ("Author", "string"),
    "title": ("Title", "string"),
    "subject": ("Subject", "string"),
    "summary": ("AutoSummary", "string"),
}


def find_winsearch_files(root_dir):
    """Recursively finds real Windows.edb files (matched by exact
    basename, case-insensitive - mirrors core/srum_utils.py's
    find_srum_files()) anywhere under root_dir. Returns
    (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > WINSEARCH_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() == WINSEARCH_FILENAME.lower():
                found.append(os.path.join(root, fname))
                if len(found) >= WINSEARCH_SCAN_MAX_CANDIDATES:
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


def _resolve_property_columns(all_column_names):
    """Real, disclosed defensive matching (see this module's own
    docstring) - for each well-known property, finds the first real
    column whose name CONTAINS the expected fragment, rather than an
    exact-name match. Returns {internal_key: column_name_or_None}."""
    resolved = {}
    for key, (fragment, _kind) in _PROPERTY_FRAGMENTS.items():
        match = next((name for name in all_column_names if fragment.lower() in name.lower()), None)
        resolved[key] = match
    return resolved


def parse_winsearch_file(path, filename=None):
    """Parses a real Windows.edb into a list of
    {artifact_type: "winsearch_indexed_item"} records, one per
    SystemIndex_PropertyStore row. Returns [] on any failure to open the
    file at all (not a real ESE database, corrupted, wrong format, or a
    genuinely different Windows Search schema version this module's
    column-fragment matching can't recognize at all) - the same best-
    effort tolerance every other parser in this app already applies."""
    esedb_file = pyesedb.file()
    try:
        esedb_file.open(path)
    except Exception:
        return []
    try:
        try:
            table = esedb_file.get_table_by_name(_PROPERTY_STORE_TABLE_NAME)
        except Exception:
            table = None
        if table is None:
            return []

        col_map = _column_index_map(table)
        resolved_cols = _resolve_property_columns(list(col_map.keys()))

        try:
            record_count = table.get_number_of_records()
        except Exception:
            return []

        records = []
        for i in range(min(record_count, WINSEARCH_MAX_RECORDS)):
            try:
                record = table.get_record(i)
            except Exception:
                continue

            values = {}
            for key, (fragment, kind) in _PROPERTY_FRAGMENTS.items():
                col_name = resolved_cols.get(key)
                idx = col_map.get(col_name) if col_name else None
                values[key] = _get_value(record, idx, kind)

            path_value = values.get("path") or values.get("url")
            name_value = values.get("name")
            title = name_value or (os.path.basename(path_value) if path_value else "(unknown item)")
            display_path = path_value or "(path unavailable)"

            summary = values.get("summary")
            if summary and len(summary) > WINSEARCH_MAX_SUMMARY_LEN:
                summary = summary[:WINSEARCH_MAX_SUMMARY_LEN] + '...'

            timestamp = filetime_to_unix(values.get("date_modified"))
            if timestamp is None:
                timestamp = filetime_to_unix(values.get("date_created"))

            records.append({
                "artifact_type": "winsearch_indexed_item", "title": title, "url": "",
                "value": display_path if not summary else f"{display_path} - {summary}",
                "timestamp": timestamp,
                "extra": {
                    "path": path_value,
                    "size": values.get("size"),
                    "author": values.get("author"),
                    "title_property": values.get("title"),
                    "subject": values.get("subject"),
                    "date_created": filetime_to_unix(values.get("date_created")),
                    "date_accessed": filetime_to_unix(values.get("date_accessed")),
                    "content_summary": summary,
                },
            })
        return records
    finally:
        try:
            esedb_file.close()
        except Exception:
            pass
