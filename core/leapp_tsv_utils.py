"""ALEAPP/iLEAPP TSV-export parsing (Android forensics expansion, Phase A).
Both tools' artifact modules (a shared codebase at their pinned commits -
see routes/file_explorer.py's LEAPP_TOOLS dict) use an @artifact_processor
decorator whose default output_types includes 'tsv' - every module that
finds non-empty data already writes its own <module>.tsv file into
`<result_dir>/_TSV Exports/`, completely independent of any CLI flag, on
every ALEAPP/iLEAPP run this app already performs. This module reads that
already-produced, previously-unread machine-readable output.

Confirmed for BOTH tools by directly reading their real installed source
at each one's own pinned commit on the deployed station (not inferred
from "they're sibling projects"): `artifact_processor()` and `tsv()` in
ALEAPP's `scripts/ilapfuncs.py` and iLEAPP's own `scripts/ilapfuncs.py`
are byte-identical in the relevant parts - same decorator, same default
`output_types`, same literal `'_TSV Exports'` folder name, same `tsv()`
function signature. This app's own iOS acquisitions never had a real
backup on this station to run iLEAPP against live, so this direct source
comparison is what actually closes that gap, not a live iLEAPP run.

A REAL, GROUNDED FINDING SHAPES THIS MODULE'S DESIGN, not a guess: a live
run against this app's own real, non-rooted `adb pull` extraction (a real
8.7GB Pixel 8a /sdcard dump) showed the overwhelming majority of ALEAPP's
~1032 modules target /data/data/<package>/databases paths that simply
don't exist in a non-rooted pull's output at all - confirmed directly via
ALEAPP's own real run log, hundreds of consecutive "No file found" module
results. This is expected, not a bug: /data/data/ is root-gated, and
`pull` mode (routes/mobile.py) never reaches it. A hand-curated allowlist
naming only a small, guessed set of modules would risk missing whatever
handful of modules DO find real data on any given real device (which apps
are installed, what's cached on shared storage, varies device to device -
unpredictable in advance). So this module uses a TWO-TIER design instead
of a strict allowlist gate:

  1. A small CURATED_LEAPP_MODULES table promotes specific, well-known,
     stable module names (confirmed real - not guessed - against this
     app's own pinned ALEAPP commit's real module catalog, observed
     directly in real run logs) to their own dedicated artifact_type, for
     the modules most likely to matter and be searched/filtered on their
     own (device info, WiFi networks, installed apps).
  2. Every OTHER TSV file actually present (any module that found real
     data, regardless of whether this module's author anticipated it) is
     parsed generically into a SINGLE shared artifact_type,
     "leapp_module_finding" - the module name and every column value ride
     along in `extra`/`value`, so real data is never silently dropped just
     because this codebase didn't happen to name that exact module ahead
     of time. This is the resolution to a real tension already noted
     during this feature's own design review: a fully-generic "one
     artifact_type per dynamically-discovered module" approach would make
     the hand-maintained PARSED_ARTIFACT_TYPE_LABELS pair (routes/
     case_index.py, static/js/main.js) unbounded and impossible to keep
     mirrored/audited; a strict curated-only allowlist would silently
     drop real findings this module's author never anticipated. One
     shared fallback bucket gets both properties at once.

TIMESTAMP PARSING (added later, once real hit data still never
materialized but real SOURCE CODE did). No real ALEAPP run against a real
device ever produced a non-empty TSV to design against (see the dated
CLAUDE.md entry above) - but ALEAPP/iLEAPP are both fully vendored on this
station at a PINNED commit, so instead of guessing, every curated
module's actual real `scripts/artifacts/*.py` source was read directly
off the deployed station (not assumed from "sibling modules probably look
alike") to find its exact `data_headers`/timestamp-column-name/timestamp-
formatting convention, module by module, before any of this was written.
Confirmed independently across 8+ separately-authored modules
(smsmms.py, calllog.py, calllogs.py, WhatsApp.py, chrome.py,
firefox.py, instagram.py, telegramAndroid.py, signalAndroid.py,
tikTok.py, reddit.py, snapchat.py, FacebookMessenger.py): every one of
them builds its timestamp value as a tz-aware
`datetime.datetime(..., tzinfo=datetime.timezone.utc)` object, which
`ilapfuncs.py`'s own `tsv()` writer then stringifies via Python's default
`csv.writer` behavior (calling `str()` on a non-string cell) - producing
the fixed, unambiguous shape `"YYYY-MM-DD HH:MM:SS[.ffffff]+00:00"` in
every TSV file this app will ever read. `datetime.fromisoformat()`
(confirmed against this app's own real Python 3.13 runtime, both the dev
machine and the production venv) parses that shape directly, no format
string needed. A module's ACTUAL timestamp COLUMN NAME varies a lot
module to module ("Date", "Call Date", "start_date", "Message Timestamp",
"Last Visit Time"/"Last Visit Date", "Timestamp", ...) - confirmed by
reading each one's real `data_headers` tuple directly, never assumed from
a naming convention - so `LEAPP_TIMESTAMP_COLUMNS` below is a real,
per-artifact_type list of the exact confirmed candidate column name(s) to
look for (more than one, for an artifact_type fed by more than one real
module using a different column name for the same concept - e.g. the two
real "Call Logs" modules). An artifact_type not in that dict, or a real
row whose value doesn't parse, gets `timestamp: None` exactly as before -
never a guessed/fabricated value. `leapp_module_finding` (the generic
fallback bucket for anything not individually curated) is deliberately
NOT in `LEAPP_TIMESTAMP_COLUMNS` at all - its column shape is unknown by
definition, so it always stays timestamp-less and never reaches the
Evidence Timeline, only File Views' searchable Parsed Artifacts list.
"""
import csv
import datetime
import os
import re

LEAPP_TSV_MAX_FILES = 300  # a real run's _TSV Exports/ folder, capped
LEAPP_TSV_MAX_ROWS_PER_FILE = 5_000

# Confirmed real module/report names - either observed directly in this
# app's own real ALEAPP run logs, or (for every entry added later, see the
# module docstring above) read directly from the module's own real
# `__artifacts_v2__["name"]` registration at this app's pinned commit, not
# guessed. Promoted to their own dedicated, filterable artifact_type.
# Matched case-insensitively/non-alnum-collapsed against the TSV
# filename's own stem via _normalize_module_name() (ALEAPP names each TSV
# after the human-readable report name it registers, not the raw Python
# function name - e.g. "Call logs " with a trailing space is a REAL,
# confirmed registered name, normalized the same as "Call Logs").
CURATED_LEAPP_MODULES = {
    # --- Device & System (kept from the original guessed set; "build"/
    # "wifi config store"/"accounts ce"/"accounts de"/the 3
    # installedapps* keys below are the real confirmed names found later -
    # the original guesses are harmless dead weight, kept in case a future
    # ALEAPP version reintroduces a module using that exact name) ---
    "device info": "leapp_device_info", "build": "leapp_device_info",
    "wifi": "leapp_wifi_network", "wifi config store": "leapp_wifi_network",
    "installed applications": "leapp_installed_app", "installed apps": "leapp_installed_app",
    "installedappsgass": "leapp_installed_app", "installedappslibrary": "leapp_installed_app",
    "installedappsvending": "leapp_installed_app",
    "accounts": "leapp_account", "accounts ce": "leapp_account", "accounts de": "leapp_account",
    "usage stats": "leapp_app_usage",
    "contacts": "leapp_contact",

    # --- Communications (native SMS/MMS/calls) ---
    "sms messages": "leapp_sms_message", "sms & mms": "leapp_sms_message",
    "mms messages": "leapp_mms_message",
    "call logs": "leapp_call_log",  # normalizes both real registered names: "Call logs " and "Call Logs"

    # --- Web Activity ---
    "browser history": "leapp_browser_history",  # kept from the original guessed set
    "web history": "leapp_browser_history", "firefox web history": "leapp_browser_history",
    "web visits": "leapp_browser_web_visit", "firefox web visits": "leapp_browser_web_visit",
    "browser bookmarks": "leapp_browser_bookmark", "firefox bookmarks": "leapp_browser_bookmark",
    "chrome autofill": "leapp_browser_autofill", "chrome autofill entries": "leapp_browser_autofill",

    # --- Social Media / Messaging Apps ---
    "whatsapp - messages": "leapp_whatsapp_message",  # kept from the original guessed set
    "whatsapp messages": "leapp_whatsapp_message",
    "whatsapp one to one messages": "leapp_whatsapp_message",
    "whatsapp group messages": "leapp_whatsapp_message",
    "whatsapp - contacts": "leapp_whatsapp_contact",  # kept from the original guessed set
    "whatsapp contacts": "leapp_whatsapp_contact",
    "whatsapp call logs": "leapp_whatsapp_call_log",
    "instagram direct messages": "leapp_instagram_message",
    "snapchat messages": "leapp_snapchat_message",
    "facebook messenger chats msys database": "leapp_facebook_messenger_message",
    "facebook messenger chats threads db2": "leapp_facebook_messenger_message",
    "telegram messages": "leapp_telegram_message",
    "signal messages": "leapp_signal_message",
    "tiktok messages": "leapp_tiktok_message",
    "reddit chat messages": "leapp_reddit_message",
}

# Real, per-artifact_type candidate timestamp column name(s), read directly
# from each real module's own `data_headers` return value at this app's
# pinned ALEAPP commit (see the module docstring above for the full
# grounding). Tried in order against a TSV's real header row (case-
# insensitive exact match) - the first one present wins, since more than
# one real module can feed the same artifact_type under a different
# column name (e.g. the two independently-authored "Call Logs" modules).
# An artifact_type not listed here always gets timestamp: None.
LEAPP_TIMESTAMP_COLUMNS = {
    "leapp_sms_message": ("Date",),
    "leapp_mms_message": ("Date",),
    "leapp_call_log": ("Call Date", "start_date"),
    "leapp_browser_history": ("Last Visit Time", "Last Visit Date"),
    "leapp_browser_web_visit": ("Visit Timestamp", "Visit Date"),
    "leapp_whatsapp_message": ("Message Timestamp",),
    "leapp_whatsapp_call_log": ("Call Start Timestamp",),
    "leapp_instagram_message": ("Timestamp",),
    "leapp_snapchat_message": ("Creation Timestamp",),
    "leapp_facebook_messenger_message": ("Message Timestamp", "Timestamp"),
    "leapp_telegram_message": ("Timestamp",),
    "leapp_signal_message": ("Date Sent", "Date Received"),
    "leapp_tiktok_message": ("Timestamp",),
    "leapp_reddit_message": ("Timestamp",),
    # 2026-09-04, Android pattern-of-life item 4: leapp_installed_app maps
    # 3 real, structurally different ALEAPP modules (installedappsGass.py/
    # installedappsLibrary.py/installedappsVending.py), confirmed directly
    # against this app's own pinned ALEAPP source on the deployed station -
    # only 2 of the 3 carry any timestamp at all. installedappsGass.py's
    # own data_headers is ('User', 'Bundle ID', 'Version Code',
    # 'SHA-256 Hash') - no datetime column exists in that module at all,
    # so a Gass-sourced row correctly keeps timestamp=None regardless;
    # this is not a gap this fix can close, it's a real absence in the
    # source data. installedappsLibrary.py's own header has ('Purchase
    # Time', 'datetime'); installedappsVending.py's has both
    # ('First Download', 'datetime') and ('Last Updated', 'datetime') in
    # the same row - 'First Download' is listed first since it's the
    # closer semantic match to "installed" than 'Last Updated' is, and
    # only the first candidate present in a given file's real header row
    # is ever used (see _find_timestamp_column_index() below).
    "leapp_installed_app": ("First Download", "Purchase Time"),
    # usagestats.py's own real data_headers has 4 separate datetime-typed
    # columns; 'Timestamp / Last Time Active' is the module's own primary
    # per-event field (listed first, right after the User column, always
    # populated - confirmed directly against the real module source).
    "leapp_app_usage": ("Timestamp / Last Time Active",),
}

# Every artifact_type this module can ever produce, for the label-dict
# regression test to assert against without needing to import this
# module's internal table shape.
LEAPP_TSV_ALL_ARTIFACT_TYPES = set(CURATED_LEAPP_MODULES.values()) | {"leapp_module_finding"}

_NON_ALNUM_RE = re.compile(r'[^a-z0-9]+')


def _normalize_module_name(tsv_stem):
    """ALEAPP TSV filenames are the report's own display name (e.g. 'Wifi
    Networks.tsv', 'SMS & MMS.tsv') - normalize to lowercase/collapsed-
    whitespace for matching against CURATED_LEAPP_MODULES's own keys,
    which are written in the same lowercase human-readable form."""
    return _NON_ALNUM_RE.sub(' ', tsv_stem.lower()).strip()


def find_leapp_tsv_files(tsv_export_dir):
    """Lists real .tsv files directly under `<result_dir>/_TSV Exports/` -
    a flat directory (confirmed via ALEAPP's own ilapfuncs.py TSV-writer,
    which always writes one file per module directly into this folder, no
    further nesting), so a plain listdir is sufficient - no recursive walk
    needed the way real-fs/in-image whole-scan parsers elsewhere in this
    app require. Returns (paths, truncated)."""
    if not tsv_export_dir or not os.path.isdir(tsv_export_dir):
        return [], False
    try:
        names = sorted(f for f in os.listdir(tsv_export_dir) if f.lower().endswith('.tsv'))
    except OSError:
        return [], False
    truncated = len(names) > LEAPP_TSV_MAX_FILES
    names = names[:LEAPP_TSV_MAX_FILES]
    return [os.path.join(tsv_export_dir, n) for n in names], truncated


def _find_timestamp_column_index(headers, artifact_type):
    """Returns the index of the first header (case-insensitive exact
    match) matching one of artifact_type's real confirmed candidate
    timestamp column names, or None if there's no confirmed candidate for
    this artifact_type or none of them are actually present in this
    file's real header row (an older/newer ALEAPP version could rename a
    column - a miss here just means timestamp: None, never a wrong
    guess)."""
    candidates = LEAPP_TIMESTAMP_COLUMNS.get(artifact_type)
    if not candidates:
        return None
    lowered = [h.strip().lower() for h in headers]
    for cand in candidates:
        cand_lower = cand.strip().lower()
        if cand_lower in lowered:
            return lowered.index(cand_lower)
    return None


# Fallback timestamp detection for UNCURATED modules (2026-09-14).
#
# The curated path above is unchanged and still takes precedence: for an
# artifact_type in LEAPP_TIMESTAMP_COLUMNS, the column name was confirmed by
# reading that module's real ALEAPP source, and that remains the strongest
# possible basis. This adds a second, weaker-but-still-evidence-based path for
# everything landing in the generic `leapp_module_finding` bucket, which until
# now was hard-coded to stay timestamp-less forever on the reasoning that its
# column shape is "unknown by definition".
#
# That reasoning turned out to be too pessimistic against real output. The DJI
# flight-track module - genuinely uncurated, one of 1000+ - writes a column
# named literally "Timestamp" carrying "2026-02-21 16:16:31+00:00": the exact
# unambiguous shape ilapfuncs.py's own tsv() writer produces for every module.
# 2,842 real rows in this project's own case, including 2,826 GPS points with
# genuine per-point times, were being dropped to timestamp: None and therefore
# never reaching the Evidence Timeline at all.
#
# This is still not guessing, because a candidate column is only accepted once
# its REAL VALUES have been shown to parse via _parse_leapp_datetime_str() -
# the same strict parser the curated path uses, which accepts only that one
# known shape. A name that looks temporal but whose values don't parse is
# rejected, exactly as before. Two further guards:
#   - Name tiers, most specific first. A column actually called "timestamp"
#     beats one merely containing "date", so a module carrying both a real
#     event time and some incidental other date doesn't silently pick whichever
#     came first in the header row.
#   - The chosen column name is recorded on every row it timestamps
#     (extra["leapp_timestamp_column"]), so the basis for the timestamp is
#     visible to an examiner and auditable, rather than being an invisible
#     inference. Curated rows do not carry it, which is itself the signal that
#     they came from the stronger, source-confirmed path.
_LEAPP_FALLBACK_TS_NAME_TIERS = (
    lambda h: h == 'timestamp',
    lambda h: h in ('date', 'time', 'datetime', 'date/time', 'date time'),
    lambda h: 'timestamp' in h,
    lambda h: re.search(r'\b(date|time)\b', h) is not None,
)
# How many non-empty values must be seen parsing before a column is trusted.
# One would be a coincidence away from wrong; requiring a few means a column of
# genuinely temporal data, while staying tolerant of the many blank cells real
# ALEAPP output contains.
_LEAPP_FALLBACK_TS_MIN_PARSED = 3
_LEAPP_FALLBACK_TS_SAMPLE_ROWS = 50


def _detect_fallback_timestamp_column(headers, rows):
    """For an uncurated module, finds a column whose name looks temporal AND
    whose real values actually parse. Returns (index, header_name) or
    (None, None). See this section's own comment for why this is evidence-
    based rather than a guess."""
    lowered = [h.strip().lower() for h in headers]
    sample = rows[:_LEAPP_FALLBACK_TS_SAMPLE_ROWS]
    for matches in _LEAPP_FALLBACK_TS_NAME_TIERS:
        for idx, name in enumerate(lowered):
            if not name or not matches(name):
                continue
            parsed = 0
            for row in sample:
                if idx < len(row) and _parse_leapp_datetime_str(row[idx]) is not None:
                    parsed += 1
                    if parsed >= _LEAPP_FALLBACK_TS_MIN_PARSED:
                        return idx, headers[idx].strip()
            # A short file can legitimately hold fewer rows than the minimum -
            # accept it only if EVERY non-empty value in it parsed, which is a
            # stronger condition than the count, not a weaker one.
            non_empty = [r[idx] for r in sample if idx < len(r) and r[idx].strip()]
            if non_empty and parsed == len(non_empty):
                return idx, headers[idx].strip()
    return None, None


def _parse_leapp_datetime_str(value):
    """Parses ALEAPP/iLEAPP's own real timestamp string shape - see the
    module docstring's TIMESTAMP PARSING section for exactly how this
    format was confirmed (real source, not guessed). Returns a Unix epoch
    float, or None for an empty/absent/unparseable value - never a
    fabricated timestamp.

    A value carrying no UTC offset is REJECTED rather than assumed
    (2026-09-14). datetime.fromisoformat() happily parses a naive
    "2026-02-21 16:16:31", and .timestamp() then interprets it in the
    SERVER's local zone - measured on the real station (EDT) that is a
    silent 5-hour error, presented in the Evidence Timeline as a genuine
    event time. The curated columns were all confirmed tz-aware against
    ALEAPP's own source, so this only ever bites the uncurated fallback
    path, which accepts any column whose values merely parse. Since this
    module cannot know what zone a naive value was recorded in, guessing
    UTC would be just as wrong as guessing local - so nothing is claimed,
    matching how every other unparseable value here is treated.
    """
    if not value or not value.strip():
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.strip())
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        return None
    return parsed.timestamp()


def _parse_one_tsv(path, tool_key):
    stem = os.path.splitext(os.path.basename(path))[0]
    module_key = _normalize_module_name(stem)
    artifact_type = CURATED_LEAPP_MODULES.get(module_key, "leapp_module_finding")

    records = []
    try:
        with open(path, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.reader(f, delimiter='\t')
            try:
                headers = next(reader)
            except StopIteration:
                return records  # empty file (header-only or truly empty)
            ts_col_idx = _find_timestamp_column_index(headers, artifact_type)
            ts_col_name = None
            # Buffered rather than streamed so an uncurated module's timestamp
            # column can be validated against its own real values before any
            # row is built - detection has to see the data to be evidence-based
            # rather than a guess. Bounded by the same per-file row cap that
            # already applied, so this reads no more than it ever did.
            data_rows = []
            for i, row in enumerate(reader):
                if i >= LEAPP_TSV_MAX_ROWS_PER_FILE:
                    break
                if not row or not any(cell.strip() for cell in row):
                    continue
                data_rows.append(row)
            if ts_col_idx is None:
                ts_col_idx, ts_col_name = _detect_fallback_timestamp_column(headers, data_rows)
            for row in data_rows:
                # Pair headers with the row defensively - ALEAPP TSVs are
                # not guaranteed to have exactly len(headers) cells per
                # row (a value containing a literal tab, or a short/
                # ragged row from an older module version, is possible).
                pairs = list(zip(headers, row))
                value_text = " | ".join(f"{h}: {v}" for h, v in pairs if v and v.strip())
                title = row[0].strip() if row and row[0].strip() else stem
                timestamp = (_parse_leapp_datetime_str(row[ts_col_idx])
                             if ts_col_idx is not None and ts_col_idx < len(row) else None)
                extra = {"leapp_tool": tool_key, "leapp_module": stem, "row": dict(pairs)}
                # Only present on a fallback-detected timestamp, never on a
                # curated one - its absence is how a reader tells the stronger,
                # source-confirmed path from this weaker inferred one.
                if ts_col_name and timestamp is not None:
                    extra["leapp_timestamp_column"] = ts_col_name
                records.append({
                    "artifact_type": artifact_type,
                    "title": title if artifact_type != "leapp_module_finding" else f"[{stem}] {title}",
                    "url": "", "value": value_text or "(no non-empty columns)",
                    "timestamp": timestamp,
                    "extra": extra,
                })
    except (OSError, csv.Error, UnicodeDecodeError):
        return []
    return records


def parse_leapp_tsv_exports(tsv_export_dir, tool_key):
    """Parses every real .tsv file found in `<result_dir>/_TSV Exports/`
    into this app's standard {artifact_type, title, url, value, timestamp,
    extra} record shape - see this module's own docstring for the two-tier
    curated/fallback design. One file's parse failure never aborts the
    rest (same best-effort tolerance every other whole-folder scanner in
    this app already applies). Returns (records, files_found, truncated)."""
    paths, truncated = find_leapp_tsv_files(tsv_export_dir)
    records = []
    for path in paths:
        records.extend(_parse_one_tsv(path, tool_key))
    return records, len(paths), truncated
