"""ALEAPP/iLEAPP TSV-export parsing (Android forensics expansion, Phase A).
Both tools' artifact modules (a shared codebase at their pinned commits -
see routes/file_explorer.py's LEAPP_TOOLS dict) use an @artifact_processor
decorator whose default output_types includes 'tsv' - every module that
finds non-empty data already writes its own <module>.tsv file into
`<result_dir>/_TSV Exports/`, completely independent of any CLI flag, on
every ALEAPP/iLEAPP run this app already performs. This module reads that
already-produced, previously-unread machine-readable output.

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

No timestamp parsing is attempted for TSV rows in either tier - ALEAPP's
own real per-module column headers/timestamp formatting conventions have
never been directly observed against a run that actually found data (the
one real run available produced zero hits across every module it reached
before this app's own NFS-related stall - see this feature's own dated
CLAUDE.md entry). Fabricating a timestamp parser against an unconfirmed
format would risk silently wrong timestamps reaching the Evidence
Timeline - worse than no timestamp at all. `timestamp` is always None
here; this can be revisited once a real TSV sample with real column
headers is available to design against, matching this app's own
established "verify before parsing" discipline.
"""
import csv
import os
import re

LEAPP_TSV_MAX_FILES = 300  # a real run's _TSV Exports/ folder, capped
LEAPP_TSV_MAX_ROWS_PER_FILE = 5_000

# Confirmed real module/report names, observed directly in this app's own
# real ALEAPP run logs against its pinned commit (not guessed) - promoted
# to their own dedicated, filterable artifact_type. Matched case-
# insensitively against the TSV filename's own stem (ALEAPP names each
# TSV after the human-readable report name it registers, not the raw
# Python function name).
CURATED_LEAPP_MODULES = {
    "device info": "leapp_device_info",
    "wifi": "leapp_wifi_network",
    "installed applications": "leapp_installed_app",
    "installed apps": "leapp_installed_app",
    "accounts": "leapp_account",
    "sms messages": "leapp_sms_message",
    "sms & mms": "leapp_sms_message",
    "call logs": "leapp_call_log",
    "contacts": "leapp_contact",
    "browser history": "leapp_browser_history",
    "browser bookmarks": "leapp_browser_bookmark",
    "chrome autofill": "leapp_browser_autofill",
    "whatsapp - messages": "leapp_whatsapp_message",
    "whatsapp - contacts": "leapp_whatsapp_contact",
    "usage stats": "leapp_app_usage",
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
            for i, row in enumerate(reader):
                if i >= LEAPP_TSV_MAX_ROWS_PER_FILE:
                    break
                if not row or not any(cell.strip() for cell in row):
                    continue
                # Pair headers with the row defensively - ALEAPP TSVs are
                # not guaranteed to have exactly len(headers) cells per
                # row (a value containing a literal tab, or a short/
                # ragged row from an older module version, is possible).
                pairs = list(zip(headers, row))
                value_text = " | ".join(f"{h}: {v}" for h, v in pairs if v and v.strip())
                title = row[0].strip() if row and row[0].strip() else stem
                records.append({
                    "artifact_type": artifact_type,
                    "title": title if artifact_type != "leapp_module_finding" else f"[{stem}] {title}",
                    "url": "", "value": value_text or "(no non-empty columns)",
                    "timestamp": None,
                    "extra": {"leapp_tool": tool_key, "leapp_module": stem, "row": dict(pairs)},
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
