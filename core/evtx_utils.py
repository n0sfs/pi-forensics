"""Windows Event Log (.evtx) parsing - a curated Event ID allowlist, not
exhaustive coverage, matching this app's own established "curated
allowlist" philosophy (Volatility3's plugin list, MVT). Mirrors
core/browser_artifacts.py's exact shape ({artifact_type, title, url,
value, timestamp, extra} records) so the shared, already-generic
_record_parsed_artifacts()/parsed_artifacts table and File Views'
"Parsed Artifacts" rendering need zero changes to support this new source.

Verified end-to-end (2026-08-25) against two real, legitimate .evtx test
fixtures from python-evtx's own upstream GitHub test suite (tests/data/
security.evtx, tests/data/system.evtx) - confirmed real 4624/4720/7045
events parse with correct fields and timestamps before this module's
per-event-ID field extraction was finalized.

No filetime_to_unix()-style helper is needed here either (see
core/registry_utils.py's own note on the same point) -
Evtx record.timestamp() already returns a native, tz-aware Python
datetime internally, confirmed via direct testing against real records,
not assumed from documentation.
"""
import os
import re
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

EVTX_EXTENSION = '.evtx'

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

EVTX_SCAN_MAX_CANDIDATES = 20
EVTX_SCAN_MAX_WALKED = 20_000
EVTX_MAX_RECORDS_PER_FILE = 50_000  # backstop against a pathologically large log, not the normal case
EVTX_MAX_MATCHES_PER_TYPE = 2_000

_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
_EVENT_ID_RE = re.compile(r'<EventID[^>]*>(\d+)</EventID>')

# Curated Event ID -> (artifact_type, human label, primary EventData field
# name used to build a specific title, fallback title if that field is
# absent). 1102 (audit log cleared) is a classic anti-forensic indicator,
# deliberately called out by name in this allowlist rather than lumped in
# generically.
EVENT_ID_ALLOWLIST = {
    '4624': ('evtx_logon_success', 'Successful Logon', 'TargetUserName'),
    '4625': ('evtx_logon_failure', 'Failed Logon', 'TargetUserName'),
    '4688': ('evtx_process_creation', 'Process Created', 'NewProcessName'),
    '4720': ('evtx_account_created', 'User Account Created', 'TargetUserName'),
    '7045': ('evtx_service_installed', 'Service Installed', 'ServiceName'),
    '1102': ('evtx_audit_log_cleared', 'Audit Log Cleared', 'SubjectUserName'),
}


def find_evtx_files(root_dir):
    """Recursively finds real .evtx files anywhere under root_dir (matched
    by extension, unlike hive/browser files - real Windows Event Log
    filenames vary: Security.evtx, System.evtx, Application.evtx, a custom
    channel name, etc.). Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > EVTX_SCAN_MAX_WALKED:
                return found, True
            if fname.lower().endswith(EVTX_EXTENSION):
                found.append(os.path.join(root, fname))
                if len(found) >= EVTX_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _event_data_dict(root_el):
    """Extracts every <Data Name="X">value</Data> under <EventData> as a
    plain {name: value} dict - the flat name/value-pair shape every
    allowlisted event ID's EventData section uses (confirmed against real
    4624/4720/7045 records)."""
    data = {}
    event_data_el = root_el.find('e:EventData', _NS)
    if event_data_el is None:
        return data
    for d in event_data_el.findall('e:Data', _NS):
        name = d.get('Name')
        if name:
            data[name] = (d.text or '').strip()
    return data


def parse_evtx_file(path):
    """Parses one .evtx file, returning a flat list of records for every
    record whose EventID is in EVENT_ID_ALLOWLIST - every other event in
    the log is skipped entirely, not just unlabeled, matching this
    module's deliberately curated (not exhaustive) scope."""
    records = []
    type_counts = {}
    try:
        with evtx.Evtx(path) as log:
            for i, record in enumerate(log.records()):
                if i >= EVTX_MAX_RECORDS_PER_FILE:
                    break
                xml_str = record.xml()
                m = _EVENT_ID_RE.search(xml_str)
                if not m or m.group(1) not in EVENT_ID_ALLOWLIST:
                    continue
                event_id = m.group(1)
                artifact_type, label, primary_field = EVENT_ID_ALLOWLIST[event_id]
                if type_counts.get(artifact_type, 0) >= EVTX_MAX_MATCHES_PER_TYPE:
                    continue
                try:
                    root_el = ET.fromstring(xml_str)
                except ET.ParseError:
                    continue
                event_data = _event_data_dict(root_el)
                primary_value = event_data.get(primary_field, '')
                title = f"{label}: {primary_value}" if primary_value else label
                try:
                    ts = record.timestamp().timestamp()
                except Exception:
                    ts = None
                records.append({
                    "artifact_type": artifact_type, "title": title, "url": "",
                    "value": ", ".join(f"{k}={v}" for k, v in list(event_data.items())[:8]),
                    "timestamp": ts,
                    "extra": {"event_id": event_id, "record_id": record.record_num()},
                })
                type_counts[artifact_type] = type_counts.get(artifact_type, 0) + 1
    except Exception as e:
        print(f"Warning: could not parse event log {path}: {e}")
        return []
    return records
