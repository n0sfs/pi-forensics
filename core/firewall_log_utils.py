"""Windows Defender Firewall connection log (pfirewall.log) -
%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log - a plain-text,
W3C-Extended-Log-File-Format-style record of allowed/blocked network
connections, when an administrator has turned logging on.

Grounded via real research (2026-09-01) before any code was written:

- **Real default file path confirmed**: `C:\\Windows\\System32\\LogFiles\\
  Firewall\\pfirewall.log`, admin-configurable but this is the real
  documented default. A rotated/oversized log is renamed
  `pfirewall.log.old` (both matched here).
- **The column set is genuinely admin-configurable, not fixed** - a
  `#Fields:` header line in the file itself declares the ACTUAL column
  order for that specific log, per Microsoft's own official "Firewall
  Log Fields" reference documentation. This module always parses that
  header line to build the real column list for that file, never
  assumes a fixed order - the same defensive-column-discovery posture
  already established for core/windows_activity_utils.py's PRAGMA
  table_info() checks, applied here to a text log's own self-declared
  schema instead of a database's.
- **A real, important disclosed caveat, confirmed via Microsoft's own
  official "Configure Windows Firewall logging" documentation**: this
  logging is OFF BY DEFAULT on a stock Windows installation (both "log
  dropped packets" and "log successful connections" default to No) - an
  examiner should expect this file/folder to be genuinely ABSENT on most
  real images, not assume its absence means a parsing failure. Stated
  directly in this module's own label text (routes/case_index.py /
  static/js/main.js), matching this app's established disclosure
  convention for other inconsistently-populated artifacts (BAM/DAM,
  post-23H2 WordWheelQuery).
- **A genuine, disclosed timestamp-timezone uncertainty, handled
  deterministically rather than silently guessed wrong**: this log's
  date/time columns are widely understood (general practitioner
  consensus, not independently re-confirmed against a dedicated primary
  source this session) to record the LOCAL system time of the machine
  that generated the log, not UTC - but which specific local timezone
  that machine used is never itself recorded anywhere in the file. This
  module deliberately does NOT call Python's plain datetime.timestamp()
  on a naive value (which would silently apply the ANALYSIS station's
  own local timezone - the exact class of real, previously-caught bug
  this app already fixed once this session for Windows Registry
  timestamps, core/registry_utils.py's _dt_to_epoch()) - instead it
  explicitly stamps the parsed date/time as UTC before converting, a
  deterministic, analysis-machine-independent choice that an examiner
  can correct for using the source machine's own known local timezone,
  rather than one that would silently vary depending on which machine
  happens to run this code.
"""
import datetime
import os

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

FIREWALL_LOG_FILENAMES = {'pfirewall.log', 'pfirewall.log.old'}
FIREWALL_LOG_SCAN_MAX_CANDIDATES = 10
FIREWALL_LOG_SCAN_MAX_WALKED = 20_000
FIREWALL_LOG_MAX_ROWS = 10_000


def find_firewall_log_files(root_dir):
    """Recursively finds real pfirewall.log(.old) files (matched by exact
    basename, case-insensitive) anywhere under root_dir. Returns
    (paths, truncated)."""
    lower_names = {n.lower() for n in FIREWALL_LOG_FILENAMES}
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > FIREWALL_LOG_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() in lower_names:
                found.append(os.path.join(root, fname))
                if len(found) >= FIREWALL_LOG_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _parse_row_timestamp(date_str, time_str):
    """date_str: 'YYYY-MM-DD', time_str: 'HH:MM:SS' (the real, standard
    W3C-extended-log format both fields use in this log). Stamped
    explicitly as UTC - see this module's own docstring for why that's a
    deliberate, deterministic choice given a genuine, disclosed real-
    world ambiguity, not an assumption the log is truly UTC."""
    if not date_str or not time_str:
        return None
    try:
        dt = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return None


def parse_firewall_log_file(path, filename=None):
    """Parses a real pfirewall.log into a list of
    {artifact_type: "firewall_connection_log"} records, one per logged
    connection row - the column order is read from the file's own real
    '#Fields:' header line, never assumed fixed (see this module's own
    docstring). Returns [] on any failure (missing file, no recognizable
    '#Fields:' header at all, genuinely undecodable bytes) - the same
    best-effort tolerance every other parser in this app already
    applies."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
    except OSError:
        return []

    fields = None
    for line in lines:
        if line.startswith('#Fields:'):
            fields = line[len('#Fields:'):].strip().split()
            break
    if not fields:
        return []

    date_idx = fields.index('date') if 'date' in fields else None
    time_idx = fields.index('time') if 'time' in fields else None
    action_idx = fields.index('action') if 'action' in fields else None
    proto_idx = fields.index('protocol') if 'protocol' in fields else None
    src_ip_idx = fields.index('src-ip') if 'src-ip' in fields else None
    dst_ip_idx = fields.index('dst-ip') if 'dst-ip' in fields else None
    src_port_idx = fields.index('src-port') if 'src-port' in fields else None
    dst_port_idx = fields.index('dst-port') if 'dst-port' in fields else None

    records = []
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if len(records) >= FIREWALL_LOG_MAX_ROWS:
            break
        parts = line.split()
        row = {fields[i]: (parts[i] if i < len(parts) and parts[i] != '-' else None) for i in range(len(fields))}

        action = row.get('action', '?') if action_idx is not None else '?'
        proto = row.get('protocol', '?') if proto_idx is not None else '?'
        src_ip = row.get('src-ip') if src_ip_idx is not None else None
        dst_ip = row.get('dst-ip') if dst_ip_idx is not None else None
        src_port = row.get('src-port') if src_port_idx is not None else None
        dst_port = row.get('dst-port') if dst_port_idx is not None else None

        title = f"{action} {proto}: {src_ip or '?'}"
        if src_port:
            title += f":{src_port}"
        title += f" -> {dst_ip or '?'}"
        if dst_port:
            title += f":{dst_port}"

        timestamp = _parse_row_timestamp(
            row.get('date') if date_idx is not None else None,
            row.get('time') if time_idx is not None else None)

        records.append({
            "artifact_type": "firewall_connection_log", "title": title, "url": "",
            "value": line, "timestamp": timestamp, "extra": row,
        })
    return records
