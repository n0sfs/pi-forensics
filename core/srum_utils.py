"""SRUM (System Resource Usage Monitor) - SRUDB.dat - widely regarded as
one of the single highest-value modern Windows forensic artifacts: per-
application network data usage and execution/timeline history, tracked
over a rolling ~30-day window, even for applications that have since been
uninstalled/deleted. Lives at C:\\Windows\\System32\\sru\\SRUDB.dat.

The first ESE/.edb-format database this app has ever parsed. A prior
write-up in this codebase declined to build Windows Search Index
(Windows.edb) parsing, calling it "too complex" - re-litigated directly
via real research (2026-09-01) before starting this module: that
rejection was specifically about the FUZZY problem of correlating
Windows Search's internal doc IDs back to real file paths/hashes, not
about ESE parsing itself. SRUM's own ID resolution (AppId/UserId ->
SruDbIdMapTable.IdIndex -> IdBlob) is a deterministic, documented 1:1
key lookup - genuinely comparable in difficulty to this app's existing
Prefetch/USN-journal parsers, not to Windows Search's fuzzy problem.

libesedb-python (import name pyesedb) is real and current (latest
release 20260704, confirmed live-installable on this app's real deployed
ARM64/Debian-trixie venv as a prebuilt manylinux2014_aarch64 wheel - no
source compile step, the same vendoring pattern already proven for
libpff-python/libscca-python/libvshadow-python). Its real API surface was
inspected directly via help()/dir() on the live installed package before
writing any of this module's code, not assumed from documentation:
pyesedb.file().open(path) -> .get_table_by_name(name) -> a table object
exposing .get_number_of_records()/.get_record(i) -> a record object
exposing .get_value_data_as_integer(col_index)/
get_value_data_as_floating_point(col_index)/get_value_data_as_string(
col_index)/get_value_data(col_index) (raw bytes). Column type info
(pyesedb.column_types.DATE_TIME/DOUBLE_64BIT/etc.) is also real and
confirmed present on the installed package.

Real schema, cross-validated against 2+ independent sources (libyal/
esedb-kb's own formal ESE-schema spec, log2timeline/plaso's real
production srum.py parser, and real pyesedb-using tools - devgc/
SrumMonkey, MarkBaggett/srum-dump):

- SruDbIdMapTable: IdType (uint8), IdIndex (int32 - the foreign key every
  other table's AppId/UserId column references), IdBlob (binary - the
  resolved string, typically a UTF-16LE executable path or a SID).
- Application Resource Usage, table GUID
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}: AutoIncId, TimeStamp, AppId,
  UserId, ForegroundCycleTime, BackgroundCycleTime, ForegroundBytesRead/
  Written, BackgroundBytesRead/Written, and several other per-process
  resource counters.
- Network Data Usage, table GUID
  {973F5D5C-1D90-4944-BE8E-24B94231A174}: AutoIncId, TimeStamp, AppId,
  UserId, InterfaceLuid, L2ProfileId, BytesSent, BytesRecvd.

A real, important correction found during research, worth recording so a
future session doesn't assume otherwise: TimeStamp is NOT Windows
FILETIME (every other artifact this app has ever attempted assumed that
first, this one genuinely isn't it). It's stored as a raw binary value
that decodes as an OLE Automation Date - a double-precision float, days
since 1899-12-30, with 1970-01-01 = 25569.0 exactly - confirmed
identically by both libyal/esedb-kb's formal spec and plaso's own real
source (_ConvertValueBinaryDataToFloatingPointValue ->
OLEAutomationDate(timestamp=...)). ole_automation_date_to_unix() below is
this app's newest genuinely distinct timestamp conversion.

Disclosed, not silently skipped, matching this app's own established
pattern for a native-dependency parser with no practical way to hand-
construct a valid test file (Prefetch's own .pf format hit the identical
problem): ESE/.edb has no simple text-based construction path and no
real writer library exists in this ecosystem (pyesedb itself, like every
other libyal binding this app uses, is read-only) - no genuine SRUDB.dat
was available to parse end-to-end this session. This module's field-
extraction/record-shaping logic is unit-tested against a stand-in object
matching pyesedb's real, live-confirmed API shape (see this module's own
test file), which proves the glue code is correct - but the full "read
real ESE-format bytes off disk" path has not been exercised against a
genuine SRUDB.dat. Flagged as an open item for the next time a real
Windows SRUDB.dat sample is available (any real Windows 10/11 machine's
own C:\\Windows\\System32\\sru\\SRUDB.dat would work).

Deliberately out of scope for this version: replaying uncommitted data
from SRUDB.dat's own ESE transaction logs (edb*.log) - a much larger
undertaking than this app's already-established SQLite-WAL-sidecar
recovery (a different, much simpler journaling mechanism), and ESE's own
crash-recovery log replay is a real, separate piece of complexity this
version doesn't attempt. Only the main SRUDB.dat file's already-committed
data is read.
"""
import os

import pyesedb

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

SRUM_FILENAME = 'SRUDB.dat'
SRUM_SCAN_MAX_CANDIDATES = 20
SRUM_SCAN_MAX_WALKED = 20_000
SRUM_MAX_RECORDS_PER_TABLE = 5_000

SRUM_ID_MAP_TABLE_NAME = 'SruDbIdMapTable'
SRUM_APP_RESOURCE_TABLE_GUID = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'
SRUM_NETWORK_TABLE_GUID = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'

_OLE_AUTOMATION_DATE_UNIX_EPOCH_DAYS = 25569.0
_SECONDS_PER_DAY = 86400.0


def ole_automation_date_to_unix(ole_days):
    """OLE Automation Date (double, days since 1899-12-30, with
    1970-01-01 == 25569.0 exactly) -> Unix epoch seconds. See this
    module's own docstring for why this - not FILETIME - is SRUM's real
    TimeStamp format, and why that's a genuinely different conversion
    from every other timestamp this app parses."""
    if ole_days is None:
        return None
    try:
        ole_days = float(ole_days)
    except (TypeError, ValueError):
        return None
    if ole_days <= 0:
        return None
    try:
        return (ole_days - _OLE_AUTOMATION_DATE_UNIX_EPOCH_DAYS) * _SECONDS_PER_DAY
    except (OverflowError, ValueError):
        return None


def find_srum_files(root_dir):
    """Recursively finds real SRUDB.dat files (matched by exact basename,
    case-insensitive - mirrors core/prefetch_utils.py's find_prefetch_files())
    anywhere under root_dir. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > SRUM_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() == SRUM_FILENAME.lower():
                found.append(os.path.join(root, fname))
                if len(found) >= SRUM_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _column_index_map(table):
    """{column_name: column_index} for a real pyesedb table object -
    real records are addressed by column INDEX, not name, so this is
    built once per table and reused for every record."""
    out = {}
    for i in range(table.get_number_of_columns()):
        try:
            out[table.get_column(i).get_name()] = i
        except Exception:
            continue
    return out


def _get_value(record, col_map, name, kind):
    """kind: 'int' | 'float' | 'string' | 'raw'. Returns None on any
    missing column / read failure rather than raising - a single bad
    column in one record must never abort the whole table's parse."""
    idx = col_map.get(name)
    if idx is None:
        return None
    try:
        if kind == 'int':
            return record.get_value_data_as_integer(idx)
        if kind == 'float':
            return record.get_value_data_as_floating_point(idx)
        if kind == 'string':
            return record.get_value_data_as_string(idx)
        return record.get_value_data(idx)
    except Exception:
        return None


def _decode_id_blob(raw_string, raw_bytes):
    """SruDbIdMapTable's IdBlob is usually a readable string (an
    executable path, a SID, an app package identifier) but its real
    on-disk column type isn't confirmed for every Windows build - tries
    pyesedb's own get_value_data_as_string() first (works cleanly when
    the column really is TEXT/LARGE_TEXT), then falls back to a UTF-16LE
    decode of the raw bytes (the confirmed real encoding for this table
    across the sources this module's docstring cites) with a printable-
    ratio sanity check, and finally a short hex summary for genuinely
    binary data (e.g. a raw SID) rather than ever returning garbage
    text."""
    if raw_string:
        return raw_string
    if not raw_bytes:
        return None
    try:
        decoded = raw_bytes.decode('utf-16-le', errors='strict').rstrip('\x00')
        if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.8:
            return decoded
    except (UnicodeDecodeError, ZeroDivisionError):
        pass
    return '0x' + raw_bytes[:32].hex() + ('...' if len(raw_bytes) > 32 else '') + ' (binary)'


def _build_id_map(esedb_file):
    """Reads SruDbIdMapTable into {id_index: resolved_string}. Returns an
    empty dict (never raises) if the table is missing or unreadable - a
    genuinely possible state on some Windows builds/damaged databases,
    handled the same tolerant way this module handles every other
    partial-schema case."""
    id_map = {}
    try:
        table = esedb_file.get_table_by_name(SRUM_ID_MAP_TABLE_NAME)
    except Exception:
        table = None
    if table is None:
        return id_map
    col_map = _column_index_map(table)
    try:
        record_count = table.get_number_of_records()
    except Exception:
        return id_map
    for i in range(record_count):
        try:
            record = table.get_record(i)
        except Exception:
            continue
        id_index = _get_value(record, col_map, 'IdIndex', 'int')
        if id_index is None:
            continue
        raw_string = _get_value(record, col_map, 'IdBlob', 'string')
        raw_bytes = _get_value(record, col_map, 'IdBlob', 'raw') if not raw_string else None
        id_map[id_index] = _decode_id_blob(raw_string, raw_bytes)
    return id_map


def _resolve_id(id_map, id_index):
    if id_index is None:
        return "(unknown)"
    resolved = id_map.get(id_index)
    return resolved if resolved else f"[unresolved id {id_index}]"


def _parse_table(esedb_file, table_guid, id_map, artifact_type, build_value_extra):
    """Shared per-table walk: opens table_guid, resolves AppId/UserId via
    id_map, converts TimeStamp, and calls build_value_extra(row) for the
    table-specific (value_string, extra_dict) pair. Returns [] if the
    table isn't present at all (a real, disclosed possibility - not every
    Windows version/SRUDB.dat necessarily has both known tables), capped
    at SRUM_MAX_RECORDS_PER_TABLE with the overflow silently NOT counted
    here (the caller's own candidate/row totals already disclose this
    app's usual truncated flag pattern at the route level)."""
    try:
        table = esedb_file.get_table_by_name(table_guid)
    except Exception:
        table = None
    if table is None:
        return []
    col_map = _column_index_map(table)
    try:
        record_count = table.get_number_of_records()
    except Exception:
        return []
    records = []
    for i in range(min(record_count, SRUM_MAX_RECORDS_PER_TABLE)):
        try:
            record = table.get_record(i)
        except Exception:
            continue
        app_id = _get_value(record, col_map, 'AppId', 'int')
        user_id = _get_value(record, col_map, 'UserId', 'int')
        raw_ts = _get_value(record, col_map, 'TimeStamp', 'float')
        timestamp = ole_automation_date_to_unix(raw_ts)
        app_name = _resolve_id(id_map, app_id)
        user_name = _resolve_id(id_map, user_id)
        value, extra = build_value_extra(record, col_map)
        extra.update({"app_id": app_id, "user_id": user_id, "user": user_name})
        records.append({
            "artifact_type": artifact_type, "title": app_name, "url": "",
            "value": value, "timestamp": timestamp, "extra": extra,
        })
    return records


def _app_resource_value_extra(record, col_map):
    fg_cycle = _get_value(record, col_map, 'ForegroundCycleTime', 'int')
    bg_cycle = _get_value(record, col_map, 'BackgroundCycleTime', 'int')
    fg_read = _get_value(record, col_map, 'ForegroundBytesRead', 'int')
    fg_written = _get_value(record, col_map, 'ForegroundBytesWritten', 'int')
    bg_read = _get_value(record, col_map, 'BackgroundBytesRead', 'int')
    bg_written = _get_value(record, col_map, 'BackgroundBytesWritten', 'int')
    value = (f"foreground cycle time: {fg_cycle if fg_cycle is not None else '?'}, "
             f"background cycle time: {bg_cycle if bg_cycle is not None else '?'}")
    return value, {
        "foreground_cycle_time": fg_cycle, "background_cycle_time": bg_cycle,
        "foreground_bytes_read": fg_read, "foreground_bytes_written": fg_written,
        "background_bytes_read": bg_read, "background_bytes_written": bg_written,
    }


def _network_usage_value_extra(record, col_map):
    bytes_sent = _get_value(record, col_map, 'BytesSent', 'int')
    bytes_recvd = _get_value(record, col_map, 'BytesRecvd', 'int')
    value = f"sent: {bytes_sent if bytes_sent is not None else '?'} bytes, received: {bytes_recvd if bytes_recvd is not None else '?'} bytes"
    return value, {"bytes_sent": bytes_sent, "bytes_recvd": bytes_recvd}


def parse_srum_file(path, filename=None):
    """Parses a real SRUDB.dat into a combined list of
    {artifact_type: "srum_app_usage"} and {artifact_type:
    "srum_network_usage"} records. Returns [] on any failure to open the
    file at all (not a real ESE database, corrupted, wrong format) - the
    same best-effort tolerance every other parser in this app already
    applies, never raises out to the caller."""
    esedb_file = pyesedb.file()
    try:
        esedb_file.open(path)
    except Exception:
        return []
    try:
        id_map = _build_id_map(esedb_file)
        records = []
        records.extend(_parse_table(
            esedb_file, SRUM_APP_RESOURCE_TABLE_GUID, id_map, "srum_app_usage", _app_resource_value_extra))
        records.extend(_parse_table(
            esedb_file, SRUM_NETWORK_TABLE_GUID, id_map, "srum_network_usage", _network_usage_value_extra))
        return records
    finally:
        try:
            esedb_file.close()
        except Exception:
            pass
