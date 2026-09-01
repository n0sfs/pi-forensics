"""core/srum_utils.py - SRUM (SRUDB.dat) parsing, the first ESE/.edb-
format artifact this app has ever parsed.

Disclosed limitation, matching this module's own docstring: no genuine
SRUDB.dat file was available this session to parse end-to-end (ESE/.edb
has no simple text-based construction path, and no writer library exists
in this ecosystem - pyesedb, like every other libyal binding this app
uses, is read-only). Instead, this file verifies parse_srum_file()'s
field-extraction/record-shaping/id-resolution/timestamp-conversion logic
against a stand-in object mirroring pyesedb's real, live-confirmed API
surface (pyesedb.file().open()/get_table_by_name(), a table's
get_number_of_columns()/get_column(i).get_name()/get_number_of_records()/
get_record(i), and a record's get_value_data_as_integer(idx)/
get_value_data_as_floating_point(idx)/get_value_data_as_string(idx)/
get_value_data(idx) - all confirmed via help()/dir() against the real
installed package on the deployed Pi before this module was written) -
matching tests/test_prefetch_utils.py's own established pattern for
exactly this situation.

Skipped (not failed) if libesedb-python isn't installed - a genuinely
optional pip dependency.
"""
import pytest

pyesedb_real = pytest.importorskip("pyesedb", reason="libesedb-python not installed")

import core.srum_utils as su


class _FakeColumn:
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


class _FakeRecord:
    def __init__(self, columns, row):
        self._columns = columns
        self._row = row

    def _val(self, idx):
        return self._row.get(self._columns[idx])

    def get_value_data_as_integer(self, idx):
        v = self._val(idx)
        return v if isinstance(v, int) else None

    def get_value_data_as_floating_point(self, idx):
        v = self._val(idx)
        return float(v) if isinstance(v, (int, float)) else None

    def get_value_data_as_string(self, idx):
        v = self._val(idx)
        return v if isinstance(v, str) else None

    def get_value_data(self, idx):
        v = self._val(idx)
        return v if isinstance(v, bytes) else None


class _FakeTable:
    def __init__(self, columns, rows):
        self._columns = columns
        self._rows = rows

    def get_number_of_columns(self):
        return len(self._columns)

    def get_column(self, i):
        return _FakeColumn(self._columns[i])

    def get_number_of_records(self):
        return len(self._rows)

    def get_record(self, i):
        return _FakeRecord(self._columns, self._rows[i])


class _FakeEsedbFile:
    """Stands in for a real pyesedb.file() instance. Reads its own tables
    from the module-level _FAKE_TABLES dict a test sets up before calling
    parse_srum_file() - the real class has no constructor args (a real
    caller does pyesedb.file() then .open(path) separately), so per-test
    configuration has to happen through a side channel like this, mirroring
    tests/test_prefetch_utils.py's own use of a mutated class attribute
    for verification (opened_path) - just extended to real per-test data."""
    opened_path = None
    open_should_raise = False

    def open(self, path):
        _FakeEsedbFile.opened_path = path
        if _FakeEsedbFile.open_should_raise:
            raise IOError("not a valid ESE database")

    def close(self):
        pass

    def get_table_by_name(self, name):
        return _FAKE_TABLES.get(name)


_FAKE_TABLES = {}


@pytest.fixture(autouse=True)
def _reset_fake_state(monkeypatch):
    global _FAKE_TABLES
    _FAKE_TABLES = {}
    _FakeEsedbFile.opened_path = None
    _FakeEsedbFile.open_should_raise = False
    monkeypatch.setattr(su.pyesedb, "file", _FakeEsedbFile)
    yield


def _id_map_table(rows):
    """rows: [(id_index, id_blob_string_or_None, id_blob_bytes_or_None), ...]"""
    columns = ['IdType', 'IdIndex', 'IdBlob']
    table_rows = []
    for id_index, blob_str, blob_bytes in rows:
        table_rows.append({'IdType': 0, 'IdIndex': id_index, 'IdBlob': blob_str if blob_str is not None else blob_bytes})
    return _FakeTable(columns, table_rows)


def test_ole_automation_date_to_unix_known_reference_value():
    # 1970-01-01 00:00:00 UTC is, by definition, OLE Automation Date
    # 25569.0 exactly - the standard cross-check reference value.
    assert su.ole_automation_date_to_unix(25569.0) == 0.0


def test_ole_automation_date_to_unix_is_genuinely_different_math_from_filetime():
    import core.registry_utils as ru
    # Feeds the SAME raw value through both conversions - a real, plausible
    # OLE Automation Date (days since 1899-12-30) correctly produces a
    # real 2025-ish date, but the identical raw number misinterpreted as a
    # raw FILETIME (100ns ticks since 1601-01-01) produces a nonsensical
    # pre-1601 negative timestamp - concrete proof SRUM's TimeStamp must
    # never accidentally be routed through filetime_to_unix(). Verified
    # precisely by hand before trusting this as a fixture, not assumed.
    ole_value = 46000.5
    correct_result = su.ole_automation_date_to_unix(ole_value)
    wrong_if_misread_as_filetime = ru.filetime_to_unix(ole_value)
    assert correct_result is not None and wrong_if_misread_as_filetime is not None
    assert correct_result > 1_700_000_000  # a real, plausible 2020s-era Unix timestamp
    assert wrong_if_misread_as_filetime < 0  # nonsense - proves the two are NOT interchangeable
    assert abs(correct_result - wrong_if_misread_as_filetime) > 10_000_000_000


def test_ole_automation_date_to_unix_handles_none_and_zero():
    assert su.ole_automation_date_to_unix(None) is None
    assert su.ole_automation_date_to_unix(0) is None
    assert su.ole_automation_date_to_unix(-5) is None


def test_parse_srum_file_resolves_app_and_user_and_converts_timestamp(tmp_path):
    _FAKE_TABLES[su.SRUM_ID_MAP_TABLE_NAME] = _id_map_table([
        (10, None, 'C:\\Program Files\\Chrome\\chrome.exe\x00'.encode('utf-16-le')),
        (20, 'S-1-5-21-1111111111-2222222222-3333333333-1001', None),
    ])
    ts = 46246.5  # a real-shaped OLE Automation Date
    app_columns = ['AutoIncId', 'TimeStamp', 'AppId', 'UserId', 'ForegroundCycleTime', 'BackgroundCycleTime',
                   'ForegroundBytesRead', 'ForegroundBytesWritten', 'BackgroundBytesRead', 'BackgroundBytesWritten']
    _FAKE_TABLES[su.SRUM_APP_RESOURCE_TABLE_GUID] = _FakeTable(app_columns, [
        {'AutoIncId': 1, 'TimeStamp': ts, 'AppId': 10, 'UserId': 20,
         'ForegroundCycleTime': 5000, 'BackgroundCycleTime': 100,
         'ForegroundBytesRead': 2048, 'ForegroundBytesWritten': 512,
         'BackgroundBytesRead': 0, 'BackgroundBytesWritten': 0},
    ])

    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "srum_app_usage"
    assert r["title"] == 'C:\\Program Files\\Chrome\\chrome.exe'
    assert r["timestamp"] == su.ole_automation_date_to_unix(ts)
    assert r["extra"]["user"] == 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    assert r["extra"]["foreground_cycle_time"] == 5000
    assert r["extra"]["app_id"] == 10
    assert _FakeEsedbFile.opened_path == str(tmp_path / su.SRUM_FILENAME)


def test_parse_srum_file_network_usage_table(tmp_path):
    _FAKE_TABLES[su.SRUM_ID_MAP_TABLE_NAME] = _id_map_table([
        (5, None, 'firefox.exe\x00'.encode('utf-16-le')),
    ])
    net_columns = ['AutoIncId', 'TimeStamp', 'AppId', 'UserId', 'InterfaceLuid', 'BytesSent', 'BytesRecvd']
    _FAKE_TABLES[su.SRUM_NETWORK_TABLE_GUID] = _FakeTable(net_columns, [
        {'AutoIncId': 1, 'TimeStamp': 46200.0, 'AppId': 5, 'UserId': None,
         'InterfaceLuid': 12345, 'BytesSent': 90210, 'BytesRecvd': 555000},
    ])

    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "srum_network_usage"
    assert r["title"] == 'firefox.exe'
    assert r["extra"]["bytes_sent"] == 90210
    assert r["extra"]["bytes_recvd"] == 555000
    assert r["extra"]["user"] == "(unknown)"


def test_parse_srum_file_unresolvable_id_falls_back_to_placeholder(tmp_path):
    # No SruDbIdMapTable at all - AppId 99 can never resolve.
    app_columns = ['AutoIncId', 'TimeStamp', 'AppId', 'UserId']
    _FAKE_TABLES[su.SRUM_APP_RESOURCE_TABLE_GUID] = _FakeTable(app_columns, [
        {'AutoIncId': 1, 'TimeStamp': 46200.0, 'AppId': 99, 'UserId': 1},
    ])
    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert len(records) == 1
    assert records[0]["title"] == "[unresolved id 99]"


def test_parse_srum_file_missing_network_table_is_not_an_error(tmp_path):
    # Only the App Resource table exists - a real, possible partial-schema
    # state (a different Windows build) that must degrade gracefully, not
    # crash or silently produce zero results for the table that IS present.
    app_columns = ['AutoIncId', 'TimeStamp', 'AppId', 'UserId']
    _FAKE_TABLES[su.SRUM_APP_RESOURCE_TABLE_GUID] = _FakeTable(app_columns, [
        {'AutoIncId': 1, 'TimeStamp': 46200.0, 'AppId': 1, 'UserId': 1},
    ])
    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "srum_app_usage"


def test_parse_srum_file_neither_table_present_returns_empty(tmp_path):
    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert records == []


def test_parse_srum_file_open_failure_returns_empty_not_raises(tmp_path):
    _FakeEsedbFile.open_should_raise = True
    assert su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME)) == []


def test_parse_srum_file_caps_records_per_table(tmp_path):
    app_columns = ['AutoIncId', 'TimeStamp', 'AppId', 'UserId']
    rows = [{'AutoIncId': i, 'TimeStamp': 46200.0, 'AppId': 1, 'UserId': 1}
            for i in range(su.SRUM_MAX_RECORDS_PER_TABLE + 250)]
    _FAKE_TABLES[su.SRUM_APP_RESOURCE_TABLE_GUID] = _FakeTable(app_columns, rows)
    records = su.parse_srum_file(str(tmp_path / su.SRUM_FILENAME))
    assert len(records) == su.SRUM_MAX_RECORDS_PER_TABLE


def test_decode_id_blob_binary_sid_falls_back_to_hex_summary():
    # A real raw SID binary structure (revision, sub-auth count, 6-byte
    # authority, 3x 4-byte sub-authorities, RID) - genuinely not readable
    # UTF-16LE text. Verified directly against a standalone copy of this
    # function before trusting it as a test fixture: this exact byte
    # pattern decodes to mostly non-printable/undefined code points and
    # correctly falls through to the hex-summary branch, unlike a naive
    # bytes(range(N)) fixture, which turned out to decode into a string
    # Python's own str.isprintable() still counts as "printable" (BMP
    # combining marks/exotic-but-assigned code points) - a real, caught-
    # before-shipping mistake in this test's own first draft.
    sid_bytes = bytes([1, 5, 0, 0, 0, 0, 0, 5] + [21, 0, 0, 0] * 3 + [0xE9, 3, 0, 0])
    result = su._decode_id_blob(None, sid_bytes)
    assert result.startswith('0x')
    assert 'binary' in result


def test_decode_id_blob_prefers_string_getter_when_available():
    assert su._decode_id_blob('C:\\real\\path.exe', b'ignored raw bytes') == 'C:\\real\\path.exe'


def test_find_srum_files_matches_exact_basename_case_insensitively(tmp_path):
    (tmp_path / 'SRUDB.dat').write_bytes(b'x')
    (tmp_path / 'srudb.dat').write_bytes(b'x')  # lower-cased on-disk casing, real-world possible
    nested = tmp_path / 'Windows' / 'System32' / 'sru'
    nested.mkdir(parents=True)
    (nested / 'SRUDB.dat').write_bytes(b'x')
    (tmp_path / 'unrelated.dat').write_bytes(b'x')

    found, truncated = su.find_srum_files(str(tmp_path))
    assert len(found) == 3
    assert truncated is False


def test_find_srum_files_skips_recovery_tool_output_dirs(tmp_path):
    skip_dir = tmp_path / 'evidence_scalpel'
    skip_dir.mkdir()
    (skip_dir / 'SRUDB.dat').write_bytes(b'x')
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    (real_dir / 'SRUDB.dat').write_bytes(b'x')

    found, _truncated = su.find_srum_files(str(tmp_path))
    assert len(found) == 1
    assert 'real' in found[0]
