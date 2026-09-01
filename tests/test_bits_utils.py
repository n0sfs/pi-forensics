"""Tests for core/bits_utils.py. Unlike this session's other new ESE-backed
modules (SRUM/Windows Search/WebCache), the real risk here is the module's
own hand-rolled byte-offset parsing of a Jobs-table Blob value, not
pyesedb's table/record API - so these tests build REAL byte blobs matching
the exact confirmed CONTROL/METADATA layout (see the module's own
docstring) via struct.pack, not a mocked pyesedb object, for the core
parsing logic; a minimal pyesedb stand-in (mirroring this session's other
ESE modules' own established technique) covers only the outer
table-lookup/dispatch wiring in parse_bits_file() itself."""
import struct
import uuid as uuid_module

import pytest

pyesedb_real = pytest.importorskip("pyesedb", reason="libesedb-python not installed")

import core.bits_utils as bu

FILETIME_EPOCH_OFFSET_SECONDS = 11_644_473_600
FILETIME_100NS_PER_SECOND = 10_000_000


def _unix_to_filetime(unix_seconds):
    return int((unix_seconds + FILETIME_EPOCH_OFFSET_SECONDS) * FILETIME_100NS_PER_SECOND)


def _pascal_utf16(text):
    encoded = text.encode('utf-16-le')
    char_count = len(text)
    return struct.pack('<L', char_count) + encoded


def _build_job_data(name='TestJob', desc='desc', cmd=r'C:\Windows\System32\cmd.exe',
                     args='/c calc.exe', sid='S-1-5-18', job_type=0, priority=2, state=6,
                     flags=0, job_id=None, file_count=1, ctime_unix=1700000000,
                     mtime_unix=1700000100, error_count=0, include_metadata=True,
                     include_file_count=True):
    """Builds a real, byte-exact job_data blob (the post-16-byte-header-skip
    portion) matching this module's own confirmed CONTROL/METADATA layout."""
    job_id = job_id or uuid_module.uuid4()
    control_part_0 = struct.pack('<LLLL', job_type, priority, state, 0) + job_id.bytes_le
    assert len(control_part_0) == bu._CONTROL_PART_0_SIZE

    body = control_part_0
    body += _pascal_utf16(name)
    body += _pascal_utf16(desc)
    body += _pascal_utf16(cmd)
    body += _pascal_utf16(args)
    body += _pascal_utf16(sid)
    body += struct.pack('<L', flags)
    body += b'\x00' * 8  # a stand-in access_token blob before the marker

    if include_file_count:
        body += bu._XFER_HEADER
        body += struct.pack('<L', file_count)
        body += b'\x00' * 4  # a stand-in files-section blob before the 2nd marker

        if include_metadata:
            body += bu._XFER_HEADER
            body += struct.pack('<L', error_count)
            body += b'\x00' * (error_count * bu._ERROR_RECORD_SIZE)
            body += struct.pack('<LLL', 0, 0, 0)  # transient_error_count, retry_delay, timeout
            body += struct.pack('<QQ', _unix_to_filetime(ctime_unix), _unix_to_filetime(mtime_unix))
            body += b'\x00' * 14  # the real struct's own Padding(14) + other_time0's own 8 bytes worth of slack

    return body, str(job_id)


def test_parse_job_control_extracts_all_real_fields():
    job_data, job_id_str = _build_job_data()
    parsed = bu._parse_job_control(job_data)
    assert parsed is not None
    assert parsed['job_id'] == job_id_str
    assert parsed['name'] == 'TestJob'
    assert parsed['desc'] == 'desc'
    assert parsed['cmd'] == r'C:\Windows\System32\cmd.exe'
    assert parsed['args'] == '/c calc.exe'
    assert parsed['sid'] == 'S-1-5-18'
    assert parsed['type'] == 'download'
    assert parsed['priority'] == 'normal'
    assert parsed['state'] == 'transferred'
    assert parsed['file_count'] == 1
    assert parsed['ctime'] == 1700000000.0
    assert parsed['mtime'] == 1700000100.0


def test_parse_job_control_unknown_enum_values_reported_honestly():
    job_data, _ = _build_job_data(job_type=99, priority=42, state=7)
    parsed = bu._parse_job_control(job_data)
    assert parsed['type'] == 'unknown(99)'
    assert parsed['priority'] == 'unknown(42)'
    assert parsed['state'] == 'acknowledged'


def test_parse_job_control_missing_xfer_header_returns_control_fields_only():
    job_data, job_id_str = _build_job_data(include_file_count=False)
    parsed = bu._parse_job_control(job_data)
    assert parsed is not None
    assert parsed['name'] == 'TestJob'
    assert parsed['file_count'] is None
    assert parsed['ctime'] is None


def test_parse_job_control_missing_metadata_still_returns_file_count():
    job_data, _ = _build_job_data(include_metadata=False)
    parsed = bu._parse_job_control(job_data)
    assert parsed is not None
    assert parsed['file_count'] == 1
    assert parsed['ctime'] is None


def test_parse_job_control_too_short_returns_none():
    assert bu._parse_job_control(b'\x00' * 10) is None


def test_parse_job_control_implausible_name_length_returns_none():
    # A garbage/corrupted name-length field (far larger than any real job
    # name) must be rejected, not trusted into a huge/garbage read.
    control_part_0 = struct.pack('<LLLL', 0, 2, 6, 0) + uuid_module.uuid4().bytes_le
    job_data = control_part_0 + struct.pack('<L', 999_999_999) + b'\x00' * 20
    assert bu._parse_job_control(job_data) is None


def test_parse_job_control_error_array_offset_is_correctly_skipped():
    # A non-zero error_count must correctly skip past the whole errors
    # array before reading transient_error_count/retry_delay/timeout and
    # landing on the real ctime/mtime - not silently misread them.
    job_data, _ = _build_job_data(error_count=3, ctime_unix=1650000000, mtime_unix=1650000500)
    parsed = bu._parse_job_control(job_data)
    assert parsed['ctime'] == 1650000000.0
    assert parsed['mtime'] == 1650000500.0


def test_read_pascal_utf16_handles_empty_string():
    data = struct.pack('<L', 0)
    text, next_offset = bu._read_pascal_utf16(data, 0)
    assert text is None  # empty string normalizes to None, matching the "or None" convention
    assert next_offset == 4


def test_read_pascal_utf16_out_of_bounds_returns_none_none():
    data = struct.pack('<L', 10)  # claims 10 chars but provides none
    text, next_offset = bu._read_pascal_utf16(data, 0)
    assert (text, next_offset) == (None, None)


class _FakeColumn:
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


class _FakeRecord:
    def __init__(self, columns, row):
        self._columns = columns
        self._row = row

    def get_value_data(self, idx):
        v = self._row.get(self._columns[idx])
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
    open_should_raise = False

    def open(self, path):
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
    _FakeEsedbFile.open_should_raise = False
    monkeypatch.setattr(bu.pyesedb, "file", _FakeEsedbFile)
    yield


def test_parse_bits_file_end_to_end_via_jobs_table(tmp_path):
    job_data, job_id_str = _build_job_data(name='RealisticBitsJob', cmd='powershell.exe',
                                             args='-enc BASE64PAYLOAD==')
    blob = b'\x00' * 16 + job_data  # the real 16-byte header this module always strips
    _FAKE_TABLES[bu._JOBS_TABLE_NAME] = _FakeTable(['Id', 'Blob'], [
        {'Id': b'\x00' * 16, 'Blob': blob},
    ])
    records = bu.parse_bits_file(str(tmp_path / bu.BITS_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "bits_job"
    assert r["title"] == 'RealisticBitsJob'
    assert 'powershell.exe' in r["value"]
    assert r["extra"]["job_id"] == job_id_str
    assert r["timestamp"] == 1700000000.0


def test_parse_bits_file_missing_jobs_table_returns_empty(tmp_path):
    assert bu.parse_bits_file(str(tmp_path / bu.BITS_FILENAME)) == []


def test_parse_bits_file_open_failure_returns_empty_not_raises(tmp_path):
    _FakeEsedbFile.open_should_raise = True
    assert bu.parse_bits_file(str(tmp_path / bu.BITS_FILENAME)) == []


def test_parse_bits_file_row_with_unparseable_blob_is_skipped_not_fatal(tmp_path):
    _FAKE_TABLES[bu._JOBS_TABLE_NAME] = _FakeTable(['Id', 'Blob'], [
        {'Id': b'\x00' * 16, 'Blob': b'\x00' * 4},  # too short to parse at all
    ])
    assert bu.parse_bits_file(str(tmp_path / bu.BITS_FILENAME)) == []


def test_find_bits_files_matches_exact_basename_case_insensitively(tmp_path):
    (tmp_path / 'qmgr.db').write_bytes(b'x')
    (tmp_path / 'QMGR.DB').write_bytes(b'x')
    (tmp_path / 'unrelated.db').write_bytes(b'x')
    found, truncated = bu.find_bits_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is False
