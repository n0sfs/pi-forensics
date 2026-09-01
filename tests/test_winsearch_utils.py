"""Tests for core/winsearch_utils.py, using the same stand-in-object
technique already proven for core/srum_utils.py's own test suite
(mirrors pyesedb's real, live-confirmed API - no genuine Windows.edb was
available this session, see the module's own docstring)."""
import pytest

pyesedb_real = pytest.importorskip("pyesedb", reason="libesedb-python not installed")

import core.winsearch_utils as wsu

FILETIME_EPOCH_OFFSET_SECONDS = 11_644_473_600
FILETIME_100NS_PER_SECOND = 10_000_000


def _unix_to_filetime(unix_seconds):
    return int((unix_seconds + FILETIME_EPOCH_OFFSET_SECONDS) * FILETIME_100NS_PER_SECOND)


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
    monkeypatch.setattr(wsu.pyesedb, "file", _FakeEsedbFile)
    yield


def test_parse_winsearch_file_extracts_real_fields_unprefixed_columns(tmp_path):
    columns = ['WorkID', 'System_ItemPathDisplay', 'System_ItemNameDisplay',
               'System_DateModified', 'System_Size', 'System_Search_AutoSummary']
    modified_ft = _unix_to_filetime(1700000000)
    _FAKE_TABLES[wsu._PROPERTY_STORE_TABLE_NAME] = _FakeTable(columns, [
        {'WorkID': 1, 'System_ItemPathDisplay': r'C:\Users\bob\Documents\case_notes.docx',
         'System_ItemNameDisplay': 'case_notes.docx', 'System_DateModified': modified_ft,
         'System_Size': 40960, 'System_Search_AutoSummary': 'Confidential findings regarding...'},
    ])
    records = wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "winsearch_indexed_item"
    assert r["title"] == 'case_notes.docx'
    assert r["extra"]["path"] == r'C:\Users\bob\Documents\case_notes.docx'
    assert r["extra"]["size"] == 40960
    assert r["timestamp"] == 1700000000.0
    assert 'Confidential findings' in r["extra"]["content_summary"]


def test_parse_winsearch_file_matches_prefixed_column_names_via_substring(tmp_path):
    # The real, disclosed uncertainty this module exists to handle
    # defensively - a real Windows.edb's PropertyStore columns may carry
    # a numeric/chunk-index prefix, confirmed via substring matching
    # rather than an exact-name lookup.
    columns = ['WorkID', '0_System_ItemPathDisplay', '3_System_ItemNameDisplay']
    _FAKE_TABLES[wsu._PROPERTY_STORE_TABLE_NAME] = _FakeTable(columns, [
        {'WorkID': 5, '0_System_ItemPathDisplay': r'D:\evidence\report.pdf',
         '3_System_ItemNameDisplay': 'report.pdf'},
    ])
    records = wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME))
    assert len(records) == 1
    assert records[0]["title"] == 'report.pdf'
    assert records[0]["extra"]["path"] == r'D:\evidence\report.pdf'


def test_parse_winsearch_file_missing_path_falls_back_honestly(tmp_path):
    columns = ['WorkID', 'System_ItemNameDisplay']
    _FAKE_TABLES[wsu._PROPERTY_STORE_TABLE_NAME] = _FakeTable(columns, [
        {'WorkID': 9, 'System_ItemNameDisplay': 'orphan_item.txt'},
    ])
    records = wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME))
    assert records[0]["extra"]["path"] is None
    assert records[0]["value"].startswith("(path unavailable)")


def test_parse_winsearch_file_truncates_long_summary(tmp_path):
    columns = ['WorkID', 'System_ItemPathDisplay', 'System_Search_AutoSummary']
    long_summary = 'x' * 1000
    _FAKE_TABLES[wsu._PROPERTY_STORE_TABLE_NAME] = _FakeTable(columns, [
        {'WorkID': 1, 'System_ItemPathDisplay': r'C:\x.txt', 'System_Search_AutoSummary': long_summary},
    ])
    records = wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME))
    assert records[0]["extra"]["content_summary"].endswith('...')
    assert len(records[0]["extra"]["content_summary"]) == wsu.WINSEARCH_MAX_SUMMARY_LEN + 3


def test_parse_winsearch_file_missing_property_store_table_returns_empty(tmp_path):
    assert wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME)) == []


def test_parse_winsearch_file_open_failure_returns_empty_not_raises(tmp_path):
    _FakeEsedbFile.open_should_raise = True
    assert wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME)) == []


def test_parse_winsearch_file_caps_record_count(tmp_path):
    columns = ['WorkID', 'System_ItemPathDisplay']
    rows = [{'WorkID': i, 'System_ItemPathDisplay': f'C:\\file{i}.txt'}
            for i in range(wsu.WINSEARCH_MAX_RECORDS + 300)]
    _FAKE_TABLES[wsu._PROPERTY_STORE_TABLE_NAME] = _FakeTable(columns, rows)
    records = wsu.parse_winsearch_file(str(tmp_path / wsu.WINSEARCH_FILENAME))
    assert len(records) == wsu.WINSEARCH_MAX_RECORDS


def test_find_winsearch_files_matches_exact_basename_case_insensitively(tmp_path):
    (tmp_path / 'Windows.edb').write_bytes(b'x')
    (tmp_path / 'windows.edb').write_bytes(b'x')
    (tmp_path / 'unrelated.edb').write_bytes(b'x')
    found, truncated = wsu.find_winsearch_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is False
