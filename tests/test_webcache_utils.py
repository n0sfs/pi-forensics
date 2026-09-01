"""Tests for core/webcache_utils.py, using the same stand-in-object
technique already proven for core/srum_utils.py's and core/
winsearch_utils.py's own test suites (mirrors pyesedb's real, live-
confirmed API - no genuine WebCacheV01.dat was available this session,
see the module's own docstring)."""
import pytest

pyesedb_real = pytest.importorskip("pyesedb", reason="libesedb-python not installed")

import core.webcache_utils as wcu

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
    monkeypatch.setattr(wcu.pyesedb, "file", _FakeEsedbFile)
    yield


def _containers_table(rows):
    """rows: [(container_id, name), ...]"""
    return _FakeTable(['ContainerId', 'Name'], [{'ContainerId': cid, 'Name': name} for cid, name in rows])


def test_parse_webcache_file_extracts_history_and_cookies_containers(tmp_path):
    accessed = _unix_to_filetime(1700000000)
    modified = _unix_to_filetime(1700000100)
    _FAKE_TABLES[wcu._CONTAINERS_TABLE_NAME] = _containers_table([
        (5, 'History'), (8, 'Cookies'), (12, 'iedownload'),  # iedownload is NOT a target
    ])
    _FAKE_TABLES['Container_5'] = _FakeTable(
        ['EntryId', 'Url', 'AccessedTime', 'ModifiedTime', 'ExpiryTime', 'AccessCount'], [
            {'EntryId': 1, 'Url': 'Visited: https://example.com/case-notes',
             'AccessedTime': accessed, 'ModifiedTime': modified, 'ExpiryTime': None, 'AccessCount': 3},
        ])
    _FAKE_TABLES['Container_8'] = _FakeTable(['EntryId', 'Url', 'ModifiedTime'], [
        {'EntryId': 1, 'Url': 'Cookie:bob@example.com/', 'ModifiedTime': modified},
    ])

    records = wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat'))
    assert len(records) == 2
    history_rec = next(r for r in records if r["extra"]["container"] == 'History')
    assert history_rec["title"] == 'https://example.com/case-notes'  # tag prefix stripped
    assert history_rec["extra"]["raw_url"] == 'Visited: https://example.com/case-notes'  # raw preserved
    assert history_rec["timestamp"] == 1700000100.0  # modified_time preferred over accessed_time
    assert history_rec["extra"]["access_count"] == 3

    cookie_rec = next(r for r in records if r["extra"]["container"] == 'Cookies')
    assert cookie_rec["title"] == 'bob@example.com/'
    assert cookie_rec["extra"]["raw_url"] == 'Cookie:bob@example.com/'


def test_parse_webcache_file_skips_non_target_containers(tmp_path):
    _FAKE_TABLES[wcu._CONTAINERS_TABLE_NAME] = _containers_table([
        (99, 'iedownload'), (100, 'ImageStore'),
    ])
    # Even if a table happened to exist for a non-target container, it must never be read.
    _FAKE_TABLES['Container_99'] = _FakeTable(['Url'], [{'Url': 'should never be read'}])
    records = wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat'))
    assert records == []


def test_parse_webcache_file_falls_back_to_accessed_time_when_modified_missing(tmp_path):
    accessed = _unix_to_filetime(1700000000)
    _FAKE_TABLES[wcu._CONTAINERS_TABLE_NAME] = _containers_table([(5, 'History')])
    _FAKE_TABLES['Container_5'] = _FakeTable(['Url', 'AccessedTime'], [
        {'Url': 'https://plain-no-tag.example.com/', 'AccessedTime': accessed},
    ])
    records = wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat'))
    assert len(records) == 1
    assert records[0]["timestamp"] == 1700000000.0
    assert records[0]["title"] == 'https://plain-no-tag.example.com/'  # no tag to strip


def test_parse_webcache_file_missing_containers_table_returns_empty(tmp_path):
    assert wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat')) == []


def test_parse_webcache_file_open_failure_returns_empty_not_raises(tmp_path):
    _FakeEsedbFile.open_should_raise = True
    assert wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat')) == []


def test_parse_webcache_file_row_with_no_url_is_skipped(tmp_path):
    _FAKE_TABLES[wcu._CONTAINERS_TABLE_NAME] = _containers_table([(5, 'History')])
    _FAKE_TABLES['Container_5'] = _FakeTable(['Url', 'AccessedTime'], [
        {'Url': None, 'AccessedTime': _unix_to_filetime(1700000000)},
    ])
    assert wcu.parse_webcache_file(str(tmp_path / 'WebCacheV01.dat')) == []


def test_strip_url_tag_handles_all_known_prefixes_and_plain_urls():
    assert wcu._strip_url_tag('Visited: https://x.com/') == 'https://x.com/'
    assert wcu._strip_url_tag('Cookie:bob@x.com/') == 'bob@x.com/'
    assert wcu._strip_url_tag('https://plain.com/') == 'https://plain.com/'
    assert wcu._strip_url_tag(None) is None


def test_find_webcache_files_matches_both_real_version_filenames(tmp_path):
    (tmp_path / 'WebCacheV01.dat').write_bytes(b'x')
    (tmp_path / 'WEBCACHEV24.DAT').write_bytes(b'x')
    (tmp_path / 'unrelated.dat').write_bytes(b'x')
    found, truncated = wcu.find_webcache_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is False
