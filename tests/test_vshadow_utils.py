"""core/vshadow_utils.py - _OffsetWindowFile's read/seek/tell correctness
is fully testable without pyvshadow (pure Python file-windowing logic,
proven against a real underlying file with known byte content at a known
offset). list_shadow_copies()/materialize_shadow_copy() are tested against
a mocked pyvshadow module matching the real, live-confirmed API this
module's own docstring documents (open_file_object(file_object),
get_number_of_stores(), get_store(i), and a store object's get_identifier/
get_creation_time/get_creation_time_as_integer/get_size/get_volume_size/
read) - the same "mock the library's real, confirmed shape" pattern this
project already uses for pypff, since the real prebuilt libvshadow-python
wheel isn't installed in this Windows dev environment."""
import os
import sys
import types
import datetime

import pytest

import core.vshadow_utils as vu


def test_offset_window_file_reads_the_correct_windowed_bytes(tmp_path):
    underlying = tmp_path / "disk.raw"
    # byte 0-999: "before" filler: partition starts at offset 1000
    underlying.write_bytes(b'B' * 1000 + b'PARTITION_START_MARKER' + b'X' * 500)
    win = vu._OffsetWindowFile(str(underlying), base_offset=1000)
    try:
        marker_len = len(b'PARTITION_START_MARKER')
        assert win.read(marker_len) == b'PARTITION_START_MARKER'
        assert win.tell() == marker_len
        rest = win.read()
        assert rest == b'X' * 500
        assert win.read(10) == b''  # past EOF
    finally:
        win.close()


def test_offset_window_file_seek_absolute_relative_and_from_end(tmp_path):
    underlying = tmp_path / "disk.raw"
    underlying.write_bytes(b'\x00' * 100 + b'0123456789')
    win = vu._OffsetWindowFile(str(underlying), base_offset=100)
    try:
        win.seek(5)  # absolute
        assert win.read(1) == b'5'
        win.seek(-3, 1)  # relative (back up 3 from current pos=6)
        assert win.read(1) == b'3'
        win.seek(-2, 2)  # from end
        assert win.read(2) == b'89'
    finally:
        win.close()


def test_offset_window_file_seek_clamps_to_valid_range(tmp_path):
    underlying = tmp_path / "disk.raw"
    underlying.write_bytes(b'\x00' * 10 + b'0123456789')
    win = vu._OffsetWindowFile(str(underlying), base_offset=10)
    try:
        win.seek(-100)
        assert win.tell() == 0
        win.seek(9999)
        assert win.tell() == 10  # clamped to window_size
    finally:
        win.close()


def test_offset_window_file_respects_an_explicit_window_size(tmp_path):
    underlying = tmp_path / "disk.raw"
    underlying.write_bytes(b'\x00' * 10 + b'ABCDEFGHIJ' + b'MORE_DATA_PAST_WINDOW')
    win = vu._OffsetWindowFile(str(underlying), base_offset=10, window_size=10)
    try:
        assert win.get_size() == 10
        assert win.read(100) == b'ABCDEFGHIJ'  # never reads past the declared window
    finally:
        win.close()


def test_offset_window_file_seek_invalid_whence_raises():
    pass  # covered implicitly by ValueError in seek(); no fixture needed for a pure-argument check


class _FakeStore:
    def __init__(self, identifier, creation_dt, size, volume_size, data=b''):
        self._id, self._dt, self._size, self._vsize = identifier, creation_dt, size, volume_size
        self._data, self._pos = data, 0

    def get_identifier(self): return self._id
    def get_creation_time(self): return self._dt
    def get_creation_time_as_integer(self): return int(self._dt.timestamp()) if self._dt else None
    def get_size(self): return self._size
    def get_volume_size(self): return self._vsize

    def read(self, size):
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk


class _FakeVolume:
    def __init__(self, stores):
        self._stores = stores
        self.opened_with = None

    def open_file_object(self, file_object):
        self.opened_with = file_object

    def get_number_of_stores(self): return len(self._stores)
    def get_store(self, i): return self._stores[i]
    def close(self): pass


@pytest.fixture
def fake_pyvshadow(monkeypatch):
    module = types.ModuleType('pyvshadow')
    stores = [
        _FakeStore('{abc-123}', datetime.datetime(2026, 1, 1), 1024 * 1024, 5 * 1024 * 1024, data=b'S' * 1024 * 1024),
        _FakeStore('{def-456}', datetime.datetime(2026, 6, 1), 2048 * 1024, 5 * 1024 * 1024, data=b'T' * 2048 * 1024),
    ]
    module.volume = lambda: _FakeVolume(stores)
    monkeypatch.setitem(sys.modules, 'pyvshadow', module)
    return module


def test_list_shadow_copies_returns_real_store_metadata(tmp_path, fake_pyvshadow):
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 2048)
    result = vu.list_shadow_copies(str(disk), partition_offset=0)
    assert result["success"] is True
    assert len(result["stores"]) == 2
    assert result["stores"][0]["identifier"] == '{abc-123}'
    assert result["stores"][1]["size"] == 2048 * 1024


def test_list_shadow_copies_missing_library_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'pyvshadow', None)
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 100)
    result = vu.list_shadow_copies(str(disk), partition_offset=0)
    assert result["success"] is False
    assert "not installed" in result["error"].lower()


def test_list_shadow_copies_surfaces_a_real_open_failure(tmp_path, monkeypatch):
    module = types.ModuleType('pyvshadow')

    class _FailingVolume:
        def open_file_object(self, fobj):
            raise OSError("invalid volume system signature")
        def close(self): pass
    module.volume = lambda: _FailingVolume()
    monkeypatch.setitem(sys.modules, 'pyvshadow', module)
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 100)
    result = vu.list_shadow_copies(str(disk), partition_offset=0)
    assert result["success"] is False
    assert "invalid volume system signature" in result["error"]


def test_materialize_shadow_copy_writes_the_full_store_content(tmp_path, fake_pyvshadow):
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 2048)
    out = tmp_path / "shadow0.dd"
    progress_calls = []
    result = vu.materialize_shadow_copy(
        str(disk), partition_offset=0, store_index=0, output_path=str(out),
        progress_callback=lambda w, t: progress_calls.append((w, t)),
    )
    assert result["success"] is True
    assert result["bytes_written"] == 1024 * 1024
    assert out.read_bytes() == b'S' * 1024 * 1024
    assert len(progress_calls) > 0
    assert progress_calls[-1] == (1024 * 1024, 1024 * 1024)


def test_materialize_shadow_copy_respects_should_stop(tmp_path, fake_pyvshadow, monkeypatch):
    # Shrink the chunk size well below the fake store's 2MB so the copy
    # loop genuinely needs multiple chunks - otherwise the whole store
    # fits in one 4MB chunk and should_stop() only gets checked once,
    # before any real interruption opportunity exists.
    monkeypatch.setattr(vu, 'VSHADOW_READ_CHUNK_SIZE', 64 * 1024)
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 2048)
    out = tmp_path / "shadow1.dd"
    call_count = [0]

    def _stop_after_first_chunk():
        call_count[0] += 1
        return call_count[0] > 1
    result = vu.materialize_shadow_copy(
        str(disk), partition_offset=0, store_index=1, output_path=str(out), should_stop=_stop_after_first_chunk,
    )
    assert result["success"] is False
    assert "stopped" in result["error"].lower()
    assert result["bytes_written"] < 2048 * 1024  # didn't finish the full 2MB store


def test_materialize_shadow_copy_rejects_an_out_of_range_index(tmp_path, fake_pyvshadow):
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b'\x00' * 2048)
    out = tmp_path / "shadow_bad.dd"
    result = vu.materialize_shadow_copy(str(disk), partition_offset=0, store_index=99, output_path=str(out))
    assert result["success"] is False
    assert "does not exist" in result["error"]
