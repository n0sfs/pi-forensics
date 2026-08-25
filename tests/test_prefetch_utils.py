"""core/prefetch_utils.py - Windows Prefetch (.pf) parsing (follow-up to
Part C, 2026-08-25).

Disclosed limitation, matching this module's own docstring: no genuine,
valid SCCA-format .pf file was available this session to parse end-to-end
(the on-disk format is compressed/checksummed and impractical to hand-
construct correctly, unlike REGF/EVTX/$I, which this project's other test
fixtures do build byte-for-byte). Instead, this file verifies
parse_prefetch_file()'s field-extraction/record-shaping logic against a
stand-in object that mirrors pyscca's real, live-confirmed API surface
(pyscca.file()'s executable_filename/open()/close()/get_run_count()/
get_last_run_time_as_integer()/get_number_of_filenames()/get_filename()/
get_prefetch_hash(), confirmed via help() against the real installed
package on the deployed Pi before this module was written) - this proves
the parsing logic itself is correct, not the on-disk byte layout.

Skipped (not failed) if libscca-python isn't installed - a genuinely
optional pip dependency, matching test_registry_utils.py's/test_evtx_
utils.py's own reasoning for the same kind of skip.
"""
import pytest

pyscca = pytest.importorskip("pyscca", reason="libscca-python not installed")

import core.prefetch_utils as pf


class _FakeSccaFile:
    """Stands in for a real pyscca.file() instance, matching its real,
    live-confirmed method/property surface exactly."""
    opened_path = None

    def __init__(self):
        self.executable_filename = "CHROME.EXE"
        self._run_count = 42
        self._last_run_raw = 133_700_000_000_000_000  # a real-shaped FILETIME
        self._filenames = ["\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                            "\\DEVICE\\HARDDISKVOLUME1\\PROGRAM FILES\\GOOGLE\\CHROME\\CHROME.EXE"]

    def open(self, path):
        _FakeSccaFile.opened_path = path

    def close(self):
        pass

    def get_run_count(self):
        return self._run_count

    def get_last_run_time_as_integer(self, index):
        return self._last_run_raw if index == 0 else None

    def get_number_of_filenames(self):
        return len(self._filenames)

    def get_filename(self, i):
        return self._filenames[i]

    def get_prefetch_hash(self):
        return 0xDEADBEEF


def test_parse_prefetch_file_extracts_real_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(pf.pyscca, "file", _FakeSccaFile)
    fake_path = tmp_path / "CHROME.EXE-DEADBEEF.pf"
    fake_path.write_bytes(b"placeholder - never actually read, pyscca.file is mocked")

    records = pf.parse_prefetch_file(str(fake_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "prefetch_execution"
    assert r["title"] == "CHROME.EXE"
    assert r["value"] == "run count: 42"
    assert r["timestamp"] is not None
    assert r["timestamp"] > 0
    assert r["extra"]["run_count"] == 42
    assert r["extra"]["prefetch_hash"] == 0xDEADBEEF
    assert len(r["extra"]["referenced_files"]) == 2
    assert "CHROME.EXE" in r["extra"]["referenced_files"][1]
    # confirms the real file path (not a placeholder) is what actually
    # gets handed to pyscca's own open() call
    assert _FakeSccaFile.opened_path == str(fake_path)


def test_parse_prefetch_file_falls_back_to_basename_when_executable_filename_empty(tmp_path, monkeypatch):
    class _NoExeName(_FakeSccaFile):
        def __init__(self):
            super().__init__()
            self.executable_filename = ""

    monkeypatch.setattr(pf.pyscca, "file", _NoExeName)
    fake_path = tmp_path / "SOMEAPP.EXE-12345678.pf"
    fake_path.write_bytes(b"x")
    records = pf.parse_prefetch_file(str(fake_path))
    assert records[0]["title"] == "SOMEAPP.EXE-12345678.pf"


def test_parse_prefetch_file_caps_referenced_files_list(tmp_path, monkeypatch):
    class _ManyFiles(_FakeSccaFile):
        def __init__(self):
            super().__init__()
            self._filenames = [f"\\file{i}.dll" for i in range(500)]

        def get_number_of_filenames(self):
            return 500

    monkeypatch.setattr(pf.pyscca, "file", _ManyFiles)
    fake_path = tmp_path / "BIG.EXE-11111111.pf"
    fake_path.write_bytes(b"x")
    records = pf.parse_prefetch_file(str(fake_path))
    assert len(records[0]["extra"]["referenced_files"]) == pf.PREFETCH_MAX_REFERENCED_FILES


def test_parse_prefetch_file_open_failure_returns_empty_not_raises(tmp_path, monkeypatch):
    class _RaisesOnOpen(_FakeSccaFile):
        def open(self, path):
            raise OSError("not a valid SCCA file")

    monkeypatch.setattr(pf.pyscca, "file", _RaisesOnOpen)
    fake_path = tmp_path / "BAD.pf"
    fake_path.write_bytes(b"not a real prefetch file")
    assert pf.parse_prefetch_file(str(fake_path)) == []


def test_find_prefetch_files_matches_by_extension_case_insensitively(tmp_path):
    (tmp_path / "CHROME.EXE-DEADBEEF.pf").write_bytes(b"x")
    (tmp_path / "lowercase.pf").write_bytes(b"x")
    (tmp_path / "unrelated.txt").write_bytes(b"x")
    found, truncated = pf.find_prefetch_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"CHROME.EXE-DEADBEEF.pf", "lowercase.pf"}
    assert truncated is False
