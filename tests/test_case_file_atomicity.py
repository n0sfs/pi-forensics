"""core/jobs.py's consolidated case-file read/write (both fixed 2026-09-15).

Two defects that compounded into complete, silent loss of a case's history:

1. `_read_case_file()` caught EVERY exception and returned an empty stub, so a
   corrupt file - or a transient read error on the NFS share this app
   routinely stores cases on - was indistinguishable from a brand-new case.
   Callers then went on to WRITE that stub back, replacing events, notes,
   custody entries and examiners with four empty keys, and reporting success.

2. `_write_case_file()` was a truncating `open(w)`, so an interrupted write
   left a truncated or empty file behind - which defect 1 then read as an
   empty case, which the next write made permanent.

Skipped (not failed) on a non-POSIX dev machine: core.jobs imports POSIX-only
pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="core.jobs imports POSIX-only pwd/fcntl")

from core.jobs import (_read_case_file, _write_case_file, read_case_file_or_stub,
                       CaseFileUnreadable)


REAL_CASE = {
    "schema_version": 1,
    "case_number": "2026-CASE-ATOMIC",
    "events": [{"event_id": "evt-1", "acquisition_status": "COMPLETED"}],
    "case_notes": [{"text": "an irreplaceable observation"}],
    "custody_log": [{"from": "field", "to": "locker"}],
    "examiners": ["A. Examiner"],
}


def _case_path(tmp_path):
    return str(tmp_path / "2026-CASE-ATOMIC_case.json")


# --- Reading -----------------------------------------------------------------

def test_a_missing_file_is_a_new_case_not_an_error(tmp_path):
    """The legitimate stub case must keep working - a case folder with no
    consolidated file yet is normal, not a failure."""
    data = _read_case_file(str(tmp_path / "does_not_exist.json"))
    assert data["events"] == []
    assert data["attachments"] == {"files": [], "reference_urls": []}


def test_an_empty_file_is_treated_as_a_new_case(tmp_path):
    """A zero-byte file is what an interrupted pre-fix write left behind.
    There is no content to lose, so this must not block the examiner."""
    path = _case_path(tmp_path)
    open(path, "w").close()
    assert _read_case_file(path)["events"] == []


def test_a_corrupt_file_raises_rather_than_reading_as_an_empty_case(tmp_path):
    """The core of the fix. Returning a stub here is what let the next write
    destroy the case."""
    path = _case_path(tmp_path)
    with open(path, "w") as f:
        f.write('{"events": [{"event_id": "evt-1"}')  # truncated mid-object
    with pytest.raises(CaseFileUnreadable):
        _read_case_file(path)


def test_the_error_says_nothing_was_modified(tmp_path):
    """The message reaches the examiner through app.py's errorhandler, so it
    has to answer the question they will actually have."""
    path = _case_path(tmp_path)
    with open(path, "w") as f:
        f.write("not json at all")
    with pytest.raises(CaseFileUnreadable) as excinfo:
        _read_case_file(path)
    assert "nothing has been modified" in str(excinfo.value).lower()


def test_a_corrupt_file_is_left_exactly_as_it_was(tmp_path):
    """Reading must never repair, truncate or replace the file it failed on -
    a corrupt case file may still be recoverable by hand."""
    path = _case_path(tmp_path)
    corrupt = '{"events": [{"event_id": "evt-1"}'
    with open(path, "w") as f:
        f.write(corrupt)
    with pytest.raises(CaseFileUnreadable):
        _read_case_file(path)
    with open(path) as f:
        assert f.read() == corrupt


def test_read_case_file_or_stub_still_degrades_for_display_paths(tmp_path):
    """Read-only views may prefer an empty render over a failure. This variant
    exists so that choice is explicit at the call site rather than being the
    silent default everywhere."""
    path = _case_path(tmp_path)
    with open(path, "w") as f:
        f.write("{oh no")
    assert read_case_file_or_stub(path)["events"] == []


# --- Writing -----------------------------------------------------------------

def test_write_then_read_round_trips(tmp_path):
    path = _case_path(tmp_path)
    _write_case_file(path, REAL_CASE)
    assert _read_case_file(path) == REAL_CASE


def test_write_leaves_no_temp_files_behind(tmp_path):
    path = _case_path(tmp_path)
    _write_case_file(path, REAL_CASE)
    leftovers = [n for n in os.listdir(tmp_path) if n != os.path.basename(path)]
    assert leftovers == [], f"temp files left behind: {leftovers}"


def test_a_failed_write_does_not_destroy_the_existing_case(tmp_path, monkeypatch):
    """The whole point of writing through a temp file. Before the fix, open(w)
    truncated the real file before serialisation had produced a single byte,
    so a serialisation failure mid-write left a half-file on disk."""
    path = _case_path(tmp_path)
    _write_case_file(path, REAL_CASE)

    class Unserialisable:
        pass

    doomed = dict(REAL_CASE)
    doomed["events"] = [Unserialisable()]
    with pytest.raises(TypeError):
        _write_case_file(path, doomed)

    # The original is intact, and still parses.
    assert _read_case_file(path) == REAL_CASE
    leftovers = [n for n in os.listdir(tmp_path) if n != os.path.basename(path)]
    assert leftovers == [], f"temp files left behind after a failed write: {leftovers}"


def test_the_temp_file_is_created_beside_the_target(tmp_path, monkeypatch):
    """os.replace is only atomic within one filesystem, and a case folder can
    sit on a mounted share while the system temp dir does not - so the temp
    file must be a sibling, never in /tmp."""
    path = _case_path(tmp_path)
    seen = {}
    import tempfile as _tempfile
    real_mkstemp = _tempfile.mkstemp

    def spy(*args, **kwargs):
        seen["dir"] = kwargs.get("dir")
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr("core.jobs.tempfile.mkstemp", spy)
    _write_case_file(path, REAL_CASE)
    assert seen["dir"] == os.path.dirname(os.path.abspath(path))


def test_a_reader_never_sees_a_partially_written_file(tmp_path):
    """Whatever is at the path is always a complete, parseable document - the
    property os.replace() buys and open(w) cannot."""
    path = _case_path(tmp_path)
    _write_case_file(path, REAL_CASE)
    for i in range(20):
        record = dict(REAL_CASE)
        record["events"] = [{"event_id": f"evt-{n}"} for n in range(i * 50)]
        _write_case_file(path, record)
        with open(path) as f:
            parsed = json.load(f)   # raises if a truncated write was ever visible
        assert len(parsed["events"]) == i * 50
