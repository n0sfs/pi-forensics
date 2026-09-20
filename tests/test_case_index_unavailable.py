"""A case index that EXISTS but cannot be read (2026-09-20).

Found live: this station's own 2026-CASE-MOBILE-SWEEP index is genuinely
malformed (`PRAGMA integrity_check` = "database disk image is malformed"),
almost certainly from SQLite's exposure to a `soft` NFS mount turning a NAS
stall into a mid-transaction I/O error. Before the fix the raw
sqlite3.DatabaseError escaped to Flask as an HTML 500 from all 28 reader
call sites, and one corrupt file took out /api/reporting/stats for the whole
station because that stat walks every case index.

The counterpart of tests covering core/jobs.py's CaseFileUnreadable - same
bug class, one file over.
"""
import json
import os
import pathlib
import sqlite3

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    folder = pathlib.Path(evidence_root) / "2026-CASE-CORRUPT"
    folder.mkdir()
    (folder / "2026-CASE-CORRUPT_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-CORRUPT", "events": [],
    }))
    return str(folder)


def _corrupt_the_index(db_path):
    """Overwrite the SQLite header so the file is unmistakably not a
    database, while still existing and being non-empty - exactly the shape
    the real damaged index has (present, right size, unreadable)."""
    with open(db_path, "r+b") as f:
        f.write(b"this is not a sqlite database at all, not even close\x00")


@pytest.fixture(autouse=True)
def _clear_schema_memo():
    """The connect-time schema memo is per-process and keyed by inode; tests
    create and destroy index files at the same paths, so it must not leak
    between them."""
    case_index_db._schema_ready.clear()
    yield
    case_index_db._schema_ready.clear()


def test_corrupt_index_raises_named_exception_not_bare_sqlite_error(case_folder):
    db_path = case_index_db.case_index_db_path(case_folder)
    case_index_db._case_index_connect(db_path).close()
    _corrupt_the_index(db_path)
    case_index_db._schema_ready.clear()

    with pytest.raises(case_index_db.CaseIndexUnavailable) as excinfo:
        case_index_db._case_index_connect(db_path)
    # The path is carried on the exception so the handler can say which case.
    assert excinfo.value.db_path == db_path
    assert isinstance(excinfo.value.original, sqlite3.DatabaseError)


def test_reader_open_propagates_rather_than_returning_none(case_folder):
    """The critical distinction. Returning None would route a corrupt index
    into the SAME code path as "this case was never indexed", so an examiner
    would be shown a confident, empty result for data that is merely
    unreadable. It must raise instead."""
    db_path = case_index_db.case_index_db_path(case_folder)
    case_index_db._case_index_connect(db_path).close()
    _corrupt_the_index(db_path)
    case_index_db._schema_ready.clear()

    with pytest.raises(case_index_db.CaseIndexUnavailable):
        case_index_db._case_index_open_readonly(case_folder)


def test_never_indexed_case_still_returns_none(case_folder):
    """The pre-existing contract, which the fix must not disturb: a case with
    no index file at all is not an error, it is an empty result."""
    db_path = case_index_db.case_index_db_path(case_folder)
    assert not os.path.exists(db_path)
    assert case_index_db._case_index_open_readonly(case_folder) is None


def _spy_on_schema_setup(monkeypatch):
    """Counts how many times the schema-setup branch actually runs.

    sqlite3.Connection is an immutable type, so executescript itself cannot be
    patched. _ensure_tags_severity_column() sits in that same branch, directly
    after the script, and is a plain module-level function - so it is a
    faithful stand-in for "the setup work ran", and counting is exact rather
    than timing-based (timing would be flaky, and on a local disk the
    difference this fix targets is tiny; it only shows up on network storage)."""
    calls = []
    real = case_index_db._ensure_tags_severity_column

    def counting(conn):
        calls.append(True)
        return real(conn)

    monkeypatch.setattr(case_index_db, "_ensure_tags_severity_column", counting)
    return calls


def test_schema_script_is_skipped_on_reopen(case_folder, monkeypatch):
    """The F2 fix: the schema setup must run once per (process, index file),
    not on every open. Measured on the station's NFS-backed index it was
    ~0.27s of every single open, paid by all 28 read-only call sites - and,
    more importantly, it meant every READ opened the evidence index
    read-write and executed CREATE TABLE against it."""
    db_path = case_index_db.case_index_db_path(case_folder)
    calls = _spy_on_schema_setup(monkeypatch)

    case_index_db._case_index_connect(db_path).close()
    assert len(calls) == 1, "first open must seed the schema"
    case_index_db._case_index_connect(db_path).close()
    case_index_db._case_index_connect(db_path).close()
    assert len(calls) == 1, "later opens of the same index must skip the setup"


def test_recreated_index_is_re_seeded(case_folder, monkeypatch):
    """The memo is keyed by (st_dev, st_ino), so deleting the index and
    letting it be recreated must seed it again - a stale path-keyed memo
    would leave the new file with no tables at all."""
    db_path = case_index_db.case_index_db_path(case_folder)
    calls = _spy_on_schema_setup(monkeypatch)

    case_index_db._case_index_connect(db_path).close()
    assert len(calls) == 1
    os.remove(db_path)
    conn = case_index_db._case_index_connect(db_path)
    try:
        assert len(calls) == 2, "a recreated index must be seeded again"
        # and it really does have its tables back
        assert conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0] == 8
    finally:
        conn.close()
