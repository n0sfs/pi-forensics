"""The examiner-decision sidecar, and journal-mode selection by storage type
(2026-09-20).

`tags`, `tagged_items` and `contact_merges` are the only three tables in the
case index a re-scan cannot reconstruct - they are judgements a person made.
Until this existed they lived in exactly one place: a single SQLite file on a
`soft`-mounted NFS share, with no backup and no rebuild path, and one of this
station's 18 indexes is already corrupt.
"""
import json
import os
import pathlib
import sqlite3

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    folder = pathlib.Path(evidence_root) / "2026-CASE-TAGBACKUP"
    folder.mkdir()
    (folder / "2026-CASE-TAGBACKUP_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-TAGBACKUP", "events": [],
    }))
    return str(folder)


@pytest.fixture(autouse=True)
def _clear_schema_memo():
    case_index_db._schema_ready.clear()
    yield
    case_index_db._schema_ready.clear()


def _tag_something(case_folder, name="Notable Item", path="/mnt/evidence/x.jpg"):
    conn = case_index_db._case_index_open_write(case_folder)
    try:
        tag_id = conn.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()[0]
        conn.execute(
            "INSERT INTO tagged_items (tag_id, source_type, path, name, tagged_by, tagged_at) "
            "VALUES (?,'real_fs',?,?,?,?)",
            (tag_id, path, os.path.basename(path), "examiner", "2026-09-20 10:00:00"))
        conn.commit()
    finally:
        conn.close()
    return tag_id


def test_export_writes_the_three_irreplaceable_tables(case_folder):
    _tag_something(case_folder)
    written = case_index_db.export_case_tag_state(case_folder)
    assert written and os.path.isfile(written)

    data = json.loads(open(written).read())
    assert data["version"] == case_index_db._CASE_TAG_BACKUP_VERSION
    assert len(data["tags"]) == 8                  # the seeded defaults
    assert len(data["tagged_items"]) == 1
    assert data["tagged_items"][0]["path"] == "/mnt/evidence/x.jpg"
    assert data["contact_merges"] == []


def test_export_is_atomic_and_leaves_no_temp_file(case_folder):
    _tag_something(case_folder)
    written = case_index_db.export_case_tag_state(case_folder)
    assert not os.path.exists(written + ".tmp")


def test_restore_reseeds_a_rebuilt_index(case_folder):
    """The scenario this exists for: the index is destroyed, a fresh empty one
    is created, and the examiner's own work comes back."""
    tag_id = _tag_something(case_folder, path="/mnt/evidence/important.jpg")
    conn = case_index_db._case_index_open_write(case_folder)
    conn.execute(
        "INSERT INTO contact_merges (primary_key, merged_key, justification, merged_by, merged_at) "
        "VALUES (?,?,?,?,?)", ("+15550100", "+15550101", "same handset", "examiner", "2026-09-20"))
    conn.commit()
    conn.close()
    case_index_db.export_case_tag_state(case_folder)

    # Destroy the index exactly as a corruption-recovery rebuild would.
    db_path = case_index_db.case_index_db_path(case_folder)
    os.remove(db_path)
    case_index_db._schema_ready.clear()

    restored = case_index_db.restore_case_tag_state(case_folder)
    assert restored["tagged_items"] == 1
    assert restored["contact_merges"] == 1

    conn = case_index_db._case_index_open_readonly(case_folder)
    try:
        row = conn.execute(
            "SELECT path, tag_id FROM tagged_items WHERE path=?",
            ("/mnt/evidence/important.jpg",)).fetchone()
        assert row is not None, "the examiner's tagged item must come back"
        assert row[1] == tag_id, "tag ids must be preserved so the FK still resolves"
        assert conn.execute("SELECT COUNT(*) FROM contact_merges").fetchone()[0] == 1
    finally:
        conn.close()


def test_restore_never_overwrites_live_rows(case_folder):
    """The live index wins: a backup may predate recent work, so restore is
    additive only."""
    _tag_something(case_folder, path="/mnt/evidence/a.jpg")
    case_index_db.export_case_tag_state(case_folder)
    # Work done AFTER the backup was taken.
    _tag_something(case_folder, path="/mnt/evidence/b.jpg")

    restored = case_index_db.restore_case_tag_state(case_folder)
    assert restored["tagged_items"] == 0, "nothing to restore; both rows already present"

    conn = case_index_db._case_index_open_readonly(case_folder)
    try:
        paths = {r[0] for r in conn.execute("SELECT path FROM tagged_items")}
        assert paths == {"/mnt/evidence/a.jpg", "/mnt/evidence/b.jpg"}
    finally:
        conn.close()


def test_missing_backup_is_not_an_error(case_folder):
    assert case_index_db.read_case_tag_backup(case_folder) is None
    assert case_index_db.restore_case_tag_state(case_folder) is None


def test_corrupt_backup_is_ignored_rather_than_raising(case_folder):
    """Unlike the index, an unreadable sidecar is not worth failing over - it
    is a recovery aid, and there is nothing to recover if the index is fine."""
    backup_path = case_index_db.case_tag_backup_path(case_folder)
    with open(backup_path, "w") as f:
        f.write("{ this is not json")
    assert case_index_db.read_case_tag_backup(case_folder) is None


def test_export_on_a_never_indexed_case_is_a_no_op(case_folder):
    assert case_index_db.export_case_tag_state(case_folder) is None


# --- journal mode by storage type ---

def test_local_storage_still_uses_wal(case_folder, monkeypatch):
    """WAL is genuinely wanted on local disk - it is why a running scan's
    writes don't block a concurrent File Explorer read. The fix must only
    change behaviour on network storage."""
    monkeypatch.setattr(case_index_db, "filesystem_is_network", lambda p: False)
    db_path = case_index_db.case_index_db_path(case_folder)
    assert case_index_db._journal_mode_for(db_path) == "WAL"
    conn = case_index_db._case_index_connect(db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


def test_network_storage_uses_delete_not_wal(case_folder, monkeypatch):
    """SQLite's documentation is explicit that WAL requires shared memory and
    does not work over a network filesystem - which is where this app
    routinely stores cases."""
    monkeypatch.setattr(case_index_db, "filesystem_is_network", lambda p: True)
    db_path = case_index_db.case_index_db_path(case_folder)
    assert case_index_db._journal_mode_for(db_path) == "DELETE"
    conn = case_index_db._case_index_connect(db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    finally:
        conn.close()


def test_filesystem_is_network_is_false_when_undeterminable(tmp_path, monkeypatch):
    """No /proc/mounts (a non-Linux dev machine) must keep today's behaviour
    rather than silently switching journal mode on a local disk."""
    def _no_proc(*args, **kwargs):
        raise OSError("no /proc/mounts here")
    monkeypatch.setattr("builtins.open", _no_proc)
    assert case_index_db.filesystem_is_network(str(tmp_path)) is False


@pytest.mark.skipif(not os.path.exists("/proc/mounts"), reason="needs /proc/mounts")
def test_filesystem_is_network_reads_real_mounts():
    """Sanity: a local path is not reported as network storage."""
    assert case_index_db.filesystem_is_network("/usr") is False
