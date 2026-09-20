"""Analysis index health reporting and repair (2026-09-20).

Closes the gap left when restore_case_tag_state() landed with no route or UI:
recovery needed a shell on the station. The defining constraint here is that
this is a forensic appliance, so a damaged index is set ASIDE, never deleted.
"""
import json
import os
import pathlib
import sqlite3

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    folder = pathlib.Path(evidence_root) / "2026-CASE-REPAIR"
    folder.mkdir()
    (folder / "2026-CASE-REPAIR_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-REPAIR", "events": [],
    }))
    return str(folder)


@pytest.fixture(autouse=True)
def _clear_schema_memo():
    case_index_db._schema_ready.clear()
    yield
    case_index_db._schema_ready.clear()


def _corrupt(db_path):
    with open(db_path, "r+b") as f:
        f.write(b"not a sqlite database at all, not even slightly\x00")
    case_index_db._schema_ready.clear()


def _tag_something(case_folder, path="/mnt/evidence/x.jpg"):
    conn = case_index_db._case_index_open_write(case_folder)
    try:
        tag_id = conn.execute("SELECT id FROM tags WHERE name='Notable Item'").fetchone()[0]
        conn.execute(
            "INSERT INTO tagged_items (tag_id, source_type, path, name, tagged_by, tagged_at) "
            "VALUES (?,'real_fs',?,?,?,?)",
            (tag_id, path, os.path.basename(path), "examiner", "2026-09-20 10:00:00"))
        conn.commit()
    finally:
        conn.close()


# --- health ---

def test_health_reports_absent_index(case_folder):
    """Must not read as a fault. A case simply has no index until something is
    scanned or tagged in it."""
    h = case_index_db.case_index_health(case_folder)
    assert h["exists"] is False
    assert h["readable"] is False
    assert h["error"] is None


def test_health_reports_a_healthy_index_with_counts(case_folder):
    _tag_something(case_folder)
    h = case_index_db.case_index_health(case_folder)
    assert h["exists"] and h["readable"]
    assert h["integrity"] == "ok"
    assert h["counts"]["tagged_items"] == 1
    assert h["counts"]["tags"] == 8


def test_health_reports_damage_without_raising(case_folder):
    """Every other reader raises CaseIndexUnavailable so a corrupt index is
    never mistaken for an empty one. This function is the single exception,
    because describing the damage is its entire purpose."""
    _tag_something(case_folder)
    _corrupt(case_index_db.case_index_db_path(case_folder))
    h = case_index_db.case_index_health(case_folder)
    assert h["exists"] is True
    assert h["readable"] is False
    assert (h["integrity"] or h["error"]), "must say what SQLite reported"


# --- repair ---

def test_repair_sets_the_damaged_file_aside_and_never_deletes_it(case_folder):
    """The single most important property here. This is a forensic appliance:
    a later SQLite version or a .recover dump may still get something out of
    that file, and its existence is part of the case's history."""
    _tag_something(case_folder)
    case_index_db.export_case_tag_state(case_folder)
    db_path = case_index_db.case_index_db_path(case_folder)
    original_bytes = open(db_path, "rb").read()
    _corrupt(db_path)
    corrupted_bytes = open(db_path, "rb").read()

    result = case_index_db.repair_case_index(case_folder)

    assert result["quarantined_to"], "the damaged file must be kept under a new name"
    kept = os.path.join(case_folder, result["quarantined_to"])
    assert os.path.isfile(kept), "quarantined file must exist on disk"
    assert open(kept, "rb").read() == corrupted_bytes, "kept byte-for-byte, not rewritten"
    assert original_bytes != corrupted_bytes  # sanity: the test really did damage it


def test_repair_rebuilds_and_restores_examiner_decisions(case_folder):
    _tag_something(case_folder, path="/mnt/evidence/important.jpg")
    case_index_db.export_case_tag_state(case_folder)
    _corrupt(case_index_db.case_index_db_path(case_folder))

    result = case_index_db.repair_case_index(case_folder)
    assert result["rebuilt"] is True
    assert result["restored"]["tagged_items"] == 1

    conn = case_index_db._case_index_open_readonly(case_folder)
    try:
        row = conn.execute("SELECT path FROM tagged_items").fetchone()
        assert row[0] == "/mnt/evidence/important.jpg"
    finally:
        conn.close()


def test_repair_removes_stale_wal_siblings(case_folder):
    """A -wal/-shm left behind by the file we just moved would be applied to
    the NEW database and could re-corrupt it immediately."""
    _tag_something(case_folder)
    case_index_db.export_case_tag_state(case_folder)
    db_path = case_index_db.case_index_db_path(case_folder)
    _corrupt(db_path)
    for suffix in ("-wal", "-shm"):
        with open(db_path + suffix, "wb") as f:
            f.write(b"stale junk")

    case_index_db.repair_case_index(case_folder)
    for suffix in ("-wal", "-shm"):
        assert not os.path.exists(db_path + suffix), "stale %s must be cleared" % suffix
    assert case_index_db.case_index_health(case_folder)["readable"]


def test_repair_without_a_backup_still_rebuilds_but_restores_nothing(case_folder):
    """An honest partial outcome. The UI warns about this case before asking
    for confirmation, so the result has to distinguish it rather than reporting
    a generic success."""
    _tag_something(case_folder)
    _corrupt(case_index_db.case_index_db_path(case_folder))   # no export_case_tag_state() first

    result = case_index_db.repair_case_index(case_folder)
    assert result["rebuilt"] is True
    assert result["backup_present"] is False
    assert result["restored"] is None
    assert case_index_db.case_index_health(case_folder)["readable"]


def test_repair_on_a_healthy_index_does_not_quarantine_anything(case_folder):
    """Running repair on a case that is fine must be harmless - no file moved,
    no data lost, just a no-op restore."""
    _tag_something(case_folder)
    case_index_db.export_case_tag_state(case_folder)

    result = case_index_db.repair_case_index(case_folder)
    assert result["quarantined_to"] is None
    assert result["rebuilt"] is False
    assert result["was_readable"] is True
    assert result["restored"]["tagged_items"] == 0, "nothing to re-add; rows already present"

    conn = case_index_db._case_index_open_readonly(case_folder)
    try:
        assert conn.execute("SELECT COUNT(*) FROM tagged_items").fetchone()[0] == 1
    finally:
        conn.close()


def test_repair_reports_derived_tables_as_empty_after_a_rebuild(case_folder):
    """Derived data does NOT come back - it needs the analysis re-run. The
    health panel has to show that truthfully rather than implying full
    recovery."""
    conn = case_index_db._case_index_open_write(case_folder)
    try:
        conn.execute(
            "INSERT INTO parsed_artifacts (source_type, image_path, source_path, artifact_type, "
            "title, value, found_at) "
            "VALUES ('image','/img','/Users/x/History','chrome_history','t','v','2026-09-20 10:00:00')")
        conn.commit()
    finally:
        conn.close()
    _tag_something(case_folder)
    case_index_db.export_case_tag_state(case_folder)
    assert case_index_db.case_index_health(case_folder)["counts"]["parsed_artifacts"] == 1

    _corrupt(case_index_db.case_index_db_path(case_folder))
    case_index_db.repair_case_index(case_folder)

    h = case_index_db.case_index_health(case_folder)
    assert h["readable"] is True
    assert h["counts"]["tagged_items"] == 1, "examiner decisions come back"
    assert h["counts"]["parsed_artifacts"] == 0, "derived data does not"


def test_health_lists_previously_quarantined_files(case_folder):
    """So an examiner can see that this case has been repaired before - a
    repeatedly-corrupting index is itself a finding about the storage."""
    _tag_something(case_folder)
    case_index_db.export_case_tag_state(case_folder)
    _corrupt(case_index_db.case_index_db_path(case_folder))
    case_index_db.repair_case_index(case_folder)

    h = case_index_db.case_index_health(case_folder)
    assert len(h["quarantined"]) == 1
    assert ".corrupt-" in h["quarantined"][0]
