"""core/case_index_db.py - the per-case SQLite analysis index's schema
seeding and the auto-tagging helper added this session (_auto_tag_case_
artifact), which report export / hash manifest / geolocation KML export
call directly, server-side, whenever they write a real file to a case
folder."""
import json
import os
import sqlite3

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    """A real, minimal consolidated case folder - just enough for
    case_consolidated_path() to recognize it (a {slug}_case.json marker
    file with the right basename-derived name). Lives inside evidence_root
    (see conftest.py) since case_index_db_path()/safe_path() both sandbox
    to core.paths.EVIDENCE_ROOT - a case folder outside it is correctly
    rejected, matching every other path-accepting function in this app."""
    import pathlib
    folder = pathlib.Path(evidence_root) / "2026-CASE-TEST"
    folder.mkdir()
    (folder / "2026-CASE-TEST_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-TEST", "events": [],
    }))
    return str(folder)


def test_schema_seeds_exactly_four_default_tags_and_is_idempotent(case_folder):
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    rows = conn.execute("SELECT name, is_default FROM tags ORDER BY name").fetchall()
    conn.close()
    names = {r[0] for r in rows}
    assert names == {"Bookmark", "Follow Up", "Notable Item", "Case Artifact"}
    assert all(r[1] == 1 for r in rows)  # every seeded default tag is_default=1

    # Re-running the schema (as every _case_index_connect() call does) must
    # not duplicate the seed rows.
    conn2 = case_index_db._case_index_connect(db_path)
    count = conn2.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
    conn2.close()
    assert count == 4


def test_auto_tag_case_artifact_creates_a_real_row(case_folder):
    target = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    case_index_db._auto_tag_case_artifact(case_folder, target)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    row = conn.execute(
        "SELECT t.name, ti.source_type, ti.path, ti.name, ti.tagged_by "
        "FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE ti.path=?",
        (target,)).fetchone()
    conn.close()
    assert row == ("Case Artifact", "real_fs", target, "2026-CASE-TEST_case.pdf", "system")


def test_auto_tag_case_artifact_does_not_duplicate_on_repeat_calls(case_folder):
    # Matches the real-world case this exists for: a report export
    # overwrites the same output filename on every re-export, so tagging it
    # again and again must stay a no-op after the first time, not pile up
    # duplicate tagged_items rows.
    target = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    for _ in range(3):
        case_index_db._auto_tag_case_artifact(case_folder, target)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM tagged_items WHERE path=?", (target,)).fetchone()[0]
    conn.close()
    assert count == 1


def test_auto_tag_case_artifact_is_a_silent_no_op_for_a_non_case_folder(tmp_path):
    # Not a real consolidated case (no {slug}_case.json marker) - must not
    # raise, and must not create a database file at all.
    not_a_case = tmp_path / "just_a_folder"
    not_a_case.mkdir()
    case_index_db._auto_tag_case_artifact(str(not_a_case), str(not_a_case / "whatever.txt"))
    assert not any(f.endswith('.db') for f in os.listdir(not_a_case))


def test_auto_tag_case_artifact_is_a_silent_no_op_for_none_or_empty_folder():
    # Must not raise for the "no active case" states every other best-effort
    # case-index write in this app already tolerates (see
    # _record_analysis_result's own docstring for the same contract).
    case_index_db._auto_tag_case_artifact(None, "/some/path.txt")
    case_index_db._auto_tag_case_artifact("", "/some/path.txt")


def test_two_different_files_get_two_distinct_tagged_rows(case_folder):
    a = os.path.join(case_folder, "a_hash_manifest_sha256.txt")
    b = os.path.join(case_folder, "b_geolocation_export.kml")
    case_index_db._auto_tag_case_artifact(case_folder, a)
    case_index_db._auto_tag_case_artifact(case_folder, b)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM tagged_items").fetchone()[0]
    conn.close()
    assert count == 2


def test_backfill_tags_pre_existing_artifact_files_never_seen_by_auto_tag(case_folder):
    # The exact gap this exists to close: a report/log/kml file that landed
    # on disk (a legacy case, a manual copy, or simply predates the
    # per-write-site auto-tag call) with no _auto_tag_case_artifact() call
    # ever having run against it. Note the case_folder fixture's own
    # {slug}_case.json marker is itself a recognized report artifact - it
    # gets swept too, correctly, so this asserts membership rather than an
    # exact set.
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    hashlog = os.path.join(case_folder, "2026-CASE-TEST_USBDrive-1_hash_manifest_sha256.txt")
    kml = os.path.join(case_folder, "geolocation_export.kml")
    evidence = os.path.join(case_folder, "batmanlego.JPG")  # not a recognized artifact - must stay untagged
    for p in (report, hashlog, kml, evidence):
        with open(p, "w") as f:
            f.write("x")

    case_index_db._backfill_case_artifact_tags(case_folder)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    tagged_paths = {r[0] for r in conn.execute(
        "SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE t.name='Case Artifact'")}
    conn.close()
    assert {report, hashlog, kml} <= tagged_paths
    assert evidence not in tagged_paths


def test_backfill_is_idempotent_and_skips_recovery_tool_output_dirs(case_folder):
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    with open(report, "w") as f:
        f.write("x")
    carved_dir = os.path.join(case_folder, "2026-CASE-TEST_ITEM-01_photorec")
    os.makedirs(carved_dir)
    # Same base name pattern classify_case_role() would otherwise match -
    # sitting inside a bulk carved-file output dir must never be swept.
    carved_lookalike = os.path.join(carved_dir, "recovered_case.pdf")
    with open(carved_lookalike, "w") as f:
        f.write("x")

    case_index_db._backfill_case_artifact_tags(case_folder)
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    first_paths = [r[0] for r in conn.execute(
        "SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE t.name='Case Artifact'")]
    conn.close()
    assert report in first_paths
    assert carved_lookalike not in first_paths

    # Re-run - a second sweep may legitimately pick up one new real artifact
    # this app itself just created (the per-case SQLite index file, which is
    # itself a recognized report artifact once it exists on disk), but must
    # never re-tag anything it already tagged, and must still never reach
    # into the carve-output dir.
    case_index_db._backfill_case_artifact_tags(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    second_paths = [r[0] for r in conn.execute(
        "SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE t.name='Case Artifact'")]
    dupes = conn.execute(
        "SELECT ti.path, COUNT(*) c FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id "
        "WHERE t.name='Case Artifact' GROUP BY ti.path HAVING c > 1").fetchall()
    conn.close()
    assert not dupes
    assert carved_lookalike not in second_paths


def test_backfill_is_a_silent_no_op_for_a_non_case_folder(tmp_path):
    not_a_case = tmp_path / "just_a_folder"
    not_a_case.mkdir()
    (not_a_case / "whatever_case.pdf").write_text("x")
    case_index_db._backfill_case_artifact_tags(str(not_a_case))
    assert not any(f.endswith('.db') for f in os.listdir(not_a_case))


def test_backfill_is_a_silent_no_op_for_none_or_empty_folder():
    case_index_db._backfill_case_artifact_tags(None)
    case_index_db._backfill_case_artifact_tags("")
