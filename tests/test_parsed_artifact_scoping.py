"""core/case_index_db.py::_record_parsed_artifacts() and _record_analysis_result()
(2026-10-02 review).

- Re-parsing a source deleted its earlier rows by source_path alone. Two images
  in one case share in-image paths - every Windows image has a
  /Windows/System32/config/SYSTEM - so parsing image B's hive wiped image A's
  parsed records.
- A caller with no source path had every INSERT fail (source_path is NOT NULL)
  inside a swallowed exception, while its route reported "indexed".
- A Closed/Archived case's index took new rows from any route that forgot the
  up-front refusal.

core/case_index_db.py has no POSIX-only imports, so this runs everywhere.
"""
import json
import os

import pytest

import core.case_index_db as case_index_db


def _make_case(evidence_root, slug="2026-SCOPE", status="Open"):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": case_dir,
                   "case_status": status, "events": []}, f)
    return case_dir


def _rows(case_dir):
    conn = case_index_db._case_index_connect(case_index_db.case_index_db_path(case_dir))
    try:
        return conn.execute("SELECT source_type, image_path, fs_offset, source_path, value "
                            "FROM parsed_artifacts ORDER BY image_path, value").fetchall()
    finally:
        conn.close()


def _record(case_dir, image, value, path="/Windows/System32/config/SYSTEM", offset=2048):
    return case_index_db._record_parsed_artifacts(case_dir, {
        "source_type": "image", "image_path": image, "fs_offset": offset, "inode": "100", "path": path,
    }, [{"artifact_type": "registry_value", "title": "t", "value": value, "timestamp": None}])


def test_parsing_a_second_image_keeps_the_first_images_records(evidence_root):
    case_dir = _make_case(evidence_root)
    image_a = os.path.join(case_dir, "laptop.dd")
    image_b = os.path.join(case_dir, "desktop.dd")
    assert _record(case_dir, image_a, "from A") == 1
    assert _record(case_dir, image_b, "from B") == 1
    assert sorted(r[4] for r in _rows(case_dir)) == ["from A", "from B"]


def test_re_parsing_the_same_source_still_replaces_its_rows(evidence_root):
    case_dir = _make_case(evidence_root)
    image_a = os.path.join(case_dir, "laptop.dd")
    _record(case_dir, image_a, "first run")
    _record(case_dir, image_a, "second run")
    assert [r[4] for r in _rows(case_dir)] == ["second run"]


def test_another_partition_of_the_same_image_is_its_own_source(evidence_root):
    case_dir = _make_case(evidence_root)
    image_a = os.path.join(case_dir, "laptop.dd")
    _record(case_dir, image_a, "partition 1", offset=2048)
    _record(case_dir, image_a, "partition 2", offset=999424)
    assert sorted(r[4] for r in _rows(case_dir)) == ["partition 1", "partition 2"]


def test_a_real_folder_source_is_unaffected_by_an_image_with_the_same_path_text(evidence_root):
    case_dir = _make_case(evidence_root)
    case_index_db._record_parsed_artifacts(case_dir, {"source_type": "real_fs", "path": "/x/History"},
                                           [{"artifact_type": "chrome_history", "value": "real"}])
    _record(case_dir, os.path.join(case_dir, "img.dd"), "image", path="/x/History")
    assert sorted(r[4] for r in _rows(case_dir)) == ["image", "real"]


def test_no_source_path_writes_nothing_and_says_zero(evidence_root):
    case_dir = _make_case(evidence_root)
    written = case_index_db._record_parsed_artifacts(case_dir, {
        "source_type": "image", "image_path": "/mnt/x.dd", "fs_offset": 0, "inode": "5", "path": None,
    }, [{"artifact_type": "lnk_shortcut", "value": "v"}])
    assert written == 0
    assert _rows(case_dir) == []


@pytest.mark.parametrize("status", ["Closed", "Archived"])
def test_a_finished_cases_index_takes_no_new_rows(evidence_root, status):
    case_dir = _make_case(evidence_root, status=status)
    assert _record(case_dir, os.path.join(case_dir, "img.dd"), "late") == 0
    case_index_db._record_analysis_result(case_dir, {
        "source_type": "image", "image_path": "/mnt/x.dd", "fs_offset": 0, "inode": "5", "path": "/a",
        "name": "a"}, "Strings", "summary", "output", run_by="examiner")
    conn = case_index_db._case_index_connect(case_index_db.case_index_db_path(case_dir))
    try:
        assert conn.execute("SELECT COUNT(*) FROM parsed_artifacts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0] == 0
    finally:
        conn.close()
