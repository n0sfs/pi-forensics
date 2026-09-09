"""routes/file_explorer.py's execution_worker_import_takeout() - the 6th
of 10 execution_worker_* functions found with zero pytest coverage during
a self-directed validation pass (2026-09-09) - see that dated CLAUDE.md
section for the discovery/scoping rationale.

A close sibling of execution_worker_import_apple_export() (see that
file's own docstring - same overall shape, same "you hold the key, we
just read what it unlocks" scope boundary, same real production calling
convention around the worker's own unconditional final
log_chain_of_custody() call needing explicit source_ip/user), but with
two real, confirmed differences worth testing rather than assuming
identical: (1) an extra prepare_takeout_root() step handling either an
already-extracted folder or real .zip parts that need merging first, and
(2) location_points arrive already-parsed from import_takeout_archive()
itself (Google Takeout's own JSON exports), never needing a second
exiftool subprocess call the way Apple's Photos-folder-based export does -
_build_geo_kml() is called directly against result["location_points"].

Mocks the genuine external boundaries: prepare_takeout_root()/
import_takeout_archive() (real archive-merging/parsing logic, core/
takeout_utils.py, already covered by its own dedicated tests) and
_record_parsed_artifacts/_auto_tag_case_artifact (real per-case SQLite
writes, already covered elsewhere). _build_geo_kml() runs for REAL
against the mocked location_points, and case_consolidated_path() also
runs for REAL against a genuine on-disk case marker (the project's own
established evidence_root fixture), matching test_apple_export_import_
worker.py's own established approach for this exact function.

Skipped (not failed) on a non-POSIX dev machine: routes.file_explorer
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.file_explorer as file_explorer
from core.jobs import snapshot_job


def _ok_result(products_found=None, warnings=None, records=None, location_points=None):
    return {
        "products_found": products_found or [],
        "warnings": warnings or [],
        "records": records or [],
        "location_points": location_points or [],
    }


def _make_case_folder(evidence_root, slug="2026-TEST-TAKEOUT"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder)
    with open(os.path.join(case_folder, f"{slug}_case.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    return case_folder


class TestExecutionWorkerImportTakeout:
    def _run(self, tmp_path, import_result=None, case_folder=None,
              prepare_return=None, source_ip="127.0.0.1", user="test-user"):
        dest_dir = str(tmp_path)
        import_result = import_result if import_result is not None else _ok_result()
        takeout_root = str(tmp_path / "Takeout")
        os.makedirs(takeout_root, exist_ok=True)
        prepare_return = prepare_return if prepare_return is not None else (takeout_root, 0, 0)

        with mock.patch.object(file_explorer, "prepare_takeout_root", return_value=prepare_return) as mock_prepare, \
             mock.patch.object(file_explorer, "import_takeout_archive", return_value=import_result), \
             mock.patch.object(file_explorer, "_record_parsed_artifacts") as mock_record, \
             mock.patch.object(file_explorer, "_auto_tag_case_artifact") as mock_tag:
            file_explorer.execution_worker_import_takeout(
                [takeout_root], case_folder, dest_dir, source_ip=source_ip, user=user)

        return snapshot_job(), mock_prepare, mock_record, mock_tag

    def test_happy_path_with_no_case_and_no_location_points_completes_cleanly(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(products_found=["Search History", "YouTube History"]),
        )
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert "Search History, YouTube History" in job["log"]
        mock_record.assert_not_called()
        mock_tag.assert_not_called()

    def test_extracted_and_skipped_counts_from_archive_merging_are_surfaced_in_the_log(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, prepare_return=(str(tmp_path / "Takeout"), 42, 3),
        )
        assert "Extracted 42 file(s) from archive part(s), skipped 3 unsafe entrie(s)" in job["log"]

    def test_an_already_extracted_folder_with_zero_extracted_and_skipped_logs_no_extraction_line(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, prepare_return=(str(tmp_path / "Takeout"), 0, 0),
        )
        assert "Extracted" not in job["log"]

    def test_records_are_recorded_against_a_real_valid_consolidated_case(self, tmp_path, evidence_root):
        case_folder = _make_case_folder(evidence_root)
        records = [{"artifact_type": "takeout_search_history", "title": "example query"}]
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(records=records), case_folder=case_folder,
        )
        assert job["status"] == "Completed Successfully"
        mock_record.assert_called_once()
        args = mock_record.call_args[0]
        assert args[0] == case_folder
        assert args[1]["source_type"] == "real_fs"
        assert args[1]["name"] == "Google Takeout Import"
        assert args[2] == records
        assert "Recorded 1 record(s)" in job["log"]

    def test_records_are_not_recorded_when_the_case_folder_has_no_real_consolidated_marker(self, tmp_path, evidence_root):
        fake_case_folder = os.path.join(evidence_root, "not-a-real-case")
        os.makedirs(fake_case_folder)
        records = [{"artifact_type": "takeout_search_history", "title": "example query"}]
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(records=records), case_folder=fake_case_folder,
        )
        assert job["status"] == "Completed Successfully"
        mock_record.assert_not_called()

    def test_a_real_location_point_produces_a_real_kml_file_with_the_real_coordinates(self, tmp_path):
        points = [{"name": "Point 1", "directory": "", "lat": 40.7128, "lon": -74.0060, "alt": None, "timestamp": None},
                  {"name": "Point 2", "directory": "", "lat": 40.71281, "lon": -74.00601, "alt": None, "timestamp": None}]
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(location_points=points),
        )
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_called_once()
        kml_path = mock_tag.call_args[0][1]
        assert kml_path.endswith("takeout_location_history.kml")
        with open(kml_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "40.712800" in content or "40.7128" in content
        assert "2 location point(s) exported" in job["log"]

    def test_no_location_points_writes_no_kml_file(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(location_points=[]),
        )
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_not_called()

    def test_warnings_from_import_takeout_archive_are_surfaced_in_the_log(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(
            tmp_path, import_result=_ok_result(warnings=["Maps place data is best-effort."]),
        )
        assert "Maps place data is best-effort." in job["log"]

    def test_prepare_takeout_root_is_called_with_the_real_input_paths_and_a_work_dir_under_dest(self, tmp_path):
        job, mock_prepare, mock_record, mock_tag = self._run(tmp_path)
        mock_prepare.assert_called_once()
        args = mock_prepare.call_args[0]
        assert args[0] == [str(tmp_path / "Takeout")]
        assert args[1] == os.path.join(str(tmp_path), "takeout_import_work")

    def test_an_unexpected_exception_during_prepare_is_caught_and_reported_as_failed(self, tmp_path):
        # No explicit source_ip/user needed here - the exception happens
        # before the worker's own final log_chain_of_custody() call is
        # ever reached.
        with mock.patch.object(file_explorer, "prepare_takeout_root", side_effect=RuntimeError("simulated failure")):
            file_explorer.execution_worker_import_takeout(
                [str(tmp_path)], None, str(tmp_path), source_ip=None, user=None)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, side_effect in enumerate((None, RuntimeError("boom"))):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            takeout_root = str(iter_root / "Takeout")
            os.makedirs(takeout_root)
            if side_effect is None:
                with mock.patch.object(file_explorer, "prepare_takeout_root", return_value=(takeout_root, 0, 0)), \
                     mock.patch.object(file_explorer, "import_takeout_archive", return_value=_ok_result()):
                    file_explorer.execution_worker_import_takeout(
                        [takeout_root], None, str(iter_root), source_ip="127.0.0.1", user="test-user")
            else:
                with mock.patch.object(file_explorer, "prepare_takeout_root", side_effect=side_effect):
                    file_explorer.execution_worker_import_takeout(
                        [takeout_root], None, str(iter_root), source_ip="127.0.0.1", user="test-user")
            assert snapshot_job()["active"] is False
