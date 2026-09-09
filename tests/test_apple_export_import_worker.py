"""routes/file_explorer.py's execution_worker_import_apple_export() - the
5th of 10 execution_worker_* functions found with zero pytest coverage
during a self-directed validation pass (2026-09-09) - see that dated
CLAUDE.md section for the discovery/scoping rationale.

Mocks the genuine external boundaries: import_apple_export() (the real
vCard/iCalendar/Safari/Photos parsing, core/apple_export_utils.py -
already covered by its own dedicated tests), _record_parsed_artifacts/
_auto_tag_case_artifact (real per-case SQLite writes, already covered by
their own dedicated tests), and subprocess.run (the real exiftool call
against the Photos export directory). _geo_points_from_exiftool_entries()/
_build_geo_kml() (core/geo_utils.py) run for REAL against the mocked
exiftool JSON output, and case_consolidated_path() runs for REAL against a
genuine on-disk case marker file (using the project's own established
evidence_root fixture, since that function routes through safe_path()
itself) - both are pure/cheap enough that exercising them for real is a
stronger test than mocking them away.

Unlike every other worker tested so far in this pass, this one has NO
Stop-button handling at all (confirmed by reading its source - no
snapshot_job()["status"] == "Stopped" check anywhere) - a real,
deliberate difference in shape from its siblings, not an oversight to
test around; import_apple_export() and the one exiftool call are both
short enough single operations that a mid-run interrupt was never built
for this one.

Skipped (not failed) on a non-POSIX dev machine: routes.file_explorer
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.file_explorer as file_explorer
from core.jobs import snapshot_job


def _ok_result(products_found=None, warnings=None, records=None, photos_dir=None):
    return {
        "products_found": products_found or [],
        "warnings": warnings or [],
        "records": records or [],
        "photos_dir": photos_dir,
    }


def _exiftool_proc(stdout_json=None, returncode=0):
    return types.SimpleNamespace(returncode=returncode, stdout=json.dumps(stdout_json) if stdout_json is not None else "", stderr="")


def _make_case_folder(evidence_root, slug="2026-TEST-APPLE"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder)
    with open(os.path.join(case_folder, f"{slug}_case.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    return case_folder


class TestExecutionWorkerImportAppleExport:
    def _run(self, tmp_path, import_result=None, case_folder=None, exiftool_side_effect=None,
              record_side_effect=None, source_ip="127.0.0.1", user="test-user"):
        export_root = str(tmp_path / "apple_export")
        os.makedirs(export_root, exist_ok=True)
        dest_dir = str(tmp_path)
        import_result = import_result if import_result is not None else _ok_result()

        with mock.patch.object(file_explorer, "import_apple_export", return_value=import_result), \
             mock.patch.object(file_explorer, "_record_parsed_artifacts",
                                side_effect=record_side_effect) as mock_record, \
             mock.patch.object(file_explorer, "_auto_tag_case_artifact") as mock_tag, \
             mock.patch("subprocess.run",
                         side_effect=exiftool_side_effect if exiftool_side_effect else lambda *a, **kw: _exiftool_proc()) as mock_run:
            file_explorer.execution_worker_import_apple_export(
                export_root, case_folder, dest_dir, source_ip=source_ip, user=user)

        return snapshot_job(), mock_record, mock_tag, mock_run

    def test_happy_path_with_no_case_and_no_photos_completes_cleanly(self, tmp_path):
        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(products_found=["Contacts", "Calendars"]),
        )
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert "Contacts, Calendars" in job["log"]
        mock_record.assert_not_called()  # no case_folder was passed at all
        mock_tag.assert_not_called()  # no photos_dir means no KML attempt
        mock_run.assert_not_called()

    def test_records_are_recorded_against_a_real_valid_consolidated_case(self, tmp_path, evidence_root):
        case_folder = _make_case_folder(evidence_root)
        records = [{"artifact_type": "apple_contact", "title": "Jane Doe", "value": "jane@example.com"}]
        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(products_found=["Contacts"], records=records),
            case_folder=case_folder,
        )
        assert job["status"] == "Completed Successfully"
        mock_record.assert_called_once()
        args = mock_record.call_args[0]
        assert args[0] == case_folder
        identity = args[1]
        assert identity["source_type"] == "real_fs"
        assert identity["path"].endswith("apple_export")
        assert args[2] == records
        assert "Recorded 1 record(s)" in job["log"]

    def test_records_are_not_recorded_when_the_case_folder_has_no_real_consolidated_marker(self, tmp_path, evidence_root):
        # A folder that merely exists (no {slug}_case.json marker) must be
        # treated exactly like no case_folder at all - case_consolidated_
        # path() runs for real here, not mocked, so this genuinely proves
        # the worker's own case_folder_valid gate, not just a mocked stand-in.
        fake_case_folder = os.path.join(evidence_root, "not-a-real-case")
        os.makedirs(fake_case_folder)
        records = [{"artifact_type": "apple_contact", "title": "Jane Doe"}]
        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(records=records), case_folder=fake_case_folder,
        )
        assert job["status"] == "Completed Successfully"
        mock_record.assert_not_called()

    def test_records_present_but_empty_list_never_calls_record_parsed_artifacts(self, tmp_path, evidence_root):
        case_folder = _make_case_folder(evidence_root)
        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(records=[]), case_folder=case_folder,
        )
        assert job["status"] == "Completed Successfully"
        mock_record.assert_not_called()

    def test_a_real_gps_tagged_photo_produces_a_real_kml_file_with_the_real_coordinates(self, tmp_path):
        photos_dir = str(tmp_path / "apple_export" / "Photos")
        os.makedirs(photos_dir, exist_ok=True)

        def exiftool_side_effect(cmd, **kw):
            return _exiftool_proc([{"GPSLatitude": 51.5074, "GPSLongitude": -0.1278, "FileName": "img1.jpg"}])

        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(photos_dir=photos_dir), exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        mock_run.assert_called_once()
        # The real exiftool command was built correctly - recursive, JSON,
        # numeric, scoped to the real GEO_IMAGE_EXTENSIONS list, targeting
        # the real photos_dir.
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "exiftool"
        assert "-r" in cmd
        assert photos_dir in cmd

        mock_tag.assert_called_once()
        kml_path = mock_tag.call_args[0][1]
        assert kml_path.endswith("apple_photos_location_history.kml")
        with open(kml_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "51.507400" in content or "51.5074" in content
        assert "1 GPS-tagged photo(s) exported" in job["log"]

    def test_no_gps_tagged_photos_writes_no_kml_file(self, tmp_path):
        photos_dir = str(tmp_path / "apple_export" / "Photos")
        os.makedirs(photos_dir, exist_ok=True)

        def exiftool_side_effect(cmd, **kw):
            return _exiftool_proc([{"FileName": "img1.jpg"}])  # no GPS tags

        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(photos_dir=photos_dir), exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_not_called()
        assert "No GPS-tagged photos found" in job["log"]

    def test_an_exiftool_timeout_is_treated_as_zero_gps_points_not_a_crash(self, tmp_path):
        import subprocess as real_subprocess
        photos_dir = str(tmp_path / "apple_export" / "Photos")
        os.makedirs(photos_dir, exist_ok=True)

        def exiftool_side_effect(cmd, **kw):
            raise real_subprocess.TimeoutExpired(cmd, 600)

        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(photos_dir=photos_dir), exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_not_called()
        assert "No GPS-tagged photos found" in job["log"]

    def test_an_exiftool_malformed_json_output_is_treated_as_zero_gps_points_not_a_crash(self, tmp_path):
        photos_dir = str(tmp_path / "apple_export" / "Photos")
        os.makedirs(photos_dir, exist_ok=True)

        def exiftool_side_effect(cmd, **kw):
            return types.SimpleNamespace(returncode=0, stdout="not valid json{{{", stderr="")

        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(photos_dir=photos_dir), exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_not_called()

    def test_warnings_from_import_apple_export_are_surfaced_in_the_log(self, tmp_path):
        job, mock_record, mock_tag, mock_run = self._run(
            tmp_path, import_result=_ok_result(warnings=["Safari bookmark parsing is best-effort."]),
        )
        assert "Safari bookmark parsing is best-effort." in job["log"]

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        # No explicit source_ip/user needed here - the exception happens
        # inside import_apple_export() itself, aborting the try block
        # before the worker's own final log_chain_of_custody() call is
        # ever reached.
        export_root = str(tmp_path / "apple_export")
        os.makedirs(export_root, exist_ok=True)
        with mock.patch.object(file_explorer, "import_apple_export", side_effect=RuntimeError("simulated failure")):
            file_explorer.execution_worker_import_apple_export(
                export_root, None, str(tmp_path), source_ip=None, user=None)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, side_effect in enumerate((None, RuntimeError("boom"))):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            export_root = str(iter_root / "apple_export")
            os.makedirs(export_root)
            if side_effect is None:
                with mock.patch.object(file_explorer, "import_apple_export", return_value=_ok_result()):
                    file_explorer.execution_worker_import_apple_export(
                        export_root, None, str(iter_root), source_ip="127.0.0.1", user="test-user")
            else:
                with mock.patch.object(file_explorer, "import_apple_export", side_effect=side_effect):
                    file_explorer.execution_worker_import_apple_export(
                        export_root, None, str(iter_root), source_ip="127.0.0.1", user="test-user")
            assert snapshot_job()["active"] is False
