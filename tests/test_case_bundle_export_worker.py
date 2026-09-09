"""routes/reporting.py's execution_worker_case_bundle_export() - zips a
whole case folder for archival/handoff (the Archive button's own backend,
see the dated "Case Bundle Export" section in CLAUDE.md).

The 3rd of 10 execution_worker_* functions found with zero pytest coverage
during a self-directed validation pass (2026-09-09) - see that dated
section for the discovery/scoping rationale. This file also locks in a
real, small bug fix found while reading this worker's own source in the
same pass: a Stopped run used to unconditionally report
progress_percent=100.0/transferred_bytes=total_size regardless of whether
the walk actually finished - now it reports the real partial totals when
genuinely stopped early.

Uses a REAL zipfile.ZipFile writing to a real tmp_path directory (matching
this project's own established "real filesystem beats mocking os.path.*
across multiple distinct paths" precedent, e.g. test_image_conversion_
worker.py) - the actual zip content is read back and verified, not just
the reported counts. Mocks only the genuine external/side-effect
boundaries: _auto_tag_case_artifact (a real per-case SQLite write, no need
to exercise that here - already covered by its own dedicated tests) and
snapshot_job (to force the Stopped path deterministically).

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import zipfile
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.reporting as reporting
from core.jobs import snapshot_job


class TestExecutionWorkerCaseBundleExport:
    def _seed_case(self, tmp_path):
        case_folder = tmp_path / "2026-TEST-BUNDLE"
        case_folder.mkdir()
        (case_folder / "notes.txt").write_text("real evidence notes")
        subdir = case_folder / "photos"
        subdir.mkdir()
        (subdir / "photo1.jpg").write_bytes(b"fake jpg bytes")
        (case_folder / "evidence.dd").write_bytes(b"raw image bytes")  # ATTACHMENT_EXCLUDE_EXT
        return case_folder

    def _run(self, case_folder, include_images=False, snapshot_side_effect=None):
        # Matches the real calling convention: start_case_bundle_export()
        # (the route) always captures requester_ip/requester_user in the
        # real request thread BEFORE spawning this worker as a background
        # daemon thread, specifically so its own log_chain_of_custody()
        # call at the end never falls back to reading request/g (which
        # don't exist outside a live Flask request) - the same capture-
        # before-spawn guard this project has already built for this exact
        # class of bug elsewhere. Passing explicit, non-None values here
        # mirrors that real production call shape.
        with mock.patch.object(reporting, "_auto_tag_case_artifact") as mock_tag:
            if snapshot_side_effect is not None:
                with mock.patch.object(reporting, "snapshot_job", side_effect=snapshot_side_effect):
                    reporting.execution_worker_case_bundle_export(
                        str(case_folder), include_images, requester_ip="127.0.0.1", requester_user="test-user")
            else:
                reporting.execution_worker_case_bundle_export(
                    str(case_folder), include_images, requester_ip="127.0.0.1", requester_user="test-user")
        return snapshot_job(), mock_tag

    def test_happy_path_zips_real_files_excluding_raw_images_by_default(self, tmp_path):
        case_folder = self._seed_case(tmp_path)
        job, mock_tag = self._run(case_folder, include_images=False)
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0

        # A real zip was actually written, and _auto_tag_case_artifact was
        # called with its real path.
        mock_tag.assert_called_once()
        zip_path = mock_tag.call_args[0][1]
        assert os.path.exists(zip_path)

        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
            assert "notes.txt" in names
            assert os.path.join("photos", "photo1.jpg") in names or "photos/photo1.jpg" in names
            # excluded: raw image extension, not requested
            assert "evidence.dd" not in names
            # the actual byte content genuinely round-trips, not just the name
            assert zf.read("notes.txt") == b"real evidence notes"

    def test_include_images_true_includes_the_raw_image_extension(self, tmp_path):
        case_folder = self._seed_case(tmp_path)
        job, mock_tag = self._run(case_folder, include_images=True)
        assert job["status"] == "Completed Successfully"
        zip_path = mock_tag.call_args[0][1]
        with zipfile.ZipFile(zip_path) as zf:
            assert "evidence.dd" in zf.namelist()

    def test_a_prior_bundle_zip_never_gets_zipped_into_the_new_one(self, tmp_path):
        # A real, previously-existing bundle export sitting in the case
        # folder (from an earlier run) must be excluded by the self_pattern
        # glob, not just the walk's own in-flight self-exclusion.
        case_folder = self._seed_case(tmp_path)
        stale_zip = case_folder / "2026-TEST-BUNDLE_case_bundle_20260101-000000.zip"
        stale_zip.write_bytes(b"a stale prior export, should never be re-bundled")
        job, mock_tag = self._run(case_folder, include_images=False)
        assert job["status"] == "Completed Successfully"
        zip_path = mock_tag.call_args[0][1]
        with zipfile.ZipFile(zip_path) as zf:
            assert stale_zip.name not in zf.namelist()

    def test_a_file_that_fails_to_write_is_counted_as_errored_not_written_and_does_not_crash_the_job(self, tmp_path):
        case_folder = self._seed_case(tmp_path)
        real_write = zipfile.ZipFile.write
        call_count = {"n": 0}

        def flaky_write(self_zf, filename, arcname=None, *a, **kw):
            call_count["n"] += 1
            if arcname == "notes.txt":
                raise OSError("simulated write failure")
            return real_write(self_zf, filename, arcname=arcname, *a, **kw)

        with mock.patch.object(zipfile.ZipFile, "write", flaky_write):
            job, mock_tag = self._run(case_folder, include_images=False)
        assert job["status"] == "Completed Successfully"
        zip_path = mock_tag.call_args[0][1]
        with zipfile.ZipFile(zip_path) as zf:
            # the other, non-failing file still made it in
            assert os.path.join("photos", "photo1.jpg") in zf.namelist() or "photos/photo1.jpg" in zf.namelist()
            assert "notes.txt" not in zf.namelist()

    def test_a_stopped_run_reports_the_real_partial_progress_not_a_false_100_percent(self, tmp_path):
        # The actual regression test for the 2026-09-09 fix: a Stopped run
        # used to unconditionally claim progress_percent=100.0/
        # transferred_bytes=total_size regardless of how much was actually
        # written before the stop. The worker checks snapshot_job() TWICE
        # for this - once inside the per-file loop (to decide whether to
        # break early) and once more right after the loop (to decide which
        # of the two progress-reporting branches to take) - both need to
        # see "Stopped" consistently, so the mock always returns it rather
        # than only on the first call.
        case_folder = self._seed_case(tmp_path)

        def always_stopped(*a, **kw):
            return {"status": "Stopped"}

        job, mock_tag = self._run(case_folder, include_images=False, snapshot_side_effect=always_stopped)
        assert job["status"] != "Completed Successfully"
        assert job["progress_percent"] < 100.0
        # Confirmed genuinely partial, not just "not 100" - the walk saw
        # candidates with a real nonzero total_size, so 0 bytes written
        # against that total is the correct, honest 0.0%.
        assert job["progress_percent"] == 0.0
        assert job["transferred_bytes"] == 0
        # The (partial) zip was still written and tagged, even though the
        # run was interrupted - a partial bundle is still real output.
        mock_tag.assert_called_once()

    def test_a_non_stopped_run_still_reports_the_full_100_percent(self, tmp_path):
        case_folder = self._seed_case(tmp_path)
        job, mock_tag = self._run(case_folder, include_images=False)
        assert job["progress_percent"] == 100.0
        assert job["transferred_bytes"] > 0

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        case_folder = self._seed_case(tmp_path)
        with mock.patch.object(reporting, "_auto_tag_case_artifact", side_effect=RuntimeError("simulated failure")):
            reporting.execution_worker_case_bundle_export(str(case_folder), False)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, side_effect in enumerate((None, RuntimeError("boom"))):
            # Each iteration needs its own real case folder - reusing the
            # same tmp_path across both would try to mkdir an
            # already-existing directory on the second pass.
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            case_folder = self._seed_case(iter_root)
            if side_effect is None:
                with mock.patch.object(reporting, "_auto_tag_case_artifact"):
                    reporting.execution_worker_case_bundle_export(
                        str(case_folder), False, requester_ip="127.0.0.1", requester_user="test-user")
            else:
                with mock.patch.object(reporting, "_auto_tag_case_artifact", side_effect=side_effect):
                    reporting.execution_worker_case_bundle_export(
                        str(case_folder), False, requester_ip="127.0.0.1", requester_user="test-user")
            assert snapshot_job()["active"] is False
