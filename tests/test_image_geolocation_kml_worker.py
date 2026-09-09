"""routes/image_browser.py's execution_worker_image_geolocation_kml() - the
4th of 10 execution_worker_* functions found with zero pytest coverage
during a self-directed validation pass (2026-09-09) - see that dated
CLAUDE.md section for the discovery/scoping rationale.

Mocks the low-level pytsk3 boundary this worker walks through
(_tsk_resolve_filesystems/_tsk_open_fs/_tsk_walk/_tsk_stream_file, all
imported from core.tsk_utils into routes.image_browser's own namespace -
mocked there, not at their original definition site, matching this
project's own already-established "mock where the code actually looks it
up" discipline) rather than requiring pytsk3/a real disk image, plus the
genuine external boundaries (subprocess.run - the real exiftool call,
_auto_tag_case_artifact - a real per-case SQLite write already covered by
its own dedicated tests). _geo_points_from_exiftool_entries()/
_build_geo_kml() (core/geo_utils.py) run for REAL against the mocked
exiftool JSON output - both are pure functions with no I/O of their own,
so exercising them for real (and reading the actual written KML file's
content back) is a stronger test than mocking them away.

Matches the real production calling convention this project has already
been bitten by getting wrong in a test once before (see
test_case_bundle_export_worker.py's own docstring): the real route
(start_image_geolocation_kml()) always captures requester_ip/user in the
live request thread before spawning this worker, so its own unconditional
final log_chain_of_custody() call never falls back to reading request/g
outside a real Flask request - every test that reaches that line passes
explicit, non-None source_ip/user.

Skipped (not failed) on a non-POSIX dev machine: routes.image_browser
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.image_browser as image_browser
from core.jobs import snapshot_job


def _entry(name, is_dir=False, deleted=False, size=1000, inode="12"):
    return {"name": name, "inode": inode, "is_dir": is_dir, "deleted": deleted, "size": size}


def _exiftool_proc(stdout_json=None, returncode=0):
    stdout = json.dumps(stdout_json) if stdout_json is not None else ""
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


class TestExecutionWorkerImageGeolocationKml:
    def _run(self, tmp_path, filesystems=None, walk_entries=None, exiftool_side_effect=None,
              source_ip="127.0.0.1", user="test-user", snapshot_side_effect=None,
              open_fs_side_effect=None, stream_file_side_effect=None):
        image_path = str(tmp_path / "case_ITEM-01.dd")
        (tmp_path / "case_ITEM-01.dd").write_bytes(b"fake image bytes")
        dest_dir = str(tmp_path)
        walk_entries = walk_entries if walk_entries is not None else []
        filesystems = filesystems if filesystems is not None else [{"offset": 0, "label": "Whole Image"}]

        fake_fs = mock.MagicMock()
        fake_fs.open_meta.return_value = mock.MagicMock()

        def default_stream_file(tsk_file, write_fn, max_bytes=None):
            write_fn(b"fake jpeg bytes")
            return 15

        with mock.patch.object(image_browser, "_tsk_resolve_filesystems", return_value=filesystems), \
             mock.patch.object(image_browser, "_tsk_open_fs",
                                side_effect=open_fs_side_effect if open_fs_side_effect else (lambda p, o: fake_fs)), \
             mock.patch.object(image_browser, "_tsk_walk",
                                return_value=iter([(e, f"/{e['name']}") for e in walk_entries])), \
             mock.patch.object(image_browser, "_tsk_stream_file",
                                side_effect=stream_file_side_effect if stream_file_side_effect else default_stream_file), \
             mock.patch.object(image_browser, "_auto_tag_case_artifact") as mock_tag, \
             mock.patch("subprocess.run",
                         side_effect=exiftool_side_effect if exiftool_side_effect else lambda *a, **kw: _exiftool_proc()) as mock_run:
            if snapshot_side_effect is not None:
                with mock.patch.object(image_browser, "snapshot_job", side_effect=snapshot_side_effect):
                    image_browser.execution_worker_image_geolocation_kml(
                        image_path, dest_dir, source_ip=source_ip, user=user)
            else:
                image_browser.execution_worker_image_geolocation_kml(
                    image_path, dest_dir, source_ip=source_ip, user=user)

        return snapshot_job(), mock_tag, mock_run

    def test_no_recognized_filesystem_fails_cleanly(self, tmp_path):
        # Reached before log_chain_of_custody's own call site - no explicit
        # source_ip/user needed for this specific early-return path.
        job, mock_tag, mock_run = self._run(tmp_path, filesystems=[], source_ip=None, user=None)
        assert job["status"] == "Failed"
        assert "No recognized filesystem found" in job["log"]
        mock_tag.assert_not_called()
        mock_run.assert_not_called()

    def test_happy_path_finds_a_real_gps_tagged_photo_and_writes_a_real_kml_file(self, tmp_path):
        walk_entries = [_entry("photo1.jpg", inode="10")]

        def exiftool_side_effect(cmd, **kw):
            return _exiftool_proc([{"GPSLatitude": 37.7749, "GPSLongitude": -122.4194, "GPSAltitude": 10.0}])

        job, mock_tag, mock_run = self._run(tmp_path, walk_entries=walk_entries, exiftool_side_effect=exiftool_side_effect)
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        mock_tag.assert_called_once()
        kml_path = mock_tag.call_args[0][1]
        assert kml_path.endswith("_geolocation_export.kml")

        with open(kml_path, "r", encoding="utf-8") as f:
            kml_content = f.read()
        # The real coordinates genuinely made it into the real written file,
        # not just a mocked call assertion.
        assert "37.774900" in kml_content or "37.7749" in kml_content
        assert "-122.419400" in kml_content or "-122.4194" in kml_content
        assert "1 GPS-tagged point(s) found" in job["log"]

    def test_no_gps_tagged_photos_writes_no_kml_file(self, tmp_path):
        walk_entries = [_entry("photo1.jpg", inode="10")]

        def exiftool_side_effect(cmd, **kw):
            # A real photo with zero GPS tags - the dominant, normal case.
            return _exiftool_proc([{"FileName": "photo1.jpg"}])

        job, mock_tag, mock_run = self._run(tmp_path, walk_entries=walk_entries, exiftool_side_effect=exiftool_side_effect)
        assert job["status"] == "Completed Successfully"
        mock_tag.assert_not_called()
        assert "No GPS-tagged photos found - no KML file was written" in job["log"]

    def test_directories_deleted_files_and_non_image_extensions_are_never_candidates(self, tmp_path):
        walk_entries = [
            _entry("subdir", is_dir=True, inode="20"),
            _entry("deleted_photo.jpg", deleted=True, inode="21"),
            _entry("readme.txt", inode="22"),
            _entry("real_photo.jpeg", inode="23"),  # the only real candidate
        ]
        job, mock_tag, mock_run = self._run(tmp_path, walk_entries=walk_entries)
        assert job["status"] == "Completed Successfully"
        # exiftool was called exactly once - only for the one genuine candidate.
        assert mock_run.call_count == 1
        assert "Found 1 candidate photo(s)" in job["log"]

    def test_a_candidate_over_the_size_cap_is_skipped_without_ever_reading_it(self, tmp_path):
        oversized = image_browser.IMAGE_GEO_MAX_FILE_BYTES + 1
        walk_entries = [_entry("huge_raw.dng", size=oversized, inode="30")]
        job, mock_tag, mock_run = self._run(tmp_path, walk_entries=walk_entries)
        assert job["status"] == "Completed Successfully"
        mock_run.assert_not_called()  # never even attempted an exiftool call
        assert mock_tag.call_count == 0  # no GPS data, so no KML written either

    def test_an_exception_reading_one_candidate_does_not_crash_the_whole_scan(self, tmp_path):
        walk_entries = [_entry("bad.jpg", inode="40"), _entry("good.jpg", inode="41")]

        # First candidate's stream read raises; confirm the scan still
        # reaches and processes the second one.
        call_state = {"n": 0}

        def stream_side_effect(tsk_file, write_fn, max_bytes=None):
            call_state["n"] += 1
            if call_state["n"] == 1:
                raise OSError("simulated corrupt read")
            write_fn(b"ok bytes")
            return 8

        def exiftool_side_effect(cmd, **kw):
            return _exiftool_proc([{"GPSLatitude": 1.0, "GPSLongitude": 2.0}])

        job, mock_tag, mock_run = self._run(
            tmp_path, walk_entries=walk_entries, stream_file_side_effect=stream_side_effect,
            exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        # Only the second (good) candidate ever reached exiftool - the first
        # one's own exception was swallowed, per this worker's own "one
        # unreadable/corrupt candidate shouldn't fail the whole scan" comment.
        assert mock_run.call_count == 1
        mock_tag.assert_called_once()  # the good candidate's real GPS data still produced a KML

    def test_a_stop_during_candidate_collection_never_marks_the_job_completed(self, tmp_path):
        walk_entries = [_entry("photo1.jpg", inode="50")]

        def stopped_snapshot(*a, **kw):
            return {"status": "Stopped"}

        job, mock_tag, mock_run = self._run(
            tmp_path, walk_entries=walk_entries, snapshot_side_effect=stopped_snapshot,
        )
        assert job["status"] != "Completed Successfully"
        mock_run.assert_not_called()  # the collection loop itself broke before any candidate was even gathered

    def test_a_stop_during_the_exif_reading_loop_stops_partway_through(self, tmp_path):
        walk_entries = [_entry("photo1.jpg", inode="60"), _entry("photo2.jpg", inode="61")]
        real_snapshot = image_browser.snapshot_job
        call_count = {"n": 0}

        def stop_after_first_candidate(*a, **kw):
            call_count["n"] += 1
            # Call #1 is the collection loop's own once-per-filesystem check
            # (here: once); call #2 is the per-candidate check right before
            # photo1.jpg is processed - let both through cleanly, so the
            # first candidate genuinely gets its own real exiftool call; call
            # #3, checked right before photo2.jpg, is where the stop lands.
            if call_count["n"] <= 2:
                return real_snapshot()
            return {"status": "Stopped"}

        def exiftool_side_effect(cmd, **kw):
            return _exiftool_proc([{"GPSLatitude": 5.0, "GPSLongitude": 6.0}])

        job, mock_tag, mock_run = self._run(
            tmp_path, walk_entries=walk_entries, snapshot_side_effect=stop_after_first_candidate,
            exiftool_side_effect=exiftool_side_effect,
        )
        assert job["status"] != "Completed Successfully"
        assert "Scan stopped by user" in job["log"]
        # Exactly the first candidate was processed before the stop landed -
        # a genuinely partial run, not "stopped before starting" or "ran to
        # completion regardless."
        assert mock_run.call_count == 1
        # And its real GPS data still made it into a real, partial KML file.
        mock_tag.assert_called_once()

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        # Reached before log_chain_of_custody's own call site (the whole try
        # block is aborted by the raise) - no explicit source_ip/user needed.
        with mock.patch.object(image_browser, "_tsk_resolve_filesystems", side_effect=RuntimeError("simulated failure")):
            image_browser.execution_worker_image_geolocation_kml(
                str(tmp_path / "img.dd"), str(tmp_path), source_ip=None, user=None)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, filesystems in enumerate(([], [{"offset": 0, "label": "Whole Image"}])):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            job, mock_tag, mock_run = self._run(iter_root, filesystems=filesystems)
            assert snapshot_job()["active"] is False
