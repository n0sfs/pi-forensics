"""routes/acquisition.py's post-write integrity confirmation (2026-09-06) -
_fsync_confirm_write() and its wiring into execution_worker()/
execution_worker_aff(). A real, live-caught gap: a writing tool's own exit
code (and even its own self-reported hash, computed while streaming
before it closes its output file) doesn't guarantee the resulting bytes
have actually, durably landed on this station's own network-mounted
evidence storage - found via a real Android bugreport that reported full
success while the destination file silently truncated (see routes/
mobile.py's own dated fix and test_android_output_integrity.py). fsync()
on the output file, confirmed live to genuinely raise a real OSError when
the destination storage can't confirm a write, is the fix applied here to
this app's own main disk-imaging path (dc3dd/dcfldd/dd/E01/ddrescue/
plain_dd via execution_worker(), and the two-phase raw+AFF conversion via
execution_worker_aff()).

Extended the same day (once the "should this cover the many-files
acquisition paths too" question was explicitly resolved) with
TestLogicalAcquisitionWriteConfirmation and TestLiveCollectionImport
WriteConfirmation - both add the identical per-file _fsync_confirm_write()
call to their own already-existing shutil.copy2() copy loops, now
exercised against real tmp_path filesystems rather than fully mocked,
since neither worker shells out to any subprocess for its actual file
copy.

Skipped (not failed) on a non-POSIX dev machine: routes.acquisition needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.acquisition as acquisition
from core.jobs import snapshot_job


def _proc(returncode=0):
    return types.SimpleNamespace(returncode=returncode)


class TestFsyncConfirmWrite:
    def test_a_real_genuine_file_confirms_cleanly(self, tmp_path):
        path = tmp_path / "output.dd"
        path.write_bytes(b"real acquired content")
        ok, error = acquisition._fsync_confirm_write(str(path))
        assert ok is True
        assert error is None

    def test_fsync_raising_is_reported_as_a_real_write_failure_not_raised(self, tmp_path):
        path = tmp_path / "output.dd"
        path.write_bytes(b"content")
        with mock.patch("os.fsync", side_effect=OSError(5, "Input/output error")):
            ok, error = acquisition._fsync_confirm_write(str(path))
        assert ok is False
        assert "could not confirm" in error

    def test_a_missing_file_is_reported_as_a_failure_not_raised(self, tmp_path):
        ok, error = acquisition._fsync_confirm_write(str(tmp_path / "does_not_exist.dd"))
        assert ok is False
        assert "could not open" in error

    def test_works_on_a_read_only_file_descriptor(self, tmp_path):
        # Confirmed live on the real deployed station before this was
        # written - fsync flushes dirty pages associated with the file's
        # own inode regardless of which fd's writes produced them, so a
        # read-only open (never needing write access to the file) is
        # sufficient. This test proves the implementation genuinely opens
        # read-only, not that it happens to work by opening read-write.
        path = tmp_path / "output.dd"
        path.write_bytes(b"content")
        real_open = os.open

        def spy_open(p, flags, *a, **kw):
            assert flags == os.O_RDONLY, "must open read-only, never needs write access"
            return real_open(p, flags, *a, **kw)

        with mock.patch("os.open", side_effect=spy_open):
            ok, error = acquisition._fsync_confirm_write(str(path))
        assert ok is True


class TestExecutionWorkerWriteConfirmation:
    def _run(self, tmp_path, proc_returncode=0, write_confirmed=True, fmt="plain_dd"):
        out_file = str(tmp_path / "case_ITEM-01.dd")
        with open(out_file, "wb") as f:
            f.write(b"acquired content")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        with mock.patch.object(acquisition, "_stream_subprocess", return_value=_proc(proc_returncode)), \
             mock.patch.object(acquisition, "reclaim_ownership"), \
             mock.patch.object(acquisition, "_write_report"), \
             mock.patch.object(
                 acquisition, "_fsync_confirm_write",
                 return_value=(write_confirmed, None if write_confirmed else "the destination storage could not confirm this file's write completed"),
             ) as mock_fsync:
            acquisition.execution_worker(["fake", "cmd"], fmt, 1000, out_file, report_path, report_data, hashes=["sha256"])

        return report_data, mock_fsync

    def test_genuine_success_with_a_confirmed_write_reports_completed(self, tmp_path):
        report_data, mock_fsync = self._run(tmp_path, proc_returncode=0, write_confirmed=True)
        assert report_data["acquisition_status"] == "COMPLETED"
        mock_fsync.assert_called_once()

    def test_the_tool_reporting_success_but_the_write_not_confirmed_is_reported_failed(self, tmp_path):
        # The exact real-world scenario this fix exists for: the
        # acquisition tool itself exits cleanly (returncode 0), but the
        # resulting file's write to network-mounted evidence storage could
        # not be confirmed - this must NEVER be reported as a genuine
        # success, unlike the previous behavior which trusted returncode
        # alone.
        report_data, mock_fsync = self._run(tmp_path, proc_returncode=0, write_confirmed=False)
        assert report_data["acquisition_status"] == "FAILED"

    def test_a_genuine_tool_failure_is_still_reported_failed_regardless_of_write_confirmation(self, tmp_path):
        report_data, mock_fsync = self._run(tmp_path, proc_returncode=1, write_confirmed=True)
        assert report_data["acquisition_status"] == "FAILED"


class TestExecutionWorkerAffWriteConfirmation:
    def _run(self, tmp_path, phase1_returncode=0, phase2_returncode=0,
             phase1_write_confirmed=True, phase2_write_confirmed=True, aff_file_exists=True):
        dest_path = str(tmp_path)
        base_name = "case_ITEM-01"
        raw_file = os.path.join(dest_path, f"{base_name}.raw")
        aff_file = os.path.join(dest_path, f"{base_name}.aff")
        dc3dd_log_file = os.path.join(dest_path, f"{base_name}_dc3dd.log")

        # execution_worker_aff computes these paths itself from dest_path/
        # base_name - pre-create the files it'll try to read/confirm so a
        # real os.path.exists()/open() call sees genuine content.
        with open(raw_file, "wb") as f:
            f.write(b"raw acquired content")
        with open(dc3dd_log_file, "w") as f:
            f.write("")
        if aff_file_exists:
            with open(aff_file, "wb") as f:
                f.write(b"converted aff content")

        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        def fsync_side_effect(path):
            if path == raw_file:
                return (phase1_write_confirmed, None if phase1_write_confirmed else "phase 1 write not confirmed")
            return (phase2_write_confirmed, None if phase2_write_confirmed else "phase 2 write not confirmed")

        with mock.patch.object(acquisition, "_stream_subprocess",
                                side_effect=[_proc(phase1_returncode), _proc(phase2_returncode)]), \
             mock.patch.object(acquisition, "reclaim_ownership"), \
             mock.patch.object(acquisition, "_write_report"), \
             mock.patch.object(acquisition, "parse_dc3dd_hashes", return_value={"sha256": "deadbeef"}), \
             mock.patch.object(acquisition, "_fsync_confirm_write", side_effect=fsync_side_effect):
            acquisition.execution_worker_aff(
                "/dev/fake", dest_path, base_name, ["sha256"], keep_raw=True,
                report_file_path=report_path, report_data=report_data, total_bytes=1000,
            )

        return report_data

    def test_genuine_success_both_phases_confirmed_reports_completed(self, tmp_path):
        report_data = self._run(tmp_path, phase1_write_confirmed=True, phase2_write_confirmed=True)
        assert report_data["acquisition_status"] == "COMPLETED"

    def test_phase1_raw_write_not_confirmed_stops_before_phase2_and_reports_failed(self, tmp_path):
        # The real, most-consequential case: if the raw acquisition itself
        # can't be confirmed as durably written, phase 2 (converting it to
        # AFF) must never even attempt to read it as if it were trustworthy.
        report_data = self._run(tmp_path, phase1_write_confirmed=False)
        assert report_data["acquisition_status"] == "FAILED"
        # computed_verification_hashes must never be set from a raw file
        # that was never confirmed as genuinely, durably written - proves
        # the function returned early, before ever reaching phase 2's own
        # hash-reading step.
        assert "computed_verification_hashes" not in report_data

    def test_phase2_aff_write_not_confirmed_reports_failed_not_completed(self, tmp_path):
        # dc3dd/affconvert both genuinely succeed, but the final .aff
        # file's own write to the destination can't be confirmed - the
        # real scenario this fix exists for at the AFF-conversion layer.
        report_data = self._run(tmp_path, phase1_write_confirmed=True, phase2_write_confirmed=False)
        assert report_data["acquisition_status"] == "FAILED"


class TestLogicalAcquisitionWriteConfirmation:
    """execution_worker_logical_acquisition()'s per-file copy loop
    (2026-09-06) - unlike execution_worker()/execution_worker_aff(), this
    never shells out to a subprocess for the actual copy (a plain
    shutil.copy2() per selected file), so this is exercised against a
    genuine tmp_path filesystem rather than fully mocked - only
    _fsync_confirm_write itself is mocked, to simulate a destination-
    storage failure for one specific file without needing a real broken
    NFS mount to reproduce it."""

    def _run(self, tmp_path, fail_on_filename=None):
        src_dir = tmp_path / "source_folder"
        src_dir.mkdir()
        (src_dir / "file1.txt").write_bytes(b"real content one")
        (src_dir / "file2.txt").write_bytes(b"real content two")
        output_root = str(tmp_path / "logical_out")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        real_fsync_confirm = acquisition._fsync_confirm_write

        def fake_fsync_confirm(path):
            if fail_on_filename and path.endswith(fail_on_filename):
                return False, "simulated destination storage failure"
            return real_fsync_confirm(path)

        with mock.patch.object(acquisition, "_fsync_confirm_write", side_effect=fake_fsync_confirm), \
             mock.patch.object(acquisition, "_write_report"):
            acquisition.execution_worker_logical_acquisition(
                [str(src_dir)], output_root, ["sha256"], make_zip=False,
                report_file_path=report_path, report_data=report_data,
            )
        return report_data

    def test_a_genuinely_clean_copy_of_every_file_reports_completed(self, tmp_path):
        report_data = self._run(tmp_path, fail_on_filename=None)
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["file_count"] == 2

    def test_one_file_failing_write_confirmation_is_counted_as_an_error_not_silently_included(self, tmp_path):
        # The real point: a copy that "succeeded" per shutil.copy2() but
        # whose write couldn't be durably confirmed must be excluded from
        # the manifest exactly like any other copy failure - proving the
        # new fsync-confirm call is wired into the SAME error-counting
        # path the loop's own except block already had, not a silent,
        # separate success. files_errored isn't itself propagated into
        # report_data["acquisition_parameters"] by this worker (only
        # file_count/total_bytes/truncated are) - file_count staying at 1
        # instead of 2 is the real proof the failed file was excluded.
        report_data = self._run(tmp_path, fail_on_filename="file1.txt")
        assert report_data["acquisition_parameters"]["file_count"] == 1
        # Still reports overall success - one real file was genuinely,
        # confirmedly copied, matching this worker's own pre-existing
        # "not every file failed" tolerance.
        assert report_data["acquisition_status"] == "COMPLETED"

    def test_every_file_failing_write_confirmation_reports_failed(self, tmp_path):
        src_dir = tmp_path / "source_folder"
        src_dir.mkdir()
        (src_dir / "only_file.txt").write_bytes(b"content")
        output_root = str(tmp_path / "logical_out")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        with mock.patch.object(acquisition, "_fsync_confirm_write", return_value=(False, "simulated failure")), \
             mock.patch.object(acquisition, "_write_report"):
            acquisition.execution_worker_logical_acquisition(
                [str(src_dir)], output_root, ["sha256"], make_zip=False,
                report_file_path=report_path, report_data=report_data,
            )
        assert report_data["acquisition_status"] == "FAILED"


class TestLiveCollectionImportWriteConfirmation:
    """execution_worker_import_live_collection()'s per-file copy loop
    (2026-09-06) - the same fix as Logical Acquisition's identical loop
    above, applied to the worker that already surfaced real NFS write
    failures live during earlier session testing (two real autoruns.json
    files this station's own NAS couldn't durably write during a real
    import). Everything around the copy loop (mounting the USB, re-
    discovering result runs, parsing/hash-list cross-referencing) is
    mocked to isolate just the copy-loop behavior; the copy itself runs
    against a genuine tmp_path filesystem."""

    def _run(self, tmp_path, fail_on_filename=None):
        fake_mountpoint = tmp_path / "fake_usb_mount"
        run_src = fake_mountpoint / "windows" / "uac-20260906_120000"
        run_src.mkdir(parents=True)
        (run_src / "processes.json").write_bytes(b'{"real": "data"}')
        (run_src / "network.json").write_bytes(b'{"real": "data"}')

        case_folder = str(tmp_path / "case_folder")
        os.makedirs(case_folder, exist_ok=True)
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        run_info = {"platform": "windows", "run_name": "uac-20260906_120000",
                    "relative_path": "windows/uac-20260906_120000", "timestamp": "20260906_120000"}

        real_fsync_confirm = acquisition._fsync_confirm_write

        def fake_fsync_confirm(path):
            if fail_on_filename and path.endswith(fail_on_filename):
                return False, "simulated destination storage failure"
            return real_fsync_confirm(path)

        with mock.patch.object(acquisition, "LIVE_COLLECTION_IMPORT_MOUNTPOINT", str(fake_mountpoint)), \
             mock.patch.object(acquisition, "mount_collection_partition", return_value={"success": True}), \
             mock.patch.object(acquisition, "unmount_collection_partition", return_value={"success": True}), \
             mock.patch.object(acquisition, "discover_collection_runs", return_value=[run_info]), \
             mock.patch.object(acquisition, "run_timestamp_to_epoch", return_value=1799000000.0), \
             mock.patch.object(acquisition, "parse_windows_collector_run", return_value=[]), \
             mock.patch.object(acquisition, "get_hash_lists", return_value=[]), \
             mock.patch.object(acquisition, "load_hash_list_sets", return_value={}), \
             mock.patch.object(acquisition, "_record_parsed_artifacts", return_value=0), \
             mock.patch.object(acquisition, "_fsync_confirm_write", side_effect=fake_fsync_confirm), \
             mock.patch.object(acquisition, "_write_report"):
            acquisition.execution_worker_import_live_collection(
                "/dev/sdz", ["windows/uac-20260906_120000"], case_folder, ["sha256"],
                report_file_path=report_path, report_data=report_data,
            )
        return report_data

    def test_a_genuinely_clean_import_of_every_file_reports_completed(self, tmp_path):
        report_data = self._run(tmp_path, fail_on_filename=None)
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["file_count"] == 2

    def test_one_file_failing_write_confirmation_is_counted_as_an_error(self, tmp_path):
        # Mirrors the real, already-observed live failure mode exactly
        # (autoruns.json specifically, though the mechanism applies to any
        # file in the run). files_errored isn't itself propagated into
        # report_data["acquisition_parameters"] by this worker (only
        # file_count/total_bytes are) - checked via the completion log
        # line instead, which does report both counts.
        report_data = self._run(tmp_path, fail_on_filename="processes.json")
        assert report_data["acquisition_parameters"]["file_count"] == 1
        assert report_data["acquisition_status"] == "COMPLETED"
        assert "1 file(s) captured, 1 error(s)" in snapshot_job()["log"]
