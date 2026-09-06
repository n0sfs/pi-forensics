"""routes/mobile.py's MTP fallback acquisition (2026-09-05) -
_parse_jmtpfs_device_list()'s real jmtpfs -l output-format parsing, and
execution_worker_mtp_pull()'s mount/copy/unmount control flow.

Mirrors this project's own established mock-the-real-subprocess-work
pattern (test_f2fs_mount_routes.py, test_extundelete_error_messages.py,
the android_companion_*_worker test files) - the mount/copy/unmount
sequence's own control-flow correctness (never attempting a copy after a
failed mount, always cleaning up the staging mount regardless of outcome,
never falsely reporting a Stopped run as either Completed or Failed) is
what's worth locking in with mocked tests here, matching this project's
already-disclosed precedent that the underlying tools' own real behavior
(jmtpfs) is verified live, not via mocks.

Rewritten 2026-09-06 after a real Android device connected for the first
time surfaced two real bugs in the original `sudo cp -a` implementation:
(1) `-a`'s ownership-preservation is meaningless for MTP (jmtpfs presents
a synthesized root:root owner, and NFS won't let root chown to it anyway)
and printed a spurious "Operation not permitted" line for every single
file copied; (2) `cp`'s own aggregate exit code treats ANY per-file I/O
error (a real, observed risk on this station's own NFS-backed evidence
store under load - confirmed live via dmesg showing genuine
"server ... not responding" stalls at the exact moments several files
failed) as total failure, which misreported a pull that had already
captured hundreds of real files as a flat FAILED with nothing usable.
The fix rewrote the copy as a per-file Python walk (os.walk + shutil.
copy2), mirroring Logical Acquisition's/Live Collection Import's own
established files_copied/files_errored per-file tracking pattern instead
of trusting one subprocess's exit code - confirmed live afterward: a real
run against the same device correctly reported files_copied=175,
files_errored=27, acquisition_status="STOPPED" (not FAILED) for a run
manually stopped mid-way, with zero ownership-preserve noise anywhere in
the log. The tests below lock in that same behavior with mocks.

Skipped (not failed) on a non-POSIX dev machine: routes.mobile needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import contextlib
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile
from core.jobs import snapshot_job


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestParseJmtpfsDeviceList:
    def test_parses_a_real_confirmed_output_line(self):
        stdout = "1, 5, 0x4ee1, 0x18d1, Pixel 8a, Google\n"
        devices = mobile._parse_jmtpfs_device_list(stdout)
        assert devices == [{
            "bus": "1", "devnum": "5",
            "product_id": "0x4ee1", "vendor_id": "0x18d1",
            "product": "Pixel 8a", "vendor": "Google",
        }]

    def test_parses_multiple_devices(self):
        stdout = "1, 5, 0x4ee1, 0x18d1, Pixel 8a, Google\n3, 2, 0x0001, 0x0002, Some Phone, Some Vendor\n"
        devices = mobile._parse_jmtpfs_device_list(stdout)
        assert len(devices) == 2
        assert devices[0]["bus"] == "1"
        assert devices[1]["bus"] == "3"

    def test_empty_output_is_an_empty_list_not_an_error(self):
        assert mobile._parse_jmtpfs_device_list("") == []
        assert mobile._parse_jmtpfs_device_list(None) == []

    def test_a_malformed_line_is_skipped_not_raised(self):
        stdout = "this is not a real device line\n1, 5, 0x4ee1, 0x18d1, Pixel 8a, Google\n"
        devices = mobile._parse_jmtpfs_device_list(stdout)
        assert len(devices) == 1
        assert devices[0]["bus"] == "1"

    def test_a_non_numeric_bus_or_devnum_is_rejected(self):
        stdout = "not-a-number, 5, 0x4ee1, 0x18d1, Pixel 8a, Google\n"
        assert mobile._parse_jmtpfs_device_list(stdout) == []


class TestExecutionWorkerMtpPull:
    def _run(self, tmp_path, mount_returncode=0, mount_ismount=True,
             walk_files=None, copy_side_effect=None, snapshot_side_effect=None):
        output_path = str(tmp_path / "case" / "ITEM-01_mtp_pull")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        if walk_files is None:
            walk_files = ["file1.jpg", "file2.jpg"]

        def fake_walk(path):
            # One flat directory containing walk_files - enough to exercise
            # the real relpath/dest-path construction without needing a
            # genuine nested tree.
            return [(path, [], walk_files)]

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(mobile, "reclaim_ownership"))
            mock_write_report = stack.enter_context(mock.patch.object(mobile, "_write_report"))
            stack.enter_context(mock.patch("os.path.ismount", return_value=mount_ismount))
            mock_run = stack.enter_context(mock.patch("subprocess.run", return_value=_proc(mount_returncode)))
            stack.enter_context(mock.patch("os.walk", side_effect=fake_walk))
            stack.enter_context(mock.patch("os.makedirs"))
            stack.enter_context(mock.patch("os.path.getsize", return_value=1024))
            mock_copy = stack.enter_context(mock.patch.object(mobile.shutil, "copy2", side_effect=copy_side_effect))
            if snapshot_side_effect is not None:
                stack.enter_context(mock.patch.object(mobile, "snapshot_job", side_effect=snapshot_side_effect))
            mobile.execution_worker_mtp_pull("1", "5", output_path, report_path, report_data)

        return snapshot_job(), report_data, mock_run, mock_copy, mock_write_report

    def test_happy_path_all_files_copy_and_the_report_reflects_it(self, tmp_path):
        job, report_data, mock_run, mock_copy, mock_write_report = self._run(tmp_path, walk_files=["a.jpg", "b.jpg"])
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["files_copied"] == 2
        assert report_data["acquisition_parameters"]["files_errored"] == 0
        # subprocess.run is used for both the mount and the final umount -
        # confirm both actually happened, in the right order. Copying
        # itself never shells out - it's a plain unprivileged Python walk
        # (os.walk + shutil.copy2), not a second subprocess.
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert cmds[0][:2] == ["sudo", "/usr/bin/jmtpfs"]
        assert "-device=1,5" in cmds[0]
        assert cmds[-1][:2] == ["sudo", "/bin/umount"]
        assert mock_copy.call_count == 2

    def test_a_mount_failure_never_attempts_a_copy_and_reports_failed(self, tmp_path):
        job, report_data, mock_run, mock_copy, mock_write_report = self._run(tmp_path, mount_returncode=1)
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        mock_copy.assert_not_called()

    def test_ismount_false_after_a_zero_returncode_is_still_treated_as_a_failure(self, tmp_path):
        # A defensive double-check, mirroring _f2fs_mount()'s own
        # os.path.ismount() verification - a "successful" mount command
        # that didn't actually produce a real mount must not be trusted.
        job, report_data, mock_run, mock_copy, mock_write_report = self._run(tmp_path, mount_returncode=0, mount_ismount=False)
        assert job["status"] == "Failed"
        mock_copy.assert_not_called()

    def test_a_stop_request_right_after_mounting_never_attempts_a_copy_and_stays_in_progress(self, tmp_path):
        job, report_data, mock_run, mock_copy, mock_write_report = self._run(
            tmp_path, snapshot_side_effect=[{"status": "Stopped"}]
        )
        # Never falsely marked either Completed or Failed for a genuinely
        # stopped run - matches execution_worker_android()'s own identical
        # "stays IN_PROGRESS, not Failed" convention for a Stopped job.
        assert report_data["acquisition_status"] == "IN_PROGRESS"
        mock_copy.assert_not_called()
        # The mount is still unmounted even though the copy never ran -
        # cleanup must never depend on how far the run got.
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert any(cmd[:2] == ["sudo", "/bin/umount"] for cmd in cmds)

    def test_some_files_failing_to_copy_still_reports_completed_with_an_honest_error_count(self, tmp_path):
        # The real, live-caught bug this rewrite fixes: a `cp -a`-based
        # copy would have treated any single per-file I/O error as total
        # job failure, even with hundreds of real files already captured.
        # Real confirmed behavior instead: some real per-file errors
        # (matching genuine NFS-write stalls observed live) must never
        # mask the files that DID copy successfully.
        def copy_side_effect(src, dst):
            if "bad" in src:
                raise OSError(5, "Input/output error")

        job, report_data, mock_run, mock_copy, mock_write_report = self._run(
            tmp_path, walk_files=["good1.jpg", "bad1.jpg", "good2.jpg", "bad2.jpg", "good3.jpg"],
            copy_side_effect=copy_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["files_copied"] == 3
        assert report_data["acquisition_parameters"]["files_errored"] == 2

    def test_every_file_failing_to_copy_is_reported_as_failed(self, tmp_path):
        def copy_side_effect(src, dst):
            raise OSError(5, "Input/output error")

        job, report_data, mock_run, mock_copy, mock_write_report = self._run(
            tmp_path, walk_files=["a.jpg", "b.jpg", "c.jpg"], copy_side_effect=copy_side_effect
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert report_data["acquisition_parameters"]["files_copied"] == 0
        assert report_data["acquisition_parameters"]["files_errored"] == 3

    def test_a_stop_mid_copy_still_records_the_partial_tally_and_reports_stopped(self, tmp_path):
        # snapshot_job is checked once right after mounting, once per loop
        # iteration, and once more in the final status-branch check after
        # the loop breaks - allow the first file through, then stop before
        # the second one is attempted, then stay Stopped for that final
        # check too.
        job, report_data, mock_run, mock_copy, mock_write_report = self._run(
            tmp_path, walk_files=["a.jpg", "b.jpg", "c.jpg"],
            snapshot_side_effect=[
                {"status": "Running"},  # check right after mount succeeds
                {"status": "Running"},  # loop i=0 - a.jpg copies
                {"status": "Stopped"},  # loop i=1 - stop before b.jpg
                {"status": "Stopped"},  # final status-branch check
            ],
        )
        assert report_data["acquisition_status"] == "STOPPED"
        assert report_data["acquisition_parameters"]["files_copied"] == 1
        assert report_data["acquisition_parameters"]["files_errored"] == 0
        assert mock_copy.call_count == 1
        # The real bonus fix this rewrite made: the previous implementation
        # never wrote any report update at all on a Stop (neither branch of
        # its old if/elif executed), silently leaving the report frozen at
        # its initial IN_PROGRESS state forever. The new code always writes
        # a report, even on Stop - confirmed here via the mocked
        # _write_report actually being called.
        mock_write_report.assert_called_once()
