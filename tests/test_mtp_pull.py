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
(jmtpfs/cp) is verified live, not via mocks.

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
    def _run(self, tmp_path, mount_returncode=0, mount_ismount=True, copy_returncode=0, stopped_after_mount=False):
        output_path = str(tmp_path / "case" / "ITEM-01_mtp_pull")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(mobile, "reclaim_ownership"))
            stack.enter_context(mock.patch.object(mobile, "_write_report"))
            stack.enter_context(mock.patch("os.path.ismount", return_value=mount_ismount))
            mock_run = stack.enter_context(mock.patch("subprocess.run", return_value=_proc(mount_returncode)))
            mock_stream = stack.enter_context(mock.patch.object(mobile, "_stream_subprocess", return_value=_proc(copy_returncode)))
            if stopped_after_mount:
                # A Stop request landing between mount success and the copy
                # starting can't be reproduced by mutating real job state
                # from outside a synchronous call (the worker's own opening
                # update_job() would immediately overwrite it) - mocking the
                # worker's own snapshot_job() check directly is the clean
                # way to exercise this exact mid-run branch.
                stack.enter_context(mock.patch.object(mobile, "snapshot_job", return_value={"status": "Stopped"}))
            mobile.execution_worker_mtp_pull("1", "5", output_path, report_path, report_data)

        return snapshot_job(), report_data, mock_run, mock_stream

    def test_happy_path_mounts_copies_reclaims_and_unmounts(self, tmp_path):
        job, report_data, mock_run, mock_stream = self._run(tmp_path)
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        # subprocess.run is used for both the mount and the final umount -
        # confirm both actually happened, in the right order.
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert cmds[0][:2] == ["sudo", "/usr/bin/jmtpfs"]
        assert "-device=1,5" in cmds[0]
        assert cmds[-1][:2] == ["sudo", "/bin/umount"]
        # The copy itself went through _stream_subprocess (for its on_poll
        # progress mechanism), not a bare subprocess.run call.
        copy_cmd = mock_stream.call_args[0][0]
        assert copy_cmd[:3] == ["sudo", "/bin/cp", "-a"]

    def test_a_mount_failure_never_attempts_a_copy_and_reports_failed(self, tmp_path):
        job, report_data, mock_run, mock_stream = self._run(tmp_path, mount_returncode=1)
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        mock_stream.assert_not_called()

    def test_ismount_false_after_a_zero_returncode_is_still_treated_as_a_failure(self, tmp_path):
        # A defensive double-check, mirroring _f2fs_mount()'s own
        # os.path.ismount() verification - a "successful" mount command
        # that didn't actually produce a real mount must not be trusted.
        job, report_data, mock_run, mock_stream = self._run(tmp_path, mount_returncode=0, mount_ismount=False)
        assert job["status"] == "Failed"
        mock_stream.assert_not_called()

    def test_a_stop_request_right_after_mounting_never_attempts_a_copy_and_stays_in_progress(self, tmp_path):
        job, report_data, mock_run, mock_stream = self._run(tmp_path, stopped_after_mount=True)
        # Never falsely marked either Completed or Failed for a genuinely
        # stopped run - matches execution_worker_android()'s own identical
        # "stays IN_PROGRESS, not Failed" convention for a Stopped job.
        assert report_data["acquisition_status"] == "IN_PROGRESS"
        mock_stream.assert_not_called()
        # The mount is still unmounted even though the copy never ran -
        # cleanup must never depend on how far the run got.
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert any(cmd[:2] == ["sudo", "/bin/umount"] for cmd in cmds)

    def test_a_copy_failure_is_reported_and_still_unmounts(self, tmp_path):
        job, report_data, mock_run, mock_stream = self._run(tmp_path, copy_returncode=1)
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert any(cmd[:2] == ["sudo", "/bin/umount"] for cmd in cmds)
