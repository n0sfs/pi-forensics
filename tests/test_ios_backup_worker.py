"""routes/mobile.py's execution_worker_ios_backup() - the 7th of 10
execution_worker_* functions found with zero pytest coverage during a
self-directed validation pass (2026-09-09) - see that dated CLAUDE.md
section for the discovery/scoping rationale.

Mocks the genuine external boundary (_stream_subprocess - the real
idevicebackup2 process this app has no real iOS device to run against,
per this project's own already-disclosed, longstanding gap: it has never
had a real iOS device connect at any point in its history), plus
clear_active_proc. Lets poll_directory_size() and _write_report() run for
REAL against a real tmp_path directory/file - both are cheap, pure
filesystem operations with no external dependency of their own, so
exercising them for real (real backup-folder content, a real report JSON
read back off disk) is a stronger test than mocking them away.

report_data is a plain mutable dict passed IN by the caller (built by the
route before spawning the worker, not by the worker itself) - each test
builds its own fresh dict and inspects its mutated state after the call,
matching test_android_physical_worker.py's own established pattern for
this exact calling shape.

Skipped (not failed) on a non-POSIX dev machine: routes.mobile needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile
from core.jobs import snapshot_job


def _proc(returncode=0):
    return types.SimpleNamespace(returncode=returncode)


def _enc_proc(returncode=0, output=""):
    return types.SimpleNamespace(returncode=returncode, stdout=output, stderr="")


class TestExecutionWorkerIosBackup:
    def _run(self, tmp_path, encrypt_password=None, backup_returncode=0, create_backup_dir=True,
              stream_side_effect=None, enc_side_effect=None, snapshot_side_effect=None,
              udid="00008030-000000000000000E"):
        dest_dir = str(tmp_path)
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        def default_stream_side_effect(cmd, on_line, **kw):
            udid_backup_dir = os.path.join(dest_dir, udid)
            if create_backup_dir:
                os.makedirs(udid_backup_dir, exist_ok=True)
                with open(os.path.join(udid_backup_dir, "Manifest.plist"), "wb") as f:
                    f.write(b"real backup bytes")
            if "on_poll" in kw and kw["on_poll"]:
                kw["on_poll"]()
            return _proc(backup_returncode)

        with mock.patch.object(mobile, "_stream_subprocess",
                                side_effect=stream_side_effect if stream_side_effect else default_stream_side_effect) as mock_stream, \
             mock.patch.object(mobile, "clear_active_proc") as mock_clear, \
             mock.patch("time.sleep"), \
             mock.patch("subprocess.run",
                         side_effect=enc_side_effect if enc_side_effect else lambda *a, **kw: _enc_proc()) as mock_enc:
            if snapshot_side_effect is not None:
                with mock.patch.object(mobile, "snapshot_job", side_effect=snapshot_side_effect):
                    mobile.execution_worker_ios_backup(udid, dest_dir, encrypt_password, report_path, report_data)
            else:
                mobile.execution_worker_ios_backup(udid, dest_dir, encrypt_password, report_path, report_data)

        return snapshot_job(), report_data, mock_stream, mock_clear, mock_enc, report_path

    def test_happy_path_with_no_encryption_completes_and_writes_a_real_report_json(self, tmp_path):
        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(tmp_path)
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["output_size_bytes"] > 0  # the real "Manifest.plist" bytes were actually counted
        assert "execution_time_seconds" in report_data
        mock_enc.assert_not_called()  # no encryption requested - never touched idevicebackup2 encryption

        with open(report_path, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["acquisition_status"] == "COMPLETED"
        assert written["output_size_bytes"] == report_data["output_size_bytes"]

    def test_a_nonzero_returncode_with_the_backup_dir_missing_is_reported_as_failed(self, tmp_path):
        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, backup_returncode=1, create_backup_dir=False,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert "idevicebackup2 exited with code 1" in job["log"]

    def test_returncode_zero_but_the_backup_dir_never_appearing_is_still_reported_as_failed(self, tmp_path):
        # A real, deliberate double-check this worker makes: a "successful"
        # exit code alone is never trusted, the backup folder must actually
        # exist on disk too - matches this app's own established "never
        # trust an exit code alone" posture used elsewhere.
        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, backup_returncode=0, create_backup_dir=False,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"

    def test_a_stopped_run_is_never_falsely_marked_completed_or_failed(self, tmp_path):
        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, backup_returncode=1, create_backup_dir=False,
            snapshot_side_effect=[{"status": "Stopped"}],
        )
        assert report_data["acquisition_status"] == "IN_PROGRESS"
        # _write_report still runs unconditionally right after the if/elif -
        # a Stopped run's report isn't silently left unwritten.
        with open(report_path, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["acquisition_status"] == "IN_PROGRESS"

    def test_encryption_enabled_successfully_proceeds_to_the_normal_backup(self, tmp_path):
        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, encrypt_password="hunter2",
        )
        assert job["status"] == "Completed Successfully"
        mock_enc.assert_called_once()
        enc_cmd = mock_enc.call_args[0][0]
        assert enc_cmd == ["idevicebackup2", "-u", mock.ANY, "encryption", "on", "hunter2"]
        mock_stream.assert_called_once()  # the real backup itself still ran

    def test_encryption_already_enabled_is_not_treated_as_a_failure(self, tmp_path):
        # A nonzero returncode whose own output text says "already"/
        # "enabled" is a real, deliberate exception to "trust the exit
        # code" - idevicebackup2's own way of saying encryption is already
        # on, not a genuine failure.
        def enc_side_effect(cmd, **kw):
            return _enc_proc(returncode=1, output="Backup encryption is already enabled.")

        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, encrypt_password="hunter2", enc_side_effect=enc_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        mock_stream.assert_called_once()

    def test_encryption_genuinely_failing_stops_before_ever_attempting_the_backup(self, tmp_path):
        def enc_side_effect(cmd, **kw):
            return _enc_proc(returncode=1, output="Could not connect to lockdownd.")

        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, encrypt_password="hunter2", enc_side_effect=enc_side_effect,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert "execution_time_seconds" in report_data
        mock_stream.assert_not_called()  # never even attempted the real backup
        with open(report_path, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["acquisition_status"] == "FAILED"

    def test_encryption_timing_out_is_reported_as_failed_and_never_attempts_the_backup(self, tmp_path):
        import subprocess as real_subprocess

        def enc_side_effect(cmd, **kw):
            raise real_subprocess.TimeoutExpired(cmd, 90)

        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, encrypt_password="hunter2", enc_side_effect=enc_side_effect,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert "Timed out waiting for encryption confirmation" in job["log"]
        mock_stream.assert_not_called()

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        def stream_side_effect(*a, **kw):
            raise RuntimeError("simulated failure")

        job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
            tmp_path, stream_side_effect=stream_side_effect,
        )
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_runs_regardless_of_outcome(self, tmp_path):
        for i, (backup_returncode, create_dir) in enumerate(((0, True), (1, False))):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            job, report_data, mock_stream, mock_clear, mock_enc, report_path = self._run(
                iter_root, backup_returncode=backup_returncode, create_backup_dir=create_dir,
            )
            assert snapshot_job()["active"] is False
            mock_clear.assert_called_once()
