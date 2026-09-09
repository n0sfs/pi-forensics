"""routes/mobile.py's execution_worker_android_physical() (2026-08-30,
v1.5.0) - Physical/raw Android acquisition for an already-rooted device,
piping `adb exec-out su -c dd` into this app's existing dc3dd/dcfldd
engine via core/jobs.py's _stream_piped_subprocess().

This feature shipped with zero pytest coverage at the time - its core
correctness claims (the two-process pipe mechanism itself, dc3dd/dcfldd
correctly reading a real Unix pipe) were verified via a live dry-run
script against the deployed station instead, per the original commit's
own honest accounting (b25d996) - and no real rooted Android device has
ever been available to exercise the on-device commands end to end. That
gap is disclosed, not silently closed by this file. What genuinely IS
worth locking in with mocked tests, matching this project's own
established mock-the-real-subprocess-work pattern (test_mtp_pull.py,
test_f2fs_mount_routes.py, the android_companion_*_worker files), is this
worker's own CONTROL FLOW around _stream_piped_subprocess() - which this
project's own precedent (see test_mtp_pull.py's docstring) deliberately
mocks as a whole rather than reaching for real subprocess.Popen pipe
mocking, since a mocked Popen would mostly just test the mock.

Mocks _stream_piped_subprocess itself (not its own internal Popen calls -
that mechanism's real correctness is the live-dry-run-verified part, per
the disclosed gap above), plus the imported dc3dd/dcfldd parsing
functions (parse_dc3dd_line/parse_dc3dd_hashes/read_hash_log_file) at
their actual resolved location - routes.mobile's own module namespace,
since `from routes.acquisition import ...` creates an independent
binding there, the same "mock where the code actually looks it up"
discipline this project has already been bitten by getting wrong once
before (see core/jobs.py's active_proc history).

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


def _proc(returncode=0):
    return types.SimpleNamespace(returncode=returncode)


class TestExecutionWorkerAndroidPhysical:
    def _run(self, tmp_path, engine="dc3dd", hashes=None, downstream_returncode=0,
              upstream_returncode=0, upstream_stderr="", dc3dd_hashes=None,
              snapshot_side_effect=None, stream_side_effect=None):
        out_file = str(tmp_path / "case" / "ITEM-01_android_physical.dd")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}
        hashes = hashes if hashes is not None else ["sha256"]

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(mobile, "reclaim_ownership"))
            mock_write_report = stack.enter_context(mock.patch.object(mobile, "_write_report"))
            stack.enter_context(mock.patch.object(mobile, "clear_active_proc"))
            stack.enter_context(mock.patch.object(mobile, "clear_upstream_proc"))
            stack.enter_context(mock.patch("time.sleep"))
            stack.enter_context(mock.patch.object(mobile, "parse_dc3dd_line", return_value=(None, None)))
            stack.enter_context(mock.patch.object(mobile, "parse_dc3dd_hashes",
                                                    return_value=dc3dd_hashes if dc3dd_hashes is not None else {"sha256": "abc123"}))
            stack.enter_context(mock.patch.object(mobile, "read_hash_log_file", return_value="def456"))

            if stream_side_effect is not None:
                mock_stream = stack.enter_context(mock.patch.object(
                    mobile, "_stream_piped_subprocess", side_effect=stream_side_effect))
            else:
                mock_stream = stack.enter_context(mock.patch.object(
                    mobile, "_stream_piped_subprocess",
                    return_value=(_proc(downstream_returncode), _proc(upstream_returncode), upstream_stderr)))

            if snapshot_side_effect is not None:
                stack.enter_context(mock.patch.object(mobile, "snapshot_job", side_effect=snapshot_side_effect))

            mobile.execution_worker_android_physical(
                "SERIAL123", "/dev/block/by-name/userdata", engine, hashes, 1000000, out_file,
                report_path, report_data,
            )

        return snapshot_job(), report_data, mock_stream, mock_write_report

    def test_happy_path_dc3dd_completes_successfully_with_the_real_hashes_recorded(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run(tmp_path, engine="dc3dd")
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["computed_verification_hashes"] == {"sha256": "abc123"}
        mock_write_report.assert_called_once()
        # Both commands actually got built and piped, in the right shape.
        args = mock_stream.call_args[0]
        upstream_cmd, downstream_cmd, _on_line = args
        assert upstream_cmd[:3] == ["adb", "-s", "SERIAL123"]
        assert "su -c 'dd if=/dev/block/by-name/userdata bs=4M'" in upstream_cmd
        assert downstream_cmd[:2] == ["sudo", "/usr/bin/dc3dd"]

    def test_happy_path_dcfldd_completes_successfully_via_the_per_hash_log_file_path(self, tmp_path):
        # dcfldd's hash extraction is a genuinely different code path
        # (read_hash_log_file per algorithm) from dc3dd's own single-log
        # parse_dc3dd_hashes() - both need their own coverage.
        job, report_data, mock_stream, mock_write_report = self._run(
            tmp_path, engine="dcfldd", hashes=["sha256", "md5"],
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["computed_verification_hashes"] == {"sha256": "def456", "md5": "def456"}
        downstream_cmd = mock_stream.call_args[0][1]
        assert downstream_cmd[:2] == ["sudo", "/usr/bin/dcfldd"]
        assert "hash=sha256,md5" in downstream_cmd

    def test_downstream_returncode_2_still_counts_as_success(self, tmp_path):
        # Same dc3dd/dcfldd exit-code convention execution_worker() (routes/
        # acquisition.py) already relies on for the identical binaries.
        job, report_data, mock_stream, mock_write_report = self._run(tmp_path, downstream_returncode=2)
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"

    def test_an_upstream_failure_is_reported_as_failed_even_if_downstream_exits_zero(self, tmp_path):
        # The real, specific failure this feature exists to distinguish:
        # a non-rooted device, denied root, or an SELinux block on the
        # device side - surfaced with its own distinguishable message
        # rather than a bare "Failed", even when the downstream dc3dd
        # itself technically "succeeded" (wrote an empty/short file).
        job, report_data, mock_stream, mock_write_report = self._run(
            tmp_path, downstream_returncode=0, upstream_returncode=1,
            upstream_stderr="su: permission denied",
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert "su: permission denied" in job["log"]
        assert "isn't actually rooted" in job["log"] or "root access was denied" in job["log"]

    def test_a_dc3dd_self_reported_failure_is_caught_despite_a_success_exit_code(self, tmp_path):
        # The same "dc3dd can exit 0 while self-reporting failure in its own
        # log text" check execution_worker() already relies on - confirmed
        # here to also apply to this worker, which reuses the identical
        # binary. parse_dc3dd_line is called once per emitted log line, so
        # feed the "dc3dd failed at" text through the real on_line callback
        # captured from the mocked _stream_piped_subprocess call.
        def stream_side_effect(upstream_cmd, downstream_cmd, on_line):
            on_line("dc3dd failed at reading!")
            return _proc(0), _proc(0), ""

        job, report_data, mock_stream, mock_write_report = self._run(
            tmp_path, stream_side_effect=stream_side_effect,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"
        assert "dc3dd reported its own failure" in job["log"]

    def test_a_stopped_run_is_never_falsely_marked_completed_or_failed(self, tmp_path):
        # Matches execution_worker_mtp_pull()'s/execution_worker_android()'s
        # own identical "stays IN_PROGRESS, not Failed" convention for a
        # genuinely Stopped job - neither branch of the if/elif should ever
        # run for this case.
        job, report_data, mock_stream, mock_write_report = self._run(
            tmp_path, downstream_returncode=1,
            snapshot_side_effect=[{"status": "Stopped"}],
        )
        assert report_data["acquisition_status"] == "IN_PROGRESS"
        # _write_report still gets called unconditionally, right after the
        # if/elif - a Stopped run's report isn't silently left unwritten.
        mock_write_report.assert_called_once()

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        def stream_side_effect(*a, **kw):
            raise RuntimeError("simulated pipe failure")

        job, report_data, mock_stream, mock_write_report = self._run(
            tmp_path, stream_side_effect=stream_side_effect,
        )
        assert job["status"] == "Failed"
        assert "simulated pipe failure" in job["log"]
        # The exception happened before the try block's own _write_report
        # call - matches execution_worker()'s own identical except-branch
        # shape elsewhere in this app (no report write inside except).
        mock_write_report.assert_not_called()

    def test_cleanup_always_runs_regardless_of_outcome(self, tmp_path):
        # reclaim_ownership/update_job(active=False)/clear_active_proc/
        # clear_upstream_proc must never depend on which branch was taken -
        # confirmed here across all three real outcomes (success, failure,
        # exception) via the same helper.
        for kwargs in (
            {},  # happy path
            {"downstream_returncode": 1},  # failure
            {"stream_side_effect": lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x"))},  # exception
        ):
            with contextlib.ExitStack() as stack:
                mock_reclaim = stack.enter_context(mock.patch.object(mobile, "reclaim_ownership"))
                stack.enter_context(mock.patch.object(mobile, "_write_report"))
                mock_clear_active = stack.enter_context(mock.patch.object(mobile, "clear_active_proc"))
                mock_clear_upstream = stack.enter_context(mock.patch.object(mobile, "clear_upstream_proc"))
                stack.enter_context(mock.patch("time.sleep"))
                stack.enter_context(mock.patch.object(mobile, "parse_dc3dd_line", return_value=(None, None)))
                stack.enter_context(mock.patch.object(mobile, "parse_dc3dd_hashes", return_value={}))
                stack.enter_context(mock.patch.object(mobile, "read_hash_log_file", return_value=None))
                if "stream_side_effect" in kwargs:
                    stack.enter_context(mock.patch.object(mobile, "_stream_piped_subprocess", side_effect=kwargs["stream_side_effect"]))
                else:
                    stack.enter_context(mock.patch.object(
                        mobile, "_stream_piped_subprocess",
                        return_value=(_proc(kwargs.get("downstream_returncode", 0)), _proc(0), "")))

                mobile.execution_worker_android_physical(
                    "SERIAL123", "/dev/block/by-name/userdata", "dc3dd", ["sha256"], 1000000,
                    str(tmp_path / "out.dd"), str(tmp_path / "report.json"),
                    {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}},
                )
            mock_reclaim.assert_called_once()
            mock_clear_active.assert_called_once()
            mock_clear_upstream.assert_called_once()
