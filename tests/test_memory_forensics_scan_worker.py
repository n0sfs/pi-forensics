"""routes/file_explorer.py's execution_worker_memory_forensics_scan() -
the 9th of 10 execution_worker_* functions found with zero pytest
coverage during a self-directed validation pass (2026-09-09) - see that
dated CLAUDE.md section for the discovery/scoping rationale.

Runs each requested Volatility3 plugin against a Windows memory image in
turn - this app's own established "target still never tested against a
real Windows memory image" gap (see the dated CLAUDE.md section for this
feature's own original build) is separate from this worker's own control
flow, which is what this pass covers.

Mocks the genuine external boundary (subprocess.run - the real
`vol -f <image> -r json <plugin>` call) plus _record_analysis_result/
_auto_tag_case_artifact/log_chain_of_custody (real per-case SQLite/audit-
log writes, already covered by their own dedicated tests elsewhere).
Lets the real output-file write happen against a real tmp_path directory
and reads the actual written content back, matching this pass's own
already-established "real filesystem beats mocking os.path.*" precedent.

Matches the real production calling convention: every path that reaches
this worker's own log_chain_of_custody() call (only on a successful
plugin run) passes explicit, non-None source_ip/user, while the early-
return paths (a genuine Stop, a missing volatility3 binary) never reach
that call site and correctly don't need them.

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


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestExecutionWorkerMemoryForensicsScan:
    def _run(self, tmp_path, plugin_keys, subprocess_side_effect=None,
              source_ip="127.0.0.1", user="test-user", snapshot_side_effect=None):
        image_path = str(tmp_path / "memdump.raw")
        (tmp_path / "memdump.raw").write_bytes(b"fake memory image bytes")
        dest_dir = str(tmp_path)

        def default_subprocess_side_effect(cmd, **kw):
            return _proc(returncode=0, stdout=json.dumps([{"PID": 4, "ImageFileName": "System"}]))

        with mock.patch("subprocess.run",
                         side_effect=subprocess_side_effect if subprocess_side_effect else default_subprocess_side_effect) as mock_run, \
             mock.patch.object(file_explorer, "_record_analysis_result") as mock_record, \
             mock.patch.object(file_explorer, "_auto_tag_case_artifact") as mock_tag, \
             mock.patch.object(file_explorer, "log_chain_of_custody") as mock_log:
            if snapshot_side_effect is not None:
                with mock.patch.object(file_explorer, "snapshot_job", side_effect=snapshot_side_effect):
                    file_explorer.execution_worker_memory_forensics_scan(
                        image_path, dest_dir, plugin_keys, source_ip=source_ip, user=user)
            else:
                file_explorer.execution_worker_memory_forensics_scan(
                    image_path, dest_dir, plugin_keys, source_ip=source_ip, user=user)

        return snapshot_job(), mock_run, mock_record, mock_tag, mock_log, dest_dir

    def test_happy_path_one_plugin_writes_a_real_output_file_and_logs_correctly(self, tmp_path):
        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(tmp_path, ["pslist"])
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert "1 plugin(s) succeeded, 0 failed" in job["log"]

        out_path = os.path.join(dest_dir, "memdump_vol3_pslist.json")
        assert os.path.isfile(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written == [{"PID": 4, "ImageFileName": "System"}]

        mock_tag.assert_called_once_with(dest_dir, out_path)
        mock_record.assert_called_once()
        record_args = mock_record.call_args[0]
        assert record_args[2] == "Volatility3 windows.pslist.PsList"
        assert record_args[3] == "1 row(s)"
        mock_log.assert_called_once()
        log_args, log_kwargs = mock_log.call_args
        assert log_args[0] == "memory_forensics_scan"
        assert log_args[1]["plugin"] == "windows.pslist.PsList"
        assert log_args[1]["row_count"] == 1
        assert log_kwargs == {"source_ip": "127.0.0.1", "user": "test-user"}

    def test_a_mix_of_success_and_failure_across_multiple_plugins_still_completes_successfully(self, tmp_path):
        def side_effect(cmd, **kw):
            plugin = cmd[-1]
            if plugin == "windows.info.Info":
                return _proc(returncode=1, stderr="real volatility3 error text")
            return _proc(returncode=0, stdout=json.dumps([{"row": 1}]))

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info", "pslist"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Completed Successfully"  # at least one plugin succeeded
        assert "1 plugin(s) succeeded, 1 failed" in job["log"]
        assert "real volatility3 error text" in job["log"]
        # The failed plugin still got its own FAILED record - never silently dropped.
        failed_calls = [c for c in mock_record.call_args_list if c[0][3] == "FAILED"]
        assert len(failed_calls) == 1

    def test_every_requested_plugin_failing_with_zero_successes_is_reported_as_failed(self, tmp_path):
        def side_effect(cmd, **kw):
            return _proc(returncode=1, stderr="every plugin fails")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info", "pslist"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "0 plugin(s) succeeded, 2 failed" in job["log"]
        mock_log.assert_not_called()  # never reached - only a successful plugin logs chain-of-custody

    def test_an_unrecognized_plugin_key_is_skipped_and_never_counted_either_way(self, tmp_path):
        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["not_a_real_plugin_key"],
        )
        assert job["status"] == "Completed Successfully"  # failed==0 and completed==0 -> still success
        assert "Skipping unrecognized plugin key" in job["log"]
        mock_run.assert_not_called()

    def test_a_plugin_timeout_is_counted_as_a_failure_and_the_scan_continues(self, tmp_path):
        import subprocess as real_subprocess
        call_count = {"n": 0}

        def side_effect(cmd, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise real_subprocess.TimeoutExpired(cmd, 1800)
            return _proc(returncode=0, stdout=json.dumps([{"row": 1}]))

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info", "pslist"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Completed Successfully"
        assert "timed out after" in job["log"]
        assert "1 plugin(s) succeeded, 1 failed" in job["log"]
        assert mock_run.call_count == 2  # the scan genuinely continued to the second plugin

    def test_volatility3_not_installed_fails_immediately_and_never_attempts_further_plugins(self, tmp_path):
        def side_effect(cmd, **kw):
            raise FileNotFoundError("no such file: vol")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info", "pslist"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "volatility3 is not installed" in job["log"]
        assert mock_run.call_count == 1  # never attempted the second plugin
        mock_log.assert_not_called()

    def test_a_stop_partway_through_the_plugin_list_leaves_the_remaining_plugins_unattempted(self, tmp_path):
        real_snapshot = file_explorer.snapshot_job
        call_count = {"n": 0}

        def stop_after_first(*a, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return real_snapshot()
            return {"status": "Stopped"}

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info", "pslist"], snapshot_side_effect=stop_after_first,
        )
        assert "Stopped by user" in job["log"]
        assert job["status"] != "Completed Successfully"
        assert job["status"] != "Failed"  # a genuine Stop is neither - the final status update is never reached
        assert mock_run.call_count == 1  # only the first plugin ran before the stop

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        def side_effect(cmd, **kw):
            raise RuntimeError("simulated failure")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["info"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_on_every_exit_path(self, tmp_path):
        real_snapshot = file_explorer.snapshot_job

        def stopped(*a, **kw):
            return {"status": "Stopped"}

        def not_installed(cmd, **kw):
            raise FileNotFoundError("no vol")

        for i, (subprocess_side_effect, snapshot_side_effect) in enumerate((
            (None, None),                       # happy path
            (not_installed, None),              # early-return: missing binary
            (None, stopped),                    # early-return: Stop
        )):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
                iter_root, ["info"], subprocess_side_effect=subprocess_side_effect,
                snapshot_side_effect=snapshot_side_effect,
            )
            assert snapshot_job()["active"] is False
