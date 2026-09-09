"""routes/file_explorer.py's execution_worker_mquire_scan() - the 10th and
LAST of 10 execution_worker_* functions found with zero pytest coverage
during a self-directed validation pass (2026-09-09) - see that dated
CLAUDE.md section for the discovery/scoping rationale. Closes this
whole 10-item backlog.

The mquire (Linux x86_64 memory forensics) counterpart to
execution_worker_memory_forensics_scan() (Volatility3/Windows) - the
worker's own docstring confirms it directly: "same overall shape as
execution_worker_memory_forensics_scan() above". This test file mirrors
test_memory_forensics_scan_worker.py's own established approach closely
for that reason, adapted for mquire's real, distinct CLI shape (`mquire
query --operating-system linux --architecture intel -f json <image>
"SELECT * FROM <table>"` instead of Volatility3's `vol -f <image> -r json
<plugin>`) and output-file/log-event naming
(`{base}_mquire_{key}.json`/`"mquire_scan"` with a `"table"` field,
instead of `_vol3_{key}.json`/`"memory_forensics_scan"` with a `"plugin"`
field).

Mocks the genuine external boundary (subprocess.run - the real mquire
process this app has never run against a genuine x86_64 Linux memory
dump, a real, already-disclosed gap separate from this worker's own
control flow) plus _record_analysis_result/_auto_tag_case_artifact/
log_chain_of_custody (real per-case SQLite/audit-log writes, already
covered elsewhere). Lets the real output-file write happen against a real
tmp_path directory and reads the actual written content back off disk.

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


class TestExecutionWorkerMquireScan:
    def _run(self, tmp_path, table_keys, subprocess_side_effect=None,
              source_ip="127.0.0.1", user="test-user", snapshot_side_effect=None):
        image_path = str(tmp_path / "memdump.raw")
        (tmp_path / "memdump.raw").write_bytes(b"fake memory image bytes")
        dest_dir = str(tmp_path)

        def default_subprocess_side_effect(cmd, **kw):
            return _proc(returncode=0, stdout=json.dumps([{"pid": 1, "comm": "systemd"}]))

        with mock.patch("subprocess.run",
                         side_effect=subprocess_side_effect if subprocess_side_effect else default_subprocess_side_effect) as mock_run, \
             mock.patch.object(file_explorer, "_record_analysis_result") as mock_record, \
             mock.patch.object(file_explorer, "_auto_tag_case_artifact") as mock_tag, \
             mock.patch.object(file_explorer, "log_chain_of_custody") as mock_log:
            if snapshot_side_effect is not None:
                with mock.patch.object(file_explorer, "snapshot_job", side_effect=snapshot_side_effect):
                    file_explorer.execution_worker_mquire_scan(
                        image_path, dest_dir, table_keys, source_ip=source_ip, user=user)
            else:
                file_explorer.execution_worker_mquire_scan(
                    image_path, dest_dir, table_keys, source_ip=source_ip, user=user)

        return snapshot_job(), mock_run, mock_record, mock_tag, mock_log, dest_dir

    def test_happy_path_one_table_writes_a_real_output_file_and_logs_correctly(self, tmp_path):
        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(tmp_path, ["tasks"])
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert "1 table(s) succeeded, 0 failed" in job["log"]

        out_path = os.path.join(dest_dir, "memdump_mquire_tasks.json")
        assert os.path.isfile(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written == [{"pid": 1, "comm": "systemd"}]

        mock_tag.assert_called_once_with(dest_dir, out_path)
        mock_record.assert_called_once()
        record_args = mock_record.call_args[0]
        assert record_args[2] == "mquire tasks"
        assert record_args[3] == "1 row(s)"
        mock_log.assert_called_once()
        log_args, log_kwargs = mock_log.call_args
        assert log_args[0] == "mquire_scan"
        assert log_args[1]["table"] == "tasks"
        assert log_args[1]["row_count"] == 1
        assert log_kwargs == {"source_ip": "127.0.0.1", "user": "test-user"}

    def test_the_real_mquire_command_shape_is_built_correctly(self, tmp_path):
        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(tmp_path, ["os_version"])
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == file_explorer.MQUIRE_BIN
        assert "--operating-system" in cmd and "linux" in cmd
        assert "--architecture" in cmd and "intel" in cmd
        assert cmd[-1] == "SELECT * FROM os_version"

    def test_a_mix_of_success_and_failure_across_multiple_tables_still_completes_successfully(self, tmp_path):
        def side_effect(cmd, **kw):
            if cmd[-1] == "SELECT * FROM dmesg":
                return _proc(returncode=1, stderr="real mquire error text")
            return _proc(returncode=0, stdout=json.dumps([{"row": 1}]))

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg", "tasks"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Completed Successfully"
        assert "1 table(s) succeeded, 1 failed" in job["log"]
        assert "real mquire error text" in job["log"]
        failed_calls = [c for c in mock_record.call_args_list if c[0][3] == "FAILED"]
        assert len(failed_calls) == 1

    def test_every_requested_table_failing_with_zero_successes_is_reported_as_failed(self, tmp_path):
        def side_effect(cmd, **kw):
            return _proc(returncode=1, stderr="every table fails")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg", "tasks"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "0 table(s) succeeded, 2 failed" in job["log"]
        mock_log.assert_not_called()

    def test_an_unrecognized_table_key_is_skipped_and_never_counted_either_way(self, tmp_path):
        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["not_a_real_table_key"],
        )
        assert job["status"] == "Completed Successfully"
        assert "Skipping unrecognized table key" in job["log"]
        mock_run.assert_not_called()

    def test_a_table_query_timeout_is_counted_as_a_failure_and_the_scan_continues(self, tmp_path):
        import subprocess as real_subprocess
        call_count = {"n": 0}

        def side_effect(cmd, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise real_subprocess.TimeoutExpired(cmd, 1800)
            return _proc(returncode=0, stdout=json.dumps([{"row": 1}]))

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg", "tasks"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Completed Successfully"
        assert "timed out after" in job["log"]
        assert "1 table(s) succeeded, 1 failed" in job["log"]
        assert mock_run.call_count == 2

    def test_mquire_not_installed_fails_immediately_and_never_attempts_further_tables(self, tmp_path):
        def side_effect(cmd, **kw):
            raise FileNotFoundError("no such file: mquire")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg", "tasks"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "mquire is not installed" in job["log"]
        assert mock_run.call_count == 1
        mock_log.assert_not_called()

    def test_a_stop_partway_through_the_table_list_leaves_the_remaining_tables_unattempted(self, tmp_path):
        real_snapshot = file_explorer.snapshot_job
        call_count = {"n": 0}

        def stop_after_first(*a, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return real_snapshot()
            return {"status": "Stopped"}

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg", "tasks"], snapshot_side_effect=stop_after_first,
        )
        assert "Stopped by user" in job["log"]
        assert job["status"] != "Completed Successfully"
        assert job["status"] != "Failed"
        assert mock_run.call_count == 1

    def test_an_unexpected_exception_is_caught_and_reported_as_failed(self, tmp_path):
        def side_effect(cmd, **kw):
            raise RuntimeError("simulated failure")

        job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
            tmp_path, ["dmesg"], subprocess_side_effect=side_effect,
        )
        assert job["status"] == "Failed"
        assert "simulated failure" in job["log"]

    def test_cleanup_always_sets_active_false_on_every_exit_path(self, tmp_path):
        def not_installed(cmd, **kw):
            raise FileNotFoundError("no mquire")

        def stopped(*a, **kw):
            return {"status": "Stopped"}

        for i, (subprocess_side_effect, snapshot_side_effect) in enumerate((
            (None, None),
            (not_installed, None),
            (None, stopped),
        )):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            job, mock_run, mock_record, mock_tag, mock_log, dest_dir = self._run(
                iter_root, ["dmesg"], subprocess_side_effect=subprocess_side_effect,
                snapshot_side_effect=snapshot_side_effect,
            )
            assert snapshot_job()["active"] is False
