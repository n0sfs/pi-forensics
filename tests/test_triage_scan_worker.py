"""routes/recovery.py's execution_worker_triage_scan() - found with zero
control-flow test coverage during a 2026-09-09 follow-up to this session's
own 10-item execution_worker_* backlog closure: a grep-based coverage-map
check (searching for the literal function-name-followed-by-open-paren
string across tests/) initially found zero matches, but every one of this
function's siblings in the same file (PhotoRec/foremost/scalpel/extundelete)
IS genuinely tested - they're just passed as a bare function reference
(`recovery.execution_worker_photorec`) into a shared `_run_worker()` helper
in tests/test_recovery_write_confirmation.py, never called directly with a
trailing paren, which the literal grep missed. This function and its
image-mode sibling (execution_worker_image_triage_scan) are the only two
genuine gaps that check turned up - tests/test_scan_patterns.py only
exercises the shared build_scan_patterns()/resolve_scan_category_label()
helper both workers consume, never either worker's own control flow.

No external tool subprocess to mock for the file-source path (a plain
Python file read, no sudo needed) - this worker's own read-only "no
external tool dependency at all" design (see its own docstring) makes a
REAL small tmp_path file with genuine content matching TRIAGE_PATTERNS
["emails"] a stronger, lower-risk test than mocking regex matching away.
Only the block-device source path (piped through `sudo dd`) needs
subprocess.Popen mocked, since there's no real block device to read here.

Skipped (not failed) on a non-POSIX dev machine: routes.recovery needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.recovery needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.recovery as recovery
from core.jobs import snapshot_job


class TestExecutionWorkerTriageScan:
    def _run(self, tmp_path, source_content=b"contact test@example.com for details\n",
              keyword_list_ids=None, snapshot_side_effect=None, block_device=False,
              popen_side_effect=None):
        source_path = str(tmp_path / "source.txt")
        with open(source_path, "wb") as f:
            f.write(source_content)
        dest_dir = str(tmp_path / "out")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS"}

        with mock.patch.object(recovery, "_write_report") as mock_write_report, \
             mock.patch.object(recovery, "clear_active_proc"), \
             mock.patch.object(recovery, "is_valid_block_device", return_value=block_device):
            if block_device:
                default_stdout = types.SimpleNamespace(read=mock.Mock(side_effect=[source_content, b""]))
                mock_proc = types.SimpleNamespace(stdout=default_stdout, poll=mock.Mock(return_value=0), terminate=mock.Mock(), wait=mock.Mock())
                with mock.patch("subprocess.Popen", side_effect=popen_side_effect if popen_side_effect else (lambda *a, **kw: mock_proc)) as mock_popen, \
                     mock.patch("subprocess.run") as mock_run:
                    if snapshot_side_effect is not None:
                        with mock.patch.object(recovery, "snapshot_job", side_effect=snapshot_side_effect):
                            recovery.execution_worker_triage_scan(source_path, dest_dir, report_path, report_data, 100, keyword_list_ids)
                    else:
                        recovery.execution_worker_triage_scan(source_path, dest_dir, report_path, report_data, 100, keyword_list_ids)
                    return snapshot_job(), report_data, mock_write_report, dest_dir, mock_popen, mock_run
            else:
                if snapshot_side_effect is not None:
                    with mock.patch.object(recovery, "snapshot_job", side_effect=snapshot_side_effect):
                        recovery.execution_worker_triage_scan(source_path, dest_dir, report_path, report_data, 100, keyword_list_ids)
                else:
                    recovery.execution_worker_triage_scan(source_path, dest_dir, report_path, report_data, 100, keyword_list_ids)
                return snapshot_job(), report_data, mock_write_report, dest_dir, None, None

    def test_happy_path_finds_a_real_regex_match_and_writes_a_real_output_file(self, tmp_path):
        job, report_data, mock_write_report, dest_dir, *_ = self._run(tmp_path)
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["triage_summary"]["emails"] == 1

        out_path = os.path.join(dest_dir, "emails.txt")
        assert os.path.isfile(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test@example.com" in content
        mock_write_report.assert_called_once()

    def test_no_matches_still_completes_and_writes_empty_category_files(self, tmp_path):
        job, report_data, mock_write_report, dest_dir, *_ = self._run(tmp_path, source_content=b"nothing interesting here at all")
        assert job["status"] == "Completed Successfully"
        assert report_data["triage_summary"]["emails"] == 0
        out_path = os.path.join(dest_dir, "emails.txt")
        assert os.path.isfile(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            assert f.read() == ""

    def test_a_match_cap_hit_stops_collecting_new_matches_for_that_category_only(self, tmp_path):
        # Two distinct emails, capped at 1 - only the first-seen match should
        # be kept, and the cap must not affect unrelated categories.
        content = b"first@example.com then second@example.com and also 192.168.1.1"
        with mock.patch.object(recovery, "TRIAGE_MAX_MATCHES_PER_CATEGORY", 1):
            job, report_data, mock_write_report, dest_dir, *_ = self._run(tmp_path, source_content=content)
        assert job["status"] == "Completed Successfully"
        assert report_data["triage_summary"]["emails"] == 1
        assert report_data["triage_summary"]["ip_addresses"] == 1  # unaffected by the emails cap
        assert "hit the 1-match cap" in job["log"]

    def test_a_stop_mid_scan_is_reported_as_stopped_not_completed_or_failed(self, tmp_path):
        # A callable side_effect (not a fixed-length list) - the real code
        # path checks snapshot_job() twice on a Stop (once inside the read
        # loop, once again in the final status-branch check after it), and
        # a short list would exhaust after the first call and raise
        # StopIteration on the second, silently turning this into a false
        # "Execution Exception"/Failed instead of the intended Stopped path.
        job, report_data, mock_write_report, dest_dir, *_ = self._run(
            tmp_path, snapshot_side_effect=lambda: {"status": "Stopped"},
        )
        assert report_data["acquisition_status"] == "STOPPED"
        assert "Scan stopped by user" in job["log"]
        # The report is still written on a Stop, not silently left unwritten.
        mock_write_report.assert_called_once()

    def test_the_block_device_source_path_reads_via_a_piped_sudo_dd_subprocess(self, tmp_path):
        job, report_data, mock_write_report, dest_dir, mock_popen, mock_run = self._run(
            tmp_path, block_device=True,
        )
        assert job["status"] == "Completed Successfully"
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd[:3] == ["sudo", "/usr/bin/dd", "if=" + str(tmp_path / "source.txt")]

    def test_a_stop_while_reading_a_block_device_still_terminates_the_dd_subprocess(self, tmp_path):
        job, report_data, mock_write_report, dest_dir, mock_popen, mock_run = self._run(
            tmp_path, block_device=True, snapshot_side_effect=lambda: {"status": "Stopped"},
        )
        assert report_data["acquisition_status"] == "STOPPED"
        # The inner finally block's own cleanup (terminate the dd process,
        # then a sudo pkill sweep as the real cleanup for a root-owned
        # process an unprivileged terminate() can't touch) still ran.
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0][:3] == ["sudo", "pkill", "-9"]

    def test_a_file_that_cannot_be_read_is_caught_and_reported_as_failed(self, tmp_path):
        # A source path that doesn't exist at all - open() raises before the
        # scan loop ever starts, exercising the outer except Exception branch.
        dest_dir = str(tmp_path / "out")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS"}
        with mock.patch.object(recovery, "_write_report"), \
             mock.patch.object(recovery, "clear_active_proc"), \
             mock.patch.object(recovery, "is_valid_block_device", return_value=False):
            recovery.execution_worker_triage_scan(
                str(tmp_path / "does_not_exist.txt"), dest_dir, report_path, report_data, 100, None)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "Execution Exception" in job["log"]

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, snapshot_side_effect in enumerate((None, lambda: {"status": "Stopped"})):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            self._run(iter_root, snapshot_side_effect=snapshot_side_effect)
            assert snapshot_job()["active"] is False
