"""routes/recovery.py's _confirm_recovery_output_or_fail() and its wiring
into all 4 file-carving/recovery workers - PhotoRec, extundelete,
foremost, scalpel (2026-09-06). All four are external subprocess-based
tools that write their carved/recovered output directly to dest_dir, so
this app has no per-file write loop of its own for them the way Logical
Acquisition/MTP pull/Live Collection Import have - the fix here is a
post-hoc directory-tree write-confirmation gate run right before the
tool's own successful exit code is trusted, closing the same real NFS
async-writeback gap the rest of this app's acquisition paths were fixed
for the same day.

Mocks routes.recovery._stream_subprocess/reclaim_ownership/
fsync_confirm_directory_tree, mirroring test_extundelete_error_
messages.py's own already-established pattern for testing an
execution_worker_* function's control flow directly without shelling out
for real.

Skipped (not failed) on a non-POSIX dev machine: routes.recovery needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.recovery needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.recovery as recovery
from core.jobs import snapshot_job


def _base_report_data():
    return {"acquisition_status": "IN_PROGRESS"}


def _confirmed_result():
    return {"files_checked": 3, "files_confirmed": 3, "files_failed": 0,
            "failed_examples": [], "capped": False, "all_confirmed": True}


def _failed_result():
    return {"files_checked": 3, "files_confirmed": 1, "files_failed": 2,
            "failed_examples": ["carved1.jpg", "carved2.jpg"], "capped": False, "all_confirmed": False}


def _empty_result():
    return {"files_checked": 0, "files_confirmed": 0, "files_failed": 0,
            "failed_examples": [], "capped": False, "all_confirmed": True}


def _capped_but_clean_result():
    return {"files_checked": 20000, "files_confirmed": 20000, "files_failed": 0,
            "failed_examples": [], "capped": True, "all_confirmed": True}


class TestConfirmRecoveryOutputOrFail:
    """Direct unit tests of the shared helper itself, independent of any
    one worker."""

    def test_a_clean_confirmed_result_returns_true_with_no_log(self):
        log = []
        with mock.patch.object(recovery, "fsync_confirm_directory_tree", return_value=_confirmed_result()):
            ok = recovery._confirm_recovery_output_or_fail("/fake/dest", "PhotoRec", log.append)
        assert ok is True
        assert not any("could not have their write confirmed" in m for m in log)

    def test_an_empty_recovery_returns_true_not_a_failure(self):
        # Nothing recovered isn't a write failure of its own - a genuinely
        # empty carve/recovery is a valid, honest outcome.
        log = []
        with mock.patch.object(recovery, "fsync_confirm_directory_tree", return_value=_empty_result()):
            ok = recovery._confirm_recovery_output_or_fail("/fake/dest", "foremost", log.append)
        assert ok is True

    def test_a_failed_confirmation_returns_false_and_logs_the_real_reason(self):
        log = []
        with mock.patch.object(recovery, "fsync_confirm_directory_tree", return_value=_failed_result()):
            ok = recovery._confirm_recovery_output_or_fail("/fake/dest", "scalpel", log.append)
        assert ok is False
        assert any("2 of 3 recovered file(s) could not have their write confirmed" in m for m in log)
        assert any("carved1.jpg" in m for m in log)

    def test_a_capped_but_fully_clean_result_returns_true_with_a_disclosure_note(self):
        # The real, deliberate design decision this test locks in: hitting
        # the safety cap on a legitimately huge, genuinely successful
        # carve must never by itself be treated as a failure.
        log = []
        with mock.patch.object(recovery, "fsync_confirm_directory_tree", return_value=_capped_but_clean_result()):
            ok = recovery._confirm_recovery_output_or_fail("/fake/dest", "PhotoRec", log.append)
        assert ok is True
        assert any("could not verify every single one" in m for m in log)
        assert any("not a sign anything is actually wrong" in m for m in log)


def _run_worker(worker_fn, tmp_path, returncode, confirm_result, monkeypatch, extra_args=()):
    dest_dir = str(tmp_path / "recovery_out")
    report_path = str(tmp_path / "report.json")
    fake_proc = types.SimpleNamespace(returncode=returncode)

    with mock.patch.object(recovery, "_stream_subprocess", return_value=fake_proc), \
         mock.patch.object(recovery, "reclaim_ownership"), \
         mock.patch.object(recovery, "fsync_confirm_directory_tree", return_value=confirm_result):
        worker_fn("/dev/sdz1", dest_dir, report_path, _base_report_data(), *extra_args)

    return snapshot_job()


class TestPhotoRecWriteConfirmation:
    def test_genuine_success_with_confirmed_write_reports_completed(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_photorec, tmp_path, 0, _confirmed_result(), monkeypatch)
        assert job["status"] == "Completed Successfully"
        assert "PhotoRec recovery completed" in job["log"]

    def test_tool_success_but_write_not_confirmed_reports_failed_without_a_misleading_exit_code_line(self, tmp_path, monkeypatch):
        # The exact real-world scenario this whole fix exists for: the
        # tool itself exits 0, but the write-confirmation check found the
        # output couldn't be trusted. Must never ALSO log "exited with
        # code 0" as if that were the real reason.
        job = _run_worker(recovery.execution_worker_photorec, tmp_path, 0, _failed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "could not have their write confirmed" in job["log"]
        assert "exited with code 0" not in job["log"]

    def test_a_genuine_tool_failure_is_still_reported_failed_with_its_own_exit_code_message(self, tmp_path, monkeypatch):
        # A real tool failure (nonzero exit) never even reaches the
        # write-confirmation check - fsync_confirm_directory_tree is mocked
        # to return a confirmed result here specifically to prove the exit
        # code path is what's actually being exercised, not the mock.
        job = _run_worker(recovery.execution_worker_photorec, tmp_path, 1, _confirmed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "photorec exited with code 1" in job["log"]


class TestForemostWriteConfirmation:
    def test_genuine_success_with_confirmed_write_reports_completed(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_foremost, tmp_path, 0, _confirmed_result(), monkeypatch)
        assert job["status"] == "Completed Successfully"

    def test_tool_success_but_write_not_confirmed_reports_failed_without_a_misleading_exit_code_line(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_foremost, tmp_path, 0, _failed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "could not have their write confirmed" in job["log"]
        assert "exited with code 0" not in job["log"]

    def test_a_genuine_tool_failure_still_logs_its_own_exit_code_message(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_foremost, tmp_path, 1, _confirmed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "foremost exited with code 1" in job["log"]


class TestScalpelWriteConfirmation:
    def test_genuine_success_with_confirmed_write_reports_completed(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_scalpel, tmp_path, 0, _confirmed_result(), monkeypatch)
        assert job["status"] == "Completed Successfully"

    def test_tool_success_but_write_not_confirmed_reports_failed_without_a_misleading_exit_code_line(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_scalpel, tmp_path, 0, _failed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "could not have their write confirmed" in job["log"]
        assert "exited with code 0" not in job["log"]

    def test_a_genuine_tool_failure_still_logs_its_own_exit_code_message(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_scalpel, tmp_path, 1, _confirmed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "scalpel exited with code 1" in job["log"]


class TestExtundeleteWriteConfirmation:
    """extundelete's own success/failure branching already has a real
    3-way split (clean success / signal-killed crash / plain nonzero
    exit) from the 2026-09-03 fix - these tests confirm the new
    write-confirmation check composes correctly with all three, not just
    the plain success case the other 3 tools' tests cover."""

    def test_genuine_success_with_confirmed_write_reports_completed(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_extundelete, tmp_path, 0, _confirmed_result(), monkeypatch)
        assert job["status"] == "Completed Successfully"
        assert "extundelete completed" in job["log"]

    def test_tool_success_but_write_not_confirmed_reports_failed_without_a_misleading_exit_code_line(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_extundelete, tmp_path, 0, _failed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "could not have their write confirmed" in job["log"]
        # Neither of extundelete's own two pre-existing failure messages
        # should appear - this failure has nothing to do with the tool's
        # own exit code, which was genuinely 0.
        assert "exited with code" not in job["log"]
        assert "crashed (signal" not in job["log"]

    def test_a_signal_killed_crash_still_reports_the_original_crash_message_unaffected(self, tmp_path, monkeypatch):
        # A negative returncode never reaches the write-confirmation check
        # at all (it's gated on proc.returncode == 0) - confirms the
        # pre-existing 2026-09-03 crash-message fix is completely
        # untouched by this same-file change.
        job = _run_worker(recovery.execution_worker_extundelete, tmp_path, -11, _confirmed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "crashed (signal 11)" in job["log"]

    def test_a_plain_nonzero_exit_still_reports_the_original_wrong_filesystem_message_unaffected(self, tmp_path, monkeypatch):
        job = _run_worker(recovery.execution_worker_extundelete, tmp_path, 1, _confirmed_result(), monkeypatch)
        assert job["status"] == "Failed"
        assert "is the source an ext2/3/4 filesystem?" in job["log"]
