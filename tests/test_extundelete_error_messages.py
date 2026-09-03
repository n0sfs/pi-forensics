"""execution_worker_extundelete()'s (routes/recovery.py) failure-branch log
message (2026-09-03) - distinguishes a signal-killed process (a negative
Python subprocess returncode, confirmed live against a real hand-built ext4
image to mean extundelete 0.2.4 crashing - SIGSEGV, returncode -11 - on a
filesystem using modern ext4 features the tool's own decade-old libext2fs
build can't parse) from a plain non-zero exit ("this probably isn't an
ext2/3/4 filesystem"). Before this fix both cases produced the exact same
generic "exited with code N" message, which is actively misleading for the
crash case - it reads as "check your source," not "this tool build has a
known compatibility gap, try PhotoRec instead."

Mocks routes.recovery._stream_subprocess/reclaim_ownership (the two real
side-effecting calls the worker makes) rather than shelling out for real,
mirroring test_chained_auto_analyze.py's own established mock.patch.object
pattern for testing an execution_worker_* function's control flow directly.

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


def _run_extundelete(tmp_path, returncode, monkeypatch):
    dest_dir = str(tmp_path / "recovery_out")
    report_path = str(tmp_path / "report.json")
    fake_proc = types.SimpleNamespace(returncode=returncode)

    with mock.patch.object(recovery, "_stream_subprocess", return_value=fake_proc), \
         mock.patch.object(recovery, "reclaim_ownership"):
        recovery.execution_worker_extundelete("/dev/sdz1", dest_dir, report_path, _base_report_data())

    return snapshot_job()


def test_a_negative_returncode_is_reported_as_a_crash_not_a_wrong_filesystem_guess(tmp_path, monkeypatch):
    job = _run_extundelete(tmp_path, -11, monkeypatch)
    assert job["status"] == "Failed"
    assert "crashed (signal 11)" in job["log"]
    assert "extundelete 0.2.4" in job["log"] or "modern ext4 features" in job["log"]
    assert "Try PhotoRec instead" in job["log"]
    # The old, misleading-for-this-case generic phrasing must not also be
    # present - this is a real replacement, not an addition alongside it.
    assert "exited with code" not in job["log"]


def test_a_plain_positive_returncode_keeps_the_original_wrong_filesystem_guess_message(tmp_path, monkeypatch):
    job = _run_extundelete(tmp_path, 1, monkeypatch)
    assert job["status"] == "Failed"
    assert "exited with code 1" in job["log"]
    assert "is the source an ext2/3/4 filesystem?" in job["log"]
    # The crash-specific message must never leak into the plain-failure case.
    assert "crashed (signal" not in job["log"]
    assert "Try PhotoRec instead" not in job["log"]


def test_a_zero_returncode_is_still_reported_as_success_unaffected_by_this_change(tmp_path, monkeypatch):
    job = _run_extundelete(tmp_path, 0, monkeypatch)
    assert job["status"] == "Completed Successfully"
    assert "extundelete completed" in job["log"]
