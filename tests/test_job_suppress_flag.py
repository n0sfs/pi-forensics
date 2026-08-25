"""core/jobs.py's begin_suppress_active_false()/end_suppress_active_false()
mechanism (Phase 2 of Linux Artifacts + Auto Analyze, 2026-08-25) - lets
Auto Analyze call an existing execution_worker_* function directly, in-line,
without that worker's own `finally: update_job(active=False)` prematurely
releasing the orchestrator's own job-slot claim, while every other field
the worker writes (status/log/progress) still updates normally.

Skipped (not failed) on a non-POSIX dev machine: core.jobs imports
POSIX-only pwd/fcntl at module level - see tests/conftest.py's own
docstring for this project's standing reason.
"""
import pytest

pytest.importorskip("core.jobs", reason="core.jobs imports POSIX-only pwd/fcntl")

import core.jobs as jobs


@pytest.fixture(autouse=True)
def _reset_job_state():
    """Every test in this file gets a clean current_job/_suppress_active_false
    state, and leaves one behind too - core.jobs' module-level globals would
    otherwise leak between tests (and between this file and any other test
    file that happens to run in the same process) since nothing else in
    this project resets them."""
    jobs.end_suppress_active_false()
    with jobs.job_lock:
        jobs.current_job["active"] = False
        jobs.current_job["status"] = "IDLE"
    yield
    jobs.end_suppress_active_false()


def test_active_false_passes_through_normally_when_not_suppressed():
    jobs.update_job(active=True)
    assert jobs.snapshot_job()["active"] is True
    jobs.update_job(active=False)
    assert jobs.snapshot_job()["active"] is False


def test_active_false_is_dropped_while_suppressed():
    jobs.update_job(active=True)
    jobs.begin_suppress_active_false()
    jobs.update_job(active=False)  # e.g. a wrapped worker's own finally block
    assert jobs.snapshot_job()["active"] is True  # unchanged - the whole point
    jobs.end_suppress_active_false()
    jobs.update_job(active=False)
    assert jobs.snapshot_job()["active"] is False  # normal behavior resumes


def test_every_other_field_still_updates_while_active_is_suppressed():
    jobs.update_job(active=True)
    jobs.begin_suppress_active_false()
    # Mirrors exactly what a wrapped worker's own finally block does: one
    # call carrying both real progress fields AND active=False together -
    # only the active key should be stripped, not the whole call dropped.
    jobs.update_job(status="Completed Successfully", progress_percent=100.0,
                     log="[+] done", active=False)
    snap = jobs.snapshot_job()
    assert snap["active"] is True
    assert snap["status"] == "Completed Successfully"
    assert snap["progress_percent"] == 100.0
    assert snap["log"] == "[+] done"


def test_active_true_is_never_suppressed_only_false_is():
    jobs.update_job(active=False)
    jobs.begin_suppress_active_false()
    jobs.update_job(active=True)
    assert jobs.snapshot_job()["active"] is True  # active=True always passes through


def test_suppress_flag_is_a_simple_toggle_not_a_counter():
    # No nested begin/end reference-counting - a second begin() while
    # already suppressed, then one end(), fully clears suppression (matches
    # Auto Analyze's own usage: one begin/end pair per wrapped step, never
    # nested calls).
    jobs.begin_suppress_active_false()
    jobs.begin_suppress_active_false()
    jobs.end_suppress_active_false()
    jobs.update_job(active=True)
    jobs.update_job(active=False)
    assert jobs.snapshot_job()["active"] is False
