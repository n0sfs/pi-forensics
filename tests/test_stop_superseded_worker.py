"""core/jobs.py - what a worker that Stop superseded may still write
(2026-10-02 review).

Stop bumps the slot generation so the stopped worker can't overwrite "Stopped"
with "Completed Successfully" (2026-09-27). But Auto Analyze holds the slot
through Stop - suppression drops Stop's own active=False so a step that is
still mid-flight can't overlap a new job - and its closing active=False was
then dropped as stale too: the station stayed "busy" until Stop was pressed a
second time. A worker superseded by Stop (and by nothing newer) may now
append to the log and release the slot; its status/progress writes are still
dropped, and once a newer job claims the slot it may write nothing at all.

Skipped (not failed) on a non-POSIX dev machine: core.jobs imports POSIX-only
pwd/fcntl at module level.
"""
import threading

import pytest

pytest.importorskip("core.jobs", reason="core.jobs imports POSIX-only pwd/fcntl")

import core.jobs as jobs


@pytest.fixture(autouse=True)
def _clean_job_state():
    jobs.end_suppress_active_false()
    with jobs.job_lock:
        for key in ('_stopped_generation', '_stop_superseded_generation'):
            jobs.current_job.pop(key, None)
        jobs.current_job.update(active=True, status="Running", log="", progress_percent=0.0)
        jobs.current_job['_slot_generation'] = jobs.current_job.get('_slot_generation', 0) + 1
    yield
    jobs.end_suppress_active_false()
    with jobs.job_lock:
        jobs.current_job.update(active=False, status="IDLE")


def _in_worker_thread(fn):
    """Run fn in a fresh thread - the way every job worker runs - and wait."""
    errors = []

    def target():
        try:
            fn()
        except Exception as e:  # surfaced below, not swallowed
            errors.append(e)

    t = threading.Thread(target=target)
    t.start()
    t.join(5)
    assert not errors, errors


def _stop():
    """What stop_imaging() does to the job state (minus killing processes)."""
    jobs.update_job(status="Stopped", active=False)
    jobs.supersede_stopped_job()


def test_auto_analyze_releases_the_slot_after_a_single_stop():
    gate = threading.Event()
    done = threading.Event()

    def worker():
        jobs.begin_suppress_active_false()
        jobs.update_job(status="Step 1/3: Hash Manifest...")   # binds this thread to the job
        gate.wait(5)                                         # Stop lands here
        jobs.update_job(status="Completed Successfully")     # must NOT overwrite "Stopped"
        jobs.update_job(log="[!] Auto Analyze stopped by user - 1 of 3 step(s) completed.")
        jobs.end_suppress_active_false()
        jobs.update_job(active=False)
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    # Wait until the worker has bound itself, then Stop from this (request-like) thread.
    for _ in range(200):
        if jobs.snapshot_job()["status"].startswith("Step 1/3"):
            break
        threading.Event().wait(0.01)
    _stop()
    snap = jobs.snapshot_job()
    assert snap["active"] is True       # held: a step may still be mid-flight
    assert snap["status"] == "Stopped"
    gate.set()
    assert done.wait(5)
    t.join(5)

    snap = jobs.snapshot_job()
    assert snap["active"] is False      # one Stop was enough
    assert snap["status"] == "Stopped"  # not "Completed Successfully"
    assert "stopped by user" in snap["log"]


def test_a_stopped_worker_writes_nothing_once_a_newer_job_owns_the_slot():
    gate = threading.Event()
    bound = threading.Event()
    done = threading.Event()

    def worker():
        jobs.update_job(log="old job running")
        bound.set()
        gate.wait(5)
        jobs.update_job(log="old job's late line", status="Completed Successfully")
        jobs.update_job(active=False)
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    assert bound.wait(5)
    _stop()
    # A new job claims the slot before the old worker finishes.
    with jobs.job_lock:
        jobs.current_job["active"] = True
        jobs.current_job["status"] = "New job running"
        jobs.current_job["log"] = "new job"
        jobs.mark_job_slot_claimed()
    gate.set()
    assert done.wait(5)
    t.join(5)

    snap = jobs.snapshot_job()
    assert snap["active"] is True                # the NEW job's slot is untouched
    assert snap["status"] == "New job running"
    assert snap["log"] == "new job"


def test_a_second_stop_keeps_the_first_workers_right_to_release():
    gate = threading.Event()
    bound = threading.Event()
    done = threading.Event()

    def worker():
        jobs.begin_suppress_active_false()
        jobs.update_job(log="running")
        bound.set()
        gate.wait(5)
        jobs.end_suppress_active_false()
        jobs.update_job(active=False)
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    assert bound.wait(5)
    _stop()
    _stop()   # an impatient second press
    gate.set()
    assert done.wait(5)
    t.join(5)
    assert jobs.snapshot_job()["active"] is False


def test_a_superseded_worker_still_cannot_release_while_suppression_is_on():
    """The chained acquisition -> Auto Analyze run: the acquisition worker's
    own closing active=False must not free the slot while the chain (which
    still holds suppression) is finishing."""
    def worker():
        jobs.begin_suppress_active_false()
        jobs.update_job(log="acquiring")
        _stop()                      # Stop lands mid-acquisition
        jobs.update_job(active=False)   # the inner worker's own finally
        assert jobs.snapshot_job()["active"] is True
        jobs.end_suppress_active_false()  # the chain's finally
        jobs.update_job(active=False)
    _in_worker_thread(worker)
    assert jobs.snapshot_job()["active"] is False
