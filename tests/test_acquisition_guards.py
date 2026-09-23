"""Acquisition safety guards added in the 2026-09-23 Mobile/Acquisition review.

core/paths.py parts run everywhere; the job-slot parts need core.jobs
(POSIX-only pwd/fcntl) and skip on a non-POSIX dev machine.
"""
import threading
from unittest import mock

import pytest

import core.paths as paths


def test_system_disk_and_its_partitions_are_not_valid_devices():
    with mock.patch.object(paths, "system_disk_names", return_value={"mmcblk0"}):
        assert paths.is_valid_block_device("/dev/mmcblk0") is False
        assert paths.is_valid_block_device_or_partition("/dev/mmcblk0p2") is False
        assert paths.is_valid_block_device("/dev/sda") is True
        assert paths.is_valid_block_device("/dev/mmcblk1") is True


def test_destination_on_the_source_device_is_detected():
    with mock.patch.object(paths, "disk_name_for_path", return_value="sdb"):
        assert paths.destination_is_on_source_device("/mnt/usb_sdb1/case", "/dev/sdb") is True
        assert paths.destination_is_on_source_device("/mnt/usb_sdb1/case", "/dev/sda") is False
    with mock.patch.object(paths, "disk_name_for_path", return_value=None):  # NFS etc.
        assert paths.destination_is_on_source_device("/mnt/nfs/case", "/dev/sda") is False


try:
    import core.jobs as jobs
except ImportError:  # pwd/fcntl on a non-POSIX dev machine
    jobs = None
posix_only = pytest.mark.skipif(jobs is None, reason="core.jobs imports POSIX-only pwd/fcntl")


def _claim():
    with jobs.job_lock:
        jobs.current_job["active"] = True
        jobs.mark_job_slot_claimed()


@posix_only
def test_a_stopped_jobs_worker_cannot_release_the_next_jobs_slot():
    """Reviewed 2026-09-23: after Stop, the old worker's closing
    update_job(active=False) freed the NEW job's slot."""
    jobs.update_job(active=False)
    _claim()                                   # job 1
    ready, go, done = threading.Event(), threading.Event(), threading.Event()

    def old_worker():
        jobs.update_job(status="imaging")      # binds this thread to job 1
        ready.set()
        go.wait(5)
        jobs.update_job(active=False, log="old worker finished")
        done.set()

    t = threading.Thread(target=old_worker)
    t.start()
    ready.wait(5)
    jobs.update_job(active=False)              # Stop (request side)
    _claim()                                   # job 2 claims the slot
    jobs.update_job(log="job 2 running")
    go.set()
    done.wait(5)
    t.join(5)
    snap = jobs.snapshot_job()
    assert snap["active"] is True
    assert snap["log"] == "job 2 running"
    jobs.update_job(active=False)


@posix_only
def test_a_workers_own_release_still_works_when_nothing_superseded_it():
    jobs.update_job(active=False)
    _claim()

    def worker():
        jobs.update_job(status="x")
        jobs.update_job(active=False)

    t = threading.Thread(target=worker)
    t.start()
    t.join(5)
    assert jobs.snapshot_job()["active"] is False
