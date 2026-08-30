"""_collect_case_timeline()'s folder-based candidate handling (2026-08-29) -
the fix for "an Android pull/iOS backup/Logical Acquisition has no Evidence
Timeline option" (there's no walkable disk image, only real files copied
onto a real filesystem, so this walks that folder directly via os.walk() +
os.stat() instead of pytsk3). The image-based candidate path (real disk
images via pytsk3) already has no test coverage of its own - this file only
covers the new folder-based path added alongside it, not a rewrite of the
whole function.

POSIX-gated like every other routes.reporting test in this suite:
routes.reporting imports core.jobs (pwd/fcntl) at module level, so the whole
module - not just this new logic - can't import on Windows."""
import os
import sys
import json
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

pytest.importorskip("routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from routes.reporting import _collect_case_timeline  # noqa: E402


def _make_event(evidence_id, tool, output_destination=None, output_image_path=None,
                 status="COMPLETED", timestamp_start="2026-08-29 10:00:00"):
    params = {}
    if output_destination:
        params["output_destination"] = output_destination
    if output_image_path:
        params["output_image_path"] = output_image_path
    return {
        "tool": tool,
        "acquisition_status": status,
        "timestamp_start": timestamp_start,
        "case_metadata": {"evidence_id": evidence_id},
        "acquisition_parameters": params,
    }


def _touch(path, mtime_epoch):
    with open(path, "w") as f:
        f.write("x")
    os.utime(path, (mtime_epoch, mtime_epoch))


def _write_device_manifest(dest_path, files):
    """Writes the exact sidecar shape execution_worker_android()
    (routes/mobile.py) writes after a real adb pull - same naming
    convention _collect_case_timeline() looks for: "{dest_path}_
    device_timestamps.json", a sibling of the pull's own output folder."""
    manifest_path = f"{dest_path.rstrip(os.sep)}_device_timestamps.json"
    with open(manifest_path, "w") as f:
        json.dump({"source": "adb shell find -H /sdcard -type f -printf '%p|%T@'",
                   "captured_at": "2026-08-29 10:00:00", "files": files}, f)
    return manifest_path


def test_folder_candidate_produces_real_macb_events(evidence_root):
    """The core fix: a mobile-pull-style event with no output_image_path but
    a real output_destination folder still yields real M/A/C timeline
    entries from the files it actually copied."""
    pulled_dir = os.path.join(evidence_root, "PIXEL8A-01_android_pull")
    os.makedirs(pulled_dir)
    known_mtime = 1700000000
    _touch(os.path.join(pulled_dir, "photo.jpg"), known_mtime)

    event = _make_event("PIXEL8A-01", "android_pull", output_destination=pulled_dir)
    result = _collect_case_timeline([event])

    assert result["events"], "expected at least one MACB event from the pulled folder"
    activities = {e["activity"] for e in result["events"]}
    assert "M" in activities and "A" in activities and "C" in activities
    for e in result["events"]:
        assert e["evidence_id"] == "PIXEL8A-01"
        assert e["path"] == "/photo.jpg"
        assert e["deleted"] is False
        assert "android_pull" in e["filesystem"]
    # at least the Modified event should carry the exact mtime we set
    m_events = [e for e in result["events"] if e["activity"] == "M"]
    assert any(abs(e["timestamp"] - known_mtime) < 2 for e in m_events)


def test_output_image_path_event_is_not_also_treated_as_a_folder(evidence_root):
    """An event that already has output_image_path (a real disk image) must
    never ALSO be walked as a folder candidate, even if it happens to also
    carry an output_destination pointing at the same directory - it's
    already covered by the image-based path."""
    case_dir = os.path.join(evidence_root, "case")
    os.makedirs(case_dir)
    fake_image = os.path.join(case_dir, "USBDrive-1.dd")
    with open(fake_image, "wb") as f:
        f.write(b"not a real image, just needs to exist")

    event = _make_event("USBDrive-1", "dd", output_destination=case_dir, output_image_path=fake_image)
    result = _collect_case_timeline([event])
    # the fake image has no real filesystem pytsk3 can open, so the image
    # path correctly produces zero events + a "no recognized filesystem"
    # note - the real assertion here is that it did NOT fall through to the
    # folder-walk path and dump every file under case_dir as M/A/C events.
    assert result["events"] == []
    assert any("no recognized filesystem" in n for n in result["notes"])


def test_failed_event_folder_is_skipped(evidence_root):
    pulled_dir = os.path.join(evidence_root, "ITEM-01_android_pull")
    os.makedirs(pulled_dir)
    _touch(os.path.join(pulled_dir, "file.txt"), 1700000000)

    event = _make_event("ITEM-01", "android_pull", output_destination=pulled_dir, status="FAILED")
    result = _collect_case_timeline([event])
    assert result["events"] == []


def test_file_destination_not_directory_is_skipped(evidence_root):
    """android_backup/bugreport also set output_destination, but it's a
    single .ab/.zip FILE, not a folder - must be excluded, not crash."""
    backup_file = os.path.join(evidence_root, "ITEM-01_android_backup.ab")
    with open(backup_file, "wb") as f:
        f.write(b"fake android backup blob")

    event = _make_event("ITEM-01", "android_backup", output_destination=backup_file)
    result = _collect_case_timeline([event])
    assert result["events"] == []


def test_two_events_sharing_the_same_destination_dedup_to_the_latest(evidence_root):
    """Mirrors the disk-image path's own ddrescue-multi-pass dedup: a
    re-run mobile pull against an unchanged Case#/Evidence ID lands in the
    exact same destination folder - only the latest event should drive the
    walk, and a "superseded" note should be recorded."""
    pulled_dir = os.path.join(evidence_root, "ITEM-01_android_pull")
    os.makedirs(pulled_dir)
    _touch(os.path.join(pulled_dir, "file.txt"), 1700000000)

    earlier = _make_event("ITEM-01", "android_pull", output_destination=pulled_dir,
                           timestamp_start="2026-08-29 09:00:00")
    later = _make_event("ITEM-01", "android_pull", output_destination=pulled_dir,
                         timestamp_start="2026-08-29 10:00:00")
    result = _collect_case_timeline([earlier, later])

    assert result["events"], "the folder should still be walked exactly once"
    assert any("earlier completed acquisition pass" in n and "same output folder" in n for n in result["notes"])


def test_logical_acquisition_uses_output_container_path(evidence_root):
    """Logical Acquisition sets output_container_path, not
    output_destination - confirm the second field name is also honored."""
    logical_dir = os.path.join(evidence_root, "ITEM-01_logical")
    os.makedirs(logical_dir)
    _touch(os.path.join(logical_dir, "document.pdf"), 1700000000)

    event = _make_event("ITEM-01", "logical_acquisition", status="COMPLETED",
                         timestamp_start="2026-08-29 10:00:00")
    event["acquisition_parameters"]["output_container_path"] = logical_dir
    result = _collect_case_timeline([event])

    assert result["events"]
    assert all(e["path"] == "/document.pdf" for e in result["events"])
    assert all("logical_acquisition" in e["filesystem"] for e in result["events"])


def test_android_pull_discloses_that_adb_does_not_preserve_timestamps(evidence_root):
    """adb pull stamps the local copy time onto every file rather than
    carrying the phone's real mtime across - empirically confirmed against
    real device output (2026-08-29). Every android_pull folder candidate
    must carry an explicit disclosure note about this, so an examiner never
    mistakes the copy date for genuine on-device activity."""
    pulled_dir = os.path.join(evidence_root, "PIXEL8A-01_android_pull")
    os.makedirs(pulled_dir)
    _touch(os.path.join(pulled_dir, "photo.jpg"), 1700000000)

    event = _make_event("PIXEL8A-01", "android_pull", output_destination=pulled_dir)
    result = _collect_case_timeline([event])

    assert any("PIXEL8A-01" in n and "adb pull does not preserve" in n for n in result["notes"])


def test_logical_acquisition_gets_no_adb_disclosure_note(evidence_root):
    """The adb-specific disclosure is scoped to android_pull only -
    Logical Acquisition's own shutil.copy2() genuinely does preserve source
    mtime, so it must never carry a note implying otherwise."""
    logical_dir = os.path.join(evidence_root, "ITEM-01_logical")
    os.makedirs(logical_dir)
    _touch(os.path.join(logical_dir, "document.pdf"), 1700000000)

    event = _make_event("ITEM-01", "logical_acquisition", status="COMPLETED",
                         timestamp_start="2026-08-29 10:00:00")
    event["acquisition_parameters"]["output_container_path"] = logical_dir
    result = _collect_case_timeline([event])

    assert not any("adb pull does not preserve" in n for n in result["notes"])


def test_android_pull_with_device_manifest_uses_real_on_device_mtime(evidence_root):
    """The core of the follow-up fix: when execution_worker_android()'s own
    sidecar manifest exists for this pull, a file listed in it gets exactly
    ONE genuine 'M' event using the manifest's real captured timestamp - not
    the copy-time os.lstat() value, and not a fabricated A/C/B alongside it."""
    pulled_dir = os.path.join(evidence_root, "PIXEL8A-01_android_pull")
    os.makedirs(pulled_dir)
    copy_time = 1900000000  # the moment the file was copied - what the OLD, wrong behavior would show
    real_device_time = 1721818354  # a genuinely earlier, real on-device modification time
    _touch(os.path.join(pulled_dir, "Screenshot_20260724-102354.png"), copy_time)
    _write_device_manifest(pulled_dir, {"Screenshot_20260724-102354.png": real_device_time})

    event = _make_event("PIXEL8A-01", "android_pull", output_destination=pulled_dir)
    result = _collect_case_timeline([event])

    matching = [e for e in result["events"] if e["path"] == "/Screenshot_20260724-102354.png"]
    assert len(matching) == 1, "exactly one event for this file - no fabricated A/C/B alongside the real M"
    assert matching[0]["activity"] == "M"
    assert matching[0]["timestamp"] == real_device_time
    assert matching[0]["timestamp"] != copy_time
    assert "real device timestamp" in matching[0]["filesystem"]
    # a genuine manifest hit means the "adb pull does not preserve" note is no longer true
    assert not any("adb pull does not preserve" in n for n in result["notes"])


def test_android_pull_manifest_falls_back_per_file_when_incomplete(evidence_root):
    """A file NOT present in an otherwise-real manifest (e.g. added to the
    phone after the timestamp capture ran, before the pull finished copying
    it) falls back to copy-time for just that one file, and the folder gets
    a distinct "N file(s) have no captured..." note - not the blanket
    "adb pull does not preserve" note, since most of the folder DOES have
    real device timestamps."""
    pulled_dir = os.path.join(evidence_root, "PIXEL8A-01_android_pull")
    os.makedirs(pulled_dir)
    _touch(os.path.join(pulled_dir, "captured.jpg"), 1900000000)
    _touch(os.path.join(pulled_dir, "not_in_manifest.jpg"), 1900000001)
    _write_device_manifest(pulled_dir, {"captured.jpg": 1721818354})

    event = _make_event("PIXEL8A-01", "android_pull", output_destination=pulled_dir)
    result = _collect_case_timeline([event])

    captured_events = [e for e in result["events"] if e["path"] == "/captured.jpg"]
    fallback_events = [e for e in result["events"] if e["path"] == "/not_in_manifest.jpg"]
    assert len(captured_events) == 1 and captured_events[0]["activity"] == "M"
    assert len(fallback_events) >= 1  # copy-time M/A/C, same as the no-manifest-at-all path
    assert any("no captured on-device timestamp" in n for n in result["notes"])
    assert not any("adb pull does not preserve" in n for n in result["notes"])


def test_android_pull_with_no_manifest_file_keeps_original_fallback_behavior(evidence_root):
    """Regression guard: a pull with genuinely no manifest on disk at all
    (the common case for every pull made before this feature shipped) must
    behave byte-for-byte as it did before this whole follow-up - full
    copy-time M/A/C and the original blanket disclosure note."""
    pulled_dir = os.path.join(evidence_root, "PIXEL8A-01_android_pull")
    os.makedirs(pulled_dir)
    _touch(os.path.join(pulled_dir, "photo.jpg"), 1700000000)

    event = _make_event("PIXEL8A-01", "android_pull", output_destination=pulled_dir)
    result = _collect_case_timeline([event])

    activities = {e["activity"] for e in result["events"] if e["path"] == "/photo.jpg"}
    assert "M" in activities and "A" in activities and "C" in activities
    assert all("real filesystem" in e["filesystem"] for e in result["events"] if e["path"] == "/photo.jpg")
    assert any("adb pull does not preserve" in n for n in result["notes"])
