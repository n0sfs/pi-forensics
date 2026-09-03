"""core/live_collection_utils.py - the wipe/format/mount mechanics are
mocked at the subprocess.run() boundary (every real command's exact
invocation shape was independently confirmed live against a real
losetup-backed loop device on the deployed station before this module was
written - see the module's own docstring), so these tests exercise the
actual control flow (success/failure branching, the fast-path skip, the
device-safety ordering) rather than re-proving the underlying Linux tools
work. discover_collection_runs()/check_existing_collection_volume()'s own
name/regex/directory-walk logic is real, unmocked Python tested against a
real filesystem fixture."""
import os
import subprocess

import pytest

import core.live_collection_utils as lcu


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_check_existing_collection_volume_no_partition(tmp_path, monkeypatch):
    fake_device = str(tmp_path / "sdx")  # partition (sdx1) deliberately never created
    result = lcu.check_existing_collection_volume(fake_device)
    assert result["already_prepared"] is False
    assert "No existing partition" in result["reason"]


def test_check_existing_collection_volume_already_prepared(tmp_path, monkeypatch):
    device = str(tmp_path / "sdx")
    partition = device + "1"
    open(partition, "w").close()

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["sudo", "blkid"]
        return _FakeCompletedProcess(0, stdout=f"TYPE=exfat\nLABEL={lcu.PIF_COLLECT_LABEL}\n")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.check_existing_collection_volume(device)
    assert result["already_prepared"] is True


def test_check_existing_collection_volume_wrong_label_not_prepared(tmp_path, monkeypatch):
    device = str(tmp_path / "sdx")
    open(device + "1", "w").close()

    def fake_run(cmd, **kwargs):
        return _FakeCompletedProcess(0, stdout="TYPE=exfat\nLABEL=SOMETHING_ELSE\n")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.check_existing_collection_volume(device)
    assert result["already_prepared"] is False
    assert "SOMETHING_ELSE" in result["reason"]


def test_check_existing_collection_volume_multi_partition_not_fast_pathed(tmp_path, monkeypatch):
    device = str(tmp_path / "sdx")
    open(device + "1", "w").close()
    open(device + "2", "w").close()  # a second partition - not the shape this feature creates

    def fake_run(cmd, **kwargs):
        return _FakeCompletedProcess(0, stdout=f"TYPE=exfat\nLABEL={lcu.PIF_COLLECT_LABEL}\n")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.check_existing_collection_volume(device)
    assert result["already_prepared"] is False


def test_check_existing_collection_volume_blkid_failure_treated_as_not_prepared(tmp_path, monkeypatch):
    device = str(tmp_path / "sdx")
    open(device + "1", "w").close()

    def fake_run(cmd, **kwargs):
        return _FakeCompletedProcess(1, stderr="blkid: error")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.check_existing_collection_volume(device)
    assert result["already_prepared"] is False


def test_wipe_and_format_device_full_success_sequence(monkeypatch, tmp_path):
    device = str(tmp_path / "sdx")
    partition = device + "1"
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["sudo", lcu.WIPEFS_BIN, "-a"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.SFDISK_BIN]:
            assert kwargs.get("input") == "label: dos\nstart=2048, type=7\n"
            open(partition, "w").close()  # simulate the kernel creating the partition node
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.BLOCKDEV_BIN]:
            return _FakeCompletedProcess(0)
        if cmd[:1] == ["udevadm"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.MKFS_EXFAT_BIN]:
            assert "-n" in cmd and lcu.PIF_COLLECT_LABEL in cmd
            return _FakeCompletedProcess(0)
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    log_lines = []
    result = lcu.wipe_and_format_device(device, append_log=log_lines.append)
    assert result["success"] is True
    assert result["partition_device"] == partition
    # confirms the real command ORDER: wipefs before sfdisk before mkfs
    step_names = [c[1] for c in calls if c[0] == "sudo" and c[1] in (lcu.WIPEFS_BIN, lcu.SFDISK_BIN, lcu.MKFS_EXFAT_BIN)]
    assert step_names == [lcu.WIPEFS_BIN, lcu.SFDISK_BIN, lcu.MKFS_EXFAT_BIN]
    assert any("Wiping" in line for line in log_lines)


def test_wipe_and_format_device_explicitly_unlocks_the_partition_before_mkfs(monkeypatch, tmp_path):
    # Real bug found live (2026-09-03) against a real USB drive: this
    # station's write-block udev rules independently re-lock a freshly-
    # created partition device the instant sfdisk makes it, regardless of
    # the whole-disk unlock the caller already did before wipefs/sfdisk ran
    # - mkfs.exfat then fails with "write failed(errno : 1)" (EPERM). This
    # asserts the fix's own ordering requirement directly: a
    # "blockdev --setrw <partition>" call must appear strictly after the
    # partition device exists and strictly before mkfs.exfat runs - not
    # just that the call happens somewhere.
    device = str(tmp_path / "sdx")
    partition = device + "1"
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["sudo", lcu.WIPEFS_BIN, "-a"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.SFDISK_BIN]:
            open(partition, "w").close()
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.BLOCKDEV_BIN]:
            return _FakeCompletedProcess(0)
        if cmd[:1] == ["udevadm"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.MKFS_EXFAT_BIN]:
            return _FakeCompletedProcess(0)
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.wipe_and_format_device(device)
    assert result["success"] is True

    setrw_partition_calls = [
        i for i, c in enumerate(calls)
        if c[:2] == ["sudo", lcu.BLOCKDEV_BIN] and "--setrw" in c and partition in c
    ]
    mkfs_calls = [i for i, c in enumerate(calls) if c[:2] == ["sudo", lcu.MKFS_EXFAT_BIN]]
    assert len(setrw_partition_calls) == 1, "wipe_and_format_device must explicitly unlock the partition device for write, not just the whole disk"
    assert setrw_partition_calls[0] < mkfs_calls[0], "the partition unlock must happen before mkfs.exfat runs, or mkfs will fail with EPERM"


def test_wipe_and_format_device_wipefs_failure_stops_before_partitioning(monkeypatch, tmp_path):
    device = str(tmp_path / "sdx")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["sudo", lcu.WIPEFS_BIN, "-a"]:
            return _FakeCompletedProcess(1, stderr="wipefs: permission denied")
        raise AssertionError(f"sfdisk/mkfs should never be reached after a wipefs failure: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.wipe_and_format_device(device)
    assert result["success"] is False
    assert "wipefs failed" in result["error"]
    assert result["partition_device"] is None


def test_wipe_and_format_device_sfdisk_failure_stops_before_mkfs(monkeypatch, tmp_path):
    device = str(tmp_path / "sdx")

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["sudo", lcu.WIPEFS_BIN, "-a"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.SFDISK_BIN]:
            return _FakeCompletedProcess(1, stderr="sfdisk: bad partition table")
        raise AssertionError(f"mkfs should never be reached after an sfdisk failure: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.wipe_and_format_device(device)
    assert result["success"] is False
    assert "sfdisk failed" in result["error"]


def test_wipe_and_format_device_partition_never_appears_is_caught(monkeypatch, tmp_path):
    # The real gotcha this module's own docstring documents: mkfs racing an
    # unrefreshed partition table. If the partition device node genuinely
    # never appears (even after --rereadpt + udevadm settle), this must be
    # caught explicitly rather than handing a nonexistent path to mkfs.
    device = str(tmp_path / "sdx")

    def fake_run(cmd, **kwargs):
        if cmd[0] == "sudo" and cmd[1] in (lcu.WIPEFS_BIN, lcu.SFDISK_BIN, lcu.BLOCKDEV_BIN):
            return _FakeCompletedProcess(0)  # note: never actually creates the partition file
        if cmd[:1] == ["udevadm"]:
            return _FakeCompletedProcess(0)
        raise AssertionError(f"mkfs should never be reached: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.wipe_and_format_device(device)
    assert result["success"] is False
    assert "never appeared" in result["error"]


def test_wipe_and_format_device_survives_a_slow_rereadpt_and_settle_on_real_hardware(monkeypatch, tmp_path):
    # Real bug found live (2026-09-03), on the same real physical USB
    # drive that surfaced the partition-lock bug above: `udevadm settle`
    # measured under 2s standalone on this exact station's idle system,
    # but genuinely timed out at 15s twice in a row during this real
    # sequence - real USB flash is slower to re-scan than the fast
    # loopback devices this module's own design/spike testing used. Since
    # the actual safety net here is the *next* check (does the partition
    # file genuinely exist), not rereadpt/settle finishing within their own
    # timeout, both calls timing out must not crash the whole function - as
    # long as the partition eventually, genuinely appears (simulated here
    # by the sfdisk mock still creating the file), formatting should
    # proceed normally.
    device = str(tmp_path / "sdx")
    partition = device + "1"

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["sudo", lcu.WIPEFS_BIN, "-a"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.SFDISK_BIN]:
            open(partition, "w").close()
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", lcu.BLOCKDEV_BIN] and "--rereadpt" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if cmd[:2] == ["sudo", lcu.BLOCKDEV_BIN] and "--setrw" in cmd:
            return _FakeCompletedProcess(0)
        if cmd[:1] == ["udevadm"]:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if cmd[:2] == ["sudo", lcu.MKFS_EXFAT_BIN]:
            return _FakeCompletedProcess(0)
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.wipe_and_format_device(device)  # must not raise
    assert result["success"] is True
    assert result["partition_device"] == partition


def test_mount_collection_partition_builds_correct_uid_gid_options(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    mountpoint = str(tmp_path / "mnt")
    result = lcu.mount_collection_partition("/dev/sdx1", mountpoint, uid=1000, gid=1000, read_only=False)
    assert result["success"] is True
    assert os.path.isdir(mountpoint)
    assert captured["cmd"] == ["sudo", "mount", "-t", "exfat", "-o", "uid=1000,gid=1000", "/dev/sdx1", mountpoint]


def test_mount_collection_partition_read_only_adds_ro_flag(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    lcu.mount_collection_partition("/dev/sdx1", str(tmp_path / "mnt"), uid=1000, gid=1000, read_only=True)
    assert captured["cmd"][5] == "uid=1000,gid=1000,ro"


def test_mount_collection_partition_failure_surfaces_stderr(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        return _FakeCompletedProcess(1, stderr="mount: wrong fs type")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.mount_collection_partition("/dev/sdx1", str(tmp_path / "mnt"), uid=1000, gid=1000)
    assert result["success"] is False
    assert "wrong fs type" in result["error"]


def test_unmount_collection_partition_clean_success_has_no_warning(monkeypatch, tmp_path):
    mountpoint = str(tmp_path / "mnt")
    os.makedirs(mountpoint)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeCompletedProcess(0)

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.unmount_collection_partition(mountpoint)
    assert result == {"success": True, "warning": None}
    # sync must run BEFORE umount, not after - the whole point is giving
    # the write-back flush its own timeline ahead of umount's own wait.
    assert calls[0] == ["sync"]
    assert calls[1] == ["sudo", "umount", mountpoint]
    assert not os.path.isdir(mountpoint)  # best-effort rmdir still ran


def test_unmount_collection_partition_umount_timeout_never_raises_but_warns(monkeypatch, tmp_path):
    # Real bug found live (2026-09-03) against a real physical USB drive:
    # this function's own docstring already promised "never raises," but
    # had no try/except around the actual umount subprocess.run() call at
    # all - a real TimeoutExpired on a slow real device escaped straight up
    # into the caller, failing the whole job even though the asset copy had
    # already fully succeeded. This proves the fix directly: a timed-out
    # umount must be swallowed, not raised, while still being reported back
    # via "warning" so the caller can decide how (or whether) to surface it.
    mountpoint = str(tmp_path / "mnt")
    os.makedirs(mountpoint)

    def fake_run(cmd, **kwargs):
        if cmd == ["sync"]:
            return _FakeCompletedProcess(0)
        if cmd[:2] == ["sudo", "umount"]:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.unmount_collection_partition(mountpoint)  # must not raise
    assert result["success"] is False
    assert "did not finish" in result["warning"]
    assert not os.path.isdir(mountpoint)  # cleanup still attempted despite the timeout


def test_unmount_collection_partition_sync_timeout_is_recorded_even_if_umount_then_succeeds(monkeypatch, tmp_path):
    mountpoint = str(tmp_path / "mnt")
    os.makedirs(mountpoint)

    def fake_run(cmd, **kwargs):
        if cmd == ["sync"]:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if cmd[:2] == ["sudo", "umount"]:
            return _FakeCompletedProcess(0)
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(lcu.subprocess, "run", fake_run)
    result = lcu.unmount_collection_partition(mountpoint)
    # umount itself succeeding doesn't erase the fact that sync never
    # confirmed everything was flushed first - still worth surfacing.
    assert result["success"] is False
    assert "sync" in result["warning"].lower()


def test_discover_collection_runs_finds_both_platforms(tmp_path):
    root = tmp_path
    uac_run = root / "uac" / "output" / "uac-testhost-linux-20260901T120000Z"
    uac_run.mkdir(parents=True)
    (uac_run / "processes.json").write_text("[]")
    (uac_run / "network.json").write_text("[]")

    win_run = root / "windows" / "results" / "WINHOST_20260901_130000"
    win_run.mkdir(parents=True)
    (win_run / "processes.json").write_text("[]")

    runs = lcu.discover_collection_runs(str(root))
    assert len(runs) == 2

    unix_run = next(r for r in runs if r["platform"] == "unix")
    assert unix_run["hostname"] == "testhost"
    assert unix_run["file_count"] == 2

    windows_run = next(r for r in runs if r["platform"] == "windows")
    assert windows_run["hostname"] == "WINHOST"
    assert windows_run["timestamp"] == "20260901_130000"
    assert windows_run["file_count"] == 1


def test_discover_collection_runs_skips_empty_run_directories(tmp_path):
    empty_run = tmp_path / "uac" / "output" / "uac-host-linux-20260901T120000Z"
    empty_run.mkdir(parents=True)  # no files inside - a run that started but never finished
    runs = lcu.discover_collection_runs(str(tmp_path))
    assert runs == []


def test_discover_collection_runs_missing_roots_is_not_an_error(tmp_path):
    # A drive only ever used for one platform (or never used at all) has no
    # uac/output or windows/results directory at all - not an error.
    runs = lcu.discover_collection_runs(str(tmp_path))
    assert runs == []


def test_unmount_all_partitions_never_raises_on_nonexistent_device(monkeypatch):
    monkeypatch.setattr(lcu.subprocess, "run", lambda *a, **k: _FakeCompletedProcess(1))
    lcu.unmount_all_partitions("/dev/sdzz")  # no partitions match the glob - should be a silent no-op
