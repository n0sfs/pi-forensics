"""routes/file_explorer.py's F2FS mount/unmount routes and _f2fs_mount()/
_f2fs_unmount() helpers (2026-09-05).

Mirrors this project's own established mock-the-real-subprocess-work pattern
for a mount mechanism this large - the same approach already used for
routes.recovery's execution_worker_extundelete() (test_extundelete_error_
messages.py) and routes.mobile's companion-app workers, and matching the
already-disclosed precedent that BitLocker/LUKS/VeraCrypt's own subprocess-
wrapping mount functions carry no unit test coverage at all, verified live
against real hardware instead - here, the routes' own input-validation/
collision-guard logic and the two-subprocess-call (losetup-then-mount) /
three-subprocess-call (losetup-then-mount-then-bindfs) control flow ARE
worth locking in with mocked tests, since a wrong argument order or a
skipped cleanup step on a failure path is exactly the class of bug this
project has repeatedly found only by either reading the code very carefully
or running it for real - a mocked test closes that gap cheaply here.

Skipped (not failed) on a non-POSIX dev machine: routes.file_explorer needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.file_explorer as file_explorer


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def _clear_f2fs_mounts():
    """Every test starts and ends with a clean active_f2fs_mounts dict -
    this module-level state would otherwise leak between tests, the same
    class of risk this project's own conftest.py fixtures already guard
    against for core.auth's lockout dicts and core.case_index_db's
    tags-flagged cache."""
    file_explorer.active_f2fs_mounts.clear()
    yield
    file_explorer.active_f2fs_mounts.clear()


class TestF2fsMountValidation:
    """Paths that fail before any subprocess call is ever made."""

    def test_rejects_a_nonexistent_image_path(self, evidence_root, tmp_path):
        dest = os.path.join(evidence_root, "case1")
        os.makedirs(dest)
        success, mount_id, browse_dir, error = file_explorer._f2fs_mount(
            os.path.join(evidence_root, "does_not_exist.dd"), 0, dest
        )
        assert success is False
        assert mount_id is None and browse_dir is None
        assert "not found" in error.lower()

    def test_rejects_a_destination_outside_evidence_root(self, evidence_root, tmp_path):
        image = os.path.join(evidence_root, "image.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 0, str(tmp_path / "outside"))
        assert success is False
        assert "destination" in error.lower()

    def test_rejects_an_invalid_offset(self, evidence_root):
        image = os.path.join(evidence_root, "image.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        success, _, _, error = file_explorer._f2fs_mount(image, "not-a-number", evidence_root)
        assert success is False
        assert "offset" in error.lower()

    def test_rejects_a_negative_offset(self, evidence_root):
        image = os.path.join(evidence_root, "image.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        success, _, _, error = file_explorer._f2fs_mount(image, -1, evidence_root)
        assert success is False
        assert "offset" in error.lower()

    def test_refuses_to_overwrite_an_existing_mount_folder(self, evidence_root):
        image = os.path.join(evidence_root, "image.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        # Simulate a browse_dir that already exists (e.g. left over from an
        # earlier, un-cleaned-up mount, or a real folder of that name).
        existing = os.path.join(evidence_root, "image.dd_f2fs_mounted")
        os.makedirs(existing)
        success, _, _, error = file_explorer._f2fs_mount(image, 0, evidence_root)
        assert success is False
        assert "already exists" in error.lower()


class TestF2fsMountOffsetZero:
    """offset=0: mount(8) is given the image file directly with -o ro,loop -
    no separate losetup call needed at all."""

    def test_happy_path_never_calls_losetup(self, evidence_root):
        image = os.path.join(evidence_root, "whole.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.side_effect = [_proc(0), _proc(0)]  # mount, then bindfs
            with mock.patch("os.path.ismount", return_value=True):
                success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 0, evidence_root)
        assert success is True
        assert error is None
        assert mount_id is not None
        assert browse_dir == os.path.join(evidence_root, "whole.dd_f2fs_mounted")
        assert mount_id in file_explorer.active_f2fs_mounts
        assert file_explorer.active_f2fs_mounts[mount_id]["loop_device"] is None
        # Confirm exactly 2 subprocess calls (mount, bindfs) - no losetup.
        assert mock_run.call_count == 2
        mount_cmd = mock_run.call_args_list[0][0][0]
        assert "ro,loop" in mount_cmd
        assert "-t" in mount_cmd and "f2fs" in mount_cmd
        bindfs_cmd = mock_run.call_args_list[1][0][0]
        assert any(a.startswith("--force-user=") for a in bindfs_cmd)
        assert any(a.startswith("--force-group=") for a in bindfs_cmd)

    def test_a_mount_failure_is_reported_and_cleans_up(self, evidence_root):
        image = os.path.join(evidence_root, "whole.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * 4096)
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.return_value = _proc(1, stderr="wrong fs magic")
            success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 0, evidence_root)
        assert success is False
        assert mount_id is None
        assert "mount failed" in error.lower()
        assert file_explorer.active_f2fs_mounts == {}
        # The mount folder must not be silently left behind on a failed mount.
        assert not os.path.exists(os.path.join(evidence_root, "whole.dd_f2fs_mounted"))


class TestF2fsMountOffsetNonzero:
    """offset>0: a loop device is created first (mirrors _luks_unlock()'s
    own identical pattern for a LUKS container embedded partway through a
    larger multi-partition image), and the mount targets that loop device,
    never the raw image file directly."""

    def test_happy_path_creates_a_loop_device_before_mounting(self, evidence_root):
        image = os.path.join(evidence_root, "disk.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * (2 * 1024 * 1024))
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(0, stdout="/dev/loop7\n"),  # losetup
                _proc(0),  # mount
                _proc(0),  # bindfs
            ]
            with mock.patch("os.path.ismount", return_value=True):
                success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 1048576, evidence_root)
        assert success is True
        assert file_explorer.active_f2fs_mounts[mount_id]["loop_device"] == "/dev/loop7"
        assert mock_run.call_count == 3
        losetup_cmd = mock_run.call_args_list[0][0][0]
        assert "-o" in losetup_cmd and "1048576" in losetup_cmd
        mount_cmd = mock_run.call_args_list[1][0][0]
        assert "/dev/loop7" in mount_cmd
        assert "ro,loop" not in mount_cmd  # no implicit-loop option needed - a real loop device was already attached

    def test_a_losetup_failure_never_attempts_to_mount(self, evidence_root):
        image = os.path.join(evidence_root, "disk.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * (2 * 1024 * 1024))
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.return_value = _proc(1, stderr="losetup: could not find a free loop device")
            success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 1048576, evidence_root)
        assert success is False
        assert "loop device" in error.lower()
        assert mock_run.call_count == 1  # only losetup was ever attempted

    def test_a_mount_failure_after_a_successful_losetup_detaches_the_loop_device(self, evidence_root):
        image = os.path.join(evidence_root, "disk.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * (2 * 1024 * 1024))
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(0, stdout="/dev/loop9\n"),  # losetup succeeds
                _proc(1, stderr="mount: unknown filesystem type 'f2fs'"),  # mount fails
                _proc(0),  # the losetup -d cleanup call
            ]
            success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 1048576, evidence_root)
        assert success is False
        cleanup_cmd = mock_run.call_args_list[2][0][0]
        assert "-d" in cleanup_cmd and "/dev/loop9" in cleanup_cmd

    def test_a_bindfs_failure_tears_down_both_the_kernel_mount_and_the_loop_device(self, evidence_root):
        image = os.path.join(evidence_root, "disk.dd")
        with open(image, "wb") as f:
            f.write(b"\x00" * (2 * 1024 * 1024))
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _proc(0, stdout="/dev/loop3\n"),  # losetup
                _proc(0),  # mount succeeds
                _proc(1, stderr="bindfs: permission denied"),  # bindfs fails
                _proc(0),  # umount (raw_dir) cleanup
                _proc(0),  # losetup -d cleanup
            ]
            success, mount_id, browse_dir, error = file_explorer._f2fs_mount(image, 1048576, evidence_root)
        assert success is False
        assert mount_id is None
        assert file_explorer.active_f2fs_mounts == {}
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert any(cmd[:2] == ["sudo", "/bin/umount"] for cmd in cmds)
        assert any("-d" in cmd and "/dev/loop3" in cmd for cmd in cmds)


class TestF2fsUnmount:
    def test_unknown_mount_id_is_a_safe_no_op(self):
        success, error = file_explorer._f2fs_unmount("does-not-exist")
        assert success is True
        assert error is None

    def test_none_mount_id_is_a_safe_no_op(self):
        success, error = file_explorer._f2fs_unmount(None)
        assert success is True

    def test_unmounts_bindfs_then_the_kernel_mount_then_detaches_the_loop_device(self, evidence_root, tmp_path):
        raw_dir = str(tmp_path / "raw")
        browse_dir = str(tmp_path / "browse")
        os.makedirs(raw_dir)
        os.makedirs(browse_dir)
        mount_id = "test-mount-id"
        file_explorer.active_f2fs_mounts[mount_id] = {
            "raw_dir": raw_dir, "browse_dir": browse_dir, "loop_device": "/dev/loop5",
            "image_path": "/mnt/case/disk.dd", "offset": 1048576, "mounted_at": "2026-01-01 00:00:00",
        }
        with mock.patch("routes.file_explorer.subprocess.run") as mock_run:
            mock_run.return_value = _proc(0)
            success, error = file_explorer._f2fs_unmount(mount_id)
        assert success is True
        assert mount_id not in file_explorer.active_f2fs_mounts
        cmds = [c[0][0] for c in mock_run.call_args_list]
        assert cmds[0] == ["sudo", "/bin/umount", browse_dir]  # bindfs unmounted FIRST (the outer layer)
        assert cmds[1] == ["sudo", "/bin/umount", raw_dir]     # then the kernel F2FS mount
        assert any("-d" in cmd and "/dev/loop5" in cmd for cmd in cmds)  # then the loop device
        assert not os.path.exists(raw_dir)
        assert not os.path.exists(browse_dir)

    def test_a_second_unmount_call_for_the_same_id_is_a_safe_no_op(self, tmp_path):
        raw_dir = str(tmp_path / "raw2")
        browse_dir = str(tmp_path / "browse2")
        os.makedirs(raw_dir)
        os.makedirs(browse_dir)
        mount_id = "test-mount-id-2"
        file_explorer.active_f2fs_mounts[mount_id] = {
            "raw_dir": raw_dir, "browse_dir": browse_dir, "loop_device": None,
            "image_path": "/mnt/case/whole.dd", "offset": 0, "mounted_at": "2026-01-01 00:00:00",
        }
        with mock.patch("routes.file_explorer.subprocess.run", return_value=_proc(0)):
            file_explorer._f2fs_unmount(mount_id)
            success, error = file_explorer._f2fs_unmount(mount_id)
        assert success is True
        assert error is None
