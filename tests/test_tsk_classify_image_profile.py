"""core/tsk_utils.py's classify_image_profile() (Auto Analyze, Phase 3,
2026-08-25) - Windows-vs-Linux filesystem-type detection built on top of
the already-hardened _tsk_resolve_filesystems() partition selection.

Uses monkeypatched _tsk_resolve_filesystems()/_tsk_open_fs() rather than a
real disk image - mkfs.ext4 isn't available on this dev machine (Windows),
and the real fs.info.ftype values were separately confirmed live against
the Pi's actual installed pytsk3 (fs.info.ftype == 8192 ==
pytsk3.TSK_FS_TYPE_EXT4 on a real ext4 test image) before this module was
written - this file tests classify_image_profile()'s own branching logic
(windows/linux/mixed/unknown bucketing across multiple partitions), not
pytsk3's own type-detection accuracy.

Skipped if pytsk3 isn't installed - a genuinely optional pip dependency
on a non-Pi dev machine (this project's own established reason for this
kind of skip, matching test_registry_utils.py's).
"""
import pytest

pytsk3 = pytest.importorskip("pytsk3", reason="pytsk3 not installed")

import core.tsk_utils as tsk


class _FakeFsInfo:
    def __init__(self, ftype):
        self.ftype = ftype


class _FakeFs:
    def __init__(self, ftype):
        self.info = _FakeFsInfo(ftype)


def test_classify_single_ntfs_partition_is_windows(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [{"offset": 0, "label": "NTFS"}])
    monkeypatch.setattr(tsk, "_tsk_open_fs", lambda p, o: _FakeFs(pytsk3.TSK_FS_TYPE_NTFS))
    result = tsk.classify_image_profile("fake.dd")
    assert result["profile"] == "windows"
    assert result["filesystems"][0]["fs_type"] == "NTFS"
    assert result["filesystems"][0]["bucket"] == "windows"


def test_classify_single_ext4_partition_is_linux(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [{"offset": 0, "label": "Linux"}])
    monkeypatch.setattr(tsk, "_tsk_open_fs", lambda p, o: _FakeFs(pytsk3.TSK_FS_TYPE_EXT4))
    result = tsk.classify_image_profile("fake.dd")
    assert result["profile"] == "linux"
    assert result["filesystems"][0]["fs_type"] == "ext4"


def test_classify_dual_boot_ntfs_and_ext4_is_mixed(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [
        {"offset": 0, "label": "NTFS"}, {"offset": 1000, "label": "Linux"},
    ])
    fakes = {0: _FakeFs(pytsk3.TSK_FS_TYPE_NTFS), 1000: _FakeFs(pytsk3.TSK_FS_TYPE_EXT4)}
    monkeypatch.setattr(tsk, "_tsk_open_fs", lambda p, o: fakes[o])
    result = tsk.classify_image_profile("fake.dd")
    assert result["profile"] == "mixed"
    buckets = {f["bucket"] for f in result["filesystems"]}
    assert buckets == {"windows", "linux"}


def test_classify_unrecognized_filesystem_type_is_unknown(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [{"offset": 0, "label": "ISO"}])
    monkeypatch.setattr(tsk, "_tsk_open_fs", lambda p, o: _FakeFs(pytsk3.TSK_FS_TYPE_ISO9660))
    result = tsk.classify_image_profile("fake.dd")
    assert result["profile"] == "unknown"
    assert result["filesystems"][0]["fs_type"] == "ISO9660"
    assert result["filesystems"][0]["bucket"] == "other"


def test_classify_no_filesystem_found_returns_unknown_with_empty_list(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [])
    result = tsk.classify_image_profile("fake.dd")
    assert result == {"profile": "unknown", "filesystems": []}


def test_classify_skips_a_partition_that_fails_to_open_without_raising(monkeypatch):
    monkeypatch.setattr(tsk, "_tsk_resolve_filesystems", lambda p: [
        {"offset": 0, "label": "OK"}, {"offset": 999, "label": "Corrupt"},
    ])

    def fake_open(p, o):
        if o == 999:
            raise Exception("simulated corrupt partition")
        return _FakeFs(pytsk3.TSK_FS_TYPE_NTFS)

    monkeypatch.setattr(tsk, "_tsk_open_fs", fake_open)
    result = tsk.classify_image_profile("fake.dd")
    assert result["profile"] == "windows"
    assert len(result["filesystems"]) == 1  # the corrupt one is skipped, not fatal
