"""Tests for core/f2fs_utils.py - F2FS superblock magic-number detection.

Byte layout confirmed against two independent authoritative sources before this module was
written (see core/f2fs_utils.py's own docstring): the Linux kernel's include/linux/f2fs_fs.h for
F2FS_SUPER_OFFSET/the __le32 magic field, and f2fs-tools' own include/f2fs_fs.h for the magic
value itself.
"""

import struct

import pytest

from core.f2fs_utils import F2FS_SUPER_MAGIC, F2FS_SUPER_OFFSET, detect_f2fs


def _build_f2fs_shaped_bytes(offset=0, magic=F2FS_SUPER_MAGIC, total_size=None):
    """Build a byte string with a real F2FS magic number at the confirmed offset."""
    size = total_size if total_size is not None else offset + F2FS_SUPER_OFFSET + 4 + 100
    data = bytearray(size)
    data[offset + F2FS_SUPER_OFFSET:offset + F2FS_SUPER_OFFSET + 4] = struct.pack("<I", magic)
    return bytes(data)


class TestDetectF2fs:
    def test_detects_real_magic_at_offset_zero(self, tmp_path):
        f = tmp_path / "f2fs.img"
        f.write_bytes(_build_f2fs_shaped_bytes(offset=0))
        assert detect_f2fs(str(f), offset=0) is True

    def test_detects_real_magic_at_a_nonzero_partition_offset(self, tmp_path):
        # Mirrors a real partition sitting partway through a larger multi-partition raw image -
        # the same byte-offset convention losetup -o already uses for LUKS/VeraCrypt elsewhere.
        partition_offset = 1048576  # 1 MiB in
        f = tmp_path / "disk.dd"
        f.write_bytes(_build_f2fs_shaped_bytes(offset=partition_offset))
        assert detect_f2fs(str(f), offset=partition_offset) is True

    def test_wrong_magic_value_is_rejected(self, tmp_path):
        f = tmp_path / "not_f2fs.img"
        f.write_bytes(_build_f2fs_shaped_bytes(offset=0, magic=0xDEADBEEF))
        assert detect_f2fs(str(f), offset=0) is False

    def test_a_real_ext4_style_signature_is_rejected(self, tmp_path):
        # ext4's own magic (0xEF53) lives at a completely different offset (1080, 2 bytes) -
        # confirm F2FS detection doesn't accidentally match unrelated filesystem bytes.
        f = tmp_path / "ext4.img"
        data = bytearray(4096)
        data[1080:1082] = struct.pack("<H", 0xEF53)
        f.write_bytes(bytes(data))
        assert detect_f2fs(str(f), offset=0) is False

    def test_file_too_short_to_contain_a_superblock_is_rejected_not_crashed(self, tmp_path):
        f = tmp_path / "tiny.img"
        f.write_bytes(b"\x00" * 10)
        assert detect_f2fs(str(f), offset=0) is False

    def test_nonexistent_file_returns_false_not_raises(self, tmp_path):
        assert detect_f2fs(str(tmp_path / "does_not_exist.img"), offset=0) is False

    def test_the_wrong_offset_against_a_real_superblock_correctly_fails(self, tmp_path):
        # A real superblock exists at offset 0, but checking at a different offset (as if this
        # were a different partition entirely) must not accidentally read into it.
        f = tmp_path / "f2fs.img"
        f.write_bytes(_build_f2fs_shaped_bytes(offset=0, total_size=8192))
        assert detect_f2fs(str(f), offset=4096) is False

    def test_confirms_the_authoritative_offset_and_magic_constant_values(self):
        # Locks in the two facts independently confirmed against kernel/f2fs-tools source before
        # this module was written - a regression here means someone changed a real, externally-
        # verified constant without re-checking it against an authoritative source.
        assert F2FS_SUPER_OFFSET == 1024
        assert F2FS_SUPER_MAGIC == 0xF2F52010
