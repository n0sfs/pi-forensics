"""F2FS (Flash-Friendly File System) detection support.

The Sleuth Kit / pytsk3 has no F2FS driver at all - it's a real gap this project already
disclosed while scoping the multi-partition tree-rendering work (see CLAUDE.md). F2FS is a
common on-disk filesystem for Android devices acquired via a rooted "physical" (raw dd) image,
so an image containing an F2FS partition/volume was previously completely unbrowsable through
this app's Sleuth Kit-based Image Browser - the partition would list in mmls but refuse to open.

Since Sleuth Kit can't parse F2FS at all, this app doesn't hand-roll an F2FS parser either -
instead it mounts the filesystem read-only through the Linux KERNEL's own native F2FS driver
(confirmed compiled directly into the deployed station's kernel, not a loadable module - see
`/proc/filesystems`), producing an ordinary, real directory tree. That directory is then browsed,
extracted from, and hashed through the exact same real-filesystem File Explorer routes every
other real folder already uses - zero new browsing/extraction/hashing code needed, matching this
project's own repeated "reuse everything downstream of the mount point" pattern already
established for BitLocker/LUKS/VeraCrypt-decrypted volumes.

This module is detection-only: a small, presence-check read of the real F2FS superblock magic
number at its confirmed, fixed byte offset - never a full superblock/checkpoint/NAT/SIT parse.
The actual mounting itself (`routes/file_explorer.py`) is a plain `mount -t f2fs -o ro[,loop]`
via the kernel driver, not anything this module does.

**Deliberately scoped to read-only browse/extract/hash only, never deleted-file recovery.**
Unlike ext4/NTFS/FAT (which Sleuth Kit already parses at the raw block level, giving this app's
existing in-image tools access to unallocated inodes/deleted directory entries), a plain kernel
mount only ever exposes the filesystem's current, live state - there is no practical way to reach
F2FS's own deleted-but-not-yet-garbage-collected data through a mount alone (F2FS's log-structured,
segment-based design has no simple analog to ext4's orphan-inode list or NTFS's $MFT slack), and
building a real from-scratch F2FS parser purely to reach that content was judged, and confirmed via
research, not realistically buildable within this project's own scope - a much larger undertaking
than every other artifact parser this project has built, for a payoff this app has no way to verify
without a corpus of real deleted-file test data. Disclosed here rather than silently attempted.

**Superblock layout, confirmed from two independent authoritative sources before this module was
written** (this project's own established "verify before build" discipline): the Linux kernel's own
`include/linux/f2fs_fs.h` confirms `F2FS_SUPER_OFFSET = 1024` (byte offset from the start of the
partition/filesystem) and that `magic` is a `__le32` - the very first field of `struct
f2fs_super_block`; f2fs-tools' own userspace `include/f2fs_fs.h` confirms the magic value itself,
`F2FS_SUPER_MAGIC = 0xF2F52010`. F2FS keeps a second, redundant superblock copy one block
(typically 4096 bytes) after the primary - this module deliberately only checks the primary copy,
matching this app's own already-established, simpler single-signature-check precedent for BitLocker/
LUKS/VeraCrypt detection (a real, disclosed simplification, not an oversight).
"""

import struct

F2FS_SUPER_OFFSET = 1024
F2FS_SUPER_MAGIC = 0xF2F52010


def detect_f2fs(file_path, offset=0):
    """Best-effort check: does the F2FS superblock magic appear at the expected byte offset?

    `offset` is the byte offset (not sectors) of the partition/volume's own start within
    `file_path` - 0 for a whole-image F2FS filesystem or a single-partition device node, or a
    real partition's own byte offset within a larger multi-partition raw disk image (the same
    byte-offset convention `losetup -o` already uses elsewhere in this app for LUKS/VeraCrypt).

    Returns True only on a genuine magic-number match; False for anything else (wrong signature,
    file too short to contain a superblock at that offset, a read/permission error) - never
    raises, matching this app's other best-effort image-format detectors (`_detect_bitlocker_
    image`, `_detect_luks_image`).
    """
    try:
        with open(file_path, "rb") as f:
            f.seek(offset + F2FS_SUPER_OFFSET)
            raw = f.read(4)
    except OSError:
        return False
    if len(raw) != 4:
        return False
    magic = struct.unpack("<I", raw)[0]
    return magic == F2FS_SUPER_MAGIC
