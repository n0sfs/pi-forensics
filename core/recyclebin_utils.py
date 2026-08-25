"""Windows Recycle Bin ($I* metadata file) parsing - the second of the two
new artifact types (alongside Prefetch) added in this same session, flagged
as deferred "more features into the timeline" when Part C's Registry/Event
Log/LNK parsing landed. Each deleted file leaves behind a paired $R (the
file's own recovered bytes, already visible/recoverable as an ordinary file
via this app's existing File Explorer/File Recovery tools - nothing new
needed there) and a small $I metadata file recording the file's *original*
path, size, and deletion time - exactly the record this module extracts.

No pip dependency at all, unlike every other Part C artifact family - the
$I format is a small, stable, well-documented fixed binary layout (no
compression, no checksums, no cross-referenced offset tables the way
Prefetch's SCCA format has), so a hand-written parser is both the lower-risk
and the more commonly-used approach in real DFIR tooling for this specific
artifact, rather than reaching for an obscure/unverified third-party pip
package. Mirrors this app's other Part C modules' exact {artifact_type,
title, url, value, timestamp, extra} record shape.

Two on-disk versions exist, both handled here:
  Version 1 (Windows Vista through 8.1): 8-byte version marker (=1) + 8-byte
    file size + 8-byte FILETIME deletion time + a fixed 520-byte
    (260 UTF-16 code unit) null-terminated original-path field.
  Version 2 (Windows 10 1809+): 8-byte version marker (=2) + 8-byte file
    size + 8-byte FILETIME deletion time + a 4-byte path-length field
    (UTF-16 code units, excluding the null terminator) + a variable-length
    null-terminated original-path field.
This layout is stable, widely documented public forensic knowledge (not
assumed from a single source) - verified in this session against a hand-
built binary fixture for both versions before being trusted, following this
app's own established discipline of proving a parser against real bytes
before shipping it, not just against documentation.

Raw deletion-time FILETIME values are converted via
core/registry_utils.py's filetime_to_unix() - the same shared helper
core/prefetch_utils.py already reuses, not a third copy of the same math.
"""
import os
import struct

from core.registry_utils import filetime_to_unix

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

RECYCLEBIN_SCAN_MAX_CANDIDATES = 2_000
RECYCLEBIN_SCAN_MAX_WALKED = 40_000

_HEADER_STRUCT = struct.Struct('<qqq')  # version, file_size, deletion_time (all int64 LE)


def _has_recyclebin_ancestor(dir_path):
    """True if any path component of dir_path is literally '$Recycle.Bin'
    (case-insensitive). A real $I file's immediate parent is always a
    per-SID subfolder (e.g. '$Recycle.Bin\\S-1-5-21-...\\$IABCDEF.txt'),
    never '$Recycle.Bin' itself - checking the whole ancestor chain rather
    than just the immediate parent directory name is what actually matches
    real Recycle Bin structure (a bug caught and fixed before this module
    was ever exercised against real data, not found live)."""
    parts = dir_path.replace('\\', '/').split('/')
    return any(p.lower() == '$recycle.bin' for p in parts)


def find_recyclebin_files(root_dir):
    """Recursively finds real $I* metadata files anywhere under a
    '$Recycle.Bin' directory (case-insensitive - real-world casing/mount
    tooling varies), at any depth below it (the real per-SID subfolder
    layer, not just directly inside it) - scoped this way rather than a
    bare '$I*' filename match anywhere in the tree, since a bare prefix
    match risks false positives on unrelated filenames. Returns
    (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        if not _has_recyclebin_ancestor(root):
            continue
        for fname in files:
            walked += 1
            if walked > RECYCLEBIN_SCAN_MAX_WALKED:
                return found, True
            if fname.upper().startswith('$I'):
                found.append(os.path.join(root, fname))
                if len(found) >= RECYCLEBIN_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def parse_recyclebin_file(path):
    """Parses one $I metadata file into a single record - original path,
    file size, and deletion time. Any parse failure (too short, not
    actually a real $I file despite the name/location) is swallowed and
    returns an empty list, same best-effort tolerance every other whole-
    folder scanner in this app already applies."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if len(data) < 24:
            return []
        version, file_size, deletion_time = _HEADER_STRUCT.unpack_from(data, 0)
        if version == 1:
            raw_path = data[24:24 + 520]
            original_path = raw_path.decode('utf-16-le', errors='ignore').split('\x00', 1)[0]
        elif version == 2:
            if len(data) < 28:
                return []
            (path_len_chars,) = struct.unpack_from('<i', data, 24)
            byte_len = max(0, path_len_chars) * 2
            raw_path = data[28:28 + byte_len]
            original_path = raw_path.decode('utf-16-le', errors='ignore').rstrip('\x00')
        else:
            return []
        if not original_path:
            return []
        return [{
            "artifact_type": "recyclebin_deleted_file", "title": original_path, "url": "",
            "value": f"{file_size:,} bytes" if file_size >= 0 else "",
            "timestamp": filetime_to_unix(deletion_time),
            "extra": {"file_size": file_size, "format_version": version, "recycle_bin_metadata_file": os.path.basename(path)},
        }]
    except Exception as e:
        print(f"Warning: could not parse recycle bin file {path}: {e}")
        return []
