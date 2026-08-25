"""core/recyclebin_utils.py - Windows Recycle Bin ($I metadata file)
parsing (follow-up to Part C, 2026-08-25). Unlike core/registry_utils.py/
core/evtx_utils.py's hand-built REGF/EVTX container fixtures, the $I format
needs no third-party library to read OR to construct - both this test file
and the module under test build/parse the same small, stable, well-
documented binary layout directly.

No skip guard needed (no optional pip dependency, unlike test_registry_
utils.py/test_evtx_utils.py/test_yara_rulesets.py) - this module is pure
stdlib.
"""
import struct

import core.recyclebin_utils as rb


def _build_v1_fixture(deletion_filetime, file_size, original_path):
    """Version 1 (Vista-8.1): 8-byte version(=1) + 8-byte size + 8-byte
    FILETIME + a fixed 520-byte (260 UTF-16 code unit) null-terminated
    path field."""
    header = struct.pack('<qqq', 1, file_size, deletion_filetime)
    path_bytes = original_path.encode('utf-16-le') + b'\x00\x00'
    path_field = path_bytes.ljust(520, b'\x00')
    return header + path_field


def _build_v2_fixture(deletion_filetime, file_size, original_path):
    """Version 2 (Windows 10 1809+): 8+8+8-byte header (same as v1) + a
    4-byte path-length-in-characters field (excluding the null terminator)
    + the variable-length null-terminated path itself."""
    header = struct.pack('<qqq', 2, file_size, deletion_filetime)
    path_len = struct.pack('<i', len(original_path))
    path_bytes = original_path.encode('utf-16-le') + b'\x00\x00'
    return header + path_len + path_bytes


def test_parse_v1_fixture_extracts_real_fields(tmp_path):
    p = tmp_path / "$IABCDEF.jpg"
    # A real-shaped FILETIME (2026-08-20-ish) - the exact value doesn't
    # matter for this test beyond "not zero, converts to a plausible epoch".
    p.write_bytes(_build_v1_fixture(133_700_000_000_000_000, 4096, "C:\\Users\\test\\Pictures\\photo.jpg"))
    records = rb.parse_recyclebin_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "recyclebin_deleted_file"
    assert r["title"] == "C:\\Users\\test\\Pictures\\photo.jpg"
    assert r["extra"]["file_size"] == 4096
    assert r["extra"]["format_version"] == 1
    assert r["timestamp"] is not None
    assert r["timestamp"] > 0  # a real 2026-ish FILETIME must convert to a positive Unix epoch


def test_parse_v2_fixture_extracts_real_fields_including_variable_length_path(tmp_path):
    p = tmp_path / "$IXYZ123.docx"
    long_path = "C:\\Users\\test\\Documents\\Very Long Subfolder Name\\budget report final v3.docx"
    p.write_bytes(_build_v2_fixture(133_700_000_000_000_000, 20480, long_path))
    records = rb.parse_recyclebin_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["title"] == long_path
    assert r["extra"]["file_size"] == 20480
    assert r["extra"]["format_version"] == 2


def test_parse_recyclebin_file_unknown_version_returns_empty_not_raises(tmp_path):
    p = tmp_path / "$IBOGUS.tmp"
    p.write_bytes(struct.pack('<qqq', 99, 0, 0) + b'\x00' * 520)
    assert rb.parse_recyclebin_file(str(p)) == []


def test_parse_recyclebin_file_truncated_or_garbage_returns_empty_not_raises(tmp_path):
    p = tmp_path / "$Ishort.txt"
    p.write_bytes(b"not a real recycle bin file")
    assert rb.parse_recyclebin_file(str(p)) == []


def test_find_recyclebin_files_matches_the_real_per_sid_subfolder_nesting(tmp_path):
    # The real bug caught before this module ever shipped: a real $I file's
    # immediate parent is always a per-SID subfolder ('$Recycle.Bin\\S-1-5-
    # 21-.../$IABCDEF.jpg'), never '$Recycle.Bin' itself - a naive "is the
    # immediate parent directory literally named $Recycle.Bin" check would
    # silently find nothing against real-world Recycle Bin structure.
    recyclebin_dir = tmp_path / "Users" / "test" / "$Recycle.Bin" / "S-1-5-21-1111111111-2222222222-3333333333-1001"
    recyclebin_dir.mkdir(parents=True)
    (recyclebin_dir / "$IABCDEF.jpg").write_bytes(_build_v1_fixture(133_700_000_000_000_000, 1, "C:\\test.jpg"))
    (tmp_path / "unrelated.txt").write_bytes(b"x")
    found, truncated = rb.find_recyclebin_files(str(tmp_path))
    assert len(found) == 1
    assert found[0].endswith("$IABCDEF.jpg")
    assert truncated is False


def test_find_recyclebin_files_case_insensitive_directory_name(tmp_path):
    d = tmp_path / "$RECYCLE.BIN" / "S-1-5-21-1-2-3-1001"
    d.mkdir(parents=True)
    (d / "$Itest.jpg").write_bytes(_build_v1_fixture(133_700_000_000_000_000, 1, "C:\\x.jpg"))
    found, truncated = rb.find_recyclebin_files(str(tmp_path))
    assert len(found) == 1


def test_find_recyclebin_files_ignores_files_outside_a_recyclebin_ancestor(tmp_path):
    # A file that merely starts with '$I' but isn't under any $Recycle.Bin
    # directory at all must never be treated as a candidate.
    (tmp_path / "$Important_notes.txt").write_bytes(b"x")
    found, truncated = rb.find_recyclebin_files(str(tmp_path))
    assert found == []
