"""core/usnjrnl_utils.py - proves parse_usnjrnl_stream()'s hand-rolled
USN_RECORD_V2 parser round-trips correctly against a hand-built synthetic
byte blob, matching this app's own established discipline (already applied
to the Recycle Bin $I parser) of proving a hand-rolled binary-format parser
against real/synthetic bytes, not just documentation."""
import os
import struct

import core.usnjrnl_utils as usnjrnl_utils


def _build_usn_record(file_ref, parent_ref, usn, filetime_raw, reason, name):
    """Hand-builds one real USN_RECORD_V2 byte blob per the module's own
    documented struct layout, WCHAR-padded to a 4-byte boundary (matching
    real Windows journal output, which pads each record's total length)."""
    name_bytes = name.encode('utf-16-le')
    header_size = usnjrnl_utils._HEADER_SIZE
    unpadded_len = header_size + len(name_bytes)
    record_length = (unpadded_len + 3) & ~3  # round up to 4-byte alignment
    header = usnjrnl_utils._HEADER_STRUCT.pack(
        record_length, 2, 0,  # RecordLength, MajorVersion=2, MinorVersion=0
        file_ref, parent_ref, usn, filetime_raw,
        reason, 0, 0, 0x20,  # SourceInfo=0, SecurityId=0, FileAttributes=0x20 (ARCHIVE)
        len(name_bytes), header_size,
    )
    padding = b'\x00' * (record_length - unpadded_len)
    return header + name_bytes + padding


def test_parse_usnjrnl_stream_round_trips_a_single_create_record():
    filetime_raw = 133_000_000_000_000_000  # an arbitrary plausible FILETIME value
    blob = _build_usn_record(
        file_ref=0x0005000000001234, parent_ref=0x0005000000000005,
        usn=98304, filetime_raw=filetime_raw, reason=0x00000100,  # FILE_CREATE
        name="malware.exe",
    )
    records = usnjrnl_utils.parse_usnjrnl_stream(blob)
    assert len(records) == 1
    rec = records[0]
    assert rec["artifact_type"] == "usnjrnl_change_record"
    assert rec["title"] == "malware.exe"
    assert rec["value"] == "FILE_CREATE"
    assert rec["timestamp"] is not None
    assert rec["extra"]["usn"] == 98304
    assert rec["extra"]["file_reference_number"] == 0x0005000000001234


def test_parse_usnjrnl_stream_round_trips_multiple_back_to_back_records():
    rec1 = _build_usn_record(1, 5, 100, 133_000_000_000_000_000, 0x00000100, "evidence.docx")
    rec2 = _build_usn_record(1, 5, 200, 133_000_000_100_000_000, 0x00000001, "evidence.docx")  # DATA_OVERWRITE
    rec3 = _build_usn_record(1, 5, 300, 133_000_000_200_000_000, 0x00000200, "evidence.docx")  # FILE_DELETE
    blob = rec1 + rec2 + rec3
    records = usnjrnl_utils.parse_usnjrnl_stream(blob)
    assert len(records) == 3
    assert [r["value"] for r in records] == ["FILE_CREATE", "DATA_OVERWRITE", "FILE_DELETE"]
    # USNs strictly increase in a real journal - confirms record boundaries
    # were walked correctly, not misaligned/overlapping.
    assert [r["extra"]["usn"] for r in records] == [100, 200, 300]


def test_parse_usnjrnl_stream_decodes_a_combined_reason_bitmask():
    # RENAME_OLD_NAME (0x1000) | RENAME_NEW_NAME (0x2000) - a real rename
    # in the journal often carries both bits together on adjacent records,
    # but a single record CAN legally carry a combined mask too.
    blob = _build_usn_record(1, 5, 50, 133_000_000_000_000_000, 0x00003000, "renamed.txt")
    records = usnjrnl_utils.parse_usnjrnl_stream(blob)
    assert len(records) == 1
    assert set(records[0]["value"].split("|")) == {"RENAME_OLD_NAME", "RENAME_NEW_NAME"}


def test_parse_usnjrnl_stream_stops_cleanly_at_a_zero_record_length_sentinel():
    real_record = _build_usn_record(1, 5, 10, 133_000_000_000_000_000, 0x00000100, "a.txt")
    sparse_region = b'\x00' * 64  # a real journal's unused/sparse region
    blob = real_record + sparse_region
    records = usnjrnl_utils.parse_usnjrnl_stream(blob)
    assert len(records) == 1
    assert records[0]["title"] == "a.txt"


def test_parse_usnjrnl_stream_never_raises_on_truncated_trailing_bytes():
    real_record = _build_usn_record(1, 5, 10, 133_000_000_000_000_000, 0x00000100, "a.txt")
    truncated_garbage = struct.pack('<I', 9999) + b'\xff' * 10  # claims a length far past the buffer
    blob = real_record + truncated_garbage
    records = usnjrnl_utils.parse_usnjrnl_stream(blob)
    assert len(records) == 1  # the real record before the corruption still parses


def test_parse_usnjrnl_stream_handles_empty_input():
    assert usnjrnl_utils.parse_usnjrnl_stream(b'') == []


def test_find_usnjrnl_files_matches_dollar_j_and_usnjrnl_named_files(tmp_path):
    (tmp_path / "$J").write_bytes(b'x')
    (tmp_path / "UsnJrnl_extracted.bin").write_bytes(b'x')
    (tmp_path / "unrelated.txt").write_bytes(b'x')
    found, truncated = usnjrnl_utils.find_usnjrnl_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"$J", "UsnJrnl_extracted.bin"}
    assert truncated is False
