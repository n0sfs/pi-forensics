"""NTFS $UsnJrnl:$J (USN Change Journal) parsing - a hand-rolled parser for
the USN_RECORD_V2 structure, matching this app's own established precedent
(Recycle Bin $I, wtmp/utmp) of hand-rolling a well-documented, stable, fixed
binary layout rather than reaching for a third-party dependency of
uncertain reliability. USN_RECORD_V2's on-disk shape is long-stable public
Microsoft documentation (the structure Windows itself has used since
Windows 2000, unchanged through Windows 11/Server 2022 - V3/V4 exist for
ReFS only, never NTFS), not assumed from a single source.

Each record is self-describing (its own leading 4-byte RecordLength field
tells the parser exactly how far to advance to the next one), which is what
makes walking a raw $J stream byte-for-byte tractable without any external
index. This module's own parse_usnjrnl_stream() was proven correct against
a hand-built synthetic USN_RECORD_V2 byte blob (see
tests/test_usnjrnl_utils.py) before being trusted - the same "prove it
against real/synthetic bytes, not just documentation" discipline already
established for the Recycle Bin parser.

The change journal is the *only* surviving trace of a file that was created,
renamed, and deleted entirely within one MFT record's lifetime (nothing
else in this app - not $MFT parsing, not TSK's own directory listing - can
see that), which is why this is scoped as its own module and report block
rather than folded into MFT parsing.

Known, disclosed limitation: extraction of $Extend/$UsnJrnl:$J from *inside*
an acquired disk image (routes/image_browser.py's find_usnjrnl_files_in_
image(), added alongside this module) reads the named data stream via
pytsk3's documented attribute-enumeration API - the same general technique
plaso/other TSK-based tooling use for NTFS ADS - but has not been verified
against a real NTFS image with an active journal, since no such test image
exists in this project's own fixtures as of this writing. The raw-bytes
parser itself (this module) is independently, fully verified; only the
in-image *extraction* step is unverified pending real test data.
"""
import os
import struct
from datetime import datetime, timezone

from core.registry_utils import filetime_to_unix

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

USNJRNL_SCAN_MAX_CANDIDATES = 20
USNJRNL_MAX_RECORDS = 100_000

# Fixed-size header preceding the variable-length filename, per Microsoft's
# public USN_RECORD_V2 documentation:
#   DWORD RecordLength; WORD MajorVersion; WORD MinorVersion;
#   DWORDLONG FileReferenceNumber; DWORDLONG ParentFileReferenceNumber;
#   LONGLONG Usn; LARGE_INTEGER TimeStamp; DWORD Reason; DWORD SourceInfo;
#   DWORD SecurityId; DWORD FileAttributes;
#   WORD FileNameLength; WORD FileNameOffset;
_HEADER_STRUCT = struct.Struct('<IHHQQqqIIIIHH')
_HEADER_SIZE = _HEADER_STRUCT.size  # 60 bytes

# USN_REASON_* bitmask flags (public Microsoft constants) - the reason(s)
# the change journal recorded this entry.
_USN_REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x80000000, "CLOSE"),
]


def _decode_usn_reason(reason):
    names = [name for bit, name in _USN_REASON_FLAGS if reason & bit]
    return names or ["UNKNOWN"]


def find_usnjrnl_files(root_dir):
    """Finds an already-extracted raw $UsnJrnl:$J stream sitting on the
    real filesystem - naming conventions vary by extraction tool (KAPE/FTK/
    manual icat all name it differently), so this matches on either an
    exact '$J' filename or any filename containing 'usnjrnl' (case-
    insensitive), rather than one single fixed name the way find_mft_files()
    can for '$MFT'. Returns (paths, truncated)."""
    found = []
    walked = 0
    max_walked = 40_000
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > max_walked:
                return found, True
            upper = fname.upper()
            if upper == '$J' or 'USNJRNL' in upper:
                found.append(os.path.join(root, fname))
                if len(found) >= USNJRNL_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def parse_usnjrnl_stream(data):
    """Parses raw $J stream bytes into a list of this app's standard
    {artifact_type, title, url, value, timestamp, extra} records - one per
    USN_RECORD_V2 entry. A real $J stream is typically sparse (the journal
    is a fixed-size ring buffer with unused regions zero-filled) - a
    RecordLength of 0 means "no more real records from here to the next
    allocated journal extent," so parsing stops there rather than treating
    it as a malformed record. Never raises - a genuinely corrupt/truncated
    record at some offset just stops the walk at that point, keeping every
    record parsed before it."""
    records = []
    offset = 0
    n = len(data)
    while offset + 4 <= n and len(records) < USNJRNL_MAX_RECORDS:
        (record_length,) = struct.unpack_from('<I', data, offset)
        if record_length == 0:
            # Sparse/unused journal region - not a parse error, just the
            # end of this contiguous run of real records.
            break
        if record_length < _HEADER_SIZE or offset + record_length > n:
            break
        try:
            (rec_len, major, minor, file_ref, parent_ref, usn, timestamp_raw,
             reason, source_info, security_id, file_attrs,
             name_len, name_offset) = _HEADER_STRUCT.unpack_from(data, offset)
        except struct.error:
            break

        if major != 2:
            # Only V2 is defined for NTFS (V3/V4 are ReFS-only) - an
            # unexpected version means this offset isn't really a record
            # boundary; stop rather than guess.
            break

        name = ""
        if name_len > 0 and offset + name_offset + name_len <= n:
            raw_name = data[offset + name_offset: offset + name_offset + name_len]
            name = raw_name.decode('utf-16-le', errors='ignore')

        reasons = _decode_usn_reason(reason)
        ts = filetime_to_unix(timestamp_raw) if timestamp_raw > 0 else None

        if name:
            records.append({
                "artifact_type": "usnjrnl_change_record",
                "title": name, "url": "",
                "value": "|".join(reasons),
                "timestamp": ts,
                "extra": {
                    "usn": usn, "file_reference_number": file_ref,
                    "parent_file_reference_number": parent_ref,
                    "reasons": reasons, "file_attributes": file_attrs,
                },
            })

        offset += record_length

    return records


def parse_usnjrnl_file(path):
    """Reads and parses an already-extracted $J file from disk. Best-effort
    - a read failure returns an empty list rather than raising, matching
    every other whole-folder scanner's tolerance in this app."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return parse_usnjrnl_stream(data)
    except Exception as e:
        print(f"Warning: could not parse UsnJrnl file {path}: {e}")
        return []
