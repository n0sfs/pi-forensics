"""Batch 4 of the 2026-10-02 review, the parts in core/ (run everywhere):

- Chunked scanners recorded a match that touched the end of a buffer, so a
  value split across two reads came out as a prefix fragment.
- A corrupt or truncated Google Takeout zip imported as "0 files".
- `strings` buffered all of its output before keeping 1000 lines.
"""
import shutil
import zipfile

import pytest

import core.case_index_db as cidb
from core.strings_utils import strings_first_lines, format_strings_output
from core.takeout_utils import TakeoutArchiveUnreadable, _safe_extract_zip


EMAIL = {"emails": cidb.TRIAGE_PATTERNS["emails"]}


def _scan(data, chunk_size):
    """Drives scan_chunk_matches() exactly as the two scanners do."""
    found, tail = set(), b""
    for i in range(0, len(data), chunk_size):
        hits, carry = cidb.scan_chunk_matches(EMAIL, tail + data[i:i + chunk_size], False, 256)
        found.update(v for _n, v in hits)
        tail = (tail + data[i:i + chunk_size])[carry:]
    if tail:
        hits, _ = cidb.scan_chunk_matches(EMAIL, tail, True, 256)
        found.update(v for _n, v in hits)
    return found


@pytest.mark.parametrize("chunk_size", [7, 13, 25, 64, 4096])
def test_a_value_split_across_chunks_is_found_whole_and_only_whole(chunk_size):
    data = b"xx joe.smith@example.com yy alice@test.org zz"
    assert _scan(data, chunk_size) == {b"joe.smith@example.com", b"alice@test.org"}


def test_a_value_ending_the_file_is_flushed():
    assert _scan(b"contact: last@example.net", 10) == {b"last@example.net"}


def test_a_corrupt_takeout_zip_is_an_error_not_an_empty_export(tmp_path):
    bad = tmp_path / "takeout-001.zip"
    bad.write_bytes(b"PK\x03\x04 this is not really a zip")
    with pytest.raises(TakeoutArchiveUnreadable):
        _safe_extract_zip(str(bad), str(tmp_path / "out"))


def test_a_damaged_member_is_an_error(tmp_path):
    good = tmp_path / "takeout-002.zip"
    with zipfile.ZipFile(good, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Takeout/data.json", b"x" * 50000)
    raw = bytearray(good.read_bytes())
    raw[60:90] = b"\xff" * 30  # inside the compressed member data
    good.write_bytes(bytes(raw))
    with pytest.raises(TakeoutArchiveUnreadable):
        _safe_extract_zip(str(good), str(tmp_path / "out2"))


@pytest.mark.skipif(shutil.which("strings") is None, reason="binutils `strings` not installed here")
def test_strings_stops_at_its_limit_and_says_so(tmp_path):
    f = tmp_path / "many.bin"
    f.write_bytes(b"".join(b"line_number_%06d\n" % i for i in range(5000)))
    lines, more, timed_out = strings_first_lines(str(f), max_lines=100)
    assert len(lines) == 100 and more and not timed_out
    assert "only the first 100 lines" in format_strings_output(lines, more, timed_out)


def test_no_strings_output_is_said_plainly():
    assert format_strings_output([], False, False) == "[no printable strings found]"
