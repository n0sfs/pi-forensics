"""core/mft_utils.py - the pure JSON-shaping/timestomp-detection logic,
tested against a hand-built raw_records fixture matching analyzeMFT's real,
live-confirmed JSON output shape (field names/timestamp-string formats
confirmed on the Pi's real ARM64 venv via its own `--generate-test-mft`
synthetic-data generator before this module was written). The real
analyzemft subprocess call itself (analyze_mft_file()) is not exercised
here - the binary isn't installed in this dev environment, matching this
project's established pattern of unit-testing the pure transformation logic
separately from a subprocess-coupled wrapper."""
import core.mft_utils as mft_utils


def test_parse_iso_or_sentinel_parses_a_real_confirmed_timestamp_format():
    # The exact format confirmed live against analyzeMFT's own JSON output.
    ts = mft_utils._parse_iso_or_sentinel("2026-08-30T17:54:07.084Z")
    assert ts is not None
    assert ts > 0


def test_parse_iso_or_sentinel_returns_none_for_both_real_sentinel_strings():
    assert mft_utils._parse_iso_or_sentinel("Not defined") is None
    assert mft_utils._parse_iso_or_sentinel("Invalid timestamp") is None


def test_parse_iso_or_sentinel_never_raises_on_garbage():
    assert mft_utils._parse_iso_or_sentinel(None) is None
    assert mft_utils._parse_iso_or_sentinel("") is None
    assert mft_utils._parse_iso_or_sentinel("not a date at all") is None
    assert mft_utils._parse_iso_or_sentinel(12345) is None


def _fake_record(filename, si_crtime, fn_crtime, si_mtime=None, recordnum=1, filesize=1024):
    return {
        "filename": filename, "recordnum": recordnum, "parent_ref": 5, "flags": 1,
        "filesize": filesize,
        "si_times": {"crtime": si_crtime, "mtime": si_mtime or si_crtime, "atime": si_crtime, "ctime": si_crtime},
        "fn_times": {"crtime": fn_crtime, "mtime": fn_crtime, "atime": fn_crtime, "ctime": fn_crtime},
    }


def test_records_from_analyzemft_json_flags_a_genuine_timestomp_case():
    # SI creation time set well BEFORE the real FN creation time - the
    # classic SetFileTime-backdating signature this heuristic exists to
    # catch.
    raw = [_fake_record(
        "malware.exe",
        si_crtime="2020-01-01T00:00:00.000Z",  # backdated
        fn_crtime="2026-08-30T12:00:00.000Z",  # the file's real creation
    )]
    records, timestomp_count = mft_utils._records_from_analyzemft_json(raw)
    assert timestomp_count == 1
    assert records[0]["extra"]["timestomp_suspected"] is True
    assert "TIMESTOMP SUSPECTED" in records[0]["title"]


def test_records_from_analyzemft_json_does_not_flag_a_normal_matching_record():
    raw = [_fake_record(
        "normal_document.docx",
        si_crtime="2026-08-30T12:00:00.000Z",
        fn_crtime="2026-08-30T12:00:00.000Z",
    )]
    records, timestomp_count = mft_utils._records_from_analyzemft_json(raw)
    assert timestomp_count == 0
    assert records[0]["extra"]["timestomp_suspected"] is False
    assert "TIMESTOMP" not in records[0]["title"]


def test_records_from_analyzemft_json_tolerates_small_clock_rounding_differences():
    # A ~30-second SI/FN gap is well within the tolerance and normal clock/
    # rounding noise - must NOT be flagged, or the heuristic would be
    # useless (constant false positives on real, unremarkable data).
    raw = [_fake_record(
        "ordinary.txt",
        si_crtime="2026-08-30T12:00:00.000Z",
        fn_crtime="2026-08-30T12:00:30.000Z",
    )]
    records, timestomp_count = mft_utils._records_from_analyzemft_json(raw)
    assert timestomp_count == 0


def test_records_from_analyzemft_json_never_flags_when_either_side_is_undefined():
    raw = [_fake_record("no_si.txt", si_crtime="Not defined", fn_crtime="2026-08-30T12:00:00.000Z")]
    records, timestomp_count = mft_utils._records_from_analyzemft_json(raw)
    assert timestomp_count == 0
    assert records[0]["extra"]["timestomp_suspected"] is False


def test_records_from_analyzemft_json_handles_an_unnamed_record():
    raw = [_fake_record("", si_crtime="2026-08-30T12:00:00.000Z", fn_crtime="2026-08-30T12:00:00.000Z", recordnum=42)]
    records, _ = mft_utils._records_from_analyzemft_json(raw)
    assert "42" in records[0]["title"]


def test_records_from_analyzemft_json_handles_a_non_list_payload():
    records, timestomp_count = mft_utils._records_from_analyzemft_json({"not": "a list"})
    assert records == []
    assert timestomp_count == 0


def test_records_from_analyzemft_json_marks_directory_flag_correctly():
    raw = [_fake_record("SomeFolder", si_crtime="2026-08-30T12:00:00.000Z", fn_crtime="2026-08-30T12:00:00.000Z")]
    raw[0]["flags"] = 0x03  # in-use (0x01) + directory (0x02)
    records, _ = mft_utils._records_from_analyzemft_json(raw)
    assert records[0]["extra"]["is_directory"] is True


def test_records_from_analyzemft_json_carries_hash_fields_when_present():
    raw = [_fake_record("hashed.bin", si_crtime="2026-08-30T12:00:00.000Z", fn_crtime="2026-08-30T12:00:00.000Z")]
    raw[0]["md5"] = "d41d8cd98f00b204e9800998ecf8427e"
    raw[0]["sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    records, _ = mft_utils._records_from_analyzemft_json(raw)
    assert records[0]["extra"]["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert records[0]["extra"]["sha256"].startswith("e3b0c442")
