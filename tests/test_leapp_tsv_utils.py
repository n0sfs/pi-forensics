"""core/leapp_tsv_utils.py - ALEAPP/iLEAPP _TSV Exports parsing (Android
forensics expansion, Phase A). Pure stdlib (csv/os/re), no third-party
library or real ALEAPP installation needed to test - real TSV files are
plain tab-separated text, hand-built directly here matching ALEAPP's own
real, confirmed-live output shape (a header row + tab-separated data
rows, one file per module, named after the module's display name).
"""
import os

import core.leapp_tsv_utils as leapp


def _write_tsv(path, headers, rows):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write("\t".join(headers) + "\n")
        for row in rows:
            f.write("\t".join(row) + "\n")


def test_normalize_module_name_matches_curated_key_shape():
    assert leapp._normalize_module_name("Wifi Networks") == "wifi networks"
    assert leapp._normalize_module_name("SMS & MMS") == "sms mms"  # & collapses to a separator, not a literal key
    assert leapp._normalize_module_name("  Extra   Spaces  ") == "extra spaces"


def test_find_leapp_tsv_files_lists_only_tsv_files(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    (tsv_dir / "Device Info.tsv").write_text("Field\tValue\n")
    (tsv_dir / "Wifi.tsv").write_text("SSID\n")
    (tsv_dir / "report.html").write_text("<html></html>")  # not a TSV - excluded
    paths, truncated = leapp.find_leapp_tsv_files(str(tsv_dir))
    assert len(paths) == 2
    assert not truncated
    assert all(p.endswith('.tsv') for p in paths)


def test_find_leapp_tsv_files_missing_dir_returns_empty_not_error(tmp_path):
    paths, truncated = leapp.find_leapp_tsv_files(str(tmp_path / "does_not_exist"))
    assert paths == []
    assert truncated is False


def test_parse_curated_module_gets_its_own_artifact_type(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    # A real, confirmed-real ALEAPP module display name (see the module's
    # own docstring for why "Wifi" -> leapp_wifi_network is in the
    # curated table) - "Wifi.tsv" matches "wifi" after normalization.
    _write_tsv(str(tsv_dir / "Wifi.tsv"), ["SSID", "BSSID", "Last Connected"],
               [["HomeNetwork", "AA:BB:CC:DD:EE:FF", "2026-01-01"]])
    records, files_found, truncated = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert files_found == 1
    assert not truncated
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "leapp_wifi_network"
    assert r["title"] == "HomeNetwork"
    assert "BSSID: AA:BB:CC:DD:EE:FF" in r["value"]
    assert r["timestamp"] is None  # deliberately never fabricated - see module docstring
    assert r["extra"]["leapp_tool"] == "aleapp"
    assert r["extra"]["leapp_module"] == "Wifi"
    assert r["extra"]["row"]["SSID"] == "HomeNetwork"


def test_parse_uncurated_module_falls_back_to_shared_bucket(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Some Obscure Third Party App.tsv"), ["Field", "Value"],
               [["session_id", "abc123"]])
    records, files_found, truncated = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert files_found == 1
    assert len(records) == 1
    r = records[0]
    # Never silently dropped just because this app's curated table didn't
    # anticipate this exact module - the whole point of the fallback tier.
    assert r["artifact_type"] == "leapp_module_finding"
    assert "Some Obscure Third Party App" in r["title"]
    assert r["extra"]["leapp_module"] == "Some Obscure Third Party App"


def test_multiple_rows_produce_multiple_records(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Installed Applications.tsv"), ["Package Name", "App Name"], [
        ["com.example.one", "App One"],
        ["com.example.two", "App Two"],
    ])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 2
    assert {r["title"] for r in records} == {"com.example.one", "com.example.two"}
    assert all(r["artifact_type"] == "leapp_installed_app" for r in records)


def test_blank_rows_are_skipped_not_recorded_as_empty(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    with open(tsv_dir / "Accounts.tsv", 'w', encoding='utf-8', newline='') as f:
        f.write("Account Name\tType\n")
        f.write("real@example.com\tGoogle\n")
        f.write("\t\n")  # a genuinely blank row - some ALEAPP module versions emit these
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["title"] == "real@example.com"


def test_header_only_file_produces_zero_records_not_an_error(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Empty Module.tsv"), ["Field", "Value"], [])
    records, files_found, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert files_found == 1
    assert records == []


def test_ragged_row_shorter_than_headers_does_not_crash(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    with open(tsv_dir / "Device Info.tsv", 'w', encoding='utf-8', newline='') as f:
        f.write("Field\tValue\tExtra\n")
        f.write("Model\tPixel 8a\n")  # only 2 of 3 columns present
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "leapp_device_info"
    assert "Value: Pixel 8a" in records[0]["value"]


def test_garbage_non_tsv_content_is_tolerated_not_fatal(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    (tsv_dir / "Corrupt.tsv").write_bytes(b"\xff\xfe\x00\x01not really text")
    records, files_found, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert files_found == 1
    assert records == []  # tolerated, not raised


def test_all_artifact_types_constant_matches_actual_curated_values():
    # Guards against the module's own two sources of truth (the curated
    # dict's values, and the exported "every type this module can
    # produce" set the regression test in test_parsed_artifact_type_
    # labels.py imports directly) drifting apart.
    assert leapp.LEAPP_TSV_ALL_ARTIFACT_TYPES == set(leapp.CURATED_LEAPP_MODULES.values()) | {"leapp_module_finding"}
