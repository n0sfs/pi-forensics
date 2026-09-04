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


# --- Timestamp parsing (2026-09-01) - real column names/formatting confirmed
# directly against this app's own pinned ALEAPP commit's real module source,
# not guessed - see the module's own docstring for the full grounding. ---

def test_sms_messages_timestamp_parsed_from_real_date_column(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    # Exact real column order confirmed from smsmms.py's get_sms_mms()
    _write_tsv(str(tsv_dir / "SMS Messages.tsv"),
               ["Date", "Date Sent", "Type", "Address", "Body", "MSG ID"],
               [["2026-08-30 14:23:11+00:00", "2026-08-30 14:23:10+00:00",
                 "Received", "555-0100", "hi", "1"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "leapp_sms_message"
    assert records[0]["timestamp"] == 1788099791.0


def test_call_logs_tries_both_real_column_name_variants(tmp_path):
    # This app's pinned ALEAPP commit has TWO independently-authored "Call
    # Logs" modules using different column names for the same concept -
    # confirmed both real, both fold into leapp_call_log via
    # _normalize_module_name(). Both must resolve their own timestamp.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Call logs .tsv"),  # real trailing-space registered name
               ["Call Date", "Phone Account Address", "Partner", "Type"],
               [["2026-08-30 09:00:00+00:00", "", "555-0100", "Incoming"]])
    _write_tsv(str(tsv_dir / "Call Logs.tsv"),  # the second, differently-named real module
               ["from_id", "to_id", "start_date", "end_date", "direction"],
               [["a", "b", "2026-08-30 10:00:00+00:00", "2026-08-30 10:01:00+00:00", "1"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 2
    assert all(r["artifact_type"] == "leapp_call_log" for r in records)
    assert {r["timestamp"] for r in records} == {1788080400.0, 1788084000.0}


def test_whatsapp_messages_and_one_to_one_share_the_same_timestamp_column(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    for name in ("WhatsApp - Messages.tsv", "WhatsApp - One To One Messages.tsv"):
        _write_tsv(str(tsv_dir / name),
                   ["Message Timestamp", "Received Timestamp", "Direction", "Message"],
                   [["2026-08-30 12:00:00+00:00", "2026-08-30 12:00:01+00:00", "Sent", "hey"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 2
    assert all(r["artifact_type"] == "leapp_whatsapp_message" for r in records)
    assert all(r["timestamp"] == 1788091200.0 for r in records)


def test_browser_history_folds_chrome_and_firefox_column_name_variants(tmp_path):
    # Chrome's real column is "Last Visit Time"; Firefox's is "Last Visit
    # Date" - both real, both fold into the same leapp_browser_history
    # artifact_type, and LEAPP_TIMESTAMP_COLUMNS must try both names.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Web History.tsv"),
               ["Last Visit Time", "URL", "Title", "Browser Name"],
               [["2026-08-30 08:00:00+00:00", "https://example.com", "Example", "Chrome"]])
    _write_tsv(str(tsv_dir / "Firefox - Web History.tsv"),
               ["Last Visit Date", "URL", "Title"],
               [["2026-08-30 08:30:00+00:00", "https://example.org", "Example Org"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 2
    assert all(r["artifact_type"] == "leapp_browser_history" for r in records)
    assert {r["timestamp"] for r in records} == {1788076800.0, 1788078600.0}


def test_social_media_message_module_timestamp_parsed(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Instagram - Direct Messages.tsv"),
               ["Timestamp", "Media Taken At", "Direction", "Sender"],
               [["2026-08-30 06:00:00+00:00", "", "Received", "alice"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "leapp_instagram_message"
    assert records[0]["timestamp"] == 1788069600.0


def test_missing_timestamp_column_stays_none_not_a_wrong_guess(tmp_path):
    # A real SMS Messages TSV whose header row happens to lack "Date"
    # entirely (a hypothetical older/renamed ALEAPP version) - must never
    # fabricate a timestamp from some other column.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "SMS Messages.tsv"), ["Address", "Body"],
               [["555-0100", "hi"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert records[0]["timestamp"] is None


def test_unparseable_timestamp_value_stays_none_not_a_crash(tmp_path):
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "SMS Messages.tsv"), ["Date", "Body"],
               [["not a real timestamp", "hi"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert records[0]["timestamp"] is None


def test_empty_timestamp_cell_stays_none(tmp_path):
    # ALEAPP's own _ms_to_utc()-style helpers return '' for a falsy raw
    # value, which csv.writer then writes as a genuinely empty cell.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "SMS Messages.tsv"), ["Date", "Body"], [["", "draft, never sent"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert records[0]["timestamp"] is None


def test_uncurated_module_never_gets_a_timestamp():
    # leapp_module_finding is deliberately absent from LEAPP_TIMESTAMP_COLUMNS
    assert "leapp_module_finding" not in leapp.LEAPP_TIMESTAMP_COLUMNS


def test_installed_app_timestamp_parsed_from_vending_and_library_real_module_headers(tmp_path):
    # 2026-09-04, Android pattern-of-life item 4 - leapp_installed_app maps
    # 3 real, structurally different ALEAPP modules; only 2 of them carry
    # any timestamp. InstalledappsVending's real header has BOTH
    # 'First Download' and 'Last Updated' - 'First Download' must win
    # since it's listed first in LEAPP_TIMESTAMP_COLUMNS.
    # InstalledappsLibrary's real header only has 'Purchase Time'.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "InstalledappsVending.tsv"),
               ["User", "First Download", "Package Name", "Title", "Install Reason",
                "Last Updated", "Auto Update?", "Account"],
               [["0", "2026-08-30 07:00:00+00:00", "com.example.vending", "Example App",
                 "user-initiated", "2026-08-31 09:00:00+00:00", "1", "user@example.com"]])
    _write_tsv(str(tsv_dir / "InstalledappsLibrary.tsv"),
               ["User", "Purchase Time", "Account", "Doc ID"],
               [["0", "2026-08-29 05:00:00+00:00", "user@example.com", "abc123"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 2
    by_source = {r["extra"]["leapp_module"]: r for r in records}
    assert all(r["artifact_type"] == "leapp_installed_app" for r in records)
    assert by_source["InstalledappsVending"]["timestamp"] == 1788073200.0  # First Download, not Last Updated
    assert by_source["InstalledappsLibrary"]["timestamp"] == 1787979600.0  # Purchase Time


def test_installed_app_gass_module_has_genuinely_no_timestamp_column_at_all(tmp_path):
    # InstalledappsGass's real data_headers is ('User', 'Bundle ID',
    # 'Version Code', 'SHA-256 Hash') - no datetime column exists in the
    # source module itself, so timestamp=None here is the honestly
    # correct outcome, not a gap this fix could ever close.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "InstalledappsGass.tsv"),
               ["User", "Bundle ID", "Version Code", "SHA-256 Hash"],
               [["0", "com.example.gass", "1", "deadbeef"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "leapp_installed_app"
    assert records[0]["timestamp"] is None


def test_app_usage_timestamp_parsed_from_the_primary_datetime_column(tmp_path):
    # usagestats.py's real data_headers has 4 separate datetime-typed
    # columns - 'Timestamp / Last Time Active' is the module's own
    # primary per-event field, listed first.
    tsv_dir = tmp_path / "_TSV Exports"
    tsv_dir.mkdir()
    _write_tsv(str(tsv_dir / "Usage Stats.tsv"),
               ["User (UID)", "Timestamp / Last Time Active", "Usage Type", "Package"],
               [["10123", "2026-08-30 14:00:00+00:00", "MOVE_TO_FOREGROUND", "com.example.app"]])
    records, _, _ = leapp.parse_leapp_tsv_exports(str(tsv_dir), "aleapp")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "leapp_app_usage"
    assert records[0]["timestamp"] == 1788098400.0


def test_all_artifact_types_constant_matches_actual_curated_values():
    # Guards against the module's own two sources of truth (the curated
    # dict's values, and the exported "every type this module can
    # produce" set the regression test in test_parsed_artifact_type_
    # labels.py imports directly) drifting apart.
    assert leapp.LEAPP_TSV_ALL_ARTIFACT_TYPES == set(leapp.CURATED_LEAPP_MODULES.values()) | {"leapp_module_finding"}
