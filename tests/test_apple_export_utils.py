"""core/apple_export_utils.py - Apple "Data & Privacy" export import.
Pure stdlib (csv/os/re/datetime), no third-party library needed. Fixtures
are hand-built matching the real RFC 6350 (vCard) and RFC 5545
(iCalendar) formats - both genuine open standards with published grammar,
so these fixtures are grounded in the actual spec, not a guess - plus the
best-effort Safari bookmark HTML and Photos CSV formats per this
module's own documented research sources.
"""
import os

import core.apple_export_utils as apple


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


# --- line unfolding (shared by vCard and iCalendar, RFC 6350/5545 §3.2) ---

def test_unfold_lines_rejoins_a_folded_continuation():
    folded = "BEGIN:VCARD\r\nFN:Jane Do\r\n e\r\nEND:VCARD"
    assert apple._unfold_lines(folded) == "BEGIN:VCARD\nFN:Jane Doe\nEND:VCARD"


def test_unfold_lines_handles_bare_lf_real_world_files():
    folded = "BEGIN:VCARD\nFN:Jane Do\n e\nEND:VCARD"
    assert apple._unfold_lines(folded) == "BEGIN:VCARD\nFN:Jane Doe\nEND:VCARD"


def test_split_property_line_splits_on_first_colon_only():
    assert apple._split_property_line("URL:https://example.com/path?a=1:2") == ("URL", "https://example.com/path?a=1:2")


def test_split_property_line_strips_parameters_from_the_name():
    assert apple._split_property_line("TEL;TYPE=CELL:+15551234567") == ("TEL", "+15551234567")


def test_split_property_line_returns_none_for_a_non_property_line():
    assert apple._split_property_line("") is None
    assert apple._split_property_line("just some text with no colon") is None


# --- vCard (RFC 6350) - HIGH CONFIDENCE ---

def test_parse_vcard_real_rfc_shape(tmp_path):
    path = tmp_path / "Contacts.vcf"
    _write(str(path),
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:Jane Doe\r\n"
        "TEL;TYPE=CELL:+15551112222\r\n"
        "EMAIL;TYPE=HOME:jane@example.com\r\n"
        "ORG:Acme Corp\r\n"
        "END:VCARD\r\n")
    records = apple.parse_vcard_file(str(path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "apple_contact"
    assert r["title"] == "Jane Doe"
    assert "+15551112222" in r["value"]
    assert "jane@example.com" in r["value"]
    assert r["extra"]["org"] == "Acme Corp"


def test_parse_vcard_multiple_concatenated_contacts_in_one_file(tmp_path):
    # A real vCard address-book export commonly concatenates many
    # BEGIN:VCARD...END:VCARD blocks in one .vcf file.
    path = tmp_path / "AllContacts.vcf"
    _write(str(path),
        "BEGIN:VCARD\r\nFN:Alice\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nFN:Bob\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nFN:Carol\r\nEND:VCARD\r\n")
    records = apple.parse_vcard_file(str(path))
    assert {r["title"] for r in records} == {"Alice", "Bob", "Carol"}


def test_parse_vcard_no_name_falls_back_to_phone_or_email(tmp_path):
    path = tmp_path / "NoName.vcf"
    _write(str(path), "BEGIN:VCARD\r\nTEL:+15559998888\r\nEND:VCARD\r\n")
    records = apple.parse_vcard_file(str(path))
    assert records[0]["title"] == "+15559998888"


def test_parse_vcard_tolerates_a_malformed_file(tmp_path):
    path = tmp_path / "Broken.vcf"
    _write(str(path), "this is not a real vcard at all")
    assert apple.parse_vcard_file(str(path)) == []


def test_find_apple_vcard_contacts_walks_recursively(tmp_path):
    _write(str(tmp_path / "sub" / "dir" / "Contacts.vcf"), "BEGIN:VCARD\r\nFN:Deep Contact\r\nEND:VCARD\r\n")
    records = apple.find_apple_vcard_contacts(str(tmp_path))
    assert len(records) == 1
    assert records[0]["title"] == "Deep Contact"


# --- iCalendar (RFC 5545) - HIGH CONFIDENCE ---

def test_parse_icalendar_real_vevent_shape(tmp_path):
    path = tmp_path / "Calendar.ics"
    _write(str(path),
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VEVENT\r\n"
        "SUMMARY:Team Meeting\r\n"
        "DTSTART:20260115T093000Z\r\n"
        "DTEND:20260115T100000Z\r\n"
        "LOCATION:Conference Room A\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n")
    records = apple.parse_icalendar_file(str(path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "apple_calendar_event"
    assert r["title"] == "Team Meeting"
    assert "Conference Room A" in r["value"]
    assert r["timestamp"] is not None


def test_parse_icalendar_vtodo_becomes_a_reminder(tmp_path):
    path = tmp_path / "Reminders.ics"
    _write(str(path),
        "BEGIN:VTODO\r\n"
        "SUMMARY:Buy milk\r\n"
        "DUE:20260120\r\n"
        "END:VTODO\r\n")
    records = apple.parse_icalendar_file(str(path))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "apple_reminder"
    assert records[0]["title"] == "Buy milk"


def test_parse_ical_datetime_handles_utc_and_date_only():
    assert apple._parse_ical_datetime("20260115T093000Z") is not None
    assert apple._parse_ical_datetime("20260115") is not None


def test_parse_ical_datetime_returns_none_for_unresolvable_tzid_form():
    # A TZID-qualified local datetime (no Z, named timezone elsewhere) -
    # deliberately not resolved, per the module's own disclosed scope.
    assert apple._parse_ical_datetime("20260115T093000") is None
    assert apple._parse_ical_datetime("not-a-date") is None
    assert apple._parse_ical_datetime(None) is None


def test_parse_icalendar_multiple_events_and_todos_in_one_file(tmp_path):
    path = tmp_path / "Mixed.ics"
    _write(str(path),
        "BEGIN:VEVENT\r\nSUMMARY:Event One\r\nEND:VEVENT\r\n"
        "BEGIN:VEVENT\r\nSUMMARY:Event Two\r\nEND:VEVENT\r\n"
        "BEGIN:VTODO\r\nSUMMARY:Todo One\r\nEND:VTODO\r\n")
    records = apple.parse_icalendar_file(str(path))
    assert len(records) == 3
    events = [r for r in records if r["artifact_type"] == "apple_calendar_event"]
    todos = [r for r in records if r["artifact_type"] == "apple_reminder"]
    assert len(events) == 2 and len(todos) == 1


def test_parse_icalendar_tolerates_malformed_file(tmp_path):
    path = tmp_path / "Broken.ics"
    _write(str(path), "not a real calendar file")
    assert apple.parse_icalendar_file(str(path)) == []


def test_find_apple_icalendar_events_walks_recursively(tmp_path):
    _write(str(tmp_path / "sub" / "Calendar.ics"), "BEGIN:VEVENT\r\nSUMMARY:Deep Event\r\nEND:VEVENT\r\n")
    records = apple.find_apple_icalendar_events(str(tmp_path))
    assert len(records) == 1


# --- Safari Bookmarks (BEST-EFFORT: NETSCAPE-Bookmark-file HTML) ---

def test_parse_safari_bookmarks_real_netscape_format(tmp_path):
    path = tmp_path / "Bookmarks.html"
    _write(str(path),
        '<!DOCTYPE NETSCAPE-Bookmark-file-1>\n'
        '<DT><A HREF="https://example.com" ADD_DATE="1700000000">Example Site</A>\n'
        '<DT><A HREF="https://another.example.com">Another Site</A>\n')
    records = apple.parse_safari_bookmarks_html(str(path))
    assert len(records) == 2
    first = records[0]
    assert first["artifact_type"] == "apple_safari_bookmark"
    assert first["title"] == "Example Site"
    assert first["url"] == "https://example.com"
    assert first["timestamp"] == 1700000000.0
    assert records[1]["timestamp"] is None  # no ADD_DATE present - honestly None, not fabricated


def test_find_apple_safari_bookmarks_matches_by_filename_pattern(tmp_path):
    _write(str(tmp_path / "MyBookmarks.html"), '<A HREF="https://x.com">X</A>')
    _write(str(tmp_path / "unrelated.html"), '<A HREF="https://y.com">Y</A>')
    records = apple.find_apple_safari_bookmarks(str(tmp_path))
    assert len(records) == 1
    assert records[0]["url"] == "https://x.com"


# --- Photos metadata CSV (BEST-EFFORT) ---

def test_parse_photos_metadata_csv_real_reported_shape(tmp_path):
    path = tmp_path / "Photo details-1.csv"
    _write(str(path), "imgName,fileChecksum,favorite,hidden,deleted,originalCreationDate,viewCount,importDate\n"
                       "IMG_1234.jpg,abc123,false,false,false,2026-01-01,5,2026-01-02\n")
    records = apple.parse_apple_photos_metadata_csv(str(path))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "apple_photo_metadata"
    assert records[0]["title"] == "IMG_1234.jpg"
    assert records[0]["extra"]["fileChecksum"] == "abc123"


def test_parse_photos_metadata_csv_skips_rows_with_no_name_column(tmp_path):
    path = tmp_path / "Photo details-2.csv"
    _write(str(path), "somethingElse,other\nvalue1,value2\n")
    assert apple.parse_apple_photos_metadata_csv(str(path)) == []


def test_find_apple_photos_metadata_finds_photos_dir_even_with_no_csv(tmp_path):
    photos = tmp_path / "iCloud Photos" / "All Photos"
    photos.mkdir(parents=True)
    (photos / "IMG_0001.heic").write_bytes(b"fake heic bytes")
    photos_dir, records = apple.find_apple_photos_metadata(str(tmp_path))
    assert photos_dir == str(photos)
    assert records == []


def test_find_apple_photos_metadata_finds_both_dir_and_csv(tmp_path):
    photos = tmp_path / "Photos"
    photos.mkdir()
    (photos / "IMG_0001.jpg").write_bytes(b"fake jpeg")
    _write(str(photos / "Photo details-1.csv"), "imgName\nIMG_0001.jpg\n")
    photos_dir, records = apple.find_apple_photos_metadata(str(tmp_path))
    assert photos_dir == str(photos)
    assert len(records) == 1


# --- import_apple_export (top-level dispatcher) ---

def test_import_apple_export_full_realistic_export(tmp_path):
    _write(str(tmp_path / "Contacts" / "Contacts.vcf"), "BEGIN:VCARD\r\nFN:Jane\r\nEND:VCARD\r\n")
    _write(str(tmp_path / "Calendars" / "Calendar.ics"), "BEGIN:VEVENT\r\nSUMMARY:Meeting\r\nEND:VEVENT\r\n")
    _write(str(tmp_path / "Safari" / "Bookmarks.html"), '<A HREF="https://x.com">X</A>')
    photos = tmp_path / "Photos"
    photos.mkdir()
    (photos / "IMG_0001.jpg").write_bytes(b"fake jpeg")

    result = apple.import_apple_export(str(tmp_path))
    assert set(result["products_found"]) == {"contacts", "calendars_reminders", "safari_bookmarks", "photos"}
    assert len(result["records"]) == 3  # 1 contact + 1 event + 1 bookmark (photos dir has no CSV record)
    assert result["photos_dir"] == str(photos)
    assert any("Safari" in w for w in result["warnings"])
    assert any("Photos" in w for w in result["warnings"])
    assert not any("Contacts" in w for w in result["warnings"])  # high-confidence, no warning needed
    assert not any("Calendar" in w for w in result["warnings"])


def test_import_apple_export_empty_export_returns_clean_empty_result(tmp_path):
    result = apple.import_apple_export(str(tmp_path))
    assert result["records"] == []
    assert result["photos_dir"] is None
    assert result["products_found"] == []
    assert result["warnings"] == []


def test_import_apple_export_partial_export_is_not_an_error(tmp_path):
    # Only Contacts present - a real examiner might only have requested
    # some categories from Apple's own export tool.
    _write(str(tmp_path / "Contacts.vcf"), "BEGIN:VCARD\r\nFN:Solo\r\nEND:VCARD\r\n")
    result = apple.import_apple_export(str(tmp_path))
    assert result["products_found"] == ["contacts"]
    assert len(result["records"]) == 1
