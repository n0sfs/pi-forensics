"""core/takeout_utils.py - Google Takeout archive import (Android
forensics expansion, Phase D). Pure stdlib (json/csv/zipfile/os), no
third-party library needed. Fixtures are hand-built matching the real,
researched Takeout formats documented in the module's own docstring -
both the high-confidence My Activity schema and the best-effort Location
History/Maps/Photos formats, including their real documented format
variance (legacy Records.json vs. new Timeline.json; GeoJSON vs. CSV for
Maps).
"""
import json
import mailbox
import os
import zipfile

import core.takeout_utils as takeout


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(text)


# --- prepare_takeout_root / zip handling ---

def test_prepare_takeout_root_uses_an_already_extracted_folder_directly(tmp_path):
    folder = tmp_path / "Takeout"
    folder.mkdir()
    root, extracted, skipped = takeout.prepare_takeout_root([str(folder)], str(tmp_path / "work"))
    assert root == str(folder)
    assert extracted == 0 and skipped == 0


def test_prepare_takeout_root_extracts_a_real_zip(tmp_path):
    zip_path = tmp_path / "takeout-20260101-001.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("Takeout/My Activity/Search/MyActivity.json", "[]")
        zf.writestr("Takeout/YouTube and YouTube Music/history/watch-history.json", "[]")
    work_dir = str(tmp_path / "work")
    root, extracted, skipped = takeout.prepare_takeout_root([str(zip_path)], work_dir)
    assert root == work_dir
    assert extracted == 2
    assert skipped == 0
    assert os.path.isfile(os.path.join(work_dir, "Takeout", "My Activity", "Search", "MyActivity.json"))


def test_safe_extract_zip_blocks_a_zip_slip_traversal_entry(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("../../../../etc/passwd_takeout_test", "malicious content")
        zf.writestr("Takeout/legit.json", "{}")
    dest = tmp_path / "safe_dest"
    dest.mkdir()
    extracted, skipped = takeout._safe_extract_zip(str(zip_path), str(dest))
    assert extracted == 1  # only the legit entry
    assert skipped == 1    # the traversal entry was rejected, not written
    # Confirm the malicious path was never created anywhere outside dest
    assert not os.path.exists(str(tmp_path / "etc" / "passwd_takeout_test"))
    assert os.path.isfile(str(dest / "Takeout" / "legit.json"))


def test_safe_extract_zip_multi_part_merges_into_one_work_dir(tmp_path):
    zip1 = tmp_path / "takeout-001.zip"
    zip2 = tmp_path / "takeout-002.zip"
    with zipfile.ZipFile(zip1, 'w') as zf:
        zf.writestr("Takeout/My Activity/Search/MyActivity.json", "[]")
    with zipfile.ZipFile(zip2, 'w') as zf:
        zf.writestr("Takeout/Google Photos/IMG_1.jpg.json", "{}")
    work_dir = str(tmp_path / "work")
    root, extracted, skipped = takeout.prepare_takeout_root([str(zip1), str(zip2)], work_dir)
    assert extracted == 2
    assert os.path.isfile(os.path.join(work_dir, "Takeout", "My Activity", "Search", "MyActivity.json"))
    assert os.path.isfile(os.path.join(work_dir, "Takeout", "Google Photos", "IMG_1.jpg.json"))


# --- find_takeout_product_folders ---

def test_find_takeout_product_folders_matches_real_and_renamed_names(tmp_path):
    root = tmp_path / "Takeout"
    (root / "My Activity").mkdir(parents=True)
    (root / "YouTube and YouTube Music").mkdir()
    (root / "Location History (Timeline)").mkdir()  # the renamed real folder name
    (root / "Maps (your places)").mkdir()
    (root / "Google Photos").mkdir()
    (root / "Mail").mkdir()  # the real, confirmed Gmail product folder name
    (root / "Contacts").mkdir()
    (root / "Calendar").mkdir()
    found = takeout.find_takeout_product_folders(str(tmp_path))  # note: passing the parent, not Takeout/ itself
    assert set(found.keys()) == {
        "search_history", "youtube_history", "location_history", "maps", "photos",
        "gmail", "contacts", "calendar",
    }


def test_find_takeout_product_folders_mail_pattern_does_not_match_email(tmp_path):
    # \bmail\b is a word-boundary match, deliberately NOT a bare substring
    # match - a hypothetical "Email" or "Voicemail" product folder must
    # never be mistaken for the real "Mail" (Gmail) product.
    root = tmp_path / "Takeout"
    (root / "Email Something Unrelated").mkdir(parents=True)
    (root / "Voicemail Archive").mkdir()
    found = takeout.find_takeout_product_folders(str(tmp_path))
    assert "gmail" not in found


def test_find_takeout_product_folders_partial_export_is_not_an_error(tmp_path):
    root = tmp_path / "Takeout"
    (root / "My Activity").mkdir(parents=True)
    found = takeout.find_takeout_product_folders(str(tmp_path))
    assert found == {"search_history": str(root / "My Activity")}


# --- Search History / YouTube History (HIGH CONFIDENCE) ---

def test_parse_search_history_real_my_activity_schema(tmp_path):
    folder = tmp_path / "My Activity" / "Search"
    _write_json(str(folder / "MyActivity.json"), [
        {"header": "Search", "title": "Searched for pizza near me",
         "titleUrl": "https://www.google.com/search?q=pizza", "time": "2026-01-15T10:30:00Z",
         "products": ["Search"]},
    ])
    records = takeout.parse_takeout_search_history(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "takeout_search_history"
    assert r["title"] == "Searched for pizza near me"
    assert r["url"] == "https://www.google.com/search?q=pizza"
    assert r["timestamp"] is not None


def test_parse_youtube_history_real_schema(tmp_path):
    folder = tmp_path / "YouTube and YouTube Music" / "history"
    _write_json(str(folder / "watch-history.json"), [
        {"header": "YouTube", "title": "Watched Some Real Video Title",
         "titleUrl": "https://www.youtube.com/watch?v=abc123", "time": "2026-02-01T08:00:00Z"},
    ])
    records = takeout.parse_takeout_youtube_history(str(tmp_path))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "takeout_youtube_history"
    assert records[0]["title"] == "Watched Some Real Video Title"


def test_parse_my_activity_json_tolerates_malformed_file(tmp_path):
    path = tmp_path / "MyActivity.json"
    path.write_text("not valid json {{{")
    assert takeout._parse_my_activity_json(str(path), "takeout_search_history") == []


def test_parse_my_activity_json_tolerates_wrong_top_level_shape(tmp_path):
    path = tmp_path / "MyActivity.json"
    path.write_text('{"not": "a list"}')
    assert takeout._parse_my_activity_json(str(path), "takeout_search_history") == []


# --- Location History (BEST-EFFORT: legacy Records.json) ---

def test_parse_legacy_records_json_real_shape(tmp_path):
    path = tmp_path / "Records.json"
    _write_json(str(path), {"locations": [
        {"latitudeE7": 377749000, "longitudeE7": -1224194000, "timestamp": "2026-01-01T12:00:00.000Z"},
    ]})
    records = takeout._parse_legacy_records_json(str(path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "takeout_location_history"
    assert abs(r["extra"]["lat"] - 37.7749) < 0.0001
    assert abs(r["extra"]["lon"] - (-122.4194)) < 0.0001
    assert r["extra"]["source_format"] == "records_json"


def test_parse_legacy_records_json_skips_entries_missing_coordinates(tmp_path):
    path = tmp_path / "Records.json"
    _write_json(str(path), {"locations": [{"timestamp": "2026-01-01T00:00:00Z"}]})
    assert takeout._parse_legacy_records_json(str(path)) == []


# --- Location History (BEST-EFFORT: new Timeline.json/semanticSegments) ---

def test_parse_timeline_json_android_shape_decimal_string():
    # Android: object wrapper, "45.4642°, 9.1900°" decimal-degree string
    point = takeout._timeline_json_point({"placeLocation": {"latLng": "45.4642°, 9.1900°"}})
    assert point is not None
    assert abs(point[0] - 45.4642) < 0.0001
    assert abs(point[1] - 9.1900) < 0.0001


def test_parse_timeline_json_ios_shape_geo_uri_string():
    # iOS: bare geo: URI string, confirmed distinct field shape from Android
    point = takeout._timeline_json_point({"placeLocation": "geo:37.7749,-122.4194"})
    assert point is not None
    assert abs(point[0] - 37.7749) < 0.0001
    assert abs(point[1] - (-122.4194)) < 0.0001


def test_timeline_json_point_returns_none_for_unrecognized_shape():
    assert takeout._timeline_json_point({"someOtherField": "irrelevant"}) is None
    assert takeout._timeline_json_point("not a dict") is None
    assert takeout._timeline_json_point(None) is None


def test_parse_timeline_json_full_file_android_wrapped_object(tmp_path):
    path = tmp_path / "Timeline.json"
    _write_json(str(path), {"semanticSegments": [
        {"startTime": "2026-01-01T09:00:00Z", "visit": {"placeLocation": {"latLng": "37.7749°, -122.4194°"}}},
    ]})
    records = takeout._parse_timeline_json(str(path))
    assert len(records) == 1
    assert records[0]["extra"]["source_format"] == "timeline_json"
    assert records[0]["timestamp"] is not None


def test_parse_timeline_json_full_file_ios_bare_array(tmp_path):
    # iOS ships semanticSegments as a bare top-level array, no wrapper object
    path = tmp_path / "Timeline.json"
    _write_json(str(path), [
        {"startTime": "2026-01-01T09:00:00Z", "visit": {"placeLocation": "geo:37.7749,-122.4194"}},
    ])
    records = takeout._parse_timeline_json(str(path))
    assert len(records) == 1


def test_parse_takeout_location_history_dispatches_both_real_formats(tmp_path):
    _write_json(str(tmp_path / "Records.json"), {"locations": [
        {"latitudeE7": 377749000, "longitudeE7": -1224194000},
    ]})
    _write_json(str(tmp_path / "Timeline.json"), {"semanticSegments": [
        {"startTime": "2026-01-01T09:00:00Z", "visit": {"placeLocation": {"latLng": "45.4642°, 9.1900°"}}},
    ]})
    records = takeout.parse_takeout_location_history(str(tmp_path))
    assert len(records) == 2
    formats = {r["extra"]["source_format"] for r in records}
    assert formats == {"records_json", "timeline_json"}


# --- Maps Places (BEST-EFFORT: GeoJSON or CSV) ---

def test_parse_maps_geojson_real_shape(tmp_path):
    path = tmp_path / "Saved Places.json"
    _write_json(str(path), {"type": "FeatureCollection", "features": [
        {"type": "Feature", "properties": {"name": "Golden Gate Bridge", "google_maps_url": "https://maps.google.com/?cid=1"},
         "geometry": {"type": "Point", "coordinates": [-122.4783, 37.8199]}},
    ]})
    records = takeout._parse_maps_geojson(str(path))
    assert len(records) == 1
    r = records[0]
    assert r["title"] == "Golden Gate Bridge"
    assert abs(r["extra"]["lat"] - 37.8199) < 0.0001
    assert abs(r["extra"]["lon"] - (-122.4783)) < 0.0001


def test_parse_maps_csv_variant(tmp_path):
    path = tmp_path / "Want to go.csv"
    path.write_text("Title,Note,URL\nFisherman's Wharf,Visit in summer,https://maps.google.com/?cid=2\n")
    records = takeout._parse_maps_csv(str(path))
    assert len(records) == 1
    assert records[0]["title"] == "Fisherman's Wharf"


def test_parse_maps_places_dispatches_both_formats(tmp_path):
    _write_json(str(tmp_path / "Saved Places.json"), {"features": [
        {"properties": {"name": "Place A"}, "geometry": {"coordinates": [1.0, 2.0]}},
    ]})
    (tmp_path / "Starred places.csv").write_text("Title\nPlace B\n")
    records = takeout.parse_takeout_maps_places(str(tmp_path))
    assert {r["title"] for r in records} == {"Place A", "Place B"}


# --- Photos sidecars (BEST-EFFORT) ---

def test_parse_photos_sidecar_real_shape(tmp_path):
    photos_dir = tmp_path / "Google Photos" / "Photos from 2026"
    photos_dir.mkdir(parents=True)
    (photos_dir / "IMG_1234.jpg").write_bytes(b"fake jpeg bytes")
    _write_json(str(photos_dir / "IMG_1234.jpg.json"), {
        "photoTakenTime": {"timestamp": "1700000000", "formatted": "Jan 1, 2026"},
        "geoData": {"latitude": 37.7749, "longitude": -122.4194, "altitude": 10.0},
    })
    records = takeout.parse_takeout_photos_sidecars(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "takeout_photo_metadata"
    assert r["extra"]["original_filename"] == "IMG_1234.jpg"
    assert abs(r["extra"]["lat"] - 37.7749) < 0.0001
    assert r["timestamp"] == 1700000000.0


def test_parse_photos_sidecar_no_geodata_excludes_lat_lon(tmp_path):
    photos_dir = tmp_path / "Google Photos"
    photos_dir.mkdir(parents=True)
    _write_json(str(photos_dir / "IMG_no_geo.jpg.json"), {
        "photoTakenTime": {"timestamp": "1700000000"},
        "geoData": {"latitude": 0.0, "longitude": 0.0},  # Google's own "no location" sentinel
    })
    records = takeout.parse_takeout_photos_sidecars(str(photos_dir))
    assert len(records) == 1
    assert "lat" not in records[0]["extra"]


def test_parse_photos_sidecar_ignores_non_sidecar_json(tmp_path):
    photos_dir = tmp_path / "Google Photos"
    photos_dir.mkdir(parents=True)
    _write_json(str(photos_dir / "metadata.json"), {"some": "unrelated data"})
    assert takeout.parse_takeout_photos_sidecars(str(photos_dir)) == []


# --- import_takeout_archive (top-level dispatcher) ---

# --- Gmail (Mail/*.mbox) - HIGH CONFIDENCE, reuses core/email_utils.py ---

def test_parse_takeout_gmail_reuses_email_message_type_not_a_new_one(tmp_path):
    # Deliberately email_message, not "takeout_gmail_message" - see this
    # module's own docstring on why Gmail (unlike Contacts/Calendar)
    # rides the same generic bucket every other desktop mail format
    # already shares, rather than getting a source-scoped type.
    mbox_path = tmp_path / "All mail Including Spam and Trash.mbox"
    box = mailbox.mbox(str(mbox_path))
    box.lock()
    try:
        msg = mailbox.mboxMessage()
        msg['Subject'] = 'Real Gmail Message'
        msg['From'] = 'sender@example.com'
        msg['Date'] = 'Mon, 30 Aug 2026 12:00:00 -0000'
        msg.set_payload('Body text')
        box.add(msg)
        box.flush()
    finally:
        box.unlock()
        box.close()
    records = takeout.parse_takeout_gmail(str(tmp_path))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "email_message"
    assert records[0]["title"] == "Real Gmail Message"


def test_parse_takeout_gmail_multiple_mbox_files_one_per_label(tmp_path):
    # A real, confirmed Takeout behavior: selecting specific labels
    # (instead of "All Mail") produces one separate .mbox file per label -
    # this parser must find and combine all of them, not just the first.
    for label in ("Inbox", "Sent"):
        mbox_path = tmp_path / f"{label}.mbox"
        box = mailbox.mbox(str(mbox_path))
        box.lock()
        try:
            msg = mailbox.mboxMessage()
            msg['Subject'] = f'{label} message'
            box.add(msg)
            box.flush()
        finally:
            box.unlock()
            box.close()
    records = takeout.parse_takeout_gmail(str(tmp_path))
    assert {r["title"] for r in records} == {"Inbox message", "Sent message"}


def test_parse_takeout_gmail_no_mbox_files_returns_empty(tmp_path):
    assert takeout.parse_takeout_gmail(str(tmp_path)) == []


# --- Contacts (Contacts/**/*.vcf) - HIGH CONFIDENCE, reuses core/apple_export_utils.py ---

def test_parse_takeout_contacts_real_rfc_shape_gets_takeout_type(tmp_path):
    path = tmp_path / "All Contacts" / "All Contacts.vcf"
    _write(str(path),
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:Jane Doe\r\n"
        "TEL;TYPE=CELL:+15551112222\r\n"
        "EMAIL;TYPE=HOME:jane@example.com\r\n"
        "END:VCARD\r\n")
    records = takeout.parse_takeout_contacts(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    # takeout_contact, NOT apple_contact - the whole point of the
    # artifact_type parameterization this feature added.
    assert r["artifact_type"] == "takeout_contact"
    assert r["title"] == "Jane Doe"
    assert "+15551112222" in r["value"]


def test_parse_takeout_contacts_walks_multiple_real_subfolders(tmp_path):
    # A real Contacts export commonly nests several subfolders (All
    # Contacts/My Contacts/Starred in Android) - confirms recursive
    # discovery finds contacts across all of them, not just the first.
    _write(str(tmp_path / "All Contacts" / "All Contacts.vcf"), "BEGIN:VCARD\r\nFN:Alice\r\nEND:VCARD\r\n")
    _write(str(tmp_path / "Starred in Android" / "Starred in Android.vcf"), "BEGIN:VCARD\r\nFN:Bob\r\nEND:VCARD\r\n")
    records = takeout.parse_takeout_contacts(str(tmp_path))
    assert {r["title"] for r in records} == {"Alice", "Bob"}
    assert all(r["artifact_type"] == "takeout_contact" for r in records)


def test_parse_takeout_contacts_no_vcf_files_returns_empty(tmp_path):
    assert takeout.parse_takeout_contacts(str(tmp_path)) == []


# --- Calendar (Calendar/*.ics) - HIGH CONFIDENCE, reuses core/apple_export_utils.py ---

def test_parse_takeout_calendar_real_vevent_gets_takeout_event_type(tmp_path):
    path = tmp_path / "user@gmail.com.ics"
    _write(str(path),
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VEVENT\r\n"
        "SUMMARY:Team Meeting\r\n"
        "DTSTART:20260115T093000Z\r\n"
        "LOCATION:Conference Room A\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n")
    records = takeout.parse_takeout_calendar(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "takeout_calendar_event"
    assert r["title"] == "Team Meeting"
    assert r["timestamp"] is not None


def test_parse_takeout_calendar_vtodo_becomes_takeout_reminder(tmp_path):
    path = tmp_path / "Secondary-Calendar-Id.ics"
    _write(str(path),
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VTODO\r\n"
        "SUMMARY:Pick up dry cleaning\r\n"
        "DUE:20260116T170000Z\r\n"
        "END:VTODO\r\n"
        "END:VCALENDAR\r\n")
    records = takeout.parse_takeout_calendar(str(tmp_path))
    assert len(records) == 1
    assert records[0]["artifact_type"] == "takeout_reminder"
    assert records[0]["title"] == "Pick up dry cleaning"


def test_parse_takeout_calendar_multiple_ics_files_one_per_calendar(tmp_path):
    # Real, confirmed Takeout behavior: one .ics per owned calendar, not
    # a single combined file - the primary calendar's filename pattern
    # (account email) and a secondary calendar's opaque-ID filename must
    # both be found, since discovery is extension-based, not name-based.
    _write(str(tmp_path / "user@gmail.com.ics"),
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Primary Cal Event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    _write(str(tmp_path / "a1b2c3d4e5f6@group.calendar.google.com.ics"),
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Secondary Cal Event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    records = takeout.parse_takeout_calendar(str(tmp_path))
    assert {r["title"] for r in records} == {"Primary Cal Event", "Secondary Cal Event"}


def test_parse_takeout_calendar_no_ics_files_returns_empty(tmp_path):
    assert takeout.parse_takeout_calendar(str(tmp_path)) == []


# --- Full dispatcher coverage for the 3 new products ---

def test_import_takeout_archive_covers_gmail_contacts_calendar_no_warnings(tmp_path):
    root = tmp_path / "Takeout"
    mbox_path = root / "Mail" / "All mail Including Spam and Trash.mbox"
    os.makedirs(mbox_path.parent, exist_ok=True)
    box = mailbox.mbox(str(mbox_path))
    box.lock()
    try:
        msg = mailbox.mboxMessage()
        msg['Subject'] = 'A Gmail message'
        box.add(msg)
        box.flush()
    finally:
        box.unlock()
        box.close()
    _write(str(root / "Contacts" / "All Contacts" / "All Contacts.vcf"),
           "BEGIN:VCARD\r\nFN:Jane Doe\r\nEND:VCARD\r\n")
    _write(str(root / "Calendar" / "user@gmail.com.ics"),
           "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Meeting\r\nDTSTART:20260115T093000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")

    result = takeout.import_takeout_archive(str(tmp_path))
    assert set(result["products_found"]) == {"gmail", "contacts", "calendar"}
    assert {r["artifact_type"] for r in result["records"]} == {
        "email_message", "takeout_contact", "takeout_calendar_event",
    }
    assert len(result["records"]) == 3
    # HIGH CONFIDENCE, same treatment as Search/YouTube History above -
    # none of these three should ever produce a best-effort warning.
    assert result["warnings"] == []


def test_import_takeout_archive_full_realistic_export(tmp_path):
    root = tmp_path / "Takeout"
    _write_json(str(root / "My Activity" / "Search" / "MyActivity.json"), [
        {"title": "Searched for X", "time": "2026-01-01T00:00:00Z"},
    ])
    _write_json(str(root / "Location History (Timeline)" / "Records.json"), {"locations": [
        {"latitudeE7": 377749000, "longitudeE7": -1224194000},
    ]})
    result = takeout.import_takeout_archive(str(tmp_path))
    assert set(result["products_found"]) == {"search_history", "location_history"}
    assert len(result["records"]) == 2
    assert len(result["location_points"]) == 1
    assert result["location_points"][0]["lat"] is not None
    assert any("Location History" in w for w in result["warnings"])
    assert not any("Search" in w for w in result["warnings"])  # high-confidence, no warning needed


def test_import_takeout_archive_empty_export_returns_clean_empty_result(tmp_path):
    (tmp_path / "Takeout").mkdir()
    result = takeout.import_takeout_archive(str(tmp_path))
    assert result["records"] == []
    assert result["location_points"] == []
    assert result["products_found"] == []
    assert result["warnings"] == []
