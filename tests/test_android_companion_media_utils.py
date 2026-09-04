"""Tests for core/android_companion_media_utils.py - the non-rooted,
no-root companion-app Photos/Video metadata extraction feature (the
pif-companion.apk relay's 5th/6th data type, 2026-09-04).

parse_content_query_output() itself is already thoroughly tested in
tests/test_android_companion_sms_utils.py (it's shared, unmodified code) -
this file focuses on build_companion_media_records() and the module's own
real-API-reference-confirmed query-column constants and timestamp-unit
handling.
"""
from core.android_companion_sms_utils import parse_content_query_output
from core.android_companion_media_utils import (
    build_companion_media_records, MEDIA_QUERY_COLUMNS,
)


def test_media_query_columns_has_freeform_fields_last():
    # The single most load-bearing invariant this module depends on - see
    # both this module's and parse_content_query_output()'s own docstrings.
    assert MEDIA_QUERY_COLUMNS[-3:] == ["bucket_display_name", "_data", "_display_name"]


def test_build_companion_media_records_basic_image():
    rows = [{"_id": "1", "bucket_id": "10", "date_added": "1700000000", "date_modified": "1700000100",
             "datetaken": "1699999000000", "width": "4032", "height": "3024", "orientation": "0",
             "duration": "", "mime_type": "image/jpeg", "is_trashed": "0", "is_favorite": "0",
             "is_pending": "0", "is_download": "0", "owner_package_name": "com.android.camera2",
             "relative_path": "DCIM/Camera/", "volume_name": "external", "_size": "3145728",
             "bucket_display_name": "Camera", "_data": "/storage/emulated/0/DCIM/Camera/IMG_001.jpg",
             "_display_name": "IMG_001.jpg"}]
    records = build_companion_media_records(rows, "image")
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_companion_media_image"
    assert r["title"] == "IMG_001.jpg"
    # datetaken present and nonzero -> used directly (milliseconds -> seconds).
    assert r["timestamp"] == 1699999000.0
    assert "image/jpeg" in r["value"]
    assert "4032x3024" in r["value"]
    assert "Album: Camera" in r["value"]
    assert "From: com.android.camera2" in r["value"]
    assert r["extra"]["path"] == "/storage/emulated/0/DCIM/Camera/IMG_001.jpg"
    assert r["extra"]["size_bytes"] == 3145728


def test_build_companion_media_records_video_includes_duration_in_value():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "width": "1920", "height": "1080", "duration": "45230", "mime_type": "video/mp4",
             "_display_name": "VID_001.mp4"}]
    records = build_companion_media_records(rows, "video")
    r = records[0]
    assert r["artifact_type"] == "android_companion_media_video"
    assert "45.2s" in r["value"]
    assert r["extra"]["duration_ms"] == 45230


def test_build_companion_media_records_image_never_shows_duration_in_value():
    # duration is a shared MediaColumns field, but only meaningful for
    # video/audio - never surfaced in an image's own value string even if
    # somehow present in the row.
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "duration": "1000", "mime_type": "image/png", "_display_name": "screenshot.png"}]
    records = build_companion_media_records(rows, "image")
    assert "s" not in records[0]["value"].split("|")[0]  # no bare duration-seconds token for images


def test_build_companion_media_records_timestamp_falls_back_to_date_modified_when_no_datetaken():
    # Mirrors MediaColumns.INFERRED_DATE's own real, documented derivation
    # logic exactly (confirmed live against the Android API reference,
    # not guessed): DATE_TAKEN if present, else DATE_MODIFIED. date_added/
    # date_modified are SECONDS since epoch (no /1000 conversion) - a real,
    # easy-to-get-backwards distinction from datetaken's milliseconds.
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000500", "datetaken": "",
             "mime_type": "video/mp4", "_display_name": "screen_recording.mp4"}]
    records = build_companion_media_records(rows, "video")
    assert records[0]["timestamp"] == 1700000500.0


def test_build_companion_media_records_timestamp_none_when_both_missing():
    rows = [{"_id": "1", "date_added": "", "date_modified": "", "datetaken": "", "mime_type": "image/jpeg",
             "_display_name": "x.jpg"}]
    records = build_companion_media_records(rows, "image")
    assert records[0]["timestamp"] is None


def test_build_companion_media_records_trashed_flag_shown_in_value():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "is_trashed": "1", "mime_type": "image/jpeg", "_display_name": "deleted.jpg"}]
    records = build_companion_media_records(rows, "image")
    assert records[0]["extra"]["is_trashed"] is True
    assert "TRASHED" in records[0]["value"]


def test_build_companion_media_records_favorite_pending_download_flags():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "is_favorite": "1", "is_pending": "1", "is_download": "1",
             "mime_type": "image/jpeg", "_display_name": "x.jpg"}]
    records = build_companion_media_records(rows, "image")
    extra = records[0]["extra"]
    assert extra["is_favorite"] is True
    assert extra["is_pending"] is True
    assert extra["is_download"] is True
    value = records[0]["value"]
    assert "FAVORITE" in value
    assert "PENDING" in value
    assert "DOWNLOAD" in value
    assert "TRASHED" not in value  # not set for this row


def test_build_companion_media_records_no_flags_produces_no_flag_segment():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "mime_type": "image/jpeg", "_display_name": "x.jpg"}]
    records = build_companion_media_records(rows, "image")
    for flag in ("TRASHED", "FAVORITE", "PENDING", "DOWNLOAD"):
        assert flag not in records[0]["value"]


def test_build_companion_media_records_missing_display_name_gets_placeholder():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "mime_type": "image/jpeg", "_display_name": ""}]
    records = build_companion_media_records(rows, "image")
    assert records[0]["title"] == "(unnamed file)"


def test_build_companion_media_records_no_owner_package_omitted_from_value():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "owner_package_name": "", "mime_type": "image/jpeg", "_display_name": "x.jpg"}]
    records = build_companion_media_records(rows, "image")
    assert "From:" not in records[0]["value"]
    assert records[0]["extra"]["owner_package_name"] is None


def test_build_companion_media_records_shape():
    rows = [{"_id": "1", "date_added": "1700000000", "date_modified": "1700000000", "datetaken": "",
             "mime_type": "image/jpeg", "_display_name": "x.jpg"}]
    records = build_companion_media_records(rows, "image")
    assert set(records[0].keys()) == {"artifact_type", "title", "url", "value", "timestamp", "extra"}


def test_end_to_end_parse_then_build_image():
    # Confirms the shared parse_content_query_output() genuinely feeds
    # build_companion_media_records() correctly - not just tested against
    # hand-built dicts in isolation.
    raw = ("Row: 0 _id=1, bucket_id=10, date_added=1700000000, date_modified=1700000100, "
           "datetaken=1699999000000, width=4032, height=3024, orientation=0, duration=, "
           "mime_type=image/jpeg, is_trashed=0, is_favorite=0, is_pending=0, is_download=0, "
           "owner_package_name=com.android.camera2, relative_path=DCIM/Camera/, volume_name=external, "
           "_size=3145728, bucket_display_name=Camera, _data=/storage/emulated/0/DCIM/Camera/IMG_001.jpg, "
           "_display_name=IMG_001.jpg")
    rows = parse_content_query_output(raw, columns=MEDIA_QUERY_COLUMNS)
    records = build_companion_media_records(rows, "image")
    assert len(records) == 1
    assert records[0]["title"] == "IMG_001.jpg"
    assert records[0]["timestamp"] == 1699999000.0
    assert records[0]["extra"]["path"] == "/storage/emulated/0/DCIM/Camera/IMG_001.jpg"
