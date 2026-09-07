"""routes/reporting.py's GET /api/cases/timeline - specifically the
parsed_artifacts-merge half (the MACB half is already covered by
tests/test_folder_timeline.py's own _collect_case_timeline() tests).

Real regression test for a real bug found live, 2026-09-01, while
verifying Windows Sticky Notes: the route hardcoded "deleted": False for
every parsed_artifacts row regardless of that row's own extra_json -
harmless for every artifact type that had shipped so far (none of them
carry a real per-row deleted concept), but a genuine, live inaccuracy
once Sticky Notes' real soft-delete tombstone flag existed to be ignored.
Fixed to read extra_json's own 'deleted' key when present.

Through a real Flask test client, matching tests/test_auto_analyze_
detect.py's own pattern (a minimal app registering just reporting_bp).
Skipped (not failed) on a non-POSIX dev machine: core.jobs needs
POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from core.case_index_db import _record_parsed_artifacts
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(reporting_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _make_real_case(evidence_root, slug="2026-TEST-TIMELINE"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    with open(os.path.join(case_folder, f"{slug}_case.json"), 'w') as f:
        json.dump({"schema_version": 1, "case_number": slug, "events": [],
                   "attachments": {"files": [], "reference_urls": []}}, f)
    return case_folder


def test_parsed_artifact_with_real_deleted_flag_is_reflected_in_the_timeline(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "plum.sqlite")}, [
        {"artifact_type": "sticky_note", "title": "delete this before the audit", "url": "",
         "value": "delete this before the audit", "timestamp": 1786784400.0,
         "extra": {"note_id": "note-1", "deleted": True}},
        {"artifact_type": "sticky_note", "title": "keep this one", "url": "",
         "value": "keep this one", "timestamp": 1786784500.0,
         "extra": {"note_id": "note-2", "deleted": False}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    by_detail = {r["detail"]: r for r in data["events"] if r["source"] == "parsed_artifact"}
    assert len(by_detail) == 2
    assert by_detail["delete this before the audit"]["deleted"] is True
    assert by_detail["keep this one"]["deleted"] is False


def test_parsed_artifact_type_with_no_deleted_concept_defaults_to_false(client, evidence_root):
    # A registry artifact (no 'deleted' key in its own extra dict at all)
    # must still correctly default to False, not raise or omit the row.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "NTUSER.DAT")}, [
        {"artifact_type": "registry_recent_docs", "title": "report.docx", "url": "",
         "value": "report.docx", "timestamp": 1786784400.0, "extra": {}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    parsed_rows = [r for r in data["events"] if r["source"] == "parsed_artifact"]
    assert len(parsed_rows) == 1
    assert parsed_rows[0]["deleted"] is False


def test_communications_web_and_social_media_categories_assigned_correctly(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "leapp_sms_message", "title": "text 1", "url": "", "value": "hi",
         "timestamp": 1786784100.0, "extra": {}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "History")}, [
        {"artifact_type": "chrome_history", "title": "example.com", "url": "https://example.com", "value": "",
         "timestamp": 1786784200.0, "extra": {}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "msgstore.db")}, [
        {"artifact_type": "leapp_whatsapp_message", "title": "hey", "url": "", "value": "hey",
         "timestamp": 1786784300.0, "extra": {}},
    ])
    # Deliberately-uncategorized type - must fall back to the safe generic
    # bucket, never be dropped from the timeline or crash the route.
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "SYSTEM")}, [
        {"artifact_type": "registry_amcache", "title": "notepad.exe", "url": "", "value": "notepad.exe",
         "timestamp": 1786784400.0, "extra": {}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    assert data["success"] is True
    assert data["categories"] == ["Communications", "Web Activity", "Social Media", "Device & System", "Filesystem"]
    by_activity = {r["activity"]: r["category"] for r in data["events"] if r["source"] == "parsed_artifact"}
    assert by_activity["leapp_sms_message"] == "Communications"
    assert by_activity["chrome_history"] == "Web Activity"
    assert by_activity["leapp_whatsapp_message"] == "Social Media"
    assert by_activity["registry_amcache"] == "Device & System"


def test_apple_export_types_get_the_same_category_as_their_native_counterpart(client, evidence_root):
    # Real bug found live (2026-09-01) verifying this feature against real
    # accumulated case data on the deployed station: apple_safari_bookmark/
    # apple_contact were missing from the category dict entirely and fell
    # back to the generic "Device & System" bucket, even though their
    # native-parser counterparts (safari_bookmarks, mobile_contact) are
    # correctly categorized Web Activity/Communications.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Bookmarks.plist")}, [
        {"artifact_type": "apple_safari_bookmark", "title": "example.com", "url": "https://example.com", "value": "",
         "timestamp": 1786784100.0, "extra": {}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Contacts.vcf")}, [
        {"artifact_type": "apple_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": 1786784200.0, "extra": {}},
    ])
    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    by_activity = {r["activity"]: r["category"] for r in res.get_json()["events"] if r["source"] == "parsed_artifact"}
    assert by_activity["apple_safari_bookmark"] == "Web Activity"
    assert by_activity["apple_contact"] == "Communications"


def test_android_mms_and_ab_backup_sms_mms_get_communications_category(client, evidence_root):
    # Real bug found live (2026-09-05, a code-grounded mobile-forensics
    # review): android_mms_message (native rooted parser) and both .ab
    # (Android Backup File) - sourced SMS/MMS types were missing from the
    # category dict entirely, even though their siblings android_sms_
    # message/android_call_log were already correctly mapped - a real MMS
    # message fell into the generic "Device & System" bucket instead of
    # Communications, alongside its own SMS/call-log messages.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_mms_message", "title": "Inbox - 5551234567", "url": "", "value": "hi",
         "timestamp": 1786784100.0, "extra": {}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "backup.ab")}, [
        {"artifact_type": "android_ab_sms_message", "title": "text", "url": None, "value": "hi",
         "timestamp": 1786784200.0, "extra": {}},
        {"artifact_type": "android_ab_mms_message", "title": "mms", "url": None, "value": "hi",
         "timestamp": 1786784300.0, "extra": {}},
    ])
    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    by_activity = {r["activity"]: r["category"] for r in res.get_json()["events"] if r["source"] == "parsed_artifact"}
    assert by_activity["android_mms_message"] == "Communications"
    assert by_activity["android_ab_sms_message"] == "Communications"
    assert by_activity["android_ab_mms_message"] == "Communications"


def test_missing_case_folder_returns_a_clean_error(client, evidence_root):
    res = client.get(f"/api/cases/timeline?case_folder={os.path.join(evidence_root, 'not_a_real_case')}")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


# --- 2026-09-07: entity-linking enrichment - every timeline row now carries
# "counterparts" (correlate_contacts()'s own resolved contact key(s), never
# a raw unmatched phone/email), and the response carries a trimmed
# "contacts" directory the frontend uses for a "Filter by contact"
# dropdown/the Relationship Graph's click-to-filter. ---

def test_a_resolved_phone_comm_row_carries_the_correlated_contact_key(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": None, "extra": {"phones": ["+15551234567"]}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hello",
         "timestamp": 1786784100.0, "extra": {"address": "(555) 123-4567"}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    sms_row = next(r for r in data["events"] if r["activity"] == "android_sms_message")
    assert sms_row["counterparts"] == ["5551234567"]
    assert len(data["contacts"]) == 1
    assert data["contacts"][0]["key"] == "5551234567"
    assert data["contacts"][0]["display_names"] == ["Jane Doe"]


def test_an_unresolved_comm_row_carries_no_counterparts_and_does_not_crash(client, evidence_root):
    # No contact source seeded at all - a real, unmatched number must
    # never be silently exposed as a "resolved" counterpart.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hello",
         "timestamp": 1786784100.0, "extra": {"address": "+15559999999"}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    sms_row = next(r for r in data["events"] if r["activity"] == "android_sms_message")
    assert sms_row["counterparts"] == []
    assert data["contacts"] == []


def test_a_resolved_email_comm_row_carries_the_correlated_contact_key(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Email Only Contact", "url": "", "value": "Email Only Contact",
         "timestamp": None, "extra": {"emails": ["jane@example.com"]}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "emails.mbox")}, [
        {"artifact_type": "email_message", "title": "jane@example.com", "url": "", "value": "jane@example.com",
         "timestamp": 1786784100.0, "extra": {}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    email_row = next(r for r in data["events"] if r["activity"] == "email_message")
    assert email_row["counterparts"] == ["jane@example.com"]
    assert data["contacts"][0]["key"] == "jane@example.com"


def test_a_row_naming_a_phone_and_a_row_naming_its_linked_email_resolve_to_the_same_key(client, evidence_root):
    # The real entity-linking guarantee, proven at the Timeline layer, not
    # just correlate_contacts() in isolation - the SAME android_contact row
    # named both a phone and an email, so an SMS (phone-based) and a
    # calendar invite (email-based) for that one real person must resolve
    # to the exact same counterpart key, letting a click on that person's
    # single Relationship Graph node filter both kinds of activity at once.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": None, "extra": {"phones": ["+15551234567"], "emails": ["jane@example.com"]}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hello",
         "timestamp": 1786784100.0, "extra": {"address": "+15551234567"}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "calendar.json")}, [
        {"artifact_type": "android_companion_calendar_event", "title": "Meeting", "url": "", "value": "Meeting",
         "timestamp": 1786784200.0, "extra": {"attendees": [{"email": "jane@example.com"}]}},
    ])

    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    sms_row = next(r for r in data["events"] if r["activity"] == "android_sms_message")
    calendar_row = next(r for r in data["events"] if r["activity"] == "android_companion_calendar_event")
    assert sms_row["counterparts"] == ["5551234567"]
    assert calendar_row["counterparts"] == ["5551234567"]  # the merged contact's canonical key, not "jane@example.com"
    assert len(data["contacts"]) == 1  # one merged person, not two


# --- content_preview (2026-09-07) ---

def test_sms_row_carries_its_own_message_text_as_content_preview(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "call me when you land",
         "timestamp": 1786784100.0, "extra": {"address": "+15551234567"}},
    ])
    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    sms_row = next(r for r in data["events"] if r["activity"] == "android_sms_message")
    assert sms_row["content_preview"] == "call me when you land"


def test_email_row_carries_body_preview_not_the_sender_address(client, evidence_root):
    # email_message's own "value" column is the SENDER address, not the
    # message body - the one real exception _comm_content_preview() has
    # to special-case, confirmed against core/email_utils.py's own real
    # record-construction code before this was built.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "emails.mbox")}, [
        {"artifact_type": "email_message", "title": "Re: budget", "url": "", "value": "jane@example.com",
         "timestamp": 1786784100.0, "extra": {"body_preview": "attached is the revised Q3 numbers"}},
    ])
    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    email_row = next(r for r in data["events"] if r["activity"] == "email_message")
    assert email_row["content_preview"] == "attached is the revised Q3 numbers"


def test_call_log_row_and_macb_row_carry_no_content_preview(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "calllog.db")}, [
        {"artifact_type": "android_call_log", "title": "call", "url": "", "value": "5551234567",
         "timestamp": 1786784100.0, "extra": {}},
    ])
    res = client.get(f"/api/cases/timeline?case_folder={case_folder}")
    data = res.get_json()
    call_row = next(r for r in data["events"] if r["activity"] == "android_call_log")
    assert call_row["content_preview"] is None
    macb_rows = [r for r in data["events"] if r["source"] == "macb"]
    assert all(r["content_preview"] is None for r in macb_rows)


# --- /api/cases/geo_activity (2026-09-07) ---

def test_geo_activity_missing_case_folder_returns_a_clean_error(client, evidence_root):
    res = client.get("/api/cases/geo_activity?case_folder=/nonexistent")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_geo_activity_returns_real_takeout_location_history_points(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Takeout", "Records.json")}, [
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "San Francisco",
         "timestamp": 1786784100.0, "extra": {"lat": 37.7749, "lon": -122.4194, "source_format": "records_json"}},
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Oakland",
         "timestamp": 1786784200.0, "extra": {"lat": 37.8044, "lon": -122.2712, "source_format": "records_json"}},
    ])
    res = client.get(f"/api/cases/geo_activity?case_folder={case_folder}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["points"]) == 2
    names = {p["name"] for p in data["points"]}
    assert names == {"San Francisco", "Oakland"}
    assert all(p["source"] == "Google Takeout Location History" for p in data["points"])
    assert data["truncated"] is False


def test_geo_activity_skips_a_row_with_no_real_lat_lon(client, evidence_root):
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Takeout", "Records.json")}, [
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Bad Row",
         "timestamp": 1786784100.0, "extra": {"lat": None, "lon": None}},
    ])
    res = client.get(f"/api/cases/geo_activity?case_folder={case_folder}")
    data = res.get_json()
    assert data["points"] == []
    assert data["frequent_locations"] == []


def test_geo_activity_clusters_nearby_points_into_a_frequent_location(client, evidence_root):
    # Three real, distinct timestamps at effectively the same real-world
    # spot (well within the ~111m grid cell) must collapse into ONE
    # frequent_locations entry, ranked by visit_count, with a correctly
    # computed first_seen/last_seen span - not three separate points each
    # counted once.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Takeout", "Records.json")}, [
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Home",
         "timestamp": 1786784100.0, "extra": {"lat": 37.77490, "lon": -122.41940}},
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Home",
         "timestamp": 1786784200.0, "extra": {"lat": 37.77491, "lon": -122.41941}},
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Home",
         "timestamp": 1786784300.0, "extra": {"lat": 37.77492, "lon": -122.41942}},
    ])
    res = client.get(f"/api/cases/geo_activity?case_folder={case_folder}")
    data = res.get_json()
    assert len(data["points"]) == 3
    assert len(data["frequent_locations"]) == 1
    cluster = data["frequent_locations"][0]
    assert cluster["visit_count"] == 3
    assert cluster["first_seen"] == 1786784100.0
    assert cluster["last_seen"] == 1786784300.0


def test_geo_activity_excludes_single_visit_points_from_frequent_locations(client, evidence_root):
    # A place seen exactly once is real, meaningful data - it must still
    # appear in "points" - but it isn't a "frequent" location by any
    # reasonable definition, and cluttering frequent_locations with every
    # single-visit point would defeat the whole point of the list. Found
    # live, 2026-09-07, while verifying the real seeded API response: the
    # first cut included every 1-visit cluster too, directly contradicting
    # the frontend's own "visited more than once" label.
    case_folder = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Takeout", "Records.json")}, [
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Home",
         "timestamp": 1786784100.0, "extra": {"lat": 37.77490, "lon": -122.41940}},
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Home",
         "timestamp": 1786784200.0, "extra": {"lat": 37.77491, "lon": -122.41941}},
        {"artifact_type": "takeout_location_history", "title": "Location", "url": "", "value": "Somewhere Once",
         "timestamp": 1786784300.0, "extra": {"lat": 40.7128, "lon": -74.0060}},
    ])
    res = client.get(f"/api/cases/geo_activity?case_folder={case_folder}")
    data = res.get_json()
    assert len(data["points"]) == 3  # the single-visit point is still a real point
    assert len(data["frequent_locations"]) == 1  # but not a "frequent location"
    assert data["frequent_locations"][0]["visit_count"] == 2


def test_geo_activity_includes_kml_derived_points_alongside_takeout(client, evidence_root):
    # A KML placemark has no reliable structured timestamp - confirmed
    # via _parse_kml_placemarks()'s own real shape - so it must always
    # come through with timestamp=None, never a guessed one.
    case_folder = _make_real_case(evidence_root)
    kml_path = os.path.join(case_folder, "photo_locations.kml")
    with open(kml_path, "w", encoding="utf-8") as f:
        f.write(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            '<Placemark><name>IMG_0001.jpg</name>'
            '<Point><coordinates>-122.4194,37.7749,0</coordinates></Point>'
            '</Placemark>'
            '</Document></kml>'
        )
    res = client.get(f"/api/cases/geo_activity?case_folder={case_folder}")
    data = res.get_json()
    assert len(data["points"]) == 1
    kml_point = data["points"][0]
    assert kml_point["name"] == "IMG_0001.jpg"
    assert kml_point["timestamp"] is None
    assert kml_point["source"] == "photo_locations.kml"
    assert abs(kml_point["lat"] - 37.7749) < 0.0001
    assert abs(kml_point["lon"] - (-122.4194)) < 0.0001
