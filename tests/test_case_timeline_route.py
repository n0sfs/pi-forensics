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


def test_missing_case_folder_returns_a_clean_error(client, evidence_root):
    res = client.get(f"/api/cases/timeline?case_folder={os.path.join(evidence_root, 'not_a_real_case')}")
    assert res.status_code == 400
    assert res.get_json()["success"] is False
