"""Unified Case Search (2026-09-09) - item 2 of the 6-item investigation-
workflow backlog: case_index_unified_search()'s three server-side search
branches (parsed_artifacts, tagged_items, and correlate_contacts()) that
Reporting's own client-side Search tab (runCaseSearch() in main.js) can't
cover on its own, since none of the three live in the report JSON already
loaded into the browser. The client-side half (Report Narrative/Files &
Artifacts/Jobs/Case Notes/Case Activity Log) has no backend route to test
at all - it's pure JS working against data a different route already
returns, so it's out of scope for this file.

Through a real Flask test client, mirroring tests/test_tag_severity_
routes.py's own established pattern (a minimal app registering just
case_index_bp). Skipped (not failed) on a non-POSIX dev machine:
routes.case_index needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.case_index needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.case_index_db as case_index_db
from routes.case_index import case_index_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(case_index_bp)
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


@pytest.fixture
def case_folder(evidence_root):
    """A real, minimal consolidated case folder - matches tests/
    test_case_index_db.py's own identical fixture (kept as a local copy
    here rather than a cross-file import, matching that file's own
    established convention of each test module owning its fixtures)."""
    import pathlib
    folder = pathlib.Path(evidence_root) / "2026-CASE-UNIFIED-SEARCH-TEST"
    folder.mkdir()
    (folder / "2026-CASE-UNIFIED-SEARCH-TEST_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-UNIFIED-SEARCH-TEST", "events": [],
    }))
    return str(folder)


def _identity(path):
    return {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None, "path": path}


def test_empty_query_returns_empty_result_shape_without_touching_the_db(client, case_folder):
    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "   "})
    data = res.get_json()
    assert data == {"success": True, "parsed_artifacts": [], "tags": [], "contacts": []}


def test_finds_a_real_parsed_artifact_by_url_substring(client, case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "History")),
        [{"artifact_type": "chrome_history", "title": "Malware Download Page",
          "url": "https://evil.example.com/payload.exe", "value": "1 visit", "timestamp": 1700000000.0, "extra": {}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "payload.exe"})
    data = res.get_json()
    assert data["success"] is True
    assert len(data["parsed_artifacts"]) == 1
    match = data["parsed_artifacts"][0]
    assert match["artifact_type"] == "chrome_history"
    assert match["label"] == "Chrome/Chromium History"  # from PARSED_ARTIFACT_TYPE_LABELS, not the raw key
    assert match["title"] == "Malware Download Page"
    assert data["tags"] == []
    assert data["contacts"] == []


def test_finds_a_real_parsed_artifact_by_title_substring_case_insensitive(client, case_folder):
    """SQLite's LIKE is case-insensitive for ASCII by default - confirmed
    directly here rather than assumed."""
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "History")),
        [{"artifact_type": "chrome_history", "title": "Confidential Merger Plans",
          "url": "https://intranet.example.com/docs", "value": "", "timestamp": None, "extra": {}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "MERGER"})
    assert len(res.get_json()["parsed_artifacts"]) == 1


def test_a_query_matching_nothing_returns_all_three_empty(client, case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "History")),
        [{"artifact_type": "chrome_history", "title": "Example", "url": "https://example.com",
          "value": "", "timestamp": None, "extra": {}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "nonexistent-xyz"})
    data = res.get_json()
    assert data == {"success": True, "parsed_artifacts": [], "tags": [], "contacts": []}


def test_finds_a_real_tagged_item_by_comment_substring(client, case_folder):
    target_file = os.path.join(case_folder, "evidence.jpg")
    with open(target_file, "w") as f:
        f.write("fake jpeg bytes")
    client.post('/api/case_index/tag_item', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "evidence.jpg",
        "new_tag_name": "Contraband", "new_tag_color": "danger", "new_tag_notable": True,
        "new_tag_severity": "critical", "comment": "flagged during initial triage",
    })

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "triage"})
    data = res.get_json()
    assert len(data["tags"]) == 1
    match = data["tags"][0]
    assert match["name"] == "evidence.jpg"
    assert match["tag_name"] == "Contraband"
    assert match["comment"] == "flagged during initial triage"
    assert data["parsed_artifacts"] == []


def test_finds_a_real_tagged_item_by_tag_name_substring(client, case_folder):
    """A search matching the TAG's own name (not the file's own name or
    comment) still surfaces the tagged item - a genuinely separate JOIN
    condition from the file-name/comment match above."""
    target_file = os.path.join(case_folder, "note.txt")
    with open(target_file, "w") as f:
        f.write("x")
    client.post('/api/case_index/tag_item', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "note.txt",
        "new_tag_name": "Suspicious Financial Activity",
    })

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "Financial"})
    assert len(res.get_json()["tags"]) == 1


def test_finds_a_real_contact_by_name_substring(client, case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "contacts2.db")),
        [{"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
          "timestamp": None, "extra": {"phones": ["+15551234567"]}}])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "mmssms.db")),
        [{"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hello",
          "timestamp": 1700000000.0, "extra": {"address": "+15551234567"}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "Jane"})
    data = res.get_json()
    assert len(data["contacts"]) == 1
    match = data["contacts"][0]
    assert "Jane Doe" in match["display_names"]
    assert match["normalized_number"] == "5551234567"  # normalize_phone_number() strips the leading US country-code digit too
    # The android_contact row itself is ALSO a real parsed_artifacts row
    # (its own title is "Jane Doe") - genuine, intentional overlap, not a
    # bug: the same underlying data is legitimately surfaced both as a raw
    # indexed record and as a resolved Contact.
    assert len(data["parsed_artifacts"]) == 1
    assert data["parsed_artifacts"][0]["artifact_type"] == "android_contact"
    assert data["tags"] == []


def test_finds_a_real_contact_by_phone_number_substring(client, case_folder):
    """The query can match the NUMBER itself, not just a display name -
    genuinely useful for an unresolved/partially-known contact."""
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "contacts2.db")),
        [{"artifact_type": "android_contact", "title": "Bob Smith", "url": "", "value": "Bob Smith",
          "timestamp": None, "extra": {"phones": ["+15559998888"]}}])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "mmssms.db")),
        [{"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hi",
          "timestamp": 1700000000.0, "extra": {"address": "+15559998888"}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "9998888"})
    assert len(res.get_json()["contacts"]) == 1


def test_a_single_query_can_match_across_all_three_sources_at_once(client, case_folder):
    """The real, end-to-end proof this is a genuinely unified search, not
    three independent endpoints happening to share a route - one query
    ('project') matches a parsed artifact by title, a tagged item by its
    own tag name, and a contact by display name, all in one request."""
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "History")),
        [{"artifact_type": "chrome_history", "title": "Project Phoenix Notes",
          "url": "https://example.com", "value": "", "timestamp": None, "extra": {}}])

    target_file = os.path.join(case_folder, "budget.xlsx")
    with open(target_file, "w") as f:
        f.write("x")
    client.post('/api/case_index/tag_item', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "budget.xlsx",
        "new_tag_name": "Project Phoenix Budget",
    })

    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "contacts2.db")),
        [{"artifact_type": "android_contact", "title": "Project Phoenix Lead", "url": "",
          "value": "Project Phoenix Lead", "timestamp": None, "extra": {"phones": ["+15550001111"]}}])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(os.path.join(case_folder, "mmssms.db")),
        [{"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hi",
          "timestamp": 1700000000.0, "extra": {"address": "+15550001111"}}])

    res = client.post('/api/case_index/unified_search', json={"case_folder": case_folder, "query": "phoenix"})
    data = res.get_json()
    # 2, not 1: the chrome_history row AND the android_contact row (whose
    # own title also contains "Phoenix") are both genuine parsed_artifacts
    # hits - the same intentional overlap already confirmed in
    # test_finds_a_real_contact_by_name_substring above, not a bug here
    # either.
    assert len(data["parsed_artifacts"]) == 2
    assert {m["artifact_type"] for m in data["parsed_artifacts"]} == {"chrome_history", "android_contact"}
    assert len(data["tags"]) == 1
    assert len(data["contacts"]) == 1


def test_no_case_folder_never_raises_even_with_a_real_query(client):
    """case_index_open_readonly() correctly returns None for a missing/
    invalid case_folder (matching every other route in this file's own
    established graceful-empty behavior) - never a 500."""
    res = client.post('/api/case_index/unified_search', json={"case_folder": None, "query": "anything"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["parsed_artifacts"] == []
