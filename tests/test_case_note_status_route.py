"""routes/reporting.py's /api/cases/notes/set_status - the follow-up/task
flag on Case Notes (2026-09-09, item 6 of the 9-item investigation-workflow
audit round): a note gains an optional status (open/resolved) and an
optional assigned_to name, both settable independently of the append-only
edit_history mechanism add_case_note()/edit_case_note() already own.

Through a real Flask test client, mirroring tests/test_report_save_updated_
at.py's own established pattern (a minimal app registering just
reporting_bp, a real on-disk case file with a real note already seeded into
its case_notes array). Skipped (not failed) on a non-POSIX dev machine:
routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os
import uuid

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
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


def _make_case_with_note(evidence_root, slug="2026-CASE-NOTE-STATUS-TEST", note_overrides=None):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, f"{slug}_case.json")
    note_id = uuid.uuid4().hex
    note = {
        "note_id": note_id, "timestamp": "2026-09-09 10:00:00", "author": "examiner_a",
        "category": "General", "text": "Original note text", "attachments": [],
        "linked_files": [], "content_hash": "abc123", "edited_at": None, "edit_history": [],
        "status": "open", "assigned_to": None,
    }
    if note_overrides:
        note.update(note_overrides)
    with open(report_path, 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_folder,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "events": [], "case_notes": [note],
        }, f)
    return report_path, note_id


def test_set_status_marks_a_note_resolved(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "status": "resolved",
    })
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    assert data["note"]["status"] == "resolved"

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["case_notes"][0]["status"] == "resolved"
    assert on_disk["updated_at"] != "2026-01-01 00:00:00"  # refreshed, not left stale


def test_set_status_reopens_a_resolved_note(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root, note_overrides={"status": "resolved"})
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "status": "open",
    })
    assert res.get_json()["note"]["status"] == "open"


def test_set_status_assigns_a_note_without_touching_status(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "assigned_to": "Jordan Rivera",
    })
    data = res.get_json()
    assert data["note"]["assigned_to"] == "Jordan Rivera"
    assert data["note"]["status"] == "open"  # untouched - this call never included a status key


def test_set_status_can_clear_assigned_to_with_an_empty_string(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root, note_overrides={"assigned_to": "Jordan Rivera"})
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "assigned_to": "",
    })
    assert res.get_json()["note"]["assigned_to"] is None


def test_set_status_and_assigned_to_can_be_set_together_in_one_call(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "status": "resolved", "assigned_to": "Sam Lee",
    })
    data = res.get_json()["note"]
    assert data["status"] == "resolved"
    assert data["assigned_to"] == "Sam Lee"


def test_set_status_never_touches_edit_history(client, evidence_root):
    """The one real design guarantee this whole route exists to provide -
    a status/assignment change is not a correction to the note's own
    recorded evidentiary text, so it must never append to edit_history the
    way edit_case_note() deliberately does for an actual text edit."""
    report_path, note_id = _make_case_with_note(evidence_root)
    client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "status": "resolved", "assigned_to": "Sam Lee",
    })
    with open(report_path) as f:
        on_disk = json.load(f)
    note = on_disk["case_notes"][0]
    assert note["edit_history"] == []
    assert note["edited_at"] is None
    assert note["text"] == "Original note text"  # completely unchanged


def test_set_status_rejects_an_invalid_status_value(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id, "status": "archived",
    })
    assert res.status_code == 400
    assert res.get_json()["success"] is False

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["case_notes"][0]["status"] == "open"  # never touched


def test_set_status_rejects_a_request_with_neither_field(client, evidence_root):
    report_path, note_id = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": note_id,
    })
    assert res.status_code == 400


def test_set_status_rejects_an_unknown_note_id(client, evidence_root):
    report_path, _ = _make_case_with_note(evidence_root)
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": report_path, "note_id": "does-not-exist", "status": "resolved",
    })
    assert res.status_code == 404


def test_set_status_rejects_a_missing_report_file(client, evidence_root):
    res = client.post("/api/cases/notes/set_status", json={
        "report_path": os.path.join(evidence_root, "does-not-exist_case.json"),
        "note_id": "anything", "status": "resolved",
    })
    assert res.status_code == 404


def test_add_case_note_defaults_a_new_note_to_open_with_no_assignment(client, evidence_root):
    """add_case_note() itself (not this route) - confirms a freshly-created
    note always starts status='open'/assigned_to=None when the form field
    is left blank, and that a non-blank assigned_to value is captured at
    creation time too."""
    case_folder = os.path.join(evidence_root, "2026-CASE-NEWNOTE-TEST")
    os.makedirs(case_folder)
    report_path = os.path.join(case_folder, "2026-CASE-NEWNOTE-TEST_case.json")
    with open(report_path, 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": "2026-CASE-NEWNOTE-TEST", "case_folder": case_folder,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "events": [], "case_notes": [],
        }, f)

    res = client.post("/api/cases/notes/add", data={
        "report_path": report_path, "text": "First real note", "category": "General",
    })
    data = res.get_json()
    assert data["success"] is True
    assert data["note"]["status"] == "open"
    assert data["note"]["assigned_to"] is None

    res2 = client.post("/api/cases/notes/add", data={
        "report_path": report_path, "text": "Second note, assigned at creation",
        "category": "General", "assigned_to": "Taylor Kim",
    })
    assert res2.get_json()["note"]["assigned_to"] == "Taylor Kim"
