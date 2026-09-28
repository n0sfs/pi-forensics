"""Closed/Archived cases are read-only in Reporting (2026-09-27).

Narrative saves, case notes and exhibit attach/caption are refused with 409 on
a finished case; the Custody Log stays writable, because returning or
transferring evidence after closure is legitimate. Skipped (not failed) on a
non-POSIX dev machine: routes.reporting needs core.jobs (pwd/fcntl).
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(reporting_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _make_case(evidence_root, status, slug="2026-CLOSED-RO-TEST"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, f"{slug}_case.json")
    exhibit = os.path.join(case_folder, "photo.jpg")
    with open(exhibit, "wb") as f:
        f.write(b"x")
    with open(report_path, "w") as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_folder, "case_status": status,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "events": [], "case_notes": [{"note_id": "n1", "text": "t", "content_hash": "h", "edit_history": []}],
            "attachments": {"files": [exhibit]},
        }, f)
    return case_folder, report_path, exhibit


@pytest.mark.parametrize("status", ["Closed", "Archived"])
def test_edits_to_a_finished_case_are_refused(client, evidence_root, status):
    case_folder, report_path, exhibit = _make_case(evidence_root, status)
    with open(report_path) as f:
        before = f.read()

    calls = [
        client.post("/api/report/save", json={"report_path": report_path,
                                               "report_data": {"executive_summary": "changed"}}),
        client.post("/api/cases/notes/add", data={"report_path": report_path, "text": "late note"}),
        client.post("/api/cases/notes/edit", json={"report_path": report_path, "note_id": "n1", "text": "edited"}),
        client.post("/api/cases/notes/set_status", json={"report_path": report_path, "note_id": "n1",
                                                        "status": "resolved"}),
        client.post("/api/cases/attach_file", json={"case_folder": case_folder, "file_path": exhibit}),
        client.post("/api/cases/set_file_caption", json={"case_folder": case_folder, "file_path": exhibit,
                                                         "caption": "c"}),
    ]
    for res in calls:
        assert res.status_code == 409, res.get_json()
        assert res.get_json()["closed_case"] == status
    with open(report_path) as f:
        assert f.read() == before


def test_custody_log_stays_writable_on_a_closed_case(client, evidence_root):
    _, report_path, _ = _make_case(evidence_root, "Closed")
    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "Evidence Locker", "to_custodian": "Owner (returned)",
    })
    assert res.status_code == 200, res.get_json()


def test_an_open_case_is_still_editable(client, evidence_root):
    _, report_path, _ = _make_case(evidence_root, "Open")
    res = client.post("/api/cases/notes/add", data={"report_path": report_path, "text": "a note"})
    assert res.status_code == 200, res.get_json()
