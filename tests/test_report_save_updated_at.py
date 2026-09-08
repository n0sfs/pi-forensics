"""routes/reporting.py's POST /api/report/save (save_report_json()) - the
route the Report Narrative tab's "Save Report Changes" button actually
calls.

Real bug, fixed 2026-09-09: this was the ONE case-mutating route in
routes/reporting.py that never refreshed updated_at - every sibling
route (add_case_note/edit_case_note/add_custody_entry/attach_file_to_
case/set_case_status in routes/case_management.py) already does. Fixed
to match those routes' exact "if 'updated_at' in data" guard.

Through a real Flask test client, matching tests/test_case_timeline_
route.py's own pattern (a minimal app registering just reporting_bp).
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


def _make_real_case(evidence_root, slug="2026-CASE-SAVE-TEST"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, f"{slug}_case.json")
    with open(report_path, 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_folder,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "notes": "original", "events": [],
        }, f)
    return report_path


def test_save_refreshes_updated_at(client, evidence_root):
    report_path = _make_real_case(evidence_root)
    with open(report_path) as f:
        report_data = json.load(f)
    report_data["notes"] = "edited"

    res = client.post("/api/report/save", json={"report_path": report_path, "report_data": report_data})
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["notes"] == "edited"
    # The actual regression this test guards - the real fix.
    assert on_disk["updated_at"] != "2026-01-01 00:00:00"


def test_save_never_raises_when_the_payload_has_no_updated_at_key(client, evidence_root):
    """A legacy report shape (or any payload the client happens to send with
    no such key at all) must never crash the save - matches the identical,
    already-established guard every sibling route in this file already
    uses for the same reason."""
    case_folder = os.path.join(evidence_root, "2026-CASE-NO-UPDATED-AT")
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, "flat_report.json")
    with open(report_path, 'w') as f:
        json.dump({"case_metadata": {"case_number": "x"}}, f)

    res = client.post("/api/report/save", json={"report_path": report_path, "report_data": {"case_metadata": {"case_number": "y"}}})
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk == {"case_metadata": {"case_number": "y"}}
