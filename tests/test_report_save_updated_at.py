"""routes/reporting.py's POST /api/report/save (save_report_json()) - the
route the Report Narrative tab's "Save Report Changes" button actually
calls.

Real bug, fixed 2026-09-09: this was the ONE case-mutating route in
routes/reporting.py that never refreshed updated_at - every sibling
route (add_case_note/edit_case_note/add_custody_entry/attach_file_to_
case/set_case_status in routes/case_management.py) already does. Fixed
to match those routes' exact "if 'updated_at' in data" guard.

A second, more serious bug fixed the same day: this route ALSO never
checked whether the case had changed on disk since the browser tab
last loaded it, so two analysts editing the same case could have one's
save silently clobber the other's - no warning, no conflict signal.
Every other write route in this file already re-reads fresh from disk
immediately before writing; this was the one that didn't. Fixed to
reject (409) rather than silently overwrite when the incoming payload's
own updated_at doesn't match what's currently on disk - the same "hard
error over silent data loss" pattern this app already uses for the
identical class of problem elsewhere (case-folder collisions, F2FS
double mounts).

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


def test_save_returns_the_fresh_updated_at_it_just_wrote(client, evidence_root):
    """The frontend's own success handler syncs this value back into its
    cached copy - without it, a second save from the same tab would
    incorrectly compare against the STALE pre-save value and false-
    positive reject itself as a conflict."""
    report_path = _make_real_case(evidence_root)
    with open(report_path) as f:
        report_data = json.load(f)

    res = client.post("/api/report/save", json={"report_path": report_path, "report_data": report_data})
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["updated_at"]
    assert body["updated_at"] != "2026-01-01 00:00:00"
    with open(report_path) as f:
        assert json.load(f)["updated_at"] == body["updated_at"]


def test_save_rejects_a_genuine_conflict_with_409(client, evidence_root):
    """The actual regression this whole fix exists for: analyst A loads the
    case, analyst B (or a different tab) saves a change first (bumping
    updated_at on disk), then A's own stale-cached save must be rejected,
    not silently allowed to overwrite B's change."""
    report_path = _make_real_case(evidence_root)
    with open(report_path) as f:
        stale_copy = json.load(f)  # what "analyst A" loaded

    # "Analyst B" saves first, from a fresh, correctly-matching copy.
    with open(report_path) as f:
        fresh_copy = json.load(f)
    fresh_copy["notes"] = "analyst B's change"
    res_b = client.post("/api/report/save", json={"report_path": report_path, "report_data": fresh_copy})
    assert res_b.status_code == 200
    assert res_b.get_json()["success"] is True

    # "Analyst A" now saves their own edit, still using their OLD stale
    # updated_at (never refreshed since they loaded it before B's save).
    stale_copy["notes"] = "analyst A's change"
    res_a = client.post("/api/report/save", json={"report_path": report_path, "report_data": stale_copy})
    assert res_a.status_code == 409
    body_a = res_a.get_json()
    assert body_a["success"] is False
    assert body_a["conflict"] is True
    assert "edited elsewhere" in body_a["error"]

    # The rejected save must never have touched the file - B's change
    # (the real, current state) survives untouched.
    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["notes"] == "analyst B's change"


def test_save_succeeds_on_the_second_attempt_once_updated_at_matches(client, evidence_root):
    """The exact frontend recovery flow: after a rejected save, the examiner
    reloads (a fresh /api/report/load-equivalent read) and reapplies their
    edit - that retried save, now carrying the CURRENT updated_at, must
    succeed."""
    report_path = _make_real_case(evidence_root)

    with open(report_path) as f:
        fresh_copy = json.load(f)
    fresh_copy["notes"] = "someone else's change"
    client.post("/api/report/save", json={"report_path": report_path, "report_data": fresh_copy})

    # Re-fetch (simulates the frontend's own reload-and-reapply step).
    with open(report_path) as f:
        reloaded = json.load(f)
    assert reloaded["notes"] == "someone else's change"
    reloaded["notes"] = "reapplied edit"

    res = client.post("/api/report/save", json={"report_path": report_path, "report_data": reloaded})
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    with open(report_path) as f:
        assert json.load(f)["notes"] == "reapplied edit"


def test_save_skips_the_conflict_check_when_the_on_disk_file_predates_updated_at(client, evidence_root):
    """A report saved by a station running before this field existed at all
    (or one hand-edited to remove it) must never become permanently
    unsaveable just because the on-disk side of the comparison is
    missing - matches the existing payload-side "no such key" tolerance."""
    case_folder = os.path.join(evidence_root, "2026-CASE-NO-DISK-UPDATED-AT")
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, "flat_report.json")
    with open(report_path, 'w') as f:
        json.dump({"notes": "original", "events": []}, f)  # no updated_at at all

    res = client.post("/api/report/save", json={
        "report_path": report_path,
        "report_data": {"notes": "edited", "events": [], "updated_at": "2026-01-01 00:00:00"},
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["notes"] == "edited"
