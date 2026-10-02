"""Closed/Archived cases are read-only (2026-09-27, widened 2026-10-02).

Narrative saves, case notes, exhibit attach/caption and the examiner's tags and
contact merges are refused with 409 on a finished case; the Custody Log stays
writable, because returning or transferring evidence after closure is
legitimate - but logging one no longer rewrites the case's examiner list.
Re-opening (set_status) is never refused. A save is also refused when its edit
base came from another case - the case-switch bug that merged one case's
narrative into another. Skipped (not failed) on a non-POSIX dev machine:
routes.reporting needs core.jobs (pwd/fcntl).
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from routes.case_index import case_index_bp
from routes.case_management import case_management_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(reporting_bp)
    app.register_blueprint(case_index_bp)
    app.register_blueprint(case_management_bp)
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
        # The remedy named must exist for every finished status (2026-10-02).
        assert "Re-open" in res.get_json()["error"]
    with open(report_path) as f:
        assert f.read() == before


@pytest.mark.parametrize("status", ["Closed", "Archived"])
def test_tags_and_contact_merges_on_a_finished_case_are_refused(client, evidence_root, status):
    """Exhibit tags and contact merges print in the exported report, so a
    finished case refuses them too - before the case index is even opened."""
    case_folder, _, exhibit = _make_case(evidence_root, status)
    calls = [
        client.post("/api/case_index/tag_item", json={"case_folder": case_folder, "source_type": "real_fs",
                                                      "path": exhibit, "new_tag_name": "Late"}),
        client.post("/api/case_index/untag_item", json={"case_folder": case_folder, "source_type": "real_fs",
                                                        "path": exhibit, "tag_id": 1}),
        client.post("/api/case_index/tags/create", json={"case_folder": case_folder, "name": "Late"}),
        client.post("/api/case_index/tags/update", json={"case_folder": case_folder, "tag_id": 1, "name": "X"}),
        client.post("/api/case_index/tags/delete", json={"case_folder": case_folder, "tag_id": 1}),
        client.post("/api/case_index/contacts/merge", json={"case_folder": case_folder, "primary_key": "a",
                                                            "merged_key": "b", "justification": "same person"}),
        client.post("/api/case_index/contacts/unmerge", json={"case_folder": case_folder, "merged_key": "b"}),
    ]
    for res in calls:
        assert res.status_code == 409, res.get_json()
        assert res.get_json()["closed_case"] == status


def test_custody_log_stays_writable_on_a_closed_case(client, evidence_root):
    _, report_path, _ = _make_case(evidence_root, "Closed")
    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "Evidence Locker", "to_custodian": "Owner (returned)",
    })
    assert res.status_code == 200, res.get_json()
    with open(report_path) as f:
        record = json.load(f)
    assert len(record["custody_log"]) == 1
    # Logging the return must not add its author to the finished case's
    # examiners - that list prints in the exported report (2026-10-02).
    assert not record.get("examiners")


def test_a_closed_case_can_be_reopened_and_then_edited(client, evidence_root):
    case_folder, report_path, _ = _make_case(evidence_root, "Closed")
    res = client.post("/api/cases/set_status", json={"case_folder": case_folder, "status": "Open"})
    assert res.status_code == 200, res.get_json()
    res = client.post("/api/cases/notes/add", data={"report_path": report_path, "text": "after re-opening"})
    assert res.status_code == 200, res.get_json()


def test_a_save_whose_edit_base_came_from_another_case_is_refused(client, evidence_root):
    """The case-switch bug (2026-10-02 review): case A's unsaved edits and
    edit base survived a switch to case B, and the next save three-way-merged
    A's narrative into B with no conflict reported."""
    _, a_path, _ = _make_case(evidence_root, "Open", slug="2026-CASE-A")
    _, b_path, _ = _make_case(evidence_root, "Open", slug="2026-CASE-B")
    with open(b_path) as f:
        before = f.read()
    res = client.post("/api/report/save", json={
        "report_path": b_path,
        "report_data": {**json.loads(before), "executive_summary": "case A's text"},
        "base_fields": {"executive_summary": None},
        "base_report_path": a_path,
    })
    assert res.status_code == 409
    assert res.get_json()["conflict"] is True
    with open(b_path) as f:
        assert f.read() == before


def test_a_save_carrying_another_cases_record_is_refused(client, evidence_root):
    _, a_path, _ = _make_case(evidence_root, "Open", slug="2026-CASE-A")
    _, b_path, _ = _make_case(evidence_root, "Open", slug="2026-CASE-B")
    with open(a_path) as f:
        record_a = json.load(f)
    with open(b_path) as f:
        before = f.read()
    res = client.post("/api/report/save", json={"report_path": b_path, "report_data": record_a})
    assert res.status_code == 409
    with open(b_path) as f:
        assert f.read() == before


def test_a_save_with_its_own_edit_base_still_works(client, evidence_root):
    _, b_path, _ = _make_case(evidence_root, "Open", slug="2026-CASE-B")
    with open(b_path) as f:
        record = json.load(f)
    res = client.post("/api/report/save", json={
        "report_path": b_path,
        "report_data": {**record, "executive_summary": "mine"},
        "base_fields": {"executive_summary": None},
        "base_report_path": b_path,
    })
    assert res.status_code == 200, res.get_json()
    with open(b_path) as f:
        assert json.load(f)["executive_summary"] == "mine"


def test_an_open_case_is_still_editable(client, evidence_root):
    _, report_path, _ = _make_case(evidence_root, "Open")
    res = client.post("/api/cases/notes/add", data={"report_path": report_path, "text": "a note"})
    assert res.status_code == 200, res.get_json()
