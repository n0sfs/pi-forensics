"""Regression tests for the 2026-10-03 reporting spot check: attachment path
sandboxing, note integrity printed, empty event selection, the integrity
summary, the software environment block, the sign-off details and the
previous-exports list/verify routes.

Skipped (not failed) on a non-POSIX dev machine: these routes import
core.jobs (pwd/fcntl).
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.reporting as reporting
from routes.reporting import reporting_bp
from tests.conftest import RemoteTestClient, login_user_session


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"))
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(reporting_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _case(evidence_root, slug="2026-RPT", events=None, notes=None):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    report = os.path.join(folder, f"{slug}_case.json")
    with open(report, "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": "Open",
                   "events": events or [], "case_notes": notes or [], "updated_at": "2026-01-01 00:00:00"}, f)
    return folder, report


def _export_html(client, report, **extra):
    res = client.post("/api/export_report", json={"report_path": report, "format": "html", "preview": True, **extra})
    assert res.status_code == 200, res.data[:300]
    return res.data.decode("utf-8")


def test_an_attachment_outside_the_evidence_root_is_never_embedded(client, evidence_root, tmp_path):
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("TOP-SECRET-STATION-CONFIG")
    _, report = _case(evidence_root)
    body = _export_html(client, report, attachment_selection={"files": [str(secret)], "urls": []})
    assert "TOP-SECRET-STATION-CONFIG" not in body


def test_note_hash_and_earlier_versions_are_printed(client, evidence_root):
    note = {"note_id": "n1", "timestamp": "2026-01-02 10:00:00", "author": "ex", "category": "General",
            "text": "current text", "attachments": [], "linked_files": [], "content_hash": "a" * 64,
            "edited_at": "2026-01-03 10:00:00",
            "edit_history": [{"text": "original wording", "content_hash": "b" * 64, "edited_at": None}]}
    _, report = _case(evidence_root, notes=[note])
    body = _export_html(client, report)
    assert "a" * 64 in body and "b" * 64 in body
    assert "original wording" in body


def test_a_missing_note_attachment_is_stated_not_dropped(client, evidence_root):
    folder, _ = _case(evidence_root)
    note = {"note_id": "n1", "timestamp": "t", "author": "ex", "category": "General", "text": "x",
            "attachments": [{"path": os.path.join(folder, "gone.png")}], "linked_files": [], "content_hash": "c" * 64}
    _, report = _case(evidence_root, notes=[note])
    assert "attachment not found at export time: gone.png" in _export_html(client, report)


def test_an_empty_event_selection_exports_no_events(client, evidence_root):
    events = [{"event_id": "e1", "tool": "dc3dd", "case_metadata": {"evidence_id": "EVID-UNIQUE-1"}}]
    _, report = _case(evidence_root, events=events)
    assert "EVID-UNIQUE-1" in _export_html(client, report)
    assert "EVID-UNIQUE-1" not in _export_html(client, report, event_ids=[])


def test_hash_summary_counts_each_state_and_flags_a_mismatch():
    events = [{"event_id": "a"}, {"event_id": "b"}, {"event_id": "c"}]
    line, problem = reporting._hash_summary(events, {"a": ("match", "2026-01-02 10:00:00"), "b": ("mismatch", None)})
    assert line.startswith("3 item(s): 1 Hash Verified, 1 HASH MISMATCH, 1 Not Checked")
    assert "2026-01-02 10:00:00" in line
    assert problem is True
    assert reporting._hash_summary([], {}) == ("No evidence items recorded.", False)


def test_environment_lists_every_tool_with_a_version_or_says_why_not():
    env = reporting._report_environment([{"tool": "dc3dd"}, {"tool": "triage_scan"}, {"tool": "made_up_tool"}])
    tools = dict(env["tools"])
    assert tools["DC3DD"].startswith("dc3dd ")
    assert tools["TRIAGE_SCAN"] == "built into this application"
    assert tools["MADE_UP_TOOL"] == "version not recorded"


def test_signoff_uses_station_attestation_and_qualifications(client, evidence_root):
    cfg = config.load_runtime_config()
    cfg["report_defaults"] = {"branding": {"attestation_text": "Custom attestation wording.",
                                           "examiner_qualifications": "Student, year 3"}}
    config.save_runtime_config(cfg)
    _, report = _case(evidence_root)
    body = _export_html(client, report, template="police")   # Standard has no sign-off section
    assert "Custom attestation wording." in body
    assert "Qualifications: Student, year 3" in body
    assert "Report exported:" in body


def test_previous_exports_are_listed_and_verified(client, evidence_root, monkeypatch):
    monkeypatch.setattr(reporting, "log_chain_of_custody", lambda *a, **k: None)
    _, report = _case(evidence_root)
    assert client.post("/api/export_report", json={"report_path": report, "format": "html"}).status_code == 200
    listed = client.get(f"/api/report_exports?report_path={report}").get_json()
    assert listed["success"] and len(listed["exports"]) == 1
    exp = listed["exports"][0]
    assert exp["sha256"] and exp["has_sidecar"]

    ok = client.post("/api/report_exports/verify", json={"report_path": report, "path": exp["path"]}).get_json()
    assert ok["success"] and ok["match"] is True

    with open(exp["path"], "ab") as f:
        f.write(b"tampered")
    bad = client.post("/api/report_exports/verify", json={"report_path": report, "path": exp["path"]}).get_json()
    assert bad["success"] and bad["match"] is False


def test_verify_refuses_a_file_that_is_not_an_export_of_this_report(client, evidence_root):
    folder, report = _case(evidence_root)
    res = client.post("/api/report_exports/verify", json={"report_path": report, "path": report})
    assert res.status_code == 400


def test_standard_template_signoff_is_opt_in(client, evidence_root):
    # Off when a caller omits it - existing exports keep their shape.
    _, report = _case(evidence_root)
    assert "Sign-off &amp; Signatures" not in _export_html(client, report, sections={"case_details": True})
    body = _export_html(client, report, sections={"case_details": True, "signoff": True})
    assert "Sign-off &amp; Signatures" in body and "Report exported:" in body


def test_custom_template_saved_without_signoff_keeps_it_off():
    # A template re-saved by a client that predates the block must not grow
    # a sign-off section; every older block still fills in enabled.
    record, err = reporting._custom_report_template_from_payload(
        {"name": "Old", "sections": [{"key": "case_info", "enabled": True}]})
    assert err is None
    by_key = {s["key"]: s for s in record["sections"]}
    assert by_key["signoff"]["enabled"] is False
    assert by_key["executive_summary"]["enabled"] is True
    record, _ = reporting._custom_report_template_from_payload(
        {"name": "New", "sections": [{"key": "signoff", "enabled": True}]})
    assert {s["key"]: s for s in record["sections"]}["signoff"]["enabled"] is True
