"""Verify All Evidence's own hash-verification status, wired into the
Evidence Inventory table both the PDF and HTML exported report already
show (2026-09-10). _draw_pdf_evidence_inventory()/_html_evidence_
inventory_table() both reuse compute_case_analysis_coverage() (core/
case_index_db.py, already extensively covered by tests/test_case_index_
db.py for its own status-derivation logic) rather than a second, separate
status computation - this file focuses on what's genuinely new: that
export_report() threads a real per-event hash_status through correctly,
that each of the five real states (plus the "never computed at all"
fallback) renders with the correct HTML label/CSS class, and that the
wiring reaches every template that shows Evidence Inventory at all
(Standard/Police/CASE-UCO - DFIR never shows this section, so it's
untouched).

Through a real Flask test client, matching tests/test_pattern_of_life_
export.py's own established pattern (a minimal app registering just
reporting_bp, the same "preview" + "custom_sections" override export_
report() already exposes for the Report Template Builder's own live-
preview button). Skipped (not failed) on a non-POSIX dev machine:
core.jobs needs POSIX-only pwd/fcntl.
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


def _event(event_id, image_path, evidence_id="USBDrive-1", computed_hashes=None):
    return {
        "event_id": event_id,
        "acquisition_status": "COMPLETED",
        "tool": "dd",
        "case_metadata": {"evidence_id": evidence_id},
        "source_drive_telemetry": {
            "device_path": "/dev/sda", "vendor_model": "Generic Media",
            "serial_number": "SN123", "capacity_gb": 14.5,
        },
        "acquisition_parameters": {"output_image_path": image_path},
        "computed_verification_hashes": computed_hashes or {},
    }


def _make_real_case(evidence_root, events, last_verification=None, slug="2026-TEST-EVID-INV"):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    case_file = os.path.join(case_folder, f"{slug}_case.json")
    data = {
        "schema_version": 1, "case_number": slug, "examiner": "x",
        "events": events, "attachments": {"files": [], "reference_urls": []},
    }
    if last_verification is not None:
        data["last_verification"] = last_verification
    with open(case_file, "w") as f:
        json.dump(data, f)
    return case_folder, case_file


def _export_preview(client, case_file, fmt="html", template=None):
    body = {"report_path": case_file, "format": fmt, "preview": True}
    if template is None:
        body["custom_sections"] = [{"key": "evidence_inventory", "enabled": True}]
    else:
        body["template"] = template
    res = client.post("/api/export_report", json=body)
    assert res.status_code == 200
    return res.get_data(as_text=(fmt == "html"))


def test_html_shows_verified_for_a_matching_hash(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "match", "current_hashes": {"sha256": "abc"}},
        ]},
    )
    html_out = _export_preview(client, case_file)
    assert "Hash Verified" in html_out
    assert 'class="hash-ok"' in html_out
    assert "HASH MISMATCH" not in html_out


def test_html_shows_mismatch_and_never_hides_it(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "mismatch", "current_hashes": {"sha256": "different"}},
        ]},
    )
    html_out = _export_preview(client, case_file)
    assert "HASH MISMATCH" in html_out
    assert 'class="hash-mismatch"' in html_out


def test_html_shows_missing_file_distinct_from_mismatch_but_same_color_class(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "missing_file", "current_hashes": {}},
        ]},
    )
    html_out = _export_preview(client, case_file)
    assert "File Missing" in html_out
    assert 'class="hash-mismatch"' in html_out


def test_html_shows_not_yet_reverified_when_hash_recorded_but_never_checked(client, evidence_root):
    # A real acquisition hash was computed at capture time, but Verify All
    # Evidence has never run against this case at all - no last_verification
    # block on the case whatsoever, not even one covering a different event.
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
    )
    html_out = _export_preview(client, case_file)
    assert "Not Yet Re-Verified" in html_out
    assert 'class="hash-warn"' in html_out


def test_html_shows_no_hash_recorded_when_neither_hash_nor_verification_exist(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"))],
    )
    html_out = _export_preview(client, case_file)
    assert "No Hash Recorded" in html_out
    assert 'class="hash-muted"' in html_out


def test_html_shows_not_checked_for_a_legacy_not_yet_consolidated_report(client, evidence_root):
    # No {slug}_case.json marker anywhere in the folder - a genuine
    # single-job legacy report, the one shape compute_case_analysis_
    # coverage() always returns {"items": []} for (case_consolidated_
    # path() correctly returns None), so every event here must fall back
    # to the honest "never even computed" state, not a wrong guess.
    case_folder = os.path.join(evidence_root, "2026-TEST-LEGACY")
    os.makedirs(case_folder, exist_ok=True)
    report_file = os.path.join(case_folder, "USBDrive-1_report.json")
    with open(report_file, "w") as f:
        json.dump({
            "case_metadata": {"case_number": "2026-TEST-LEGACY", "examiner": "x", "evidence_id": "USBDrive-1"},
            "source_drive_telemetry": {"device_path": "/dev/sda", "vendor_model": "Generic Media", "serial_number": "SN1", "capacity_gb": 14.5},
            "computed_verification_hashes": {"sha256": "abc"},
            "timestamp_start": "t",
        }, f)
    html_out = _export_preview(client, report_file)
    assert "Not Checked" in html_out
    assert 'class="hash-muted"' in html_out


def test_multiple_events_each_get_their_own_independent_status(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [
            _event("evt-match", os.path.join(evidence_root, "a.dd"), evidence_id="ItemA", computed_hashes={"sha256": "a"}),
            _event("evt-mismatch", os.path.join(evidence_root, "b.dd"), evidence_id="ItemB", computed_hashes={"sha256": "b"}),
        ],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-match", "evidence_id": "ItemA", "status": "match", "current_hashes": {"sha256": "a"}},
            {"event_id": "evt-mismatch", "evidence_id": "ItemB", "status": "mismatch", "current_hashes": {"sha256": "different"}},
        ]},
    )
    html_out = _export_preview(client, case_file)
    assert "Hash Verified" in html_out
    assert "HASH MISMATCH" in html_out


def test_pdf_export_renders_with_the_new_column_and_does_not_crash(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "mismatch", "current_hashes": {"sha256": "different"}},
        ]},
    )
    pdf_bytes = _export_preview(client, case_file, fmt="pdf")
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 500


def test_police_template_also_shows_verification_status(client, evidence_root):
    # Police always includes Evidence Inventory unconditionally (no section
    # checkbox at all, part of its fixed structure) - confirms the wiring
    # reaches _build_html_report_police, not just the Standard template's
    # own configurable dispatch dict.
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "match", "current_hashes": {"sha256": "abc"}},
        ]},
    )
    html_out = _export_preview(client, case_file, template="police")
    assert "Hash Verified" in html_out
    assert 'class="hash-ok"' in html_out


def test_caseuco_template_also_shows_verification_status(client, evidence_root):
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
        last_verification={"timestamp": "t", "results": [
            {"event_id": "evt-1", "evidence_id": "USBDrive-1", "status": "unverifiable", "current_hashes": {}},
        ]},
    )
    html_out = _export_preview(client, case_file, template="caseuco")
    assert "Unverifiable" in html_out
    assert 'class="hash-muted"' in html_out


def test_dfir_template_export_still_succeeds_unaffected(client, evidence_root):
    # DFIR's own fixed structure never includes Evidence Inventory at all -
    # a plain, real regression check that threading hash_status_by_event
    # through export_report() didn't break the one template that never
    # consumes it.
    case_folder, case_file = _make_real_case(
        evidence_root,
        [_event("evt-1", os.path.join(evidence_root, "img.dd"), computed_hashes={"sha256": "abc"})],
    )
    html_out = _export_preview(client, case_file, template="dfir")
    assert "<html>" in html_out
    assert "Hash Verified" not in html_out
    assert "No Hash Recorded" not in html_out
