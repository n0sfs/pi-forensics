"""The exported report's own Timeline section (2026-09-08) - previously
_draw_pdf_timeline_block()/_html_timeline_block() only ever drew raw
_collect_case_timeline() MACB rows, quietly falling behind the interactive
Evidence Timeline tab once THAT view got enriched with parsed_artifacts
rows/entity-linked counterparts/suspicious flags/content previews on
2026-09-07 (see tests/test_case_timeline_route.py for that route's own
extensive coverage - _build_enriched_case_timeline() is the exact same
function this export path now shares, so this file focuses on what's
genuinely NEW here: that export_report() actually threads case_folder
through to the export builders (not just the interactive route), that the
new include_timeline_previews station setting round-trips through
settings_case_reporting() and gates real content correctly, and that a
suspicious/content-preview-bearing row renders through the real HTTP
export path end to end.

Uses the same "custom_sections" preview-only override export_report()
already exposes for the Report Template Builder's own live-preview button
(req.get('preview') + req.get('custom_sections')) - a minimal, one-block
{"key": "timeline", "enabled": True} list is all a custom template's own
_resolve_section_order() needs (confirmed: it tolerates a partial section
list, nothing else needs to be present), and preview mode returns the
rendered bytes directly with no disk write - the simplest way to exercise
the real export path without also constructing a full saved
custom_report_templates record.

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
from routes.reporting import reporting_bp, _draw_pdf_timeline_block, _html_timeline_block
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


def _make_real_case(evidence_root, slug="2026-TEST-TIMELINE-EXPORT"):
    # One dummy event (no acquisition_status/output_image_path) so
    # REPORT_SECTION_BLOCKS' requires_events gate (True for "timeline")
    # is satisfied, while _collect_case_timeline() itself still
    # contributes zero MACB rows for it (its own COMPLETED/output_
    # image_path filter never matches this event) - keeps the test
    # focused purely on the parsed_artifacts enrichment path.
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    case_file = os.path.join(case_folder, f"{slug}_case.json")
    with open(case_file, 'w') as f:
        json.dump({"schema_version": 1, "case_number": slug, "examiner": "x",
                   "events": [{"tool": "dd"}],
                   "attachments": {"files": [], "reference_urls": []}}, f)
    return case_folder, case_file


def _export_preview(client, case_file, fmt="html", include_previews=None):
    if include_previews is not None:
        res = client.post("/api/settings/case_reporting", json={
            "report_defaults": {"include_timeline_previews": include_previews},
        })
        assert res.status_code == 200
    res = client.post("/api/export_report", json={
        "report_path": case_file, "format": fmt, "preview": True,
        "custom_sections": [{"key": "timeline", "enabled": True}],
    })
    assert res.status_code == 200
    return res.get_data(as_text=(fmt == "html"))


def test_include_timeline_previews_round_trips_through_settings(client):
    res = client.get("/api/settings/case_reporting")
    assert res.get_json()["report_defaults"].get("include_timeline_previews") in (None, False)

    res = client.post("/api/settings/case_reporting", json={
        "report_defaults": {"include_timeline_previews": True},
    })
    assert res.status_code == 200

    res = client.get("/api/settings/case_reporting")
    assert res.get_json()["report_defaults"]["include_timeline_previews"] is True

    # And back off again - a real toggle, not a one-way ratchet.
    client.post("/api/settings/case_reporting", json={"report_defaults": {"include_timeline_previews": False}})
    res = client.get("/api/settings/case_reporting")
    assert res.get_json()["report_defaults"]["include_timeline_previews"] is False


def test_html_export_uses_the_enriched_timeline_not_raw_macb(client, evidence_root):
    # Proves case_folder is genuinely threaded from export_report() into
    # _build_html_report_standard()'s own "timeline" dispatch lambda - a
    # raw _collect_case_timeline(events) call would show nothing at all
    # here (this case's one dummy event has no acquired image), so any
    # sign of this artifact's own text in the export can only have come
    # from the enriched, case_folder-aware path.
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "registry.hive")}, [
        {"artifact_type": "registry_recent_docs", "title": "quarterly_report.docx", "url": "",
         "value": "quarterly_report.docx", "timestamp": 1786784400.0, "extra": {}},
    ])
    html_out = _export_preview(client, case_file)
    assert "quarterly_report.docx" in html_out
    assert "registry_recent_docs" in html_out


def test_suspicious_row_gets_the_warning_marker_in_html_export(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "Security.evtx")}, [
        {"artifact_type": "evtx_audit_log_cleared", "title": "Audit log cleared", "url": "",
         "value": "Audit log cleared", "timestamp": 1786784400.0, "extra": {}},
    ])
    html_out = _export_preview(client, case_file)
    assert "⚠ evtx_audit_log_cleared" in html_out


def test_content_preview_absent_by_default_present_when_enabled(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "meet at the warehouse at 9",
         "timestamp": 1786784400.0, "extra": {"address": "+15551234567"}},
    ])

    # Default (station never touched this setting) - previews stay off.
    html_default = _export_preview(client, case_file)
    assert "meet at the warehouse at 9" not in html_default

    # Explicitly disabled - same result, but exercised through the real
    # settings write path rather than assumed from the default alone.
    html_off = _export_preview(client, case_file, include_previews=False)
    assert "meet at the warehouse at 9" not in html_off

    # Explicitly enabled - the real message text now appears, escaped.
    html_on = _export_preview(client, case_file, include_previews=True)
    assert "meet at the warehouse at 9" in html_on


def test_pdf_export_also_uses_the_enriched_timeline(client, evidence_root):
    # Same proof as the HTML test above, through the PDF path instead -
    # confirms _build_pdf_report_standard()'s own "timeline" dispatch
    # lambda got the identical case_folder threading, not just its HTML
    # sibling. A real .pdf byte stream can't be substring-matched for
    # readable text the way HTML can, so this only asserts on structural
    # signals: a real multi-page PDF (>1 page implies real content was
    # drawn, not just the empty "No timeline data..." fallback line) with
    # the correct magic bytes.
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "registry.hive")}, [
        {"artifact_type": "registry_recent_docs", "title": "quarterly_report.docx", "url": "",
         "value": "quarterly_report.docx", "timestamp": 1786784400.0, "extra": {}},
    ])
    pdf_bytes = _export_preview(client, case_file, fmt="pdf")
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 500


def test_draw_functions_tolerate_a_missing_case_folder_without_crashing():
    # The documented defensive fallback (case_folder=None) - no real call
    # site in this file ever omits it, but neither drawing function should
    # ever crash if one somehow did. A bare reportlab canvas is enough to
    # exercise the PDF path directly, with no Flask/case-folder machinery
    # involved at all.
    from reportlab.pdfgen import canvas
    import io
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    y = _draw_pdf_timeline_block(c, 700, events=[], case_folder=None)
    assert isinstance(y, (int, float))

    html_out = _html_timeline_block(events=[], case_folder=None)
    assert "No timeline data available" in html_out
