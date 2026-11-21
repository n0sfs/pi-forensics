"""C11 (2026-11-21): the three fixed report templates exercised end to end
on a realistic case (one device image, one logical copy). Found: the DFIR
report never listed the evidence or any hash; evidence-table cells ran into
each other in the PDF; CASE/UCO's "Tools & Configured Tools" contents entry
had a differently-named heading; re-saving an unchanged case status logged
"Open -> Open" to the custody record."""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from reportlab.pdfbase.pdfmetrics import stringWidth
from werkzeug.security import generate_password_hash

import core.config as config
import routes.case_management as case_management
import routes.reporting as reporting
from tests.conftest import RemoteTestClient, login_user_session

SHA = "daa817c5a148c184aa7a83a168fb93499080b97f620b55db236d61a61cbaa162"
EVENTS = [
    {"event_id": "e1", "tool": "dc3dd", "acquisition_status": "COMPLETED", "timestamp_start": "2026-11-20 09:12:03",
     "case_metadata": {"evidence_id": "ITEM-02"},
     "source_drive_telemetry": {"device_path": "/dev/sda", "vendor_model": "Samsung SSD 870 EVO",
                                "serial_number": "S6PNNX0T123456", "capacity_gb": 160.0},
     "computed_verification_hashes": {"sha256": SHA}},
    {"event_id": "e2", "tool": "logical_acquisition", "acquisition_status": "COMPLETED",
     "case_metadata": {"evidence_id": "ITEM-03"}, "computed_verification_hashes": {"sha256": "c3" * 32}},
]


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"))
    app.secret_key = "test-only"
    app.register_blueprint(reporting.reporting_bp)
    app.register_blueprint(case_management.case_management_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _case(evidence_root, slug="2026-TPL"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    report = os.path.join(folder, f"{slug}_case.json")
    with open(report, "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": "Open",
                   "events": EVENTS, "updated_at": "2026-01-01 00:00:00"}, f)
    return folder, report


def _export(client, report, template, fmt):
    res = client.post("/api/export_report", json={"report_path": report, "format": fmt, "template": template, "preview": True})
    assert res.status_code == 200, res.data[:300]
    return res.data


@pytest.mark.parametrize("template", ["dfir", "police", "caseuco"])
def test_every_fixed_template_lists_each_item_and_its_full_hash(client, evidence_root, template):
    _, report = _case(evidence_root)
    html_out = _export(client, report, template, "html").decode()
    for needle in ("ITEM-02", "ITEM-03", SHA, "Folders (logical)"):
        assert needle in html_out, (template, needle)
    assert _export(client, report, template, "pdf").startswith(b"%PDF")


def test_dfir_pdf_has_an_evidence_section(client, evidence_root, monkeypatch):
    _, report = _case(evidence_root)
    drawn = []
    real = reporting._draw_pdf_evidence_inventory

    def spy(c, y, events, title="Evidence Inventory", hash_status_by_event=None):
        drawn.append((title, [e["case_metadata"]["evidence_id"] for e in events]))
        return real(c, y, events, title=title, hash_status_by_event=hash_status_by_event)

    monkeypatch.setattr(reporting, "_draw_pdf_evidence_inventory", spy)
    assert _export(client, report, "dfir", "pdf").startswith(b"%PDF")
    assert drawn == [("Evidence Acquired & Integrity Hashing", ["ITEM-02", "ITEM-03"])]


def test_pdf_cells_never_overrun_their_column():
    for value, width in [("Samsung SSD 870 EVO Plus 2TB", 84), ("SHA256: " + SHA, 87), ("S6PNNX0T123456789", 69)]:
        fitted = reporting._pdf_fit(value, width, "Helvetica", 7.5)
        assert stringWidth(fitted, "Helvetica", 7.5) <= width
        assert fitted.endswith("…")
    assert reporting._pdf_fit("ITEM-02", 56, "Helvetica", 7.5) == "ITEM-02"


def test_caseuco_tools_heading_matches_its_contents_entry(client, evidence_root):
    _, report = _case(evidence_root)
    html_out = _export(client, report, "caseuco", "html").decode()
    assert '<h2 id="sec-tools">Tools &amp; Configured Tools</h2>' in html_out


def test_resaving_the_same_status_is_not_logged(client, evidence_root, monkeypatch):
    folder, report = _case(evidence_root)
    logged = []
    monkeypatch.setattr(case_management, "log_chain_of_custody", lambda ev, data, **k: logged.append((ev, data)))
    res = client.post("/api/cases/set_status", json={"case_folder": folder, "status": "Open"})
    assert res.get_json()["success"] is True and res.get_json().get("unchanged") is True
    assert logged == []
    client.post("/api/cases/set_status", json={"case_folder": folder, "status": "Closed"})
    assert [e for e, _ in logged] == ["case_status_changed"]
