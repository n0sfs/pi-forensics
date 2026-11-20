"""Export gaps from the 2026-10-09 review, closed 2026-11-20:
- Raw JSON / Evidence Inventory CSV are kept on the station (versioned
  name, .sha256 sidecar, custody entry) and listed under Previous exports.
- A saved export can be downloaded again, and only a listed one.
- A custom template without an Exhibits block says the checked files were
  left out (X-Report-Notice) instead of dropping them silently.

Same minimal-app pattern as tests/test_reporting_spot_check_2026_10_03.py.
"""
import hashlib
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


@pytest.fixture
def custody(monkeypatch):
    calls = []
    monkeypatch.setattr(reporting, "log_chain_of_custody", lambda action, details, *a, **k: calls.append((action, details)))
    return calls


def _case(evidence_root, slug="2026-EXP"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    report = os.path.join(folder, f"{slug}_case.json")
    with open(report, "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": "Open",
                   "events": [], "case_notes": [], "updated_at": "2026-01-01 00:00:00"}, f)
    return folder, report


@pytest.mark.parametrize("fmt,suffix", [("json", ".json"), ("csv", "_evidence_inventory.csv")])
def test_a_client_export_is_saved_hashed_logged_and_listed(client, evidence_root, custody, fmt, suffix):
    folder, report = _case(evidence_root)
    text = '{"a": 1}' if fmt == "json" else "Evidence ID\r\nITEM-01\r\n"
    data = client.post("/api/report_exports/save_client_export",
                       json={"report_path": report, "format": fmt, "content": text}).get_json()
    assert data["success"] is True
    assert data["filename"].startswith("2026-EXP_case_") and data["filename"].endswith(suffix)
    path = os.path.join(folder, data["filename"])
    with open(path, "rb") as f:
        assert f.read() == text.encode("utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert data["sha256"] == digest
    with open(path + ".sha256") as f:
        assert f.read().split()[0] == digest
    assert custody == [("report_exported", {"case_folder": folder, "format": fmt, "template": None,
                                            "file": path, "sha256": digest})]
    listed = client.get(f"/api/report_exports?report_path={report}").get_json()["exports"]
    assert [e["name"] for e in listed] == [data["filename"]]


def test_two_saves_in_the_same_second_never_overwrite(client, evidence_root, custody):
    _, report = _case(evidence_root)
    names = {client.post("/api/report_exports/save_client_export",
                         json={"report_path": report, "format": "json", "content": c}).get_json()["filename"]
             for c in ("1", "2")}
    assert len(names) == 2


def test_client_export_rejects_other_formats_and_empty_content(client, evidence_root, custody):
    _, report = _case(evidence_root)
    assert client.post("/api/report_exports/save_client_export",
                       json={"report_path": report, "format": "pdf", "content": "x"}).status_code == 400
    assert client.post("/api/report_exports/save_client_export",
                       json={"report_path": report, "format": "json", "content": ""}).status_code == 400
    assert custody == []


def test_a_listed_export_downloads_and_is_logged(client, evidence_root, custody):
    folder, report = _case(evidence_root)
    saved = client.post("/api/report_exports/save_client_export",
                        json={"report_path": report, "format": "json", "content": "{}"}).get_json()
    path = os.path.join(folder, saved["filename"])
    res = client.get("/api/report_exports/download", query_string={"report_path": report, "path": path})
    assert res.status_code == 200 and res.data == b"{}"
    assert res.headers["X-Report-Sha256"] == saved["sha256"]
    assert saved["filename"] in res.headers["Content-Disposition"]
    assert custody[-1] == ("report_export_downloaded", {"case_folder": folder, "file": path, "sha256": saved["sha256"]})


def test_download_refuses_anything_not_listed_as_an_export(client, evidence_root, custody):
    folder, report = _case(evidence_root)
    res = client.get("/api/report_exports/download", query_string={"report_path": report, "path": report})
    assert res.status_code == 400
    assert custody == []


def test_custom_template_without_exhibits_says_checked_files_were_left_out(client, evidence_root):
    folder, report = _case(evidence_root)
    exhibit = os.path.join(folder, "photo.jpg")
    open(exhibit, "wb").close()
    body = {"report_path": report, "format": "html", "preview": True,
            "attachment_selection": {"files": [exhibit], "urls": []}}
    res = client.post("/api/export_report", json={**body, "custom_sections": [{"key": "case_info"}]})
    assert res.status_code == 200
    assert "1 checked file(s)" in res.headers.get("X-Report-Notice", "")
    with_exhibits = client.post("/api/export_report", json={**body, "custom_sections": [{"key": "attachments"}]})
    assert "X-Report-Notice" not in with_exhibits.headers
