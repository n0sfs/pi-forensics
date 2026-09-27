"""Regression tests for the 2026-09-27 full-app review fixes that don't have
a more specific home: File Explorer delete/copy protections, versioned
report export, and the no-case job report merge.

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
import core.jobs as jobs
import core.paths as paths
import routes.file_explorer as fe
from routes.file_explorer import file_explorer_bp
from routes.reporting import reporting_bp
from tests.conftest import RemoteTestClient, login_user_session


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"))
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(file_explorer_bp)
    app.register_blueprint(reporting_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _case(evidence_root, slug="2026-REV", status="Open"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": status,
                   "events": [], "updated_at": "2026-01-01 00:00:00"}, f)
    return folder


# --- File Explorer delete ---------------------------------------------------

def test_delete_refuses_the_evidence_root_a_case_folder_and_its_record(client, evidence_root, monkeypatch):
    monkeypatch.setattr(fe, "EVIDENCE_ROOT", evidence_root)
    folder = _case(evidence_root)
    for target in (evidence_root, folder, os.path.join(folder, "2026-REV_case.json")):
        res = client.post("/api/files/delete", json={"path": target})
        assert res.status_code == 409, target
    assert os.path.exists(os.path.join(folder, "2026-REV_case.json"))


def test_delete_refuses_anything_inside_a_closed_case(client, evidence_root):
    folder = _case(evidence_root, "2026-CLOSED", "Closed")
    f = os.path.join(folder, "evidence.dd")
    open(f, "wb").close()
    assert client.post("/api/files/delete", json={"path": f}).status_code == 409
    assert os.path.exists(f)


def test_delete_still_works_for_an_ordinary_file_in_an_open_case(client, evidence_root):
    folder = _case(evidence_root)
    f = os.path.join(folder, "scratch.txt")
    open(f, "w").close()
    assert client.post("/api/files/delete", json={"path": f}).status_code == 200
    assert not os.path.exists(f)


# --- File Explorer copy -----------------------------------------------------

def test_copy_never_overwrites_or_merges(client, evidence_root):
    src_dir, dest_dir = os.path.join(evidence_root, "src"), os.path.join(evidence_root, "dest")
    os.makedirs(src_dir)
    os.makedirs(dest_dir)
    with open(os.path.join(src_dir, "a.txt"), "w") as f:
        f.write("new")
    with open(os.path.join(dest_dir, "a.txt"), "w") as f:
        f.write("original evidence")
    res = client.post("/api/files/copy", json={"source": os.path.join(src_dir, "a.txt"), "destination_dir": dest_dir})
    assert res.status_code == 409
    with open(os.path.join(dest_dir, "a.txt")) as f:
        assert f.read() == "original evidence"


def test_copy_does_not_follow_symlinks_out_of_the_tree(client, evidence_root, tmp_path):
    secret = tmp_path / "outside_secret"
    secret.write_text("should not be copied")
    src = os.path.join(evidence_root, "pull")
    os.makedirs(src)
    os.symlink(str(secret), os.path.join(src, "link"))
    dest = os.path.join(evidence_root, "copies")
    os.makedirs(dest)
    assert client.post("/api/files/copy", json={"source": src, "destination_dir": dest}).status_code == 200
    copied = os.path.join(dest, "pull", "link")
    assert os.path.islink(copied)                  # copied AS a link, the secret's bytes never read


def test_copy_into_a_closed_case_is_refused(client, evidence_root):
    folder = _case(evidence_root, "2026-SHUT", "Archived")
    src = os.path.join(evidence_root, "x.txt")
    open(src, "w").close()
    assert client.post("/api/files/copy", json={"source": src, "destination_dir": folder}).status_code == 409


# --- Report export versioning ------------------------------------------------

def test_each_export_is_a_new_file_and_the_custody_log_records_its_hash(client, evidence_root, monkeypatch):
    folder = _case(evidence_root)
    logged = []
    import routes.reporting as reporting
    monkeypatch.setattr(reporting, "log_chain_of_custody", lambda action, details=None, **kw: logged.append((action, details)))
    report = os.path.join(folder, "2026-REV_case.json")
    names = set()
    for _ in range(2):
        res = client.post("/api/export_report", json={"report_path": report, "format": "html"})
        assert res.status_code == 200
        names.add(res.headers.get("Content-Disposition"))
    exports = [n for n in os.listdir(folder) if n.endswith(".html")]
    assert len(exports) == 2, exports                 # the first export was not overwritten
    assert all(paths.classify_case_role(n) == "report" for n in exports)
    details = [d for a, d in logged if a == "report_exported"]
    assert len(details) == 2 and all(d.get("sha256") and d.get("file") for d in details)


# --- No-case job report ------------------------------------------------------

def test_job_completion_keeps_notes_added_while_it_ran(tmp_path):
    report = str(tmp_path / "C_ITEM_report.json")
    jobs.write_initial_report(report, {"acquisition_status": "IN_PROGRESS", "tool": "dd"})
    with open(report) as f:
        data = json.load(f)
    data["case_notes"] = [{"note_id": "n1", "text": "seal intact"}]
    with open(report, "w") as f:
        json.dump(data, f)
    jobs._write_report(report, {"acquisition_status": "COMPLETED", "tool": "dd"}, lambda m: None)
    with open(report) as f:
        final = json.load(f)
    assert final["acquisition_status"] == "COMPLETED"
    assert final["case_notes"] == [{"note_id": "n1", "text": "seal intact"}]
