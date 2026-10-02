"""Batch 4 of the 2026-10-02 review, the route parts (POSIX: these blueprints
need core.jobs, which imports pwd/fcntl - skipped, not failed, elsewhere).

- /api/files/browse had no permission check; a broken link vanished from it.
- PhotoRec's /d is a name prefix, so its output landed BESIDE the job folder;
  re-runs of PhotoRec/extundelete reused an earlier run's folder.
- TestDisk ran beside a running job and reported a failed run as a listing.
- An Android block path ending in a newline, or holding '..', passed.
- File Explorer's writers took new work into a Closed case.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="these blueprints need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.file_explorer as file_explorer
import routes.recovery as recovery
from routes.mobile import is_valid_android_block_path
from tests.conftest import RemoteTestClient, login_user_session


def _client(blueprint, group="admin"):
    app = Flask(__name__)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(blueprint)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "u", "password_hash": generate_password_hash("x"),
                                        "group_id": group})
    if group == "viewer":
        cfg.setdefault("user_groups", []).append({"id": "viewer", "name": "Viewer", "permissions": {}})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "u")
    return c


@pytest.fixture
def fe(runtime_config_file, monkeypatch):
    monkeypatch.setattr(file_explorer, "log_chain_of_custody", lambda *a, **k: None)
    return _client(file_explorer.file_explorer_bp)


def test_a_broken_link_is_listed_not_dropped(fe, evidence_root):
    os.symlink(os.path.join(evidence_root, "gone.bin"), os.path.join(evidence_root, "dangling"))
    data = fe.post("/api/files/browse", json={"path": evidence_root}).get_json()
    item = next(i for i in data["items"] if i["name"] == "dangling")
    assert item["broken_link"] is True and item["is_symlink"] is True
    assert item["link_target"].endswith("gone.bin")


def test_browse_needs_a_permission(runtime_config_file, evidence_root):
    c = _client(file_explorer.file_explorer_bp, group="viewer")
    assert c.post("/api/files/browse", json={"path": evidence_root}).status_code == 403


def _case(root, status):
    folder = os.path.join(root, f"2026-{status.upper()}")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"2026-{status.upper()}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": "x", "case_folder": folder, "case_status": status,
                   "events": []}, f)
    return folder


@pytest.mark.parametrize("route", ["/api/files/parse_registry", "/api/files/parse_evtx",
                                   "/api/files/parse_mobile_artifacts", "/api/files/quick_triage_scan"])
def test_a_closed_case_takes_no_new_file_explorer_work(fe, evidence_root, route):
    folder = _case(evidence_root, "Closed")
    res = fe.post(route, json={"path": evidence_root, "case_folder": folder})
    assert res.status_code == 409 and res.get_json()["closed_case"] == "Closed"


@pytest.mark.parametrize("path, ok", [
    ("/dev/block/sda", True), ("/dev/block/by-name/userdata", True),
    ("/dev/block/sda\n", False), ("/dev/block/../../sdcard/x", False), ("/dev/block/./sda", False),
    ("/dev/sda", False), (None, False),
])
def test_android_block_paths(path, ok):
    assert is_valid_android_block_path(path) is ok


# --- recovery --------------------------------------------------------------------------

@pytest.fixture
def rec(runtime_config_file, monkeypatch):
    monkeypatch.setattr(recovery, "log_chain_of_custody", lambda *a, **k: None)
    with jobs.job_lock:
        jobs.current_job["active"] = False
    yield _client(recovery.recovery_bp)
    with jobs.job_lock:
        jobs.current_job["active"] = False


def test_photorec_writes_inside_its_own_folder(monkeypatch, tmp_path):
    seen = {}

    def fake_stream(cmd, *a, **k):
        seen["cmd"] = cmd
        raise RuntimeError("stop here")

    monkeypatch.setattr(recovery, "_stream_subprocess", fake_stream)
    monkeypatch.setattr(recovery, "_write_report", lambda *a, **k: None, raising=False)
    try:
        recovery.execution_worker_photorec("/dev/sdz", str(tmp_path / "job"), str(tmp_path / "r.json"), {})
    except Exception:
        pass
    cmd = seen["cmd"]
    assert cmd[cmd.index("/d") + 1] == os.path.join(str(tmp_path / "job"), "recup_dir")


def test_testdisk_waits_for_a_running_job(rec, evidence_root):
    image = os.path.join(evidence_root, "x.dd")
    open(image, "wb").close()
    with jobs.job_lock:
        jobs.current_job["active"] = True
    res = rec.post("/api/recovery/testdisk_analyze", json={"source": image})
    assert res.status_code == 409
