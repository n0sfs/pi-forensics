"""Hash Manifest, YARA Rule Sweep and Recover Deleted run as the station's
background job (Eric's decision 2026-11-20, 10-09 item 7). Each used to be
one request walking the whole image for minutes with no progress, no Stop and
no job slot. They now claim the slot, report files done / total, stop
between files, and say in their output that a stopped run is incomplete."""
import os
import threading
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.image_browser as image_browser
from core.jobs import current_job, job_lock, snapshot_job, update_job
from tests.conftest import RemoteTestClient, login_user_session
from tests.test_image_browser_integrity import _File, _Fs, _entry, _case, _install_walk


@pytest.fixture(autouse=True)
def idle_slot():
    with job_lock:
        current_job.update(active=False, status="IDLE", format="dd", log="", summary="")
    yield
    with job_lock:
        current_job.update(active=False, status="IDLE")


@pytest.fixture
def custody(monkeypatch):
    events = []
    monkeypatch.setattr(image_browser, "log_chain_of_custody", lambda ev, data, **k: events.append((ev, data)))
    return events


@pytest.fixture
def client(runtime_config_file, custody):
    app = Flask(__name__)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(image_browser.image_browser_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


@pytest.fixture
def image(evidence_root, monkeypatch):
    path = os.path.join(evidence_root, "disk.dd")
    with open(path, "wb") as f:
        f.write(b"\0" * 512)
    monkeypatch.setattr(image_browser, "_resolve_browsable_source", lambda raw: path)
    return path


def _wait_idle(timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if not snapshot_job()["active"]:
            return snapshot_job()
        time.sleep(0.02)
    raise AssertionError("job never finished")


def _files(n):
    return _Fs({i: _File(f"file {i}".encode()) for i in range(1, n + 1)}), [(_entry(f"f{i}.txt", i, size=6), f"/f{i}.txt") for i in range(1, n + 1)]


def test_hash_manifest_runs_as_a_job_and_reports_its_counts(client, evidence_root, image, monkeypatch, custody):
    folder = _case(evidence_root)
    fs, entries = _files(3)
    _install_walk(monkeypatch, fs, entries)
    res = client.post("/api/image/hash_manifest", json={"image_path": image, "destination_dir": folder})
    assert res.status_code == 200 and res.get_json()["job"] is True
    job = _wait_idle()
    assert job["format"] == "image_hash_manifest", job["log"]
    assert job["status"] == "Completed Successfully", job["log"]
    assert "Hashed 3 file(s)" in job["summary"]
    manifest = os.path.join(folder, "disk_hash_manifest_sha256.txt")
    assert os.path.isfile(manifest)
    names = [ev for ev, _ in custody]
    assert names == ["hash_manifest_export_image_start", "hash_manifest_export_image"]
    assert custody[-1][1]["files_hashed"] == 3 and custody[-1][1]["stopped"] is False


def test_a_second_tool_cannot_start_beside_a_running_job(client, evidence_root, image):
    folder = _case(evidence_root)
    with job_lock:
        current_job["active"] = True
    for url, extra in [("/api/image/hash_manifest", {}), ("/api/image/recover_deleted", {})]:
        res = client.post(url, json={"image_path": image, "destination_dir": folder, **extra})
        assert res.status_code == 400 and "already running" in res.get_json()["error"]


def test_stop_ends_the_walk_between_files_and_marks_the_output_incomplete(client, evidence_root, image, monkeypatch, custody):
    folder = _case(evidence_root)
    gate = threading.Event()
    fs, entries = _files(50)
    real_stream = image_browser._tsk_stream_file

    def slow_stream(f, write_fn, **k):
        if f.data == b"file 3":
            update_job(status="Stopped")   # what stop_imaging() writes
            gate.set()
        return real_stream(f, write_fn, **k)

    monkeypatch.setattr(image_browser, "_tsk_stream_file", slow_stream)
    _install_walk(monkeypatch, fs, entries)
    client.post("/api/image/hash_manifest", json={"image_path": image, "destination_dir": folder})
    assert gate.wait(5)
    _wait_idle()
    text = open(os.path.join(folder, "disk_hash_manifest_sha256.txt"), encoding="utf-8").read()
    assert "INCOMPLETE" in text and "pressed Stop" in text
    assert text.count("/f") <= 4   # stopped within a file, not after all 50
    assert custody[-1][1]["stopped"] is True


def test_progress_reports_files_done_out_of_total(evidence_root, image, monkeypatch):
    fs, entries = _files(4)
    _install_walk(monkeypatch, fs, entries)
    seen = []
    result = image_browser._run_hash_manifest_body(image, evidence_root, "sha256", {},
                                                   progress=lambda d, t: seen.append((d, t)), max_seconds=None)
    assert result["success"] and result["files_hashed"] == 4 and result["stopped"] is False
    assert seen[0] == (0, 4) and seen[-1] == (3, 4)


def test_recover_deleted_runs_as_a_job(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root)
    fs = _Fs({7: _File(b"gone but not forgotten")})
    _install_walk(monkeypatch, fs, [(_entry("old.txt", 7, deleted=True, size=22), "/old.txt")])
    res = client.post("/api/image/recover_deleted", json={"image_path": image, "destination_dir": folder})
    assert res.get_json()["job"] is True
    job = _wait_idle()
    assert job["format"] == "image_recover_deleted" and job["status"] == "Completed Successfully"
    assert "Recovered 1 file(s)" in job["summary"]


def test_yara_sweep_runs_as_a_job(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root)
    monkeypatch.setattr(image_browser, "load_yara_ruleset_sources",
                        lambda ids: {"r1": {"name": "Test", "rule_text": 'rule hit { strings: $a = "needle" condition: $a }'}})
    fs = _Fs({1: _File(b"hay needle hay"), 2: _File(b"nothing")})
    _install_walk(monkeypatch, fs, [(_entry("a.bin", 1, size=14), "/a.bin"), (_entry("b.bin", 2, size=7), "/b.bin")])
    res = client.post("/api/image/yara_sweep", json={"image_path": image, "destination_dir": folder, "ruleset_ids": ["r1"]})
    assert res.get_json()["job"] is True
    job = _wait_idle()
    assert job["format"] == "image_yara_sweep" and job["status"] == "Completed Successfully"
    assert "1 file(s) matched a rule" in job["summary"]


def test_no_filesystem_fails_the_job_with_the_reason(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root)
    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems", lambda image_path, skipped=None: [])
    client.post("/api/image/hash_manifest", json={"image_path": image, "destination_dir": folder})
    job = _wait_idle()
    assert job["status"] == "Failed" and "No recognized filesystem" in job["summary"]


def test_progress_route_carries_the_summary():
    from routes.acquisition import acquisition_bp
    app = Flask(__name__)
    app.register_blueprint(acquisition_bp)
    with job_lock:
        current_job["summary"] = "Hashed 3 file(s)."
    body = app.test_client().get("/api/progress", base_url="http://127.0.0.1:5000").get_json()
    assert body["summary"] == "Hashed 3 file(s)."
