"""routes/acquisition.py's Live Collection USB routes (/api/live_collection/
start_build, /api/live_collection/scan, /api/live_collection/start_import) -
request validation, job-slot claiming, and response shape, through a real
Flask test client (matching tests/test_auto_analyze_detect.py's own
pattern). The actual wipe/mount/discover mechanics are independently
covered by tests/test_live_collection_utils.py's 16 mocked-subprocess
tests and by live verification on the deployed Pi (this project's own
established split between "route orchestration" and "underlying mechanics"
test coverage - see e.g. test_auto_analyze_detect.py).

Skipped (not failed) on a non-POSIX dev machine: core.jobs (imported by
routes.acquisition) needs POSIX-only pwd/fcntl.
"""
import os
import time
import threading

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.acquisition as acq
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(acq.acquisition_bp)
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


@pytest.fixture(autouse=True)
def _reset_job_state():
    """current_job/active_write_unlocked_devices are module-level shared
    state (by design, matching this app's single-shared-job architecture) -
    reset before and after every test so one test's job claim can never
    leak into the next."""
    jobs.current_job["active"] = False
    acq.active_write_unlocked_devices.clear()
    yield
    jobs.current_job["active"] = False
    acq.active_write_unlocked_devices.clear()


@pytest.fixture
def no_op_thread(monkeypatch):
    """Prevents the route from actually spawning a background worker
    thread against real subprocess/sudo calls - the route's own
    synchronous behavior (validation, job-slot claim, response) is what
    these tests exercise; the worker's own logic is covered elsewhere
    (see this file's own docstring)."""
    class _FakeThread:
        def __init__(self, target=None, args=(), daemon=None):
            pass

        def start(self):
            pass

    monkeypatch.setattr(acq.threading, "Thread", _FakeThread)


def test_start_build_rejects_invalid_device(client, no_op_thread):
    res = client.post("/api/live_collection/start_build", json={"device": "/dev/sda; rm -rf /"})
    assert res.status_code == 400
    assert res.get_json()["success"] is False
    assert jobs.current_job["active"] is False  # rejected before ever claiming the job slot for real


def test_start_build_rejects_when_a_job_is_already_active(client, no_op_thread):
    jobs.current_job["active"] = True
    res = client.post("/api/live_collection/start_build", json={"device": "/dev/sdb"})
    assert res.status_code == 400
    assert "already running" in res.get_json()["error"]


def test_start_build_accepts_a_valid_device_and_claims_the_job_slot(client, no_op_thread):
    res = client.post("/api/live_collection/start_build", json={
        "device": "/dev/sdb",
        "device_info": {"model": "Test USB", "serial": "ABC123", "size": "16 GB"},
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    assert jobs.current_job["active"] is True  # the route itself claims the slot before spawning the worker


def test_start_build_rejects_missing_device(client, no_op_thread):
    res = client.post("/api/live_collection/start_build", json={})
    assert res.status_code == 400


def test_scan_rejects_invalid_device(client):
    res = client.post("/api/live_collection/scan", json={"device": "not-a-device"})
    assert res.status_code == 400


def test_scan_rejects_when_no_partition_exists(client, tmp_path, monkeypatch):
    # A real /dev/sdX won't exist on this test machine either way, but the
    # route's own os.path.exists() check on the *partition* path is what
    # we're proving fires correctly and returns a clear error rather than
    # trying to mount a nonexistent device.
    res = client.post("/api/live_collection/scan", json={"device": "/dev/sdz"})
    assert res.status_code == 400
    assert "Has a Live Collection USB been built" in res.get_json()["error"]


def test_scan_returns_discovered_runs_on_success(client, monkeypatch):
    real_exists = os.path.exists
    monkeypatch.setattr(acq.os.path, "exists", lambda p: True if p == "/dev/sdz1" else real_exists(p))
    monkeypatch.setattr(acq, "mount_collection_partition", lambda *a, **k: {"success": True, "error": None})
    monkeypatch.setattr(acq, "unmount_collection_partition", lambda *a, **k: None)
    monkeypatch.setattr(acq, "discover_collection_runs", lambda mount_path: [
        {"platform": "unix", "run_name": "uac-host-linux-20260901T120000Z", "relative_path": "uac/output/uac-host-linux-20260901T120000Z",
         "hostname": "host", "timestamp": "20260901T120000Z", "file_count": 5, "total_bytes": 12345},
    ])
    res = client.post("/api/live_collection/scan", json={"device": "/dev/sdz"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["runs"]) == 1
    assert data["runs"][0]["hostname"] == "host"


def test_start_import_rejects_missing_selected_runs(client, no_op_thread):
    res = client.post("/api/live_collection/start_import", json={"device": "/dev/sdb", "destination": "/mnt"})
    assert res.status_code == 400
    assert "Select at least one" in res.get_json()["error"]


def test_start_import_rejects_invalid_hash_algorithm(client, no_op_thread, evidence_root):
    res = client.post("/api/live_collection/start_import", json={
        "device": "/dev/sdb",
        "selected_relative_paths": ["uac/output/uac-host-linux-20260901T120000Z"],
        "destination": evidence_root,
        "hashes": ["md5", "not_a_real_algo"],
    })
    assert res.status_code == 400
    assert "Unsupported hash algorithm" in res.get_json()["error"]


def test_start_import_accepts_a_valid_request_and_claims_the_job_slot(client, no_op_thread, evidence_root, monkeypatch):
    monkeypatch.setattr(acq, "build_report_target", lambda *a, **k: "/tmp/fake_report.json")
    monkeypatch.setattr(acq, "write_initial_report", lambda *a, **k: None)
    res = client.post("/api/live_collection/start_import", json={
        "device": "/dev/sdb",
        "selected_relative_paths": ["uac/output/uac-host-linux-20260901T120000Z"],
        "destination": evidence_root,
        "hashes": ["sha256"],
        "metadata": {"case_number": "2026-TEST-01", "evidence_id": "LIVECOLLECT-01"},
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    assert jobs.current_job["active"] is True
