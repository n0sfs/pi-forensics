"""The write blocker reports only what the kernel says, and Start refuses a
source drive that is not confirmed read-only (Maintainer decision 2026-11-20,
10-09 item 3A). Before: the badge fell back to /dev/sda with no drive
selected and read "On" whenever the check failed or the drive was gone, and
acquisition/recovery started from a writable source without a word."""
import os
import subprocess
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import core.write_block as write_block
import routes.acquisition as acquisition
import routes.recovery as recovery
import routes.settings as settings_routes
from tests.conftest import RemoteTestClient, login_user_session

REAL_READ_STATE = write_block.read_write_block_state   # captured before conftest's autouse patch


def _run_returning(code, out):
    return mock.Mock(return_value=mock.Mock(returncode=code, stdout=out, stderr=""))


@pytest.mark.parametrize("code,out,expected", [
    (0, "1\n", True), (0, "0\n", False), (1, "", None), (0, "garbage", None),
])
def test_state_is_only_what_the_kernel_said(monkeypatch, code, out, expected):
    monkeypatch.setattr(write_block.os.path, "exists", lambda p: True)
    monkeypatch.setattr(write_block.subprocess, "run", _run_returning(code, out))
    assert REAL_READ_STATE("/dev/sdz") is expected


def test_a_hung_check_is_unknown_not_protected(monkeypatch):
    monkeypatch.setattr(write_block.os.path, "exists", lambda p: True)
    monkeypatch.setattr(write_block.subprocess, "run", mock.Mock(side_effect=subprocess.TimeoutExpired("blockdev", 5)))
    assert REAL_READ_STATE("/dev/sdz") is None


def test_missing_or_bad_device_is_unknown(monkeypatch):
    monkeypatch.setattr(write_block.os.path, "exists", lambda p: False)
    assert REAL_READ_STATE("/dev/sdz") is None
    assert REAL_READ_STATE("/etc/shadow") is None
    assert REAL_READ_STATE("") is None


def test_problem_text(monkeypatch):
    monkeypatch.setattr(write_block, "read_write_block_state", lambda d: False)
    assert "OFF on /dev/sdz" in write_block.source_write_block_problem("/dev/sdz")
    monkeypatch.setattr(write_block, "read_write_block_state", lambda d: None)
    assert "Could not confirm" in write_block.source_write_block_problem("/dev/sdz")
    monkeypatch.setattr(write_block, "read_write_block_state", lambda d: True)
    assert write_block.source_write_block_problem("/dev/sdz") is None
    # image files are not block devices - never refused on this ground
    assert write_block.source_write_block_problem("/mnt/case/disk.dd") is None


def _client(*blueprints):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"))
    app.secret_key = "test-only"
    for bp in blueprints:
        app.register_blueprint(bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


@pytest.mark.parametrize("state,needle", [(False, "OFF on /dev/sdz"), (None, "Could not confirm")])
def test_start_imaging_refuses_an_unprotected_source(runtime_config_file, evidence_root, monkeypatch, state, needle):
    monkeypatch.setattr(write_block, "read_write_block_state", lambda d: state)
    c = _client(acquisition.acquisition_bp)
    dest = os.path.join(evidence_root, "dest")
    os.makedirs(dest)
    jobs.update_job(active=False)
    with mock.patch.object(acquisition, "_resolve_acquisition_source", return_value=("/dev/sdz", "real_device", None)), \
         mock.patch.object(acquisition, "is_valid_block_device", return_value=True), \
         mock.patch.object(acquisition, "destination_is_on_source_device", return_value=False), \
         mock.patch.object(acquisition.os.path, "exists", side_effect=lambda p: p == "/dev/sdz" or os.path.lexists(p)), \
         mock.patch.object(acquisition.threading, "Thread") as thread:
        res = c.post("/api/start_imaging", json={
            "source": "/dev/sdz", "destination": dest, "format": "dd", "hashes": ["sha256"],
            "metadata": {"case_number": "2026-CASE", "evidence_id": "ITEM-01", "examiner": "x"}})
    assert res.status_code == 409
    body = res.get_json()
    assert needle in body["error"] and body["write_blocker_off"] is True
    thread.assert_not_called()
    assert jobs.snapshot_job()["active"] is False


def test_recovery_refuses_an_unprotected_source_drive(runtime_config_file, evidence_root, monkeypatch):
    monkeypatch.setattr(write_block, "read_write_block_state", lambda d: False)
    monkeypatch.setattr(recovery, "destination_is_on_source_device", lambda d, s: False)
    dest = os.path.join(evidence_root, "case")
    os.makedirs(dest)
    assert "OFF on /dev/sdz" in recovery._recovery_destination_problem(dest, "/dev/sdz")
    # an image file source is fine
    assert recovery._recovery_destination_problem(dest, os.path.join(dest, "disk.dd")) is None


@pytest.mark.parametrize("query,exists,state,expected_active,expected_state", [
    ("", True, True, None, "no_drive"),           # nothing selected: no /dev/sda fallback
    ("?drive=/dev/sdz", False, True, None, "missing"),
    ("?drive=/dev/sdz", True, None, None, "unknown"),
    ("?drive=/dev/sdz", True, False, False, "off"),
    ("?drive=/dev/sdz", True, True, True, "on"),
])
def test_system_info_reports_real_state(runtime_config_file, monkeypatch, query, exists, state, expected_active, expected_state):
    monkeypatch.setattr(settings_routes, "read_write_block_state", lambda d: state)
    real_exists = os.path.exists
    monkeypatch.setattr(settings_routes.os.path, "exists", lambda p: exists if p == "/dev/sdz" else real_exists(p))
    c = _client(settings_routes.settings_bp)
    body = c.get(f"/api/system_info{query}").get_json()
    assert body["write_blocker_active"] is expected_active
    assert body["write_blocker_state"] == expected_state
