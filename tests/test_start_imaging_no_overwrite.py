"""/api/start_imaging must never overwrite an earlier acquisition (2026-09-23).

The output name is {case}_{evidence} with no timestamp, and dc3dd/dcfldd/dd
truncate an existing of= - so re-imaging with the same Case #/Evidence ID
into the same folder used to silently destroy the previous image, its log
and its hashes. The route now refuses (409) before claiming any work, and
leaves the job slot free.

Skipped (not failed) on a non-POSIX dev machine: routes.acquisition needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.acquisition as acquisition
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(acquisition.acquisition_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _fake_run(argv, *a, **kw):
    # blockdev --getsize64 -> a size; smartctl -j -> a JSON object.
    out = "{}" if any("smartctl" in str(x) for x in argv) else "1000000"
    return mock.Mock(returncode=0, stdout=out, stderr="")


@pytest.mark.parametrize("fmt,existing_name", [
    ("dd", "2026-CASE_ITEM-01.dd"),
    ("dcfldd", "2026-CASE_ITEM-01_sha256.log"),
    ("plain_dd", "2026-CASE_ITEM-01.dd"),
    ("e01", "2026-CASE_ITEM-01.E01"),
])
def test_an_existing_acquisition_is_never_overwritten(client, evidence_root, fmt, existing_name):
    dest = os.path.join(evidence_root, "dest")
    os.makedirs(dest)
    earlier = os.path.join(dest, existing_name)
    with open(earlier, "wb") as f:
        f.write(b"the earlier image")
    jobs.update_job(active=False)
    with mock.patch.object(acquisition, "_resolve_acquisition_source", return_value=("/dev/sdz", "real_device", None)), \
         mock.patch.object(acquisition, "is_valid_block_device", return_value=True), \
         mock.patch.object(acquisition, "destination_is_on_source_device", return_value=False), \
         mock.patch.object(acquisition.os.path, "exists", side_effect=lambda p: p == "/dev/sdz" or os.path.lexists(p)), \
         mock.patch.object(acquisition.subprocess, "run") as run, \
         mock.patch.object(acquisition.threading, "Thread") as thread:
        run.side_effect = _fake_run
        res = client.post("/api/start_imaging", json={
            "source": "/dev/sdz", "destination": dest, "format": fmt, "hashes": ["sha256"],
            "metadata": {"case_number": "2026-CASE", "evidence_id": "ITEM-01", "examiner": "x"},
        })
    assert res.status_code == 409, res.get_json()
    assert "already exists" in res.get_json()["error"]
    thread.assert_not_called()
    assert jobs.snapshot_job()["active"] is False
    with open(earlier, "rb") as f:
        assert f.read() == b"the earlier image"


def test_a_different_evidence_id_sharing_a_prefix_is_not_a_collision(client, evidence_root):
    dest = os.path.join(evidence_root, "dest2")
    os.makedirs(dest)
    # ITEM-01_x's own log must not block ITEM-01
    open(os.path.join(dest, "2026-CASE_ITEM-01_x_dc3dd.log"), "w").close()
    jobs.update_job(active=False)
    with mock.patch.object(acquisition, "_resolve_acquisition_source", return_value=("/dev/sdz", "real_device", None)), \
         mock.patch.object(acquisition, "is_valid_block_device", return_value=True), \
         mock.patch.object(acquisition, "destination_is_on_source_device", return_value=False), \
         mock.patch.object(acquisition.os.path, "exists", side_effect=lambda p: p == "/dev/sdz" or os.path.lexists(p)), \
         mock.patch.object(acquisition.subprocess, "run") as run, \
         mock.patch.object(acquisition.threading, "Thread"):
        run.side_effect = _fake_run
        res = client.post("/api/start_imaging", json={
            "source": "/dev/sdz", "destination": dest, "format": "dd", "hashes": ["sha256"],
            "metadata": {"case_number": "2026-CASE", "evidence_id": "ITEM-01", "examiner": "x"},
        })
    assert res.status_code == 200, res.get_json()
    jobs.update_job(active=False)
