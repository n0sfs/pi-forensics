"""stop_imaging() (routes/acquisition.py) had no @requires_permission check
at all beyond login - found in an Acquisition-tab review pass. Every
/api/start_* route in this file requires 'acquisition', but the single
shared job it stops can be started from Recovery, Mobile, File Explorer, or
Reporting too (all call update_job() somewhere), so the gate is an OR across
every job-starting tab's own permission, not just 'acquisition' alone -
matching this codebase's existing OR-gate precedent for genuinely
cross-cutting routes (see test_file_explorer_permissions.py).

get_progress() was deliberately left ungated in the same pass - it's polled
globally every 1s regardless of active tab, so gating it would 403-spam any
account without one of these permissions (e.g. a settings-only/
manage_users-only admin-lite group).

Skipped (not failed) on a non-POSIX dev machine: routes/acquisition.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.acquisition import acquisition_bp
from tests.conftest import RemoteTestClient


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(acquisition_bp)
    return flask_app


@pytest.fixture
def client(app):
    return RemoteTestClient(app.test_client())


def _save_group(group_id, **perms):
    cfg = config.load_runtime_config()
    base = {
        "acquisition": False, "mobile": False, "recovery": False,
        "file_explorer": False, "reporting": False,
        "settings": False, "manage_users": False,
    }
    base.update(perms)
    cfg.setdefault("user_groups", []).append({"id": group_id, "name": group_id, "permissions": base})
    config.save_runtime_config(cfg)


def _save_user(username, password, group_id):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": group_id,
    })
    config.save_runtime_config(cfg)


def _login(client, username):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()


def test_stop_imaging_rejects_a_user_with_none_of_the_job_permissions(client, runtime_config_file):
    _save_group("settings_only", settings=True, manage_users=True)
    _save_user("settings_admin", "pw", "settings_only")
    _login(client, "settings_admin")
    res = client.post("/api/stop_imaging")
    assert res.status_code == 403


def test_stop_imaging_allows_acquisition_permission(client, runtime_config_file):
    _save_group("acq_only", acquisition=True)
    _save_user("acq_user", "pw", "acq_only")
    _login(client, "acq_user")
    res = client.post("/api/stop_imaging")
    # Permission gate passed - falls through to the "no active job" case
    # rather than a 403, since no job is running in this test.
    assert res.status_code != 403


def test_stop_imaging_allows_recovery_permission_alone(client, runtime_config_file):
    # The real-world case this OR-gate protects: a Recovery-only examiner
    # (no 'acquisition') still needs to be able to stop their own PhotoRec/
    # extundelete/foremost/scalpel job, since it's the same shared job slot.
    _save_group("recovery_only", recovery=True)
    _save_user("recovery_user", "pw", "recovery_only")
    _login(client, "recovery_user")
    res = client.post("/api/stop_imaging")
    assert res.status_code != 403


def test_stop_imaging_allows_mobile_permission_alone(client, runtime_config_file):
    _save_group("mobile_only", mobile=True)
    _save_user("mobile_user", "pw", "mobile_only")
    _login(client, "mobile_user")
    res = client.post("/api/stop_imaging")
    assert res.status_code != 403


def test_stop_imaging_allows_file_explorer_permission_alone(client, runtime_config_file):
    _save_group("fe_only", file_explorer=True)
    _save_user("fe_user", "pw", "fe_only")
    _login(client, "fe_user")
    res = client.post("/api/stop_imaging")
    assert res.status_code != 403


def test_stop_imaging_allows_reporting_permission_alone(client, runtime_config_file):
    _save_group("reporting_only", reporting=True)
    _save_user("reporting_user", "pw", "reporting_only")
    _login(client, "reporting_user")
    res = client.post("/api/stop_imaging")
    assert res.status_code != 403
