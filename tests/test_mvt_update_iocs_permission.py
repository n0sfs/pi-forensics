"""routes/settings.py's mvt_update_iocs() - originally carried no permission
check at all, unlike its sibling install_tool() (both @requires_permission
('settings')). A real finding from the 2026-08-22 security audit: any
authenticated account could trigger a network fetch of spyware-indicator
definitions regardless of group.

Only the REJECTION path is asserted strictly (403, before any subprocess
call). The "settings permission granted" case is exercised too, but only
asserts we got PAST the permission check (never a 403) - whether MVT itself
is installed on the machine running this test is irrelevant and untested
here, matching this project's own mvt integration test scope elsewhere.

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.settings import settings_bp
from tests.conftest import RemoteTestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INSTALL_DIR", str(tmp_path))
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(settings_bp)
    return flask_app


@pytest.fixture
def client(app):
    return RemoteTestClient(app.test_client())


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


def test_rejected_without_settings_permission(client, runtime_config_file, mount_key_file):
    _save_user("limited", "pw", "analyst")  # Analyst: no 'settings' by default
    _login(client, "limited")
    res = client.post("/api/tools/mvt_update_iocs")
    assert res.status_code == 403


def test_allowed_past_the_permission_check_with_settings_permission(client, runtime_config_file, mount_key_file):
    _save_user("admin_user", "pw", "admin")
    _login(client, "admin_user")
    res = client.post("/api/tools/mvt_update_iocs")
    assert res.status_code != 403
