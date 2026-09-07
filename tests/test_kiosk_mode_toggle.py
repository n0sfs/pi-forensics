"""GET/POST /api/system/kiosk_mode - routes/settings.py, added this session.

Enables/disables the physical touchscreen's own kiosk-mode Chromium browser
(a real, distinct thing from is_local_kiosk_request()'s AUTH-BYPASS "kiosk"
concept covered by tests/test_kiosk_bypass.py - deliberately a separate test
file/name to avoid any confusion between the two). The write side creates or
removes a plain marker file (install.py's own labwc autostart respawn loop
checks it on every iteration) and, when disabling, kills the currently-
running chromium process directly.

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py needs
core.jobs, which imports POSIX-only pwd/fcntl - see tests/conftest.py's
module docstring.
"""
import os
import time
from unittest import mock

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


def test_get_defaults_to_enabled_when_never_configured(client, runtime_config_file, mount_key_file):
    _save_user("limited", "pw", "analyst")
    _login(client, "limited")
    res = client.get("/api/system/kiosk_mode")
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["enabled"] is True  # a station that's never touched this new toggle must never silently start with kiosk mode off


def test_get_is_readable_with_no_settings_permission(client, runtime_config_file, mount_key_file):
    # Matches this app's own established "read-only settings state is safe
    # to expose to any logged-in account" convention (e.g. keyword_lists'
    # own GET) - only the write below requires 'settings'.
    _save_user("limited", "pw", "analyst")
    _login(client, "limited")
    cfg = config.load_runtime_config()
    cfg["kiosk_mode_enabled"] = False
    config.save_runtime_config(cfg)
    res = client.get("/api/system/kiosk_mode")
    assert res.get_json()["enabled"] is False


def test_post_requires_settings_permission(client, runtime_config_file, mount_key_file):
    _save_user("limited", "pw", "analyst")  # Analyst: no settings permission by default
    _login(client, "limited")
    res = client.post("/api/system/kiosk_mode", json={"enabled": False})
    assert res.status_code == 403


def test_post_disable_creates_marker_inside_the_test_install_dir_not_the_real_one(client, app, tmp_path, runtime_config_file, mount_key_file):
    # The actual regression test for the real bug caught before this ever
    # shipped: a bare module-level `os.path.join(INSTALL_DIR, ...)`
    # computed once at import time would resolve against the REAL,
    # production INSTALL_DIR (whatever it was when routes.settings was
    # first imported), completely unreachable by this fixture's own
    # monkeypatch.setattr(config, "INSTALL_DIR", tmp_path) - the exact
    # same bug class this app has already been bitten by 4 times before
    # (active_proc, RUNTIME_CONFIG_FILE, EVIDENCE_ROOT). Asserting the
    # marker lands INSIDE tmp_path is what actually proves the fix (a
    # function reading config.INSTALL_DIR fresh on every call) works.
    _save_user("admin", "pw", "admin")
    _login(client, "admin")
    with mock.patch("subprocess.run") as mock_run:
        res = client.post("/api/system/kiosk_mode", json={"enabled": False})
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["enabled"] is False
    marker = tmp_path / ".kiosk_disabled"
    assert marker.exists()
    mock_run.assert_called_once()
    assert mock_run.call_args[0][0] == ["pkill", "-9", "-f", "chromium"]


def test_post_enable_removes_an_existing_marker(client, app, tmp_path, runtime_config_file, mount_key_file):
    marker = tmp_path / ".kiosk_disabled"
    marker.write_text("")
    _save_user("admin", "pw", "admin")
    _login(client, "admin")
    with mock.patch("subprocess.run") as mock_run:
        res = client.post("/api/system/kiosk_mode", json={"enabled": True})
    assert res.status_code == 200
    assert res.get_json()["enabled"] is True
    assert not marker.exists()
    mock_run.assert_not_called()  # re-enabling never kills anything - the already-running respawn loop relaunches chromium on its own


def test_post_persists_to_runtime_config_and_a_later_get_reflects_it(client, tmp_path, runtime_config_file, mount_key_file):
    _save_user("admin", "pw", "admin")
    _login(client, "admin")
    with mock.patch("subprocess.run"):
        client.post("/api/system/kiosk_mode", json={"enabled": False})
    cfg = config.load_runtime_config()
    assert cfg["kiosk_mode_enabled"] is False
    res = client.get("/api/system/kiosk_mode")
    assert res.get_json()["enabled"] is False


def test_post_enable_never_creates_a_marker_that_did_not_already_exist(client, app, tmp_path, runtime_config_file, mount_key_file):
    # A plain os.remove() on a nonexistent path would raise - confirms the
    # route's own os.path.exists() guard before removing.
    _save_user("admin", "pw", "admin")
    _login(client, "admin")
    with mock.patch("subprocess.run"):
        res = client.post("/api/system/kiosk_mode", json={"enabled": True})
    assert res.status_code == 200
    assert not os.path.exists(tmp_path / ".kiosk_disabled")
