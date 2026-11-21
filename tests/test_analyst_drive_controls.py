"""Analysts (acquisition permission, no settings) may write-unlock and detach
a destination drive (Eric's decision 2026-11-20, 10-09 item 4A). Unlock stays
black-port-only inside _unlock_device_for_write(); this only pins who may
reach the routes. A group with neither permission still gets 403."""
import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.acquisition import acquisition_bp
from routes.settings import settings_bp
from tests.conftest import RemoteTestClient, login_user_session


def _client(username, group_id, perms=None):
    cfg = config.load_runtime_config()
    if perms is not None:
        cfg.setdefault("user_groups", []).append({"id": group_id, "name": group_id, "permissions": perms})
    cfg.setdefault("users", []).append({"username": username, "password_hash": generate_password_hash("x"),
                                        "group_id": group_id})
    config.save_runtime_config(cfg)
    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(acquisition_bp)
    app.register_blueprint(settings_bp)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, username)
    return c


ROUTES = [("/api/toggle_write_block", {"enable": False, "drive": "not-a-device"}),
          ("/api/system/eject_drive", {"drive": "not-a-device"})]


def test_analyst_reaches_the_drive_routes(runtime_config_file):
    c = _client("ana", "analyst")
    for url, body in ROUTES:
        res = c.post(url, json=body)
        assert res.status_code == 400, url  # past the permission check, refused on the device name


def test_group_without_acquisition_or_settings_is_refused(runtime_config_file):
    c = _client("vic", "viewer", {"reporting": True})
    for url, body in ROUTES:
        assert c.post(url, json=body).status_code == 403, url


def test_analyst_still_cannot_restart_the_service(runtime_config_file):
    c = _client("ana", "analyst")
    assert c.post("/api/system/restart_service", json={}).status_code == 403
