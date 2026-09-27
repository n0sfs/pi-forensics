"""manage_users is not Admin (2026-09-27 review).

A group holding only manage_users could create an Admin-group user, reset an
Admin's password, grant its own group any permission, or restore a crafted
config backup - whose branding-logo name went through basename() only, so
"app.py" overwrote the application. A real account named "local-kiosk" also
inherited the physical kiosk's full Admin access remotely.

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py imports
core.jobs (pwd/fcntl).
"""
import base64
import io
import json
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

from cryptography.fernet import Fernet
from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.settings import settings_bp, _BACKUP_MAGIC, _derive_backup_key
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


def _seed(runtime_config_file):
    cfg = config.load_runtime_config()
    cfg["users"] = [
        {"username": "boss", "password_hash": generate_password_hash("bosspass1"), "group_id": "admin"},
        {"username": "hr", "password_hash": generate_password_hash("hrpass123"), "group_id": "hr"},
    ]
    cfg["user_groups"] = [{"id": "hr", "name": "HR", "permissions": {"manage_users": True}}]
    config.save_runtime_config(cfg)


def _login(client, username):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()


def test_manage_users_cannot_create_an_admin(client, runtime_config_file):
    _seed(runtime_config_file)
    _login(client, "hr")
    res = client.post("/api/users/create", json={"username": "mallory", "password": "longenough1", "group_id": "admin"})
    assert res.status_code == 403
    res = client.post("/api/users/create", json={"username": "newbie", "password": "longenough1", "group_id": "analyst"})
    assert res.status_code == 200


def test_manage_users_cannot_reset_or_delete_an_admin(client, runtime_config_file):
    _seed(runtime_config_file)
    _login(client, "hr")
    assert client.post("/api/users/reset_password", json={"username": "boss", "new_password": "takeover123"}).status_code == 403
    assert client.post("/api/users/delete", json={"username": "boss", "current_password": "hrpass123"}).status_code == 403


def test_manage_users_cannot_grant_what_it_lacks(client, runtime_config_file):
    _seed(runtime_config_file)
    _login(client, "hr")
    res = client.put("/api/user_groups/hr", json={"name": "HR", "permissions": {"manage_users": True, "settings": True}})
    assert res.status_code == 403
    res = client.post("/api/user_groups", json={"name": "Sneaky", "permissions": {"acquisition": True}})
    assert res.status_code == 403


def test_admin_still_can(client, runtime_config_file):
    _seed(runtime_config_file)
    _login(client, "boss")
    res = client.post("/api/users/create", json={"username": "admin2", "password": "longenough1", "group_id": "admin"})
    assert res.status_code == 200


@pytest.mark.parametrize("name", ["local-kiosk", "LOCAL-KIOSK", "system-startup", "has space", "tab\tname"])
def test_reserved_and_malformed_usernames_are_refused(client, runtime_config_file, name):
    _seed(runtime_config_file)
    _login(client, "boss")
    res = client.post("/api/users/create", json={"username": name, "password": "longenough1", "group_id": "analyst"})
    assert res.status_code == 400


def test_first_account_must_be_admin(client, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg["users"] = []
    config.save_runtime_config(cfg)
    # no users = legacy shared-login mode; the caller is treated as admin
    with client.session_transaction() as sess:
        sess["username"] = config.load_runtime_config().get("user", "admin")
        sess["last_activity"] = time.time()
    res = client.post("/api/users/create", json={"username": "first", "password": "longenough1", "group_id": "analyst"})
    assert res.status_code == 400


def _crafted_backup(passphrase, manifest):
    salt = os.urandom(16)
    token = Fernet(_derive_backup_key(passphrase, salt)).encrypt(json.dumps(manifest).encode())
    return _BACKUP_MAGIC + salt + token


@pytest.mark.parametrize("bad", [
    {"report_logo": {"filename": "app.py", "data_b64": base64.b64encode(b"import os").decode()}},
    {"hash_lists_data": {"../../escape": base64.b64encode(b"x").decode()}},
])
def test_restore_rejects_path_carrying_fields_before_writing_anything(client, runtime_config_file, tmp_path, bad):
    _seed(runtime_config_file)
    _login(client, "boss")
    before = config.load_runtime_config()
    manifest = dict({"version": 1, "runtime_config": {"users": []}}, **bad)
    res = client.post("/api/settings/config_restore",
                      data={"passphrase": "correcthorsebattery",
                            "backup_file": (io.BytesIO(_crafted_backup("correcthorsebattery", manifest)), "b.pfback")},
                      content_type="multipart/form-data")
    assert res.status_code == 400
    assert not (tmp_path / "app.py").exists()
    assert config.load_runtime_config()["users"] == before["users"]   # nothing restored


def test_restore_is_admin_only(client, runtime_config_file):
    _seed(runtime_config_file)
    _login(client, "hr")
    manifest = {"version": 1, "runtime_config": {"users": []}}
    res = client.post("/api/settings/config_restore",
                      data={"passphrase": "correcthorsebattery",
                            "backup_file": (io.BytesIO(_crafted_backup("correcthorsebattery", manifest)), "b.pfback")},
                      content_type="multipart/form-data")
    assert res.status_code == 403
