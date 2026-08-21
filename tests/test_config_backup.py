"""End-to-end tests for /api/settings/config_backup and
/api/settings/config_restore (routes/settings.py), added this session.

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py imports
core.jobs, which imports the POSIX-only stdlib modules pwd/fcntl at module
level - see tests/conftest.py's module docstring. Runs in full on Linux
(the real deployment target, and CI).
"""
import io
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.settings import settings_bp, _BACKUP_MAGIC
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
    return cfg


def _login(client, username):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()


def test_backup_requires_manage_users_permission(client, runtime_config_file, mount_key_file):
    _save_user("limited", "pw", "analyst")  # Analyst: no manage_users by default
    _login(client, "limited")
    res = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"})
    assert res.status_code == 403


def test_backup_rejects_short_passphrase(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/config_backup", json={"passphrase": "short"})
    assert res.status_code == 400


def test_backup_produces_a_recognizable_encrypted_file(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"})
    assert res.status_code == 200
    assert res.data.startswith(_BACKUP_MAGIC)
    # The passphrase and every user account's data must never appear in the
    # clear anywhere in the encrypted output.
    assert b"correcthorsebattery" not in res.data
    assert b"admin_test" not in res.data


def test_backup_and_restore_round_trip(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")

    backup_res = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"})
    assert backup_res.status_code == 200
    backup_bytes = backup_res.data

    # Mutate the live config so restore has something real to prove it undid.
    mutated = config.load_runtime_config()
    mutated["users"].append({"username": "should_not_survive", "password_hash": "x", "group_id": "analyst"})
    config.save_runtime_config(mutated)
    assert any(u["username"] == "should_not_survive" for u in config.load_runtime_config()["users"])

    restore_res = client.post(
        "/api/settings/config_restore",
        data={"passphrase": "correcthorsebattery", "backup_file": (io.BytesIO(backup_bytes), "backup.pfback")},
        content_type="multipart/form-data",
    )
    assert restore_res.status_code == 200
    assert restore_res.get_json()["success"] is True

    restored = config.load_runtime_config()
    assert not any(u["username"] == "should_not_survive" for u in restored["users"])
    assert any(u["username"] == "admin_test" for u in restored["users"])

    # The pre-restore state was preserved, not silently discarded.
    assert os.path.exists(str(runtime_config_file) + ".pre_restore_backup")


def test_restore_requires_manage_users_permission(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    backup_bytes = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"}).data

    _save_user("limited", "pw", "analyst")
    _login(client, "limited")
    res = client.post(
        "/api/settings/config_restore",
        data={"passphrase": "correcthorsebattery", "backup_file": (io.BytesIO(backup_bytes), "backup.pfback")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 403


def test_restore_rejects_wrong_passphrase(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    backup_bytes = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"}).data

    res = client.post(
        "/api/settings/config_restore",
        data={"passphrase": "totally-the-wrong-passphrase", "backup_file": (io.BytesIO(backup_bytes), "backup.pfback")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert "Wrong passphrase" in res.get_json()["error"]
    # A failed restore must never touch the live config.
    assert any(u["username"] == "admin_test" for u in config.load_runtime_config()["users"])


def test_restore_rejects_a_file_that_is_not_a_backup(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post(
        "/api/settings/config_restore",
        data={"passphrase": "whatever-123", "backup_file": (io.BytesIO(b"not a real backup file at all"), "junk.pfback")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


def test_backup_and_restore_round_trip_a_report_logo_stays_inside_the_test_install_dir(client, runtime_config_file, mount_key_file, tmp_path):
    # Regression test for a real bug this test suite caught live on its
    # first run against the deployed Pi: config_backup()/config_restore()
    # originally read INSTALL_DIR as a bare imported name (stale, pointing
    # at the real /opt/pi-forensics regardless of what this test's `app`
    # fixture patches core.config.INSTALL_DIR to) - which meant this exact
    # test silently read AND overwrote the real production report_logo.png
    # instead of ever touching tmp_path. Fixed to read config.INSTALL_DIR
    # instead - this test would fail again if that regressed, by finding
    # nothing written under tmp_path even though the route reported success.
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")

    logo_path = tmp_path / "report_logo.png"
    logo_bytes = b"\x89PNG\r\n\x1a\nnot a real png but distinguishable bytes"
    logo_path.write_bytes(logo_bytes)

    backup_bytes = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"}).data

    logo_path.unlink()  # so restore has to actually recreate it, not just leave it alone
    assert not logo_path.exists()

    restore_res = client.post(
        "/api/settings/config_restore",
        data={"passphrase": "correcthorsebattery", "backup_file": (io.BytesIO(backup_bytes), "backup.pfback")},
        content_type="multipart/form-data",
    )
    assert restore_res.status_code == 200
    assert logo_path.exists()
    assert logo_path.read_bytes() == logo_bytes


def test_restore_carries_the_mount_key_forward_so_saved_shares_still_decrypt(client, runtime_config_file, mount_key_file, tmp_path, monkeypatch):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")

    secret = config._encrypt_secret("a-share-password")
    cfg = config.load_runtime_config()
    cfg["auto_mount_shares"] = [{"id": "share1", "password_enc": secret}]
    config.save_runtime_config(cfg)

    backup_bytes = client.post("/api/settings/config_backup", json={"passphrase": "correcthorsebattery"}).data

    # Simulate a fresh station: a different (missing) mount key, which
    # would otherwise leave the saved share password permanently
    # undecryptable garbage post-restore.
    monkeypatch.setattr(config, "MOUNT_KEY_FILE", str(tmp_path / "fresh_mount_key"))

    client.post(
        "/api/settings/config_restore",
        data={"passphrase": "correcthorsebattery", "backup_file": (io.BytesIO(backup_bytes), "backup.pfback")},
        content_type="multipart/form-data",
    )

    restored_secret = config.load_runtime_config()["auto_mount_shares"][0]["password_enc"]
    assert config._decrypt_secret(restored_secret) == "a-share-password"
