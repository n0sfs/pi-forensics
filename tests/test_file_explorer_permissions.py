"""preview_text_file() and get_file_hex() (routes/file_explorer.py) - both
were missing a @requires_permission check entirely until the 2026-08-22
security audit found it: every sibling content route (copy/delete/
verify_hash/exif/binwalk/hex's own neighbors) checks 'file_explorer', but
these two didn't, letting an account whose group has that permission
switched off still read the full text or raw bytes of any evidence file.

preview_text_file() specifically needs an OR-gate ('file_explorer' OR
'reporting'), not just 'file_explorer' alone - it's also called from
Reporting's own Geolocation section and its Files gallery's KML viewer
(static/js/main.js), matching the same two-permission pattern this codebase
already uses for attach_file_to_case()/report_templates_custom_detail() for
the identical "reachable from two tabs" reason. get_file_hex() has no such
call site (File-Explorer-only), so a single permission key is correct there.

Skipped (not failed) on a non-POSIX dev machine: routes/file_explorer.py
needs core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.file_explorer import file_explorer_bp
from tests.conftest import RemoteTestClient


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(file_explorer_bp)
    return flask_app


@pytest.fixture
def client(app):
    return RemoteTestClient(app.test_client())


def _save_group(group_id, file_explorer, reporting):
    cfg = config.load_runtime_config()
    cfg.setdefault("user_groups", []).append({
        "id": group_id, "name": group_id,
        "permissions": {
            "acquisition": False, "mobile": False, "recovery": False,
            "file_explorer": file_explorer, "reporting": reporting,
            "settings": False, "manage_users": False,
        },
    })
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


def _make_test_file(evidence_root):
    import os
    path = os.path.join(evidence_root, "note.txt")
    with open(path, "w") as f:
        f.write("evidence content")
    return path


def test_preview_text_rejects_a_user_with_neither_permission(client, runtime_config_file, evidence_root):
    _save_group("no_access", file_explorer=False, reporting=False)
    _save_user("limited", "pw", "no_access")
    _login(client, "limited")
    path = _make_test_file(evidence_root)
    res = client.post("/api/files/preview_text", json={"path": path})
    assert res.status_code == 403


def test_preview_text_allowed_with_file_explorer_permission_alone(client, runtime_config_file, evidence_root):
    _save_group("fe_only", file_explorer=True, reporting=False)
    _save_user("fe_user", "pw", "fe_only")
    _login(client, "fe_user")
    path = _make_test_file(evidence_root)
    res = client.post("/api/files/preview_text", json={"path": path})
    assert res.status_code == 200
    assert res.get_json()["content"] == "evidence content"


def test_preview_text_allowed_with_reporting_permission_alone(client, runtime_config_file, evidence_root):
    # The real-world case this OR-gate protects: Reporting's Geolocation
    # section and Files-gallery KML viewer both call this route, and an
    # account can legitimately have 'reporting' without 'file_explorer'.
    _save_group("reporting_only", file_explorer=False, reporting=True)
    _save_user("rep_user", "pw", "reporting_only")
    _login(client, "rep_user")
    path = _make_test_file(evidence_root)
    res = client.post("/api/files/preview_text", json={"path": path})
    assert res.status_code == 200


def test_hex_rejects_a_user_with_no_file_explorer_permission(client, runtime_config_file, evidence_root):
    _save_group("no_fe", file_explorer=False, reporting=True)
    _save_user("no_fe_user", "pw", "no_fe")
    _login(client, "no_fe_user")
    path = _make_test_file(evidence_root)
    res = client.post("/api/files/hex", json={"path": path})
    assert res.status_code == 403  # 'reporting' alone must NOT be enough - hex is File-Explorer-only


def test_hex_allowed_with_file_explorer_permission(client, runtime_config_file, evidence_root):
    _save_group("fe_only2", file_explorer=True, reporting=False)
    _save_user("fe_user2", "pw", "fe_only2")
    _login(client, "fe_user2")
    path = _make_test_file(evidence_root)
    res = client.post("/api/files/hex", json={"path": path})
    assert res.status_code == 200
    assert res.get_json()["success"] is True
