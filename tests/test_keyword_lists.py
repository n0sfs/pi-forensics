"""/api/settings/keyword_lists (GET/POST) and /api/settings/keyword_lists/<id>
(PUT/DELETE) - routes/settings.py, added this session. Examiner-defined,
station-wide keyword/regex lists selectable at Triage Scan time, additive to
the 5 built-in structured-data categories (see
tests/test_case_index_db.py's build_scan_patterns()/resolve_scan_category_
label() tests for the scanning side of this feature).

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level - see
tests/conftest.py's module docstring.
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


def test_get_is_readable_with_no_settings_permission(client, runtime_config_file, mount_key_file):
    # Every Triage Scan launcher (File Recovery, Quick Triage Scan, the
    # whole-image job) needs to read the list regardless of whether that
    # account has 'settings' - matches report_templates_custom()'s own GET
    # precedent.
    _save_user("limited", "pw", "analyst")
    _login(client, "limited")
    res = client.get("/api/settings/keyword_lists")
    assert res.status_code == 200
    assert res.get_json()["success"] is True


def test_create_requires_settings_permission(client, runtime_config_file, mount_key_file):
    _save_user("limited", "pw", "analyst")  # Analyst: no settings permission by default
    _login(client, "limited")
    res = client.post("/api/settings/keyword_lists", json={"name": "Test", "terms": ["foo"]})
    assert res.status_code == 403


def test_create_rejects_empty_name(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/keyword_lists", json={"name": "", "terms": ["foo"]})
    assert res.status_code == 400


def test_create_rejects_no_terms(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/keyword_lists", json={"name": "Empty List", "terms": []})
    assert res.status_code == 400


def test_create_rejects_invalid_regex(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "Bad Regex", "terms": ["foo(bar"], "is_regex": True,
    })
    assert res.status_code == 400
    assert "not a valid regular expression" in res.get_json()["error"]


def test_create_accepts_a_valid_regex_list(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "IOC Domains", "terms": [r"evil\.example\.(com|net)"], "is_regex": True,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["list"]["is_regex"] is True
    assert data["list"]["id"]  # slugified, non-empty


def test_create_strips_blank_terms(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "Names", "terms": ["  john smith  ", "", "   ", "jane doe"],
    })
    data = res.get_json()
    assert data["list"]["terms"] == ["john smith", "jane doe"]


def test_full_crud_round_trip(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")

    created = client.post("/api/settings/keyword_lists", json={
        "name": "Suspects", "terms": ["alice", "bob"],
    }).get_json()["list"]
    list_id = created["id"]

    got = client.get("/api/settings/keyword_lists").get_json()["lists"]
    assert any(l["id"] == list_id and l["name"] == "Suspects" for l in got)

    updated = client.put(f"/api/settings/keyword_lists/{list_id}", json={
        "name": "Suspects (renamed)", "terms": ["alice", "bob", "carol"],
    }).get_json()["list"]
    assert updated["id"] == list_id  # id never changes across a rename
    assert updated["name"] == "Suspects (renamed)"
    assert updated["terms"] == ["alice", "bob", "carol"]
    assert updated["created_at"] == created["created_at"]  # preserved across an update

    deleted = client.delete(f"/api/settings/keyword_lists/{list_id}")
    assert deleted.status_code == 200
    remaining = client.get("/api/settings/keyword_lists").get_json()["lists"]
    assert not any(l["id"] == list_id for l in remaining)


def test_update_and_delete_require_settings_permission(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    list_id = client.post("/api/settings/keyword_lists", json={
        "name": "Protected", "terms": ["x"],
    }).get_json()["list"]["id"]

    _save_user("limited", "pw", "analyst")
    _login(client, "limited")
    assert client.put(f"/api/settings/keyword_lists/{list_id}", json={"name": "Hijacked", "terms": ["y"]}).status_code == 403
    assert client.delete(f"/api/settings/keyword_lists/{list_id}").status_code == 403


def test_update_unknown_id_is_404(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    res = client.put("/api/settings/keyword_lists/does_not_exist", json={"name": "X", "terms": ["y"]})
    assert res.status_code == 404


def test_name_collision_soft_dedupes_with_a_numeric_suffix(client, runtime_config_file, mount_key_file):
    _save_user("admin_test", "pw", "admin")
    _login(client, "admin_test")
    first = client.post("/api/settings/keyword_lists", json={"name": "Names", "terms": ["a"]}).get_json()["list"]
    second = client.post("/api/settings/keyword_lists", json={"name": "Names", "terms": ["b"]}).get_json()["list"]
    assert first["id"] != second["id"]
