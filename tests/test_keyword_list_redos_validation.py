"""routes/settings.py's _keyword_list_from_payload() - save-time rejection
of a catastrophic-backtracking regex keyword-list pattern, the primary
defense from the 2026-08-22 security audit's ReDoS finding (see
tests/test_redos_defense.py for the underlying mechanism, which runs on any
dev machine since it only needs core.case_index_db).

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


def _save_user(username, password, group_id="admin"):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": group_id,
    })
    config.save_runtime_config(cfg)


def _login(client, username):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()


def test_creating_a_catastrophic_regex_keyword_list_is_rejected(client, runtime_config_file, mount_key_file):
    _save_user("admin_user", "pw")
    _login(client, "admin_user")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "Evil List", "terms": [r"(a+)+$"], "is_regex": True,
    })
    assert res.status_code == 400
    body = res.get_json()
    assert body["success"] is False
    assert "backtracking" in body["error"].lower() or "slow" in body["error"].lower()

    # And it must never have been persisted.
    cfg = config.load_runtime_config()
    assert cfg.get("keyword_lists", []) == []


def test_creating_a_safe_regex_keyword_list_succeeds(client, runtime_config_file, mount_key_file):
    _save_user("admin_user2", "pw")
    _login(client, "admin_user2")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "Safe List", "terms": [r"foo\d+bar"], "is_regex": True,
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True


def test_editing_an_existing_list_into_a_catastrophic_pattern_is_also_rejected(client, runtime_config_file, mount_key_file):
    _save_user("admin_user3", "pw")
    _login(client, "admin_user3")
    created = client.post("/api/settings/keyword_lists", json={
        "name": "Starts Safe", "terms": [r"abc"], "is_regex": True,
    }).get_json()["list"]

    res = client.put(f"/api/settings/keyword_lists/{created['id']}", json={
        "name": "Starts Safe", "terms": [r"(a|a)*$"], "is_regex": True,
    })
    assert res.status_code == 400

    # The original safe version must survive the rejected edit untouched.
    cfg = config.load_runtime_config()
    stored = next(r for r in cfg["keyword_lists"] if r["id"] == created["id"])
    assert stored["terms"] == [r"abc"]


def test_a_plain_non_regex_list_is_never_redos_checked(client, runtime_config_file, mount_key_file):
    # is_regex=False terms are always re.escape()'d - no backtracking risk
    # regardless of content, so a term that merely LOOKS dangerous as text
    # must be accepted without even attempting the check.
    _save_user("admin_user4", "pw")
    _login(client, "admin_user4")
    res = client.post("/api/settings/keyword_lists", json={
        "name": "Literal", "terms": [r"(a+)+$"], "is_regex": False,
    })
    assert res.status_code == 200
