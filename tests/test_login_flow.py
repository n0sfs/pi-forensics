"""End-to-end tests for routes/auth_routes.py's /login, /logout, and
/api/whoami through a real Flask test client - including the idle-session
timeout added this session (core/auth.py's SESSION_IDLE_TIMEOUT_SECONDS).

Deliberately builds its own minimal Flask app registering only
auth_routes_bp, not the full app.py - routes/auth_routes.py only imports
core.auth (no core.jobs, so no POSIX-only pwd/fcntl requirement), which is
exactly why this file runs on a non-POSIX dev machine too, unlike most other
routes/*.py test coverage in this suite.
"""
import os
import time

import pytest
from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.auth as auth
from routes.auth_routes import auth_routes_bp
from tests.conftest import RemoteTestClient

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(auth_routes_bp)
    return flask_app


@pytest.fixture
def client(app):
    return RemoteTestClient(app.test_client())


def _save_user(username, password, group_id="analyst"):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": group_id,
    })
    config.save_runtime_config(cfg)


def test_whoami_requires_a_session(client, runtime_config_file):
    res = client.get("/api/whoami")
    assert res.status_code == 401


def test_login_success_sets_a_working_session(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    res = client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    who = client.get("/api/whoami")
    assert who.status_code == 200
    assert who.get_json()["username"] == "carol"


def test_login_wrong_password_rejected_and_no_session_created(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    res = client.post("/login", json={"username": "carol", "password": "wrong"})
    assert res.status_code == 401
    assert res.get_json()["success"] is False
    assert client.get("/api/whoami").status_code == 401


def test_login_unknown_user_rejected_same_as_wrong_password(client, runtime_config_file):
    # No username-enumeration signal - both cases return the identical
    # generic error/status (see check_auth()'s dummy-hash comparison).
    res = client.post("/login", json={"username": "nobody-here", "password": "whatever"})
    assert res.status_code == 401
    assert "Incorrect username or password" in res.get_json()["error"]


def test_logout_clears_the_session(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})
    assert client.get("/api/whoami").status_code == 200

    res = client.post("/logout")
    assert res.get_json()["success"] is True
    assert client.get("/api/whoami").status_code == 401


def test_repeated_wrong_passwords_trigger_lockout(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    for _ in range(auth.MAX_AUTH_FAILURES):
        res = client.post("/login", json={"username": "carol", "password": "wrong"})
        assert res.status_code in (401, 429)
    locked = client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})
    assert locked.status_code == 429


def test_idle_session_forces_relogin(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})
    assert client.get("/api/whoami").status_code == 200

    # Simulate the session having gone quiet well past the idle window,
    # without sleeping in the test - directly backdate last_activity.
    with client.session_transaction() as sess:
        sess["last_activity"] = time.time() - auth.SESSION_IDLE_TIMEOUT_SECONDS - 1

    assert client.get("/api/whoami").status_code == 401


def test_active_session_does_not_idle_out(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})

    with client.session_transaction() as sess:
        sess["last_activity"] = time.time() - 5  # well inside the window
    assert client.get("/api/whoami").status_code == 200


def test_a_request_refreshes_the_idle_window(client, runtime_config_file):
    # Every authenticated request pushes the idle deadline back out - a
    # session that was one second from expiring, but just made a real
    # request, should not expire on its very next request either.
    _save_user("carol", "correcthorsebattery")
    client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})

    with client.session_transaction() as sess:
        sess["last_activity"] = time.time() - auth.SESSION_IDLE_TIMEOUT_SECONDS + 1
    assert client.get("/api/whoami").status_code == 200  # refreshes last_activity
    assert client.get("/api/whoami").status_code == 200  # would have expired without the refresh above


def test_deleted_user_loses_access_on_next_request_even_with_a_live_session(client, runtime_config_file):
    _save_user("carol", "correcthorsebattery")
    client.post("/login", json={"username": "carol", "password": "correcthorsebattery"})
    assert client.get("/api/whoami").status_code == 200

    config.save_runtime_config({"users": []})
    assert client.get("/api/whoami").status_code == 401
