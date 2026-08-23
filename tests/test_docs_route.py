"""End-to-end tests for routes/auth_routes.py's GET /docs/<doc_id> - serves
the shipped Quick-Start Guide, User Manual, and CHANGELOG as plain text to
any logged-in account, from a link in the Help modal and Settings >
Diagnostics.

Deliberately reuses test_login_flow.py's exact fixture pattern (a minimal
Flask app registering only auth_routes_bp, no core.jobs dependency) so this
runs on a non-POSIX dev machine too, not just Linux/the deployed Pi.
"""
import os

import pytest
from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
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


def _login(client, runtime_config_file, username="carol", password="correcthorsebattery"):
    _save_user(username, password)
    res = client.post("/login", json={"username": username, "password": password})
    assert res.status_code == 200


def test_docs_route_requires_a_session(client, runtime_config_file):
    # /docs/<id> is a page-like route (not under /api/), so requires_auth
    # redirects to /login rather than returning a plain 401 - same behavior
    # as / (index()) itself.
    res = client.get("/docs/quickstart")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]


def test_logged_in_account_can_read_each_real_doc(client, runtime_config_file):
    _login(client, runtime_config_file)
    for doc_id, expected_start in (
        ("quickstart", "# Quick-Start Guide"),
        ("user-manual", "# Pi Forensics Suite"),
        ("changelog", "# Changelog"),
    ):
        res = client.get(f"/docs/{doc_id}")
        assert res.status_code == 200
        assert res.mimetype == "text/plain"
        # Real bug caught live: passing a mimetype string that already
        # includes "; charset=utf-8" to Response(mimetype=...) makes
        # Werkzeug append its own default charset on top, producing a
        # malformed "charset=utf-8; charset=utf-8" header. Assert the raw
        # header has exactly one charset param, not just that .mimetype
        # (which strips params entirely) looks right.
        assert res.headers["Content-Type"].count("charset") == 1
        assert res.get_data(as_text=True).startswith(expected_start)


def test_unknown_doc_id_is_a_clean_404_not_a_crash(client, runtime_config_file):
    _login(client, runtime_config_file)
    res = client.get("/docs/bogus-id")
    assert res.status_code == 404


def test_path_traversal_attempt_is_a_clean_404_not_a_leaked_file(client, runtime_config_file):
    _login(client, runtime_config_file)
    res = client.get("/docs/..%2f..%2f..%2fetc%2fpasswd")
    assert res.status_code == 404
