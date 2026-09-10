"""routes/reporting.py's GET /api/report/examiner_names - the route backing
the Examiners picker on Report Narrative.

Real gap found and fixed 2026-09-10: an examiner name used to be a plain
free-text field with zero validation against this station's own registered
user accounts - anyone could type an arbitrary string and it would be
recorded as if it were a real, accountable examiner-of-record. This route
returns the actual username list so the frontend can render a select-only
add control instead, restricted to real accounts.

Through a real Flask test client, matching tests/test_set_file_caption_
route.py's own pattern (a minimal app registering just reporting_bp).
Skipped (not failed) on a non-POSIX dev machine: core.jobs needs
POSIX-only pwd/fcntl.
"""
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(reporting_bp)
    return flask_app


def _save_group(group_id, reporting):
    cfg = config.load_runtime_config()
    cfg.setdefault("user_groups", []).append({
        "id": group_id, "name": group_id,
        "permissions": {
            "acquisition": False, "mobile": False, "recovery": False,
            "file_explorer": False, "reporting": reporting,
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


def test_returns_every_registered_username_sorted(app, runtime_config_file):
    _save_group("examiner_group", reporting=True)
    _save_user("zoe", "pw", "examiner_group")
    _save_user("amir", "pw", "examiner_group")
    _save_user("morgan", "pw", "examiner_group")
    client = RemoteTestClient(app.test_client())
    login_user_session(client._raw, "amir")

    res = client.get("/api/report/examiner_names")
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["usernames"] == ["amir", "morgan", "zoe"]


def test_returns_an_empty_list_when_this_station_has_no_registered_users(app, runtime_config_file):
    # A station still running on the legacy single-shared-login env-var
    # fallback (check_auth()'s own two-tier design) has no "users" entries
    # at all. The frontend's own no-registered-accounts fallback depends on
    # this coming back as a real empty list, not an error. Reached via the
    # raw (un-wrapped) test client - its default REMOTE_ADDR (127.0.0.1) is
    # genuine loopback, so requires_auth()'s own kiosk bypass authenticates
    # this request without needing any "users" entry to log in as (the
    # bypass sets g.forensic_user='local-kiosk' directly) - a real, needed
    # way to exercise the empty-users case, since login_user_session()
    # would otherwise need a real registered user to seed a valid session
    # for in the first place, which would make "users" non-empty by
    # construction.
    cfg = config.load_runtime_config()
    cfg["users"] = []
    config.save_runtime_config(cfg)
    client = app.test_client()

    res = client.get("/api/report/examiner_names")
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["usernames"] == []


def test_rejects_a_user_without_reporting_permission(app, runtime_config_file):
    _save_group("no_access", reporting=False)
    _save_user("limited", "pw", "no_access")
    client = RemoteTestClient(app.test_client())
    login_user_session(client._raw, "limited")

    res = client.get("/api/report/examiner_names")
    assert res.status_code == 403
