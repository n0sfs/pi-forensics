"""At the touchscreen a real signed-in session wins over the shared
"local-kiosk" identity (Maintainer decision 2026-11-20, 10-09 item 2A). Before,
the kiosk bypass ran first, so Switch User did nothing and every action was
attributed to local-kiosk. Logout, an idle-expired session or a deleted
account fall back to local-kiosk, never to a login wall."""
import time

import pytest
from flask import Flask, g, jsonify
from werkzeug.security import generate_password_hash

import core.auth as auth
import core.config as config
from routes.auth_routes import auth_routes_bp


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(auth_routes_bp)

    @app.route('/api/test/who', methods=['GET'])
    @auth.requires_auth
    def who():
        return jsonify({"user": g.forensic_user, "perms": auth.get_current_user_permissions()})
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).extend([
        {"username": "boss", "password_hash": generate_password_hash("admin-pass-1"), "group_id": "admin"},
        {"username": "ana", "password_hash": generate_password_hash("analyst-pass-1"), "group_id": "analyst"},
    ])
    config.save_runtime_config(cfg)
    auth.auth_fail_tracker.clear()
    return app.test_client()


def _who(c):
    return c.get('/api/test/who').get_json()


def test_no_session_is_the_shared_kiosk_identity(client):
    assert _who(client)["user"] == "local-kiosk"


def test_switch_user_at_the_kiosk_takes_effect(client):
    res = client.post('/login', json={"username": "ana", "password": "analyst-pass-1"},
                      headers={"Origin": "http://localhost"})
    assert res.get_json()["success"] is True
    who = _who(client)
    assert who["user"] == "ana"
    assert who["perms"]["settings"] is False  # the analyst's own permissions, not kiosk Admin


def test_logout_returns_to_the_kiosk_identity(client):
    client.post('/login', json={"username": "ana", "password": "analyst-pass-1"}, headers={"Origin": "http://localhost"})
    client.post('/logout', headers={"Origin": "http://localhost"})
    assert _who(client)["user"] == "local-kiosk"


def test_an_idle_expired_kiosk_session_falls_back_not_locks_out(client):
    client.post('/login', json={"username": "ana", "password": "analyst-pass-1"}, headers={"Origin": "http://localhost"})
    with client.session_transaction() as s:
        s['last_activity'] = time.time() - auth.SESSION_IDLE_TIMEOUT_SECONDS - 5
    res = client.get('/api/test/who')
    assert res.status_code == 200 and res.get_json()["user"] == "local-kiosk"


def test_a_deleted_account_falls_back_to_the_kiosk_identity(client):
    client.post('/login', json={"username": "ana", "password": "analyst-pass-1"}, headers={"Origin": "http://localhost"})
    cfg = config.load_runtime_config()
    cfg["users"] = [u for u in cfg["users"] if u["username"] != "ana"]
    config.save_runtime_config(cfg)
    assert _who(client)["user"] == "local-kiosk"


def test_kiosk_case_needs_a_typed_examiner_name(runtime_config_file, evidence_root):
    pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")
    from routes.case_management import case_management_bp
    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(case_management_bp)
    c = app.test_client()
    for examiner in ("", "local-kiosk", "LOCAL-KIOSK"):
        res = c.post('/api/cases/create', json={"case_number": "2026-K1", "examiner": examiner, "parent_dir": evidence_root})
        assert res.status_code == 400 and "examiner" in res.get_json()["error"], examiner
    res = c.post('/api/cases/create', json={"case_number": "2026-K1", "examiner": "Det. Rivera", "parent_dir": evidence_root})
    assert res.status_code == 200 and res.get_json()["case"]["examiners"] == ["Det. Rivera"]
