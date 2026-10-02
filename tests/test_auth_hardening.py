"""core/auth.py hardening from the 2026-10-02 review - runs everywhere (no
POSIX-only imports): a minimal Flask app with the real auth blueprint plus one
dummy state-changing route.

- Cross-site requests: the kiosk is authenticated by source address, not a
  cookie, so any page shown in the kiosk browser could POST as Admin.
- The kiosk bypass also needs a loopback Host (DNS rebinding).
- A password change ends the account's other sessions.
- The failed-login window resets.
- Concurrent config writes are serialised.
"""
import threading
import time

import pytest
from flask import Flask, g, jsonify
from werkzeug.security import generate_password_hash

import core.auth as auth
import core.config as config
from routes.auth_routes import auth_routes_bp
from tests.conftest import RemoteTestClient


@pytest.fixture
def app(runtime_config_file):
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(auth_routes_bp)

    @flask_app.route('/api/test/change', methods=['POST', 'GET'])
    @auth.requires_auth
    def change():
        return jsonify({"success": True, "user": g.forensic_user})
    return flask_app


@pytest.fixture(autouse=True)
def _clear_lockouts():
    auth.auth_fail_tracker.clear()
    yield
    auth.auth_fail_tracker.clear()


def _save_user(username, password, group_id="admin"):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": username, "password_hash": generate_password_hash(password),
                                        "group_id": group_id})
    config.save_runtime_config(cfg)


# --- cross-site requests (the kiosk path: Flask's default 127.0.0.1 / localhost) ---

def test_a_kiosk_post_from_another_site_is_refused(app):
    res = app.test_client().post('/api/test/change', headers={"Origin": "http://evil.example"})
    assert res.status_code == 403


def test_a_kiosk_post_from_its_own_page_is_allowed(app):
    res = app.test_client().post('/api/test/change', headers={"Origin": "http://localhost:5000"})
    assert res.status_code == 200 and res.get_json()["user"] == "local-kiosk"


def test_a_post_with_no_origin_or_referer_is_allowed(app):
    """curl / scripts - and the Basic-auth workflow - send neither."""
    assert app.test_client().post('/api/test/change').status_code == 200


def test_the_opaque_null_origin_is_refused(app):
    """What a sandboxed frame or a no-referrer cross-site form produces."""
    res = app.test_client().post('/api/test/change', headers={"Origin": "null"})
    assert res.status_code == 403


def test_a_cross_site_referer_is_refused_when_origin_is_absent(app):
    res = app.test_client().post('/api/test/change', headers={"Referer": "http://evil.example/page"})
    assert res.status_code == 403


def test_reads_are_not_affected(app):
    res = app.test_client().get('/api/test/change', headers={"Origin": "http://evil.example"})
    assert res.status_code == 200


def test_scheme_and_port_differences_are_not_cross_site(app):
    """nginx terminates TLS and forwards $host without the port."""
    res = app.test_client().post('/api/test/change', headers={"Origin": "https://localhost"})
    assert res.status_code == 200


def test_a_loopback_request_addressed_to_another_name_is_not_the_kiosk(app):
    """DNS rebinding: a site whose name resolves to 127.0.0.1."""
    res = app.test_client().post('/api/test/change', headers={"Host": "evil.example:5000"})
    assert res.status_code == 401


def test_forged_cross_site_logins_cannot_lock_the_examiner_out(app):
    _save_user("carol", "correcthorsebattery")
    client = RemoteTestClient(app.test_client())
    for _ in range(6):
        assert client.post("/login", json={"username": "carol", "password": "x"},
                           headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/login", json={"username": "carol", "password": "correcthorsebattery"}).status_code == 200


# --- sessions end when the password changes -----------------------------------

def test_a_password_reset_ends_existing_sessions(app):
    _save_user("dave", "first-password-1")
    a = RemoteTestClient(app.test_client())
    b = RemoteTestClient(app.test_client())
    for c in (a, b):
        assert c.post("/login", json={"username": "dave", "password": "first-password-1"}).status_code == 200
        assert c.get("/api/whoami").status_code == 200
    cfg = config.load_runtime_config()
    cfg["users"][0]["password_hash"] = generate_password_hash("second-password-2")
    config.save_runtime_config(cfg)
    assert a.get("/api/whoami").status_code == 401
    assert b.get("/api/whoami").status_code == 401


def test_a_session_from_before_the_fingerprint_must_log_in_again(app):
    _save_user("erin", "some-password-1")
    client = RemoteTestClient(app.test_client())
    with client._raw.session_transaction() as sess:
        sess["username"] = "erin"
        sess["last_activity"] = time.time()
    assert client.get("/api/whoami").status_code == 401


# --- the failed-login window -------------------------------------------------------

def test_the_failure_count_starts_over_after_a_lockout_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    for _ in range(auth.MAX_AUTH_FAILURES):
        auth._record_auth_failure("198.51.100.7")
    assert auth._is_locked_out("198.51.100.7")
    now[0] += auth.LOCKOUT_SECONDS + 1
    assert not auth._is_locked_out("198.51.100.7")
    auth._record_auth_failure("198.51.100.7")       # one typo after the lockout...
    assert not auth._is_locked_out("198.51.100.7")  # ...is not another lockout


def test_old_failures_age_out_of_the_window(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    for _ in range(auth.MAX_AUTH_FAILURES - 1):
        auth._record_auth_failure("198.51.100.8")
    now[0] += auth.LOCKOUT_SECONDS + 1
    auth._record_auth_failure("198.51.100.8")
    assert not auth._is_locked_out("198.51.100.8")


# --- serialised config writes ----------------------------------------------------------

def test_concurrent_config_writes_both_persist(runtime_config_file):
    config.save_runtime_config({})
    entered = threading.Event()
    release = threading.Event()

    @config.serializes_config_writes
    def slow_writer():
        cfg = config.load_runtime_config()
        entered.set()
        release.wait(5)
        cfg["slow"] = True
        config.save_runtime_config(cfg)

    @config.serializes_config_writes
    def fast_writer():
        cfg = config.load_runtime_config()
        cfg["fast"] = True
        config.save_runtime_config(cfg)

    t1 = threading.Thread(target=slow_writer)
    t1.start()
    assert entered.wait(5)
    t2 = threading.Thread(target=fast_writer)
    t2.start()
    time.sleep(0.2)       # fast_writer is now blocked on the lock, not reading stale data
    release.set()
    t1.join(5)
    t2.join(5)
    saved = config.load_runtime_config()
    assert saved.get("slow") and saved.get("fast")


# --- core/web_hardening.py (what app.py installs) --------------------------------

@pytest.fixture
def hardened_app(runtime_config_file, monkeypatch):
    from core.web_hardening import install_web_hardening
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    install_web_hardening(flask_app)

    @flask_app.route('/api/test/body', methods=['POST'])
    @auth.requires_auth
    def body():
        from flask import request
        return jsonify({"success": True, "size": len(request.get_data())})

    @flask_app.route('/api/test/big_upload', methods=['POST'])
    @auth.requires_auth
    def big_upload():
        from flask import request
        return jsonify({"success": True, "size": len(request.get_data())})

    monkeypatch.setitem(config.REQUEST_BODY_ENDPOINT_MAX_BYTES, 'big_upload', 200 * 1024 * 1024)
    import core.web_hardening as wh
    monkeypatch.setattr(wh, "REQUEST_BODY_ENDPOINT_MAX_BYTES", config.REQUEST_BODY_ENDPOINT_MAX_BYTES)
    return flask_app


def test_an_oversized_body_gets_a_json_413(hardened_app):
    res = hardened_app.test_client().post('/api/test/body', data=b"x" * 10,
                                          environ_overrides={"CONTENT_LENGTH": str(64 * 1024 * 1024)})
    assert res.status_code == 413
    assert "too large" in res.get_json()["error"]


def test_a_listed_endpoint_gets_its_own_larger_limit(hardened_app):
    res = hardened_app.test_client().post('/api/test/big_upload', data=b"x" * 10,
                                          environ_overrides={"CONTENT_LENGTH": str(64 * 1024 * 1024)})
    assert res.status_code != 413


def test_an_unreadable_settings_file_is_a_503_not_a_login(hardened_app, runtime_config_file, monkeypatch):
    import base64
    monkeypatch.setattr(config, "ADMIN_PASS", None)
    runtime_config_file.write_text("{corrupt")
    token = base64.b64encode(f"{config.ADMIN_USER}:forensics".encode()).decode()
    res = RemoteTestClient(hardened_app.test_client()).post('/api/test/body',
                                                           headers={"Authorization": f"Basic {token}"})
    assert res.status_code == 503
    assert res.get_json()["runtime_config_unreadable"] is True


def test_anti_framing_headers_are_set(hardened_app):
    res = hardened_app.test_client().post('/api/test/body')
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in res.headers.get("Content-Security-Policy", "")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
