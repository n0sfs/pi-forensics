"""Login-lockout bucket keying - a real finding from the 2026-08-22 security
audit, distinct from (but fixed alongside) the kiosk-bypass spoofing issue
in tests/test_kiosk_bypass.py.

Before the fix, the lockout tracker (core/auth.py's auth_fail_tracker) was
keyed by request.remote_addr alone. In this app's own recommended
deployment (nginx in front, TLS configured), remote_addr is ALWAYS nginx's
own loopback address for every real client - so every remote/LAN examiner
shared one lockout bucket. Two concrete consequences: (1) one attacker
failing 5 times locked out every other legitimate examiner too, and (2) a
successful login from ANY client cleared the shared bucket, silently
resetting an attacker's in-progress lockout counter.

The fix (_effective_client_ip() in core/auth.py) keys by X-Real-IP - the
real per-client address nginx forwards - but only once remote_addr is
confirmed loopback (the same trust gate the kiosk-bypass fix uses), so a
direct-to-gunicorn deployment (no nginx) is completely unaffected and still
keys by the real remote_addr.

Same minimal-app pattern as tests/test_login_flow.py (routes/auth_routes.py
only needs core.auth, no core.jobs, so this runs on any dev machine).
"""
import os

import pytest
from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.auth_routes import auth_routes_bp

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(auth_routes_bp)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


def _save_user(username, password):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": "analyst",
    })
    config.save_runtime_config(cfg)


def _login_via_nginx(client, real_ip, username="whoever", password="wrong"):
    """Simulates a request that actually passed through nginx: remote_addr
    is nginx's own loopback peer address, X-Real-IP carries the true client."""
    return client.post(
        "/login",
        json={"username": username, "password": password},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
        headers={"X-Real-IP": real_ip},
    )


def test_two_different_proxied_clients_get_independent_lockout_buckets(client, runtime_config_file):
    # 4 failures from client A (one short of the 5-strike lockout) must not
    # touch client B's own counter at all.
    for _ in range(4):
        res = _login_via_nginx(client, "203.0.113.10")
        assert res.status_code == 401
    res_b = _login_via_nginx(client, "203.0.113.20")
    assert res_b.status_code == 401  # not locked out - a fresh bucket, not client A's


def test_one_client_locking_out_does_not_lock_out_a_different_client(client, runtime_config_file):
    for _ in range(5):
        _login_via_nginx(client, "203.0.113.10")
    locked = _login_via_nginx(client, "203.0.113.10")
    assert locked.status_code == 429  # client A is now locked out

    still_ok = _login_via_nginx(client, "203.0.113.20")
    assert still_ok.status_code == 401  # client B is unaffected - real credential failure, not a 429


def test_a_different_clients_successful_login_does_not_clear_the_attackers_lockout(client, runtime_config_file):
    _save_user("realuser", "correcthorsebatterystaple")

    # Client A (the attacker) racks up 4 failures.
    for _ in range(4):
        _login_via_nginx(client, "203.0.113.10")

    # Client B (a legitimate examiner) logs in successfully, proxied through
    # the exact same nginx instance.
    ok = _login_via_nginx(client, "203.0.113.20", username="realuser", password="correcthorsebatterystaple")
    assert ok.status_code == 200

    # Pre-fix, this cleared the SHARED bucket both clients keyed into,
    # resetting the attacker back to 0. Post-fix, client A's own count must
    # still be exactly where it was - one more failure locks them out.
    locked = _login_via_nginx(client, "203.0.113.10")
    assert locked.status_code == 401  # 5th failure, not yet locked (still 401)
    now_locked = _login_via_nginx(client, "203.0.113.10")
    assert now_locked.status_code == 429  # 6th attempt: correctly locked out


def test_direct_no_nginx_deployment_still_keys_by_real_remote_addr(client, runtime_config_file):
    # No X-Real-IP at all (no nginx in front) - remote_addr itself, a real
    # non-loopback address, is what should be used, exactly as before.
    for _ in range(5):
        client.post("/login", json={"username": "x", "password": "wrong"},
                     environ_base={"REMOTE_ADDR": "198.51.100.7"})
    locked = client.post("/login", json={"username": "x", "password": "wrong"},
                          environ_base={"REMOTE_ADDR": "198.51.100.7"})
    assert locked.status_code == 429

    # A genuinely different real remote_addr is a separate bucket.
    other = client.post("/login", json={"username": "x", "password": "wrong"},
                         environ_base={"REMOTE_ADDR": "198.51.100.8"})
    assert other.status_code == 401
