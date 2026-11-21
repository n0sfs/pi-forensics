"""The session cookie gets Secure over HTTPS (nginx in front, or direct TLS)
and stays without it for the plain-HTTP kiosk (2026-11-21)."""
from flask import Flask, session

from core.web_hardening import install_web_hardening


def _app():
    app = Flask(__name__)
    app.secret_key = "test-only"
    install_web_hardening(app)

    @app.route("/login", methods=["POST"])
    def login():
        session["user"] = "ana"
        return "ok"

    return app


def _session_cookie(res):
    return [c for c in res.headers.getlist("Set-Cookie") if c.startswith("session=")]


def test_secure_behind_station_nginx():
    c = _app().test_client()
    res = c.post("/login", headers={"X-Forwarded-Proto": "https"}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
    [cookie] = _session_cookie(res)
    assert "; Secure" in cookie and "HttpOnly" in cookie


def test_secure_on_direct_tls():
    c = _app().test_client()
    [cookie] = _session_cookie(c.post("/login", base_url="https://localhost"))
    assert "; Secure" in cookie


def test_not_secure_for_the_plain_http_kiosk():
    c = _app().test_client()
    [cookie] = _session_cookie(c.post("/login", environ_base={"REMOTE_ADDR": "127.0.0.1"}))
    assert "Secure" not in cookie


def test_forwarded_proto_from_a_lan_peer_is_ignored():
    c = _app().test_client()
    res = c.post("/login", headers={"X-Forwarded-Proto": "https"}, environ_base={"REMOTE_ADDR": "192.168.1.50"})
    [cookie] = _session_cookie(res)
    assert "Secure" not in cookie


def test_other_cookies_untouched():
    app = _app()

    @app.route("/other")
    def other():
        from flask import make_response
        r = make_response("x")
        r.set_cookie("pref", "1")
        return r

    res = app.test_client().get("/other", headers={"X-Forwarded-Proto": "https"}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert res.headers.getlist("Set-Cookie") == ["pref=1; Path=/"]
