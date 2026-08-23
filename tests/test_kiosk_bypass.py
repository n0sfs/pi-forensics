"""core/auth.py's is_local_kiosk_request() - the physical-touchscreen
login-bypass boundary.

Locks in the fix for a real, exploitable finding from the 2026-08-22
security audit: on a station where the optional TLS/nginx setup step was
skipped, gunicorn listens on every network interface (see install.py's
GUNICORN_BIND), and the old check trusted a client-supplied X-Real-IP
header unconditionally - letting any remote/LAN attacker send
`X-Real-IP: 127.0.0.1` straight to gunicorn and get the kiosk's full
unauthenticated bypass. The fix gates X-Real-IP trust on request.remote_addr
(the real, unspoofable TCP peer) already being loopback - which nginx's own
proxy_pass (always 127.0.0.1, see nginx/pi-forensics.conf) guarantees in
the TLS-configured deployment mode, so this is a pure no-op there.

Uses a bare Flask request context rather than the full app - this function
only ever reads flask.request, and core/auth.py has no POSIX-only imports
(unlike core/jobs.py), so this runs on any dev machine.
"""
import flask

import core.auth as auth

_app = flask.Flask(__name__)


def _is_local(remote_addr, x_real_ip=None):
    headers = {}
    if x_real_ip is not None:
        headers["X-Real-IP"] = x_real_ip
    with _app.test_request_context("/", environ_base={"REMOTE_ADDR": remote_addr}, headers=headers):
        return auth.is_local_kiosk_request()


def test_genuine_local_request_no_nginx_is_local():
    # Direct-to-gunicorn kiosk browser, no TLS/nginx configured - no
    # X-Real-IP header exists at all in this deployment mode.
    assert _is_local("127.0.0.1") is True


def test_genuine_nginx_proxied_kiosk_is_local():
    # TLS configured: nginx is the real peer (loopback) and correctly
    # forwards the true original client's own loopback address.
    assert _is_local("127.0.0.1", x_real_ip="127.0.0.1") is True


def test_genuine_nginx_proxied_remote_client_is_not_local():
    # TLS configured: nginx is the real peer (loopback) but forwards the
    # true remote client's real LAN address.
    assert _is_local("127.0.0.1", x_real_ip="192.168.1.50") is False


def test_remote_attacker_forging_x_real_ip_is_rejected():
    # THE FIX: no nginx in front (remote_addr is the attacker's own real,
    # unspoofable address), forging X-Real-IP to look like the kiosk must
    # NOT grant the bypass. Pre-fix this returned True - a full
    # unauthenticated Admin bypass reachable by anyone on the network.
    assert _is_local("203.0.113.77", x_real_ip="127.0.0.1") is False


def test_remote_request_with_no_header_is_not_local():
    assert _is_local("203.0.113.77") is False


def test_ipv6_loopback_variants_are_local():
    assert _is_local("::1") is True
    assert _is_local("::1", x_real_ip="::1") is True
