"""Login/logout/session routes, plus the main index page and /api/whoami.

Smallest possible blueprint by design - no worker threads, no job-state
coupling - chosen as the first routes/*.py extraction specifically to
validate the whole blueprint-registration + `app:app`-still-works-under-
the-existing-systemd-unit mechanism end to end with minimal blast radius.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import json
import time

from flask import Blueprint, render_template, jsonify, request, g, session, redirect

from core.auth import (
    requires_auth, check_auth, is_local_kiosk_request, get_offline_tiles_info,
    get_current_user_permissions, get_current_user_role,
    _session_user_still_valid, _safe_next_path, _effective_client_ip,
    _record_last_login, _is_locked_out, _record_auth_failure, _record_auth_success,
)
from core.config import get_app_version

auth_routes_bp = Blueprint('auth_routes', __name__)


@auth_routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Already have a valid session - no need to show the form again.
        existing = session.get('username')
        if existing and _session_user_still_valid(existing):
            return redirect(_safe_next_path(request.args.get('next')))
        return render_template(
            'login.html',
            next=_safe_next_path(request.args.get('next')),
            expired=bool(request.args.get('expired')),
            app_version=get_app_version(),
        )

    client_key = _effective_client_ip()
    if _is_locked_out(client_key):
        return jsonify({
            "success": False,
            "error": "Too many failed login attempts. Try again in a few minutes.",
        }), 429

    req = request.get_json(silent=True) or {}
    username = (req.get('username') or '').strip()
    password = req.get('password') or ''

    if not check_auth(username, password):
        _record_auth_failure(client_key)
        return jsonify({"success": False, "error": "Incorrect username or password."}), 401

    _record_auth_success(client_key)
    _record_last_login(username)
    session.clear()  # drop any prior identity outright rather than merge state into it
    session['username'] = username
    session['last_activity'] = time.time()
    session.permanent = True
    return jsonify({"success": True, "redirect": _safe_next_path(req.get('next'))})


@auth_routes_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})


@auth_routes_bp.route('/')
@requires_auth
def index():
    return render_template(
        'index.html',
        is_local_kiosk=is_local_kiosk_request(),
        offline_tiles_json=json.dumps(get_offline_tiles_info()),
        app_version=get_app_version(),
    )


@auth_routes_bp.route('/api/whoami', methods=['GET'])
@requires_auth
def whoami():
    username = getattr(g, 'forensic_user', None)
    perms = get_current_user_permissions()
    return jsonify({
        "username": username,
        "role": get_current_user_role(),
        "permissions": perms,
    })
