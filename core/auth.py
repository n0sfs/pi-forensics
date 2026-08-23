"""Session/Basic-Auth authentication, brute-force lockout, and the user
group / permission model - the @requires_auth / @requires_permission
decorators every route in every routes/*.py module is wrapped in.

Part of the app.py -> core/ + routes/ split - pure code motion, no
behavior change, with one deliberate adaptation: get_offline_tiles_info()
used to read the literal module-level `app` object's static_folder
directly (safe when everything lived in one file); it now uses Flask's
`current_app` context-local proxy instead, since core/ modules must never
import the real `app` object from app.py (app.py itself imports FROM
core/, so importing `app` back here would be a circular import). This is
the standard, idiomatic Flask way to reach the running app from any
module - not a functional change, current_app.static_folder resolves to
the exact same value app.static_folder always did.

See the dated CLAUDE.md entry for this refactor for the full rationale.
"""
import os
import json
import hmac
import time
import threading
from functools import wraps
from flask import request, g, session, redirect, Response, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from core.config import ADMIN_USER, load_runtime_config, save_runtime_config, get_active_admin_pass

# --- Basic brute-force throttling for Basic Auth ---
# In-memory only (resets on restart) and keyed by source IP, so it's not a
# substitute for a real WAF/fail2ban setup on a network you don't control -
# but it closes the "unlimited guesses" gap in the meantime.
auth_fail_lock = threading.Lock()
auth_fail_tracker = {}  # ip -> {"count": int, "locked_until": float|None}
MAX_AUTH_FAILURES = 5
LOCKOUT_SECONDS = 300

# --- Last-login tracking (User Accounts list) ---
# HTTP Basic Auth re-sends credentials on every single request, and this
# app's own telemetry alone polls every 2 seconds per open tab - persisting
# runtime_config.json (the whole file, not just this one field) on every
# successful auth would mean a disk write several times a second for one
# active user. Throttled instead: only actually written to disk once per
# LAST_LOGIN_PERSIST_INTERVAL per username, tracked here in memory (resets
# on restart, which just means one extra write next time that user is seen -
# never wrong, only occasionally a little stale between restarts).
_last_login_persist_times = {}  # username -> epoch seconds of last disk write
LAST_LOGIN_PERSIST_INTERVAL = 300

def _record_last_login(username):
    if not username:
        return
    now = time.time()
    if now - _last_login_persist_times.get(username, 0) < LAST_LOGIN_PERSIST_INTERVAL:
        return
    cfg = load_runtime_config()
    user = find_user(username, cfg.get('users'))
    if not user:
        # Local-kiosk sentinel or the legacy single-shared-account login -
        # neither has a real per-user record to update.
        return
    user['last_login'] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_runtime_config(cfg)
    _last_login_persist_times[username] = now

# --- Idle session timeout ---
# A session cookie only ever proves "this browser logged in at some point" -
# left alone, PERMANENT_SESSION_LIFETIME (12h, app.py) is the only thing that
# ever expires it, which is fine for an actively-open tab (this app's own 2s
# telemetry poll keeps refreshing it below) but does nothing for a laptop
# that's closed, put to sleep, or walked away from mid-session on a remote/
# LAN connection. Deliberately does NOT apply to the physical kiosk bypass
# (requires_auth's first branch, below) - that path never touches the
# session at all, matching this app's standing "physical access already
# implies high trust" posture, and to the /api/* Basic Auth fallback (no
# session there either, by design - see check_auth()'s docstring). A sliding
# window, not an absolute one: every authenticated request pushes it back out
# by SESSION_IDLE_TIMEOUT_SECONDS, so a genuinely active session never times
# out mid-use, only one that's gone quiet.
SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get('FORENSIC_IDLE_TIMEOUT', 1800))  # 30 min
print(f"[SECURITY] Remote/LAN sessions idle-timeout after {SESSION_IDLE_TIMEOUT_SECONDS // 60} minutes of "
      f"inactivity (set FORENSIC_IDLE_TIMEOUT, in seconds, to change this). Does not apply to the physical "
      f"kiosk touchscreen.")

# Skips login for the physical kiosk touchscreen only (see requires_auth and
# is_local_kiosk_request below) - remote/LAN/WiFi access always still
# requires authentication regardless of this setting. Defaults on since a
# working on-screen keyboard for the native Basic Auth prompt has proven
# unreliable in this project's Wayland/labwc kiosk environment. Set
# FORENSIC_KIOSK_AUTH_BYPASS=0 to require login locally too.
KIOSK_AUTH_BYPASS_ENABLED = os.environ.get('FORENSIC_KIOSK_AUTH_BYPASS', '1') != '0'
if KIOSK_AUTH_BYPASS_ENABLED:
    print("[SECURITY] Local kiosk login is bypassed (FORENSIC_KIOSK_AUTH_BYPASS=1, the default). "
          "Anyone with physical access to the touchscreen has full control of this station without "
          "a password. Remote/LAN access still requires login. Set FORENSIC_KIOSK_AUTH_BYPASS=0 "
          "in the systemd unit to disable this.")

# --- Authentication Middleware ---
# Computed once at import time so check_auth() always has a real hash to
# compare against for a nonexistent username - without this, a lookup miss
# would return instantly while a real user takes as long as a scrypt hash
# comparison, a timing side-channel that leaks which usernames exist.
_DUMMY_PASSWORD_HASH = generate_password_hash('dummy-timing-safety-password')

def find_user(username, users=None):
    if users is None:
        users = load_runtime_config().get('users') or []
    for u in users:
        if hmac.compare_digest(u.get('username', ''), username or ''):
            return u
    return None

def check_auth(username, password):
    # Two-tier: real multi-user accounts (runtime_config.json['users']) take
    # priority once any exist; otherwise fall back to the original single
    # shared-login path unchanged, so a station that upgrades app.py via git
    # pull but hasn't created a user yet keeps working exactly as before.
    users = load_runtime_config().get('users')
    if users:
        user = find_user(username, users)
        if user:
            return check_password_hash(user.get('password_hash', ''), password or '')
        check_password_hash(_DUMMY_PASSWORD_HASH, password or '')
        return False

    # Constant-time comparison to avoid leaking credential info via timing.
    user_ok = hmac.compare_digest(username or '', ADMIN_USER)
    pass_ok = hmac.compare_digest(password or '', get_active_admin_pass())
    return user_ok and pass_ok

def _session_user_still_valid(username):
    # Mirrors check_auth()'s two-tier logic, but for existence rather than a
    # password match - a session only ever proves "this browser successfully
    # logged in as this username at some point", so every subsequent request
    # re-derives whether that identity still exists rather than trusting the
    # cookie forever. This is what makes a deleted user's still-cached
    # session cookie die on their very next request, for free, with no
    # separate server-side session-revocation list needed.
    if not username:
        return False
    users = load_runtime_config().get('users')
    if users:
        return find_user(username, users) is not None
    return hmac.compare_digest(username, ADMIN_USER)

def is_local_kiosk_request():
    """
    True if this request is coming from the Pi's own local kiosk session,
    not a remote LAN/WiFi client. The kiosk's chromium always talks to
    gunicorn directly over loopback (http://127.0.0.1:5000), regardless of
    whether TLS/nginx is set up - see install.py's autostart script.

    When nginx is in front of gunicorn (TLS setup), gunicorn only ever sees
    connections from nginx itself (also loopback), so a naive remote_addr
    check would misidentify every remote client as local. nginx forwards
    the real client IP via X-Real-IP (see nginx/pi-forensics.conf), so that
    takes priority when present - but ONLY once request.remote_addr - the
    actual TCP peer, not anything header-based - is itself confirmed
    loopback. That gate is the real security boundary, found missing during
    a security audit (2026-08-22): TLS/nginx is an *optional* install.py
    prompt (see GUNICORN_BIND there), and skipping it leaves gunicorn
    listening on every interface, not just localhost - in that mode
    request.remote_addr is a genuine, unspoofable TCP-layer value (a
    LAN/remote attacker's connection always shows their real address), while
    X-Real-IP is just a client-supplied header with no nginx there to
    strip/overwrite it. Trusting X-Real-IP unconditionally let a remote
    attacker send `X-Real-IP: 127.0.0.1` straight to gunicorn and get the
    kiosk's full unauthenticated bypass. Gating on remote_addr first closes
    that without touching the TLS-configured deployment mode at all: nginx's
    proxy_pass always connects to gunicorn via 127.0.0.1 (nginx/pi-
    forensics.conf), so remote_addr is unconditionally loopback there
    already - this check is a pure no-op in that mode, and only ever
    changes behavior when there's no nginx in front to have set X-Real-IP
    honestly in the first place.
    """
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return False
    real_ip = request.headers.get('X-Real-IP', request.remote_addr)
    return real_ip in ('127.0.0.1', '::1', 'localhost')

def get_offline_tiles_info():
    """Read install.py's optional offline OSM tile cache manifest, if that setup step was run.
    Returns {'max_zoom': N} or None - a tiny file, read fresh per page load rather than cached at
    process start, since re-running install.py's tile step (or a future manual refresh) shouldn't
    need a service restart to be picked up."""
    manifest_path = os.path.join(current_app.static_folder, 'vendor', 'osm_tiles', 'manifest.json')
    try:
        with open(manifest_path) as f:
            data = json.load(f)
        if isinstance(data.get('max_zoom'), int):
            return {'max_zoom': data['max_zoom']}
    except (OSError, ValueError, TypeError):
        pass
    return None

def _plain_401():
    # No WWW-Authenticate header - that header alone is what makes a browser
    # pop its native Basic Auth credentials dialog, which this app no longer
    # wants to ever show (the browser UI authenticates via /login instead).
    # Basic Auth is still *accepted* on /api/* routes (see requires_auth()),
    # just never *advertised/demanded* via this challenge header.
    return Response('Authentication required to access Pi Forensics Suite.\n', 401)

def _is_locked_out(client_key):
    with auth_fail_lock:
        entry = auth_fail_tracker.get(client_key)
        return bool(entry and entry["locked_until"] and time.time() < entry["locked_until"])

def _record_auth_failure(client_key):
    with auth_fail_lock:
        entry = auth_fail_tracker.get(client_key, {"count": 0, "locked_until": None})
        entry["count"] += 1
        if entry["count"] >= MAX_AUTH_FAILURES:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
        auth_fail_tracker[client_key] = entry

def _record_auth_success(client_key):
    with auth_fail_lock:
        auth_fail_tracker.pop(client_key, None)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Physical-kiosk-only auth bypass. Deliberately narrow: this only
        # matches genuine loopback origin with no X-Real-IP header (see
        # is_local_kiosk_request() above) - a remote client proxied through
        # nginx always has X-Real-IP set to their real address, so this does
        # NOT bypass auth for LAN/WiFi/remote access, which stays fully
        # authenticated exactly as before. The remaining risk is narrow but
        # real: anyone with physical access to the touchscreen gets full
        # control of the station, including destructive actions in Advanced
        # Settings (those still have confirmation dialogs). Set
        # FORENSIC_KIOSK_AUTH_BYPASS=0 to disable this and require login
        # locally too.
        if KIOSK_AUTH_BYPASS_ENABLED and is_local_kiosk_request():
            # Kiosk requests never carry a Basic Auth header, so there's no
            # real username to attribute - use a fixed sentinel rather than
            # leaving chain-of-custody entries with no user at all.
            g.forensic_user = 'local-kiosk'
            return f(*args, **kwargs)

        # Primary path: a real signed session cookie, set by POST /login (or
        # by the "Switch User" flow, which is just a second /login call).
        # Re-derived on every request rather than trusted for the cookie's
        # whole lifetime, so a user deleted mid-session loses access on their
        # very next request (see _session_user_still_valid()).
        session_username = session.get('username')
        idle_expired = False
        if session_username:
            if _session_user_still_valid(session_username):
                now = time.time()
                last_activity = session.get('last_activity')
                if last_activity is not None and (now - last_activity) > SESSION_IDLE_TIMEOUT_SECONDS:
                    idle_expired = True
                    session.clear()
                else:
                    session['last_activity'] = now
                    g.forensic_user = session_username
                    return f(*args, **kwargs)
            else:
                session.clear()

        client_key = request.remote_addr or 'unknown'

        # Fallback path, /api/* only: plain HTTP Basic Auth, unchanged from
        # this app's original auth model - kept specifically so this
        # project's own extensively-documented `curl -sk -u user:pass
        # https://host/api/...` live-verification workflow keeps working
        # with zero changes. Deliberately NOT offered for the page route
        # (see the redirect-to-/login branch below) - the browser UI only
        # ever authenticates via the login page/session from here on.
        if request.path.startswith('/api/'):
            auth = request.authorization
            if auth:
                # Only an actually-presented-and-wrong credential counts as a
                # failed attempt. Treating "no Authorization header at all"
                # the same way would auto-lock the examiner's own IP out of
                # the login form itself - this app already polls several
                # /api/* endpoints every 2 seconds from the browser, and a
                # tab left open past logout (or open before ever logging in)
                # would rack up "failures" purely from having no cookie yet,
                # with no credentials involved at all.
                if _is_locked_out(client_key):
                    return Response(
                        'Too many failed login attempts. Try again in a few minutes.\n',
                        429,
                        {'Retry-After': str(LOCKOUT_SECONDS)}
                    )
                if not check_auth(auth.username, auth.password):
                    _record_auth_failure(client_key)
                    return _plain_401()
                _record_auth_success(client_key)
                _record_last_login(auth.username)
                g.forensic_user = auth.username
                return f(*args, **kwargs)
            # No session, no Authorization header - a plain unauthenticated
            # API request. No lockout tracking here (nothing was actually
            # attempted - see the comment above this branch).
            return _plain_401()

        # The one page route (/) with no valid session - send the browser to
        # our own branded login page instead of ever showing a 401 that
        # would trigger the native Basic Auth dialog. Flag idle-timeout
        # separately from "never logged in" so the login page can say why.
        next_url = f'/login?next={request.path}'
        if idle_expired:
            next_url += '&expired=1'
        return redirect(next_url)
    return decorated

# --- User Groups / Permissions ---
# A group is {id, name, is_builtin, permissions: {key: bool}}. Two built-ins
# always exist: "admin" (every key forced True, never persisted, never
# editable - there must always be at least one group with full access that
# no code path, bug, or accidental checkbox click can weaken) and "analyst"
# (a sane operational-access default, persisted/editable like any custom
# group once a station admin adjusts it, but not deletable/renamable - it's
# meant to always exist as the sensible non-admin default new users land in).
PERMISSION_KEYS = [
    ("acquisition", "Forensic Acquisition"),
    ("mobile", "Mobile Forensics"),
    ("recovery", "File Recovery"),
    ("file_explorer", "File Explorer"),
    ("reporting", "Reporting"),
    ("settings", "Settings (station configuration)"),
    ("manage_users", "User & Group Management"),
]

def _all_permissions_true():
    return {k: True for k, _ in PERMISSION_KEYS}

def _normalize_permissions(raw):
    raw = raw or {}
    return {k: bool(raw.get(k, False)) for k, _ in PERMISSION_KEYS}

def _default_analyst_permissions():
    # Full day-to-day operational access, no station configuration and no
    # ability to manage other accounts - matches this app's pre-groups
    # "standard" role exactly, so nothing changes for an existing standard
    # user migrated into this group (see get_user_group_id below).
    return {
        "acquisition": True, "mobile": True, "recovery": True,
        "file_explorer": True, "reporting": True,
        "settings": False, "manage_users": False,
    }

def get_user_groups():
    """Full group list: the two built-ins merged with any custom groups from
    runtime_config.json. Admin is synthesized fresh every call - it is never
    read from or written to disk, so there is no code path that can persist
    a weakened Admin group. Analyst is also always present even if never
    explicitly saved, using its sane default permissions until a station
    admin edits and saves it."""
    cfg = load_runtime_config()
    saved = {rec.get('id'): rec for rec in cfg.get('user_groups', [])}

    groups = [{"id": "admin", "name": "Admin", "is_builtin": True, "permissions": _all_permissions_true()}]

    analyst_saved = saved.get('analyst')
    groups.append({
        "id": "analyst", "name": "Analyst", "is_builtin": True,
        "permissions": _normalize_permissions(analyst_saved.get('permissions')) if analyst_saved else _default_analyst_permissions(),
    })

    for rec in cfg.get('user_groups', []):
        if rec.get('id') in ('admin', 'analyst'):
            continue
        groups.append({
            "id": rec.get('id'), "name": rec.get('name'), "is_builtin": False,
            "permissions": _normalize_permissions(rec.get('permissions')),
        })
    return groups

def find_group(group_id, groups=None):
    groups = groups if groups is not None else get_user_groups()
    for grp in groups:
        if grp['id'] == group_id:
            return grp
    return None

def get_user_group_id(user):
    """Resolves a user record's group id. A user created before groups
    existed has no group_id, only the old role field - migrated on read
    (not rewritten to disk) so this never needs an explicit migration step:
    role 'admin' -> group 'admin', anything else (including the old
    'standard' default) -> group 'analyst'."""
    if not user:
        return None
    gid = user.get('group_id')
    if gid:
        return gid
    return 'admin' if user.get('role') == 'admin' else 'analyst'

def get_current_user_permissions():
    """Full permission dict for whoever requires_auth() just authenticated.
    Local kiosk access and the pre-multi-user single-shared-account mode
    both resolve to full (Admin-equivalent) access - see
    get_current_user_role()'s docstring below for why that's unchanged
    behavior, not a new grant."""
    username = getattr(g, 'forensic_user', None)
    if username == 'local-kiosk':
        return _all_permissions_true()
    users = load_runtime_config().get('users')
    if not users:
        return _all_permissions_true()
    user = find_user(username, users)
    if not user:
        return {k: False for k, _ in PERMISSION_KEYS}
    group = find_group(get_user_group_id(user))
    return dict(group['permissions']) if group else {k: False for k, _ in PERMISSION_KEYS}

def get_current_user_role():
    """
    Display-only label for whoever requires_auth() just authenticated on
    this request (shown in the navbar's "Logged in as" indicator and the
    user list). Local kiosk access and the pre-multi-user single-shared-
    account mode both behave as "Admin" - they're the same one account this
    app has always had, full station control, nothing new granted by this
    change. Actual authorization decisions use get_current_user_permissions()
    / requires_permission(), never this string.
    """
    username = getattr(g, 'forensic_user', None)
    if username == 'local-kiosk':
        return 'Admin'
    users = load_runtime_config().get('users')
    if not users:
        return 'Admin'
    user = find_user(username, users)
    if not user:
        return None
    group = find_group(get_user_group_id(user))
    return group['name'] if group else 'Unknown'

def caller_reauth_ok(current_password):
    """
    Re-verifies the CALLER's own password for the delete/reset-another-user
    actions (same friction as self-service password change). The physical
    kiosk sentinel ('local-kiosk', see requires_auth's bypass branch) has no
    real account/password to check against - physical access to the
    touchscreen is already this app's most-trusted tier (full station
    control with no login at all), so demanding a password confirmation
    there would be both meaningless and a hard lockout, not a security
    improvement.
    """
    caller_username = getattr(g, 'forensic_user', None)
    if caller_username == 'local-kiosk':
        return True
    caller = find_user(caller_username)
    return bool(caller) and check_password_hash(caller.get('password_hash', ''), current_password)

def requires_permission(*keys):
    """Stack under @requires_auth - relies on it having already set
    g.forensic_user. Passes if the caller's group has ANY of the given
    permission keys (most call sites pass exactly one; a few genuinely
    cross-cutting routes - reachable from more than one tab's UI - pass more
    than one so either tab's access is sufficient)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            perms = get_current_user_permissions()
            if not any(perms.get(k, False) for k in keys):
                return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def _safe_next_path(raw):
    # Only ever redirect to a same-origin relative path - "//evil.com/x" is
    # parsed by browsers as protocol-relative (i.e. an off-site redirect),
    # so reject anything not starting with exactly one "/". Falls back to
    # "/" for anything else (missing, empty, off-site, or malformed).
    if raw and raw.startswith('/') and not raw.startswith('//'):
        return raw
    return '/'
