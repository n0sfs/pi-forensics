import os
import threading

from flask import Flask, jsonify

# Every route this app serves now lives in a routes/*.py Blueprint, backed
# by core/*.py for shared cross-cutting state/helpers - see the dated
# CLAUDE.md entry for the full app.py -> core/ + routes/ split. app.py
# itself only needs the one core/ helper below (the secret-key bootstrap,
# which must run exactly once at this exact module position - see the
# comment at its call site) plus attempt_startup_auto_mounts() (imported
# from routes/settings.py further down, alongside that blueprint's
# registration) for the startup thread at the bottom of this file.
from core.config import _get_or_create_secret_key
# Registered as an app-wide errorhandler at the bottom of this file - see
# the comment there for why it is one handler rather than a try/except per
# route.
from core.jobs import CaseFileUnreadable
# Same pattern, same reason - one app-wide handler instead of a try/except
# in each of the 28 case-index reader routes. See its own docstring.
from core.case_index_db import CaseIndexUnavailable, CaseFolderUnavailable

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Deliberately left at Flask's default (False), not hardcoded True: this app
# supports both TLS-optional and plain-HTTP deployment (see install.py's TLS
# prompt, which already discloses "without TLS, credentials are sent over
# plain HTTP" as an accepted tradeoff for a LAN appliance), there's no
# ProxyFix/X-Forwarded-Proto handling here to reliably detect TLS at runtime,
# and Secure=False cookies are sent over both HTTP and HTTPS (Secure=True is
# the one that *restricts*, so leaving this False never regresses the
# HTTPS-configured case, only avoids silently breaking the HTTP-only one).
app.config['PERMANENT_SESSION_LIFETIME'] = 12 * 60 * 60  # 12h - a workstation shift, not a web app's short-lived token

# ADMIN_USER/ADMIN_PASS, INSTALL_DIR and every path derived from it, the
# mount-key helper, log_chain_of_custody(), load/save_runtime_config(),
# EVIDENCE_ROOT, etc. all live in core/config.py and core/paths.py now,
# used directly by whichever routes/*.py blueprint needs them - app.py
# itself doesn't need to import them. The one thing that has to stay here
# rather than move into core/config.py itself: this exact call, in this
# exact position (right after `app = Flask(__name__)` above), since it does
# real filesystem I/O (creates/chmods the key file on first run) and must
# fire exactly once, at this module's own top level.
app.secret_key = _get_or_create_secret_key()

# routes/*.py Blueprints - registered as each is extracted out of this file
# (Phase B of the app.py -> core/ + routes/ split). See the dated CLAUDE.md
# entry for the full rationale and rollout order.
from routes.auth_routes import auth_routes_bp
app.register_blueprint(auth_routes_bp)
from routes.mobile import mobile_bp
app.register_blueprint(mobile_bp)
from routes.recovery import recovery_bp
app.register_blueprint(recovery_bp)
from routes.case_management import case_management_bp
app.register_blueprint(case_management_bp)
from routes.acquisition import acquisition_bp
app.register_blueprint(acquisition_bp)
from routes.file_explorer import file_explorer_bp
app.register_blueprint(file_explorer_bp)
from routes.image_browser import image_browser_bp
app.register_blueprint(image_browser_bp)
from routes.case_index import case_index_bp
app.register_blueprint(case_index_bp)
from routes.reporting import reporting_bp
app.register_blueprint(reporting_bp)
from routes.settings import settings_bp, attempt_startup_auto_mounts
app.register_blueprint(settings_bp)
from routes.auto_analyze import auto_analyze_bp
app.register_blueprint(auto_analyze_bp)


# A corrupt/unreadable consolidated case file surfaces as a clear message on
# EVERY route at once, rather than each one growing its own try/except
# (2026-09-15). Before CaseFileUnreadable existed, _read_case_file() swallowed
# the failure and handed back an empty stub, so a case with an unreadable file
# rendered as a case with no evidence - and any route that wrote afterwards
# replaced the real history with that stub. Failing visibly is the whole point
# of the exception; this handler is what makes it readable instead of a bare
# 500, and states plainly that nothing was changed on disk.
@app.errorhandler(CaseFileUnreadable)
def _handle_unreadable_case_file(e):
    return jsonify({
        "success": False,
        "error": f"This case's file could not be read, so nothing was loaded or changed: {e}",
        "case_file_unreadable": True,
    }), 500

# The analysis index's counterpart to the handler above (2026-09-20). Without
# it, an unreadable index reached the browser as Flask's stock HTML 500 page,
# which every fetch() in main.js then failed to parse - so the only thing an
# examiner ever saw was "Request failed", with no hint that the index is
# damaged or that the underlying evidence is untouched. 503 rather than 500:
# the request was valid and the case data itself is fine, it is this one
# derived file that is unavailable.
# The storage-level counterpart (2026-09-20). Without it, a case folder that
# cannot be read - overwhelmingly because the evidence share is unmounted or
# stalled - produced a perfectly successful, perfectly empty result, so an
# examiner could read "no contacts found" off a case whose data was simply
# unreachable. 503 for the same reason as above: the request was valid, the
# storage is not currently available.
@app.errorhandler(CaseFolderUnavailable)
def _handle_unavailable_case_folder(e):
    return jsonify({
        "success": False,
        "error": str(e),
        "case_folder_unavailable": True,
    }), 503


@app.errorhandler(CaseIndexUnavailable)
def _handle_unavailable_case_index(e):
    return jsonify({
        "success": False,
        "error": ("This case's analysis index could not be read, so tags, keyword hits and "
                  "parsed artifacts cannot be shown. The acquired evidence itself is not "
                  "affected - only this derived index. Re-running the analysis for this case "
                  "rebuilds it. Details: " + str(e)),
        "case_index_unavailable": True,
    }), 503

# Replay saved auto-mount shares once per process start - module-level (not
# inside the __main__ guard below) so this also runs under gunicorn, which
# imports this module rather than executing it as __main__. Backgrounded so
# a slow/unreachable share can't delay the app from becoming ready; harmless
# no-op when no auto-mount shares are configured (the common case).
threading.Thread(target=attempt_startup_auto_mounts, daemon=True).start()

if __name__ == '__main__':
    # This dev-mode entrypoint is only used for `python3 app.py` directly.
    # The production installer (install.py) runs this app under gunicorn
    # instead - see install.py / README.md for how to add TLS there
    # (reverse proxy, or gunicorn's --certfile/--keyfile).
    tls_cert = os.environ.get('FORENSIC_TLS_CERT')
    tls_key = os.environ.get('FORENSIC_TLS_KEY')
    ssl_context = (tls_cert, tls_key) if tls_cert and tls_key else None

    if not ssl_context:
        print("[SECURITY WARNING] No FORENSIC_TLS_CERT/FORENSIC_TLS_KEY configured - "
              "serving plain HTTP. Basic Auth credentials will be sent unencrypted.")

    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
