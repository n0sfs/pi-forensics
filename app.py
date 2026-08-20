import os
import threading

from flask import Flask

# Every route this app serves now lives in a routes/*.py Blueprint, backed
# by core/*.py for shared cross-cutting state/helpers - see the dated
# CLAUDE.md entry for the full app.py -> core/ + routes/ split. app.py
# itself only needs the one core/ helper below (the secret-key bootstrap,
# which must run exactly once at this exact module position - see the
# comment at its call site) plus attempt_startup_auto_mounts() (imported
# from routes/settings.py further down, alongside that blueprint's
# registration) for the startup thread at the bottom of this file.
from core.config import _get_or_create_secret_key

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
