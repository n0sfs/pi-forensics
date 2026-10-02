"""App-wide request hardening (2026-10-02 review), installed once by app.py.

Kept out of app.py itself so tests can install exactly the same hooks on a
throwaway Flask app - importing app.py starts the station's startup threads
(share auto-mounts, a pending network revert), which must never run in a test.

- Request body limits: there were none, so one multi-GB body could exhaust the
  single gunicorn worker's memory and every running job with it.
- A JSON 413 the UI can show, instead of a bare HTML page.
- Anti-framing / nosniff headers: the kiosk talks to gunicorn directly, never
  through nginx, so nginx's copies of these never reached it.
- One readable error for an unreadable or unwritable runtime_config.json
  (core/config.py) instead of a fail-open "no users" or a silent "saved".
"""
from flask import jsonify, request

from core.config import (RuntimeConfigUnreadable, RuntimeConfigWriteFailed,
                         REQUEST_BODY_DEFAULT_MAX_BYTES, REQUEST_BODY_ENDPOINT_MAX_BYTES)


def install_web_hardening(app):
    app.config['MAX_CONTENT_LENGTH'] = REQUEST_BODY_DEFAULT_MAX_BYTES

    @app.before_request
    def _apply_request_size_limit():
        limit = REQUEST_BODY_ENDPOINT_MAX_BYTES.get(request.endpoint)
        if limit:
            request.max_content_length = limit

    @app.errorhandler(413)
    def _handle_request_too_large(e):
        limit = request.max_content_length or REQUEST_BODY_DEFAULT_MAX_BYTES
        return jsonify({"success": False,
                        "error": f"That upload is too large - this action accepts up to {limit // (1024 * 1024)} MB."}), 413

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        response.headers.setdefault('Content-Security-Policy', "frame-ancestors 'self'")
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        return response

    @app.errorhandler(RuntimeConfigUnreadable)
    def _handle_unreadable_runtime_config(e):
        return jsonify({
            "success": False,
            "error": ("This station's settings file could not be read, so nothing that depends on it - accounts, "
                      "lists, settings - can be used or changed. Restore a configuration backup from the "
                      "touchscreen, or repair the file from a shell. Details: " + str(e)),
            "runtime_config_unreadable": True,
        }), 503

    @app.errorhandler(RuntimeConfigWriteFailed)
    def _handle_runtime_config_write_failed(e):
        return jsonify({"success": False, "error": f"{e} Nothing was changed.",
                        "runtime_config_write_failed": True}), 500
