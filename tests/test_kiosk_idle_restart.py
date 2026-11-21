"""The kiosk watchdog restarts Chromium only when the touchscreen is idle
(Eric's decision 2026-11-20, 10-09 item 1A). It used to pkill on the clock
every 30 minutes, mid-sentence, losing unsaved Reporting text. The page now
reports real input to /api/kiosk/activity, which touches a marker file the
watchdog reads."""
import os
import re

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask

import routes.settings as settings_routes
from routes.settings import settings_bp
from tests.conftest import RemoteTestClient, login_user_session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def app(runtime_config_file, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_routes, "KIOSK_ACTIVITY_FILE", str(tmp_path / ".kiosk_last_input"))
    a = Flask(__name__)
    a.secret_key = "test-only"
    a.register_blueprint(settings_bp)
    return a


def test_kiosk_input_touches_the_marker(app, tmp_path):
    marker = tmp_path / ".kiosk_last_input"
    res = app.test_client().post('/api/kiosk/activity', base_url="http://127.0.0.1:5000")
    assert res.status_code == 200 and res.get_json()["success"] is True
    assert marker.exists()
    os.utime(marker, (1, 1))
    app.test_client().post('/api/kiosk/activity', base_url="http://127.0.0.1:5000")
    assert marker.stat().st_mtime > 1


def test_a_remote_browser_cannot_hold_off_the_restart(app, tmp_path):
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin")
    res = c.post('/api/kiosk/activity')
    assert res.status_code == 403
    assert not (tmp_path / ".kiosk_last_input").exists()


def test_watchdog_waits_for_ten_idle_minutes():
    src = open(os.path.join(ROOT, "install.py"), encoding="utf-8").read()
    block = src[src.index("# Periodic watchdog"):]
    block = block[:block.index("done &") + len("done &")]
    assert '.kiosk_last_input' in block
    assert re.search(r'-ge 600', block)
    # the kill sits after the idle wait, not straight after the 30-minute sleep
    assert block.index('-ge 600') < block.index('pkill -9 -f "chromium.*--kiosk"')
    assert not re.search(r'sleep 1800\s*\n\s*pkill', block)
