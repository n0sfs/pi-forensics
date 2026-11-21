"""Settings > Case & Reporting > Privacy-Tool Apps (2026-11-21)."""
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.settings as settings
from tests.conftest import RemoteTestClient, login_user_session


def test_parser_accepts_defaults_and_comments():
    apps, err = settings._parse_privacy_tool_apps_text(
        "# station list\ncom.example.vpn\ncom.example.tor | Example Tor | TOR\n\ncom.example.vpn | dup | vpn\n")
    assert err is None
    assert apps == [{"id": "com.example.vpn", "label": "com.example.vpn", "category": "vpn"},
                    {"id": "com.example.tor", "label": "Example Tor", "category": "tor"}]


@pytest.mark.parametrize("text, needle", [
    ("com.example.vpn | X | proxy", "category must be one of"),
    ("bad id with spaces | X | vpn", "Line 1"),
    ("ok.id | a | vpn | extra", "Line 1"),
    ("ok.id | " + "x" * 81 + " | vpn", "longer than 80"),
])
def test_parser_rejects_bad_lines(text, needle):
    apps, err = settings._parse_privacy_tool_apps_text(text)
    assert apps is None and needle in err


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(settings.settings_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def test_save_and_read_back(client):
    res = client.post("/api/settings/privacy_tool_apps", json={"apps_text": "com.example.vpn | Example | vpn"})
    assert res.status_code == 200 and res.get_json()["apps"][0]["id"] == "com.example.vpn"
    data = client.get("/api/settings/privacy_tool_apps").get_json()
    assert data["apps"] == [{"id": "com.example.vpn", "label": "Example", "category": "vpn"}]
    assert any(b["id"] == "org.torproject.android" for b in data["builtin"])
    assert config.get_privacy_tool_apps() == data["apps"]
    res = client.post("/api/settings/privacy_tool_apps", json={"apps_text": "nope | X | bogus"})
    assert res.status_code == 400
    assert config.get_privacy_tool_apps() == data["apps"]
