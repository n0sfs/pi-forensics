"""routes/settings.py hardening from the 2026-10-02 review.

- /api/list_server_shares: 'settings' permission, argument hygiene, and the
  SMB password in a 0600 file instead of on the command line.
- Network change safety net: the pending revert survives a restart/reboot, a
  second apply can't orphan the first, an unreadable snapshot is refused, and
  the revert's real outcome is logged.
- Update App: refused while busy, fast-forward only, installer-requiring
  updates refused, rolled back when the new code fails to import.
- Restart refused while a job runs; shared-login password handling; the
  session survives its own password change while the account's others end.

No real git, nmcli, smbclient or systemctl ever runs: subprocess.run and the
thread starter are replaced in every test that reaches them.

Skipped (not failed) on a non-POSIX dev machine: routes.settings needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os
import sys
import threading as real_threading
import time as real_time
import types

import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.settings as settings
from routes.auth_routes import auth_routes_bp
from tests.conftest import RemoteTestClient, login_user_session


@pytest.fixture
def app(runtime_config_file, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "NETWORK_PENDING_REVERT_FILE", str(tmp_path / ".network_pending_revert.json"))
    monkeypatch.setattr(settings, "pending_network_revert", None)
    monkeypatch.setattr(settings, "log_chain_of_custody", lambda *a, **k: None)
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(settings_bp_for_tests())
    flask_app.register_blueprint(auth_routes_bp)
    return flask_app


def settings_bp_for_tests():
    return settings.settings_bp


def _save_user(username, password, group_id):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": username, "password_hash": generate_password_hash(password),
                                        "group_id": group_id})
    config.save_runtime_config(cfg)


@pytest.fixture
def admin(app):
    _save_user("admin_user", "admin-password-1", "admin")
    c = RemoteTestClient(app.test_client())
    login_user_session(c, "admin_user")
    return c


class _Result(types.SimpleNamespace):
    pass


def _ok(stdout="", rc=0, stderr=""):
    return _Result(returncode=rc, stdout=stdout, stderr=stderr)


class _NoThread:
    started = []

    def __init__(self, target=None, daemon=None, **kw):
        self.target = target

    def start(self):
        _NoThread.started.append(self.target)


class _ModuleProxy:
    """Replaces one module reference inside routes.settings only - patching
    the stdlib module itself would leak into everything else in the test."""
    def __init__(self, real, **overrides):
        self._real = real
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _sub_proxy(run):
    import subprocess as real_subprocess
    return _ModuleProxy(real_subprocess, run=run)


def _no_threads(monkeypatch, thread_cls=None):
    _NoThread.started = []
    monkeypatch.setattr(settings, "threading", _ModuleProxy(real_threading, Thread=thread_cls or _NoThread))


# --- list_server_shares -------------------------------------------------------------

def test_listing_shares_needs_the_settings_permission(app, monkeypatch):
    _save_user("analyst_user", "analyst-password-1", "analyst")
    c = RemoteTestClient(app.test_client())
    login_user_session(c, "analyst_user")
    monkeypatch.setattr(settings, "subprocess", _sub_proxy(lambda *a, **k: pytest.fail("must not run anything")))
    res = c.post("/api/list_server_shares", json={"protocol": "smb", "host": "10.0.0.9"})
    assert res.status_code == 403


def test_a_host_that_looks_like_a_flag_is_refused(admin, monkeypatch):
    monkeypatch.setattr(settings, "subprocess", _sub_proxy(lambda *a, **k: pytest.fail("must not run anything")))
    res = admin.post("/api/list_server_shares", json={"protocol": "smb", "host": "-xdebug"})
    assert res.status_code == 400


def test_the_smb_password_never_appears_on_the_command_line(admin, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        cred = cmd[cmd.index("-A") + 1]
        seen["cred_text"] = open(cred).read()
        seen["cred_mode"] = os.stat(cred).st_mode & 0o777
        seen["cred_path"] = cred
        return _ok(stdout="Disk|evidence|\n")
    monkeypatch.setattr(settings, "subprocess", _sub_proxy(fake_run))
    res = admin.post("/api/list_server_shares", json={"protocol": "smb", "host": "10.0.0.9",
                                                      "user": "examiner", "pass": "hunter2-secret"})
    assert res.status_code == 200 and res.get_json()["shares"] == ["evidence"]
    assert not any("hunter2-secret" in str(part) for part in seen["cmd"])
    assert "password = hunter2-secret" in seen["cred_text"]
    assert seen["cred_mode"] == 0o600
    assert not os.path.exists(seen["cred_path"])


# --- network change safety net ------------------------------------------------------------

@pytest.fixture
def nm(monkeypatch):
    monkeypatch.setattr(settings, "_nmcli_list_devices", lambda: [{"device": "eth0"}])
    monkeypatch.setattr(settings, "_nmcli_resolve_connection", lambda dev: "Wired 1")
    snapshot = {"method": "manual", "address": "192.0.2.10", "prefix": "24", "gateway": "192.0.2.1",
                "dns": ["192.0.2.53"], "read_ok": True}
    monkeypatch.setattr(settings, "_nmcli_get_ipv4", lambda conn: dict(snapshot))
    _no_threads(monkeypatch)
    monkeypatch.setattr(settings, "_current_boot_id", lambda: "boot-1")
    return snapshot


def _apply(admin):
    return admin.post("/api/network/apply", json={"device": "eth0", "method": "auto"})


def test_a_pending_revert_is_written_to_disk(admin, nm):
    res = _apply(admin)
    assert res.status_code == 200, res.get_json()
    record = json.load(open(settings.NETWORK_PENDING_REVERT_FILE))
    assert record["device"] == "eth0" and record["boot_id"] == "boot-1"
    assert record["snapshot"]["address"] == "192.0.2.10"
    assert oct(os.stat(settings.NETWORK_PENDING_REVERT_FILE).st_mode & 0o777) == oct(0o600)


def test_a_second_change_waits_for_the_first(admin, nm):
    assert _apply(admin).status_code == 200
    res = _apply(admin)
    assert res.status_code == 409
    assert "waiting for confirmation" in res.get_json()["error"]


def test_confirming_removes_the_record(admin, nm):
    token = _apply(admin).get_json()["revert_token"]
    assert admin.post("/api/network/confirm", json={"revert_token": token}).status_code == 200
    assert not os.path.exists(settings.NETWORK_PENDING_REVERT_FILE)


def test_an_unreadable_snapshot_is_refused_not_treated_as_dhcp(admin, nm, monkeypatch):
    monkeypatch.setattr(settings, "_nmcli_get_ipv4", lambda conn: {"method": "auto", "address": "", "prefix": "",
                                                                   "gateway": "", "dns": [], "read_ok": False})
    res = _apply(admin)
    assert res.status_code == 503
    assert not os.path.exists(settings.NETWORK_PENDING_REVERT_FILE)


def test_an_unconfirmed_change_is_reverted_after_a_reboot(app, nm, monkeypatch):
    with open(settings.NETWORK_PENDING_REVERT_FILE, "w") as f:
        json.dump({"token": "t1", "device": "eth0", "connection": "Wired 1",
                   "snapshot": {"method": "manual", "address": "192.0.2.10", "prefix": "24",
                                "gateway": "192.0.2.1", "dns": []},
                   "revert_at": 1.0, "confirmed": False, "boot_id": "boot-OLD"}, f)
    applied = {}

    def fake_apply(conn, method, address=None, prefix=None, gateway=None, dns=None):
        applied.update(conn=conn, method=method, address=address)
        return _ok(), _ok()
    monkeypatch.setattr(settings, "_apply_network_ipv4", fake_apply)
    logged = []
    monkeypatch.setattr(settings, "log_chain_of_custody", lambda action, *a, **k: logged.append(action))
    monkeypatch.setattr(settings, "time", _ModuleProxy(real_time, sleep=lambda s: None))

    class _RunNow(_NoThread):
        def start(self):
            self.target()
    _no_threads(monkeypatch, _RunNow)

    settings.resume_pending_network_revert()
    assert applied == {"conn": "Wired 1", "method": "manual", "address": "192.0.2.10"}
    assert "network_config_reverted" in logged
    assert not os.path.exists(settings.NETWORK_PENDING_REVERT_FILE)


def test_a_failed_revert_is_logged_as_a_failure(app, nm, monkeypatch):
    settings.pending_network_revert = {"token": "t2", "device": "eth0", "connection": "Wired 1",
                                       "snapshot": {"method": "auto", "address": "", "prefix": "",
                                                    "gateway": "", "dns": []},
                                       "revert_at": 0, "confirmed": False}
    monkeypatch.setattr(settings, "_apply_network_ipv4", lambda *a, **k: (_ok(rc=4, stderr="device busy"), _ok()))
    logged = []
    monkeypatch.setattr(settings, "log_chain_of_custody", lambda action, *a, **k: logged.append(action))
    settings._run_network_revert("t2", None, "test", "not confirmed in time")
    assert logged == ["network_config_revert_failed"]


# --- busy guard, update app ---------------------------------------------------------------

def test_restart_is_refused_while_a_job_runs(admin, monkeypatch):
    monkeypatch.setattr(settings, "snapshot_job", lambda: {"active": True})
    monkeypatch.setattr(settings, "subprocess", _sub_proxy(lambda *a, **k: pytest.fail("must not run anything")))
    assert admin.post("/api/system/restart_service").status_code == 409


def _fake_git(monkeypatch, *, diverged=False, changed="routes/x.py", smoke_rc=0):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["git", "rev-parse"]:
            return _ok(stdout="aaaaaaa1\n" if cmd[2] == "HEAD" else "bbbbbbb2\n")
        if cmd[:2] == ["git", "fetch"]:
            return _ok()
        if cmd[:2] == ["git", "merge-base"]:
            return _ok(rc=1 if diverged else 0)
        if cmd[:2] == ["git", "diff"]:
            return _ok(stdout=changed + "\n")
        if cmd[:2] == ["git", "merge"]:
            return _ok()
        if cmd[0] == sys.executable:
            return _ok(rc=smoke_rc, stderr="ImportError: boom" if smoke_rc else "")
        if cmd[:2] == ["git", "reset"]:
            return _ok()
        if cmd[:2] == ["git", "log"]:
            return _ok(stdout="bbbbbbb2 a change\n")
        pytest.fail(f"unexpected command {cmd}")
    monkeypatch.setattr(settings, "subprocess", _sub_proxy(fake_run))
    _no_threads(monkeypatch)
    monkeypatch.setattr(settings, "snapshot_job", lambda: {"active": False})
    return calls


def test_update_is_fast_forward_only(admin, monkeypatch):
    calls = _fake_git(monkeypatch, diverged=True)
    res = admin.post("/api/system/git_update")
    assert res.status_code == 409 and "diverged" in res.get_json()["error"]
    assert not any(c[:2] == ["git", "merge"] for c in calls)
    assert _NoThread.started == []


def test_an_update_that_needs_the_installer_is_refused(admin, monkeypatch):
    calls = _fake_git(monkeypatch, changed="requirements.txt")
    res = admin.post("/api/system/git_update")
    assert res.status_code == 409 and "installer" in res.get_json()["error"]
    assert not any(c[:2] == ["git", "merge"] for c in calls)


def test_an_update_that_cannot_start_is_rolled_back(admin, monkeypatch):
    calls = _fake_git(monkeypatch, smoke_rc=1)
    res = admin.post("/api/system/git_update")
    assert res.status_code == 500 and "back on the previous version" in res.get_json()["error"]
    assert ["git", "reset", "--keep", "aaaaaaa1"] in calls
    assert _NoThread.started == []      # never restarted


def test_a_good_update_restarts(admin, monkeypatch):
    calls = _fake_git(monkeypatch)
    res = admin.post("/api/system/git_update")
    assert res.status_code == 200 and res.get_json()["restarting"] is True
    assert ["git", "merge", "--ff-only", "FETCH_HEAD"] in calls
    assert len(_NoThread.started) == 1


# --- passwords and sessions ---------------------------------------------------------------

def test_changing_your_password_keeps_this_session_and_ends_the_others(app):
    _save_user("dana", "first-password-1", "analyst")
    mine = RemoteTestClient(app.test_client())
    other = RemoteTestClient(app.test_client())
    for c in (mine, other):
        assert c.post("/login", json={"username": "dana", "password": "first-password-1"}).status_code == 200
    res = mine.post("/api/system/change_password", json={"current_password": "first-password-1",
                                                         "new_password": "second-password-2"})
    assert res.status_code == 200, res.get_json()
    assert mine.get("/api/whoami").status_code == 200
    assert other.get("/api/whoami").status_code == 401


def test_the_first_account_ends_the_shared_login(app):
    config.save_runtime_config({"pass": "old-shared-plaintext"})
    kiosk = app.test_client()       # 127.0.0.1 / localhost = the physical kiosk
    res = kiosk.post("/api/users/create", json={"username": "boss", "password": "boss-password-1",
                                                "group_id": "admin"})
    assert res.status_code == 200, res.get_json()
    saved = config.load_runtime_config()
    assert "pass" not in saved and "pass_hash" not in saved
