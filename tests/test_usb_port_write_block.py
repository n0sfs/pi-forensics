"""routes/acquisition.py's /api/toggle_write_block route and the
black-port-only rule shared with Live Collection USB's own build worker
(_unlock_device_for_write(), 2026-09-05).

Two real, live-caught findings this file's tests exist to lock in:
1. Before this fix, /api/toggle_write_block flipped blockdev --setrw
   directly with no exemption-registry update at all - the flag genuinely
   changed for a moment, but list_drives()'s own periodic re-lock (fired
   on every /api/drives poll, which the frontend does routinely) had no
   record of the unlock being legitimate, and silently reverted it within
   seconds. The toggle was, in effect, non-functional for its designed
   purpose.
2. The station's 2 blue (USB 3.0) ports are meant to stay evidence-only,
   permanently write-blocked with no software override at all - neither
   the toggle nor Live Collection USB's build may ever unlock one,
   regardless of confirmation. classify_usb_port()'s own pure-function
   correctness is covered separately in tests/test_paths.py; these tests
   prove the ROUTE-level enforcement and persistence fix, mocking
   classify_usb_port() itself so port-color logic isn't re-tested here.

Skipped (not failed) on a non-POSIX dev machine: core.jobs (imported by
routes.acquisition) needs POSIX-only pwd/fcntl.
"""
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.acquisition as acq
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(acq.acquisition_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


@pytest.fixture(autouse=True)
def _reset_write_lock_state():
    """active_write_unlocked_devices is module-level shared state (by
    design, matching this app's single-shared-job architecture) - reset
    before and after every test so one test's unlock can never leak into
    the next."""
    acq.active_write_unlocked_devices.clear()
    jobs.current_job["active"] = False
    yield
    acq.active_write_unlocked_devices.clear()
    jobs.current_job["active"] = False


class TestToggleWriteBlockRejectsInvalidInput:
    def test_rejects_a_non_whole_disk_device(self, client, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "black")
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda; rm -rf /", "enable": False})
        assert res.status_code == 400
        assert res.get_json()["success"] is False


class TestToggleWriteBlockBluePortRefusal:
    """The core new security rule: unlocking is refused outright for
    anything that isn't a confirmed black-port device - blockdev is never
    even invoked in that case."""

    def test_refuses_to_unlock_a_confirmed_blue_port_device(self, client, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "blue")
        calls = []
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: calls.append(a) or _FakeCompleted())
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": False})
        assert res.status_code == 400
        body = res.get_json()
        assert body["success"] is False
        assert "black" in body["error"].lower()
        assert "blue" in body["error"].lower()
        # blockdev --setrw must never have been reached.
        assert not any("--setrw" in str(c) for c in calls)
        assert "/dev/sda" not in acq.active_write_unlocked_devices

    def test_refuses_to_unlock_an_unclassifiable_device(self, client, monkeypatch):
        # Fail closed: 'unknown' is treated exactly like 'blue', never
        # like 'black'.
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "unknown")
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": False})
        assert res.status_code == 400
        assert res.get_json()["success"] is False
        assert "/dev/sda" not in acq.active_write_unlocked_devices

    def test_re_locking_a_blue_port_device_is_still_permitted(self, client, monkeypatch):
        # Locking (enable=True) is always safe on any port - only the
        # unlock direction is gated.
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "blue")
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: _FakeCompleted(stdout="1"))
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": True})
        assert res.status_code == 200
        assert res.get_json()["success"] is True


class TestToggleWriteBlockPersistsThePermittedUnlock:
    """The real, previously-live bug: an unlock through this route used to
    never register in active_write_unlocked_devices at all, so
    list_drives()'s own periodic relock silently reverted it within
    seconds. Confirms the fix directly - not just that the response looks
    right, but that the exemption registry genuinely reflects it
    afterward, and that the relock path genuinely clears it again."""

    def test_a_permitted_unlock_registers_the_exemption(self, client, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "black")
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: _FakeCompleted(stdout="0"))
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": False})
        assert res.status_code == 200
        assert res.get_json()["success"] is True
        assert "/dev/sda" in acq.active_write_unlocked_devices

    def test_a_failed_blockdev_call_does_not_leave_a_dangling_exemption(self, client, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "black")
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: _FakeCompleted(returncode=1, stderr="boom"))
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": False})
        assert res.status_code == 400
        assert "/dev/sda" not in acq.active_write_unlocked_devices

    def test_relocking_clears_a_previously_registered_exemption(self, client, monkeypatch):
        acq.active_write_unlocked_devices["/dev/sda"] = {"unlocked_at": time.time()}
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "black")
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: _FakeCompleted(stdout="1"))
        res = client.post("/api/toggle_write_block", json={"drive": "/dev/sda", "enable": True})
        assert res.status_code == 200
        assert "/dev/sda" not in acq.active_write_unlocked_devices

    def test_list_drives_no_longer_silently_relocks_a_registered_exemption(self, monkeypatch):
        """Direct proof the coordination gap is closed: a device this
        route just registered as exempt must survive a subsequent
        list_drives()-style relock call untouched."""
        acq.active_write_unlocked_devices["/dev/sda"] = {"unlocked_at": time.time()}
        calls = []
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: calls.append(a) or _FakeCompleted())
        acq._relock_device_for_list_drives("/dev/sda")
        assert calls == []  # never even attempted --setro for an exempted device
        assert "/dev/sda" in acq.active_write_unlocked_devices

    def test_list_drives_does_relock_a_device_with_no_registered_exemption(self, monkeypatch):
        calls = []
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: calls.append(a) or _FakeCompleted())
        acq._relock_device_for_list_drives("/dev/sda")
        assert any("--setro" in str(c) for c in calls)


class TestUnlockDeviceForWriteSharedGate:
    """_unlock_device_for_write() is the one function both the toggle and
    the Live Collection USB build go through - proving it directly (not
    just via the route) covers both callers at once."""

    def test_returns_failure_and_a_clear_message_for_a_blue_port_device(self, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "blue")
        ok, error = acq._unlock_device_for_write("/dev/sda")
        assert ok is False
        assert "black" in error.lower()
        assert "/dev/sda" not in acq.active_write_unlocked_devices

    def test_returns_success_and_registers_the_exemption_for_a_black_port_device(self, monkeypatch):
        monkeypatch.setattr(acq, "classify_usb_port", lambda d: "black")
        monkeypatch.setattr(acq.subprocess, "run", lambda *a, **k: _FakeCompleted())
        ok, error = acq._unlock_device_for_write("/dev/sda")
        assert ok is True
        assert error is None
        assert "/dev/sda" in acq.active_write_unlocked_devices


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
