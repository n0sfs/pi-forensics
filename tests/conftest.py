"""Shared pytest fixtures for the Pi Forensics Suite test suite.

Scope note: this app is a Raspberry Pi appliance. A few of its deeper
modules (core/jobs.py, and routes/*.py blueprints that import it - which is
most of them) import POSIX-only stdlib modules (pwd, fcntl) at module level,
and several blueprints depend on hardware-adjacent third-party packages
(pytsk3, mvt, reportlab) that aren't installed everywhere a test run might
happen. Test modules that need one of those call pytest.importorskip() at
the top, so:
  - On a non-POSIX dev machine (e.g. Windows), the core/paths.py,
    core/config.py, core/auth.py, and routes/auth_routes.py tests still run
    in full; anything needing core/jobs.py is skipped, not failed.
  - On Linux (the real deployment target, and CI - see
    .github/workflows/tests.yml) everything here imports and runs cleanly
    with just Flask + psutil + cryptography installed - nothing in this
    suite touches real hardware, sudo, or an actual block device. Routes
    that genuinely need those (drive imaging, mobile device pulls, Sleuth
    Kit image browsing, PDF export, MVT scanning) aren't covered here yet -
    see CLAUDE.md's "hardware validation" open items for what's still
    verified manually against the live station instead.

Nothing here ever reads or writes this repo's own real files - every
fixture that touches "runtime_config.json" or similar points core.config's
module-level path constants at a throwaway file inside pytest's own tmp_path
for the duration of one test (monkeypatch, auto-reverted after).
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def runtime_config_file(tmp_path, monkeypatch):
    """Points core.config's runtime_config.json at an empty (nonexistent
    until first save) file in a temp dir for one test."""
    import core.config as config
    cfg_path = tmp_path / "runtime_config.json"
    monkeypatch.setattr(config, "RUNTIME_CONFIG_FILE", str(cfg_path))
    return cfg_path


@pytest.fixture
def mount_key_file(tmp_path, monkeypatch):
    """Points core.config's auto-mount Fernet key file at a temp path, so
    encrypt/decrypt tests never touch (or depend on) a real station's key."""
    import core.config as config
    key_path = tmp_path / ".mount_key"
    monkeypatch.setattr(config, "MOUNT_KEY_FILE", str(key_path))
    return key_path


@pytest.fixture
def secret_key_file(tmp_path, monkeypatch):
    """Points core.config's Flask session-signing key file at a temp path,
    mirroring mount_key_file above."""
    import core.config as config
    key_path = tmp_path / ".flask_secret_key"
    monkeypatch.setattr(config, "SECRET_KEY_FILE", str(key_path))
    return key_path


@pytest.fixture
def hash_lists_dir(tmp_path, monkeypatch):
    """Points core.config's D2 hash-list storage directory at a fresh temp
    dir, so a test never touches (or depends on) a real station's saved
    hash lists."""
    import core.config as config
    hl_dir = tmp_path / "hash_lists"
    monkeypatch.setattr(config, "HASH_LISTS_DIR", str(hl_dir))
    return hl_dir


@pytest.fixture
def evidence_root(tmp_path, monkeypatch):
    """Points core.paths.safe_path()'s sandbox root at a fresh temp dir."""
    import core.paths as paths
    root = tmp_path / "evidence_root"
    root.mkdir()
    resolved = os.path.realpath(str(root))
    monkeypatch.setattr(paths, "EVIDENCE_ROOT", resolved)
    return resolved


@pytest.fixture(autouse=True)
def _clear_auth_lockout_state():
    """core.auth's brute-force lockout tracker (auth_fail_tracker) and
    last-login-persist throttle are plain module-level dicts, keyed by
    client IP / username - real, deliberate global state on the live
    station (see core/auth.py), but it would otherwise leak between test
    functions that all happen to look like the same client IP (Flask's test
    client defaults every request to 127.0.0.1), silently making one test's
    failed-login attempts count against a completely unrelated later test.
    Autouse so every test starts and ends with a clean slate without having
    to remember to ask for this."""
    import core.auth as auth
    auth.auth_fail_tracker.clear()
    yield
    auth.auth_fail_tracker.clear()


@pytest.fixture(autouse=True)
def _clear_case_artifact_backfill_throttle():
    """core.case_index_db._artifact_backfill_last_run (added 2026-09-01, a
    real live-measured performance fix - see that module's own docstring)
    is a plain module-level dict, keyed by case_folder absolute path - real,
    deliberate global state on the live station, but it would otherwise leak
    between any two test functions that happen to reuse the exact same
    case_folder path (most tests use a fresh tmp_path-derived path so this
    is rarely hit in practice, but it's the same real leak risk
    _clear_auth_lockout_state already exists to close for its own dicts, so
    it gets the same autouse treatment rather than relying on every test
    remembering it exists)."""
    import core.case_index_db as case_index_db
    case_index_db._artifact_backfill_last_run.clear()
    yield
    case_index_db._artifact_backfill_last_run.clear()


@pytest.fixture(autouse=True)
def _clear_reporting_tags_flagged_cache():
    """routes/reporting.py's _tags_flagged_cache (added 2026-09-05, a real
    live-measured NFS-latency fix - see _count_notable_tagged_items_
    station_wide()'s own docstring) is a single module-level dict, not
    keyed by anything - so unlike the two throttles above it would leak
    into EVERY later test's own result, not just ones that happen to reuse
    the same key, if left uncleared. routes.reporting needs core.jobs
    (POSIX-only pwd/fcntl) to import at all, so this import is wrapped the
    same defensive way every POSIX-gated fixture/test file in this suite
    already handles that - importorskip isn't available inside a fixture
    body, so a plain try/except ImportError makes this a silent no-op on a
    non-POSIX dev machine instead of an import-time collection error."""
    try:
        import routes.reporting as reporting
    except ImportError:
        yield
        return
    reporting._tags_flagged_cache["computed_at"] = 0.0
    yield
    reporting._tags_flagged_cache["computed_at"] = 0.0


class RemoteTestClient:
    """Wraps a Flask test client so every request looks like it came from a
    real remote/LAN address (203.0.113.5, a reserved TEST-NET-3 address
    that can never collide with a real deployment) instead of Flask's test
    client default of 127.0.0.1. That default matters a lot here: this
    app's is_local_kiosk_request() treats 127.0.0.1 as the physically-
    trusted kiosk touchscreen and bypasses auth for it entirely - left
    unpatched, every route test below would silently succeed regardless of
    session/permission state, masking exactly the kind of bug these tests
    exist to catch. See core/auth.py's is_local_kiosk_request()."""
    REMOTE_ADDR = "203.0.113.5"

    def __init__(self, raw_client):
        self._raw = raw_client

    def get(self, *args, **kwargs):
        kwargs.setdefault("environ_base", {})["REMOTE_ADDR"] = self.REMOTE_ADDR
        return self._raw.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs.setdefault("environ_base", {})["REMOTE_ADDR"] = self.REMOTE_ADDR
        return self._raw.post(*args, **kwargs)

    def put(self, *args, **kwargs):
        kwargs.setdefault("environ_base", {})["REMOTE_ADDR"] = self.REMOTE_ADDR
        return self._raw.put(*args, **kwargs)

    def delete(self, *args, **kwargs):
        kwargs.setdefault("environ_base", {})["REMOTE_ADDR"] = self.REMOTE_ADDR
        return self._raw.delete(*args, **kwargs)

    def session_transaction(self, *args, **kwargs):
        return self._raw.session_transaction(*args, **kwargs)


def login_user_session(client, username):
    """Directly seeds a valid, non-idle session for `username`, bypassing a
    real POST /login round trip - used by tests that only care about what
    happens once a session already exists (permission checks, backup/
    restore), not login itself (see tests/test_login_flow.py for that)."""
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()
