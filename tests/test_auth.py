"""core/auth.py - unit-level tests for the two-tier check_auth() model,
session-validity re-derivation, the user-group/permission system (with
particular attention to the "Admin can never be weakened" invariant), and
the brute-force lockout tracker. End-to-end session/idle-timeout behavior
through real HTTP requests lives in tests/test_login_flow.py instead."""
from werkzeug.security import generate_password_hash

import core.config as config
import core.auth as auth


def _save_user(username, password, group_id="analyst", extra=None):
    cfg = config.load_runtime_config()
    user = {"username": username, "password_hash": generate_password_hash(password), "group_id": group_id}
    user.update(extra or {})
    cfg.setdefault("users", []).append(user)
    config.save_runtime_config(cfg)
    return user


# --- check_auth() ---

def test_check_auth_legacy_single_account_when_no_users_exist(runtime_config_file):
    assert auth.check_auth(config.ADMIN_USER, config.get_active_admin_pass())
    assert not auth.check_auth(config.ADMIN_USER, "wrong-password")
    assert not auth.check_auth("nobody", config.get_active_admin_pass())


def test_check_auth_multi_user_mode_once_real_users_exist(runtime_config_file):
    _save_user("alice", "s3cret-phrase")
    assert auth.check_auth("alice", "s3cret-phrase")
    assert not auth.check_auth("alice", "wrong")
    assert not auth.check_auth("someone-else", "s3cret-phrase")
    # The legacy single-shared-account path stops being checked entirely
    # once real per-user accounts exist - matches check_auth()'s own
    # documented two-tier priority.
    assert not auth.check_auth(config.ADMIN_USER, config.get_active_admin_pass())


# --- _session_user_still_valid() ---

def test_session_user_still_valid_legacy_mode(runtime_config_file):
    assert auth._session_user_still_valid(config.ADMIN_USER)
    assert not auth._session_user_still_valid("someone-else")
    assert not auth._session_user_still_valid(None)


def test_session_user_still_valid_dies_once_the_user_is_deleted(runtime_config_file):
    _save_user("bob", "pw")
    assert auth._session_user_still_valid("bob")
    config.save_runtime_config({"users": []})
    assert not auth._session_user_still_valid("bob")


# --- User groups / permissions ---

def test_admin_group_is_always_full_access_even_if_the_saved_record_is_weakened(runtime_config_file):
    # A tampered/corrupted "admin" entry on disk (or a bug that wrote one)
    # must never actually take effect - Admin is synthesized fresh on every
    # call, never read from runtime_config.json (see get_user_groups()).
    config.save_runtime_config({"user_groups": [
        {"id": "admin", "name": "Admin", "permissions": {k: False for k, _ in auth.PERMISSION_KEYS}},
    ]})
    admin = auth.find_group("admin", auth.get_user_groups())
    assert all(admin["permissions"].values())


def test_admin_group_cannot_be_found_missing_and_has_every_key(runtime_config_file):
    admin = auth.find_group("admin", auth.get_user_groups())
    assert set(admin["permissions"]) == {k for k, _ in auth.PERMISSION_KEYS}


def test_analyst_group_default_matches_legacy_standard_role(runtime_config_file):
    analyst = auth.find_group("analyst", auth.get_user_groups())
    assert analyst["permissions"]["acquisition"] is True
    assert analyst["permissions"]["mobile"] is True
    assert analyst["permissions"]["recovery"] is True
    assert analyst["permissions"]["file_explorer"] is True
    assert analyst["permissions"]["reporting"] is True
    assert analyst["permissions"]["settings"] is False
    assert analyst["permissions"]["manage_users"] is False


def test_analyst_group_permissions_are_editable_and_persist(runtime_config_file):
    config.save_runtime_config({"user_groups": [
        {"id": "analyst", "name": "Analyst", "permissions": {**auth._default_analyst_permissions(), "settings": True}},
    ]})
    analyst = auth.find_group("analyst", auth.get_user_groups())
    assert analyst["permissions"]["settings"] is True


def test_custom_group_round_trips_and_normalizes_unknown_keys(runtime_config_file):
    config.save_runtime_config({"user_groups": [
        {"id": "photo_tech", "name": "Photo Tech", "permissions": {"file_explorer": True, "made_up_key": True}},
    ]})
    grp = auth.find_group("photo_tech", auth.get_user_groups())
    assert grp["permissions"]["file_explorer"] is True
    assert grp["permissions"]["acquisition"] is False  # unspecified -> False
    assert "made_up_key" not in grp["permissions"]  # unknown keys dropped, not passed through


def test_get_user_group_id_migrates_legacy_role_field():
    assert auth.get_user_group_id({"role": "admin"}) == "admin"
    assert auth.get_user_group_id({"role": "standard"}) == "analyst"
    # A real user record predating groups, with no role field at all -
    # still falls back to analyst, not None (an empty/falsy dict is the
    # "no user at all" sentinel instead - see the next test).
    assert auth.get_user_group_id({"username": "legacy_user"}) == "analyst"
    assert auth.get_user_group_id({"group_id": "custom1", "role": "admin"}) == "custom1"  # group_id wins
    assert auth.get_user_group_id(None) is None
    assert auth.get_user_group_id({}) is None


def test_get_current_user_permissions_local_kiosk_and_legacy_are_full_access(runtime_config_file, monkeypatch):
    class FakeG:
        forensic_user = "local-kiosk"
    monkeypatch.setattr(auth, "g", FakeG())
    assert all(auth.get_current_user_permissions().values())

    FakeG.forensic_user = "anyone"  # legacy single-shared-account mode: no users[] saved
    assert all(auth.get_current_user_permissions().values())


def test_get_current_user_permissions_unknown_user_gets_nothing(runtime_config_file, monkeypatch):
    _save_user("real_user", "pw")
    class FakeG:
        forensic_user = "not_a_real_user"
    monkeypatch.setattr(auth, "g", FakeG())
    perms = auth.get_current_user_permissions()
    assert not any(perms.values())


# --- Brute-force lockout ---

def test_lockout_engages_after_max_failures_and_clears_on_success():
    key = "unit-test-client"
    for _ in range(auth.MAX_AUTH_FAILURES - 1):
        auth._record_auth_failure(key)
        assert not auth._is_locked_out(key)
    auth._record_auth_failure(key)
    assert auth._is_locked_out(key)
    auth._record_auth_success(key)
    assert not auth._is_locked_out(key)


def test_lockout_is_scoped_per_client_key():
    auth._record_auth_failure("client-a")
    assert not auth._is_locked_out("client-b")
