"""core/config.py - runtime_config.json load/save, and the Fernet-based
encrypt/decrypt helpers auto-mount share credentials (and, since this
session, the config backup/restore feature) are encrypted at rest under."""
import os
import stat

import pytest

import core.config as config


def test_load_runtime_config_returns_empty_dict_when_file_missing(runtime_config_file):
    assert not runtime_config_file.exists()
    assert config.load_runtime_config() == {}


def test_load_runtime_config_refuses_a_corrupted_file(runtime_config_file):
    """2026-10-02 review: a corrupt file used to read as {} - "no users, every
    permission" - and the next settings save wrote that over the real file."""
    runtime_config_file.write_text("{not valid json at all")
    with pytest.raises(config.RuntimeConfigUnreadable):
        config.load_runtime_config()


def test_load_runtime_config_refuses_a_non_object(runtime_config_file):
    runtime_config_file.write_text("[1, 2, 3]")
    with pytest.raises(config.RuntimeConfigUnreadable):
        config.load_runtime_config()


def test_a_failed_save_raises_instead_of_reporting_success(runtime_config_file, monkeypatch):
    def broken_mkstemp(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(config.tempfile, "mkstemp", broken_mkstemp)
    with pytest.raises(config.RuntimeConfigWriteFailed):
        config.save_runtime_config({"a": 1})


def test_save_then_load_round_trips_exactly(runtime_config_file):
    payload = {"pass": "x", "users": [{"username": "a"}], "nested": {"k": [1, 2, 3]}}
    config.save_runtime_config(payload)
    assert config.load_runtime_config() == payload


def test_save_runtime_config_sets_restrictive_permissions(runtime_config_file):
    config.save_runtime_config({"a": 1})
    if os.name != "nt":  # chmod is a documented no-op for regular files on Windows
        mode = stat.S_IMODE(os.stat(runtime_config_file).st_mode)
        assert mode == 0o600


def test_there_is_no_default_shared_password(runtime_config_file, monkeypatch):
    """The shared login used to fall back to the published 'forensics'."""
    monkeypatch.setattr(config, "ADMIN_PASS", None)
    assert not config.legacy_password_ok("forensics")
    assert not config.legacy_password_ok("")


def test_an_explicit_forensic_pass_still_works(runtime_config_file, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_PASS", "env-configured-pass")
    assert config.legacy_password_ok("env-configured-pass")
    assert not config.legacy_password_ok("other")


def test_a_saved_shared_password_is_checked_by_hash_or_legacy_plaintext(runtime_config_file, monkeypatch):
    from werkzeug.security import generate_password_hash
    monkeypatch.setattr(config, "ADMIN_PASS", None)
    config.save_runtime_config({"pass_hash": generate_password_hash("hashed-pass")})
    assert config.legacy_password_ok("hashed-pass")
    assert not config.legacy_password_ok("wrong")
    config.save_runtime_config({"pass": "old-plaintext"})
    assert config.legacy_password_ok("old-plaintext")


def test_last_logins_live_in_their_own_file(runtime_config_file, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LAST_LOGIN_FILE", str(tmp_path / "last_logins.json"))
    config.save_runtime_config({"users": [{"username": "a"}]})
    before = runtime_config_file.read_text()
    config.record_last_login("a", "2026-10-02 10:00:00")
    assert config.get_last_logins() == {"a": "2026-10-02 10:00:00"}
    assert runtime_config_file.read_text() == before   # the credential store is untouched


def test_text_eq_handles_non_ascii(runtime_config_file):
    """hmac.compare_digest raises TypeError for a non-ASCII str."""
    assert config._text_eq("Ångström", "Ångström")
    assert not config._text_eq("Ångström", "Angstrom")


def test_encrypt_decrypt_secret_round_trip(mount_key_file):
    token = config._encrypt_secret("hunter2")
    assert token is not None
    assert token != "hunter2"
    assert config._decrypt_secret(token) == "hunter2"


def test_encrypt_secret_none_or_empty_returns_none(mount_key_file):
    assert config._encrypt_secret("") is None
    assert config._encrypt_secret(None) is None


def test_decrypt_secret_handles_garbage_input_without_raising(mount_key_file):
    assert config._decrypt_secret("not-a-real-fernet-token") == ""
    assert config._decrypt_secret(None) == ""
    assert config._decrypt_secret("") == ""


def test_decrypt_secret_fails_closed_under_a_different_key(mount_key_file, tmp_path, monkeypatch):
    token = config._encrypt_secret("secret-value")
    # Swap in a different key file, simulating a token that was encrypted
    # under a different station's key (or a truncated/replaced key file) -
    # must fail closed (empty string), never raise or return garbage.
    monkeypatch.setattr(config, "MOUNT_KEY_FILE", str(tmp_path / "a-different-key"))
    assert config._decrypt_secret(token) == ""


def test_mount_key_is_generated_once_and_persists(mount_key_file):
    assert not mount_key_file.exists()
    key1 = config._get_or_create_mount_key()
    assert mount_key_file.exists()
    key2 = config._get_or_create_mount_key()
    assert key1 == key2


def test_get_report_defaults_and_custom_case_fields_default_empty(runtime_config_file):
    assert config.get_report_defaults() == {}
    assert config.get_custom_case_fields() == []
