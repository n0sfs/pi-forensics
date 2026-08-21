"""core/config.py - runtime_config.json load/save, and the Fernet-based
encrypt/decrypt helpers auto-mount share credentials (and, since this
session, the config backup/restore feature) are encrypted at rest under."""
import os
import stat

import core.config as config


def test_load_runtime_config_returns_empty_dict_when_file_missing(runtime_config_file):
    assert not runtime_config_file.exists()
    assert config.load_runtime_config() == {}


def test_load_runtime_config_returns_empty_dict_on_corrupted_json(runtime_config_file):
    runtime_config_file.write_text("{not valid json at all")
    assert config.load_runtime_config() == {}


def test_save_then_load_round_trips_exactly(runtime_config_file):
    payload = {"pass": "x", "users": [{"username": "a"}], "nested": {"k": [1, 2, 3]}}
    config.save_runtime_config(payload)
    assert config.load_runtime_config() == payload


def test_save_runtime_config_sets_restrictive_permissions(runtime_config_file):
    config.save_runtime_config({"a": 1})
    if os.name != "nt":  # chmod is a documented no-op for regular files on Windows
        mode = stat.S_IMODE(os.stat(runtime_config_file).st_mode)
        assert mode == 0o600


def test_get_active_admin_pass_falls_back_to_env_default(runtime_config_file):
    assert config.get_active_admin_pass() == config.ADMIN_PASS


def test_get_active_admin_pass_prefers_saved_value(runtime_config_file):
    config.save_runtime_config({"pass": "a-changed-password"})
    assert config.get_active_admin_pass() == "a-changed-password"


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
