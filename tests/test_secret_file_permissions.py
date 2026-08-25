"""core/config.py's secret-file-writing functions - _get_or_create_secret_key(),
_get_or_create_mount_key(), save_runtime_config(). All three previously wrote
the file with default (umask-dependent) permissions first, then chmod()'d it
to 0600 afterward - a real, if brief, window where the file could be more
permissive than intended (2026-08-22 security audit, Informational finding).
Fixed 2026-08-25 to create the file with its final 0600 mode atomically (via
os.open()'s explicit mode / tempfile.mkstemp()'s own documented 0600
guarantee), closing that window entirely. This file is the regression test
for that fix - no POSIX-only import (core.jobs) is needed here, so it runs
everywhere; the permission-bit assertions themselves are POSIX-only (Windows
has no equivalent octal mode bits) and are skipped, not failed, elsewhere.
"""
import os
import sys
import glob

import pytest

import core.config as config

_posix_only = pytest.mark.skipif(sys.platform == 'win32', reason="POSIX file-mode bits don't apply on Windows")


def _mode(path):
    return os.stat(str(path)).st_mode & 0o777


@_posix_only
def test_get_or_create_secret_key_creates_file_at_0600(secret_key_file):
    config._get_or_create_secret_key()
    assert secret_key_file.exists()
    assert _mode(secret_key_file) == 0o600


def test_get_or_create_secret_key_returns_same_key_on_second_call(secret_key_file):
    first = config._get_or_create_secret_key()
    second = config._get_or_create_secret_key()
    assert first == second
    assert len(first) == 64  # secrets.token_hex(32) -> 64 hex chars


def test_get_or_create_secret_key_reads_back_a_pre_existing_file_rather_than_overwriting_it(secret_key_file):
    # Simulates the FileExistsError race path (a second process/worker
    # winning the create) - the pre-existing content must survive, not be
    # silently overwritten by a second, different generated key.
    secret_key_file.write_text("a-pre-existing-key-from-elsewhere")
    result = config._get_or_create_secret_key()
    assert result == "a-pre-existing-key-from-elsewhere"


@_posix_only
def test_get_or_create_mount_key_creates_file_at_0600(mount_key_file):
    config._get_or_create_mount_key()
    assert mount_key_file.exists()
    assert _mode(mount_key_file) == 0o600


def test_get_or_create_mount_key_returns_same_key_on_second_call(mount_key_file):
    first = config._get_or_create_mount_key()
    second = config._get_or_create_mount_key()
    assert first == second


def test_get_or_create_mount_key_reads_back_a_pre_existing_file_rather_than_overwriting_it(mount_key_file):
    from cryptography.fernet import Fernet
    real_key = Fernet.generate_key()
    mount_key_file.write_bytes(real_key)
    result = config._get_or_create_mount_key()
    assert result == real_key


@_posix_only
def test_save_runtime_config_creates_file_at_0600(runtime_config_file):
    config.save_runtime_config({"hello": "world"})
    assert runtime_config_file.exists()
    assert _mode(runtime_config_file) == 0o600


@_posix_only
def test_save_runtime_config_stays_at_0600_on_a_repeat_save(runtime_config_file):
    # The real-world case this fix mattered most for - unlike the two key
    # files (written once, ever), this file rewrites on every settings
    # save, so the old open()-then-chmod() window reopened every time.
    config.save_runtime_config({"first": "save"})
    config.save_runtime_config({"second": "save"})
    assert _mode(runtime_config_file) == 0o600


def test_save_runtime_config_round_trips_content_correctly(runtime_config_file):
    config.save_runtime_config({"users": [{"username": "admin"}], "keyword_lists": []})
    loaded = config.load_runtime_config()
    assert loaded == {"users": [{"username": "admin"}], "keyword_lists": []}


def test_save_runtime_config_a_second_save_correctly_replaces_the_first(runtime_config_file):
    config.save_runtime_config({"version": 1})
    config.save_runtime_config({"version": 2})
    assert config.load_runtime_config() == {"version": 2}


def test_save_runtime_config_leaves_no_leftover_temp_file(runtime_config_file, tmp_path):
    config.save_runtime_config({"a": 1})
    config.save_runtime_config({"a": 2})
    leftovers = glob.glob(os.path.join(str(tmp_path), ".runtime_config_*.tmp"))
    assert leftovers == []
