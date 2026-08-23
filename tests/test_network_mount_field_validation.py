"""routes/settings.py's _do_network_mount() - rejects a host/share_path/
user value starting with '-' before it ever reaches sshfs/mount/smbclient's
own argument parser, a real finding from the 2026-08-22 security audit.

These fields end up combined into a single argv element for the mount tool
(e.g. sftp_source = f"{user}@{host}:{share_path}") - list-form subprocess
calls mean this was never a shell-injection risk, but an unvalidated
flag-like value could still be misread as an option by the target binary
rather than the positional data it's meant to be.

Only the REJECTION path is tested here - the function returns (False,
error) before touching any filesystem/subprocess for a bad field, which is
safe to call directly on any machine. The acceptance path (a normal share
actually mounts) already has extensive live-verification coverage
documented elsewhere in this project's history; re-mocking subprocess to
re-prove that isn't this test's job.

Skipped (not failed) on a non-POSIX dev machine: routes/settings.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

from routes.settings import _do_network_mount


def test_a_flag_like_host_is_rejected_before_any_subprocess_call():
    success, error = _do_network_mount("nfs", "-oProxyCommand=evil", "/share", "/mnt/x", "", "", "")
    assert success is False
    assert "Host" in error and "-" in error


def test_a_flag_like_share_path_is_rejected():
    success, error = _do_network_mount("sftp", "192.168.1.5", "-oExec=x", "/mnt/x", "user", "pw", "")
    assert success is False
    assert "Share path" in error


def test_a_flag_like_username_is_rejected():
    success, error = _do_network_mount("sftp", "192.168.1.5", "/share", "/mnt/x", "-oProxyCommand=evil", "pw", "")
    assert success is False
    assert "Username" in error
