"""Tests for core/idevicecrashreport_utils.py. Mocks subprocess.run - no
genuine idevicecrashreport binary/connected iPhone needed. This project has
never had a real iOS device connect at any point in its history, so the
`-e`/`-k` flag semantics documented in the module's own docstring (confirmed
against the real installed binary's --help) are what this file locks in as
a regression - never pass a command shape without both flags, since that
would silently make a pull destructive to the device's own crash reports."""
import os
import subprocess

import core.idevicecrashreport_utils as icr


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_correct_command_always_includes_keep_and_extract_flags(tmp_path, monkeypatch):
    # -k (keep, never remove from device) and -e (extract/decode locally)
    # must ALWAYS be present - a live-device mutation must never be a
    # silent default, per the module's own documented reasoning.
    out_dir = tmp_path / 'out'
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)
    icr.pull_ios_crash_reports('00008030-ABCDEF', str(out_dir))
    cmd = seen['cmd']
    assert cmd == ['idevicecrashreport', '-u', '00008030-ABCDEF', '-k', '-e', str(out_dir)]


def test_creates_output_dir_before_running(tmp_path, monkeypatch):
    out_dir = tmp_path / 'crash_reports'
    assert not out_dir.exists()
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    icr.pull_ios_crash_reports('UDID', str(out_dir))
    assert out_dir.is_dir()


def test_success_lists_every_pulled_file_recursively(tmp_path, monkeypatch):
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    (out_dir / 'crash1.ips').write_text('x')
    sub = out_dir / 'DiagnosticLogs'
    sub.mkdir()
    (sub / 'crash2.crash').write_text('x')
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = icr.pull_ios_crash_reports('UDID', str(out_dir))
    assert result['success'] is True
    assert result['files'] == [os.path.join('DiagnosticLogs', 'crash2.crash'), 'crash1.ips']


def test_nonzero_exit_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='ERROR: Could not connect to lockdownd'))
    result = icr.pull_ios_crash_reports('UDID', str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'lockdownd' in result['error']


def test_missing_binary_returns_clean_error(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = icr.pull_ios_crash_reports('UDID', str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'not installed' in result['error']


def test_timeout_returns_clean_error(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 60))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = icr.pull_ios_crash_reports('UDID', str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'Timed out' in result['error']


def test_generic_exception_returns_clean_error(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        raise OSError("device disconnected")
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = icr.pull_ios_crash_reports('UDID', str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'device disconnected' in result['error']


def test_success_with_no_crash_reports_returns_empty_files_list(tmp_path, monkeypatch):
    out_dir = tmp_path / 'out'
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = icr.pull_ios_crash_reports('UDID', str(out_dir))
    assert result['success'] is True
    assert result['files'] == []
