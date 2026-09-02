"""Tests for core/sqlite_dissect_utils.py. Mocks subprocess.run (no genuine
sqlite_dissect binary needed to test this module's own request-shaping/
response-handling logic - the real tool's own deleted-row-recovery
correctness was already separately, live-verified against this station's
real installed 1.0.0 package, see the module's own docstring)."""
import os
import subprocess

import core.sqlite_dissect_utils as sd


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_missing_binary_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(tmp_path / 'does_not_exist'))
    result = sd.run_sqlite_dissect(str(tmp_path / 'evidence.db'), str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'not installed' in result['error']


def test_correct_command_construction(tmp_path, monkeypatch):
    # Real, confirmed CLI shape per the module's own docstring: carving and
    # freelist-carving are OFF by default in the real tool, so -c -f must
    # always be passed, and the prefix is derived from the source db's own
    # basename (without extension), never a hardcoded/guessed value.
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    db_path = str(tmp_path / 'mmssms.db')
    out_dir = tmp_path / 'out'
    out_dir.mkdir()

    seen_cmd = {}
    def fake_run(cmd, **kw):
        seen_cmd['cmd'] = cmd
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)

    sd.run_sqlite_dissect(db_path, str(out_dir))
    cmd = seen_cmd['cmd']
    assert cmd[0] == str(fake_bin)
    assert cmd[1] == db_path
    assert '-d' in cmd and cmd[cmd.index('-d') + 1] == str(out_dir)
    assert '-p' in cmd and cmd[cmd.index('-p') + 1] == 'mmssms'
    assert '-e' in cmd and cmd[cmd.index('-e') + 1] == 'csv'
    assert '-c' in cmd
    assert '-f' in cmd


def test_nonzero_exit_is_a_clean_failure_not_a_crash(tmp_path, monkeypatch):
    # Real, confirmed live behavior: sqlite_dissect can raise an outright
    # Python traceback on a malformed/hard-killed-mid-write file - this
    # wrapper must treat ANY non-zero exit as a clean, reported failure.
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='Traceback (most recent call last):\nKeyError: text_encoding'))
    result = sd.run_sqlite_dissect(str(tmp_path / 'x.db'), str(out_dir))
    assert result['success'] is False
    assert 'KeyError' in result['error']


def test_timeout_returns_clean_error(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 300))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = sd.run_sqlite_dissect(str(tmp_path / 'x.db'), str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'timed out' in result['error']


def test_success_with_no_files_written_is_still_success(tmp_path, monkeypatch):
    # A cleanly-closed SQLite file can genuinely have nothing recoverable -
    # confirmed live, see the module's own docstring - this is a real,
    # honest result, not an error.
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = sd.run_sqlite_dissect(str(tmp_path / 'x.db'), str(out_dir))
    assert result['success'] is True
    assert result['files'] == []
    assert 'No output produced' in result['summary']


def test_success_with_files_written_lists_and_summarizes_them(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    (out_dir / 'mmssms-carved-tables.csv').write_text('a,b\n1,2\n')
    (out_dir / 'mmssms-carved-freelists.csv').write_text('a,b\n3,4\n')
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = sd.run_sqlite_dissect(str(tmp_path / 'mmssms.db'), str(out_dir))
    assert result['success'] is True
    assert result['files'] == ['mmssms-carved-freelists.csv', 'mmssms-carved-tables.csv']
    assert '2 output file(s)' in result['summary']


def test_generic_exception_returns_clean_error(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'sqlite_dissect'
    fake_bin.write_text('x')
    monkeypatch.setattr(sd, 'SQLITE_DISSECT_BIN', str(fake_bin))
    def fake_run(cmd, **kw):
        raise OSError("permission denied")
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = sd.run_sqlite_dissect(str(tmp_path / 'x.db'), str(tmp_path / 'out'))
    assert result['success'] is False
    assert 'permission denied' in result['error']
