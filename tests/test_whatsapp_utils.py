"""Tests for core/whatsapp_utils.py. Mocks subprocess.run throughout - no
genuine adb/wadecrypt binary needed to test this module's own request-
shaping/response-handling logic. The real wadecrypt CLI's positional-
argument order and success/failure behavior were already separately,
live-verified via a real synthetic key+crypt14 round trip (see the
module's own docstring) - what this file owns is the wrapper logic
around that confirmed-real shape."""
import subprocess

import core.whatsapp_utils as wa


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr='', stdout_bytes=None):
        self.returncode = returncode
        self.stdout = stdout_bytes if stdout_bytes is not None else stdout
        self.stderr = stderr


# --- pull_whatsapp_key_file() ---

def test_pull_key_correct_command_construction(monkeypatch):
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        return _FakeCompletedProcess(returncode=0, stdout_bytes=b'a-real-16-byte-k')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    wa.pull_whatsapp_key_file('EMULATOR123', '/tmp/key')
    cmd = seen['cmd']
    assert cmd == ['adb', '-s', 'EMULATOR123', 'shell', 'su', '-c',
                    'cat /data/data/com.whatsapp/files/key']


def test_pull_key_success_writes_bytes_to_dest(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    monkeypatch.setattr(subprocess, 'run',
                         lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b'\x01\x02realkeybytes'))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is True
    assert result['path'] == str(dest)
    assert dest.read_bytes() == b'\x01\x02realkeybytes'


def test_pull_key_nonzero_exit_returns_clean_error(monkeypatch):
    # text=False in the real call (raw device bytes, not decoded text), so
    # res.stderr is genuinely bytes here, matching the real subprocess
    # contract - not a plain str the way most of this app's other
    # subprocess wrappers (text=True) would receive it.
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr=b'su: not found'))
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'su: not found' in result['error']


def test_pull_key_nonzero_exit_with_no_stderr_gets_a_helpful_fallback(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=1))
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'rooted' in result['error']


def test_pull_key_empty_output_is_a_clean_error_not_a_zero_byte_file(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b''))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is False
    assert not dest.exists()


def test_pull_key_oversized_response_is_rejected_as_likely_su_denial(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    oversized = b'x' * (wa.WHATSAPP_KEY_MAX_BYTES + 1)
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=oversized))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is False
    assert 'su-denial' in result['error']
    assert not dest.exists()


def test_pull_key_timeout_returns_clean_error(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 20))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'Timed out' in result['error']


def test_pull_key_unwritable_dest_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b'realkey'))
    bad_dest = str(tmp_path / 'no_such_dir' / 'key')
    result = wa.pull_whatsapp_key_file('SERIAL', bad_dest)
    assert result['success'] is False
    assert 'Could not write key file' in result['error']


# --- decrypt_whatsapp_backup() ---

def test_decrypt_missing_binary_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(tmp_path / 'does_not_exist'))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'not installed' in result['error']


def test_decrypt_correct_positional_argument_order(tmp_path, monkeypatch):
    # Confirmed real, live-verified order: [keyfile] [encrypted] [decrypted]
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'msgstore.db'
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        out_path.write_bytes(b'a decrypted sqlite db')
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)
    wa.decrypt_whatsapp_backup(str(tmp_path / 'msgstore.db.crypt14'), str(tmp_path / 'key'), str(out_path))
    cmd = seen['cmd']
    assert cmd == [str(fake_bin), str(tmp_path / 'key'), str(tmp_path / 'msgstore.db.crypt14'), str(out_path)]


def test_decrypt_success_strips_ansi_codes_from_log(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'out.db'
    def fake_run(cmd, **kw):
        out_path.write_bytes(b'real decrypted content')
        return _FakeCompletedProcess(returncode=0, stderr='\x1b[32mDecryption successful\x1b[0m')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(out_path))
    assert result['success'] is True
    assert result['log'] == 'Decryption successful'
    assert '\x1b' not in result['log']


def test_decrypt_nonzero_exit_from_a_real_wrong_key_traceback_is_a_clean_failure(tmp_path, monkeypatch):
    # Real, confirmed live behavior: a wrong/malformed key can make
    # wadecrypt itself raise a raw Python traceback rather than fail
    # gracefully.
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='Traceback (most recent call last):\nvalueError: Invalid key'))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'Invalid key' in result['error']


def test_decrypt_success_exit_but_no_output_file_is_still_a_failure(tmp_path, monkeypatch):
    # A wrong key can also fail "quietly" with exit 0 and no real output -
    # never trust a success exit code alone.
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'key may not match' in result['error']


def test_decrypt_success_exit_but_empty_output_file_is_still_a_failure(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'out.db'
    def fake_run(cmd, **kw):
        out_path.write_bytes(b'')  # written but genuinely empty
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(out_path))
    assert result['success'] is False


def test_decrypt_timeout_returns_clean_error(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 300))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'timed out' in result['error']
