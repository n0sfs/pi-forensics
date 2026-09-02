"""Tests for core/sim_utils.py. Mocks subprocess.run - no genuine pysim
install/PC/SC reader/inserted SIM card needed. As the module's own docstring
discloses, no real SIM/UICC card has ever been read by this project - v1
deliberately returns raw tool stdout unparsed rather than attempting to
parse a shape that's never actually been observed. What this file locks
down is the wrapper logic around the two confirmed-real invocation shapes
(reader enumeration via a direct pyscard snippet; pySim-shell.py's
non-interactive --noprompt shape), not the SIM data itself."""
import subprocess

import core.sim_utils as sim


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- list_pcsc_readers() ---

def test_list_readers_missing_venv_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(tmp_path / 'does_not_exist'))
    result = sim.list_pcsc_readers()
    assert result['success'] is False
    assert result['readers'] == []
    assert 'not installed' in result['error']


def test_list_readers_no_reader_attached_is_success_with_empty_list(tmp_path, monkeypatch):
    # Confirmed real, live behavior - a real, common non-error PC/SC state.
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout='[]\n'))
    result = sim.list_pcsc_readers()
    assert result['success'] is True
    assert result['readers'] == []
    assert result['error'] is None


def test_list_readers_real_readers_are_parsed_from_json(tmp_path, monkeypatch):
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=0, stdout='["Identiv uTrust 3700 F CL Reader(1)"]\n'))
    result = sim.list_pcsc_readers()
    assert result['success'] is True
    assert result['readers'] == ["Identiv uTrust 3700 F CL Reader(1)"]


def test_list_readers_correct_command_construction(tmp_path, monkeypatch):
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        return _FakeCompletedProcess(returncode=0, stdout='[]')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    sim.list_pcsc_readers()
    cmd = seen['cmd']
    assert cmd[0] == str(fake_python)
    assert cmd[1] == '-c'
    assert 'readers()' in cmd[2]
    assert 'json.dumps' in cmd[2]


def test_list_readers_malformed_json_output_returns_clean_error(tmp_path, monkeypatch):
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=0, stdout='not valid json at all'))
    result = sim.list_pcsc_readers()
    assert result['success'] is False
    assert result['readers'] == []
    assert 'Unexpected output' in result['error']


def test_list_readers_nonzero_exit_returns_clean_error(tmp_path, monkeypatch):
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='pcscd is not running'))
    result = sim.list_pcsc_readers()
    assert result['success'] is False
    assert 'pcscd is not running' in result['error']


def test_list_readers_timeout_returns_clean_error(tmp_path, monkeypatch):
    fake_python = tmp_path / 'python3'
    fake_python.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_VENV_PYTHON', str(fake_python))
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 15))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = sim.list_pcsc_readers()
    assert result['success'] is False
    assert 'pcscd' in result['error']


# --- read_sim_card() ---

def test_read_card_missing_shell_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(sim, 'PYSIM_SHELL_BIN', str(tmp_path / 'does_not_exist'))
    result = sim.read_sim_card(0)
    assert result['success'] is False
    assert 'not installed' in result['error']


def test_read_card_correct_noninteractive_command_shape(tmp_path, monkeypatch):
    # Confirmed real, live-verified shape (see module docstring):
    # pySim-shell.py --noprompt -p <reader_index> -e cardinfo
    fake_shell = tmp_path / 'pySim-shell.py'
    fake_shell.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_SHELL_BIN', str(fake_shell))
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        seen['cwd'] = kw.get('cwd')
        return _FakeCompletedProcess(returncode=0, stdout='real card info output')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    sim.read_sim_card(1)
    cmd = seen['cmd']
    assert '--noprompt' in cmd
    assert '-p' in cmd and cmd[cmd.index('-p') + 1] == '1'
    assert '-e' in cmd and cmd[cmd.index('-e') + 1] == 'cardinfo'
    assert seen['cwd'] == sim.PYSIM_DIR


def test_read_card_success_returns_raw_unparsed_output(tmp_path, monkeypatch):
    # v1 deliberately never parses card output into structured fields -
    # a real, disclosed scope decision, not an oversight.
    fake_shell = tmp_path / 'pySim-shell.py'
    fake_shell.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_SHELL_BIN', str(fake_shell))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=0, stdout='ICCID: 8901260...\nIMSI: 310260...'))
    result = sim.read_sim_card(0)
    assert result['success'] is True
    assert 'ICCID' in result['output']
    assert 'IMSI' in result['output']


def test_read_card_no_reader_at_index_is_a_clean_failure_not_a_crash(tmp_path, monkeypatch):
    # Confirmed real, live behavior: pySim-shell.py can raise a raw Python
    # traceback when no reader exists at the requested index.
    fake_shell = tmp_path / 'pySim-shell.py'
    fake_shell.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_SHELL_BIN', str(fake_shell))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='Traceback (most recent call last):\nIndexError: list index out of range'))
    result = sim.read_sim_card(5)
    assert result['success'] is False
    assert 'IndexError' in result['error']


def test_read_card_timeout_returns_clean_error(tmp_path, monkeypatch):
    fake_shell = tmp_path / 'pySim-shell.py'
    fake_shell.write_text('x')
    monkeypatch.setattr(sim, 'PYSIM_SHELL_BIN', str(fake_shell))
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 30))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = sim.read_sim_card(0)
    assert result['success'] is False
    assert 'Timed out' in result['error']
