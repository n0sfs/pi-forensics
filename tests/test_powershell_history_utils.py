"""Tests for core/powershell_history_utils.py, built against real
PSReadLine on-disk file content (the exact backtick+newline continuation
byte sequence PSReadLine's own write path produces, per its real
confirmed source - see the module's own docstring), not mocks."""
import os

import core.powershell_history_utils as psh


def test_parse_powershell_history_simple_single_line_commands(tmp_path):
    p = tmp_path / 'ConsoleHost_history.txt'
    p.write_text("Get-Process\nGet-ChildItem -Recurse\n", encoding='utf-8')

    records = psh.parse_powershell_history_file(str(p))
    assert len(records) == 2
    assert records[0]["artifact_type"] == "powershell_console_history"
    assert records[0]["value"] == "Get-Process"
    assert records[0]["timestamp"] is None
    assert records[1]["value"] == "Get-ChildItem -Recurse"
    assert records[0]["extra"]["host_name"] == "ConsoleHost"
    assert records[0]["extra"]["is_multiline"] is False


def test_parse_powershell_history_reassembles_a_real_multiline_command(tmp_path):
    # Exact real on-disk byte sequence PSReadLine's own write path
    # produces for a genuine 3-line pasted/typed command block (backtick
    # inserted immediately before every embedded newline) - traced by
    # hand against the real confirmed mechanism before trusting this as
    # a fixture, not assumed.
    raw = "foreach ($i in 1..3) {`\n  Write-Host $i`\n}\nGet-Process\n"
    p = tmp_path / 'ConsoleHost_history.txt'
    p.write_text(raw, encoding='utf-8')

    records = psh.parse_powershell_history_file(str(p))
    assert len(records) == 2
    assert records[0]["value"] == "foreach ($i in 1..3) {\n  Write-Host $i\n}"
    assert records[0]["extra"]["is_multiline"] is True
    assert records[0]["title"].endswith('...')  # truncated/marked since it's multi-line
    assert records[1]["value"] == "Get-Process"
    assert records[1]["extra"]["is_multiline"] is False


def test_parse_powershell_history_derives_host_name_from_filename(tmp_path):
    p = tmp_path / 'Visual Studio Code Host_history.txt'
    p.write_text("code --version\n", encoding='utf-8')
    records = psh.parse_powershell_history_file(str(p))
    assert records[0]["extra"]["host_name"] == "Visual Studio Code Host"


def test_parse_powershell_history_empty_file_returns_empty(tmp_path):
    p = tmp_path / 'Windows PowerShell ISE Host_history.txt'
    p.write_text("", encoding='utf-8')
    assert psh.parse_powershell_history_file(str(p)) == []


def test_parse_powershell_history_missing_file_returns_empty(tmp_path):
    assert psh.parse_powershell_history_file(str(tmp_path / 'ConsoleHost_history.txt')) == []


def test_parse_powershell_history_caps_command_count(tmp_path):
    p = tmp_path / 'ConsoleHost_history.txt'
    p.write_text("\n".join(f"cmd{i}" for i in range(psh.POWERSHELL_HISTORY_MAX_COMMANDS + 500)), encoding='utf-8')
    records = psh.parse_powershell_history_file(str(p))
    assert len(records) == psh.POWERSHELL_HISTORY_MAX_COMMANDS


def test_find_powershell_history_files_requires_psreadline_parent_dir(tmp_path):
    # A same-named-suffix file OUTSIDE a real PSReadLine folder must never
    # match - the whole point of the parent-directory check.
    wrong_dir = tmp_path / 'SomeOtherFolder'
    wrong_dir.mkdir()
    (wrong_dir / 'ConsoleHost_history.txt').write_bytes(b'x')

    real_dir = tmp_path / 'Roaming' / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine'
    real_dir.mkdir(parents=True)
    (real_dir / 'ConsoleHost_history.txt').write_bytes(b'x')
    (real_dir / 'Windows PowerShell ISE Host_history.txt').write_bytes(b'')

    found, truncated = psh.find_powershell_history_files(str(tmp_path))
    basenames = sorted(os.path.basename(p) for p in found)
    assert basenames == ['ConsoleHost_history.txt', 'Windows PowerShell ISE Host_history.txt']
    assert truncated is False


def test_find_powershell_history_files_matches_psreadline_case_insensitively(tmp_path):
    real_dir = tmp_path / 'psreadline'  # real-world casing can vary
    real_dir.mkdir()
    (real_dir / 'ConsoleHost_history.txt').write_bytes(b'x')
    found, _truncated = psh.find_powershell_history_files(str(tmp_path))
    assert len(found) == 1
