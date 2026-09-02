"""Tests for core/bugreport_utils.py's parse_bugreport() - needs the real
dumpstate-py package (confirmed live-installable on this station's ARM64
venv, not guessed - see that module's own docstring). Gated by a module-
level pytest.importorskip so this whole file SKIPS on a dev machine
without the package (matching this project's own established convention -
see test_prefetch_utils.py/test_srum_utils.py) and runs for real on the
Pi, where dumpstate-py genuinely is installed. Deliberately does NOT
attempt to construct a genuine real-shaped `adb bugreport` archive (the
project has never had one - see this module's own CLAUDE.md disclosure) -
these tests instead confirm the wrapper's own file-handling/error-path
logic, which is exactly what a zero-coverage module left completely
unverified."""
import zipfile

import pytest

pytest.importorskip("dumpstate", reason="dumpstate-py not installed")

import core.bugreport_utils as br


def test_parse_bugreport_missing_file_returns_clean_error(tmp_path):
    result = br.parse_bugreport(str(tmp_path / 'does_not_exist.zip'))
    assert result['success'] is False
    assert result['sections'] is None


def test_parse_bugreport_not_a_zip_and_not_a_plain_dumpstate_file(tmp_path):
    # A file that's neither a real zip nor parseable as raw dumpstate text -
    # dumpstate-py's own parse() never raises on unrecognized input per the
    # module's own docstring, so this should come back success with mostly-
    # empty sections, not crash.
    garbage = tmp_path / 'garbage.txt'
    garbage.write_text('this is not a real bugreport of any kind')
    result = br.parse_bugreport(str(garbage))
    assert result['success'] is True
    assert isinstance(result['sections'], dict)


def test_parse_bugreport_zip_with_no_dumpstate_member_returns_clean_error(tmp_path):
    bad_zip = tmp_path / 'not_a_bugreport.zip'
    with zipfile.ZipFile(bad_zip, 'w') as zf:
        zf.writestr('unrelated_file.txt', 'nothing to see here')
    result = br.parse_bugreport(str(bad_zip))
    assert result['success'] is False
    assert 'dumpstate-*' in result['error']


def test_parse_bugreport_corrupt_zip_returns_clean_error(tmp_path):
    corrupt = tmp_path / 'corrupt.zip'
    corrupt.write_bytes(b'PK\x03\x04' + b'not actually a valid zip structure')
    result = br.parse_bugreport(str(corrupt))
    assert result['success'] is False
    assert result['sections'] is None
