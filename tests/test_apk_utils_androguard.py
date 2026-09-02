"""Tests for core/apk_utils.py's analyze_apk() against the real androguard
package (confirmed live-installable on this station's ARM64 venv - see
that module's own docstring). Gated by a module-level pytest.importorskip
so this whole file SKIPS on a dev machine without it and runs for real on
the Pi. Deliberately does NOT attempt to hand-construct a genuinely valid,
parseable APK (a real APK needs a compiled/binary AndroidManifest.xml -
not something reasonably hand-buildable without real Android SDK build
tooling, aapt/aapt2, which this station doesn't have either) - these tests
instead confirm the wrapper's own error-handling against the real
library, which is exactly what a zero-coverage module left completely
unverified regardless of a "famous sample" being available."""
import zipfile

import pytest

pytest.importorskip("androguard", reason="androguard not installed")

import core.apk_utils as apk


def test_analyze_apk_missing_file_returns_clean_error(tmp_path):
    result = apk.analyze_apk(str(tmp_path / 'does_not_exist.apk'))
    assert result['success'] is False
    assert result['package'] is None


def test_analyze_apk_not_a_zip_at_all_returns_clean_error(tmp_path):
    garbage = tmp_path / 'not_an_apk.apk'
    garbage.write_bytes(b'this is not a zip file of any kind, just plain bytes')
    result = apk.analyze_apk(str(garbage))
    assert result['success'] is False
    assert 'Could not parse' in result['error']
    assert result['package'] is None


def test_analyze_apk_valid_zip_but_no_manifest_returns_clean_error(tmp_path):
    # A real zip, but with none of the structure androguard's own APK class
    # needs (an AndroidManifest.xml at minimum) - must fail cleanly, not
    # raise.
    empty_zip = tmp_path / 'empty.apk'
    with zipfile.ZipFile(empty_zip, 'w') as zf:
        zf.writestr('README.txt', 'this zip has no Android structure at all')
    result = apk.analyze_apk(str(empty_zip))
    assert result['success'] is False
    assert result['package'] is None
