"""Tests for core/apk_utils.py's URL-extraction regex - a plain module-
level constant, no androguard import needed to test it (the androguard
import only happens inside analyze_apk() itself). analyze_apk() end-to-end
needs the real androguard package (confirmed live-installable on this
station's ARM64 venv against a real, legitimately-signed APK - see the
module's own docstring) - those tests live in a separate file,
tests/test_apk_utils_androguard.py, gated by a module-level
pytest.importorskip (matching this project's own established convention)."""
import sys

import core.apk_utils as apk


def test_url_regex_extracts_a_plain_https_url():
    data = b'some binary junk http://example.com/api/v1 more junk'
    matches = [m.group(0) for m in apk._URL_RE.finditer(data)]
    assert b'http://example.com/api/v1' in matches


def test_url_regex_extracts_multiple_urls():
    data = b'https://a.example.com/x https://b.example.com/y'
    matches = [m.group(0) for m in apk._URL_RE.finditer(data)]
    assert len(matches) == 2


def test_url_regex_stops_at_whitespace_and_quotes():
    data = b'"https://example.com/path" and <https://other.example.com/x>'
    matches = [m.group(0) for m in apk._URL_RE.finditer(data)]
    assert b'https://example.com/path' in matches
    assert b'https://other.example.com/x' in matches
    # Never includes the surrounding quote/angle-bracket delimiters
    assert all(not m.endswith((b'"', b'>')) for m in matches)


def test_url_regex_rejects_urls_shorter_than_the_minimum():
    # Requires at least 4 chars after the scheme - "http://a" is too short
    # to be a meaningful embedded URL, not a real find.
    data = b'http://a'
    matches = list(apk._URL_RE.finditer(data))
    assert matches == []


def test_url_regex_ignores_non_http_schemes():
    data = b'ftp://example.com/file.zip file:///etc/passwd'
    matches = list(apk._URL_RE.finditer(data))
    assert matches == []


def test_analyze_apk_missing_androguard_returns_clean_error(tmp_path, monkeypatch):
    # Forces the import to fail regardless of whether androguard genuinely
    # is installed in this environment (setting a module's own sys.modules
    # entry to None is a documented CPython mechanism that makes any
    # subsequent "import <that exact name>" raise ImportError) - this way
    # the same test is meaningful both here (where androguard genuinely
    # isn't installed) and, unchanged, on the Pi (where it genuinely is),
    # rather than relying on ambient package-presence state either way.
    monkeypatch.setitem(sys.modules, 'androguard.core.apk', None)
    result = apk.analyze_apk(str(tmp_path / 'anything.apk'))
    assert result['success'] is False
    assert 'not installed' in result['error']
    assert result['package'] is None
