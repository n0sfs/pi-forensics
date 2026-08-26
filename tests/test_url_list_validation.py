"""routes/settings.py's _parse_url_list_text() - the save-time validation
every pasted URL-list blob goes through before being written to disk
(2026-08-26, Linux-DFIR-tools follow-up: URL Lists). Skipped (not failed)
on a non-POSIX dev machine: routes/settings.py needs core.jobs, which
imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.settings as settings


def test_parses_a_real_valid_url_list():
    text = "http://evil.example/bin.sh\nhttps://example.com/malicious/x.exe\n"
    urls, error = settings._parse_url_list_text(text)
    assert error is None
    assert urls == ["http://evil.example/bin.sh", "https://example.com/malicious/x.exe"]


def test_tolerates_blank_lines_and_comment_lines():
    text = "# a comment\n\nhttp://evil.example/bin.sh\n   \n"
    urls, error = settings._parse_url_list_text(text)
    assert error is None
    assert urls == ["http://evil.example/bin.sh"]


def test_rejects_a_line_with_no_http_scheme():
    text = "http://good.example/x\nftp://not-http-or-https/y\n"
    urls, error = settings._parse_url_list_text(text)
    assert urls is None
    assert "Line 2" in error


def test_rejects_a_bare_domain_with_no_scheme():
    urls, error = settings._parse_url_list_text("evil.example/bin.sh\n")
    assert urls is None
    assert error is not None


def test_rejects_an_implausibly_long_line():
    text = "http://evil.example/" + ("a" * settings.URL_LIST_MAX_URL_LENGTH) + "\n"
    urls, error = settings._parse_url_list_text(text)
    assert urls is None
    assert error is not None


def test_rejects_empty_text():
    urls, error = settings._parse_url_list_text("")
    assert urls is None
    assert "No valid URLs" in error


def test_accepts_uppercase_scheme_case_insensitively():
    urls, error = settings._parse_url_list_text("HTTPS://Evil.Example/X\n")
    assert error is None
    assert urls == ["HTTPS://Evil.Example/X"]
