"""routes/settings.py's _parse_hash_list_text() - the save-time validation
every pasted/uploaded hash-list blob goes through before being written to
disk (D2). Skipped (not failed) on a non-POSIX dev machine: routes/
settings.py needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.settings as settings


def test_parses_a_real_valid_sha256_list():
    text = "09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8\n5d41402abc4b2a76b9719d911017c592d81c5cbe14a1a1e4b8c4c1a3f5e1d2b\n"
    hashes, error = settings._parse_hash_list_text(text, "sha256")
    assert error is None
    assert len(hashes) == 2


def test_normalizes_to_lowercase():
    hashes, error = settings._parse_hash_list_text(
        "09ABE58E1025B54B8E020CE1560652F77D13F169F6DC596B5F2BB30111DF3C8\n", "sha256")
    assert error is None
    assert hashes == ["09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8"]


def test_skips_blank_lines_and_leading_comment_lines():
    text = "# NSRL known-bad export\n\n09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8\n\n"
    hashes, error = settings._parse_hash_list_text(text, "sha256")
    assert error is None
    assert len(hashes) == 1


def test_rejects_a_line_with_the_wrong_length_for_the_declared_algorithm():
    # A real, valid MD5 hash - but declared as sha256, which needs 64 hex chars, not 32.
    hashes, error = settings._parse_hash_list_text("5d41402abc4b2a76b9719d911017c592\n", "sha256")
    assert hashes is None
    assert "not a valid 64-character sha256 hash" in error


def test_rejects_non_hex_content():
    hashes, error = settings._parse_hash_list_text("not-a-real-hash-at-all-just-text-here-padding\n", "md5")
    assert hashes is None
    assert error is not None


def test_rejects_an_unsupported_algorithm():
    hashes, error = settings._parse_hash_list_text("abc\n", "sha3-512")
    assert hashes is None
    assert "Unsupported algorithm" in error


def test_rejects_empty_input():
    hashes, error = settings._parse_hash_list_text("", "sha256")
    assert hashes is None
    assert "No valid hashes" in error


def test_enforces_the_max_hash_count_cap(monkeypatch):
    # A tiny cap swapped in for this one test - the real 500,000-line
    # default would be needlessly slow to build/parse just to prove the
    # cap check itself fires.
    monkeypatch.setattr(settings, "HASH_LIST_MAX_HASHES", 3)
    valid_md5 = "5d41402abc4b2a76b9719d911017c592"
    text = "\n".join([valid_md5] * 4)
    hashes, error = settings._parse_hash_list_text(text, "md5")
    assert hashes is None
    assert "max 3" in error
