"""routes/settings.py's _parse_hash_list_text() - the save-time validation
every pasted/uploaded hash-list blob goes through before being written to
disk (D2). Skipped (not failed) on a non-POSIX dev machine: routes/
settings.py needs core.jobs, which imports POSIX-only pwd/fcntl.

Real bug caught by this file's own first run (2026-08-25): the original
version hand-typed a "real" 64-character sha256 hash from memory that
turned out to be only 63 characters - _parse_hash_list_text() correctly
rejected it (the validation logic was never wrong), but every test
asserting a *successful* parse failed as a result. Fixed by computing
every hash value here via hashlib directly rather than typing/recalling
one by hand - see _REAL_SHA256/_REAL_MD5 below.
"""
import hashlib

import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.settings as settings

_REAL_SHA256 = hashlib.sha256(b"pi-forensics-test-fixture").hexdigest()
_REAL_SHA256_2 = hashlib.sha256(b"pi-forensics-test-fixture-2").hexdigest()
_REAL_MD5 = hashlib.md5(b"pi-forensics-test-fixture").hexdigest()

assert len(_REAL_SHA256) == 64 and len(_REAL_MD5) == 32  # sanity-check the fixtures themselves before using them below


def test_parses_a_real_valid_sha256_list():
    text = f"{_REAL_SHA256}\n{_REAL_SHA256_2}\n"
    hashes, error = settings._parse_hash_list_text(text, "sha256")
    assert error is None
    assert len(hashes) == 2


def test_normalizes_to_lowercase():
    hashes, error = settings._parse_hash_list_text(f"{_REAL_SHA256.upper()}\n", "sha256")
    assert error is None
    assert hashes == [_REAL_SHA256]


def test_skips_blank_lines_and_leading_comment_lines():
    text = f"# NSRL known-bad export\n\n{_REAL_SHA256}\n\n"
    hashes, error = settings._parse_hash_list_text(text, "sha256")
    assert error is None
    assert len(hashes) == 1


def test_rejects_a_line_with_the_wrong_length_for_the_declared_algorithm():
    # A real, valid MD5 hash - but declared as sha256, which needs 64 hex chars, not 32.
    hashes, error = settings._parse_hash_list_text(f"{_REAL_MD5}\n", "sha256")
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
    text = "\n".join([_REAL_MD5] * 4)
    hashes, error = settings._parse_hash_list_text(text, "md5")
    assert hashes is None
    assert "max 3" in error
