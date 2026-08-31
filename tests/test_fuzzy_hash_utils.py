"""core/fuzzy_hash_utils.py - the real py-tlsh package isn't installed in
this dev environment (source-only, confirmed live-compilable on the Pi's
real ARM64 venv instead), so these tests mock the tlsh module's own real,
documented function-level API (tlsh.hash(bytes) -> str, tlsh.diff(a, b)
-> int) via sys.modules injection - the same "mock the library's real,
confirmed shape" pattern this project already uses for pypff."""
import sys
import types

import pytest

import core.fuzzy_hash_utils as fh


class _FakeTlsh(types.ModuleType):
    def __init__(self, hash_fn=None, diff_fn=None):
        super().__init__('tlsh')
        self._hash_fn = hash_fn or (lambda data: 'T1' + '0' * 70)
        self._diff_fn = diff_fn or (lambda a, b: 0 if a == b else 50)

    def hash(self, data):
        return self._hash_fn(data)

    def diff(self, a, b):
        return self._diff_fn(a, b)


@pytest.fixture
def fake_tlsh(monkeypatch):
    fake = _FakeTlsh()
    monkeypatch.setitem(sys.modules, 'tlsh', fake)
    return fake


def test_compute_tlsh_hash_returns_a_real_digest(tmp_path, fake_tlsh):
    f = tmp_path / "sample.bin"
    f.write_bytes(b'A' * 2000)  # comfortably past the min-size floor
    result = fh.compute_tlsh_hash(str(f))
    assert result["success"] is True
    assert result["hash"] == 'T1' + '0' * 70
    assert result["error"] is None


def test_compute_tlsh_hash_rejects_a_too_small_file_gracefully(tmp_path, fake_tlsh):
    f = tmp_path / "tiny.bin"
    f.write_bytes(b'x' * 10)
    result = fh.compute_tlsh_hash(str(f))
    assert result["success"] is True
    assert result["hash"] is None
    assert "too small" in result["note"].lower()


def test_compute_tlsh_hash_handles_the_real_tnull_sentinel(tmp_path, monkeypatch):
    fake = _FakeTlsh(hash_fn=lambda data: 'TNULL')
    monkeypatch.setitem(sys.modules, 'tlsh', fake)
    f = tmp_path / "uniform.bin"
    f.write_bytes(b'\x00' * 2000)
    result = fh.compute_tlsh_hash(str(f))
    assert result["success"] is True
    assert result["hash"] is None
    assert "could not compute" in result["note"].lower()


def test_compute_tlsh_hash_missing_file_returns_clean_error(tmp_path, fake_tlsh):
    result = fh.compute_tlsh_hash(str(tmp_path / "does_not_exist.bin"))
    assert result["success"] is False
    assert result["hash"] is None


def test_compute_tlsh_hash_missing_library_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'tlsh', None)  # simulates "not installed"
    f = tmp_path / "sample.bin"
    f.write_bytes(b'A' * 2000)
    result = fh.compute_tlsh_hash(str(f))
    assert result["success"] is False
    assert "not installed" in result["error"].lower()


def test_compare_tlsh_hashes_identical_is_similar(fake_tlsh):
    result = fh.compare_tlsh_hashes('T1AAAA', 'T1AAAA')
    assert result["success"] is True
    assert result["distance"] == 0
    assert result["similar"] is True


def test_compare_tlsh_hashes_far_apart_is_not_similar(monkeypatch):
    fake = _FakeTlsh(diff_fn=lambda a, b: 500)
    monkeypatch.setitem(sys.modules, 'tlsh', fake)
    result = fh.compare_tlsh_hashes('T1AAAA', 'T1BBBB')
    assert result["success"] is True
    assert result["distance"] == 500
    assert result["similar"] is False


def test_compare_tlsh_hashes_respects_the_documented_threshold_boundary(monkeypatch):
    fake = _FakeTlsh(diff_fn=lambda a, b: fh.FUZZY_HASH_DEFAULT_SIMILARITY_THRESHOLD)
    monkeypatch.setitem(sys.modules, 'tlsh', fake)
    result = fh.compare_tlsh_hashes('T1AAAA', 'T1BBBB')
    assert result["similar"] is True  # <= threshold, not strictly <


def test_compare_tlsh_hashes_requires_both_values(fake_tlsh):
    assert fh.compare_tlsh_hashes('', 'T1AAAA')["success"] is False
    assert fh.compare_tlsh_hashes('T1AAAA', None)["success"] is False


def test_compare_tlsh_hashes_handles_a_malformed_hash_gracefully(monkeypatch):
    def _raise(a, b):
        raise ValueError("invalid hash format")
    fake = _FakeTlsh(diff_fn=_raise)
    monkeypatch.setitem(sys.modules, 'tlsh', fake)
    result = fh.compare_tlsh_hashes('not-a-real-tlsh-hash', 'also-not-real')
    assert result["success"] is False
    assert "invalid" in result["error"].lower() or "compare" in result["error"].lower()
