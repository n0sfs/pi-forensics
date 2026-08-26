"""routes/acquisition.py's _resolve_acquisition_source() 3-way dispatch
(BitLocker/LUKS/VeraCrypt) and the DECRYPTED_SOURCE_KIND_LABELS/
DECRYPTED_SOURCE_LOCK_FN dicts that replaced a 2-way if/else once VeraCrypt
made "else means luks" fragile (2026-08-26, gap-closing round). These are
pure dict-lookup/dispatch logic - no subprocess calls, unlike
_veracrypt_unlock()/_luks_unlock()/_dislocker_unlock() themselves, which
(matching this project's own established precedent - no unit tests exist
for those either) are verified live against real hardware instead, not
unit-tested with mocks.

Skipped (not failed) on a non-POSIX dev machine: routes/acquisition.py
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.acquisition as acquisition


def test_resolve_acquisition_source_real_device_when_no_mount_matches():
    source, kind, meta = acquisition._resolve_acquisition_source("/dev/sdb")
    assert source == "/dev/sdb"
    assert kind == "real_device"
    assert meta is None


def test_resolve_acquisition_source_matches_bitlocker_mount(monkeypatch):
    monkeypatch.setattr(acquisition, "active_bitlocker_mounts", {
        "mount1": {"source_path": "/opt/pi-forensics/.bitlocker_mounts/mount1/dislocker-file", "device": "/dev/sdb1"},
    })
    monkeypatch.setattr(acquisition, "active_luks_mounts", {})
    monkeypatch.setattr(acquisition, "active_veracrypt_mounts", {})
    source, kind, meta = acquisition._resolve_acquisition_source(
        "/opt/pi-forensics/.bitlocker_mounts/mount1/dislocker-file")
    assert kind == "decrypted_file"
    assert meta == {"kind": "bitlocker", "mount_id": "mount1", "device": "/dev/sdb1"}


def test_resolve_acquisition_source_matches_luks_mount(monkeypatch):
    monkeypatch.setattr(acquisition, "active_bitlocker_mounts", {})
    monkeypatch.setattr(acquisition, "active_luks_mounts", {
        "pif_luks_abc": {"mapper_path": "/dev/mapper/pif_luks_abc", "device": "/dev/sdb1"},
    })
    monkeypatch.setattr(acquisition, "active_veracrypt_mounts", {})
    source, kind, meta = acquisition._resolve_acquisition_source("/dev/mapper/pif_luks_abc")
    assert kind == "decrypted_block_device"
    assert meta == {"kind": "luks", "mount_id": "pif_luks_abc", "device": "/dev/sdb1"}


def test_resolve_acquisition_source_matches_veracrypt_mount(monkeypatch):
    # The real, load-bearing new case - VeraCrypt reuses the exact same
    # "decrypted_block_device" source_kind LUKS already established,
    # confirmed live that cryptsetup's own `open --type tcrypt` produces
    # the identical /dev/mapper/<name> shape luksOpen already does.
    monkeypatch.setattr(acquisition, "active_bitlocker_mounts", {})
    monkeypatch.setattr(acquisition, "active_luks_mounts", {})
    monkeypatch.setattr(acquisition, "active_veracrypt_mounts", {
        "pif_veracrypt_xyz": {"mapper_path": "/dev/mapper/pif_veracrypt_xyz", "device": "/dev/sdc1"},
    })
    source, kind, meta = acquisition._resolve_acquisition_source("/dev/mapper/pif_veracrypt_xyz")
    assert kind == "decrypted_block_device"
    assert meta == {"kind": "veracrypt", "mount_id": "pif_veracrypt_xyz", "device": "/dev/sdc1"}


def test_resolve_acquisition_source_all_three_mount_dicts_populated_simultaneously(monkeypatch):
    # Confirms the 3-way lookup checks each dict independently and doesn't
    # short-circuit incorrectly when more than one type happens to have an
    # active mount at once (an edge case that shouldn't arise in real use,
    # but the dispatch logic itself must still be correct).
    monkeypatch.setattr(acquisition, "active_bitlocker_mounts", {
        "bl1": {"source_path": "/bl/path", "device": "/dev/sda1"},
    })
    monkeypatch.setattr(acquisition, "active_luks_mounts", {
        "pif_luks_1": {"mapper_path": "/dev/mapper/pif_luks_1", "device": "/dev/sdb1"},
    })
    monkeypatch.setattr(acquisition, "active_veracrypt_mounts", {
        "pif_veracrypt_1": {"mapper_path": "/dev/mapper/pif_veracrypt_1", "device": "/dev/sdc1"},
    })
    _, kind_bl, meta_bl = acquisition._resolve_acquisition_source("/bl/path")
    _, kind_luks, meta_luks = acquisition._resolve_acquisition_source("/dev/mapper/pif_luks_1")
    _, kind_vc, meta_vc = acquisition._resolve_acquisition_source("/dev/mapper/pif_veracrypt_1")
    assert (kind_bl, meta_bl["kind"]) == ("decrypted_file", "bitlocker")
    assert (kind_luks, meta_luks["kind"]) == ("decrypted_block_device", "luks")
    assert (kind_vc, meta_vc["kind"]) == ("decrypted_block_device", "veracrypt")


def test_decrypted_source_kind_labels_and_lock_fn_cover_all_three_kinds():
    assert set(acquisition.DECRYPTED_SOURCE_KIND_LABELS.keys()) == {"bitlocker", "luks", "veracrypt"}
    assert set(acquisition.DECRYPTED_SOURCE_LOCK_FN.keys()) == {"bitlocker", "luks", "veracrypt"}
    assert acquisition.DECRYPTED_SOURCE_LOCK_FN["bitlocker"] is acquisition._dislocker_lock
    assert acquisition.DECRYPTED_SOURCE_LOCK_FN["luks"] is acquisition._luks_lock
    assert acquisition.DECRYPTED_SOURCE_LOCK_FN["veracrypt"] is acquisition._veracrypt_lock


def test_veracrypt_detect_never_returns_a_definitive_true_or_false():
    # The honest, disclosure-over-silent-promise design: VeraCrypt volumes
    # have no fixed signature at all, so _detect_veracrypt() must never
    # claim a definitive answer the way _detect_bitlocker/_detect_luks can
    # (best-effort, via blkid) - only a real invalid-input case (None) or
    # the fixed "cannot be auto-detected" response.
    result = acquisition._detect_veracrypt("/dev/sdb1")
    assert result["is_veracrypt"] is None
    assert "note" in result
    assert acquisition._detect_veracrypt("not-a-real-device-path") is None


def test_veracrypt_detect_image_never_returns_a_definitive_true_or_false(tmp_path):
    import core.paths as paths
    import unittest.mock as mock
    fake_image = tmp_path / "test.dd"
    fake_image.write_bytes(b"\x00" * 100)
    with mock.patch.object(paths, "EVIDENCE_ROOT", str(tmp_path)):
        result = acquisition._detect_veracrypt_image(str(fake_image), 0)
    assert result["is_veracrypt"] is None
    assert "note" in result
