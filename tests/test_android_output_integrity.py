"""routes/mobile.py's _verify_android_single_file_output() (2026-09-06) -
the post-transfer integrity check added after a real Android device
connected and surfaced a genuine, live-caught data-loss bug: `adb
bugreport` reported a full, error-free 29MB transfer, but the resulting
file on this station's own NFS-backed evidence storage was silently
truncated to exactly 1,048,576 bytes (two full NFS write-RPC chunks) - a
real NFS server stall hit the async writeback AFTER adb's own process
had already exited reporting success, with no error surfaced anywhere.
The previous success check was just `os.path.getsize(output_path) > 0`,
which a truncated-but-nonzero file trivially passes.

Confirmed directly against the real truncated file on the deployed
station before this fix shipped: zipfile.is_zipfile() correctly rejects
it, and a genuine complete zip built the same way passes cleanly - these
tests lock in that exact behavior with self-contained fixtures instead.

Skipped (not failed) on a non-POSIX dev machine: routes.mobile needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import zlib
import zipfile

import pytest

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


def _write_genuine_zip(path, entry_count=5):
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(entry_count):
            zf.writestr(f"file{i}.txt", ("real content " * 200).encode())


def _write_plain_ab(path, tar_bytes, compressed=True):
    header = b"ANDROID BACKUP\n5\n" + (b"1\n" if compressed else b"0\n") + b"none\n"
    payload = zlib.compress(tar_bytes) if compressed else tar_bytes
    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)


class TestBugreportZipIntegrity:
    def test_a_genuine_complete_zip_passes(self, tmp_path):
        path = str(tmp_path / "bugreport.zip")
        _write_genuine_zip(path)
        ok, error = mobile._verify_android_single_file_output("bugreport", path)
        assert ok is True
        assert error is None

    def test_a_file_truncated_after_a_full_report_is_written_is_rejected(self, tmp_path):
        # Mirrors the real live-caught scenario exactly: a genuine, complete
        # zip that then loses its trailing bytes (the "end of central
        # directory" record specifically) - structurally undetectable as
        # complete without this check, since the byte count alone is still
        # nonzero and would have passed the old getsize()>0 check.
        path = str(tmp_path / "bugreport.zip")
        _write_genuine_zip(path, entry_count=20)
        with open(path, "rb") as f:
            full_bytes = f.read()
        with open(path, "wb") as f:
            f.write(full_bytes[: len(full_bytes) // 2])

        ok, error = mobile._verify_android_single_file_output("bugreport", path)
        assert ok is False
        assert "not a valid, complete zip archive" in error

    def test_a_real_world_sized_truncation_partway_through_is_rejected(self, tmp_path):
        # The real, live-observed truncation was suspiciously round (exactly
        # 1,048,576 bytes = 2 x this station's NFS wsize) - reproduce a
        # comparable truncation point (well past the halfway mark, not just
        # a 50%-cut case) on a larger synthetic zip.
        path = str(tmp_path / "bugreport.zip")
        _write_genuine_zip(path, entry_count=2000)
        with open(path, "rb") as f:
            full_bytes = f.read()
        cut_point = 1048576
        assert len(full_bytes) > cut_point * 2, "fixture must be comfortably bigger than the cut point"
        with open(path, "wb") as f:
            f.write(full_bytes[:cut_point])

        ok, error = mobile._verify_android_single_file_output("bugreport", path)
        assert ok is False


class TestBackupAbIntegrity:
    def test_a_genuine_complete_unencrypted_ab_passes(self, tmp_path):
        path = str(tmp_path / "backup.ab")
        _write_plain_ab(path, b"real tar-shaped content " * 5000, compressed=True)
        ok, error = mobile._verify_android_single_file_output("backup", path)
        assert ok is True
        assert error is None

    def test_a_truncated_unencrypted_ab_is_rejected(self, tmp_path):
        path = str(tmp_path / "backup.ab")
        _write_plain_ab(path, b"real tar-shaped content " * 5000, compressed=True)
        with open(path, "rb") as f:
            full_bytes = f.read()
        with open(path, "wb") as f:
            f.write(full_bytes[:-200])

        ok, error = mobile._verify_android_single_file_output("backup", path)
        assert ok is False
        assert "failed a structural integrity check" in error

    def test_an_encrypted_ab_with_no_password_available_is_treated_as_unverifiable_not_corrupt(self, tmp_path):
        # A real, disclosed, accepted limitation - full payload verification
        # of an encrypted backup needs the backup password, which isn't
        # available at acquisition time. The header itself still parses
        # correctly (confirmed before the password-required point is ever
        # reached), so this must never be reported as a corruption failure.
        path = str(tmp_path / "backup.ab")
        header = (b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"deadbeef\n" * 4
                  + b"10000\n" + b"deadbeef\n" * 2)
        with open(path, "wb") as f:
            f.write(header)

        ok, error = mobile._verify_android_single_file_output("backup", path)
        assert ok is True
        assert error is None

    def test_a_malformed_ab_header_is_rejected(self, tmp_path):
        path = str(tmp_path / "backup.ab")
        with open(path, "wb") as f:
            f.write(b"NOT A REAL BACKUP FILE AT ALL")

        ok, error = mobile._verify_android_single_file_output("backup", path)
        assert ok is False


class TestPullModeIsUnaffected:
    def test_pull_mode_always_passes_no_per_mode_check_exists_for_a_directory_tree(self, tmp_path):
        # 'pull' produces a directory of arbitrarily many files, not a
        # single self-verifying container - explicitly out of scope here,
        # confirmed this never blocks a real pull for any reason.
        d = tmp_path / "pulled_files"
        d.mkdir()
        ok, error = mobile._verify_android_single_file_output("pull", str(d))
        assert ok is True
        assert error is None
