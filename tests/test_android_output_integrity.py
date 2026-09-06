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

Extended the same day, once the "does the many-files case (pull mode)
need this too" question was explicitly resolved: 'pull' now gets a real
check via core/jobs.py's fsync_confirm_directory_tree() (TestPullMode
WriteConfirmation replaces the old TestPullModeIsUnaffected), and
'bugreport'/'backup' both gained an explicit fsync-confirm BEFORE their
own structural check, closing a narrow residual timing gap: a plain
re-read only reliably catches a truncation that's ALREADY manifested in
the file's own on-disk size, not a writeback that's still genuinely
pending at that exact instant.

Skipped (not failed) on a non-POSIX dev machine: routes.mobile needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
import zlib
import zipfile
from unittest import mock

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

    def test_a_failed_fsync_confirmation_is_caught_before_the_structural_check_even_runs(self, tmp_path):
        # Defense-in-depth added 2026-09-06: even a genuinely complete zip
        # must fail here if the write itself can't be durably confirmed -
        # proves fsync-confirm runs FIRST, not just as a fallback after a
        # structural check that would otherwise have passed this file.
        path = str(tmp_path / "bugreport.zip")
        _write_genuine_zip(path)
        with mock.patch.object(mobile, "_fsync_confirm_write", return_value=(False, "simulated destination storage failure")):
            ok, error = mobile._verify_android_single_file_output("bugreport", path)
        assert ok is False
        assert "simulated destination storage failure" in error


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

    def test_a_failed_fsync_confirmation_is_caught_before_the_structural_check_even_runs(self, tmp_path):
        path = str(tmp_path / "backup.ab")
        _write_plain_ab(path, b"real tar-shaped content " * 5000, compressed=True)
        with mock.patch.object(mobile, "_fsync_confirm_write", return_value=(False, "simulated destination storage failure")):
            ok, error = mobile._verify_android_single_file_output("backup", path)
        assert ok is False
        assert "simulated destination storage failure" in error


class TestPullModeWriteConfirmation:
    """'pull' produces a directory of arbitrarily many files, not one
    structurally self-verifying container - originally left entirely out
    of scope (see this module's own now-superseded TestPullModeIsUnaffected
    class), now checked via core/jobs.py's fsync_confirm_directory_tree()
    once that scope decision was explicitly revisited (2026-09-06)."""

    def test_a_directory_of_genuinely_written_files_passes(self, tmp_path):
        d = tmp_path / "pulled_files"
        d.mkdir()
        (d / "photo1.jpg").write_bytes(b"real photo bytes")
        (d / "photo2.jpg").write_bytes(b"more real photo bytes")
        ok, error = mobile._verify_android_single_file_output("pull", str(d))
        assert ok is True
        assert error is None

    def test_an_empty_pull_directory_still_passes_nothing_to_confirm_is_not_a_failure(self, tmp_path):
        d = tmp_path / "pulled_files"
        d.mkdir()
        ok, error = mobile._verify_android_single_file_output("pull", str(d))
        assert ok is True
        assert error is None

    def test_a_file_that_fails_write_confirmation_is_reported_with_a_clear_reason(self, tmp_path):
        d = tmp_path / "pulled_files"
        d.mkdir()
        (d / "good.jpg").write_bytes(b"fine")
        (d / "bad.jpg").write_bytes(b"will fail to confirm")

        # fsync_confirm_directory_tree() (core/jobs.py) calls
        # _fsync_confirm_write() as a name resolved within core.jobs's OWN
        # module namespace, not routes.mobile's imported copy of the same
        # name - patching mobile._fsync_confirm_write here would silently
        # do nothing (confirmed live: the first version of this test did
        # exactly that and failed, since the real call this test needs to
        # intercept happens one level deeper than mobile._verify_android_
        # single_file_output()'s own direct bugreport/backup calls). This
        # is the same "bare import creates an independent binding" lesson
        # this codebase has already learned for active_proc/RUNTIME_CONFIG_
        # FILE/EVIDENCE_ROOT - patch where the code actually looks the name
        # up, not wherever else it happens to also be imported.
        import core.jobs as jobs
        real_fsync_confirm = jobs._fsync_confirm_write

        def fake(path):
            if path.endswith("bad.jpg"):
                return False, "simulated destination storage failure"
            return real_fsync_confirm(path)

        with mock.patch.object(jobs, "_fsync_confirm_write", side_effect=fake):
            ok, error = mobile._verify_android_single_file_output("pull", str(d))
        assert ok is False
        assert "1 of 2 pulled file(s) could not have their write confirmed" in error
        assert "bad.jpg" in error

    def test_hitting_the_directory_tree_check_own_safety_cap_does_not_by_itself_fail_a_clean_pull(self, tmp_path):
        # A real pull of a phone's full media library can legitimately,
        # correctly produce more files than fsync_confirm_directory_tree()'s
        # own safety cap - this must never be treated as a failure on its
        # own if nothing actually confirmed cleanly is missing. Mocks the
        # helper's own return value directly (its max_files default is
        # captured at def-time, so patching the module-level constant
        # after the fact wouldn't actually change a no-argument call).
        d = tmp_path / "pulled_files"
        d.mkdir()
        capped_but_clean = {"files_checked": 20000, "files_confirmed": 20000, "files_failed": 0,
                             "failed_examples": [], "capped": True, "all_confirmed": True}
        with mock.patch.object(mobile, "fsync_confirm_directory_tree", return_value=capped_but_clean):
            ok, error = mobile._verify_android_single_file_output("pull", str(d))
        assert ok is True
        assert error is None
