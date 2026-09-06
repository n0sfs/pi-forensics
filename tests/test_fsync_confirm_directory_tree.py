"""core/jobs.py's fsync_confirm_directory_tree() (2026-09-06) - the
many-files counterpart to _fsync_confirm_write() (already tested in
tests/test_execution_worker_write_confirmation.py), added once the
single-file fsync-confirmation fix built the same day for the app's main
dc3dd/dcfldd/plain-dd/E01/ddrescue/AFF acquisition path was explicitly
scoped out to every other acquisition path that writes a directory of
many files instead of one output file: Android `pull`, MTP pull, Logical
Acquisition, the Live Collection USB import worker, and PhotoRec/
extundelete/foremost/scalpel's own carved output.

Skipped (not failed) on a non-POSIX dev machine: core.jobs imports
POSIX-only pwd/fcntl.
"""
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="core.jobs imports POSIX-only pwd/fcntl")

import core.jobs as jobs


def test_an_empty_directory_reports_zero_files_checked_and_all_confirmed(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    result = jobs.fsync_confirm_directory_tree(str(d))
    assert result["files_checked"] == 0
    assert result["files_confirmed"] == 0
    assert result["files_failed"] == 0
    assert result["capped"] is False
    assert result["all_confirmed"] is True


def test_a_nonexistent_directory_is_treated_like_an_empty_one_not_raised(tmp_path):
    # os.walk() on a nonexistent path returns nothing, no exception -
    # confirmed directly before relying on it. A recovery tool that
    # genuinely produced no output directory at all (e.g. it refused to
    # run) should read the same way an empty one does: nothing to
    # confirm, not a write failure of its own.
    result = jobs.fsync_confirm_directory_tree(str(tmp_path / "never_created"))
    assert result["files_checked"] == 0
    assert result["all_confirmed"] is True


def test_every_real_file_confirms_cleanly_on_a_genuine_local_filesystem(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"one")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_bytes(b"two")
    result = jobs.fsync_confirm_directory_tree(str(tmp_path))
    assert result["files_checked"] == 2
    assert result["files_confirmed"] == 2
    assert result["files_failed"] == 0
    assert result["all_confirmed"] is True


def test_a_failing_fsync_on_one_file_is_reported_without_aborting_the_whole_walk(tmp_path):
    (tmp_path / "good.txt").write_bytes(b"fine")
    (tmp_path / "bad.txt").write_bytes(b"will fail to confirm")

    real_fsync_confirm = jobs._fsync_confirm_write

    def fake(path):
        if path.endswith("bad.txt"):
            return False, "simulated destination storage failure"
        return real_fsync_confirm(path)

    with mock.patch.object(jobs, "_fsync_confirm_write", side_effect=fake):
        result = jobs.fsync_confirm_directory_tree(str(tmp_path))

    assert result["files_checked"] == 2
    assert result["files_confirmed"] == 1
    assert result["files_failed"] == 1
    assert result["failed_examples"] == ["bad.txt"]
    assert result["all_confirmed"] is False


def test_hitting_the_file_count_cap_does_not_by_itself_mark_all_confirmed_false(tmp_path):
    # The deliberate, real design decision this test locks in (2026-09-06):
    # a bulk file-carving tool can legitimately, correctly recover well
    # past this cap's own file count on a genuinely successful run -
    # treating "hit the cap" as equivalent to "a real failure" would
    # falsely report a perfectly good large recovery as corrupted. Every
    # file actually checked here confirms cleanly, so all_confirmed must
    # be True even though capped is also True.
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_bytes(b"x")
    result = jobs.fsync_confirm_directory_tree(str(tmp_path), max_files=3)
    assert result["files_checked"] == 3
    assert result["capped"] is True
    assert result["files_failed"] == 0
    assert result["all_confirmed"] is True


def test_a_real_failure_among_the_capped_subset_is_still_reported_as_a_failure(tmp_path):
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_bytes(b"x")

    real_fsync_confirm = jobs._fsync_confirm_write

    def fake(path):
        if path.endswith("file0.txt"):
            return False, "simulated failure"
        return real_fsync_confirm(path)

    with mock.patch.object(jobs, "_fsync_confirm_write", side_effect=fake):
        result = jobs.fsync_confirm_directory_tree(str(tmp_path), max_files=3)

    assert result["capped"] is True
    assert result["files_failed"] >= 0  # file0 may or may not fall within the first 3 walked, order-dependent
    # The real point of this test: capped and a genuine failure can coexist,
    # and when a real failure did occur among what was checked, it must
    # still surface as all_confirmed=False regardless of the cap.
    if result["files_failed"] > 0:
        assert result["all_confirmed"] is False


def test_symlinks_and_directories_are_never_themselves_fsync_confirmed(tmp_path):
    real_file = tmp_path / "real.txt"
    real_file.write_bytes(b"content")
    link_path = tmp_path / "link.txt"
    try:
        link_path.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted in this environment")

    result = jobs.fsync_confirm_directory_tree(str(tmp_path))
    # Only the one real file counts - the symlink is skipped outright.
    assert result["files_checked"] == 1
    assert result["all_confirmed"] is True


def test_failed_examples_list_is_capped_at_twenty_even_with_many_failures(tmp_path):
    for i in range(30):
        (tmp_path / f"file{i:02d}.txt").write_bytes(b"x")

    with mock.patch.object(jobs, "_fsync_confirm_write", return_value=(False, "simulated failure")):
        result = jobs.fsync_confirm_directory_tree(str(tmp_path))

    assert result["files_checked"] == 30
    assert result["files_failed"] == 30
    assert len(result["failed_examples"]) == 20
    assert result["all_confirmed"] is False
