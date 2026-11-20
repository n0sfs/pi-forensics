"""core/errors.py friendly_error() (2026-11-20): raw "[Errno 30] ..." strings
used to reach the examiner verbatim. Known filesystem errnos become a plain
sentence naming the path; everything else is passed through unchanged."""
import errno
import os

from core.errors import friendly_error


def test_read_only_storage_is_plain_and_names_the_path():
    e = OSError(errno.EROFS, os.strerror(errno.EROFS), "/mnt/case")
    assert friendly_error(e) == "The storage is read-only (/mnt/case)."


def test_permission_error_subclass_is_mapped():
    e = PermissionError(errno.EACCES, os.strerror(errno.EACCES), "/mnt/x")
    assert friendly_error(e) == "Permission denied (/mnt/x)."


def test_full_storage_without_a_path():
    assert friendly_error(OSError(errno.ENOSPC, "No space left on device")) == "The storage is full."


def test_a_two_path_error_names_the_destination():
    e = OSError(errno.EEXIST, "File exists", "/mnt/a", None, "/mnt/b")  # 4th arg is winerror
    assert friendly_error(e) == "Something with that name already exists (/mnt/b)."


def test_unknown_errno_and_non_oserror_pass_through_unchanged():
    assert friendly_error(OSError(errno.EXDEV, "Invalid cross-device link")) == "[Errno 18] Invalid cross-device link"
    assert friendly_error(ValueError("bad value")) == "bad value"
