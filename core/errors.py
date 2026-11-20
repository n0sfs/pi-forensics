"""Plain-language messages for the filesystem errors examiners actually hit.

A raw OSError reads as "[Errno 30] Read-only file system: '/mnt/...'", which
tells an examiner nothing about what to do. friendly_error() turns the common
ones into a sentence that says what went wrong and where, and falls back to
str(e) for anything else, so no detail is ever lost - just made readable.
"""
import errno

_PLAIN = {
    errno.EACCES: "Permission denied",
    errno.EPERM: "Permission denied",
    errno.EROFS: "The storage is read-only",
    errno.ENOSPC: "The storage is full",
    errno.EDQUOT: "The storage quota is full",
    errno.ENOENT: "The file or folder no longer exists",
    errno.EEXIST: "Something with that name already exists",
    errno.ENOTDIR: "A part of the path is a file, not a folder",
    errno.EISDIR: "That is a folder, not a file",
    errno.ENAMETOOLONG: "The name is too long",
    errno.EIO: "The storage returned an I/O error - the drive or network share may have gone away",
    errno.ENOTCONN: "The network share is not connected",
    errno.ESTALE: "The network share was disconnected (stale handle) - remount it",
    errno.ETIMEDOUT: "The storage stopped answering (timed out)",
    errno.EBUSY: "The file or device is busy",
}


def friendly_error(e):
    """A readable message for e. OSErrors with a known errno become
    '<plain sentence> (<path>).'; anything else is str(e) unchanged."""
    if isinstance(e, OSError) and e.errno in _PLAIN:
        where = e.filename2 or e.filename
        text = _PLAIN[e.errno]
        return f"{text} ({where})." if where else f"{text}."
    return str(e)
