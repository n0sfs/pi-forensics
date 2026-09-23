"""Case-file primitives: the atomic read/write of a case's {slug}_case.json
and the lock that serialises every read-modify-write of one.

Split out of core/jobs.py (2026-09-23) because core.jobs imports POSIX-only
pwd/fcntl, and core/case_index_db.py - whose tests run on every platform -
needs the same lock and atomic write for ensure_examiner_recorded(). Everything
here is re-exported from core.jobs, so existing imports keep working.
"""
import os
import json
import tempfile
import threading
import functools

from core.paths import case_consolidated_path


class CaseFileUnreadable(Exception):
    """The consolidated case file EXISTS but could not be read or parsed.

    Deliberately distinct from "no case file yet" (fixed 2026-09-15).
    _read_case_file() used to swallow every exception and return an empty
    stub, so a corrupt file - or a transient read error on the NFS share this
    app routinely stores cases on - looked exactly like a brand-new case with
    no events. The caller then went on to WRITE that stub back, and a case's
    entire events/notes/custody/examiners history was replaced by four empty
    keys, with the operation reporting success.

    Raising instead means a mutating path fails loudly and the file on disk is
    left exactly as it was. A file that is genuinely absent, or present and
    empty, still yields the stub - that is a real new case, not a failure."""


def _case_file_stub():
    return {"schema_version": 1, "events": [], "attachments": {"files": [], "reference_urls": []}}


def _read_case_file(case_file):
    """Returns the parsed case record. Raises CaseFileUnreadable if the file
    exists but cannot be read or parsed - see that exception's own docstring
    for why that must not degrade to an empty stub."""
    try:
        with open(case_file, 'r') as f:
            raw = f.read()
    except FileNotFoundError:
        return _case_file_stub()
    except OSError as e:
        raise CaseFileUnreadable(f"{case_file} could not be read: {e}") from e
    if not raw.strip():
        # A zero-byte file is what an interrupted pre-2026-09-15 (non-atomic)
        # write left behind. Treat it as a new case rather than an error -
        # there is no content to lose.
        return _case_file_stub()
    try:
        return json.loads(raw)
    except ValueError as e:
        raise CaseFileUnreadable(
            f"{case_file} is not valid JSON and may be corrupt: {e}. "
            f"Nothing has been modified - the file is left exactly as it is on disk.") from e


def read_case_file_or_stub(case_file):
    """The old, forgiving behaviour, for READ-ONLY display paths that should
    degrade to an empty view rather than fail. Never use this anywhere the
    result is written back - that is precisely the bug CaseFileUnreadable
    exists to prevent."""
    try:
        return _read_case_file(case_file)
    except CaseFileUnreadable:
        return _case_file_stub()


def _write_case_file(case_file, case_record):
    """Atomic replace, not a truncating open (fixed 2026-09-15).

    open(w) truncates the target before a single byte is written, so an
    interrupted write - a crash, a full disk, a dropped NFS mount - left a
    truncated or empty case file behind. Combined with _read_case_file()'s old
    swallow-everything behaviour that was a complete, silent loss of a case's
    history. Writing a sibling temp file and os.replace()-ing it means a
    reader only ever sees the whole old file or the whole new one.

    The temp file is created in the SAME directory on purpose: os.replace is
    only atomic within one filesystem, and a case folder can sit on a mounted
    share while the system temp dir does not."""
    directory = os.path.dirname(os.path.abspath(case_file)) or '.'
    fd, tmp_path = tempfile.mkstemp(prefix='.case_', suffix='.json.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(case_record, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, case_file)
    except BaseException:
        # Leave the real file untouched, and do not leak the temp file.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

# Serialises every read-modify-write of a case JSON (2026-09-23). Atomic
# replace (above) stops TORN files; it does nothing for LOST UPDATES. A job
# worker's completion upsert and an examiner's note/status/save each read the
# whole file, change one part and write the whole thing back - interleaved,
# the last writer silently erased the other's change (a completed
# acquisition's event and hashes, or a just-added note). One process-wide
# re-entrant lock is enough because the service runs a single gunicorn
# worker (--workers 1, gthread - see install.py's ExecStart); if that ever
# changes, this must become a cross-process (fcntl) lock. Case writes are
# small JSON files, so one global lock costs nothing measurable.
CASE_WRITE_LOCK = threading.RLock()


def serialize_case_writes(fn):
    """Route decorator: hold CASE_WRITE_LOCK for the whole read-modify-write."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with CASE_WRITE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


def is_case_record_path(path):
    """True only for a file this app itself writes as a case/job record: a
    case marker ({slug}_case.json in its own case folder) or a no-case job
    report (*_report.json). Routes that accept a client-supplied path and
    WRITE JSON to it must check this - safe_path() only confines a path to
    the evidence root, and without this /api/report/save would overwrite any
    file there, acquired images included (found live 2026-09-23)."""
    if not path or not os.path.isfile(path):
        return False
    if case_consolidated_path(os.path.dirname(path)) == path:
        return True
    return path.endswith('_report.json')
