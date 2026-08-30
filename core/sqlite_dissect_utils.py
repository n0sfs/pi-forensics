"""SQLite Dissect (DoD Cyber Crime Center) - recovers deleted rows still
present in a SQLite file's own unallocated space, freeblocks, and any
surviving WAL/rollback-journal file. Wraps the `sqlite_dissect` console
script as a subprocess (this app's dominant tool-integration pattern - see
MVT/Volatility3/hashdeep/ExifTool/ALEAPP/iLEAPP) rather than importing its
internal API - confirmed live installable as a pure-Python `py3-none-any`
wheel on this station's real ARM64 venv, with no independently-confirmed
stable Python import surface to build against instead.

Real CLI flags confirmed live against the installed 1.0.0 package's own
--help output (a real, useful correction over an earlier guess): output
goes to `-d/--directory`, files are named via `-p/--file-prefix`, export
format(s) via `-e/--export {text,csv,sqlite,xlsx,case}`, and - important -
carving is OFF by default: `-c/--carve` must be passed to recover any
table data at all, `-f/--carve-freelists` additionally carves freelist
pages (the tool's own --help marks this "under development").

HONEST DISCLOSURE, confirmed via real live testing on this station, not
assumed: SQLite's own B-Tree page management frequently compacts a
deleted row's freed byte range immediately on DELETE+COMMIT, before any
acquisition ever happens - three separate hand-built test scenarios this
session (a 3-row single-page table, a 100-row multi-page table, both
closed normally) left literally zero recoverable trace of the deleted
row's own bytes anywhere in the file, confirmed via a raw byte-level grep
independent of this tool entirely. This is a genuine, real limitation of
what any deleted-row-recovery tool (this one included) can find in an
already-cleanly-closed SQLite file - it is not a defect in this wrapper
or in sqlite_dissect itself. The scenario most likely to yield real
recovered data is a database acquired WITH a surviving `-wal`/rollback-
journal file still present alongside it (an app mid-transaction at the
moment of seizure/acquisition, not yet checkpointed) - this app's own
existing acquisition tools already preserve any such sidecar files
untouched, since they copy every file in a source folder as-is. Confirmed
separately: a real hard-killed-mid-write test file (a genuinely malformed/
unusual database header) made sqlite_dissect itself crash with a Python
traceback (KeyError on an unset text-encoding field) rather than fail
gracefully - this wrapper treats ANY non-zero exit (traceback or not) as
a clean, reported failure, never letting a crash propagate.
"""
import os
import subprocess

from core.config import MVT_BIN_DIR

SQLITE_DISSECT_TIMEOUT_SECONDS = 300
# sqlite_dissect is a pip console-script (see requirements.txt), same as
# mvt-ios/mvt-android/vol/pip - NOT on PATH under gunicorn/systemd (a bare
# shutil.which("sqlite_dissect") confirmed live to find nothing, the same
# class of gap those tools' own resolution already had to solve). Resolve
# via the shared venv's own bin directory instead - see core/config.py's
# MVT_BIN_DIR docstring for why (it's genuinely just "this venv's bin/",
# not specific to MVT despite the name).
SQLITE_DISSECT_BIN = os.path.join(MVT_BIN_DIR, "sqlite_dissect")


def run_sqlite_dissect(db_path, output_dir):
    """Runs `sqlite_dissect <db_path> -d <output_dir> -p <prefix> -e csv
    -c -f` against a single .db/.sqlite/.sqlite3 file - carving and
    freelist-carving both explicitly enabled (off by default in the real
    tool). Returns {"success": bool, "output_dir": str, "summary": str,
    "log": str, "error": str|None, "files": list[str]} - never raises.
    output_dir is created by the caller before this runs (matches this
    app's own established os.makedirs(exist_ok=True) convention for every
    other tool that writes a whole output directory)."""
    if not os.path.isfile(SQLITE_DISSECT_BIN):
        return {"success": False, "error": "sqlite_dissect is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions."}

    prefix = os.path.splitext(os.path.basename(db_path))[0]
    cmd = [SQLITE_DISSECT_BIN, db_path, "-d", output_dir, "-p", prefix, "-e", "csv", "-c", "-f"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=SQLITE_DISSECT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "sqlite_dissect timed out (large database - consider a smaller file)."}
    except Exception as e:
        return {"success": False, "error": str(e)}

    log = ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip() or "[no output]"
    written_files = sorted(os.listdir(output_dir)) if os.path.isdir(output_dir) else []

    if res.returncode != 0:
        # A non-zero exit (including an outright Python traceback from the
        # tool itself, confirmed live against a genuinely malformed test
        # file) is always a clean, reported failure here - never surfaced
        # as a crash to the examiner, and any partial output already
        # written is discarded rather than presented as trustworthy.
        return {"success": False, "error": (log[:2000] or "sqlite_dissect failed with no output.")}

    if not written_files:
        return {"success": True, "output_dir": output_dir, "summary": "No output produced - "
                "the file may have no recognized SQLite structure, or genuinely nothing "
                "recoverable was found.", "log": log[:20000], "files": []}

    summary = f"{len(written_files)} output file(s) written"
    return {"success": True, "output_dir": output_dir, "summary": summary, "log": log[:20000], "files": written_files}
