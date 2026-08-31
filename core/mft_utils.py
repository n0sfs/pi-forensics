"""NTFS $MFT (Master File Table) parsing - wraps the analyzeMFT console
script (PyPI: analyzeMFT) as a subprocess rather than driving its internal
API directly. Confirmed live on the Pi's real ARM64 venv before writing this
module: the package is pure Python (no compile step), and its internal
MftAnalyzer class is built around an async, chunked, multiprocessing-hash
pipeline oriented toward its own CLI/file-writer flow rather than a clean
"give me records" API - matching this app's own established rule (see the
Volatility3/MVT/sqlite-dissect/dumpstate-py precedent) to prefer a
documented CLI surface over reverse-engineering a complex internal API.

Confirmed live via `analyzemft --generate-test-mft` (the tool's own built-in
synthetic-MFT generator - no external test fixture needed) exactly what its
`--json` output shape looks like before writing this parser: a flat JSON
list, one dict per MFT record, with (among many other fields this module
ignores) `filename`, `recordnum`, `parent_ref`, `flags`, `filesize`,
`si_times` and `fn_times` (each a {crtime, mtime, atime, ctime} dict of
either an ISO-8601 'YYYY-MM-DDTHH:MM:SS.mmmZ' string or a literal sentinel
string - 'Not defined' or 'Invalid timestamp' - for a record with no valid
attribute of that kind).

Timestomping detection is this module's actual headline value, not just
raw record listing - flags a record as `timestomp_suspected` when its
$STANDARD_INFORMATION creation time is earlier than its $FILE_NAME creation
time by more than a small tolerance. This is a well-known, widely-used DFIR
heuristic (SI times are trivially rewritable via the Windows SetFileTime
API; FN times require direct low-level MFT manipulation and are far harder
to fake), not a certainty - flagged, never asserted, matching this app's
own established honesty convention for every other suspicious-but-not-
certain indicator (e.g. the Evidence Timeline's EVTX audit-log-cleared
flag). `analyzemft` itself ships a `--test-type anomaly` synthetic-data mode
built specifically to exercise this exact class of detection, which is
strong independent confirmation this is a real, recognized use case for
this data - not a heuristic invented for this app alone.
"""
import os
import re
import sys
import json
import subprocess
import tempfile
from datetime import datetime, timezone

MFT_TIMESTOMP_TOLERANCE_SECONDS = 60
MFT_ANALYSIS_TIMEOUT_SECONDS = 900


def _resolve_analyzemft_bin():
    """The console script installs into the shared app venv (requirements.txt)
    alongside the running app itself - but a bare shutil.which() against
    gunicorn's own PATH does NOT reliably find it, since systemd doesn't
    necessarily put the venv's bin/ directory on PATH just because gunicorn
    was launched via the venv's own python (a real bug caught live: the
    route returned "analyzemft is not installed" even with the package
    correctly pip-installed, until switched to this exact
    sys.executable-relative resolution already established for MVT_IOS_BIN/
    VOL3_BIN in core/config.py - the one genuinely reliable way to locate a
    sibling console script in the same venv as the running interpreter)."""
    candidate = os.path.join(os.path.dirname(sys.executable), "analyzemft")
    return candidate if os.path.isfile(candidate) else None


def _parse_iso_or_sentinel(raw):
    """Converts one of analyzeMFT's real-confirmed timestamp strings to a
    Unix epoch float, or None for a sentinel ('Not defined'/'Invalid
    timestamp') or any other unparseable value - never raises."""
    if not raw or not isinstance(raw, str):
        return None
    if raw in ("Not defined", "Invalid timestamp"):
        return None
    try:
        cleaned = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, OverflowError):
        return None


def find_mft_files(root_dir):
    """Recursively finds a real-fs file literally named '$MFT' (case-
    insensitive - some extraction tools normalize the leading $) anywhere
    under root_dir. Returns (paths, truncated) - matches every other
    artifact-parser module's find_X_files() shape in this app."""
    from core.recyclebin_utils import _SCAN_SKIP_DIR_NAMES, _SCAN_SKIP_DIR_SUFFIXES

    found = []
    walked = 0
    max_walked = 40_000
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > max_walked:
                return found, True
            if fname.upper() in ("$MFT", "MFT", "$MFT.BIN"):
                found.append(os.path.join(root, fname))
                if len(found) >= 20:
                    return found, True
    return found, False


def analyze_mft_file(mft_path, compute_hashes=False):
    """Runs the real analyzemft CLI against an extracted $MFT file, parses
    its JSON output into this app's standard {artifact_type, title, url,
    value, timestamp, extra} record shape. Returns
    {"success", "error", "records", "total_records", "timestomp_count"}.
    Never raises - every failure mode (binary missing, tool crash, timeout,
    malformed JSON) returns a clean {"success": False, "error": ...}."""
    bin_path = _resolve_analyzemft_bin()
    if not bin_path:
        return {"success": False, "error": "analyzemft is not installed on this station.", "records": []}

    with tempfile.TemporaryDirectory(prefix="pif_mft_") as tmpdir:
        out_json = os.path.join(tmpdir, "mft_out.json")
        cmd = [bin_path, "-f", mft_path, "-o", out_json, "--json"]
        if compute_hashes:
            cmd.append("--hash")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=MFT_ANALYSIS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"analyzemft timed out after {MFT_ANALYSIS_TIMEOUT_SECONDS}s.", "records": []}
        except Exception as e:
            return {"success": False, "error": f"Failed to run analyzemft: {e}", "records": []}

        if not os.path.isfile(out_json):
            tail = (proc.stderr or proc.stdout or "").strip()[-800:]
            return {"success": False, "error": f"analyzemft produced no output. {tail}", "records": []}

        try:
            with open(out_json, "r", encoding="utf-8") as f:
                raw_records = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return {"success": False, "error": f"Could not parse analyzemft's JSON output: {e}", "records": []}

    records, timestomp_count = _records_from_analyzemft_json(raw_records)
    return {
        "success": True, "error": None, "records": records,
        "total_records": len(records), "timestomp_count": timestomp_count,
    }


def _records_from_analyzemft_json(raw_records):
    """The real JSON-record-list -> this app's own {artifact_type, title,
    url, value, timestamp, extra} record shape transformation, factored out
    of analyze_mft_file() specifically so it can be unit-tested against a
    hand-built raw_records fixture without needing the real analyzemft
    binary installed (not present in this project's Windows dev environment,
    and not worth adding as a CI dependency just to exercise this pure
    JSON-shaping logic). Returns (records, timestomp_count)."""
    records = []
    timestomp_count = 0
    for rec in raw_records if isinstance(raw_records, list) else []:
        filename = (rec.get("filename") or "").strip()
        si_times = rec.get("si_times") or {}
        fn_times = rec.get("fn_times") or {}

        si_crtime = _parse_iso_or_sentinel(si_times.get("crtime"))
        si_mtime = _parse_iso_or_sentinel(si_times.get("mtime"))
        si_atime = _parse_iso_or_sentinel(si_times.get("atime"))
        si_ctime = _parse_iso_or_sentinel(si_times.get("ctime"))
        fn_crtime = _parse_iso_or_sentinel(fn_times.get("crtime"))
        fn_mtime = _parse_iso_or_sentinel(fn_times.get("mtime"))
        fn_atime = _parse_iso_or_sentinel(fn_times.get("atime"))
        fn_ctime = _parse_iso_or_sentinel(fn_times.get("ctime"))

        timestomp_suspected = bool(
            si_crtime is not None and fn_crtime is not None
            and si_crtime < (fn_crtime - MFT_TIMESTOMP_TOLERANCE_SECONDS)
        )
        if timestomp_suspected:
            timestomp_count += 1

        primary_ts = si_mtime if si_mtime is not None else si_crtime
        flags = rec.get("flags")
        is_dir = bool(isinstance(flags, int) and (flags & 0x02))

        extra = {
            "record_num": rec.get("recordnum"), "parent_ref": rec.get("parent_ref"),
            "is_directory": is_dir, "filesize": rec.get("filesize"),
            "si_crtime": si_crtime, "si_mtime": si_mtime, "si_atime": si_atime, "si_ctime": si_ctime,
            "fn_crtime": fn_crtime, "fn_mtime": fn_mtime, "fn_atime": fn_atime, "fn_ctime": fn_ctime,
            "timestomp_suspected": timestomp_suspected,
        }
        for hash_key in ("md5", "sha256", "sha512"):
            if rec.get(hash_key):
                extra[hash_key] = rec[hash_key]

        title = filename if filename else f"(unnamed record #{rec.get('recordnum')})"
        if timestomp_suspected:
            title = f"[TIMESTOMP SUSPECTED] {title}"

        records.append({
            "artifact_type": "mft_file_record", "title": title, "url": "",
            "value": f"{rec.get('filesize', 0):,} bytes" if isinstance(rec.get("filesize"), int) else "",
            "timestamp": primary_ts, "extra": extra,
        })

    return records, timestomp_count
