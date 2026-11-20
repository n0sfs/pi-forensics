"""Unreadable photos are reported, not counted as "no GPS" (2026-11-20,
plan.md B4 leftover). With only named tags requested, exiftool lists an
unreadable photo with just its file name, exits 1 and prints nothing on
stderr - observed with exiftool 12.76 on a chmod-000 file as a non-root
user. The commands now request -Error, and both the File Explorer
geolocation export and the Apple export import state the gap."""
import json
import os
import shutil
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

from core.geo_utils import exiftool_unreadable, exiftool_unreadable_warning
from core.jobs import snapshot_job
import routes.file_explorer as file_explorer

GPS = {"FileName": "a.jpg", "Directory": "/x", "GPSLatitude": 51.5, "GPSLongitude": -0.12}
NOGPS = {"FileName": "b.jpg", "Directory": "/x"}
BAD = {"FileName": "c.jpg", "Directory": "/x", "Error": "Error opening file"}


def _proc(entries, rc=1):
    return types.SimpleNamespace(returncode=rc, stdout=json.dumps(entries), stderr="")


def test_helper_counts_and_words_the_gap():
    assert exiftool_unreadable([GPS, NOGPS]) == (0, None)
    assert exiftool_unreadable([GPS, BAD, BAD]) == (2, "Error opening file")
    assert exiftool_unreadable_warning(0, 3, None) is None
    assert exiftool_unreadable_warning(2, 3, "Error opening file") == (
        "2 of 3 photo(s) could not be read by exiftool (Error opening file) - they were NOT checked for GPS.")


def test_directory_export_requests_error_and_reports_partial_unreadable(tmp_path):
    with mock.patch("subprocess.run", return_value=_proc([GPS, NOGPS, BAD])) as run, \
         mock.patch.object(file_explorer, "_auto_tag_case_artifact"):
        r = file_explorer._geolocation_kml_directory_body(str(tmp_path), str(tmp_path))
    assert "-Error" in run.call_args[0][0]
    assert r["success"] is True
    assert (r["files_scanned"], r["unreadable_files"], r["points_found"]) == (2, 1, 1)
    assert "1 of 3 photo(s) could not be read" in r["warning"]
    assert r["detail"] == r["warning"]


def test_directory_export_fails_when_no_photo_was_readable(tmp_path):
    with mock.patch("subprocess.run", return_value=_proc([BAD, BAD])):
        r = file_explorer._geolocation_kml_directory_body(str(tmp_path), str(tmp_path))
    assert r["success"] is False
    assert "could not read any of the 2 photo(s)" in r["error"]


def test_directory_export_clean_run_has_no_warning(tmp_path):
    with mock.patch("subprocess.run", return_value=_proc([NOGPS], rc=0)):
        r = file_explorer._geolocation_kml_directory_body(str(tmp_path), str(tmp_path))
    assert r["success"] is True and "warning" not in r and r["unreadable_files"] == 0


def test_directory_export_missing_exiftool_is_named(tmp_path):
    with mock.patch("subprocess.run", side_effect=FileNotFoundError(2, "No such file", "exiftool")):
        r = file_explorer._geolocation_kml_directory_body(str(tmp_path), str(tmp_path))
    assert r == {"success": False, "error": "exiftool is not installed (package libimage-exiftool-perl)."}


def _apple(tmp_path, run_kw):
    photos = tmp_path / "apple_export" / "Photos"
    photos.mkdir(parents=True)
    result = {"products_found": ["Photos"], "warnings": [], "records": [], "photos_dir": str(photos)}
    with mock.patch.object(file_explorer, "import_apple_export", return_value=result), \
         mock.patch.object(file_explorer, "_auto_tag_case_artifact"), \
         mock.patch.object(file_explorer, "log_chain_of_custody") as custody, \
         mock.patch("subprocess.run", **run_kw):
        file_explorer.execution_worker_import_apple_export(str(tmp_path / "apple_export"), None, str(tmp_path))
    entry = [c for c in custody.call_args_list if c[0][0] == "apple_export_import"][0][0][1]
    return snapshot_job(), entry


def test_apple_import_logs_partial_unreadable(tmp_path):
    job, entry = _apple(tmp_path, {"return_value": _proc([GPS, BAD])})
    assert job["status"] == "Completed Successfully"
    assert "[!] 1 of 2 photo(s) could not be read by exiftool" in job["log"]
    assert entry["photo_gps_unreadable"] == 1 and entry["photo_gps_points"] == 1


def test_apple_import_all_unreadable_is_a_problem_not_no_gps(tmp_path):
    job, entry = _apple(tmp_path, {"return_value": _proc([BAD, BAD])})
    assert job["status"] == "Completed with 1 problem - see the log"
    assert "Photos GPS was NOT checked - exiftool could not read any of the 2 photo(s)" in job["log"]
    assert "No GPS-tagged photos found" not in job["log"]
    assert entry["photo_gps_problem"].startswith("exiftool could not read any")


def test_apple_import_missing_exiftool_is_a_problem(tmp_path):
    job, entry = _apple(tmp_path, {"side_effect": FileNotFoundError(2, "No such file", "exiftool")})
    assert job["status"] == "Completed with 1 problem - see the log"
    assert "exiftool is not installed" in job["log"]


@pytest.mark.skipif(not shutil.which("exiftool") or os.geteuid() != 0 or not shutil.which("setpriv"),
                    reason="needs real exiftool, root and setpriv to read as an unprivileged user")
def test_real_exiftool_marks_an_unreadable_photo_with_error():
    """Pins the exiftool behaviour the fix relies on. Built under /var/tmp
    because pytest's tmp_path is 0700 and the unprivileged reader needs to
    traverse to the folder."""
    import subprocess
    import tempfile
    base = tempfile.mkdtemp(dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    try:
        os.chmod(base, 0o755)
        d = os.path.join(base, "photos")
        os.mkdir(d, 0o755)
        for name in ("ok.jpg", "locked.jpg"):
            with open(os.path.join(d, name), "wb") as f:
                f.write(b"\xff\xd8\xff\xd9")
        os.chmod(os.path.join(d, "locked.jpg"), 0)
        res = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                              "exiftool", "-j", "-n", "-r", "-ext", "jpg", "-FileName", "-Error", d],
                             capture_output=True, text=True, timeout=60)
        if not res.stdout.strip():
            pytest.skip(f"an unprivileged user cannot reach {d}: {res.stderr.strip()[:200]}")
        entries = json.loads(res.stdout)
        assert res.returncode == 1
        assert exiftool_unreadable(entries) == (1, "Error opening file")
    finally:
        shutil.rmtree(base, ignore_errors=True)
