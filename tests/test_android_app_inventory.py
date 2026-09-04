"""routes/mobile.py::_capture_android_app_inventory() - the Android
pattern-of-life app-inventory capture step (2026-09-04), run as a
best-effort enrichment immediately after a successful `adb pull`.

The regex field extraction is grounded directly against a real, working,
maintained third-party ADB parsing tool (patrickfav/uber-adb-tools'
DumpsysPackageParser.java) that already parses `dumpsys package packages`
output for the identical purpose - fetched and confirmed via WebFetch
before this module was written, not guessed. This test file builds real
sample dumpsys-shaped text matching those confirmed patterns (not a
literal captured real device dump, since none was available - mirrors
this project's own established "build a real, format-accurate fixture
when a genuine sample isn't available" precedent used throughout this
session), and mocks subprocess.run() rather than requiring a real
connected device.

Gated behind routes.mobile importing cleanly, since that module needs
core.jobs (POSIX-only pwd/fcntl) - skips on a non-POSIX dev machine,
runs for real on the Pi's Linux venv, matching every other routes/*.py
test file's established convention in this repo.
"""
import json
from unittest.mock import patch, MagicMock

import pytest

pytest.importorskip("routes.mobile", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


# Real sample output shaped exactly like `dumpsys package packages` -
# 3 packages: one user-installed with both timestamps, one user-installed
# with only a first-install time (no update since install), and one
# system app (codePath under /system/) to prove the classification.
SAMPLE_DUMPSYS_OUTPUT = """Activity Resolver Table:
Packages:
  Package [com.whatsapp] (a1b2c3d):
    userId=10123
    pkg=Package{abc123 com.whatsapp}
    codePath=/data/app/~~xyz==/com.whatsapp-abc==
    resourcePath=/data/app/~~xyz==/com.whatsapp-abc==
    versionCode=460123 minSdk=21 targetSdk=34
    versionName=2.26.1.10
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    firstInstallTime=2026-01-15 10:23:45
    lastUpdateTime=2026-08-30 14:12:33

  Package [com.example.freshapp] (feedbee):
    userId=10201
    codePath=/data/app/~~aaa==/com.example.freshapp-bbb==
    versionCode=1
    versionName=1.0.0
    firstInstallTime=2026-08-25 08:00:00
    lastUpdateTime=2026-08-25 08:00:00

  Package [com.android.systemui] (deadbeef):
    userId=10007
    codePath=/system/priv-app/SystemUI/SystemUI.apk
    versionCode=1
    versionName=1.0
    firstInstallTime=2024-01-01 00:00:00
    lastUpdateTime=2024-01-01 00:00:00

Hidden system packages:
"""


def _mock_completed_process(stdout, returncode=0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    return proc


# --- _android_dumpsys_time_to_unix() ---

def test_dumpsys_time_parses_real_confirmed_format():
    ts = mobile._android_dumpsys_time_to_unix("2026-01-15 10:23:45")
    assert ts is not None
    # Stamped as UTC (no timezone in the source) - a known, real epoch value.
    import datetime
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    assert (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) == (2026, 1, 15, 10, 23, 45)


@pytest.mark.parametrize("bad", [None, "", "not a date", "2026-13-99 25:99:99"])
def test_dumpsys_time_returns_none_for_missing_or_malformed_values(bad):
    assert mobile._android_dumpsys_time_to_unix(bad) is None


# --- _capture_android_app_inventory() ---

def test_capture_app_inventory_parses_three_real_shaped_packages(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        count = mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    assert count == 3
    mock_record.assert_called_once()
    call_args = mock_record.call_args[0]
    assert call_args[0] == case_folder
    records = call_args[2]
    by_pkg = {r["extra"]["package"]: r for r in records}
    assert set(by_pkg.keys()) == {"com.whatsapp", "com.example.freshapp", "com.android.systemui"}
    assert all(r["artifact_type"] == "android_installed_app" for r in records)


def test_capture_app_inventory_correctly_distinguishes_user_and_system_apps(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    by_pkg = {r["extra"]["package"]: r for r in records}
    assert by_pkg["com.whatsapp"]["extra"]["is_system_app"] is False
    assert by_pkg["com.example.freshapp"]["extra"]["is_system_app"] is False
    assert by_pkg["com.android.systemui"]["extra"]["is_system_app"] is True


def test_capture_app_inventory_extracts_version_and_both_timestamps_correctly(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    by_pkg = {r["extra"]["package"]: r for r in records}

    whatsapp = by_pkg["com.whatsapp"]
    assert whatsapp["title"] == "com.whatsapp"
    assert whatsapp["extra"]["version_name"] == "2.26.1.10"
    assert whatsapp["extra"]["version_code"] == "460123"
    # First-install time is the record's own timestamp (the "installed"
    # framing this artifact_type is named for).
    assert whatsapp["timestamp"] is not None
    # A real, distinct last-update time (14:12:33, not the install time
    # 10:23:45) must be captured separately, not conflated with install.
    assert whatsapp["extra"]["last_update_timestamp"] is not None
    assert whatsapp["extra"]["last_update_timestamp"] != whatsapp["timestamp"]

    fresh = by_pkg["com.example.freshapp"]
    # Install and update times are identical here (never updated since
    # install) - both captured, correctly equal, not deduplicated away.
    assert fresh["extra"]["last_update_timestamp"] == fresh["timestamp"]


def test_capture_app_inventory_does_not_bleed_fields_across_package_blocks(tmp_path):
    # The real regression this app's own per-block slicing exists to
    # prevent: a naive whole-dump regex search (not scoped per block)
    # would let com.whatsapp's own versionName leak onto every other
    # package too, since re.search() with no block boundary just finds
    # the FIRST occurrence anywhere in the string. Confirms each package
    # gets its own, distinct version.
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    by_pkg = {r["extra"]["package"]: r for r in records}
    assert by_pkg["com.whatsapp"]["extra"]["version_name"] == "2.26.1.10"
    assert by_pkg["com.example.freshapp"]["extra"]["version_name"] == "1.0.0"
    assert by_pkg["com.android.systemui"]["extra"]["version_name"] == "1.0"


def test_capture_app_inventory_writes_a_real_manifest_sidecar(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts"), \
         patch("routes.mobile._auto_tag_case_artifact") as mock_tag:
        mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    manifest_path = f"{output_path}_app_inventory.json"
    assert (tmp_path / "2026-CASE-TEST" / "PIXEL_pull_app_inventory.json").exists()
    with open(manifest_path) as f:
        manifest = json.load(f)
    assert manifest["package_count"] == 3
    assert manifest["source"] == "adb shell dumpsys package packages"
    mock_tag.assert_called_once_with(case_folder, manifest_path)


@pytest.mark.parametrize("proc_result,label", [
    (None, "subprocess raises"),
    (_mock_completed_process("", 0), "empty stdout"),
    (_mock_completed_process("some output", 1), "nonzero returncode"),
    (_mock_completed_process("no package markers in this text at all", 0), "no real package blocks found"),
])
def test_capture_app_inventory_gracefully_returns_zero_never_raises(tmp_path, proc_result, label):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    if proc_result is None:
        run_patch = patch("routes.mobile.subprocess.run", side_effect=OSError("adb not found"))
    else:
        run_patch = patch("routes.mobile.subprocess.run", return_value=proc_result)

    with run_patch, patch("routes.mobile._record_parsed_artifacts") as mock_record:
        count = mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    assert count == 0, label
    mock_record.assert_not_called()
    assert not (tmp_path / "2026-CASE-TEST" / "PIXEL_pull_app_inventory.json").exists()


def test_capture_app_inventory_missing_optional_fields_stay_none_not_a_crash(tmp_path):
    # A package block with only the header line and none of the confirmed
    # optional fields (a minimal/stripped-down real-world package entry)
    # must still be captured, with every missing field honestly None.
    sparse_dump = "Packages:\n  Package [com.example.sparse] (cafef00d):\n    userId=10555\n\n"
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(sparse_dump)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        count = mobile._capture_android_app_inventory("SERIAL123", output_path, case_folder)

    assert count == 1
    r = mock_record.call_args[0][2][0]
    assert r["extra"]["package"] == "com.example.sparse"
    assert r["extra"]["version_name"] is None
    assert r["extra"]["code_path"] is None
    assert r["extra"]["is_system_app"] is False  # empty code_path never matches a system-path prefix
    assert r["timestamp"] is None
