"""routes/mobile.py::_capture_android_accounts()/_capture_android_notification_
snapshot() - the Android pattern-of-life accounts + notification snapshot
capture steps (2026-09-04), run as best-effort enrichment immediately after
a successful `adb pull`.

Both are grounded directly against the real AOSP framework source, fetched
and read line-by-line before writing any code (not guessed, not taken from
a secondhand blog post):

- Accounts: AccountManagerService.java's real dump()/dumpUser() (dumpUser()
  literally does `fout.println("  " + account.toString())`) and Account
  .java's real toString() (`"Account {name=" + name + ", type=" + type +
  "}"`) - confirms the account name is printed in full, never masked.

- Notifications: NotificationManagerService.java's real dump()/dumpImpl()/
  dumpNotificationRecords(), NotificationRecord.java's real dump()/
  dumpNotification()/shouldRedactStringExtra(), and DumpFilter's real
  `redact = true` default. Confirms REDACTED-by-default is the real,
  standard behavior of a plain `adb shell dumpsys notification` with no
  extra flags - actual title/body text is NOT recoverable this way (only
  a "[length=N]" placeholder), only package/timestamp/importance/key
  metadata is. This test suite exists partly to lock that boundary in -
  if a future change ever made this module capture real notification text
  under the DEFAULT (non---reveal) invocation, that would be a real
  regression in what this app promises about its own privacy footprint.

Both sample fixtures below are hand-built, format-accurate text (not a
literal captured real device dump, since none was available - mirrors this
project's own established "build a real, format-accurate fixture when a
genuine sample isn't available" precedent used throughout this session),
with subprocess.run() mocked rather than requiring a real connected device.

Gated behind routes.mobile importing cleanly (needs core.jobs, POSIX-only
pwd/fcntl) - skips on a non-POSIX dev machine, runs for real on the Pi's
Linux venv.
"""
from unittest.mock import patch, MagicMock

import pytest

pytest.importorskip("routes.mobile", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


def _mock_completed_process(stdout, returncode=0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    return proc


# --- _capture_android_accounts() -------------------------------------------

# Real, confirmed shape from AccountManagerService.dump()/dumpUser() - a
# "User <UserInfo>:" header per device user, then "Accounts: N" followed by
# N "  Account {name=..., type=...}" lines. Two users (a real multi-profile
# device shape - e.g. a personal profile plus a work profile), 3 accounts
# total, deliberately including a real-looking email address (the account
# name is printed unredacted by the real OS, confirmed above) and a
# non-Google account type (proving this isn't hardcoded to only recognize
# "com.google").
SAMPLE_ACCOUNT_DUMPSYS_OUTPUT = """User UserInfo{0:Owner:c13} serialNo=0:
  Accounts: 2
    Account {name=jane.doe@gmail.com, type=com.google}
    Account {name=+15551234567, type=com.whatsapp}

  Account Debug Table:
  Active Sessions: 0

User UserInfo{10:Work Profile:c1030} serialNo=10:
  Accounts: 1
    Account {name=jane.doe@work-example.com, type=com.google}

  Account Debug Table:
  Active Sessions: 0
"""


def test_capture_accounts_parses_all_three_real_shaped_accounts_across_two_users(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_ACCOUNT_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        count = mobile._capture_android_accounts("SERIAL123", output_path, case_folder)

    assert count == 3
    mock_record.assert_called_once()
    call_args = mock_record.call_args[0]
    assert call_args[0] == case_folder
    records = call_args[2]
    assert all(r["artifact_type"] == "android_configured_account" for r in records)
    by_name = {r["extra"]["name"]: r["extra"]["type"] for r in records}
    assert by_name == {
        "jane.doe@gmail.com": "com.google",
        "+15551234567": "com.whatsapp",
        "jane.doe@work-example.com": "com.google",
    }


def test_capture_accounts_names_are_never_masked_or_redacted(tmp_path):
    # Real, confirmed behavior (Account.toString() prints the raw name) -
    # this test would fail if a future change accidentally started masking
    # account names the way notification content is deliberately redacted.
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_ACCOUNT_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_accounts("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    titles = {r["title"] for r in records}
    assert "jane.doe@gmail.com" in titles
    assert not any("***" in t or "REDACTED" in t.upper() for t in titles)


def test_capture_accounts_no_accounts_configured_returns_zero_no_record_call(tmp_path):
    output = "User UserInfo{0:Owner:c13} serialNo=0:\n  Accounts: 0\n\n  Account Debug Table:\n"
    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(output)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record:
        count = mobile._capture_android_accounts("SERIAL123", "/x/out", "/x")

    assert count == 0
    mock_record.assert_not_called()


def test_capture_accounts_subprocess_failure_never_raises_returns_zero():
    with patch("routes.mobile.subprocess.run", side_effect=OSError("adb not found")):
        assert mobile._capture_android_accounts("SERIAL123", "/x/out", "/x") == 0

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process("", returncode=1)):
        assert mobile._capture_android_accounts("SERIAL123", "/x/out", "/x") == 0


# --- _capture_android_notification_snapshot() -------------------------------

# Real, confirmed shape from NotificationRecord.toString() (the exact format
# string quoted from the real source: "NotificationRecord(0x%08x: pkg=%s
# user=%s id=%d tag=%s importance=%d key=%s: %s)") followed by dump()'s many
# indented detail lines including the real "mCreationTimeMs="/
# "mUpdateTimeMs=" fields this module actually extracts. The "extras={...}"
# block deliberately includes a redacted [length=N] placeholder - proving
# this test fixture matches the REAL default-redacted output shape, not an
# idealized one that happens to omit the very thing this feature is
# scoped around.
SAMPLE_NOTIFICATION_DUMPSYS_OUTPUT = """Current Notification Manager state:
  Toast Queue:

  Notification List:
    NotificationRecord(0x1a2b3c4d: pkg=com.whatsapp user=UserHandle{0} id=1001 tag=null importance=3 key=0|com.whatsapp|1001|null|10123: android.app.Notification(...))
      uid=10123 userId=0
      opPkg=com.whatsapp
      icon=Icon(typ=RESOURCE pkg=com.whatsapp id=0x7f080001)
      flags=[ ]
      pri=0
      key=0|com.whatsapp|1001|null|10123
      seen=true
      groupKey=0|com.whatsapp|g:conv123
      notification=
        fullscreenIntent=null
        contentIntent=PendingIntent{abc123: android.os.BinderProxy@def456}
        deleteIntent=null
        number=0
        when=1725000000000/1725000000000
        tickerText=New message from Jane...
        vis=1
        extras={
          android.title=CharSequence [length=8]
          android.text=CharSequence [length=42]
        }
      mContactAffinity=0.0
      mCreationTimeMs=1725000000000
      mUpdateTimeMs=1725000001000
      mVisibleSinceMs=1725000000500
      mInterruptionTimeMs=1725000000500

    NotificationRecord(0x5e6f7a8b: pkg=com.google.android.gm user=UserHandle{0} id=2002 tag=null importance=4 key=0|com.google.android.gm|2002|null|10201: android.app.Notification(...))
      uid=10201 userId=0
      opPkg=com.google.android.gm
      key=0|com.google.android.gm|2002|null|10201
      seen=false
      notification=
        extras={
          android.title=CharSequence [length=15]
          android.text=CharSequence [length=88]
        }
      mCreationTimeMs=1725000100000
      mUpdateTimeMs=1725000100000

  mMaxPackageEnqueueRate=10.0
"""


def test_capture_notifications_parses_both_real_shaped_records(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_NOTIFICATION_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        count = mobile._capture_android_notification_snapshot("SERIAL123", output_path, case_folder)

    assert count == 2
    records = mock_record.call_args[0][2]
    assert all(r["artifact_type"] == "android_notification_snapshot" for r in records)
    by_pkg = {r["extra"]["package"]: r for r in records}
    assert set(by_pkg.keys()) == {"com.whatsapp", "com.google.android.gm"}


def test_capture_notifications_extracts_correct_metadata_per_record(tmp_path):
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_NOTIFICATION_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_notification_snapshot("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    by_pkg = {r["extra"]["package"]: r for r in records}

    whatsapp = by_pkg["com.whatsapp"]
    assert whatsapp["extra"]["notification_id"] == "1001"
    assert whatsapp["extra"]["importance"] == "3"
    assert whatsapp["extra"]["key"] == "0|com.whatsapp|1001|null|10123"
    # mCreationTimeMs is real milliseconds-since-epoch wall-clock
    # (StatusBarNotification.getPostTime()) - must divide by 1000, not
    # pass through, and must not be confused with SystemClock.
    # elapsedRealtime()-based values (which this field is NOT).
    assert whatsapp["timestamp"] == pytest.approx(1725000000.0)
    assert whatsapp["extra"]["update_timestamp"] == pytest.approx(1725000001.0)

    gmail = by_pkg["com.google.android.gm"]
    assert gmail["extra"]["notification_id"] == "2002"
    assert gmail["extra"]["importance"] == "4"
    assert gmail["timestamp"] == pytest.approx(1725000100.0)


def test_capture_notifications_never_recovers_real_title_or_body_text(tmp_path):
    # The single most important guarantee this feature makes: under the
    # default (non---reveal) invocation this app deliberately always uses,
    # real notification content must never appear anywhere in a captured
    # record - only metadata. The sample fixture's real title/body text
    # ("New message from Jane...", the literal strings that would appear
    # if redaction were somehow bypassed) must never leak into any record.
    case_folder = str(tmp_path / "2026-CASE-TEST")
    (tmp_path / "2026-CASE-TEST").mkdir()
    output_path = str(tmp_path / "2026-CASE-TEST" / "PIXEL_pull")

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(SAMPLE_NOTIFICATION_DUMPSYS_OUTPUT)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record, \
         patch("routes.mobile._auto_tag_case_artifact"):
        mobile._capture_android_notification_snapshot("SERIAL123", output_path, case_folder)

    records = mock_record.call_args[0][2]
    for r in records:
        full_text = (r["title"] + " " + r["value"] + " " + str(r["extra"])).lower()
        assert "new message from jane" not in full_text
        assert "[length=" not in full_text  # not even the redaction placeholder should leak through


def test_capture_notifications_no_notifications_visible_returns_zero(tmp_path):
    output = "Current Notification Manager state:\n  mMaxPackageEnqueueRate=10.0\n"
    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process(output)), \
         patch("routes.mobile._record_parsed_artifacts") as mock_record:
        count = mobile._capture_android_notification_snapshot("SERIAL123", "/x/out", "/x")

    assert count == 0
    mock_record.assert_not_called()


def test_capture_notifications_subprocess_failure_never_raises_returns_zero():
    with patch("routes.mobile.subprocess.run", side_effect=OSError("adb not found")):
        assert mobile._capture_android_notification_snapshot("SERIAL123", "/x/out", "/x") == 0

    with patch("routes.mobile.subprocess.run", return_value=_mock_completed_process("", returncode=1)):
        assert mobile._capture_android_notification_snapshot("SERIAL123", "/x/out", "/x") == 0
