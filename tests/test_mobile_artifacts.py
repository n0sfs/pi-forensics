"""core/mobile_artifacts.py - iOS backup (Manifest.db-driven) chat/app
artifact parsing.

No real iOS backup was available on this station to test against (a real
device has never connected to it - an already-disclosed, pre-existing gap
this project has flagged for other mobile-forensics features too), so this
builds a synthetic backup fixture matching the real, publicly-documented
Manifest.db schema and fileID resolution scheme (verified via research
during implementation, cited in core/mobile_artifacts.py's own module
docstring) - real SQLite files with the real table/column names, not mocks.
This proves the module's own logic is internally correct; the on-disk
layout assumption itself (fileID -> <fileID[0:2]>/<fileID>) still needs a
real backup to fully confirm, per that module's own disclosed verification
checkpoint.

Pure stdlib (sqlite3, plistlib) - no optional pip dependency, no skip guard
needed.
"""
import os
import sqlite3
import plistlib

import core.mobile_artifacts as ma


def _build_synthetic_backup(tmp_path, udid="a1b2c3d4e5f6789012345678901234567890abcd", encrypted=False):
    """Builds a real, format-accurate synthetic iOS backup folder: a real
    Manifest.db (Files table mapping domain/relativePath -> a real fileID,
    with matching content files at <fileID[0:2]>/<fileID>), Info.plist,
    and Manifest.plist (IsEncrypted flag)."""
    backup_dir = tmp_path / udid
    backup_dir.mkdir()

    manifest_db_path = backup_dir / "Manifest.db"
    conn = sqlite3.connect(str(manifest_db_path))
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")

    def _add_file(domain, relative_path, file_id, content_bytes):
        conn.execute("INSERT INTO Files (fileID, domain, relativePath, flags) VALUES (?, ?, ?, 1)",
                     (file_id, domain, relative_path))
        subdir = backup_dir / file_id[0:2]
        subdir.mkdir(exist_ok=True)
        (subdir / file_id).write_bytes(content_bytes)

    # --- sms.db (real message/handle schema) ---
    sms_bytes = _build_sms_db()
    _add_file("HomeDomain", "Library/SMS/sms.db", "aaaa1111sms0000000000000000000000000000", sms_bytes)

    # --- AddressBook.sqlitedb (real ABPerson/ABMultiValue schema) ---
    ab_bytes = _build_addressbook_db()
    _add_file("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", "bbbb2222ab00000000000000000000000000000", ab_bytes)

    # --- CallHistory.storedata (real ZCALLRECORD schema) ---
    ch_bytes = _build_callhistory_db()
    _add_file("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata", "cccc3333ch00000000000000000000000000000", ch_bytes)

    conn.commit()
    conn.close()

    (backup_dir / "Info.plist").write_bytes(plistlib.dumps({"Product Version": "17.0"}))
    (backup_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": encrypted}))
    return backup_dir


def _build_sms_db():
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
    conn.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER, is_from_me INTEGER, handle_id INTEGER)")
    conn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')")
    # A pre-iOS-11-shaped value (seconds since 2001) - 2026-01-01 ~ 789000000s since 2001.
    conn.execute("INSERT INTO message (text, date, is_from_me, handle_id) VALUES ('Hello there', 789000000, 0, 1)")
    # An iOS-11+-shaped value (nanoseconds since 2001) for the same rough date.
    conn.execute("INSERT INTO message (text, date, is_from_me, handle_id) VALUES ('On my way', 789000000000000000, 1, 1)")
    conn.commit()
    conn.close()
    data = open(path, "rb").read()
    os.remove(path)
    return data


def _build_addressbook_db():
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Organization TEXT)")
    conn.execute("CREATE TABLE ABMultiValue (record_id INTEGER, property INTEGER, value TEXT)")
    conn.execute("INSERT INTO ABPerson (ROWID, First, Last, Organization) VALUES (1, 'Jane', 'Doe', NULL)")
    conn.execute("INSERT INTO ABMultiValue (record_id, property, value) VALUES (1, 3, '+15559876543')")
    conn.commit()
    conn.close()
    data = open(path, "rb").read()
    os.remove(path)
    return data


def _build_callhistory_db():
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS TEXT, ZDATE REAL, ZDURATION REAL, ZORIGINATED INTEGER, ZANSWERED INTEGER)")
    conn.execute("INSERT INTO ZCALLRECORD (ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED) VALUES ('+15551112222', 789000000.0, 42.5, 1, 1)")
    conn.commit()
    conn.close()
    data = open(path, "rb").read()
    os.remove(path)
    return data


# --- cocoa_time_to_unix() epoch math ---

def test_cocoa_epoch_is_genuinely_different_math_from_webkit_firefox_filetime():
    from core.browser_artifacts import webkit_time_to_unix, firefox_time_to_unix
    from core.registry_utils import filetime_to_unix
    # Same raw numeric value fed through all 4 conversions must not agree -
    # proves this isn't a copy-pasted epoch, matching this codebase's own
    # established regression-test pattern for every prior epoch helper.
    raw = 1_000_000_000
    results = {
        webkit_time_to_unix(raw), firefox_time_to_unix(raw),
        filetime_to_unix(raw), ma.cocoa_time_to_unix(raw),
    }
    assert len(results) == 4


def test_cocoa_epoch_reference_point_is_correct():
    # 2001-01-01 00:00:00 UTC in seconds-since-2001 is 0 -> should resolve
    # to exactly the well-known Unix-epoch offset constant.
    assert ma.cocoa_time_to_unix(0.0) is None  # falsy value -> None, matches every other epoch helper's convention
    # A tiny nonzero seconds-since-2001 value stays interpreted as seconds
    # (well under the 1e12 nanosecond-disambiguation threshold).
    assert ma.cocoa_time_to_unix(1.0) == ma.COCOA_EPOCH_OFFSET_SECONDS + 1.0


def test_cocoa_epoch_disambiguates_seconds_vs_nanoseconds_by_magnitude():
    seconds_value = 789_000_000  # a plausible seconds-since-2001 value
    nanoseconds_value = 789_000_000 * 1_000_000_000  # the same real instant, iOS 11+ shape
    result_seconds = ma.cocoa_time_to_unix(seconds_value)
    result_nanoseconds = ma.cocoa_time_to_unix(nanoseconds_value)
    # Both should resolve to (approximately) the same real Unix timestamp,
    # despite one being 1e9x the other numerically.
    assert abs(result_seconds - result_nanoseconds) < 1.0


def test_cocoa_epoch_returns_none_for_absent_or_unparseable():
    assert ma.cocoa_time_to_unix(None) is None
    assert ma.cocoa_time_to_unix("") is None
    assert ma.cocoa_time_to_unix("not a number") is None


# --- Discovery ---

def test_find_backup_when_root_dir_is_the_udid_folder_itself(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    found, truncated = ma.find_mobile_backup_manifest(str(backup_dir))
    assert found == [str(backup_dir)]
    assert truncated is False


def test_find_backup_when_root_dir_contains_the_udid_folder(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    found, truncated = ma.find_mobile_backup_manifest(str(tmp_path))
    assert found == [str(backup_dir)]


def test_find_backup_returns_empty_for_a_udid_shaped_dir_missing_markers(tmp_path):
    fake_udid_dir = tmp_path / "a1b2c3d4e5f6789012345678901234567890abcd"
    fake_udid_dir.mkdir()
    (fake_udid_dir / "Manifest.db").write_text("not a real manifest, but Info.plist is missing")
    found, truncated = ma.find_mobile_backup_manifest(str(tmp_path))
    assert found == []


def test_find_backup_ignores_non_udid_shaped_directories(tmp_path):
    (tmp_path / "not_a_udid").mkdir()
    (tmp_path / "not_a_udid" / "Manifest.db").write_text("x")
    (tmp_path / "not_a_udid" / "Info.plist").write_text("x")
    found, truncated = ma.find_mobile_backup_manifest(str(tmp_path))
    assert found == []


# --- Encryption disclosure ---

def test_encrypted_backup_returns_no_records_with_encrypted_flag_set(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path, encrypted=True)
    records, summary = ma.parse_mobile_backup_manifest(str(backup_dir))
    assert records == []
    assert summary["encrypted"] is True


# --- Full parse, all 3 target types ---

def test_full_parse_extracts_all_three_target_types(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    records, summary = ma.parse_mobile_backup_manifest(str(backup_dir))
    assert summary["encrypted"] is False
    assert summary["found"] == {"mobile_sms_message": True, "mobile_contact": True, "mobile_call_log": True}
    types_present = {r["artifact_type"] for r in records}
    assert types_present == {"mobile_sms_message", "mobile_contact", "mobile_call_log"}


def test_sms_parsing_extracts_real_text_and_direction(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    records, _found = ma.parse_mobile_sms(str(backup_dir))
    by_text = {r["value"]: r for r in records}
    assert "Hello there" in by_text
    assert by_text["Hello there"]["extra"]["direction"] == "Received"
    assert by_text["Hello there"]["extra"]["counterpart"] == "+15551234567"
    assert "On my way" in by_text
    assert by_text["On my way"]["extra"]["direction"] == "Sent"
    # Both the seconds-shaped and nanoseconds-shaped rows should resolve to
    # comparable real timestamps despite the raw magnitude difference.
    assert abs(by_text["Hello there"]["timestamp"] - by_text["On my way"]["timestamp"]) < 2.0


def test_contact_parsing_joins_name_and_phone_number(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    records, _found = ma.parse_mobile_contacts(str(backup_dir))
    assert len(records) == 1
    r = records[0]
    assert r["title"] == "Jane Doe"
    assert r["value"] == "+15559876543"
    assert r["timestamp"] is None  # no reliable per-record timestamp exists in this schema


def test_call_log_parsing_extracts_direction_and_duration(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    records, _found = ma.parse_mobile_call_history(str(backup_dir))
    assert len(records) == 1
    r = records[0]
    assert "+15551112222" in r["title"]
    assert "Outgoing" in r["title"]
    assert "Answered" in r["value"]
    assert r["extra"]["duration_seconds"] == 42.5


def test_missing_target_app_reports_found_false_not_a_silent_empty_list(tmp_path):
    # A backup with a Manifest.db that simply never backed up Contacts
    # (e.g. contacts sync disabled) - found=False for that type, distinct
    # from found=True with zero records.
    backup_dir = tmp_path / "a1b2c3d4e5f6789012345678901234567890abcd"
    backup_dir.mkdir()
    conn = sqlite3.connect(str(backup_dir / "Manifest.db"))
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.commit()
    conn.close()
    (backup_dir / "Info.plist").write_bytes(plistlib.dumps({}))
    records, summary = ma.parse_mobile_backup_manifest(str(backup_dir))
    assert records == []
    assert summary["found"] == {"mobile_sms_message": False, "mobile_contact": False, "mobile_call_log": False}


def test_requested_types_filters_to_only_those_parsers(tmp_path):
    backup_dir = _build_synthetic_backup(tmp_path)
    records, summary = ma.parse_mobile_backup_manifest(str(backup_dir), requested_types=["mobile_sms_message"])
    assert {r["artifact_type"] for r in records} == {"mobile_sms_message"}
    assert "mobile_contact" not in summary["found"]
