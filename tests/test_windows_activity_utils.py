"""Tests for core/windows_activity_utils.py, built against real SQLite
databases matching the confirmed real Notification/NotificationHandler and
Activity table schemas (2026-09-01 research, cross-validated against
swiftforensics.com/inc0x0.com for wpndatabase.db and hermes-codex/
istrosec.com/Velociraptor for ActivitiesCache.db) - not mocks."""
import datetime
import json
import os
import shutil
import sqlite3
import tempfile

import core.windows_activity_utils as wau

FILETIME_EPOCH_OFFSET_SECONDS = 11_644_473_600
FILETIME_100NS_PER_SECOND = 10_000_000


def _unix_to_filetime(unix_seconds):
    return int((unix_seconds + FILETIME_EPOCH_OFFSET_SECONDS) * FILETIME_100NS_PER_SECOND)


def _dt_filetime(dt):
    return _unix_to_filetime(dt.replace(tzinfo=datetime.timezone.utc).timestamp())


# ---------------------------------------------------------------------------
# wpndatabase.db (Notification / NotificationHandler)
# ---------------------------------------------------------------------------

def _build_wpndatabase(path, notifications, handlers=None, wal_mode=False,
                        notification_cols=('Id', 'HandlerId', 'Type', 'Payload', 'Tag', 'ArrivalTime', 'ExpiryTime')):
    conn = sqlite3.connect(path)
    col_defs = ', '.join(f'{c} {"INTEGER" if c in ("Id", "HandlerId", "ArrivalTime", "ExpiryTime") else "TEXT"}'
                          for c in notification_cols)
    conn.execute(f"CREATE TABLE Notification ({col_defs})")
    for row in notifications:
        placeholders = ', '.join('?' for _ in notification_cols)
        conn.execute(f"INSERT INTO Notification ({', '.join(notification_cols)}) VALUES ({placeholders})", row)
    if handlers is not None:
        conn.execute("CREATE TABLE NotificationHandler (RecordId INTEGER, PrimaryId TEXT)")
        for record_id, primary_id in handlers:
            conn.execute("INSERT INTO NotificationHandler (RecordId, PrimaryId) VALUES (?, ?)",
                         (record_id, primary_id))
    conn.commit()
    if wal_mode:
        conn.execute('PRAGMA journal_mode=WAL')
    return conn


def test_parse_wpndatabase_resolves_handler_and_extracts_toast_text(tmp_path):
    arrived = datetime.datetime(2026, 8, 15, 12, 0, 0)
    payload = '<toast><visual><binding><text>Case Update</text><text>New evidence uploaded</text></binding></visual></toast>'
    conn = _build_wpndatabase(str(tmp_path / wau.WPNDATABASE_FILENAME), [
        (1, 42, 'toast', payload, 'case-tag', _dt_filetime(arrived), None),
    ], handlers=[(42, 'Microsoft.Outlook_8wekyb3d8bbwe!App')])
    conn.close()

    records = wau.parse_wpndatabase_file(str(tmp_path / wau.WPNDATABASE_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "windows_notification"
    assert r["title"] == 'Microsoft.Outlook_8wekyb3d8bbwe!App'
    assert r["value"] == 'Case Update | New evidence uploaded'
    assert r["timestamp"] == arrived.replace(tzinfo=datetime.timezone.utc).timestamp()
    assert r["extra"]["handler_id"] == 42
    assert r["extra"]["tag"] == 'case-tag'


def test_parse_wpndatabase_unresolvable_handler_falls_back_to_numeric_id(tmp_path):
    arrived = datetime.datetime(2026, 8, 15, 12, 0, 0)
    conn = _build_wpndatabase(str(tmp_path / wau.WPNDATABASE_FILENAME), [
        (1, 99, 'toast', '<toast><text>hi</text></toast>', None, _dt_filetime(arrived), None),
    ], handlers=None)
    conn.close()

    records = wau.parse_wpndatabase_file(str(tmp_path / wau.WPNDATABASE_FILENAME))
    assert len(records) == 1
    assert records[0]["title"] == 'Handler #99'


def test_parse_wpndatabase_tolerates_missing_optional_columns(tmp_path):
    # Real schema drift across Windows builds - Tag/ExpiryTime absent
    # entirely on this "build" must not crash, just omit those fields.
    arrived = datetime.datetime(2026, 8, 15, 12, 0, 0)
    conn = _build_wpndatabase(
        str(tmp_path / wau.WPNDATABASE_FILENAME),
        [(1, 5, 'toast', '<toast><text>minimal build</text></toast>', _dt_filetime(arrived))],
        notification_cols=('Id', 'HandlerId', 'Type', 'Payload', 'ArrivalTime'))
    conn.close()

    records = wau.parse_wpndatabase_file(str(tmp_path / wau.WPNDATABASE_FILENAME))
    assert len(records) == 1
    assert records[0]["value"] == 'minimal build'
    assert records[0]["extra"]["tag"] is None


def test_parse_wpndatabase_non_xml_payload_falls_back_to_stripped_text(tmp_path):
    conn = _build_wpndatabase(str(tmp_path / wau.WPNDATABASE_FILENAME), [
        (1, 1, 'toast', 'not really xml at all just raw text', None, None, None),
    ])
    conn.close()
    records = wau.parse_wpndatabase_file(str(tmp_path / wau.WPNDATABASE_FILENAME))
    assert len(records) == 1
    assert 'not really xml' in records[0]["value"]
    assert records[0]["timestamp"] is None


def test_parse_wpndatabase_missing_main_file_returns_empty(tmp_path):
    assert wau.parse_wpndatabase_file(str(tmp_path / wau.WPNDATABASE_FILENAME)) == []


def test_parse_wpndatabase_not_a_real_sqlite_file_returns_empty(tmp_path):
    p = tmp_path / wau.WPNDATABASE_FILENAME
    p.write_bytes(b'not a real sqlite database')
    assert wau.parse_wpndatabase_file(str(p)) == []


def test_parse_wpndatabase_recovers_data_stranded_only_in_the_wal_sidecar(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    main_path = str(src_dir / wau.WPNDATABASE_FILENAME)
    conn = _build_wpndatabase(main_path, [
        (1, 1, 'toast', '<toast><text>checkpointed</text></toast>', None, None, None),
    ], wal_mode=True)
    conn2 = sqlite3.connect(main_path)
    conn2.execute('SELECT 1')
    conn.execute(
        "INSERT INTO Notification (Id, HandlerId, Type, Payload, Tag, ArrivalTime, ExpiryTime) "
        "VALUES (2, 1, 'toast', ?, NULL, NULL, NULL)",
        ('<toast><text>wal-only notification</text></toast>',))
    conn.commit()
    assert os.path.isfile(main_path + '-wal')

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    for name in os.listdir(src_dir):
        shutil.copy2(str(src_dir / name), str(dest_dir / name))
    conn.close()
    conn2.close()

    records = wau.parse_wpndatabase_file(str(dest_dir / wau.WPNDATABASE_FILENAME))
    values = {r["value"] for r in records}
    assert 'checkpointed' in values
    assert 'wal-only notification' in values, "the WAL-only notification must be recovered"


# ---------------------------------------------------------------------------
# ActivitiesCache.db (Activity)
# ---------------------------------------------------------------------------

def _build_activitiescache(path, rows, wal_mode=False):
    """rows: [(id, app_id_json_or_str, activity_type, activity_status, payload_json_or_str, start, end, modified), ...]"""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE Activity (Id TEXT, AppId TEXT, ActivityType INTEGER, ActivityStatus INTEGER, "
        "Payload TEXT, StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER)")
    for row in rows:
        conn.execute(
            "INSERT INTO Activity (Id, AppId, ActivityType, ActivityStatus, Payload, StartTime, EndTime, "
            "LastModifiedTime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
    conn.commit()
    if wal_mode:
        conn.execute('PRAGMA journal_mode=WAL')
    return conn


def test_parse_activitiescache_resolves_app_and_payload_summary(tmp_path):
    app_id = json.dumps([{"platform": "windows_win32", "application": "notepad.exe"}])
    payload = json.dumps({"appActivityId": "x", "activityContent": {"title": "case_notes.txt", "description": "Edited document"}})
    start = 1788200000
    end = 1788200300
    conn = _build_activitiescache(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME), [
        ('act-1', app_id, 5, 1, payload, start, end, start),
    ])
    conn.close()

    records = wau.parse_activitiescache_file(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "windows_timeline_activity"
    assert r["title"] == 'notepad.exe'
    assert r["value"] == 'case_notes.txt'
    assert r["timestamp"] == float(start)
    assert r["extra"]["end_timestamp"] == float(end)


def test_parse_activitiescache_malformed_json_falls_back_to_raw_string(tmp_path):
    conn = _build_activitiescache(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME), [
        ('act-bad', 'not-json-app-id', 1, 1, 'not-json-payload-either', 1788200000, None, None),
    ])
    conn.close()
    records = wau.parse_activitiescache_file(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME))
    assert len(records) == 1
    assert records[0]["title"] == 'not-json-app-id'
    assert records[0]["value"] == 'not-json-payload-either'


def test_parse_activitiescache_timestamp_is_plain_unix_seconds_not_filetime():
    # Direct regression test: StartTime is confirmed plain Unix-epoch
    # seconds (three independent sources), a genuinely different real-
    # world convention from every FILETIME-based artifact this app also
    # parses - must NOT be run through filetime_to_unix() or any other
    # epoch-conversion helper, just a plain numeric pass-through.
    assert wau._activity_timestamp(1788200000) == 1788200000.0
    assert wau._activity_timestamp("1788200000") == 1788200000.0


def test_parse_activitiescache_missing_main_file_returns_empty(tmp_path):
    assert wau.parse_activitiescache_file(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME)) == []


def test_parse_activitiescache_recovers_data_stranded_only_in_the_wal_sidecar(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    main_path = str(src_dir / wau.ACTIVITIESCACHE_FILENAME)
    conn = _build_activitiescache(main_path, [
        ('act-checkpointed', '[{"application": "chrome.exe"}]', 5, 1, '{}', 1788200000, None, None),
    ], wal_mode=True)
    conn2 = sqlite3.connect(main_path)
    conn2.execute('SELECT 1')
    conn.execute(
        "INSERT INTO Activity (Id, AppId, ActivityType, ActivityStatus, Payload, StartTime, EndTime, "
        "LastModifiedTime) VALUES ('act-wal-only', '[{\"application\": \"cmd.exe\"}]', 5, 1, '{}', 1788200500, NULL, NULL)")
    conn.commit()
    assert os.path.isfile(main_path + '-wal')

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    for name in os.listdir(src_dir):
        shutil.copy2(str(src_dir / name), str(dest_dir / name))
    conn.close()
    conn2.close()

    records = wau.parse_activitiescache_file(str(dest_dir / wau.ACTIVITIESCACHE_FILENAME))
    titles = {r["title"] for r in records}
    assert 'chrome.exe' in titles
    assert 'cmd.exe' in titles, "the WAL-only activity must be recovered"


# ---------------------------------------------------------------------------
# Shared: discovery, canonical-name resolution, top-level dispatch
# ---------------------------------------------------------------------------

def test_find_windows_activity_files_matches_both_names_case_insensitively(tmp_path):
    (tmp_path / 'wpndatabase.db').write_bytes(b'x')
    (tmp_path / 'ACTIVITIESCACHE.DB').write_bytes(b'x')
    (tmp_path / 'wpndatabase.db-wal').write_bytes(b'x')  # sidecar - never itself a "found" candidate
    (tmp_path / 'unrelated.db').write_bytes(b'x')

    found, truncated = wau.find_windows_activity_files(str(tmp_path))
    basenames = sorted(os.path.basename(p) for p in found)
    assert basenames == ['ACTIVITIESCACHE.DB', 'wpndatabase.db']
    assert truncated is False


def test_find_windows_activity_files_skips_recovery_tool_output_dirs(tmp_path):
    skip_dir = tmp_path / 'evidence_foremost'
    skip_dir.mkdir()
    (skip_dir / 'wpndatabase.db').write_bytes(b'x')
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    (real_dir / 'wpndatabase.db').write_bytes(b'x')

    found, _truncated = wau.find_windows_activity_files(str(tmp_path))
    assert len(found) == 1
    assert 'real' in found[0]


def test_windows_activity_canonical_filename():
    assert wau.windows_activity_canonical_filename('WPNDATABASE.DB') == 'wpndatabase.db'
    assert wau.windows_activity_canonical_filename('wpndatabase.db-wal') == 'wpndatabase.db-wal'
    assert wau.windows_activity_canonical_filename('activitiescache.db-shm') == 'ActivitiesCache.db-shm'
    assert wau.windows_activity_canonical_filename('unrelated.db') is None


def test_windows_activity_base_name_strips_sidecar_suffix_without_conflating_families():
    assert wau.windows_activity_base_name('wpndatabase.db') == 'wpndatabase.db'
    assert wau.windows_activity_base_name('wpndatabase.db-wal') == 'wpndatabase.db'
    assert wau.windows_activity_base_name('wpndatabase.db-shm') == 'wpndatabase.db'
    assert wau.windows_activity_base_name('ActivitiesCache.db-wal') == 'ActivitiesCache.db'
    assert wau.windows_activity_base_name('ActivitiesCache.db') == 'ActivitiesCache.db'
    assert wau.windows_activity_base_name(None) is None
    assert wau.windows_activity_base_name('unrelated.db') is None


def test_parse_windows_activity_file_dispatches_by_filename(tmp_path):
    conn = _build_wpndatabase(str(tmp_path / wau.WPNDATABASE_FILENAME), [
        (1, 1, 'toast', '<toast><text>dispatch check</text></toast>', None, None, None),
    ])
    conn.close()
    records = wau.parse_windows_activity_file(str(tmp_path / wau.WPNDATABASE_FILENAME), wau.WPNDATABASE_FILENAME)
    assert len(records) == 1
    assert records[0]["artifact_type"] == "windows_notification"

    conn2 = _build_activitiescache(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME), [
        ('act-1', '[{"application": "explorer.exe"}]', 5, 1, '{}', 1788200000, None, None),
    ])
    conn2.close()
    records2 = wau.parse_windows_activity_file(str(tmp_path / wau.ACTIVITIESCACHE_FILENAME), wau.ACTIVITIESCACHE_FILENAME)
    assert len(records2) == 1
    assert records2[0]["artifact_type"] == "windows_timeline_activity"


def test_parse_windows_activity_file_unrecognized_filename_returns_empty(tmp_path):
    p = tmp_path / 'unrelated.db'
    p.write_bytes(b'x')
    assert wau.parse_windows_activity_file(str(p), 'unrelated.db') == []
