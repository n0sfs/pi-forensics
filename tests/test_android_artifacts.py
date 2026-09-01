"""core/android_artifacts.py - Android SMS/Contacts/Call Log parsing from
the two on-device SQLite databases (mmssms.db, contacts2.db). Both are
plain SQLite, no third-party library needed to build or parse fixtures -
mirrors core/recyclebin_utils.py's own "the module and this test build/
read the same real, well-documented format directly" approach, just with
stdlib sqlite3 instead of struct-packed bytes.

Disclosed gap (matching the module's own docstring): these fixtures are
hand-built from the real, stable, public Android SDK Telephony.Sms/
ContactsContract schemas - not extracted from a real rooted-device
`physical` acquisition, since no rooted Android test device was available
when this module was written.
"""
import sqlite3

import core.android_artifacts as android


def _build_sms_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, "
                 "date_sent INTEGER, type INTEGER, body TEXT, read INTEGER, thread_id INTEGER)")
    conn.executemany(
        "INSERT INTO sms (_id, address, date, date_sent, type, body, read, thread_id) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, 1)", rows)
    conn.commit()
    conn.close()


def _build_contacts_db(path, data_rows, call_rows):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT)")
    conn.execute("CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, account_type TEXT, display_name TEXT)")
    conn.execute("CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, "
                 "mimetype_id INTEGER, data1 TEXT, data2 TEXT, data3 TEXT)")
    conn.execute("CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, "
                 "duration INTEGER, type INTEGER, name TEXT, geocoded_location TEXT)")
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (1, ?)", (android._MIME_STRUCTURED_NAME,))
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (2, ?)", (android._MIME_PHONE,))
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (3, ?)", (android._MIME_EMAIL,))
    conn.executemany(
        "INSERT INTO data (raw_contact_id, mimetype_id, data1, data2, data3) VALUES (?, ?, ?, ?, ?)",
        data_rows)
    conn.executemany(
        "INSERT INTO calls (number, date, duration, type, name, geocoded_location) VALUES (?, ?, ?, ?, ?, '')",
        call_rows)
    conn.commit()
    conn.close()


def test_android_ms_to_unix_is_a_units_conversion_not_a_different_epoch():
    # Android's SQLite date columns are plain Unix-epoch milliseconds - the
    # SAME 1970-01-01 origin every other Unix timestamp in this app uses,
    # just scaled. 1700000000000 ms == 1700000000.0 s exactly (not some
    # offset epoch like WebKit/FILETIME/Cocoa elsewhere in this codebase).
    assert android.android_ms_to_unix(1700000000000) == 1700000000.0
    assert android.android_ms_to_unix(None) is None
    assert android.android_ms_to_unix("not-a-number") is None


def test_parse_android_sms_db_real_schema(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_sms_db(db_path, [
        (1, "+15551234567", 1700000000000, 1700000000000, 1, "Hey, are we still on for tonight?"),
        (2, "+15551234567", 1700000100000, 1700000100000, 2, "Yes! See you at 7."),
        (3, "+15559999999", 1700000200000, 1700000200000, 1, ""),  # empty body - skipped
    ])
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 2  # the empty-body row is correctly excluded
    inbox = next(r for r in records if r["extra"]["direction"] == "Inbox")
    assert inbox["artifact_type"] == "android_sms_message"
    assert inbox["value"] == "Hey, are we still on for tonight?"
    assert inbox["extra"]["address"] == "+15551234567"
    assert inbox["timestamp"] == 1700000000.0
    sent = next(r for r in records if r["extra"]["direction"] == "Sent")
    assert sent["value"] == "Yes! See you at 7."


def test_parse_android_sms_db_unrecognized_type_falls_back_to_numeric_label(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_sms_db(db_path, [(1, "+15550000000", 1700000000000, 1700000000000, 99, "Weird type")])
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert records[0]["extra"]["direction"] == "Type 99"


def test_parse_android_contacts_real_schema(tmp_path):
    db_path = str(tmp_path / "contacts2.db")
    _build_contacts_db(db_path,
        data_rows=[
            (1, 1, "Jane Doe", "Jane", "Doe"),   # StructuredName for raw_contact_id 1
            (1, 2, "+15551112222", None, None),  # Phone for raw_contact_id 1
            (1, 3, "jane@example.com", None, None),  # Email for raw_contact_id 1
            (2, 1, "No Phone Guy", "No Phone", "Guy"),  # a name-only contact - excluded (no phone/email)
        ],
        call_rows=[])
    records = android.parse_android_contacts_db(db_path, "contacts2.db")
    assert len(records) == 1  # the name-only contact correctly produced no record
    jane = records[0]
    assert jane["artifact_type"] == "android_contact"
    assert jane["title"] == "Jane Doe"
    assert "+15551112222" in jane["value"]
    assert "jane@example.com" in jane["value"]
    assert jane["extra"]["phones"] == ["+15551112222"]
    assert jane["extra"]["emails"] == ["jane@example.com"]


def test_parse_android_call_log_real_schema(tmp_path):
    db_path = str(tmp_path / "contacts2.db")
    _build_contacts_db(db_path, data_rows=[], call_rows=[
        ("+15551112222", 1700000000000, 45, 1, "Jane Doe"),   # Incoming
        ("+15559999999", 1700000100000, 0, 3, None),           # Missed, no saved name
    ])
    records = android.parse_android_contacts_db(db_path, "contacts2.db")
    assert len(records) == 2
    incoming = next(r for r in records if r["extra"]["direction"] == "Incoming")
    assert incoming["artifact_type"] == "android_call_log"
    assert incoming["title"] == "Incoming - Jane Doe"
    assert incoming["value"] == "45s"
    assert incoming["timestamp"] == 1700000000.0
    missed = next(r for r in records if r["extra"]["direction"] == "Missed")
    assert missed["title"] == "Missed - +15559999999"  # falls back to number when no saved name


def test_parse_android_artifact_file_dispatches_by_exact_basename(tmp_path):
    sms_path = str(tmp_path / "mmssms.db")
    _build_sms_db(sms_path, [(1, "+1555", 1700000000000, 1700000000000, 1, "hi")])
    assert len(android.parse_android_artifact_file(sms_path, "mmssms.db")) == 1

    contacts_path = str(tmp_path / "contacts2.db")
    _build_contacts_db(contacts_path,
        data_rows=[(1, 1, "X", None, None), (1, 2, "+1555", None, None)], call_rows=[])
    assert len(android.parse_android_artifact_file(contacts_path, "contacts2.db")) == 1

    assert android.parse_android_artifact_file(sms_path, "unrecognized.db") == []


def test_parsers_tolerate_a_file_that_is_not_actually_a_matching_sqlite_db(tmp_path):
    garbage_path = tmp_path / "mmssms.db"
    garbage_path.write_bytes(b"not a real sqlite file at all")
    assert android.parse_android_sms_db(str(garbage_path), "mmssms.db") == []
    assert android.parse_android_artifact_file(str(garbage_path), "mmssms.db") == []


def test_parse_android_contacts_db_missing_calls_table_still_parses_contacts(tmp_path):
    # A real contacts2.db missing the `calls` table entirely (an unusual
    # build/config) should never abort contact parsing - _parse_call_log's
    # own sqlite3.Error catch should silently no-op instead.
    db_path = str(tmp_path / "contacts2.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT)")
    conn.execute("CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, "
                 "mimetype_id INTEGER, data1 TEXT, data2 TEXT, data3 TEXT)")
    conn.execute("INSERT INTO mimetypes (_id, mimetype) VALUES (1, ?)", (android._MIME_PHONE,))
    conn.execute("INSERT INTO data (raw_contact_id, mimetype_id, data1) VALUES (1, 1, '+15551234567')")
    conn.commit()
    conn.close()
    records = android.parse_android_contacts_db(db_path, "contacts2.db")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "android_contact"
