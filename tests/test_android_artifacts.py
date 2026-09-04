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


def _build_mms_db(path, pdu_rows, part_rows=(), addr_rows=()):
    """Real Telephony.Mms/Mms.Part/Mms.Addr schema - column names/PduHeaders
    constants confirmed directly against real AOSP source and a real,
    working MMS PDU-parsing library (see core/android_artifacts.py's own
    _parse_mms()/android_mms_date_to_unix() docstrings for the specific
    sources), not guessed. pdu_rows: (id, date, msg_box, sub).
    part_rows: (mid, ct, text, name, fn). addr_rows: (msg_id, address, type)."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE pdu (_id INTEGER PRIMARY KEY, date INTEGER, msg_box INTEGER, sub TEXT)")
    conn.execute("CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, text TEXT, "
                 "name TEXT, fn TEXT)")
    conn.execute("CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER)")
    conn.executemany("INSERT INTO pdu (_id, date, msg_box, sub) VALUES (?, ?, ?, ?)", pdu_rows)
    conn.executemany("INSERT INTO part (mid, ct, text, name, fn) VALUES (?, ?, ?, ?, ?)", part_rows)
    conn.executemany("INSERT INTO addr (msg_id, address, type) VALUES (?, ?, ?)", addr_rows)
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


# --- MMS (2026-09-04, Android pattern-of-life item 5) ---

def test_android_mms_date_to_unix_is_genuinely_different_math_from_ms_epoch():
    # The real, confirmed regression this dedicated function exists to
    # prevent: feeding the SAME raw value through android_ms_to_unix()
    # (milliseconds) vs android_mms_date_to_unix() (seconds) must produce
    # two very different real answers, not the same value scaled - proves
    # this isn't a copy-paste of the SMS/CallLog conversion.
    raw = 1700000000
    ms_result = android.android_ms_to_unix(raw)   # treats raw AS milliseconds
    mms_result = android.android_mms_date_to_unix(raw)  # treats raw AS seconds
    assert mms_result == 1700000000.0
    assert ms_result == 1700000.0
    assert abs(mms_result - ms_result) > 1_000_000  # genuinely, hugely different
    assert android.android_mms_date_to_unix(None) is None
    assert android.android_mms_date_to_unix("not-a-number") is None


def test_parse_mms_incoming_text_message_real_schema(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_mms_db(db_path,
        pdu_rows=[(1, 1700000000, 1, None)],  # msg_box=1 -> Inbox
        part_rows=[(1, "text/plain", "Running 10 min late", None, None)],
        addr_rows=[(1, "+15551234567", 137)])  # PduHeaders.FROM
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_mms_message"
    assert r["extra"]["direction"] == "Inbox"
    assert r["extra"]["counterpart"] == "+15551234567"
    assert r["value"] == "Running 10 min late"
    assert r["timestamp"] == 1700000000.0  # seconds, not divided


def test_parse_mms_outgoing_with_photo_attachment_and_subject(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_mms_db(db_path,
        pdu_rows=[(1, 1700000100, 2, "Check this out")],  # msg_box=2 -> Sent
        part_rows=[
            (1, "application/smil", None, None, None),  # SMIL layout part - deliberately excluded
            (1, "image/jpeg", None, "vacation.jpg", None),
        ],
        addr_rows=[(1, "+15559876543", 151)])  # PduHeaders.TO
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 1
    r = records[0]
    assert r["extra"]["direction"] == "Sent"
    assert r["extra"]["counterpart"] == "+15559876543"
    assert "Subject: Check this out" in r["value"]
    assert "1 attachment(s): vacation.jpg" in r["value"]
    assert r["extra"]["attachment_names"] == ["vacation.jpg"]


def test_parse_mms_group_message_folds_cc_and_bcc_into_the_to_bucket(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_mms_db(db_path,
        pdu_rows=[(1, 1700000200, 2, None)],
        part_rows=[(1, "text/plain", "See everyone Friday", None, None)],
        addr_rows=[(1, "+15551111111", 151),  # TO
                   (1, "+15552222222", 130),  # CC
                   (1, "+15553333333", 129)])  # BCC
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 1
    to_addrs = records[0]["extra"]["to_addresses"]
    assert set(to_addrs) == {"+15551111111", "+15552222222", "+15553333333"}


def test_parse_mms_empty_pdu_with_no_text_attachment_or_subject_is_skipped(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_mms_db(db_path, pdu_rows=[(1, 1700000000, 1, None)])  # no part/addr rows at all
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert records == []


def test_parse_mms_missing_pdu_table_does_not_break_sms_parsing(tmp_path):
    # A device/build with no MMS ever sent/received might genuinely lack
    # pdu/part/addr entirely - _parse_mms()'s own sqlite3.Error catch must
    # not abort _parse_sms(), same as _parse_call_log's own precedent.
    db_path = str(tmp_path / "mmssms.db")
    _build_sms_db(db_path, [(1, "+15551234567", 1700000000000, 1700000000000, 1, "just sms, no mms")])
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 1
    assert records[0]["artifact_type"] == "android_sms_message"


def test_parse_android_sms_db_combines_sms_and_mms_from_the_same_file(tmp_path):
    db_path = str(tmp_path / "mmssms.db")
    _build_sms_db(db_path, [(1, "+15551234567", 1700000000000, 1700000000000, 1, "sms message")])
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE pdu (_id INTEGER PRIMARY KEY, date INTEGER, msg_box INTEGER, sub TEXT)")
    conn.execute("CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, text TEXT, "
                 "name TEXT, fn TEXT)")
    conn.execute("CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER)")
    conn.execute("INSERT INTO pdu (_id, date, msg_box, sub) VALUES (1, 1700000100, 1, NULL)")
    conn.execute("INSERT INTO part (mid, ct, text) VALUES (1, 'text/plain', 'mms message')")
    conn.execute("INSERT INTO addr (msg_id, address, type) VALUES (1, '+15559999999', 137)")
    conn.commit()
    conn.close()
    records = android.parse_android_sms_db(db_path, "mmssms.db")
    assert len(records) == 2
    assert {r["artifact_type"] for r in records} == {"android_sms_message", "android_mms_message"}
