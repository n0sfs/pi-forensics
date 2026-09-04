"""Tests for core/android_companion_contacts_calllog_utils.py - the
non-rooted, no-root companion-app Contacts/Call Log extraction feature
(the pif-companion.apk relay, 2026-09-04).

parse_content_query_output() itself is already thoroughly tested in
tests/test_android_companion_sms_utils.py (it's shared, unmodified code) -
this file focuses on the two build_companion_*_records() functions and
the module's own query-column constants, exercising the real
ContactsContract/CallLog.Calls type-code conventions against realistic
fixture data.
"""
from core.android_companion_sms_utils import parse_content_query_output
from core.android_companion_contacts_calllog_utils import (
    build_companion_contact_records, build_companion_call_log_records,
    CONTACTS_QUERY_COLUMNS, CALLLOG_QUERY_COLUMNS,
)


def test_contacts_query_columns_has_display_name_last():
    # The single most load-bearing invariant this module depends on - see
    # both this module's and parse_content_query_output()'s own docstrings.
    assert CONTACTS_QUERY_COLUMNS[-1] == "display_name"


def test_calllog_query_columns_has_name_last():
    assert CALLLOG_QUERY_COLUMNS[-1] == "name"


def test_build_companion_contact_records_phone_row_with_known_type():
    rows = [{"_id": "10", "contact_id": "3", "mimetype": "vnd.android.cursor.item/phone_v2",
             "data1": "+15551234567", "data2": "2", "data3": "", "display_name": "Jane Doe"}]
    records = build_companion_contact_records(rows)
    r = records[0]
    assert r["artifact_type"] == "android_companion_contact"
    assert r["title"] == "Jane Doe"
    assert r["value"] == "Phone (Mobile): +15551234567"
    assert r["timestamp"] is None
    assert r["extra"]["mimetype_label"] == "Phone"


def test_build_companion_contact_records_phone_row_with_custom_label():
    # data2=0 ("Custom") means the real label lives in data3, not the
    # standard type table - a real, documented ContactsContract convention.
    rows = [{"_id": "11", "contact_id": "3", "mimetype": "vnd.android.cursor.item/phone_v2",
             "data1": "+15559998888", "data2": "0", "data3": "Emergency Contact",
             "display_name": "Jane Doe"}]
    records = build_companion_contact_records(rows)
    assert records[0]["value"] == "Phone (Emergency Contact): +15559998888"


def test_build_companion_contact_records_email_row():
    rows = [{"_id": "12", "contact_id": "3", "mimetype": "vnd.android.cursor.item/email_v2",
             "data1": "jane@example.com", "data2": "1", "data3": "", "display_name": "Jane Doe"}]
    records = build_companion_contact_records(rows)
    assert records[0]["value"] == "Email (Home): jane@example.com"


def test_build_companion_contact_records_unrecognized_mimetype_falls_back_to_raw_string():
    rows = [{"_id": "13", "contact_id": "3", "mimetype": "vnd.android.cursor.item/nickname",
             "data1": "Janie", "data2": "", "data3": "", "display_name": "Jane Doe"}]
    records = build_companion_contact_records(rows)
    r = records[0]
    assert r["value"] == "vnd.android.cursor.item/nickname: Janie"
    assert r["extra"]["mimetype_label"] == "vnd.android.cursor.item/nickname"


def test_build_companion_contact_records_unnamed_contact_gets_placeholder():
    rows = [{"_id": "14", "contact_id": "9", "mimetype": "vnd.android.cursor.item/phone_v2",
             "data1": "5550001111", "data2": "1", "data3": "", "display_name": ""}]
    records = build_companion_contact_records(rows)
    assert records[0]["title"] == "(unnamed contact)"


def test_build_companion_contact_records_shape():
    rows = [{"_id": "15", "contact_id": "3", "mimetype": "vnd.android.cursor.item/phone_v2",
             "data1": "5551112222", "data2": "3", "data3": "", "display_name": "Test Person"}]
    records = build_companion_contact_records(rows)
    r = records[0]
    assert set(r.keys()) == {"artifact_type", "title", "url", "value", "timestamp", "extra"}
    assert r["extra"]["data_row_id"] == "15"
    assert r["extra"]["contact_id"] == "3"


def test_build_companion_call_log_records_full_type_label_coverage():
    rows = [{"_id": str(i), "number": "5551234567", "date": "1700000000000",
              "duration": "30", "type": str(i), "numbertype": "", "numberlabel": "",
              "name": ""} for i in range(1, 8)]
    records = build_companion_call_log_records(rows)
    labels = [r["value"].split(" call,")[0] for r in records]
    assert labels == ["Incoming", "Outgoing", "Missed", "Voicemail", "Rejected", "Blocked", "Answered Externally"]


def test_build_companion_call_log_records_timestamp_is_milliseconds_converted_to_seconds():
    rows = [{"_id": "1", "number": "5551234567", "date": "1700000000000",
             "duration": "60", "type": "1", "name": ""}]
    records = build_companion_call_log_records(rows)
    assert records[0]["timestamp"] == 1700000000.0


def test_build_companion_call_log_records_missing_or_malformed_date_gives_none_not_crash():
    rows = [
        {"_id": "1", "number": "5551234567", "duration": "0", "type": "3", "name": ""},
        {"_id": "2", "number": "5551234567", "date": "garbage", "duration": "0", "type": "3", "name": ""},
    ]
    records = build_companion_call_log_records(rows)
    assert records[0]["timestamp"] is None
    assert records[1]["timestamp"] is None


def test_build_companion_call_log_records_unknown_type_falls_back_cleanly():
    rows = [{"_id": "1", "number": "5551234567", "date": "1700000000000",
             "duration": "0", "type": "99", "name": ""}]
    records = build_companion_call_log_records(rows)
    assert records[0]["value"].startswith("Type 99 call,")


def test_build_companion_call_log_records_title_includes_resolved_name_when_present():
    rows = [{"_id": "1", "number": "5551234567", "date": "1700000000000",
             "duration": "45", "type": "1", "name": "Jane Doe"}]
    records = build_companion_call_log_records(rows)
    assert records[0]["title"] == "Jane Doe (5551234567)"


def test_build_companion_call_log_records_title_is_bare_number_when_name_absent():
    rows = [{"_id": "1", "number": "5551234567", "date": "1700000000000",
             "duration": "45", "type": "1", "name": ""}]
    records = build_companion_call_log_records(rows)
    assert records[0]["title"] == "5551234567"


def test_build_companion_call_log_records_unknown_number_gets_placeholder():
    rows = [{"_id": "1", "number": "", "date": "1700000000000", "duration": "0", "type": "3", "name": ""}]
    records = build_companion_call_log_records(rows)
    assert records[0]["title"] == "(unknown number)"


def test_build_companion_call_log_records_shape():
    rows = [{"_id": "1", "number": "5551234567", "date": "1700000000000",
             "duration": "10", "type": "1", "numbertype": "2", "numberlabel": "", "name": ""}]
    records = build_companion_call_log_records(rows)
    r = records[0]
    assert r["artifact_type"] == "android_companion_call_log_entry"
    assert set(r.keys()) == {"artifact_type", "title", "url", "value", "timestamp", "extra"}
    assert r["extra"]["call_id"] == "1"
    assert r["extra"]["number_type"] == "2"


def test_end_to_end_parse_then_build_contacts():
    # Confirms the shared parse_content_query_output() genuinely feeds
    # build_companion_contact_records() correctly - not just each function
    # tested against hand-built dicts in isolation.
    raw = ("Row: 0 _id=1, contact_id=5, mimetype=vnd.android.cursor.item/phone_v2, "
           "data1=+15551234567, data2=2, data3=, display_name=Real Contact")
    rows = parse_content_query_output(raw, columns=CONTACTS_QUERY_COLUMNS)
    records = build_companion_contact_records(rows)
    assert len(records) == 1
    assert records[0]["title"] == "Real Contact"
    assert records[0]["value"] == "Phone (Mobile): +15551234567"


def test_end_to_end_parse_then_build_call_log():
    raw = ("Row: 0 _id=1, number=5551234567, date=1700000000000, duration=90, "
           "type=2, numbertype=1, numberlabel=, name=Real Caller")
    rows = parse_content_query_output(raw, columns=CALLLOG_QUERY_COLUMNS)
    records = build_companion_call_log_records(rows)
    assert len(records) == 1
    assert records[0]["title"] == "Real Caller (5551234567)"
    assert records[0]["value"] == "Outgoing call, 90s"
    assert records[0]["timestamp"] == 1700000000.0
