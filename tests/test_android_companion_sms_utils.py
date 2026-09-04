"""Tests for core/android_companion_sms_utils.py - the non-rooted, no-root
companion-app SMS extraction feature (pif-companion relay app, 2026-09-04,
consolidated the same day from a separately-vendored adbsms.min relay).

parse_content_query_output() is the one genuinely risky piece here (a
hand-rolled parser for AOSP's real, unescaped "Row: N col=val, col=val"
`content query` output format) - most of this file exercises it directly
against realistic fixture text, including the exact edge case (a message
body containing embedded ", " and "=" sequences) the module's own
docstring identifies as the reason `body` must be the last requested
column.
"""
from core.android_companion_sms_utils import (
    parse_content_query_output, build_companion_sms_records, SMS_QUERY_COLUMNS,
)


def test_parse_content_query_output_no_result_found_returns_empty_list():
    assert parse_content_query_output("No result found.") == []
    assert parse_content_query_output("") == []
    assert parse_content_query_output(None) == []


def test_parse_content_query_output_single_row():
    raw = ("Row: 0 _id=1, thread_id=1, address=+15551234567, date=1700000000000, "
           "date_sent=1700000000000, type=1, read=1, body=Hello there")
    rows = parse_content_query_output(raw)
    assert len(rows) == 1
    r = rows[0]
    assert r["_id"] == "1"
    assert r["thread_id"] == "1"
    assert r["address"] == "+15551234567"
    assert r["date"] == "1700000000000"
    assert r["date_sent"] == "1700000000000"
    assert r["type"] == "1"
    assert r["read"] == "1"
    assert r["body"] == "Hello there"


def test_parse_content_query_output_multiple_rows_in_order():
    raw = (
        "Row: 0 _id=1, thread_id=1, address=5551234567, date=1700000000000, "
        "date_sent=1700000000000, type=2, read=1, body=First message\n"
        "Row: 1 _id=2, thread_id=1, address=5551234567, date=1700000060000, "
        "date_sent=1700000060000, type=1, read=0, body=Second message"
    )
    rows = parse_content_query_output(raw)
    assert len(rows) == 2
    assert rows[0]["body"] == "First message"
    assert rows[0]["type"] == "2"
    assert rows[1]["body"] == "Second message"
    assert rows[1]["read"] == "0"


def test_parse_content_query_output_body_with_embedded_comma_and_equals_survives_intact():
    # The real reason `body` must be requested LAST: a naive ", "-split
    # parser would corrupt this exact message, splitting it into several
    # bogus "columns" instead of preserving it as one value.
    raw = ("Row: 0 _id=1, thread_id=1, address=5551234567, date=1700000000000, "
           "date_sent=1700000000000, type=1, read=1, "
           "body=Meet at 5pm, bring cash=$40, see you there!")
    rows = parse_content_query_output(raw)
    assert len(rows) == 1
    assert rows[0]["body"] == "Meet at 5pm, bring cash=$40, see you there!"
    assert rows[0]["address"] == "5551234567"  # unaffected by the messy body


def test_parse_content_query_output_skips_non_row_lines():
    # A permission-denial stack trace or shell error line must never be
    # force-parsed as if it were real data.
    raw = (
        "java.lang.SecurityException: Permission Denial: reading\n"
        "\tat android.os.Parcel.createExceptionOrNull(Parcel.java:3212)\n"
        "Row: 0 _id=1, thread_id=1, address=5551234567, date=1700000000000, "
        "date_sent=1700000000000, type=1, read=1, body=Real message"
    )
    rows = parse_content_query_output(raw)
    assert len(rows) == 1
    assert rows[0]["body"] == "Real message"


def test_parse_content_query_output_missing_column_in_a_row_omits_key_not_crash():
    raw = "Row: 0 _id=1, address=5551234567, type=1, body=No thread_id here"
    rows = parse_content_query_output(raw)
    assert len(rows) == 1
    assert "thread_id" not in rows[0]
    assert rows[0]["body"] == "No thread_id here"


def test_parse_content_query_output_respects_custom_column_order():
    # A caller passing a different (still body-last) projection must be
    # honored, not silently overridden by the SMS_QUERY_COLUMNS default.
    raw = "Row: 0 address=5551234567, type=2, body=Custom order test"
    rows = parse_content_query_output(raw, columns=["address", "type", "body"])
    assert rows[0] == {"address": "5551234567", "type": "2", "body": "Custom order test"}


def test_build_companion_sms_records_full_type_label_coverage():
    rows = [{"_id": str(i), "thread_id": "1", "address": "5551234567",
             "date": "1700000000000", "date_sent": "1700000000000",
             "type": str(i), "read": "1", "body": f"msg {i}"} for i in range(7)]
    records = build_companion_sms_records(rows)
    labels = [r["value"].split(":")[0] for r in records]
    assert labels == ["All", "Received", "Sent", "Draft", "Outbox", "Failed", "Queued"]


def test_build_companion_sms_records_timestamp_is_milliseconds_converted_to_seconds():
    rows = [{"_id": "1", "address": "5551234567", "date": "1700000000000",
             "type": "1", "body": "hi"}]
    records = build_companion_sms_records(rows)
    assert records[0]["timestamp"] == 1700000000.0


def test_build_companion_sms_records_missing_or_malformed_date_gives_none_not_crash():
    rows = [
        {"_id": "1", "address": "5551234567", "type": "1", "body": "no date at all"},
        {"_id": "2", "address": "5551234567", "date": "not-a-number", "type": "1", "body": "garbage date"},
    ]
    records = build_companion_sms_records(rows)
    assert records[0]["timestamp"] is None
    assert records[1]["timestamp"] is None


def test_build_companion_sms_records_unknown_type_falls_back_cleanly():
    rows = [{"_id": "1", "address": "5551234567", "date": "1700000000000",
             "type": "99", "body": "weird type"}]
    records = build_companion_sms_records(rows)
    assert records[0]["value"].startswith("Type 99:")


def test_build_companion_sms_records_artifact_type_and_shape():
    rows = [{"_id": "1", "thread_id": "2", "address": "5551234567",
             "date": "1700000000000", "date_sent": "1700000000000",
             "type": "1", "read": "1", "body": "shape check"}]
    records = build_companion_sms_records(rows)
    r = records[0]
    assert r["artifact_type"] == "android_companion_sms_message"
    assert r["title"] == "5551234567"
    assert set(r.keys()) == {"artifact_type", "title", "url", "value", "timestamp", "extra"}
    assert r["extra"]["sms_id"] == "1"
    assert r["extra"]["thread_id"] == "2"
    assert r["extra"]["body"] == "shape check"


def test_build_companion_sms_records_empty_body_gets_placeholder():
    rows = [{"_id": "1", "address": "5551234567", "date": "1700000000000",
             "type": "1", "body": ""}]
    records = build_companion_sms_records(rows)
    assert "(no text content)" in records[0]["value"]


def test_sms_query_columns_has_body_last():
    # The single most load-bearing invariant this module depends on - see
    # both this module's and parse_content_query_output()'s own docstrings.
    assert SMS_QUERY_COLUMNS[-1] == "body"
