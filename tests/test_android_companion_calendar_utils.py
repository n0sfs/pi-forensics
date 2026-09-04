"""Tests for core/android_companion_calendar_utils.py - the non-rooted,
no-root companion-app Calendar extraction feature (the pif-companion.apk
relay's 4th data type, 2026-09-04).

parse_content_query_output() itself is already thoroughly tested in
tests/test_android_companion_sms_utils.py (it's shared, unmodified code) -
this file focuses on build_companion_calendar_records() and the module's
own real-API-reference-confirmed query-column constants and status/
relationship/type label mappings.
"""
from core.android_companion_sms_utils import parse_content_query_output
from core.android_companion_calendar_utils import (
    build_companion_calendar_records,
    CALENDAR_EVENTS_QUERY_COLUMNS, CALENDAR_ATTENDEES_QUERY_COLUMNS,
    EVENT_STATUS_LABELS, EVENT_AVAILABILITY_LABELS,
    ATTENDEE_STATUS_LABELS, ATTENDEE_RELATIONSHIP_LABELS, ATTENDEE_TYPE_LABELS,
)


def test_events_query_columns_has_freeform_fields_last():
    # The single most load-bearing invariant this module depends on - see
    # both this module's and parse_content_query_output()'s own docstrings.
    # title/eventLocation/description are all real freeform fields, in
    # increasing order of risk.
    assert CALENDAR_EVENTS_QUERY_COLUMNS[-3:] == ["title", "eventLocation", "description"]


def test_attendees_query_columns_has_attendee_name_last():
    assert CALENDAR_ATTENDEES_QUERY_COLUMNS[-1] == "attendeeName"


def test_build_companion_calendar_records_basic_event_no_attendees():
    events = [{"_id": "1", "calendar_id": "2", "dtstart": "1700000000000", "dtend": "1700003600000",
               "eventTimezone": "America/New_York", "allDay": "0", "eventStatus": "1", "availability": "0",
               "selfAttendeeStatus": "1", "organizer": "boss@example.com", "rrule": "",
               "title": "Quarterly Review", "eventLocation": "Conference Room B",
               "description": "Discuss Q3 numbers"}]
    records = build_companion_calendar_records(events, [])
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_companion_calendar_event"
    assert r["title"] == "Quarterly Review"
    assert r["timestamp"] == 1700000000.0
    assert r["value"] == "Confirmed | Organizer: boss@example.com | Location: Conference Room B"
    assert r["extra"]["attendees"] == []
    # An empty rrule string means "no recurrence" - normalized to None,
    # matching organizer/location/description's own identical treatment.
    assert r["extra"]["rrule"] is None
    assert r["extra"]["description"] == "Discuss Q3 numbers"


def test_build_companion_calendar_records_status_labels_full_coverage():
    events = [{"_id": str(i), "dtstart": "1700000000000", "eventStatus": str(i), "title": f"Event {i}"}
              for i in range(3)]
    records = build_companion_calendar_records(events, [])
    labels = [r["value"].split(" | ")[0] for r in records]
    assert labels == ["Tentative", "Confirmed", "Canceled"]
    # Confirms these exactly match Google's own real, live-confirmed
    # CalendarContract.EventsColumns.STATUS_* integer constants.
    assert EVENT_STATUS_LABELS == {0: "Tentative", 1: "Confirmed", 2: "Canceled"}


def test_build_companion_calendar_records_availability_labels_full_coverage():
    assert EVENT_AVAILABILITY_LABELS == {0: "Busy", 1: "Free", 2: "Tentative"}
    events = [{"_id": "1", "dtstart": "1700000000000", "availability": "1", "title": "Free Time"}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["extra"]["availability_label"] == "Free"


def test_build_companion_calendar_records_unrecognized_status_falls_back_cleanly():
    events = [{"_id": "1", "dtstart": "1700000000000", "eventStatus": "99", "title": "Weird Event"}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["value"].startswith("Status 99")


def test_build_companion_calendar_records_untitled_event_gets_placeholder():
    events = [{"_id": "1", "dtstart": "1700000000000", "title": ""}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["title"] == "(untitled event)"


def test_build_companion_calendar_records_all_day_flag_true():
    events = [{"_id": "1", "dtstart": "1700000000000", "allDay": "1", "title": "Holiday"}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["extra"]["all_day"] is True
    assert "All Day" in records[0]["value"]


def test_build_companion_calendar_records_all_day_flag_false():
    events = [{"_id": "1", "dtstart": "1700000000000", "allDay": "0", "title": "Regular Meeting"}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["extra"]["all_day"] is False
    assert "All Day" not in records[0]["value"]


def test_build_companion_calendar_records_missing_or_malformed_dtstart_gives_none_not_crash():
    events = [
        {"_id": "1", "title": "No dtstart at all"},
        {"_id": "2", "dtstart": "garbage", "title": "Malformed dtstart"},
    ]
    records = build_companion_calendar_records(events, [])
    assert records[0]["timestamp"] is None
    assert records[1]["timestamp"] is None


def test_build_companion_calendar_records_dtend_captured_in_extra():
    events = [{"_id": "1", "dtstart": "1700000000000", "dtend": "1700003600000", "title": "Timed Event"}]
    records = build_companion_calendar_records(events, [])
    assert records[0]["extra"]["dtend_epoch"] == 1700003600.0
    assert records[0]["extra"]["dtend_ms"] == "1700003600000"


def test_build_companion_calendar_records_attendees_grouped_by_event_id():
    events = [
        {"_id": "1", "dtstart": "1700000000000", "title": "Meeting A"},
        {"_id": "2", "dtstart": "1700100000000", "title": "Meeting B"},
    ]
    attendees = [
        {"event_id": "1", "attendeeName": "Alice", "attendeeEmail": "alice@example.com",
         "attendeeRelationship": "1", "attendeeType": "1", "attendeeStatus": "1"},
        {"event_id": "1", "attendeeName": "Bob", "attendeeEmail": "bob@example.com",
         "attendeeRelationship": "1", "attendeeType": "2", "attendeeStatus": "2"},
        {"event_id": "2", "attendeeName": "Carol", "attendeeEmail": "carol@example.com",
         "attendeeRelationship": "2", "attendeeType": "1", "attendeeStatus": "3"},
    ]
    records = build_companion_calendar_records(events, attendees)
    by_id = {r["extra"]["event_id"]: r for r in records}

    meeting_a_attendees = by_id["1"]["extra"]["attendees"]
    assert len(meeting_a_attendees) == 2
    assert meeting_a_attendees[0]["name"] == "Alice"
    assert meeting_a_attendees[0]["status_label"] == "Accepted"
    assert meeting_a_attendees[1]["name"] == "Bob"
    assert meeting_a_attendees[1]["status_label"] == "Declined"

    meeting_b_attendees = by_id["2"]["extra"]["attendees"]
    assert len(meeting_b_attendees) == 1
    assert meeting_b_attendees[0]["name"] == "Carol"
    assert meeting_b_attendees[0]["relationship_label"] == "Organizer"
    assert meeting_b_attendees[0]["status_label"] == "Invited"


def test_build_companion_calendar_records_attendee_status_labels_full_coverage():
    # Confirmed live against Google's own real CalendarContract.
    # AttendeesColumns API reference page - not guessed.
    assert ATTENDEE_STATUS_LABELS == {0: "None", 1: "Accepted", 2: "Declined", 3: "Invited", 4: "Tentative"}
    events = [{"_id": "1", "dtstart": "1700000000000", "title": "Event"}]
    attendees = [{"event_id": "1", "attendeeName": f"Person {i}", "attendeeStatus": str(i)} for i in range(5)]
    records = build_companion_calendar_records(events, attendees)
    labels = [a["status_label"] for a in records[0]["extra"]["attendees"]]
    assert labels == ["None", "Accepted", "Declined", "Invited", "Tentative"]


def test_build_companion_calendar_records_attendee_relationship_and_type_labels_full_coverage():
    assert ATTENDEE_RELATIONSHIP_LABELS == {0: "None", 1: "Attendee", 2: "Organizer", 3: "Performer", 4: "Speaker"}
    assert ATTENDEE_TYPE_LABELS == {0: "None", 1: "Required", 2: "Optional", 3: "Resource"}


def test_build_companion_calendar_records_attendee_with_no_matching_event_is_silently_dropped():
    # A real, benign edge case - not something that should crash or
    # produce an orphaned/floating record with no parent event.
    events = [{"_id": "1", "dtstart": "1700000000000", "title": "Real Event"}]
    attendees = [{"event_id": "999", "attendeeName": "Orphan", "attendeeStatus": "1"}]
    records = build_companion_calendar_records(events, attendees)
    assert len(records) == 1
    assert records[0]["extra"]["attendees"] == []


def test_build_companion_calendar_records_shape():
    events = [{"_id": "1", "dtstart": "1700000000000", "title": "Event"}]
    records = build_companion_calendar_records(events, [])
    assert set(records[0].keys()) == {"artifact_type", "title", "url", "value", "timestamp", "extra"}


def test_end_to_end_parse_then_build_events():
    # Confirms the shared parse_content_query_output() genuinely feeds
    # build_companion_calendar_records() correctly - not just tested
    # against hand-built dicts in isolation.
    raw = ("Row: 0 _id=1, calendar_id=1, dtstart=1700000000000, dtend=1700003600000, "
           "eventTimezone=America/New_York, allDay=0, eventStatus=1, availability=0, "
           "selfAttendeeStatus=1, organizer=boss@example.com, rrule=, "
           "title=Real Meeting, eventLocation=HQ, description=Real agenda text")
    rows = parse_content_query_output(raw, columns=CALENDAR_EVENTS_QUERY_COLUMNS)
    records = build_companion_calendar_records(rows, [])
    assert len(records) == 1
    assert records[0]["title"] == "Real Meeting"
    assert records[0]["extra"]["location"] == "HQ"
    assert records[0]["extra"]["description"] == "Real agenda text"


def test_end_to_end_parse_then_build_attendees():
    raw = "Row: 0 event_id=1, attendeeRelationship=1, attendeeType=1, attendeeStatus=1, attendeeEmail=real@example.com, attendeeName=Real Attendee"
    rows = parse_content_query_output(raw, columns=CALENDAR_ATTENDEES_QUERY_COLUMNS)
    events = [{"_id": "1", "dtstart": "1700000000000", "title": "Real Meeting"}]
    records = build_companion_calendar_records(events, rows)
    attendees = records[0]["extra"]["attendees"]
    assert len(attendees) == 1
    assert attendees[0]["name"] == "Real Attendee"
    assert attendees[0]["email"] == "real@example.com"
    assert attendees[0]["status_label"] == "Accepted"
