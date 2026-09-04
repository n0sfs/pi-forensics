"""Non-rooted Android Calendar (events + attendees) extraction via the
same small companion app relayed through `adb shell content query` - the
4th data type this app's hand-built `pif-companion.apk` relay covers,
alongside SMS/Contacts/Call Log (see core/android_companion_sms_utils.py's
own module docstring for the full mechanism/gap-closing rationale, read
that first).

Calendar events are genuinely high-value pattern-of-life evidence (a
meeting's title, time, location, organizer, and every invited attendee's
own RSVP status) that this app had no other way to capture from a
non-rooted device - `adb backup`'s own per-app allowlist varies by which
calendar sync app is installed (the AOSP Calendar Provider itself has no
`allowBackup` declaration of its own to check the way `com.android.
contacts` does, since the Provider is a system component, not a normal
app - but in practice a device's actual calendar DATA usually lives synced
to a cloud account, e.g. Google Calendar, with no local backup path at all
regardless), so a direct `content query` against the Calendar Provider is
the one reliable way to see it locally.

Real, authoritative research (2026-09-04), fetched directly from Google's
own official Android Developers reference pages (via a real browser
session against developer.android.com, not the offline `android docs`
tool's own indexed knowledge base - that index only covers guide-level
docs, not the raw Javadoc API reference pages with literal string/int
constant values, confirmed by trying it first and getting "no document
found"), not guessed or recalled from memory - this project's own
established "confirm before build" discipline, applied here specifically
because getting an integer status-code mapping backwards would be a real,
silent correctness bug (report "Declined" for a truly "Accepted" RSVP),
not just a missing nice-to-have:

- Permission: `android.permission.READ_CALENDAR` - a single, plain
  "dangerous"-protection-level runtime permission, confirmed via Google's
  own "The Calendar Provider" guide (identity/providers/calendar-provider).
  No default-app-role dance needed at all, exactly like Contacts/Call Log -
  one `pm grant` is enough, no window of degraded phone functionality.
- Content URI, confirmed via the same guide's own literal intent-URI
  examples: `content://com.android.calendar/events` (== CalendarContract.
  Events.CONTENT_URI). The sibling `attendees` table URI
  (`content://com.android.calendar/attendees`) follows the identical
  `content://com.android.calendar/<table>` convention every constant on
  both reference pages below confirms has been stable and unchanged since
  API level 14 (Ice Cream Sandwich, 2011) - not independently re-fetched
  as its own separate guide example, but a solid inference given how
  consistently every other constant on both pages carries that exact same
  "Added in API level 14" marker with zero later revision.
- Every column-name STRING (not just the Java constant name) and every
  ATTENDEE_STATUS_*/ATTENDEE_RELATIONSHIP_*/ATTENDEE_TYPE_*/STATUS_*/
  AVAILABILITY_* integer constant value below was read directly off the
  real, live-rendered CalendarContract.EventsColumns and CalendarContract.
  AttendeesColumns API reference pages (developer.android.com/reference/
  android/provider/CalendarContract.{Events,Attendees}Columns) - not
  assumed from the Java constant's own name (a real, confirmed mismatch
  this exact check caught: EventsColumns.STATUS's actual column-name
  string is "eventStatus", not the more obvious-looking "status").

`adb shell content query` output format is identical to the SMS/Contacts/
Call Log case (shared parser - see parse_content_query_output()'s own
docstring in core/android_companion_sms_utils.py for the exact AOSP-
source-confirmed "Row: N col=val, col=val, ..." shape and why the
freeform-text column(s) must be requested last) - reused directly here,
not duplicated.

Recurring events (RRULE/RDATE/EXRULE/EXDATE) are deliberately NOT
expanded into their individual future occurrences here - the single
defining Events row (with DTSTART as its own anchor/first occurrence) is
captured as one record, with the raw RRULE text disclosed verbatim in
`extra` for an examiner to interpret themselves. Fully expanding a
recurrence rule into every real occurrence (which would need either the
separate CalendarContract.Instances table or a real RFC 5545 recurrence-
rule expansion library) is meaningfully more scope than this pass, and
this project's own established "narrower but confidently correct beats
guessed and wrong" precedent applies here too - deferred, not silently
half-done.

EVENT_LOCATION is captured as free text ONLY, deliberately never
geocoded - a calendar location is almost always a plain address/place-name
string ("Conference Room B", "123 Main St"), not a decimal lat/lon pair
the way EXIF GPS tags or Google Takeout location history are, so folding
it into this app's existing KML/geolocation export pipeline would require
a real geocoding API call - a new network dependency and a real privacy/
scope decision this offline forensic tool should never make silently on
an examiner's behalf. Disclosed, not attempted."""

PIF_COMPANION_CALENDAR_AUTHORITY = "pif.companion.calendar"

# Attendees table's rows all reference an event via this column - the
# actual query joins the two client-side in build_companion_calendar_
# records() (grouped in Python, not via a SQL JOIN the content:// query
# interface doesn't support), not a real relational join.
CALENDAR_ATTENDEES_EVENT_ID_COLUMN = "event_id"

# Order matters, matching every other companion module's own established
# free-text-column-last convention: 'title' (short, but a real freeform
# field), then 'eventLocation' (freeform), then 'description' (freeform
# and typically the longest/riskiest field of all) come last, in
# increasing order of "how likely is this to contain an embedded ', ' or
# '=' sequence that could confuse parse_content_query_output()'s marker
# search". Every earlier column is a narrowly-shaped id/timestamp/small
# integer/short string.
CALENDAR_EVENTS_QUERY_COLUMNS = [
    "_id", "calendar_id", "dtstart", "dtend", "eventTimezone", "allDay",
    "eventStatus", "availability", "selfAttendeeStatus", "organizer", "rrule",
    "title", "eventLocation", "description",
]

# 'attendeeName' last for the same reason, though in practice it's
# typically a short display name, not a long freeform field the way
# Events.description is.
CALENDAR_ATTENDEES_QUERY_COLUMNS = [
    "event_id", "attendeeRelationship", "attendeeType", "attendeeStatus",
    "attendeeEmail", "attendeeName",
]

# CalendarContract.EventsColumns.STATUS_* - confirmed live via the real
# API reference page (developer.android.com/reference/android/provider/
# CalendarContract.EventsColumns), not guessed.
EVENT_STATUS_LABELS = {0: "Tentative", 1: "Confirmed", 2: "Canceled"}

# CalendarContract.EventsColumns.AVAILABILITY_* - same source.
EVENT_AVAILABILITY_LABELS = {0: "Busy", 1: "Free", 2: "Tentative"}

# CalendarContract.AttendeesColumns.ATTENDEE_STATUS_* - confirmed live via
# the real API reference page (CalendarContract.AttendeesColumns), not
# guessed. Reused for selfAttendeeStatus too (Events.SELF_ATTENDEE_STATUS
# is documented as "a copy of the attendee status for the owner of this
# event" - the identical enum, not a separate one).
ATTENDEE_STATUS_LABELS = {0: "None", 1: "Accepted", 2: "Declined", 3: "Invited", 4: "Tentative"}

# CalendarContract.AttendeesColumns.RELATIONSHIP_* - same source.
ATTENDEE_RELATIONSHIP_LABELS = {0: "None", 1: "Attendee", 2: "Organizer", 3: "Performer", 4: "Speaker"}

# CalendarContract.AttendeesColumns.TYPE_* - same source.
ATTENDEE_TYPE_LABELS = {0: "None", 1: "Required", 2: "Optional", 3: "Resource"}


def _int_or_none(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def build_companion_calendar_records(event_rows, attendee_rows):
    """Turns parse_content_query_output()'s row dicts (queried separately
    against CALENDAR_EVENTS_QUERY_COLUMNS and CALENDAR_ATTENDEES_QUERY_
    COLUMNS) into this app's standard parsed_artifacts record shape - one
    record per event, with every matching attendee folded into that
    event's own `extra.attendees` list rather than emitted as separate,
    un-timestamped rows of their own (an attendee has no independent
    timestamp - it only ever means something relative to its parent
    event's own DTSTART, the same reasoning this app already applies to
    e.g. registry_rdp_mru's shared-timestamp-per-list convention).

    dtstart/dtend are milliseconds since the epoch (the exact same
    convention Telephony.Sms.DATE and CallLog.Calls.DATE already use) -
    reused as-is, no new epoch-conversion logic needed."""
    attendees_by_event = {}
    for row in attendee_rows:
        event_id = row.get(CALENDAR_ATTENDEES_EVENT_ID_COLUMN)
        if not event_id:
            continue
        rel_int = _int_or_none(row.get("attendeeRelationship"))
        type_int = _int_or_none(row.get("attendeeType"))
        status_int = _int_or_none(row.get("attendeeStatus"))
        attendees_by_event.setdefault(event_id, []).append({
            "name": row.get("attendeeName") or None,
            "email": row.get("attendeeEmail") or None,
            "relationship": rel_int,
            "relationship_label": ATTENDEE_RELATIONSHIP_LABELS.get(rel_int, f"Type {rel_int}" if rel_int is not None else "Unknown"),
            "type": type_int,
            "type_label": ATTENDEE_TYPE_LABELS.get(type_int, f"Type {type_int}" if type_int is not None else "Unknown"),
            "status": status_int,
            "status_label": ATTENDEE_STATUS_LABELS.get(status_int, f"Status {status_int}" if status_int is not None else "Unknown"),
        })

    records = []
    for row in event_rows:
        event_id = row.get("_id")
        title = row.get("title") or "(untitled event)"
        organizer = row.get("organizer") or None
        location = row.get("eventLocation") or None
        description = row.get("description") or None
        rrule = row.get("rrule") or None

        status_int = _int_or_none(row.get("eventStatus"))
        status_label = EVENT_STATUS_LABELS.get(status_int, f"Status {status_int}" if status_int is not None else "Unknown")
        availability_int = _int_or_none(row.get("availability"))
        availability_label = EVENT_AVAILABILITY_LABELS.get(availability_int, "Unknown")
        self_status_int = _int_or_none(row.get("selfAttendeeStatus"))
        self_status_label = ATTENDEE_STATUS_LABELS.get(self_status_int, "Unknown")
        all_day = row.get("allDay") in ("1", 1, True)

        raw_dtstart = row.get("dtstart", "")
        try:
            timestamp = int(raw_dtstart) / 1000.0
        except (TypeError, ValueError):
            timestamp = None
        raw_dtend = row.get("dtend", "")
        try:
            dtend_seconds = int(raw_dtend) / 1000.0
        except (TypeError, ValueError):
            dtend_seconds = None

        value_parts = [status_label]
        if organizer:
            value_parts.append(f"Organizer: {organizer}")
        if location:
            value_parts.append(f"Location: {location}")
        if all_day:
            value_parts.append("All Day")

        records.append({
            "artifact_type": "android_companion_calendar_event",
            "title": title,
            "url": "",
            "value": " | ".join(value_parts),
            "timestamp": timestamp,
            "extra": {
                "event_id": event_id,
                "calendar_id": row.get("calendar_id"),
                "dtstart_ms": row.get("dtstart"),
                "dtend_ms": row.get("dtend"),
                "dtend_epoch": dtend_seconds,
                "event_timezone": row.get("eventTimezone"),
                "all_day": all_day,
                "status": status_int,
                "status_label": status_label,
                "availability": availability_int,
                "availability_label": availability_label,
                "self_attendee_status": self_status_int,
                "self_attendee_status_label": self_status_label,
                "organizer": organizer,
                "rrule": rrule,
                "location": location,
                "description": description,
                "attendees": attendees_by_event.get(event_id, []),
            },
        })
    return records
