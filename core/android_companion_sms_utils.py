"""Non-rooted Android SMS extraction via a small companion app relayed
through `adb shell content query` - closes the one real gap this app's
`.ab` Android Backup Format decoder (core/android_backup_utils.py) can
never close on its own: a modern Android device's default SMS app is
almost always excluded from `adb backup` unless it happens to declare
`android:allowBackup="true"` (many are not), so a non-rooted phone with a
backup-excluded messaging app has no SMS content reachable via `.ab` at
all, exactly like Contacts/Call Log never are.

Researched and grounded 2026-09-04 (a real "review this app and similar
open source projects" request from the user): plain `adb shell content
query --uri content://sms` does NOT reliably work against a stock, modern
Android device - the `shell` identity has no READ_SMS grant by default,
confirmed via real search results and Android's own documented
Marshmallow+ SMS-provider restriction (a non-default SMS app - which the
`shell` identity structurally can never be - only sees `inbox`/`sent`
messages even WITH the permission granted). A companion app is required
either way.

This originally drove a separately vendored third-party app, adbsms.min
(github.com/gonodono/adbsms, MIT-licensed by Mike M.) - the exact same
day, this project's own Contacts/Call Log companion (core/android_
companion_contacts_calllog_utils.py) was hand-built mirroring adbsms's
own real relay-provider design, once a real Android build toolchain
(Google's official `android` CLI) was obtained. With that toolchain
proven and the exact SMS relay mechanism already fully understood from
reading adbsms's real source, the SMS capability was folded directly
into that same app (a third ContentProvider, SmsProvider.java, alongside
ContactsProvider/CallLogProvider) the same day - removing the separate
third-party dependency entirely rather than maintaining two vendored
apps for a mechanism this project now fully owns and builds itself. See
android_companion/README.md for the full app's own provenance.

Two real access tiers, both driven entirely by adb shell commands against
the installed collector - see execution_worker_android_companion_sms()
(routes/mobile.py) for the actual command sequence and disclosed
device-modification bookkeeping:

- READ-ONLY (default, lower risk): `adb shell pm grant <pkg>
  android.permission.READ_SMS`. Only ever sees `inbox`/`sent` - Android's
  own real, documented restriction for any app that isn't the current
  default SMS app, and adbsms's own README confirms this applies to it
  too. No disruption to the phone's own live messaging at all.
- FULL ACCESS (opt-in, real disclosed tradeoff): temporarily makes the
  collector the device's default SMS app role holder (`adb shell cmd
  role add-role-holder android.app.role.SMS <pkg>`) to see every folder
  (draft/outbox/failed/queued too) - but the phone's own real SMS app
  stops receiving/sending normal messages for as long as that role is
  held. The worker always restores the original default role holder (or
  removes the role entirely if none was set) before finishing, but this
  is a real, active window of degraded phone functionality, not a
  cosmetic caveat - the confirm dialog in the UI states this plainly
  before an examiner opts in.

Real, confirmed `Telephony.Sms` column semantics reused directly from
core/android_backup_utils.py's own already-researched-and-verified
findings (never re-derived here, to avoid two independently-drifting
copies of the same fact): DATE/DATE_SENT are milliseconds since the
epoch, and the numeric `type` column maps to the same MESSAGE_TYPE_*
constants (_SMS_TYPE_LABELS, imported directly from that module) already
used for `.ab`-derived SMS records - the live ContentProvider and the
`.ab` backup's own JSON export are both just different views onto the
exact same underlying columns.

`adb shell content query` output format confirmed directly from the real,
current AOSP source (frameworks/base cmds/content/.../Content.java,
QueryCommand.onExecute()), not guessed: one line per row, shaped
`Row: <index> col1=val1, col2=val2, ...` with NO escaping or quoting of
values at all - a value containing a literal ", " or "=" would corrupt a
naive comma-split parse. parse_content_query_output() below handles this
by deliberately requesting `body` (the one genuinely free-text column)
LAST in the projection and parsing by searching for each subsequent
column's own literal "<name>=" marker rather than blindly splitting on
", " - the one remaining, accepted, disclosed edge case is a non-body
column (address/date/etc, all narrowly-shaped fields in real data) whose
own value happens to contain a string that looks like a later column's
marker; not worth defending against given how implausible that is for
these particular column types, matching this project's own established
risk-tolerance for this class of parsing (e.g. core/firewall_log_utils.py's
admin-configurable-column trust).
"""
import re

from core.android_backup_utils import _SMS_TYPE_LABELS
from core.android_companion_contacts_calllog_utils import PIF_COMPANION_PACKAGE

# SmsProvider's own relay authority - a sibling of PIF_COMPANION_CONTACTS_
# AUTHORITY/PIF_COMPANION_CALLLOG_AUTHORITY (core/android_companion_
# contacts_calllog_utils.py), all three now served by the exact same
# vendored app (PIF_COMPANION_PACKAGE, imported above rather than
# duplicated - this module used to define its own ADBSMS_MIN_PACKAGE/
# ADBSMS_MIN_AUTHORITY pointing at the separate third-party app).
PIF_COMPANION_SMS_AUTHORITY = "pif.companion.sms"

# Order matters: 'body' (the one free-text column) must be requested LAST -
# see the module docstring's explanation of why. Every other column here is
# a narrowly-shaped field (an id, a timestamp, a phone number, a small
# integer) with no realistic risk of colliding with a later marker.
SMS_QUERY_COLUMNS = ["_id", "thread_id", "address", "date", "date_sent", "type", "read", "body"]

_ROW_PREFIX_RE = re.compile(r"^Row:\s*\d+\s+")


def parse_content_query_output(raw_stdout, columns=None):
    """Parses real `adb shell content query` output (see the module
    docstring for the exact, AOSP-source-confirmed format) into a list of
    {column_name: value_string} dicts, in row order. `columns` must be the
    exact, ordered column list the query's own --projection argument
    requested (defaults to SMS_QUERY_COLUMNS) - this function does not
    discover column names from the output itself, it looks for each
    expected column's own "name=" marker in the given order, which is what
    makes the trailing free-text column safe (see docstring).

    "No result found." (the real, exact string AOSP's Content.java prints
    for either a null cursor or a query with zero rows) returns [], not an
    error. Any line that doesn't start with "Row: " (a permission-denial
    stack trace, a shell error, anything else unexpected) is skipped, not
    force-parsed - real, malformed data is worse than a shorter, correct
    result. Never raises."""
    if columns is None:
        columns = SMS_QUERY_COLUMNS
    rows = []
    if not raw_stdout:
        return rows
    for line in raw_stdout.splitlines():
        line = line.rstrip("\r")
        if not line.startswith("Row:"):
            continue
        body = _ROW_PREFIX_RE.sub("", line, count=1)
        row = {}
        for i, col in enumerate(columns):
            marker = f"{col}="
            # Boundary-aware search, not a bare body.find(marker) - a plain
            # unanchored substring search can find a column's own marker
            # INSIDE an earlier, longer column name that happens to end
            # with the same text (e.g. MediaStore's "bucket_display_name="
            # itself ends with the literal substring "_display_name=", so a
            # naive search for the later, real "_display_name=" column
            # matched there instead - a real bug this exact check caught
            # live, 2026-09-04). Every genuine column boundary in this
            # format is either the very start of `body` (first column
            # only, no comma before it) or immediately preceded by ", " -
            # anchoring to one of those two positions is what a same-name
            # substring collision inside a longer column's own value can
            # never satisfy.
            boundary_idx = body.find(f", {marker}")
            if boundary_idx != -1:
                start = boundary_idx + 2
            elif body.startswith(marker):
                start = 0
            else:
                continue
            value_start = start + len(marker)
            if i + 1 < len(columns):
                next_marker = f", {columns[i + 1]}="
                end = body.find(next_marker, value_start)
                value = body[value_start:end] if end != -1 else body[value_start:]
            else:
                value = body[value_start:]
            row[col] = value
        if row:
            rows.append(row)
    return rows


def build_companion_sms_records(rows):
    """Turns parse_content_query_output()'s row dicts into this app's
    standard parsed_artifacts record shape ({artifact_type, title, url,
    value, timestamp, extra}), reusing _SMS_TYPE_LABELS directly from
    core/android_backup_utils.py rather than a second copy of the same
    MESSAGE_TYPE_* mapping. A row missing 'date' entirely (shouldn't
    happen against a real column that's always populated for a real SMS
    row, but defended anyway) gets timestamp=None rather than raising or
    guessing. artifact_type is deliberately distinct from android_ab_sms_
    message/android_sms_message - same underlying data, but a genuinely
    different, worth-disclosing acquisition method (a live query against
    an actively-modified device, not a passive file read)."""
    records = []
    for row in rows:
        raw_type = row.get("type", "")
        try:
            type_int = int(raw_type)
        except (TypeError, ValueError):
            type_int = None
        type_label = _SMS_TYPE_LABELS.get(type_int, f"Type {raw_type}" if raw_type else "Unknown")

        raw_date = row.get("date", "")
        try:
            timestamp = int(raw_date) / 1000.0
        except (TypeError, ValueError):
            timestamp = None

        address = row.get("address") or "(unknown)"
        body_text = row.get("body") or "(no text content)"

        records.append({
            "artifact_type": "android_companion_sms_message",
            "title": address,
            "url": "",
            "value": f"{type_label}: {body_text}",
            "timestamp": timestamp,
            "extra": {
                "sms_id": row.get("_id"),
                "thread_id": row.get("thread_id"),
                "address": address,
                "type": raw_type,
                "type_label": type_label,
                "read": row.get("read"),
                "date_sent": row.get("date_sent"),
                "body": body_text,
            },
        })
    return records
