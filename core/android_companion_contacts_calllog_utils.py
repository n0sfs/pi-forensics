"""Non-rooted Android Contacts/Call Log extraction via a small companion
app relayed through `adb shell content query` - the same real gap and the
same mechanism already documented at length in
core/android_companion_sms_utils.py's own module docstring (read that
first), extended to the two data types the AFLogical-style tooling of a
decade ago used to cover before Android's runtime-permission model made
that approach obsolete: Contacts and Call Log are BOTH unreachable via
`.ab`/adb backup on a modern device (core/android_backup_utils.py's own
docstring already confirms this via a direct AOSP manifest check -
com.android.contacts, which owns both providers, declares
android:allowBackup="false" at the application level, so the OS itself
excludes this data from every `adb backup` before the file is even
written), and reading them via a bare `adb shell content query` fails the
same way SMS does - the `shell` identity has no READ_CONTACTS/READ_CALL_LOG
grant by default.

Unlike SMS, neither of these two needs any default-app-role dance -
READ_CONTACTS and READ_CALL_LOG are both plain "dangerous"-protection-level
runtime permissions, confirmed via the official Android developer
documentation's own "Retrieve Contact Details" guide (fetched directly via
the `android docs` tool, not assumed) and CallLog's own stable,
unchanged-since-API-1 authority ("call_log") and permission constant. This
is a real, meaningful simplification over the SMS companion: a single
`pm grant` per permission is enough, there's no "assume then restore the
default role" cleanup step, and no window of degraded phone functionality
- the device's own Contacts/Phone apps are completely unaffected the whole
time this companion app holds these grants.

No suitable existing open-source relay app was found for these two data
types when this gap was first surveyed (2026-09-04) - the closest
candidates were either UI-driven dev tools with no headless build
(ContentProviderTester) or long-archived, pre-runtime-permission-model
tools with no LICENSE file (nowsecure/android-forensics, the old
AFLogical). Rather than leave the gap open, this companion app
(source: routes/mobile.py's ANDROID_COMPANION_CONTACTS_CALLLOG_* constants
and core's own vendored `pif-companion.apk`) was hand-built the same day,
directly mirroring github.com/gonodono/adbsms's own proven relay-provider
design (its real source was cloned and read to confirm the exact pattern
before writing this app's own two provider classes, ContactsProvider.java/
CallLogProvider.java) - a pure ContentProvider authority-rewriting pass-
through for each data type, each restricted to SHELL_UID callers only via
the identical checkCallingProcess() guard adbsms itself uses, built with
Google's own official `android` CLI tool (developer.android.com/tools/
agents/android-cli) rather than needing Android Studio - confirmed live
that its bundled JDK/SDK-management/build pipeline works entirely
headlessly from this dev environment, closing the "no Android build
tooling available" gap the SMS companion's own docstring disclosed as
still-open.

`adb shell content query` output format is identical to the SMS case
(shared parser, see parse_content_query_output()'s own docstring in
core/android_companion_sms_utils.py for the exact AOSP-source-confirmed
"Row: N col=val, col=val, ..." shape and why the free-text column must be
requested last) - reused directly here rather than a second copy of the
same parsing logic, matching this project's own established cross-module
reuse-via-import convention (the SMS module itself already imports
_SMS_TYPE_LABELS from core/android_backup_utils.py for the identical
reason). Callers (routes/mobile.py) import parse_content_query_output
directly from core.android_companion_sms_utils, its actual home - not
re-exported through here, matching this project's own "import from the
real source, don't add an indirection layer" convention.
"""

PIF_COMPANION_PACKAGE = "com.pif.companion"
PIF_COMPANION_CONTACTS_AUTHORITY = "pif.companion.contacts"
PIF_COMPANION_CALLLOG_AUTHORITY = "pif.companion.calllog"

# Order matters: 'display_name' (the one genuinely freeform field - a
# contact's own chosen name) is requested LAST, matching the SMS module's
# own free-text-column-last convention. contact_id groups rows belonging
# to the same contact; mimetype distinguishes what data1/data2/data3 hold
# for that row (a phone number, an email address, etc. - see
# CONTACTS_MIMETYPE_LABELS below); data2 is commonly a numeric TYPE code
# (Mobile/Home/Work/...), data3 a custom label string when data2 signals
# a custom type.
CONTACTS_QUERY_COLUMNS = ["_id", "contact_id", "mimetype", "data1", "data2", "data3", "display_name"]

# Real, stable ContentValues type-code constants from
# ContactsContract.CommonDataKinds.{Phone,Email}.TYPE - unchanged since
# these classes were introduced. 0 ("Custom") means the real label lives
# in data3 instead.
CONTACTS_PHONE_TYPE_LABELS = {
    0: "Custom", 1: "Home", 2: "Mobile", 3: "Work", 4: "Work Fax",
    5: "Home Fax", 6: "Pager", 7: "Other", 8: "Callback", 9: "Car",
    10: "Company Main", 11: "ISDN", 12: "Main", 13: "Other Fax",
    14: "Radio", 15: "Telex", 16: "TTY TDD", 17: "Work Mobile",
    18: "Work Pager", 19: "Assistant", 20: "MMS",
}
CONTACTS_EMAIL_TYPE_LABELS = {
    0: "Custom", 1: "Home", 2: "Work", 3: "Other", 4: "Mobile",
}

# Real, stable ContactsContract.CommonDataKinds.*.CONTENT_ITEM_TYPE MIME
# constants for the row types most worth surfacing to an examiner - every
# other mimetype (structured postal address, organization, IM, website,
# etc.) still comes back from the query and lands in `extra` untouched,
# just without a friendlier label here.
CONTACTS_MIMETYPE_LABELS = {
    "vnd.android.cursor.item/phone_v2": "Phone",
    "vnd.android.cursor.item/email_v2": "Email",
    "vnd.android.cursor.item/name": "Name",
    "vnd.android.cursor.item/postal-address_v2": "Address",
    "vnd.android.cursor.item/organization": "Organization",
    "vnd.android.cursor.item/im": "Instant Messaging",
    "vnd.android.cursor.item/website": "Website",
    "vnd.android.cursor.item/note": "Note",
}

# Order matters: 'name' (the cached, resolved display name for the number,
# if any - the one genuinely freeform field here) is requested LAST,
# matching the SMS module's own free-text-column-last convention. Every
# other CallLog.Calls column is a narrowly-shaped field (an id, a phone
# number, a timestamp, a small integer).
CALLLOG_QUERY_COLUMNS = ["_id", "number", "date", "duration", "type", "numbertype", "numberlabel", "name"]

# Real, stable CallLog.Calls.*_TYPE int constants - unchanged since API 1
# (ANSWERED_EXTERNALLY_TYPE was added later, API 21, but the numbering of
# every earlier constant was never revised).
CALLLOG_TYPE_LABELS = {
    1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Voicemail",
    5: "Rejected", 6: "Blocked", 7: "Answered Externally",
}


def build_companion_contact_records(rows):
    """Turns parse_content_query_output()'s row dicts (queried against
    CONTACTS_QUERY_COLUMNS) into this app's standard parsed_artifacts
    record shape. timestamp is always None - ContactsContract.Data rows
    carry no per-row timestamp at all (unlike SMS/CallLog), only a
    contact-level CONTACTS_LAST_UPDATED_TIMESTAMP this app doesn't request
    here, so this is an honest gap, not an oversight."""
    records = []
    for row in rows:
        mimetype = row.get("mimetype") or ""
        type_label = CONTACTS_MIMETYPE_LABELS.get(mimetype, mimetype or "Unknown")
        value = row.get("data1") or "(no value)"

        subtype_label = None
        if mimetype == "vnd.android.cursor.item/phone_v2":
            subtype_label = _resolve_subtype_label(row.get("data2"), row.get("data3"), CONTACTS_PHONE_TYPE_LABELS)
        elif mimetype == "vnd.android.cursor.item/email_v2":
            subtype_label = _resolve_subtype_label(row.get("data2"), row.get("data3"), CONTACTS_EMAIL_TYPE_LABELS)

        display_value = f"{type_label} ({subtype_label}): {value}" if subtype_label else f"{type_label}: {value}"

        records.append({
            "artifact_type": "android_companion_contact",
            "title": row.get("display_name") or "(unnamed contact)",
            "url": "",
            "value": display_value,
            "timestamp": None,
            "extra": {
                "data_row_id": row.get("_id"),
                "contact_id": row.get("contact_id"),
                "mimetype": mimetype,
                "mimetype_label": type_label,
                "data1": value,
                "data2": row.get("data2"),
                "data3": row.get("data3"),
            },
        })
    return records


def build_companion_call_log_records(rows):
    """Turns parse_content_query_output()'s row dicts (queried against
    CALLLOG_QUERY_COLUMNS) into this app's standard parsed_artifacts
    record shape. date is milliseconds since the epoch (the same
    convention CallLog.Calls.DATE has always used, identical to
    Telephony.Sms.DATE) - duration is whole seconds."""
    records = []
    for row in rows:
        raw_type = row.get("type", "")
        try:
            type_int = int(raw_type)
        except (TypeError, ValueError):
            type_int = None
        type_label = CALLLOG_TYPE_LABELS.get(type_int, f"Type {raw_type}" if raw_type else "Unknown")

        raw_date = row.get("date", "")
        try:
            timestamp = int(raw_date) / 1000.0
        except (TypeError, ValueError):
            timestamp = None

        number = row.get("number") or "(unknown number)"
        name = row.get("name") or None
        duration = row.get("duration") or "0"
        title = f"{name} ({number})" if name else number

        records.append({
            "artifact_type": "android_companion_call_log_entry",
            "title": title,
            "url": "",
            "value": f"{type_label} call, {duration}s",
            "timestamp": timestamp,
            "extra": {
                "call_id": row.get("_id"),
                "number": number,
                "name": name,
                "type": raw_type,
                "type_label": type_label,
                "duration_seconds": duration,
                "number_type": row.get("numbertype"),
                "number_label": row.get("numberlabel"),
            },
        })
    return records


def _resolve_subtype_label(raw_data2, raw_data3, type_labels):
    """Resolves a Phone/Email row's own TYPE (data2) to a readable label,
    falling back to the custom label (data3) when the type code is 0
    ("Custom") - the standard ContactsContract convention for both
    CommonDataKinds.Phone and CommonDataKinds.Email."""
    try:
        type_int = int(raw_data2)
    except (TypeError, ValueError):
        return None
    if type_int == 0 and raw_data3:
        return raw_data3
    return type_labels.get(type_int)
