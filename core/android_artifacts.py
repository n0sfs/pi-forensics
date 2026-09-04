"""Android SMS/MMS, Contacts, and Call Log parsing - from the two on-device
SQLite databases (mmssms.db, contacts2.db) that back the standard, public,
long-documented Android SDK content-provider schemas (android.provider.
Telephony.Sms, android.provider.ContactsContract). Mirrors core/registry_
utils.py's exact shape ({artifact_type, title, url, value, timestamp,
extra} records, a curated not exhaustive set of tables/columns) so the
shared, already-generic _record_parsed_artifacts()/parsed_artifacts table
and File Views' "Parsed Artifacts" rendering need zero changes to support
a new source.

Deliberately in-image only, unlike every other real-fs+in-image parser
pair in this codebase - see this module's own real, confirmed finding:
both databases live under /data/data/<package>/databases/, which a
non-rooted `adb pull` acquisition (this app's `pull` mode, confirmed live
against a real Pixel 8a) can never reach - it's sandboxed to /sdcard. The
only acquisition mode in this app that can reach /data/data/ at all is
`physical` (a rooted, raw-block-device dd image), which produces a real
disk/partition IMAGE, not a folder - so this module is wired only into
routes/image_browser.py's pytsk3-backed in-image pipeline (extract via
_tsk_extract_to_temp(), then parse the local temp copy), never a real-fs
route. A `physical` acquisition's userdata partition is typically ext4,
already fully supported by this app's existing Sleuth Kit layer.

Disclosed gap, not silently assumed correct: this has not been tested
against a real rooted-device `physical` acquisition - no rooted Android
test device was available when this module was written. Schema risk is
low (Telephony.Sms/ContactsContract are stable, Google-documented public
SDK schemas, far more stable across OS versions than typical Windows
internals already parsed elsewhere in this app), but end-to-end
verification against real hardware is a real, disclosed gap - matching
this project's own established pattern for BitLocker/LUKS/Prefetch/mquire,
all of which shipped the same way before real hardware existed for each.
Verified instead against a hand-built synthetic SQLite fixture matching
the real schemas below (tests/test_android_artifacts.py).
"""
import sqlite3

from core.browser_artifacts import _open_sqlite_readonly

ANDROID_ARTIFACT_DB_FILENAMES = {'mmssms.db', 'contacts2.db'}

ANDROID_SCAN_MAX_CANDIDATES = 20
ANDROID_SMS_MAX_ROWS = 20_000
ANDROID_CONTACTS_MAX_ROWS = 20_000
ANDROID_CALLLOG_MAX_ROWS = 20_000
ANDROID_MMS_MAX_ROWS = 20_000

# Telephony.Sms.MESSAGE_TYPE_* constants (android.provider.Telephony.
# TextBasedSmsColumns) - the public SDK's own documented values.
_SMS_TYPE_LABELS = {
    1: "Inbox", 2: "Sent", 3: "Draft", 4: "Outbox", 5: "Failed", 6: "Queued",
}
# CallLog.Calls.*_TYPE constants (android.provider.CallLog.Calls).
_CALL_TYPE_LABELS = {
    1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Voicemail", 5: "Rejected", 6: "Blocked",
}
# Telephony.BaseMmsColumns.MESSAGE_BOX_* constants - confirmed directly
# against the real AOSP source (core/java/android/provider/Telephony.java,
# fetched and read via WebFetch before writing this, not guessed):
# MESSAGE_BOX_INBOX=1, MESSAGE_BOX_SENT=2, MESSAGE_BOX_DRAFTS=3,
# MESSAGE_BOX_OUTBOX=4.
_MMS_BOX_LABELS = {
    1: "Inbox", 2: "Sent", 3: "Draft", 4: "Outbox",
}
# PduHeaders.FROM/TO/CC/BCC - the real numeric values Mms.Addr.TYPE
# stores (confirmed against a real, working MMS PDU-parsing library's own
# PduHeaders.java: FROM=0x89=137, TO=0x97=151, CC=0x82=130, BCC=0x81=129).
# CC/BCC are folded into the same "to" bucket below - a group MMS's real
# distinction between them is rarely forensically load-bearing, and
# splitting them into a 3rd/4th bucket would be more complexity than this
# curated parser's own established "narrower but confidently correct"
# scope calls for.
_MMS_ADDR_TYPE_FROM = 137
_MMS_ADDR_TYPE_TO = (151, 130, 129)


def android_ms_to_unix(value):
    """Android's SQLite date/date_sent columns (Telephony.Sms, CallLog.Calls)
    are plain Unix-epoch milliseconds - NOT a distinct epoch origin the way
    WebKit/FILETIME/Cocoa timestamps elsewhere in this codebase are (each of
    those starts counting from a different calendar date). This is the same
    1970-01-01 origin every other Unix timestamp in this app already uses,
    just in milliseconds instead of seconds - a units difference, not a math
    difference, so no dedicated epoch-offset constant is needed here."""
    if value is None:
        return None
    try:
        return float(value) / 1000.0
    except (TypeError, ValueError):
        return None


def android_mms_date_to_unix(value):
    """Telephony.Mms's own `date` column (the `pdu` table) is Unix epoch
    SECONDS - a genuinely different unit from sms.date's milliseconds right
    above, confirmed via multiple independent real sources (a real MMS PDU-
    parsing library's own delta-seconds-to-Date conversion logic, cross-
    referenced against Android forensics literature that explicitly flags
    this exact seconds-vs-milliseconds distinction as a common analyst
    mistake) - the AOSP javadoc for Mms.DATE itself only says "INTEGER
    (long)" with no unit stated, so this couldn't be confirmed from that
    one source alone. Deliberately a separate, real, distinctly-tested
    function - never a copy-paste of android_ms_to_unix()."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_android_sms_db(path, filename=None):
    """mmssms.db - both `_parse_sms()` (the `sms` table, Telephony.Sms)
    and `_parse_mms()` (the `pdu`/`part`/`addr` tables, Telephony.Mms -
    2026-09-04, Android pattern-of-life item 5) live in this same file,
    mirroring parse_android_contacts_db()'s own combined-tables shape."""
    return _parse_sms(path) + _parse_mms(path)


def _parse_sms(path):
    """mmssms.db's `sms` table (Telephony.Sms). Ordered newest-first,
    capped - mirrors every other whole-table parser's own row cap in this
    app (e.g. core/mobile_artifacts.py's iOS SMS parser, also 20,000)."""
    records = []
    try:
        conn = _open_sqlite_readonly(path)
        try:
            cur = conn.execute(
                "SELECT _id, address, date, type, body FROM sms "
                "ORDER BY date DESC LIMIT ?", (ANDROID_SMS_MAX_ROWS,)
            )
            for row_id, address, date_ms, msg_type, body in cur:
                if not body:
                    continue
                direction = _SMS_TYPE_LABELS.get(msg_type, f"Type {msg_type}")
                records.append({
                    "artifact_type": "android_sms_message",
                    "title": f"{direction} - {address or '(unknown)'}",
                    "url": "", "value": body,
                    "timestamp": android_ms_to_unix(date_ms),
                    "extra": {"row_id": row_id, "direction": direction, "address": address},
                })
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return records


def parse_android_contacts_db(path, filename=None):
    """contacts2.db - two genuinely different artifact types share this one
    file: `_parse_contacts()` (raw_contacts/data/mimetypes join, per the
    real ContactsContract schema) and `_parse_call_log()` (the `calls`
    table - call log lives in this same database on modern Android, not a
    separate file, per this module's own grounded research). Both are
    called from the dispatcher below."""
    return _parse_contacts(path) + _parse_call_log(path)


# ContactsContract.CommonDataKinds.* MIMETYPE constants (public SDK).
_MIME_STRUCTURED_NAME = 'vnd.android.cursor.item/name'
_MIME_PHONE = 'vnd.android.cursor.item/phone_v2'
_MIME_EMAIL = 'vnd.android.cursor.item/email_v2'


def _parse_contacts(path):
    records = []
    try:
        conn = _open_sqlite_readonly(path)
        try:
            # One row per (raw_contact_id, mimetype) hit - aggregated below
            # into one record per contact, since a contact can have several
            # phone numbers/emails but this app's standard record shape is
            # one flat {title, value} per artifact, not a nested structure.
            cur = conn.execute(
                "SELECT d.raw_contact_id, m.mimetype, d.data1, d.data2, d.data3 "
                "FROM data d JOIN mimetypes m ON d.mimetype_id = m._id "
                "WHERE m.mimetype IN (?, ?, ?) "
                "ORDER BY d.raw_contact_id LIMIT ?",
                (_MIME_STRUCTURED_NAME, _MIME_PHONE, _MIME_EMAIL, ANDROID_CONTACTS_MAX_ROWS * 5)
            )
            by_contact = {}
            for raw_contact_id, mimetype, data1, data2, data3 in cur:
                entry = by_contact.setdefault(raw_contact_id, {"name": None, "phones": [], "emails": []})
                if mimetype == _MIME_STRUCTURED_NAME:
                    entry["name"] = data1 or " ".join(filter(None, [data2, data3])) or None
                elif mimetype == _MIME_PHONE and data1:
                    entry["phones"].append(data1)
                elif mimetype == _MIME_EMAIL and data1:
                    entry["emails"].append(data1)

            for raw_contact_id, entry in list(by_contact.items())[:ANDROID_CONTACTS_MAX_ROWS]:
                name = entry["name"] or "(unnamed contact)"
                value_parts = []
                if entry["phones"]:
                    value_parts.append("Phone: " + ", ".join(entry["phones"]))
                if entry["emails"]:
                    value_parts.append("Email: " + ", ".join(entry["emails"]))
                if not value_parts:
                    continue  # a bare name with no phone/email isn't forensically useful on its own
                records.append({
                    "artifact_type": "android_contact", "title": name,
                    "url": "", "value": " | ".join(value_parts), "timestamp": None,
                    "extra": {"raw_contact_id": raw_contact_id, "phones": entry["phones"], "emails": entry["emails"]},
                })
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return records


def _parse_call_log(path):
    records = []
    try:
        conn = _open_sqlite_readonly(path)
        try:
            cur = conn.execute(
                "SELECT _id, number, date, duration, type, name FROM calls "
                "ORDER BY date DESC LIMIT ?", (ANDROID_CALLLOG_MAX_ROWS,)
            )
            for row_id, number, date_ms, duration, call_type, name in cur:
                direction = _CALL_TYPE_LABELS.get(call_type, f"Type {call_type}")
                who = name or number or "(unknown)"
                records.append({
                    "artifact_type": "android_call_log",
                    "title": f"{direction} - {who}",
                    "url": "", "value": f"{duration or 0}s",
                    "timestamp": android_ms_to_unix(date_ms),
                    "extra": {"row_id": row_id, "direction": direction, "number": number, "duration_seconds": duration},
                })
        finally:
            conn.close()
    except sqlite3.Error:
        # A `calls` table missing entirely (a contacts2.db from a build/
        # config with call logging split into a separate provider) is a
        # normal, silent no-op here - contacts still parse via _parse_contacts.
        pass
    return records


def _parse_mms(path):
    """mmssms.db's `pdu`/`part`/`addr` tables (Telephony.Mms/Mms.Part/
    Mms.Addr) - a genuinely more complex join than every other table this
    module parses, since MMS has no single `address`/`body` column the
    way `sms` does: the message text lives in `part` (one row per MIME
    part, keyed by `part.mid` -> `pdu._id`), and the sender/recipient
    lives in `addr` (one row per address, keyed by `addr.msg_id` ->
    `pdu._id`, disambiguated by `addr.type` against the real PduHeaders.
    FROM/TO/CC/BCC values above). Every column name and constant here is
    confirmed directly against real AOSP source and a real, working MMS
    library - see the constants block above and android_mms_date_to_
    unix()'s own docstring for the specific sources - not guessed.

    A non-text part (a photo/video/audio attachment) is captured as its
    filename only, never its binary content - this app's own established
    "index the metadata, don't try to inline arbitrary binary content"
    posture used throughout every other artifact parser. A message with
    no text part, no attachment, AND no subject (a rare, essentially
    empty PDU - e.g. a delivery-report-only row some devices leave in
    this table) is skipped as not forensically useful, matching _parse_
    contacts()'s identical "nothing captured, don't record an empty row"
    convention right above."""
    records = []
    try:
        conn = _open_sqlite_readonly(path)
        try:
            text_by_mid = {}
            try:
                cur = conn.execute("SELECT mid, text FROM part WHERE ct = ? AND text IS NOT NULL",
                                    ("text/plain",))
                for mid, text in cur:
                    if text:
                        text_by_mid.setdefault(mid, []).append(text)
            except sqlite3.Error:
                pass

            attachments_by_mid = {}
            try:
                cur = conn.execute("SELECT mid, ct, name, fn FROM part WHERE ct != ? AND ct != ?",
                                    ("text/plain", "application/smil"))
                for mid, ct, name, fn in cur:
                    attachments_by_mid.setdefault(mid, []).append(name or fn or ct or "(unknown part)")
            except sqlite3.Error:
                pass

            addr_by_msg = {}
            try:
                cur = conn.execute("SELECT msg_id, address, type FROM addr")
                for msg_id, address, addr_type in cur:
                    addr_by_msg.setdefault(msg_id, []).append((address, addr_type))
            except sqlite3.Error:
                pass

            cur = conn.execute(
                "SELECT _id, date, msg_box, sub FROM pdu ORDER BY date DESC LIMIT ?",
                (ANDROID_MMS_MAX_ROWS,)
            )
            for row_id, date_s, msg_box, subject in cur:
                texts = text_by_mid.get(row_id, [])
                attachments = attachments_by_mid.get(row_id, [])
                if not texts and not attachments and not subject:
                    continue

                direction = _MMS_BOX_LABELS.get(msg_box, f"Type {msg_box}")
                addrs = addr_by_msg.get(row_id, [])
                from_addrs = [a for a, t in addrs if t == _MMS_ADDR_TYPE_FROM and a]
                to_addrs = [a for a, t in addrs if t in _MMS_ADDR_TYPE_TO and a]
                # Outgoing (Sent/Drafts/Outbox): the counterpart is who
                # this device sent TO. Incoming: the counterpart is who
                # it came FROM. Matches _parse_sms()'s own direction-based
                # framing right above.
                counterpart_list = to_addrs if direction != "Inbox" else from_addrs
                counterpart = ", ".join(counterpart_list) if counterpart_list else "(unknown)"

                body = " ".join(texts)
                value_parts = []
                if subject:
                    value_parts.append(f"Subject: {subject}")
                if body:
                    value_parts.append(body)
                if attachments:
                    value_parts.append(f"{len(attachments)} attachment(s): {', '.join(attachments)}")

                records.append({
                    "artifact_type": "android_mms_message",
                    "title": f"{direction} - {counterpart}",
                    "url": "", "value": " | ".join(value_parts) if value_parts else "(no content captured)",
                    "timestamp": android_mms_date_to_unix(date_s),
                    "extra": {
                        "row_id": row_id, "direction": direction, "counterpart": counterpart,
                        "from_addresses": from_addrs, "to_addresses": to_addrs,
                        "subject": subject, "attachment_names": attachments,
                    },
                })
        finally:
            conn.close()
    except sqlite3.Error:
        # A `pdu`/`part`/`addr` table missing entirely (a device/build
        # with no MMS ever sent/received might genuinely lack these) is a
        # normal, silent no-op here - SMS still parses via _parse_sms.
        pass
    return records


def parse_android_artifact_file(path, filename):
    """Dispatches a candidate DB file (matched by exact basename against
    ANDROID_ARTIFACT_DB_FILENAMES) to the right parser, mirroring
    core/registry_utils.py's parse_registry_hive_file() single-entry-point
    shape. Any parse failure (corrupted/not actually a matching DB despite
    the matching name) is swallowed and returns an empty list - same
    best-effort tolerance every other whole-folder/image scanner in this
    app already applies."""
    lower = (filename or '').lower()
    if lower == 'mmssms.db':
        return parse_android_sms_db(path, filename)
    if lower == 'contacts2.db':
        return parse_android_contacts_db(path, filename)
    return []
