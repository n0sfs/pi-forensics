"""WhatsApp local-backup decryption AND native msgstore.db/wa.db parsing -
three independent pieces: pulling the device's own `key` file off a
rooted Android phone (an acquisition step, called from routes/mobile.py),
decrypting an already-acquired `msgstore.db.crypt12/14/15` file against
that key (an analysis step, called from routes/file_explorer.py), and -
new, 2026-09-04, Android pattern-of-life follow-up - actually PARSING the
resulting msgstore.db into this app's standard artifact record shape.
Before this, the decrypt feature produced a real, browsable SQLite
database and stopped there - nothing then read it.

The schema grounding below is deliberately NOT guessed - it's read
directly from this app's own pinned, actively-maintained ALEAPP source
(leapp/ALEAPP/scripts/artifacts/WhatsApp.py on the deployed station,
last_update_date 2026-07-03 for the message queries), the exact same
schema this app's ALEAPP integration already trusts and has already
shipped as leapp_whatsapp_message/leapp_whatsapp_call_log/
leapp_whatsapp_contact. Confirmed directly from that source:

  MODERN schema (message/chat/jid tables) - the only schema covered here.
  ALEAPP's OWN "get_whatsapp_messages" (the legacy `messages`/`.data`
  table) is explicitly marked "Legacy schema only" in its own
  description and returned ZERO rows across every one of ALEAPP's 7 real
  sample devices (Android 13 through 16) - a real, confirmed signal that
  the legacy schema is essentially extinct on any current device, not a
  hypothetical cutoff. This module follows the same "target the dominant
  modern format, disclose the cutoff" precedent already used elsewhere
  in this app (Shimcache Win10/11-only, Sticky Notes modern-plum.sqlite-
  only) rather than also covering a schema with confirmed real-world
  zero coverage.

  message.timestamp / message.received_timestamp / call_log.timestamp -
  epoch MILLISECONDS (confirmed via ALEAPP's own `timestamp/1000` before
  a SQLite `unixepoch` conversion, which expects seconds) - the identical
  convention core/android_artifacts.py's android_ms_to_unix() already
  handles for Telephony.Sms/CallLog.Calls. NOT imported from there,
  deliberately - core/android_artifacts.py already imports FROM core/
  browser_artifacts.py, and this module needs core/browser_artifacts.py's
  _open_sqlite_readonly() too, so importing android_artifacts.py here as
  well would only ever matter if android_artifacts.py later imports BACK
  from this module (e.g. to wire msgstore.db/wa.db into its own in-image
  whole-userdata-partition scan) - a genuine circular import. A 2-line
  duplicate of the same trivial ms-to-s-then-epoch-add math costs far
  less than that coupling risk.

  message.recipient_count=0 means a 1:1 chat, >=1 means a group chat -
  literally how ALEAPP itself distinguishes the two from the SAME
  `message` table, rather than two structurally different tables.

  wa_contacts (the table resolving a raw JID into a real display name)
  lives in a SEPARATE file, wa.db - NOT inside msgstore.db at all. This
  app's own WhatsApp-decrypt feature only ever decrypts msgstore.db, so
  wa.db is genuinely often absent - handled the same way ALEAPP's own
  `_open_msgstore()` does: msgstore.db always opens and parses on its
  own (falling back to the raw JID string, e.g. "15551234567@s.whatsapp.net"
  stripped to just "15551234567", when no contact name can be resolved),
  and a sibling wa.db - if present alongside it (e.g. from a rooted
  physical pull where both files coexist) - is OPTIONALLY ATTACHed via
  SQLite's own ATTACH DATABASE for real name resolution. Never required,
  never assumed present.

  message.message_type - a small, real, confirmed enum: 0=Text,
  1=Picture, 2=Audio, 3=Video, 5=Static Location, 7=System Message,
  9=Document, 16=Live Location.

Real CLI shapes for the decrypt/key-pull functions below were confirmed
live against the installed wa-crypt-tools 0.1.0 package on this station's
real ARM64 venv before writing them, not assumed - including a real,
genuine upstream bug found along the way: `wacreatekey`'s own
`-o/--output` flag crashes with a TypeError on this exact installed
version (it opens the file via argparse's FileType('wb') and then
re-wraps the already-open handle in Path(), which is invalid) - irrelevant
to this module itself (it never calls wacreatekey), but worth remembering
if a future feature ever needs to generate a synthetic test key file the
way this module's own live verification did (work around it by omitting
-o and using the tool's own default output filename instead).

`wadecrypt`'s real, confirmed positional argument order is
`[keyfile] [encrypted] [decrypted]` - verified via a real synthetic
key+crypt14 round trip (wacreatekey -> waencrypt -> wadecrypt) that
reproduced the original plaintext byte-for-byte. On success, wadecrypt
writes nothing to stdout and its own log lines (ANSI-colored) go to
stderr with exit code 0; on failure (a malformed/wrong key, confirmed
live against a real wrong-key test) it can raise an outright Python
traceback rather than fail gracefully - this wrapper treats any non-zero
exit as a clean, reported failure, the same "never let a tool's own
crash propagate" discipline already established for SQLite Dissect.
"""
import os
import re
import sqlite3
import subprocess

from core.config import MVT_BIN_DIR
from core.browser_artifacts import _open_sqlite_readonly

WHATSAPP_KEY_PULL_TIMEOUT_SECONDS = 20
WHATSAPP_KEY_MAX_BYTES = 4096  # a real key file is a few hundred bytes at
                               # most across crypt12/14/15 formats - a
                               # larger response is very likely an `su -c`
                               # denial message misrouted to stdout, not a
                               # real key, and is rejected rather than
                               # trusted.
WADECRYPT_TIMEOUT_SECONDS = 300
# wadecrypt is a pip console-script (see requirements.txt), same
# MVT_BIN_DIR resolution as every other pip-installed analysis tool in
# this app - not on PATH under gunicorn/systemd.
WADECRYPT_BIN = os.path.join(MVT_BIN_DIR, "wadecrypt")

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

WHATSAPP_MSG_MAX_ROWS = 20_000
WHATSAPP_CALL_LOG_MAX_ROWS = 20_000
WHATSAPP_CONTACTS_MAX_ROWS = 20_000

_WA_MESSAGE_TYPE_LABELS = {
    0: "Text", 1: "Picture", 2: "Audio", 3: "Video", 5: "Static Location",
    7: "System Message", 9: "Document", 16: "Live Location",
}


def _wa_ms_to_unix(value):
    """Deliberate 2-line duplicate of core/android_artifacts.py's own
    android_ms_to_unix() - see this module's own docstring for why it's
    not imported from there instead (avoiding a circular import)."""
    if value is None:
        return None
    try:
        return float(value) / 1000.0
    except (TypeError, ValueError):
        return None


def _strip_wa_jid_suffix(jid):
    """A raw WhatsApp JID looks like "15551234567@s.whatsapp.net"
    (individual) or "123456-789012@g.us" (group) - stripped to just the
    number/id for a cleaner display when no real contact name can be
    resolved (no wa.db attached)."""
    if not jid:
        return jid
    return jid.split('@', 1)[0]


def find_whatsapp_databases(root_dir):
    """Recursively finds a real msgstore.db (and, separately, a real
    wa.db) anywhere under root_dir - mirrors every other artifact-parser
    module's find_X_files() shape in this app. Returns
    {"msgstore": [...], "wa_db": [...]} (both lists, since more than one
    of either could genuinely exist - a multi-user-profile pull, or
    several case-folder test artifacts)."""
    msgstore_paths, wa_db_paths = [], []
    walked = 0
    for root, _dirs, files in os.walk(root_dir):
        for fname in files:
            walked += 1
            if walked > 40_000:
                return {"msgstore": msgstore_paths, "wa_db": wa_db_paths}
            if fname == 'msgstore.db':
                msgstore_paths.append(os.path.join(root, fname))
            elif fname == 'wa.db':
                wa_db_paths.append(os.path.join(root, fname))
    return {"msgstore": msgstore_paths, "wa_db": wa_db_paths}


def _open_msgstore_with_optional_wa_db(msgstore_path):
    """Opens msgstore.db read-only; if a real wa.db file sits in the SAME
    directory, attaches it (read-only) as "wadb" for contact-name
    resolution - mirrors ALEAPP's own _open_msgstore() exactly. Returns
    (conn, wa_attached: bool). A failed attach (a genuinely corrupt
    sibling file) is swallowed - msgstore.db still parses on its own,
    the identical tolerance ALEAPP's own real source applies."""
    conn = _open_sqlite_readonly(msgstore_path)
    wa_candidate = os.path.join(os.path.dirname(msgstore_path), 'wa.db')
    wa_attached = False
    if os.path.isfile(wa_candidate):
        try:
            conn.execute(f"ATTACH DATABASE 'file:{wa_candidate}?mode=ro&immutable=1' AS wadb")
            wa_attached = True
        except sqlite3.Error:
            pass
    return conn, wa_attached


def parse_whatsapp_messages(msgstore_path):
    """1:1 and group messages, distinguished by message.recipient_count -
    see this module's own docstring for the full schema grounding. One
    artifact_type ("whatsapp_message") for both, matching how this app's
    own ALEAPP-sourced leapp_whatsapp_message already covers both kinds
    from one bucket - a group message is flagged via extra["is_group"]
    rather than getting a wholly separate type."""
    records = []
    try:
        conn, wa_attached = _open_msgstore_with_optional_wa_db(msgstore_path)
    except sqlite3.Error:
        return records
    try:
        # A real bug caught live (2026-09-04, deployed-station verification):
        # chat.jid_row_id identifies the OTHER PARTICIPANT for a 1:1 chat
        # (there's only ever one), but for a GROUP chat it identifies the
        # GROUP's own jid, not a person - ALEAPP's own real source
        # confirms this exact split (its 1:1 query joins jid via
        # chat.jid_row_id; its SEPARATE group-message query joins jid via
        # message.sender_jid_row_id instead, to identify WHICH group
        # member sent THIS particular message). Unifying both into one
        # query (as this function deliberately does, unlike ALEAPP's own
        # two-query split) means joining jid TWICE - once each way - and
        # picking the correct one in Python based on is_group, rather
        # than silently reusing chat.jid_row_id for both cases (which
        # would leave every group message's sender permanently
        # unresolved - confirmed live before this fix: "(unknown)" for
        # every group message, even with wa.db attached).
        chat_contact_expr = "wadb.wa_contacts_via_chat.wa_name" if wa_attached else "NULL"
        sender_contact_expr = "wadb.wa_contacts_via_sender.wa_name" if wa_attached else "NULL"
        contact_joins = (
            "LEFT JOIN wadb.wa_contacts AS wa_contacts_via_chat "
            "ON wa_contacts_via_chat.jid = chat_jid.raw_string "
            "LEFT JOIN wadb.wa_contacts AS wa_contacts_via_sender "
            "ON wa_contacts_via_sender.jid = sender_jid.raw_string"
            if wa_attached else "")
        rows = conn.execute(f'''
            SELECT
                message.timestamp, message.received_timestamp,
                message.from_me, message.recipient_count,
                chat_jid.raw_string, sender_jid.raw_string, chat.subject,
                {chat_contact_expr}, {sender_contact_expr},
                message.message_type, message.text_data
            FROM message
            JOIN chat ON chat._id = message.chat_row_id
            LEFT JOIN jid AS chat_jid ON chat_jid._id = chat.jid_row_id
            LEFT JOIN jid AS sender_jid ON sender_jid._id = message.sender_jid_row_id
            {contact_joins}
            ORDER BY message.timestamp DESC
            LIMIT ?
        ''', (WHATSAPP_MSG_MAX_ROWS,)).fetchall()
    except sqlite3.Error:
        conn.close()
        return records
    conn.close()

    for row in rows:
        (ts_raw, received_raw, from_me, recipient_count, chat_jid_raw, sender_jid_raw,
         chat_subject, chat_contact_name, sender_contact_name, msg_type, text_data) = row
        is_group = bool(recipient_count and recipient_count >= 1)
        # 1:1 -> resolve via the chat's own jid; group -> resolve via the
        # message's own sender_jid, exactly matching ALEAPP's own two
        # distinct real queries (see the comment above).
        effective_jid = sender_jid_raw if is_group else chat_jid_raw
        effective_name = sender_contact_name if is_group else chat_contact_name
        contact_display = effective_name or _strip_wa_jid_suffix(effective_jid) or "(unknown)"
        direction = "Outgoing" if from_me else "Incoming"
        type_label = _WA_MESSAGE_TYPE_LABELS.get(msg_type, f"Type {msg_type}")
        title = (chat_subject if is_group else contact_display) or "(unknown chat)"
        body = (text_data or "").strip()
        value = f"[{direction}, {type_label}] " + (body if body else f"({type_label.lower()}, no text)")
        records.append({
            "artifact_type": "whatsapp_message", "title": title, "url": "",
            "value": value, "timestamp": _wa_ms_to_unix(ts_raw),
            "extra": {
                "is_group": is_group, "direction": direction, "message_type": type_label,
                "sender_or_recipient": contact_display, "sender_jid": effective_jid,
                "received_timestamp": _wa_ms_to_unix(received_raw) if received_raw else None,
                "contact_name_resolved": bool(effective_name),
            },
        })
    return records[:WHATSAPP_MSG_MAX_ROWS]


def parse_whatsapp_call_log(msgstore_path):
    """call_log table (also lives in msgstore.db, not a separate file) -
    same optional wa.db attach for caller-name resolution."""
    records = []
    try:
        conn, wa_attached = _open_msgstore_with_optional_wa_db(msgstore_path)
    except sqlite3.Error:
        return records
    try:
        caller_name_expr = "wadb.wa_contacts.wa_name" if wa_attached else "NULL"
        contact_join = (
            "LEFT JOIN wadb.wa_contacts ON wadb.wa_contacts.jid = jid.raw_string"
            if wa_attached else "")
        rows = conn.execute(f'''
            SELECT
                call_log.timestamp, call_log.duration, call_log.from_me,
                call_log.video_call, jid.raw_string, {caller_name_expr}, chat.subject
            FROM call_log
            LEFT JOIN jid ON jid._id = call_log.jid_row_id
            {contact_join}
            LEFT JOIN chat ON chat.jid_row_id = call_log.group_jid_row_id
            ORDER BY call_log.timestamp DESC
            LIMIT ?
        ''', (WHATSAPP_CALL_LOG_MAX_ROWS,)).fetchall()
    except sqlite3.Error:
        conn.close()
        return records
    conn.close()

    for row in rows:
        ts_raw, duration, from_me, video_call, jid_raw, caller_name, group_subject = row
        direction = "Outgoing" if from_me else "Incoming"
        call_type = "Video" if video_call else "Audio"
        caller_display = caller_name or _strip_wa_jid_suffix(jid_raw) or "(unknown)"
        title = group_subject or caller_display
        duration_s = int(duration) if duration else 0
        value = f"[{direction}, {call_type}] {caller_display} - {duration_s}s"
        records.append({
            "artifact_type": "whatsapp_call_log", "title": title, "url": "",
            "value": value, "timestamp": _wa_ms_to_unix(ts_raw),
            "extra": {
                "direction": direction, "call_type": call_type, "duration_seconds": duration_s,
                "caller_jid": jid_raw, "is_group_call": bool(group_subject),
                "contact_name_resolved": bool(caller_name),
            },
        })
    return records[:WHATSAPP_CALL_LOG_MAX_ROWS]


def parse_whatsapp_contacts(wa_db_path):
    """wa_contacts table, read directly from a standalone wa.db - mirrors
    core/android_artifacts.py's own independent contacts2.db parsing
    precedent (a contact source parses on its own, not only as an
    enrichment join). Same name-fallback CASE logic ALEAPP's own
    get_whatsapp_contacts() uses, with one deliberate difference: when
    NO name field exists at all, ALEAPP's own SQL falls back to the raw,
    unstripped JID directly (e.g. "15551234567@s.whatsapp.net"); this
    returns NULL from SQL instead and lets the SAME Python-level
    _strip_wa_jid_suffix() fallback every other "no name resolved" case
    in this module already goes through handle it - a consistently
    formatted "15551234567" display, not a bare-jid-with-@-suffix
    edge case that would look inconsistent against every other row."""
    records = []
    try:
        conn = _open_sqlite_readonly(wa_db_path)
    except sqlite3.Error:
        return records
    try:
        rows = conn.execute('''
            SELECT
                CASE
                    WHEN given_name IS NULL AND family_name IS NULL AND display_name IS NULL THEN NULL
                    WHEN given_name IS NULL AND family_name IS NULL THEN display_name
                    WHEN given_name IS NULL THEN family_name
                    WHEN family_name IS NULL THEN given_name
                    ELSE given_name || " " || family_name
                END,
                jid,
                CASE WHEN number IS NULL THEN jid WHEN number = "" THEN jid ELSE number END
            FROM wa_contacts
            LIMIT ?
        ''', (WHATSAPP_CONTACTS_MAX_ROWS,)).fetchall()
    except sqlite3.Error:
        conn.close()
        return records
    conn.close()

    for name, jid_raw, number in rows:
        title = name or _strip_wa_jid_suffix(jid_raw) or "(unnamed contact)"
        records.append({
            "artifact_type": "whatsapp_contact", "title": title, "url": "",
            "value": f"Number/JID: {number}", "timestamp": None,
            "extra": {"jid": jid_raw, "number": number},
        })
    return records[:WHATSAPP_CONTACTS_MAX_ROWS]


def pull_whatsapp_key_file(serial, dest_path):
    """Pulls a rooted Android device's own WhatsApp `key` file
    (/data/data/com.whatsapp/files/key) via `adb shell su -c cat` and
    writes its raw bytes to dest_path. Returns
    {"success": bool, "path": str|None, "error": str|None}. Requires the
    device to already be rooted (_probe_android_root_status()'s own
    check) - a non-rooted device's `su` invocation fails cleanly, the
    same outcome as any other su-denied command elsewhere in this app."""
    try:
        res = subprocess.run(
            ["adb", "-s", serial, "shell", "su", "-c", "cat /data/data/com.whatsapp/files/key"],
            capture_output=True, text=False, timeout=WHATSAPP_KEY_PULL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "path": None, "error": "Timed out waiting for the device."}
    except Exception as e:
        return {"success": False, "path": None, "error": str(e)}

    if res.returncode != 0:
        stderr_text = (res.stderr or b'').decode('utf-8', errors='replace').strip()
        return {"success": False, "path": None, "error": stderr_text or
                "Could not read the key file - is WhatsApp installed and is this device genuinely rooted?"}

    key_bytes = res.stdout or b''
    if not key_bytes:
        return {"success": False, "path": None, "error": "No key file content returned - "
                "WhatsApp may not be installed, or su access was denied."}
    if len(key_bytes) > WHATSAPP_KEY_MAX_BYTES:
        return {"success": False, "path": None, "error": f"Unexpectedly large response "
                f"({len(key_bytes)} bytes) - this is very likely an su-denial message rather "
                f"than a real key file, so it was not saved."}

    try:
        with open(dest_path, 'wb') as f:
            f.write(key_bytes)
    except OSError as e:
        return {"success": False, "path": None, "error": f"Could not write key file: {e}"}

    return {"success": True, "path": dest_path, "error": None}


def decrypt_whatsapp_backup(crypt_path, key_path, output_db_path):
    """Runs `wadecrypt <key_path> <crypt_path> <output_db_path>` -
    confirmed positional order via a real synthetic round trip on this
    station. Returns {"success": bool, "output_path": str|None,
    "log": str, "error": str|None} - never raises."""
    if not os.path.isfile(WADECRYPT_BIN):
        return {"success": False, "output_path": None, "log": "",
                "error": "wadecrypt is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions."}

    cmd = [WADECRYPT_BIN, key_path, crypt_path, output_db_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=WADECRYPT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "output_path": None, "log": "",
                "error": "wadecrypt timed out (unusually large backup file)."}
    except Exception as e:
        return {"success": False, "output_path": None, "log": "", "error": str(e)}

    log = _ANSI_RE.sub('', ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip())

    if res.returncode != 0:
        # A non-zero exit (including a raw Python traceback from the tool
        # itself on a wrong/malformed key, confirmed live) is always a
        # clean, reported failure here - never surfaced as a crash.
        return {"success": False, "output_path": None, "log": log,
                "error": log[:2000] or "wadecrypt failed with no output."}

    if not os.path.isfile(output_db_path) or os.path.getsize(output_db_path) == 0:
        return {"success": False, "output_path": None, "log": log,
                "error": "wadecrypt reported success but wrote no decrypted output - "
                "the key may not match this backup file."}

    return {"success": True, "output_path": output_db_path, "log": log, "error": None}
