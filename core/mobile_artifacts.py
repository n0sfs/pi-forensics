"""Mobile chat/app artifact parsing - SMS/iMessage, Contacts, and Call
History out of an already-pulled, UNENCRYPTED iOS backup (idevicebackup2
--full output, routes/mobile.py's execution_worker_ios_backup - the
standard iTunes/Finder backup layout: a UDID-named folder containing
Manifest.db, Info.plist, and content files stored under 2-hex-char
subdirectories named by fileID).

Unlike every prior artifact-parser module (browser/registry/evtx/prefetch/
recyclebin/linux), no existing code in this app opens Manifest.db at all -
confirmed via a full repo grep before writing this. This is the one
genuinely new sub-parser needed: every other artifact family already had a
directly-reusable discovery convention (walk for a known filename, open it),
but an iOS backup's real content files are stored by an opaque hashed
fileID, not their real name - Manifest.db's own Files table is what maps
"domain + relativePath" (a real logical path like HomeDomain/Library/SMS/
sms.db) back to that hashed on-disk location, and has to be queried first.

fileID resolution deliberately reads Manifest.db's own recorded fileID
column directly (a plain "SELECT fileID FROM Files WHERE domain=? AND
relativePath=?" query) rather than recomputing SHA1(domain + "-" +
relativePath) independently - Apple's backup tooling already computed and
stored that value once at backup time, so trusting it removes an entire
class of "did I get the hash formula exactly right" risk this module would
otherwise carry. The on-disk content-file layout this still depends on
(<manifest_dir>/<fileID[0:2]>/<fileID>) is documented as stable across iOS
10 through current versions (Manifest.db's own format, as opposed to the
pre-iOS-10 Manifest.mbdb flat file this app does not support).
VERIFICATION CHECKPOINT, not yet done: confirm this on-disk layout against
a real unencrypted idevicebackup2 backup before fully trusting it in a
real case - no real iOS backup was available on this station to test
against (per this project's own established disclosure discipline, called
out here rather than silently assumed correct); a synthetic, format-
accurate fixture is used for this module's own test suite instead.

Target apps for v1 are all native HomeDomain files with long-stable,
well-documented schemas (SMS/iMessage, Contacts, Call History). WhatsApp
is deliberately NOT included - its own domain/relativePath strings and
message-table schema shift across app versions and need live verification
against a real extracted backup this station doesn't have; shipping a
guess would risk silently mis-locating or mis-parsing real evidence, which
this project's own established discipline (e.g. wtmp/utmp's self-checking
gate in core/linux_artifacts.py) treats as a worse failure mode than simply
not offering the capability yet.

Encryption: idevicebackup2 optionally password-encrypts a backup at
acquisition time (routes/mobile.py already supports enabling this).
Manifest.db itself is always plaintext regardless (only individual content
files are encrypted when this is on) - checked via Manifest.plist's own
IsEncrypted key before ever attempting to read a content file, so an
encrypted backup gets an honest "cannot extract - backup is encrypted"
signal instead of looking identical to "found nothing."
"""
import os
import sqlite3
import plistlib

from core.browser_artifacts import _open_sqlite_readonly

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

MOBILE_BACKUP_MAX_CANDIDATES = 5  # an examiner rarely has more than one or two backups under one folder
MOBILE_BACKUP_MAX_WALKED = 20_000

# Apple's Cocoa/Core Data reference date, 2001-01-01 00:00:00 UTC, expressed
# as seconds since the Unix epoch (1970-01-01) - the standard, well-known
# constant for this conversion.
COCOA_EPOCH_OFFSET_SECONDS = 978_307_200


def cocoa_time_to_unix(value):
    """Apple Cocoa/Core Data epoch time -> Unix epoch seconds. A THIRD
    distinct epoch shape from webkit_time_to_unix()/firefox_time_to_unix()
    (core/browser_artifacts.py) and filetime_to_unix() (core/
    registry_utils.py) - do not copy-paste any of those, this one has its
    own genuinely different math (this module's own regression test proves
    it, matching this codebase's established "prove it's different, not
    copy-pasted" discipline for every prior epoch helper).

    iOS's own message.date column ambiguously mixes UNITS within the same
    column depending on which iOS version wrote the row: seconds-since-2001
    on iOS 10 and earlier, nanoseconds-since-2001 from iOS 11 onward -
    documented behavior (Apple never changed the column's own storage type,
    just what later OS versions started writing into it), with no reliable
    per-row flag distinguishing which unit a given value uses. Disambiguated
    here via magnitude, not iOS-version lookup: a real seconds-since-2001
    value for any plausible backup date is at most on the order of 1e9
    (decades, not centuries); the same real date as nanoseconds-since-2001
    is on the order of 1e17-1e18 - an enormous, unambiguous gap with no
    real date landing anywhere near a 1e12 threshold, so this reliably
    disambiguates without needing the source iOS version at all.
    """
    if not value:
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    if abs(value) > 1e12:
        value = value / 1e9
    return value + COCOA_EPOCH_OFFSET_SECONDS


def _udid_like(name):
    # Mirrors routes/auto_analyze.py's own _UDID_RE - not imported (routes/
    # *.py files deliberately don't import each other in this codebase, and
    # this module stays independent of any routes/ file the same way every
    # other core/*_utils.py module already does).
    if not (20 <= len(name) <= 64):
        return False
    return all(c in '0123456789abcdefABCDEF-' for c in name)


def find_mobile_backup_manifest(root_dir):
    """Finds Manifest.db + Info.plist pairs anywhere under root_dir - checks
    both "root_dir IS the UDID backup folder" and "a UDID folder sits
    directly under root_dir" shapes, matching routes/auto_analyze.py's own
    _looks_like_ios_backup_dir() detection exactly (re-implemented, not
    imported, for the reason above). Returns (manifest_dirs, truncated)."""
    def _has_markers(d):
        return os.path.isfile(os.path.join(d, 'Manifest.db')) and os.path.isfile(os.path.join(d, 'Info.plist'))

    found = []
    base = os.path.basename(root_dir.rstrip('/\\'))
    if _udid_like(base) and _has_markers(root_dir):
        found.append(root_dir)
    try:
        for entry in sorted(os.listdir(root_dir)):
            if len(found) >= MOBILE_BACKUP_MAX_CANDIDATES:
                return found, True
            if not _udid_like(entry):
                continue
            sub = os.path.join(root_dir, entry)
            if os.path.isdir(sub) and _has_markers(sub):
                found.append(sub)
    except OSError:
        pass
    return found, False


def _is_backup_encrypted(manifest_dir):
    plist_path = os.path.join(manifest_dir, 'Manifest.plist')
    if not os.path.isfile(plist_path):
        return False
    try:
        with open(plist_path, 'rb') as f:
            data = plistlib.load(f)
        return bool(data.get('IsEncrypted', False))
    except Exception:
        return False


# The 3 v1 target apps' (domain, relativePath) pairs, keyed by
# artifact_type - single source of truth so routes/image_browser.py's
# in-image resolver (which has to look up a fileID and then separately
# locate it INSIDE the image, a two-step process
# _resolve_manifest_files_query_only()/the caller's own in-image lookup
# below splits apart) never needs to hardcode these strings a second time.
MOBILE_ARTIFACT_TARGET_PATHS = {
    "mobile_sms_message": ('HomeDomain', 'Library/SMS/sms.db'),
    "mobile_contact": ('HomeDomain', 'Library/AddressBook/AddressBook.sqlitedb'),
    "mobile_call_log": ('HomeDomain', 'Library/CallHistoryDB/CallHistory.storedata'),
}


def _resolve_manifest_files_query_only(manifest_dir, domain, relative_path):
    """The query half of _resolve_manifest_files() below, split out so
    routes/image_browser.py's in-image resolver can reuse it - that caller
    needs the raw fileID string to go look up its own on-disk (well,
    in-image) location separately, rather than _resolve_manifest_files()'s
    real-fs os.path.isfile() existence check, which is meaningless for a
    path that only exists inside an unmounted image. Returns the fileID
    string, or None."""
    manifest_db = os.path.join(manifest_dir, 'Manifest.db')
    try:
        conn = _open_sqlite_readonly(manifest_db)
        cur = conn.execute(
            "SELECT fileID FROM Files WHERE domain=? AND relativePath=? LIMIT 1",
            (domain, relative_path))
        row = cur.fetchone()
        conn.close()
    except sqlite3.Error as e:
        print(f"Warning: could not query Manifest.db at {manifest_db}: {e}")
        return None
    return row[0] if row else None


def _resolve_manifest_files(manifest_dir, domain, relative_path):
    """Queries Manifest.db's Files table for the given domain+relativePath,
    resolves the matched fileID to its real on-disk path
    (<manifest_dir>/<fileID[0:2]>/<fileID>), and confirms that path actually
    exists before returning it - a stale/renamed/never-backed-up file
    correctly yields nothing rather than a dangling path. Returns the
    resolved absolute path, or None."""
    file_id = _resolve_manifest_files_query_only(manifest_dir, domain, relative_path)
    if not file_id:
        return None
    content_path = os.path.join(manifest_dir, file_id[0:2], file_id)
    if not os.path.isfile(content_path):
        return None
    return content_path


# --- SMS / iMessage ---

def parse_mobile_sms(manifest_dir):
    """HomeDomain/Library/SMS/sms.db - message/handle join. Returns
    (records, found) - found=False means sms.db itself was never located
    (not backed up, or a backup format this resolver doesn't understand),
    distinct from found=True with zero records (backup has no messages)."""
    content_path = _resolve_manifest_files(manifest_dir, *MOBILE_ARTIFACT_TARGET_PATHS["mobile_sms_message"])
    if not content_path:
        return [], False
    records = []
    try:
        conn = _open_sqlite_readonly(content_path)
        cur = conn.execute(
            "SELECT message.ROWID, message.text, message.date, message.is_from_me, "
            "handle.id AS handle_address "
            "FROM message LEFT JOIN handle ON message.handle_id = handle.ROWID "
            "ORDER BY message.date DESC LIMIT 20000")
        for row_id, text, date, is_from_me, handle_address in cur:
            if not text:
                continue
            direction = "Sent" if is_from_me else "Received"
            counterpart = handle_address or "(unknown)"
            records.append({
                "artifact_type": "mobile_sms_message", "title": f"{direction} - {counterpart}",
                "url": "", "value": text, "timestamp": cocoa_time_to_unix(date),
                "extra": {"row_id": row_id, "direction": direction, "counterpart": counterpart},
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"Warning: could not parse sms.db at {content_path}: {e}")
        return [], True
    return records, True


# --- Contacts ---

def parse_mobile_contacts(manifest_dir):
    """HomeDomain/Library/AddressBook/AddressBook.sqlitedb - ABPerson +
    ABMultiValue (phone numbers/emails). Classic AddressBook schema has no
    reliable per-record timestamp field at all - never guessed, always
    None, matching this codebase's established "no timestamp exists, don't
    invent one" convention (e.g. core/linux_artifacts.py's /etc/passwd
    parser using the file's own mtime as an honest proxy where no per-
    record timestamp exists; contacts have no comparable proxy either, so
    this is left None rather than misleadingly proxied)."""
    content_path = _resolve_manifest_files(manifest_dir, *MOBILE_ARTIFACT_TARGET_PATHS["mobile_contact"])
    if not content_path:
        return [], False
    records = []
    try:
        conn = _open_sqlite_readonly(content_path)
        values_by_person = {}
        try:
            cur = conn.execute("SELECT record_id, value FROM ABMultiValue WHERE property IN (3, 4)")
            for record_id, value in cur:
                values_by_person.setdefault(record_id, []).append(value)
        except sqlite3.Error:
            pass  # ABMultiValue may not exist on every backup variant - contact names alone still have value
        cur = conn.execute("SELECT ROWID, First, Last, Organization FROM ABPerson LIMIT 20000")
        for row_id, first, last, org in cur:
            name = " ".join(p for p in (first, last) if p) or org or "(unnamed contact)"
            contact_values = values_by_person.get(row_id, [])
            records.append({
                "artifact_type": "mobile_contact", "title": name, "url": "",
                "value": ", ".join(contact_values) if contact_values else "(no phone/email on file)",
                "timestamp": None,
                "extra": {"row_id": row_id, "organization": org},
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"Warning: could not parse AddressBook.sqlitedb at {content_path}: {e}")
        return [], True
    return records, True


# --- Call History ---

def parse_mobile_call_history(manifest_dir):
    """HomeDomain/Library/CallHistoryDB/CallHistory.storedata -
    ZCALLRECORD. CallHistory.storedata's own ZDATE column is documented as
    seconds-since-2001 (not the nanosecond variant sms.db's message.date
    can carry) - cocoa_time_to_unix()'s magnitude-based disambiguation
    handles this correctly either way, so no special-casing is needed here
    even if that documented behavior turns out to vary in practice."""
    content_path = _resolve_manifest_files(manifest_dir, *MOBILE_ARTIFACT_TARGET_PATHS["mobile_call_log"])
    if not content_path:
        return [], False
    records = []
    try:
        conn = _open_sqlite_readonly(content_path)
        cur = conn.execute(
            "SELECT Z_PK, ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED "
            "FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 20000")
        for row_id, address, date, duration, originated, answered in cur:
            direction = "Outgoing" if originated else "Incoming"
            status = "Answered" if answered else "Missed/Unanswered"
            title = f"{direction} call - {address or '(unknown)'}"
            records.append({
                "artifact_type": "mobile_call_log", "title": title, "url": "",
                "value": f"{status}, duration {duration or 0:.0f}s" if duration is not None else status,
                "timestamp": cocoa_time_to_unix(date),
                "extra": {"row_id": row_id, "address": address, "direction": direction,
                          "duration_seconds": duration, "answered": bool(answered)},
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"Warning: could not parse CallHistory.storedata at {content_path}: {e}")
        return [], True
    return records, True


MOBILE_ARTIFACT_PARSERS = {
    "mobile_sms_message": parse_mobile_sms,
    "mobile_contact": parse_mobile_contacts,
    "mobile_call_log": parse_mobile_call_history,
}


def parse_mobile_backup_manifest(manifest_dir, requested_types=None):
    """Runs every requested target-app parser (default: all of
    MOBILE_ARTIFACT_PARSERS) against one located backup folder. Returns
    (records, summary) where summary discloses encryption state and, per
    type, whether that app's data file was even found in this backup -
    honest disclosure over a bare empty list that could otherwise read as
    "nothing found" when the truth might be "this backup is encrypted" or
    "this app was never installed/backed up"."""
    encrypted = _is_backup_encrypted(manifest_dir)
    types = requested_types if requested_types else list(MOBILE_ARTIFACT_PARSERS.keys())
    all_records = []
    per_type_found = {}
    if encrypted:
        return [], {"encrypted": True, "found": {}}
    for artifact_type in types:
        parser = MOBILE_ARTIFACT_PARSERS.get(artifact_type)
        if not parser:
            continue
        try:
            records, found = parser(manifest_dir)
        except Exception as e:
            print(f"Warning: mobile artifact parser for {artifact_type} failed on {manifest_dir}: {e}")
            records, found = [], False
        per_type_found[artifact_type] = found
        all_records.extend(records)
    return all_records, {"encrypted": False, "found": per_type_found}
