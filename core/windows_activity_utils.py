"""Windows Notification database (wpndatabase.db) and Windows Timeline /
Activity History (ActivitiesCache.db) parsing - two small, plain-SQLite
"what did the user actually see/do" artifacts, shipped together since both
are simple single-main-table databases with the same real gotcha (a
recently-written row can live only in an adjacent -wal/-shm sidecar, not
yet checkpointed into the main file) and the same defensive-column-
discovery need (both schemas are confirmed to have drifted slightly across
Windows 10/11 builds).

Grounded via real, cross-corroborated research (2026-09-01) before writing
any code, matching this app's own established "two+ independent real
sources, never a single secondhand summary" bar for any new artifact:

wpndatabase.db (%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\
wpndatabase.db) - the OS-level Action Center notification history. The
Notification table's ArrivalTime column is confirmed, independently and
identically, by two separate real DFIR write-ups (Yogesh Khatri's
swiftforensics.com post and inc0x0.com's own analysis) to be a genuine
Windows FILETIME - reused via core/registry_utils.py's existing
filetime_to_unix(), no new epoch math needed here. Payload is a raw Toast
XML blob (both sources agree it is NOT JSON), so this module does a
minimal, disclosed-as-partial extraction of the <text> node content rather
than a full XML/toast-schema parse - correct regardless of whichever
notification template (simple text, image, progress bar, etc.) produced
it, since every template still nests its visible text in <text> elements.
Both sources also flag that the exact column set (Group/Order/Tag in
particular) has drifted across Windows 10 builds since 1607 - handled here
via a genuine PRAGMA table_info() column-existence check before building
the SELECT, rather than guessing a fixed column list and risking a hard
crash against an older/newer build.

ActivitiesCache.db (%LOCALAPPDATA%\\ConnectedDevicesPlatform\\<uid>\\
ActivitiesCache.db) - the "Windows Timeline" feature's own activity
history (apps used, documents opened, websites visited). StartTime/EndTime
are confirmed as plain Unix-epoch-seconds integers by three independent
sources (hermes-codex.vercel.app, istrosec.com - which quotes the exact
`datetime(StartTime, 'unixepoch')` SQL idiom - and Velociraptor's own
published artifact definition) - genuinely simpler than every other
timestamp this app has ever parsed, no conversion function needed at all,
just a plain int/float cast. AppId and Payload are both JSON (AppId is
itself a JSON array of per-platform app identifiers; Payload nests a
title/description/contentUri under a versioned wrapper) - parsed
defensively, a malformed/unexpected shape falls back to the raw string
rather than aborting the row.

Deprecation status, disclosed rather than silently assumed either way:
Microsoft removed the Timeline UI and cross-device cloud sync via the
January 2024 KB5034204 update on Windows 11 22H2/23H2, but real, dated
forensic-comparison research (cyberengage.org) confirms the
ActivitiesCache.db FILE ITSELF still exists and is still actively written
on current Windows 11 builds post-KB5034204 - just with sharply reduced
content (mostly system/network events, minimal real app-usage history).
On Windows 10 (still commonly imaged, in support through October 2025)
the database remains fully populated exactly as documented above. This is
therefore a genuine two-tier artifact, not a defunct one - the reduced-
fidelity caveat for a post-KB5034204 Windows 11 image is stated directly
in this module's own label text (routes/case_index.py /
static/js/main.js), the same disclosure convention already established
for MVT-Android's own best-effort status.
"""
import json
import os
import re
import shutil
import sqlite3
import tempfile

from core.registry_utils import filetime_to_unix

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

WPNDATABASE_FILENAME = 'wpndatabase.db'
ACTIVITIESCACHE_FILENAME = 'ActivitiesCache.db'
_SQLITE_SIDECAR_SUFFIXES = ('-wal', '-shm')

WINDOWS_ACTIVITY_FILENAMES = {WPNDATABASE_FILENAME, ACTIVITIESCACHE_FILENAME}

WINDOWS_ACTIVITY_SCAN_MAX_CANDIDATES = 20
WINDOWS_ACTIVITY_SCAN_MAX_WALKED = 20_000
WINDOWS_NOTIFICATION_MAX_ROWS = 3_000
WINDOWS_TIMELINE_MAX_ROWS = 5_000

_TOAST_TEXT_RE = re.compile(r'<text[^>]*>(.*?)</text>', re.IGNORECASE | re.DOTALL)
_XML_TAG_RE = re.compile(r'<[^>]+>')


def find_windows_activity_files(root_dir):
    """Recursively finds real wpndatabase.db / ActivitiesCache.db files
    (matched by exact basename, case-insensitive - mirrors
    core/stickynotes_utils.py's find_sticky_notes_files()) anywhere under
    root_dir. Returns (paths, truncated); -wal/-shm sidecars are found
    alongside the main file later by the caller, not returned here."""
    lower_names = {n.lower() for n in WINDOWS_ACTIVITY_FILENAMES}
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > WINDOWS_ACTIVITY_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() in lower_names:
                found.append(os.path.join(root, fname))
                if len(found) >= WINDOWS_ACTIVITY_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def windows_activity_canonical_filename(entry_name):
    """Normalizes a case-insensitively-matched filename to its canonical
    form (wpndatabase.db(-wal/-shm) or ActivitiesCache.db(-wal/-shm)), or
    None - used by the in-image route so extracted files always land under
    the exact name this module's parsers look for, mirroring
    core/stickynotes_utils.py's sticky_notes_canonical_filename()."""
    lower = entry_name.lower()
    for canonical in WINDOWS_ACTIVITY_FILENAMES:
        canon_lower = canonical.lower()
        if lower == canon_lower:
            return canonical
        for suffix in _SQLITE_SIDECAR_SUFFIXES:
            if lower == canon_lower + suffix:
                return canonical + suffix
    return None


def windows_activity_base_name(canonical_name):
    """Strips a -wal/-shm sidecar suffix off an already-canonicalized name
    (see windows_activity_canonical_filename()), returning just the base
    (wpndatabase.db or ActivitiesCache.db) - used by the in-image route to
    group a main file with its own sidecars WITHOUT accidentally merging
    two genuinely different families that happen to land in the same
    in-image directory (not realistic on a real Windows system, where the
    two live under different LOCALAPPDATA subtrees, but grouped correctly
    regardless rather than assumed)."""
    if not canonical_name:
        return None
    for canonical in WINDOWS_ACTIVITY_FILENAMES:
        if canonical_name == canonical:
            return canonical
        for suffix in _SQLITE_SIDECAR_SUFFIXES:
            if canonical_name == canonical + suffix:
                return canonical
    return None


def _copy_with_sidecars_and_open(main_src, canonical_name):
    """Shared with core/stickynotes_utils.py's own established technique:
    copy the main file plus any real -wal/-shm sidecars into a fresh
    scratch temp directory (never the original evidence path, even though
    the caller has typically already copied/extracted it once itself -
    defense in depth) and open with a plain, non-immutable read-write
    connection so SQLite performs its own standard WAL checkpoint before
    this module queries it. Returns an open sqlite3.Connection, or None on
    any failure. Caller is responsible for conn.close() and cleaning up
    the returned tmp_dir."""
    if not os.path.isfile(main_src):
        return None, None
    tmp_dir = tempfile.mkdtemp(prefix='pif_winactivity_')
    tmp_main = os.path.join(tmp_dir, canonical_name)
    try:
        shutil.copy2(main_src, tmp_main)
    except OSError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return None, None
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        sidecar_src = main_src + suffix
        if os.path.isfile(sidecar_src):
            try:
                shutil.copy2(sidecar_src, tmp_main + suffix)
            except OSError:
                pass
    try:
        conn = sqlite3.connect(tmp_main)
        return conn, tmp_dir
    except sqlite3.Error:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return None, None


def _existing_columns(conn, table, candidates):
    """Real PRAGMA table_info() column-existence check - both this
    module's schemas are confirmed (by real, cited research) to have
    drifted slightly across Windows builds, so the SELECT is built only
    from columns actually present rather than a fixed guessed list that
    could crash against a build missing one of them."""
    try:
        present = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return []
    return [c for c in candidates if c in present]


def _extract_toast_text(payload):
    """Payload is a raw Toast XML blob, not JSON (confirmed by two
    independent sources - see this module's own docstring). Pulls every
    <text> node's content regardless of which toast template produced it;
    falls back to the raw payload (stripped of any XML tags, as a last
    resort readable summary) if no <text> node is found at all - a
    malformed/binary payload never raises, it just yields an empty/best-
    effort string, matching this app's established defensive posture for
    every other under-documented binary/text field."""
    if not payload:
        return ''
    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8', errors='replace')
        except Exception:
            return ''
    texts = _TOAST_TEXT_RE.findall(payload)
    if texts:
        cleaned = [_XML_TAG_RE.sub('', t).strip() for t in texts]
        return ' | '.join(t for t in cleaned if t)
    # No recognizable <text> node - fall back to a stripped-tags summary
    # rather than dumping raw markup, still disclosed as best-effort.
    stripped = _XML_TAG_RE.sub(' ', payload).strip()
    return re.sub(r'\s+', ' ', stripped)[:300]


def parse_wpndatabase_file(path, filename=None):
    """Parses a real wpndatabase.db (+ its -wal/-shm sidecars, if present
    alongside it) into a list of {artifact_type: "windows_notification"}
    records - one per Action Center notification, with the sending app
    (resolved via NotificationHandler.RecordId -> PrimaryId when that join
    succeeds, else just the raw numeric HandlerId) and the notification's
    own visible text (extracted from its Toast XML Payload)."""
    conn, tmp_dir = _copy_with_sidecars_and_open(path, WPNDATABASE_FILENAME)
    if conn is None:
        return []
    try:
        cols = _existing_columns(conn, 'Notification',
                                  ['Id', 'HandlerId', 'Type', 'Payload', 'Tag', 'ArrivalTime', 'ExpiryTime'])
        if 'Id' not in cols or 'Payload' not in cols:
            return []
        handler_names = {}
        handler_cols = _existing_columns(conn, 'NotificationHandler', ['RecordId', 'PrimaryId'])
        if 'RecordId' in handler_cols and 'PrimaryId' in handler_cols:
            try:
                for record_id, primary_id in conn.execute("SELECT RecordId, PrimaryId FROM NotificationHandler"):
                    handler_names[record_id] = primary_id
            except sqlite3.Error:
                pass

        records = []
        try:
            select_cols = ', '.join(cols)
            for row in conn.execute(f"SELECT {select_cols} FROM Notification"):
                if len(records) >= WINDOWS_NOTIFICATION_MAX_ROWS:
                    break
                row_dict = dict(zip(cols, row))
                notif_id = row_dict.get('Id')
                handler_id = row_dict.get('HandlerId')
                app_name = handler_names.get(handler_id) if handler_id is not None else None
                if not app_name:
                    app_name = f"Handler #{handler_id}" if handler_id is not None else "(unknown app)"
                text = _extract_toast_text(row_dict.get('Payload'))
                arrival_raw = row_dict.get('ArrivalTime')
                timestamp = filetime_to_unix(arrival_raw) if arrival_raw else None
                expiry_raw = row_dict.get('ExpiryTime')
                records.append({
                    "artifact_type": "windows_notification", "title": app_name, "url": "",
                    "value": text if text else "(no readable notification text)",
                    "timestamp": timestamp,
                    "extra": {
                        "notification_id": notif_id,
                        "handler_id": handler_id,
                        "notification_type": row_dict.get('Type'),
                        "tag": row_dict.get('Tag'),
                        "expiry_timestamp": filetime_to_unix(expiry_raw) if expiry_raw else None,
                    },
                })
        except sqlite3.Error:
            pass
        return records
    finally:
        conn.close()
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _resolve_activity_app(app_id_raw):
    """AppId is a JSON array of per-platform identifiers (each an object
    with keys like 'platform'/'application', or on the Win32 platform an
    'x_exe_path'/similar executable-path-shaped value) - defensively
    picks the most readable single string out of it rather than dumping
    the whole array, falling back to the raw AppId text unchanged if it
    isn't valid JSON at all (an older/different-shaped export, or genuine
    corruption)."""
    if not app_id_raw:
        return "(unknown app)"
    try:
        parsed = json.loads(app_id_raw)
    except (TypeError, ValueError):
        return str(app_id_raw)[:200]
    if isinstance(parsed, list):
        for entry in parsed:
            if isinstance(entry, dict):
                for key in ('application', 'x_exe_path', 'alternateId', 'packageId'):
                    if entry.get(key):
                        return str(entry[key])[:200]
        if parsed:
            return str(parsed[0])[:200]
    return str(app_id_raw)[:200]


def _resolve_activity_payload_summary(payload_raw):
    """Payload is JSON (often nesting the visible title/description under
    a versioned wrapper whose exact shape varies by ActivityType) -
    defensively pulls the first readable title/description-ish field it
    finds; falls back to a truncated raw string on any parse failure
    rather than dropping the row."""
    if not payload_raw:
        return ''
    try:
        parsed = json.loads(payload_raw)
    except (TypeError, ValueError):
        return str(payload_raw)[:300]

    def _hunt(obj, depth=0):
        if depth > 4 or not isinstance(obj, dict):
            return None
        for key in ('title', 'displayText', 'description', 'contentUri'):
            if obj.get(key):
                return str(obj[key])
        for v in obj.values():
            if isinstance(v, dict):
                found = _hunt(v, depth + 1)
                if found:
                    return found
        return None

    found = _hunt(parsed)
    return found[:300] if found else str(payload_raw)[:200]


def _activity_timestamp(raw):
    """StartTime/EndTime are confirmed plain Unix-epoch-seconds integers
    (see this module's own docstring) - handled defensively anyway, since
    a differently-shaped export could in principle store an ISO datetime
    string instead; a plain numeric value is used as-is, an ISO-looking
    string is parsed, anything else yields None rather than a wrong
    number."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        return float(raw)
    except (TypeError, ValueError):
        pass
    try:
        import datetime
        return datetime.datetime.fromisoformat(str(raw).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError):
        return None


def parse_activitiescache_file(path, filename=None):
    """Parses a real ActivitiesCache.db (+ sidecars) into a list of
    {artifact_type: "windows_timeline_activity"} records - one per
    Windows Timeline activity (an app launch, a document opened, a
    website visited), each with a resolved app name and a short content
    summary pulled out of its own JSON Payload. See this module's own
    docstring for the disclosed Windows-11-22H2+ reduced-fidelity
    caveat - this parser makes no attempt to distinguish a "rich"
    pre-KB5034204 record from a "thin" post-update one, it just reports
    whatever the database actually contains."""
    conn, tmp_dir = _copy_with_sidecars_and_open(path, ACTIVITIESCACHE_FILENAME)
    if conn is None:
        return []
    try:
        cols = _existing_columns(conn, 'Activity', [
            'Id', 'AppId', 'ActivityType', 'ActivityStatus', 'Payload', 'StartTime', 'EndTime', 'LastModifiedTime',
        ])
        if 'Id' not in cols:
            return []
        records = []
        try:
            select_cols = ', '.join(cols)
            for row in conn.execute(f"SELECT {select_cols} FROM Activity"):
                if len(records) >= WINDOWS_TIMELINE_MAX_ROWS:
                    break
                row_dict = dict(zip(cols, row))
                app_name = _resolve_activity_app(row_dict.get('AppId'))
                summary = _resolve_activity_payload_summary(row_dict.get('Payload'))
                start_ts = _activity_timestamp(row_dict.get('StartTime'))
                end_ts = _activity_timestamp(row_dict.get('EndTime'))
                records.append({
                    "artifact_type": "windows_timeline_activity", "title": app_name, "url": "",
                    "value": summary if summary else f"(activity type {row_dict.get('ActivityType')})",
                    "timestamp": start_ts,
                    "extra": {
                        "activity_id": row_dict.get('Id'),
                        "activity_type": row_dict.get('ActivityType'),
                        "activity_status": row_dict.get('ActivityStatus'),
                        "start_timestamp": start_ts,
                        "end_timestamp": end_ts,
                        "last_modified_timestamp": _activity_timestamp(row_dict.get('LastModifiedTime')),
                    },
                })
        except sqlite3.Error:
            pass
        return records
    finally:
        conn.close()
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def parse_windows_activity_file(path, filename=None):
    """Top-level dispatcher, mirroring core/registry_utils.py's
    parse_registry_hive_file()'s single-entry-point shape - dispatches on
    the file's own (canonicalized) basename since both real-fs and
    in-image callers already resolve one of the two known filenames
    before calling this."""
    name = (filename or os.path.basename(path)).lower()
    if name == WPNDATABASE_FILENAME.lower():
        return parse_wpndatabase_file(path, filename)
    if name == ACTIVITIESCACHE_FILENAME.lower():
        return parse_activitiescache_file(path, filename)
    return []
