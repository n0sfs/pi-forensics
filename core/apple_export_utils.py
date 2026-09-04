"""Apple "Data & Privacy" export import (privacy.apple.com) - the iOS-world
counterpart to Google Takeout import (core/takeout_utils.py), extending
this app's Android forensics expansion to iOS/Apple-account data given
the same real-world reality that motivated it: most people's data lives
partly in a phone-maker's cloud, not just on the device itself.

SCOPE BOUNDARY, identical to core/takeout_utils.py's own: this imports an
archive the examiner (or the account holder) already obtained through
Apple's own official self-service export tool at privacy.apple.com, or a
legal production from Apple. Nothing here performs live account access,
authentication, or any Apple API call. Apple delivers the export as an
ENCRYPTED zip plus a separately-emailed password - this module does NOT
attempt to decrypt it; the examiner must extract it themselves first
(using the password they/the account holder already legitimately have,
exactly the same "you hold the key, we just read what it unlocks" pattern
this app already uses for BitLocker/LUKS/VeraCrypt volumes, just one
manual step earlier in the chain rather than inside this app). Only an
already-extracted folder is accepted here, never a raw .zip - avoiding
any need for this module to itself handle a password at all.

Per-category schema confidence, sourced from real, dated web research
(not guessed) - see this module's own dated CLAUDE.md entry for sources:

  HIGH CONFIDENCE - genuine, stable, RFC-documented open standards, MORE
  reliable than anything in the Google Takeout research (which relies on
  Google's own JSON conventions, not published open standards): Contacts
  (vCard, RFC 6350) and Calendars/Reminders (iCalendar, RFC 5545).

  BEST-EFFORT: Safari Bookmarks (reported as the standard NETSCAPE-
  Bookmark-file HTML format used across every major browser, but only
  moderately confirmed - Apple's own support docs describe it, no second
  independent source directly inspected a real export) and Photos
  metadata (a batched CSV sidecar, e.g. "Photo details-1.csv", with
  REPORTED but not Apple-published column names, and real-world reports
  of inconsistent per-photo coverage).

  NOT AVAILABLE AT ALL, disclosed rather than treated as a parsing gap:
  Apple's export has no location-history category whatsoever - Find My/
  Significant Locations data is end-to-end encrypted on-device and
  genuinely inaccessible to Apple itself, confirmed via Apple's own
  community-support statements. This is a real architectural absence,
  not a format-instability problem the way Google's Location History is
  - there is nothing to defensively parse here because nothing is ever
  exported. The one real location source in an Apple export is embedded
  EXIF GPS in the Photos themselves (JPEG/HEIC), which this module
  deliberately does NOT re-implement - the caller (routes/file_
  explorer.py's import worker) points the ALREADY-EXISTING real-directory
  Geolocation Export mechanism (core/geo_utils.py's
  _geo_points_from_exiftool_entries/_build_geo_kml, the same code an
  examiner would already reach via a normal folder's right-click menu)
  directly at the discovered Photos folder - zero new location-parsing
  code needed for this source.
"""
import csv
import os
import re
from datetime import datetime, timezone

APPLE_MAX_RECORDS_PER_PRODUCT = 10_000

_VCF_EXT = '.vcf'
_ICS_EXT = '.ics'


def _unfold_lines(text):
    """RFC 6350/5545 line-folding: a long line is continued by inserting a
    CRLF (or bare LF, real-world files vary) immediately followed by a
    single space or tab - unfolding removes that break+whitespace pair so
    each logical property is back on one line before parsing. The exact
    same folding rule is shared by vCard and iCalendar (both descend from
    the same IETF property-list convention), so one function serves both
    parsers."""
    text = text.replace('\r\n', '\n')
    return re.sub(r'\n[ \t]', '', text)


def _split_property_line(line):
    """A vCard/iCalendar property line is `NAME[;PARAM=VALUE...]:VALUE` -
    splits on the FIRST unescaped colon (a value can itself legitimately
    contain colons, e.g. a URL), returning (name_upper, value) or None
    for a line that doesn't look like a property at all (blank lines
    between folded content, stray whitespace)."""
    line = line.strip()
    if not line or ':' not in line:
        return None
    name_part, _, value = line.partition(':')
    name = name_part.split(';', 1)[0].strip().upper()
    return name, value.strip()


def _parse_ical_datetime(value):
    """Best-effort iCalendar datetime parsing - handles the two common
    real forms (`20260115T093000Z` UTC, and `20260115` all-day-event
    DATE value). A TZID-qualified local datetime (no Z suffix, a named
    timezone in a separate parameter) is NOT resolved to an absolute
    time here - full IANA timezone-database handling is real scope this
    best-effort parser deliberately doesn't take on; returns None rather
    than silently guessing at an offset."""
    if not value:
        return None
    value = value.strip()
    try:
        if re.fullmatch(r'\d{8}T\d{6}Z', value):
            return datetime.strptime(value, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp()
        if re.fullmatch(r'\d{8}', value):
            return datetime.strptime(value, '%Y%m%d').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return None


def _record(artifact_type, title, url, value, timestamp, extra=None):
    return {"artifact_type": artifact_type, "title": title, "url": url,
            "value": value, "timestamp": timestamp, "extra": extra or {}}


def parse_vcard_file(path, artifact_type="apple_contact"):
    """RFC 6350 vCard - HIGH CONFIDENCE. A single .vcf file commonly holds
    MANY concatenated BEGIN:VCARD...END:VCARD blocks (a full address-book
    export), not just one contact. `artifact_type` defaults to Apple's own
    export (this function's original caller) but vCard is an open
    standard, not Apple-specific - core/takeout_utils.py's Google Contacts
    import (2026-09-04) reuses this exact function with
    artifact_type="takeout_contact" rather than duplicating the parsing
    logic, matching this app's own "one source, one artifact_type" naming
    convention (every other artifact_type in this app is source-scoped,
    e.g. android_contact vs mobile_contact vs apple_contact - a Google-
    sourced contact must never be silently labeled "Apple Export")."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = _unfold_lines(f.read())
    except OSError:
        return records

    for block in re.findall(r'BEGIN:VCARD(.*?)END:VCARD', text, re.DOTALL | re.IGNORECASE):
        if len(records) >= APPLE_MAX_RECORDS_PER_PRODUCT:
            break
        name = None
        phones, emails, org = [], [], None
        for line in block.splitlines():
            parsed = _split_property_line(line)
            if not parsed:
                continue
            prop, val = parsed
            if prop == 'FN':
                name = val
            elif prop.startswith('TEL') and val:
                phones.append(val)
            elif prop.startswith('EMAIL') and val:
                emails.append(val)
            elif prop == 'ORG':
                org = val
        title = name or (phones[0] if phones else None) or (emails[0] if emails else None) or '(unnamed contact)'
        value_parts = []
        if phones:
            value_parts.append("Phone: " + ", ".join(phones))
        if emails:
            value_parts.append("Email: " + ", ".join(emails))
        if org:
            value_parts.append(f"Org: {org}")
        records.append(_record(artifact_type, title, "", " | ".join(value_parts) or "(no phone/email)",
                                None, {"phones": phones, "emails": emails, "org": org}))
    return records


def find_apple_vcard_contacts(root):
    records = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if fname.lower().endswith(_VCF_EXT):
                records.extend(parse_vcard_file(os.path.join(dirpath, fname)))
    return records[:APPLE_MAX_RECORDS_PER_PRODUCT]


def parse_icalendar_file(path, event_type="apple_calendar_event", reminder_type="apple_reminder"):
    """RFC 5545 iCalendar - HIGH CONFIDENCE. Covers both VEVENT (calendar
    events) and VTODO (Reminders) blocks, since Apple's export documents
    both riding the same .ics format. event_type/reminder_type default to
    Apple's own export but iCalendar is an open standard - see
    parse_vcard_file()'s own docstring above for why a Google-sourced
    calendar/reminder must get its own source-scoped artifact_type
    (core/takeout_utils.py, 2026-09-04, passes
    takeout_calendar_event/takeout_reminder)."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = _unfold_lines(f.read())
    except OSError:
        return records

    for kind, artifact_type in (('VEVENT', event_type), ('VTODO', reminder_type)):
        for block in re.findall(rf'BEGIN:{kind}(.*?)END:{kind}', text, re.DOTALL | re.IGNORECASE):
            if len(records) >= APPLE_MAX_RECORDS_PER_PRODUCT:
                break
            fields = {}
            for line in block.splitlines():
                parsed = _split_property_line(line)
                if not parsed:
                    continue
                prop, val = parsed
                if prop in ('SUMMARY', 'LOCATION', 'DESCRIPTION', 'DTSTART', 'DTEND', 'DUE', 'COMPLETED') and prop not in fields:
                    fields[prop] = val
            title = fields.get('SUMMARY') or '(untitled)'
            ts = _parse_ical_datetime(fields.get('DTSTART') or fields.get('DUE'))
            value_parts = []
            if fields.get('LOCATION'):
                value_parts.append(f"Location: {fields['LOCATION']}")
            if fields.get('DESCRIPTION'):
                value_parts.append(fields['DESCRIPTION'][:200])
            records.append(_record(artifact_type, title, "", " | ".join(value_parts) or title, ts, dict(fields)))
    return records


def find_apple_icalendar_events(root):
    records = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if fname.lower().endswith(_ICS_EXT):
                records.extend(parse_icalendar_file(os.path.join(dirpath, fname)))
    return records[:APPLE_MAX_RECORDS_PER_PRODUCT]


_BOOKMARK_LINK_RE = re.compile(
    r'<A\s+[^>]*HREF="([^"]*)"[^>]*>(.*?)</A>', re.IGNORECASE | re.DOTALL)
_ADD_DATE_RE = re.compile(r'ADD_DATE="(\d+)"', re.IGNORECASE)


def parse_safari_bookmarks_html(path):
    """BEST-EFFORT - the standard NETSCAPE-Bookmark-file HTML format
    (the same cross-browser-compatible format Chrome/Firefox/Edge all
    use for bookmark export/import) - see module docstring for this
    format's own confidence caveat. A plain regex over `<A HREF=...>` tags
    is used rather than a full HTML parser, matching this format's own
    real-world looseness (it's tag-soup, not valid XML/XHTML)."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            html_text = f.read()
    except OSError:
        return records
    for match in _BOOKMARK_LINK_RE.finditer(html_text):
        if len(records) >= APPLE_MAX_RECORDS_PER_PRODUCT:
            break
        url = match.group(1).strip()
        title = re.sub(r'<[^>]+>', '', match.group(2)).strip() or url
        add_date_match = _ADD_DATE_RE.search(match.group(0))
        ts = float(add_date_match.group(1)) if add_date_match else None
        records.append(_record("apple_safari_bookmark", title, url, url, ts, {}))
    return records


def find_apple_safari_bookmarks(root):
    records = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if 'bookmark' in fname.lower() and fname.lower().endswith(('.html', '.htm')):
                records.extend(parse_safari_bookmarks_html(os.path.join(dirpath, fname)))
    return records[:APPLE_MAX_RECORDS_PER_PRODUCT]


def parse_apple_photos_metadata_csv(path):
    """BEST-EFFORT - a batched 'Photo details-N.csv' sidecar, REPORTED
    (not Apple-published) columns: imgName, fileChecksum, favorite,
    hidden, deleted, originalCreationDate, viewCount, importDate. Real-
    world reports describe inconsistent per-photo coverage - some photos
    have no corresponding row at all. Read defensively via DictReader so
    a differently-ordered or partially-different real column set doesn't
    crash the parse; any row missing the one column this parser actually
    keys on (a name-like column) is skipped, not guessed at."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if len(records) >= APPLE_MAX_RECORDS_PER_PRODUCT:
                    break
                name_col = next((v for k, v in row.items() if k and 'name' in k.lower()), None)
                if not name_col:
                    continue
                records.append(_record("apple_photo_metadata", name_col, "", name_col, None, dict(row)))
    except (OSError, csv.Error):
        pass
    return records


def find_apple_photos_metadata(root):
    """Finds both the Photos directory itself (for the caller to run
    EXIF-based geolocation extraction against - see module docstring)
    and any 'Photo details*.csv' sidecar files. Returns
    (photos_dir_or_None, metadata_records)."""
    photos_dir = None
    records = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            lower = fname.lower()
            if lower.startswith('photo details') and lower.endswith('.csv'):
                records.extend(parse_apple_photos_metadata_csv(os.path.join(dirpath, fname)))
                if photos_dir is None:
                    photos_dir = dirpath
            elif photos_dir is None and lower.endswith(('.jpg', '.jpeg', '.heic', '.png')):
                photos_dir = dirpath
    return photos_dir, records[:APPLE_MAX_RECORDS_PER_PRODUCT]


def import_apple_export(export_root):
    """Top-level dispatcher - walks export_root once per real category
    (vCard/iCalendar/Safari/Photos), returning a summary dict. `warnings`
    lists which categories were found but are best-effort (Safari,
    Photos) - matching core/takeout_utils.py's own disclosure shape.
    `photos_dir` is returned separately (not folded into `records`) since
    the caller needs the real directory path to run the existing EXIF-
    based geolocation extraction against, not a set of already-parsed
    records - see module docstring for why no new location-parsing code
    exists in this module at all."""
    all_records = []
    warnings = []
    products_found = []

    contacts = find_apple_vcard_contacts(export_root)
    if contacts:
        all_records.extend(contacts)
        products_found.append('contacts')

    calendar_events = find_apple_icalendar_events(export_root)
    if calendar_events:
        all_records.extend(calendar_events)
        products_found.append('calendars_reminders')

    bookmarks = find_apple_safari_bookmarks(export_root)
    if bookmarks:
        all_records.extend(bookmarks)
        products_found.append('safari_bookmarks')
        warnings.append(f"Safari Bookmarks: {len(bookmarks)} record(s) found - best-effort format, see documentation.")

    photos_dir, photo_records = find_apple_photos_metadata(export_root)
    if photo_records:
        all_records.extend(photo_records)
    if photos_dir:
        products_found.append('photos')
        warnings.append("Photos: found - best-effort metadata CSV coverage, see documentation. "
                         "Location data (if any) comes from each photo's own embedded GPS EXIF, extracted separately.")

    return {
        "records": all_records, "photos_dir": photos_dir,
        "products_found": products_found, "warnings": warnings,
    }
