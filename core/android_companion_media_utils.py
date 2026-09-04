"""Non-rooted Android Photos/Video metadata extraction via the same small
companion app relayed through `adb shell content query` - the 5th data
type this app's hand-built `pif-companion.apk` relay covers, alongside
SMS/Contacts/Call Log/Calendar (see core/android_companion_sms_utils.py's
own module docstring for the full mechanism/gap-closing rationale, read
that first).

**Scope, stated plainly**: this queries the OS's own MediaStore INDEX of
every photo/video it knows about (filename, size, dimensions, real
capture/added/modified timestamps, which folder/album, which app
contributed it, favorite/trashed/pending flags) - it does NOT pull the
actual image/video bytes. This app's existing "Pull Accessible Storage
(adb pull)" acquisition mode already copies the real files (including
their own embedded EXIF, readable via File Explorer's existing Metadata
tab/exiftool-backed tools once pulled) - this companion feature is a
complementary INDEX/CATALOG on top of that, not a replacement for it. Real
value it adds beyond a plain file listing: OWNER_PACKAGE_NAME (which app
contributed a given item - Camera vs. WhatsApp vs. a screenshot tool vs.
Instagram, genuine provenance a bare filename never reveals), IS_TRASHED
(Android 11+'s own Recycle-Bin-like "recently deleted, not yet purged"
media flag - a real, forensically valuable signal `adb pull`'s own plain
directory walk has no way to surface), and a device-wide catalog that
isn't limited to whatever folder an examiner happened to think to pull.

Real, authoritative research (2026-09-04), fetched directly from Google's
own official Android Developers reference pages (via a real browser
session against developer.android.com - the offline `android docs` tool's
own indexed knowledge base only covers guide-level docs, already confirmed
absent for the raw Javadoc reference pages during the Calendar companion
feature's own research), not guessed:

- Authority: `MediaStore.AUTHORITY` is literally `"media"` - confirmed via
  the real MediaStore class reference page. One relay provider class
  (MediaProvider.java) transparently serves BOTH
  `content://media/external/images/media` and
  `content://media/external/video/media` (and, in principle, `/audio/
  media`, not queried here - scoped to photos/video per the actual ask),
  exactly like CalendarProvider already serves both `events` and
  `attendees` under one shared authority.
- Permissions: since Android 13 (API 33), reading another app's photos/
  videos needs the granular `android.permission.READ_MEDIA_IMAGES`/
  `READ_MEDIA_VIDEO` (confirmed via the real "Access media files from
  shared storage" guide's own literal manifest example, which declares
  all three side by side with no `maxSdkVersion` gate needed - the OS
  itself only enforces whichever set actually exists on a given device).
  Pre-33 devices need the older `READ_EXTERNAL_STORAGE` instead - the
  worker (routes/mobile.py) attempts all three grants independently and
  treats each one's own success/failure as non-fatal, letting the actual
  query itself be the real signal of whether access worked, rather than
  trying to detect the connected device's exact API level itself. The
  guide's own caution that READ_MEDIA_IMAGES/VIDEO are "restricted to
  specific use cases" is a GOOGLE PLAY DISTRIBUTION policy, not an OS-
  enforced runtime restriction - irrelevant here since this app is never
  submitted to Play, only side-loaded via `adb install` (the identical
  reasoning already established for SMS/Call Log's own Play-policy lint
  category, gated the same way via `tools:ignore`).
- Every column-name STRING (not the Java constant's own name) below was
  read directly off the real, live-rendered MediaStore.MediaColumns API
  reference page - a real, easy-to-miss set of mismatches this exact
  check caught (the same class of gotcha CalendarContract.EventsColumns.
  STATUS already taught this session): SIZE's real column name is
  "_size" (not "size"), DISPLAY_NAME's is "_display_name" (not
  "display_name"), and DATE_TAKEN's is "datetaken" (not "date_taken" -
  genuinely the least guessable of the three).
- Timestamp units, confirmed live, not assumed uniform across every
  timestamp column the way most of this app's other artifact parsers
  have been so far: DATE_ADDED/DATE_MODIFIED are documented as "a non-
  negative timestamp measured as the number of seconds since
  1970-01-01T00:00:00Z" - SECONDS, no /1000 conversion needed - while
  DATE_TAKEN is documented as "milliseconds since 1970-01-01T00:00:00Z" -
  a real, easy-to-get-backwards mix of units within the very same table
  that this exact research step was what caught, not assumed.
- Fallback logic when DATE_TAKEN is absent/zero (common for videos,
  screenshots, and any image whose EXIF never populated DATETIME_ORIGINAL)
  mirrors Google's own real, documented MediaColumns.INFERRED_DATE
  derivation exactly ("1. If DATE_TAKEN is present, use it. 2. If DATE_
  TAKEN is absent, use DATE_MODIFIED.") - reimplemented here rather than
  querying the real INFERRED_DATE column itself, since that column was
  only added in API level 36 and this app's own devices may well be
  older; the documented LOGIC is what's reused, not the column.

GPS/location is deliberately NOT queried here, despite MediaStore having
historically exposed LATITUDE/LONGITUDE columns on older API levels - the
current MediaStore.MediaColumns reference page (confirmed live) no longer
lists them at all, and the sibling XMP column's own doc explicitly states
"any location details are redacted from this metadata for privacy
reasons." Modern MediaStore access to real, unredacted location data needs
a separate ACCESS_MEDIA_LOCATION permission plus opening each file via a
special non-redacted URI (MediaStore.setRequireOriginal()) - materially
more scope and a real, disclosed reliability caveat even then ("there is
no guarantee that your app has access to unredacted EXIF metadata"). This
app already has a genuinely more direct, more reliable path to real photo/
video GPS data for anything actually pulled via the standard "Pull
Accessible Storage" acquisition mode: the existing real-directory
Geolocation Export action (core/geo_utils.py, exiftool-backed), which
reads each file's own real, unredacted embedded EXIF GPS tags directly -
not attempted a second time here via a gated, unreliable MediaStore path.

owner_package_name is disclosed as best-effort, not guaranteed: the same
reference page notes that from Android 14 (UPSIDE_DOWN_CAKE) onward,
"visibility and query of this field will depend on package visibility" -
without this companion app declaring a <queries> manifest entry for the
specific packages an examiner might care about, the field may come back
null on a 14+ device even when a real value exists server-side. Reported
as-is (None when absent), never guessed or backfilled."""

PIF_COMPANION_MEDIA_AUTHORITY = "pif.companion.media"

# Order matters, matching every other companion module's own established
# free-text-column-last convention: bucket_display_name (a folder/album
# name - short, but user-influenced), then _data (a full path) and
# _display_name (a filename) last, in increasing order of "how likely is
# this to contain an embedded ', ' or '=' sequence" - genuinely low risk
# for all three compared to e.g. Calendar's free-text description, but
# still the least-constrained fields in this list, so kept last per this
# project's own established convention.
MEDIA_QUERY_COLUMNS = [
    "_id", "bucket_id", "date_added", "date_modified", "datetaken",
    "width", "height", "orientation", "duration", "mime_type",
    "is_trashed", "is_favorite", "is_pending", "is_download",
    "owner_package_name", "relative_path", "volume_name", "_size",
    "bucket_display_name", "_data", "_display_name",
]


def _int_or_none(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _bool_flag(raw):
    return raw in ("1", 1, True)


def build_companion_media_records(rows, media_kind):
    """Turns parse_content_query_output()'s row dicts (queried against
    MEDIA_QUERY_COLUMNS, against either the images or video MediaStore
    table) into this app's standard parsed_artifacts record shape.
    `media_kind` is 'image' or 'video' - determines the artifact_type
    (kept distinct rather than one shared type, so File Views/Evidence
    Timeline can filter photos separately from videos, matching this
    app's own established precedent of distinguishing SMS from MMS
    despite both riding through very similar query mechanics).

    timestamp follows MediaColumns.INFERRED_DATE's own documented
    derivation exactly (DATE_TAKEN if present, else DATE_MODIFIED) - see
    the module docstring for why DATE_TAKEN needs /1000.0 (milliseconds)
    while DATE_MODIFIED does not (already seconds)."""
    artifact_type = f"android_companion_media_{media_kind}"
    records = []
    for row in rows:
        display_name = row.get("_display_name") or "(unnamed file)"
        mime_type = row.get("mime_type") or "unknown"
        width = _int_or_none(row.get("width"))
        height = _int_or_none(row.get("height"))
        duration_ms = _int_or_none(row.get("duration"))
        size_bytes = _int_or_none(row.get("_size"))
        bucket = row.get("bucket_display_name") or None
        owner_package = row.get("owner_package_name") or None

        is_trashed = _bool_flag(row.get("is_trashed"))
        is_favorite = _bool_flag(row.get("is_favorite"))
        is_pending = _bool_flag(row.get("is_pending"))
        is_download = _bool_flag(row.get("is_download"))

        raw_datetaken = row.get("datetaken")
        datetaken_int = _int_or_none(raw_datetaken)
        raw_date_modified = row.get("date_modified")
        date_modified_int = _int_or_none(raw_date_modified)

        if datetaken_int:
            timestamp = datetaken_int / 1000.0
        elif date_modified_int:
            timestamp = float(date_modified_int)
        else:
            timestamp = None

        value_parts = [mime_type]
        if width and height:
            value_parts.append(f"{width}x{height}")
        if media_kind == "video" and duration_ms:
            value_parts.append(f"{round(duration_ms / 1000.0, 1)}s")
        if bucket:
            value_parts.append(f"Album: {bucket}")
        if owner_package:
            value_parts.append(f"From: {owner_package}")
        flags = []
        if is_trashed:
            flags.append("TRASHED")
        if is_favorite:
            flags.append("FAVORITE")
        if is_pending:
            flags.append("PENDING")
        if is_download:
            flags.append("DOWNLOAD")
        if flags:
            value_parts.append("/".join(flags))

        records.append({
            "artifact_type": artifact_type,
            "title": display_name,
            "url": "",
            "value": " | ".join(value_parts),
            "timestamp": timestamp,
            "extra": {
                "media_id": row.get("_id"),
                "bucket_id": row.get("bucket_id"),
                "bucket_display_name": bucket,
                "date_added": row.get("date_added"),
                "date_modified": row.get("date_modified"),
                "date_taken_ms": raw_datetaken,
                "width": width,
                "height": height,
                "orientation": _int_or_none(row.get("orientation")),
                "duration_ms": duration_ms,
                "mime_type": mime_type,
                "is_trashed": is_trashed,
                "is_favorite": is_favorite,
                "is_pending": is_pending,
                "is_download": is_download,
                "owner_package_name": owner_package,
                "relative_path": row.get("relative_path"),
                "volume_name": row.get("volume_name"),
                "size_bytes": size_bytes,
                "path": row.get("_data"),
            },
        })
    return records
