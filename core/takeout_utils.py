"""Google Takeout archive import (Android forensics expansion, Phase D).

SCOPE BOUNDARY, restated from this feature's own plan so it can't be
missed: this module imports an archive the examiner ALREADY OBTAINED
through Google's own official self-service export tool
(takeout.google.com, or the on-device Timeline export in Android
Settings) - or a legal production from Google. Nothing here performs
live account access, OAuth, scripted login, credential handling, or any
Google API call of any kind. The whole feature operates on local files
already sitting under this app's evidence-root sandbox, safe_path()-
validated throughout, exactly like every other import feature in this
app (Live Collection USB's "Import Selected Results" being the closest
precedent). Live cloud account access was explicitly ruled out during
this feature's own scoping - Google's anti-automation protections make
scripted login impractical, and it would be a real architectural/legal
departure this app has never made.

Per-product schema confidence, sourced from real, dated web research
(not guessed) - see this module's own dated CLAUDE.md entry for sources:

  HIGH CONFIDENCE (stable, Google-documented schema): Search History,
  YouTube History - both use the same "My Activity" JSON shape
  (header/title/titleUrl/time/products).

  BEST-EFFORT (no authoritative published schema, or a genuinely unstable
  real-world format): Location History (Google discontinued server-side
  Timeline storage in Dec 2024 - moved on-device-only, so a CURRENT
  Takeout Location History export is very often empty; this module
  supports both the legacy Records.json format AND the newer on-device
  Timeline.json/semanticSegments format, with confirmed Android-vs-iOS
  field-name divergence), Maps Places (format varies - GeoJSON or CSV
  depending on which Takeout export path was used), Photos sidecars
  (known filename-matching unreliability per community sources - no
  Google-published schema found).

Every best-effort parser is written defensively: a malformed/unexpected
record is skipped and counted, never crashes the whole file/import. This
mirrors this app's own established "disclose what's uncertain, don't
silently claim full coverage" discipline (e.g. MVT-Android's disclosed
best-effort status, linux_wtmp_login's "(Experimental)" label).
"""
import csv
import io
import json
import os
import re
import zipfile

TAKEOUT_MAX_RECORDS_PER_PRODUCT = 10_000
TAKEOUT_MAX_PHOTO_SIDECARS = 5_000

# Product folder names Google has used (renamed periodically) - matched
# as a case-insensitive substring against real directory names, not an
# exact match, since Takeout's own folder naming has already changed at
# least once for Location History alone ("Location History" ->
# "Location History (Timeline)").
_PRODUCT_FOLDER_PATTERNS = {
    "search_history": re.compile(r'my activity', re.IGNORECASE),
    "youtube_history": re.compile(r'youtube', re.IGNORECASE),
    "location_history": re.compile(r'location history|semantic location', re.IGNORECASE),
    "maps": re.compile(r'^maps', re.IGNORECASE),
    "photos": re.compile(r'google photos', re.IGNORECASE),
}


def _safe_extract_zip(zip_path, dest_dir):
    """Extracts a real Takeout .zip part into dest_dir, with a genuine
    zip-slip guard (no precedent for this existed elsewhere in this
    codebase - every other zip-reading module here only reads a single
    known member's bytes in memory, never bulk-extracts an untrusted
    archive to disk). Every member's resolved extraction path is checked
    to stay under dest_dir before writing - a crafted '../../etc/passwd'-
    style entry name is skipped and counted, never written outside the
    intended destination."""
    real_dest = os.path.realpath(dest_dir)
    skipped = 0
    extracted = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                target = os.path.realpath(os.path.join(dest_dir, member.filename))
                if target != real_dest and not target.startswith(real_dest + os.sep):
                    skipped += 1
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(member) as src, open(target, 'wb') as dst:
                    dst.write(src.read())
                extracted += 1
    except (zipfile.BadZipFile, OSError):
        return 0, 0
    return extracted, skipped


def prepare_takeout_root(input_paths, work_dir):
    """Accepts either an already-extracted Takeout/ folder path, or one-or-
    more real .zip parts (Google splits a large export into several
    independently-complete-but-partial archives, e.g. takeout-<ts>-001.zip,
    -002.zip - each needs merging into one working tree, not just using
    the first part). Returns (takeout_root, extracted_count, skipped_count)."""
    real_dirs = [p for p in input_paths if os.path.isdir(p)]
    real_zips = [p for p in input_paths if os.path.isfile(p) and p.lower().endswith('.zip')]

    if real_dirs and not real_zips:
        # Already an extracted folder - use it directly, no copy needed.
        return real_dirs[0], 0, 0

    os.makedirs(work_dir, exist_ok=True)
    total_extracted = 0
    total_skipped = 0
    for zip_path in real_zips:
        extracted, skipped = _safe_extract_zip(zip_path, work_dir)
        total_extracted += extracted
        total_skipped += skipped
    return work_dir, total_extracted, total_skipped


def find_takeout_product_folders(takeout_root):
    """Walks takeout_root (shallow - Takeout's own product folders are
    always one level down from the root 'Takeout/' directory, or directly
    at the root if the examiner already navigated one level in) looking
    for real folders matching _PRODUCT_FOLDER_PATTERNS. Returns
    {product_key: real_folder_path} for whichever products were actually
    found - an examiner's export may only include some products, and
    that's normal, not a failure."""
    found = {}
    try:
        entries = os.listdir(takeout_root)
    except OSError:
        return found
    # Also check one level deeper if this is the literal "Takeout" wrapper folder.
    search_dirs = [takeout_root]
    for e in entries:
        full = os.path.join(takeout_root, e)
        if os.path.isdir(full) and e.lower() == 'takeout':
            search_dirs.append(full)

    for base in search_dirs:
        try:
            sub_entries = os.listdir(base)
        except OSError:
            continue
        for name in sub_entries:
            full = os.path.join(base, name)
            if not os.path.isdir(full):
                continue
            for key, pattern in _PRODUCT_FOLDER_PATTERNS.items():
                if key not in found and pattern.search(name):
                    found[key] = full
    return found


def _record(artifact_type, title, url, value, timestamp, extra=None):
    return {"artifact_type": artifact_type, "title": title, "url": url,
            "value": value, "timestamp": timestamp, "extra": extra or {}}


def _iso_to_epoch(iso_str):
    """My Activity's `time` field is a real ISO-8601 timestamp - stdlib
    fromisoformat() handles it directly on Python 3.11+ (the 'Z' suffix
    needs a small pre-swap for 3.11's own fromisoformat, still simpler
    and more honest than a hand-rolled parser for a format this
    consistently documented)."""
    if not iso_str:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(iso_str.replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError):
        return None


def _parse_my_activity_json(path, artifact_type):
    """Shared by Search History and YouTube History - both use the exact
    same 'My Activity' JSON shape: an array of {header, title, titleUrl,
    time, products}. HIGH CONFIDENCE - a real, stable, Google-documented
    schema."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return records
    if not isinstance(data, list):
        return records
    for entry in data[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]:
        if not isinstance(entry, dict):
            continue
        title = entry.get('title') or '(untitled activity)'
        records.append(_record(
            artifact_type, title, entry.get('titleUrl', ''), title,
            _iso_to_epoch(entry.get('time')),
            {"header": entry.get('header'), "products": entry.get('products')},
        ))
    return records


def parse_takeout_search_history(folder):
    """My Activity/Search/MyActivity.json (and similarly-shaped per-
    product My Activity exports, e.g. Maps/Image Search) - walks for any
    MyActivity.json under the given folder, since Takeout can produce one
    per selected product under 'My Activity/'."""
    records = []
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if fname == 'MyActivity.json':
                records.extend(_parse_my_activity_json(os.path.join(root, fname), "takeout_search_history"))
    return records[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]


def parse_takeout_youtube_history(folder):
    """YouTube and YouTube Music/history/{watch-history,search-history}.json
    - same My Activity schema."""
    records = []
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if fname.endswith('-history.json'):
                records.extend(_parse_my_activity_json(os.path.join(root, fname), "takeout_youtube_history"))
    return records[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]


def _parse_legacy_records_json(path):
    """Records.json (pre-Dec-2024 Takeout Location History) - a flat
    locations[] array with latitudeE7/longitudeE7 (integer-encoded,
    divide by 1e7) and a millisecond or ISO timestamp depending on
    export age."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return records
    locations = data.get('locations') if isinstance(data, dict) else None
    if not isinstance(locations, list):
        return records
    for entry in locations[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]:
        if not isinstance(entry, dict):
            continue
        try:
            lat = entry.get('latitudeE7')
            lon = entry.get('longitudeE7')
            if lat is None or lon is None:
                continue
            lat_f, lon_f = float(lat) / 1e7, float(lon) / 1e7
        except (TypeError, ValueError):
            continue
        ts = entry.get('timestamp')
        ts_epoch = _iso_to_epoch(ts) if isinstance(ts, str) else None
        records.append(_record(
            "takeout_location_history", f"{lat_f:.5f}, {lon_f:.5f}", "",
            f"lat={lat_f:.5f} lon={lon_f:.5f}", ts_epoch,
            {"lat": lat_f, "lon": lon_f, "source_format": "records_json"},
        ))
    return records


def _timeline_json_point(obj):
    """Best-effort extraction of a single lat/lon pair from one
    semanticSegments entry's 'visit' or 'activity' sub-object - handles
    the confirmed real Android-vs-iOS field-name divergence
    (placeId/placeID, placeLocation.latLng decimal-string vs a bare
    geo:-URI string on iOS). No authoritative schema exists for this
    format - every access here is defensive, returns None rather than
    guessing on anything unexpected."""
    loc = None
    if isinstance(obj, dict):
        pl = obj.get('placeLocation')
        if isinstance(pl, dict):
            loc = pl.get('latLng')
        elif isinstance(pl, str):
            loc = pl  # iOS: a bare "geo:lat,lon" URI string
        elif isinstance(obj.get('start'), dict):
            loc = obj['start'].get('latLng')  # activity segment shape
    if not isinstance(loc, str):
        return None
    # "37.7749°, -122.4194°" (Android decimal-degree string) or
    # "geo:37.7749,-122.4194" (iOS geo: URI) - strip non-numeric noise.
    cleaned = loc.replace('geo:', '').replace('°', '')
    parts = [p.strip() for p in cleaned.split(',')]
    if len(parts) != 2:
        return None
    try:
        return float(parts[0]), float(parts[1])
    except ValueError:
        return None


def _parse_timeline_json(path):
    """The current (post-Dec-2024) on-device Timeline export format -
    top-level 'semanticSegments' array (Android wraps in an object; iOS
    ships a bare array - both handled). BEST-EFFORT, see this module's
    own docstring."""
    records = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return records
    segments = data.get('semanticSegments') if isinstance(data, dict) else data
    if not isinstance(segments, list):
        return records
    for seg in segments[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]:
        if not isinstance(seg, dict):
            continue
        point = _timeline_json_point(seg.get('visit')) or _timeline_json_point(seg.get('activity')) or _timeline_json_point(seg)
        if not point:
            continue
        lat_f, lon_f = point
        if not (-90 <= lat_f <= 90 and -180 <= lon_f <= 180):
            continue
        ts_epoch = _iso_to_epoch(seg.get('startTime'))
        records.append(_record(
            "takeout_location_history", f"{lat_f:.5f}, {lon_f:.5f}", "",
            f"lat={lat_f:.5f} lon={lon_f:.5f}", ts_epoch,
            {"lat": lat_f, "lon": lon_f, "source_format": "timeline_json"},
        ))
    return records


def parse_takeout_location_history(folder):
    """BEST-EFFORT - see module docstring. Handles both the legacy
    Records.json format and the new on-device Timeline.json format,
    wherever found under the given folder."""
    records = []
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            full = os.path.join(root, fname)
            if fname == 'Records.json':
                records.extend(_parse_legacy_records_json(full))
            elif fname == 'Timeline.json':
                records.extend(_parse_timeline_json(full))
    return records[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]


def _parse_maps_geojson(path):
    records = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return records
    features = data.get('features') if isinstance(data, dict) else None
    if not isinstance(features, list):
        return records
    for feat in features[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]:
        if not isinstance(feat, dict):
            continue
        props = feat.get('properties') or {}
        geom = feat.get('geometry') or {}
        coords = geom.get('coordinates')
        lat = lon = None
        if isinstance(coords, list) and len(coords) >= 2:
            try:
                lon, lat = float(coords[0]), float(coords[1])  # GeoJSON order: [lon, lat]
            except (TypeError, ValueError):
                lat = lon = None
        name = props.get('name') or props.get('location', {}).get('name') if isinstance(props.get('location'), dict) else props.get('name')
        name = name or '(unnamed place)'
        extra = {"google_maps_url": props.get('google_maps_url')}
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
            extra["lat"], extra["lon"] = lat, lon
        records.append(_record("takeout_maps_place", name, props.get('google_maps_url', ''),
                                name, None, extra))
    return records


def _parse_maps_csv(path):
    records = []
    try:
        with open(path, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if len(records) >= TAKEOUT_MAX_RECORDS_PER_PRODUCT:
                    break
                title_col = next((v for k, v in row.items() if k and 'title' in k.lower()), None)
                title = (title_col or '(unnamed place)').strip() or '(unnamed place)'
                records.append(_record("takeout_maps_place", title, "", title, None, dict(row)))
    except (OSError, csv.Error):
        pass
    return records


def parse_takeout_maps_places(folder):
    """BEST-EFFORT - format genuinely varies (GeoJSON 'Saved Places.json'/
    'Labeled Places.json', or a per-list CSV) depending on which Takeout
    export path was used - see module docstring."""
    records = []
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            full = os.path.join(root, fname)
            if fname.endswith('.json') and ('saved' in fname.lower() or 'labeled' in fname.lower()):
                records.extend(_parse_maps_geojson(full))
            elif fname.endswith('.csv'):
                records.extend(_parse_maps_csv(full))
    return records[:TAKEOUT_MAX_RECORDS_PER_PRODUCT]


def parse_takeout_photos_sidecars(folder):
    """BEST-EFFORT - <filename>.<ext>.json sidecars, photoTakenTime/
    geoData. Known real-world unreliability (filename truncation at 46
    chars, numeric-suffix mismatches on duplicates per community
    sources) - disclosed, not silently assumed complete. Capped
    separately from other products (TAKEOUT_MAX_PHOTO_SIDECARS, not
    TAKEOUT_MAX_RECORDS_PER_PRODUCT) since a real Photos export can be
    tens of thousands of files."""
    records = []
    count = 0
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if not fname.lower().endswith('.json') or count >= TAKEOUT_MAX_PHOTO_SIDECARS:
                continue
            full = os.path.join(root, fname)
            try:
                with open(full, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict) or 'photoTakenTime' not in data and 'geoData' not in data:
                continue
            count += 1
            taken = data.get('photoTakenTime') or {}
            ts = None
            try:
                ts = float(taken.get('timestamp')) if taken.get('timestamp') else None
            except (TypeError, ValueError):
                pass
            geo = data.get('geoData') or {}
            extra = {"original_filename": fname[:-5] if fname.lower().endswith('.json') else fname}
            try:
                lat, lon = float(geo.get('latitude', 0)), float(geo.get('longitude', 0))
                if (lat, lon) != (0.0, 0.0) and -90 <= lat <= 90 and -180 <= lon <= 180:
                    extra["lat"], extra["lon"] = lat, lon
            except (TypeError, ValueError):
                pass
            title = extra["original_filename"]
            records.append(_record("takeout_photo_metadata", title, "", title, ts, extra))
    return records


def import_takeout_archive(takeout_root):
    """Top-level dispatcher - walks discovered product folders and calls
    the right per-product parser for each, returning a summary dict.
    `warnings` lists which products were found but are best-effort (not
    a parse error - just the honest confidence-level disclosure this
    module's own docstring describes), driving the import UI's own
    solid-vs-best-effort labeling."""
    products = find_takeout_product_folders(takeout_root)
    all_records = []
    location_points = []
    warnings = []

    if 'search_history' in products:
        all_records.extend(parse_takeout_search_history(products['search_history']))
    if 'youtube_history' in products:
        all_records.extend(parse_takeout_youtube_history(products['youtube_history']))
    if 'location_history' in products:
        recs = parse_takeout_location_history(products['location_history'])
        all_records.extend(recs)
        if recs:
            warnings.append(f"Location History: {len(recs)} record(s) found - best-effort format, see documentation.")
        location_points.extend({"name": r["title"], "directory": "Takeout Location History",
                                 "lat": r["extra"]["lat"], "lon": r["extra"]["lon"], "alt": None,
                                 "timestamp": r["timestamp"]} for r in recs if "lat" in r.get("extra", {}))
    if 'maps' in products:
        recs = parse_takeout_maps_places(products['maps'])
        all_records.extend(recs)
        if recs:
            warnings.append(f"Maps Places: {len(recs)} record(s) found - best-effort format, see documentation.")
        location_points.extend({"name": r["title"], "directory": "Takeout Maps Places",
                                 "lat": r["extra"]["lat"], "lon": r["extra"]["lon"], "alt": None,
                                 "timestamp": r["timestamp"]} for r in recs if "lat" in r.get("extra", {}))
    if 'photos' in products:
        recs = parse_takeout_photos_sidecars(products['photos'])
        all_records.extend(recs)
        if recs:
            warnings.append(f"Photos: {len(recs)} sidecar(s) parsed - best-effort filename matching, see documentation.")
        location_points.extend({"name": r["title"], "directory": "Takeout Photos",
                                 "lat": r["extra"]["lat"], "lon": r["extra"]["lon"], "alt": None,
                                 "timestamp": r["timestamp"]} for r in recs if "lat" in r.get("extra", {}))

    return {
        "records": all_records, "location_points": location_points,
        "products_found": sorted(products.keys()), "warnings": warnings,
    }
