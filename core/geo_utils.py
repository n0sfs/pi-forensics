"""Geolocation KML-building helpers shared by both the real-directory
geolocation export (routes/file_explorer.py) and the in-image geolocation
export (still in app.py pending its Step 7 extraction into
routes/image_browser.py) - the KML-building logic itself is identical
between the two, only how each candidate photo's bytes reach exiftool
differs (one batch call over a real directory vs. one call per candidate
extracted out of an unmounted image).

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import html
import re

# Scoped to camera-native still-image formats that reliably carry GPS EXIF
# tags - not every file in a case folder (raw acquisition images, logs, etc.
# would just be wasted exiftool calls). Video GPS extraction is a real gap
# but out of scope for v1.
GEO_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'tiff', 'tif', 'dng', 'heic', 'heif']


def _kml_escape(text):
    return html.escape(str(text), quote=True)


def _geo_points_from_exiftool_entries(entries):
    """Shared by both the real-directory and in-image geolocation routes -
    turns exiftool -j -n JSON output into a filtered list of GPS points."""
    points = []
    for entry in entries:
        lat, lon = entry.get('GPSLatitude'), entry.get('GPSLongitude')
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue  # most photos have no GPS tags at all - normal, not an error
        points.append({
            "name": entry.get('FileName', '(unknown)'),
            "directory": entry.get('Directory', ''),
            "lat": lat, "lon": lon,
            "alt": entry.get('GPSAltitude') if isinstance(entry.get('GPSAltitude'), (int, float)) else None,
            "timestamp": entry.get('DateTimeOriginal'),
        })
    return points


_LAT_COLUMN_RE = re.compile(r'lat(itude)?', re.IGNORECASE)
_LON_COLUMN_RE = re.compile(r'lon(g|gitude)?', re.IGNORECASE)


def _first_matching_float(row, pattern):
    """Scans a TSV row's {column_name: string_value} dict for the first
    column whose NAME matches `pattern`, returning its value as a float or
    None. Deliberately defensive rather than keyed to one specific,
    confirmed column name - see _geo_points_from_leapp_records()'s own
    docstring for why no real, confirmed sample of a location-bearing
    ALEAPP/iLEAPP module's exact column layout exists yet."""
    for key, value in row.items():
        if pattern.search(key):
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


def _geo_points_from_leapp_records(records):
    """Adapts core/leapp_tsv_utils.py's already-parsed ALEAPP/iLEAPP
    records into the same {name, directory, lat, lon, alt, timestamp}
    shape _geo_points_from_exiftool_entries() already produces, so
    _build_geo_kml() needs zero changes to render location data from
    either source.

    Deliberately column-name-pattern-based, not module-specific: no real,
    confirmed sample of a location-bearing ALEAPP/iLEAPP module's exact
    TSV column layout was available when this was written (this app's own
    one real live run against a non-rooted pull extraction found zero
    hits across every module it reached before an unrelated NFS stall -
    see core/leapp_tsv_utils.py's own docstring). Rather than guess a
    specific module/column name that might be wrong, this scans every
    leapp_* record's own raw row data (extra['row'], the full original
    TSV columns) for anything that LOOKS like a latitude/longitude pair -
    genuinely more robust than a hardcoded assumption given the same
    reality that shaped Phase A's curated-plus-fallback design: which
    modules produce real data (and what they name their columns) varies
    device to device in ways this codebase can't fully predict in
    advance. A row with no plausible lat/lon columns, or values outside
    real coordinate ranges, is silently skipped - most leapp_* records
    (a WiFi network, an installed app) have no location data at all, and
    that's the normal case, not an error."""
    points = []
    for r in records:
        if not str(r.get("artifact_type", "")).startswith("leapp_"):
            continue
        row = (r.get("extra") or {}).get("row")
        if not isinstance(row, dict):
            continue
        lat = _first_matching_float(row, _LAT_COLUMN_RE)
        lon = _first_matching_float(row, _LON_COLUMN_RE)
        if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            continue
        points.append({
            "name": r.get("title") or "(unnamed)",
            "directory": (r.get("extra") or {}).get("leapp_module", ""),
            "lat": lat, "lon": lon, "alt": None,
            "timestamp": r.get("timestamp"),
        })
    return points


def _build_geo_kml(points, doc_title):
    """Builds a KML document from a list of {name, directory, lat, lon, alt,
    timestamp} points - built in Python rather than exiftool's own -kml/
    kml.fmt template mechanism, which is a separate example asset in
    exiftool's upstream distribution not guaranteed present in the Debian
    package. Returns None if there are no points - an empty KML with zero
    placemarks isn't a meaningful forensic artifact worth writing."""
    if not points:
        return None
    placemarks = []
    for p in points:
        alt_str = f"{p['alt']:.1f} m" if p['alt'] is not None else "Unknown"
        desc = f"File: {p['name']}\nPath: {p['directory']}\nCaptured: {p['timestamp'] or 'Unknown'}\nAltitude: {alt_str}"
        # KML <coordinates> order is lon,lat,alt - the reverse of how
        # latitude/longitude are normally said out loud, easy to get backwards.
        placemarks.append(
            "<Placemark>"
            f"<name>{_kml_escape(p['name'])}</name>"
            f"<description>{_kml_escape(desc)}</description>"
            f"<Point><coordinates>{p['lon']:.7f},{p['lat']:.7f},{p['alt'] or 0}</coordinates></Point>"
            "</Placemark>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        f'<name>{_kml_escape(doc_title)}</name>'
        + "".join(placemarks) +
        '</Document></kml>'
    )
