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
