"""core/geo_utils.py - the KML-building core (_build_geo_kml, already used
by the EXIF-photo geolocation export) plus _geo_points_from_leapp_records(),
the new adapter feeding it from ALEAPP/iLEAPP-parsed records (Android
forensics expansion, Phase C). Pure stdlib, no fixtures needed beyond
plain dicts matching core/leapp_tsv_utils.py's own real record shape.
"""
import core.geo_utils as geo


def _leapp_record(artifact_type, title, row, timestamp=None, module="Some Module"):
    return {
        "artifact_type": artifact_type, "title": title, "url": "", "value": "",
        "timestamp": timestamp, "extra": {"leapp_tool": "aleapp", "leapp_module": module, "row": row},
    }


def test_first_matching_float_finds_the_first_column_matching_the_pattern():
    row = {"SSID": "HomeNet", "Latitude": "37.7749", "Longitude": "-122.4194"}
    assert geo._first_matching_float(row, geo._LAT_COLUMN_RE) == 37.7749
    assert geo._first_matching_float(row, geo._LON_COLUMN_RE) == -122.4194


def test_first_matching_float_returns_none_when_no_column_matches():
    row = {"SSID": "HomeNet", "BSSID": "AA:BB:CC:DD:EE:FF"}
    assert geo._first_matching_float(row, geo._LAT_COLUMN_RE) is None


def test_first_matching_float_returns_none_for_a_non_numeric_value():
    row = {"Latitude": "unknown"}
    assert geo._first_matching_float(row, geo._LAT_COLUMN_RE) is None


def test_geo_points_from_leapp_records_extracts_a_valid_point():
    records = [_leapp_record(
        "leapp_wifi_network", "HomeNetwork",
        {"SSID": "HomeNetwork", "Lat": "37.7749", "Lon": "-122.4194"},
        module="Wifi",
    )]
    points = geo._geo_points_from_leapp_records(records)
    assert len(points) == 1
    p = points[0]
    assert p["name"] == "HomeNetwork"
    assert p["directory"] == "Wifi"
    assert p["lat"] == 37.7749
    assert p["lon"] == -122.4194
    assert p["alt"] is None


def test_geo_points_from_leapp_records_skips_records_with_no_coordinates():
    records = [_leapp_record("leapp_installed_app", "com.example.app", {"Package": "com.example.app"})]
    assert geo._geo_points_from_leapp_records(records) == []


def test_geo_points_from_leapp_records_skips_out_of_range_values():
    # A column that matches the lat/lon name pattern but holds a value no
    # real coordinate could have (e.g. a row count, a version number) -
    # real defensive tolerance, since the column-name match is a heuristic.
    records = [_leapp_record("leapp_module_finding", "x", {"Latitude": "99999", "Longitude": "-122.0"})]
    assert geo._geo_points_from_leapp_records(records) == []


def test_geo_points_from_leapp_records_ignores_non_leapp_artifact_types():
    records = [{
        "artifact_type": "browser_url_ioc_match", "title": "x", "url": "", "value": "",
        "timestamp": None, "extra": {"row": {"Latitude": "37.0", "Longitude": "-122.0"}},
    }]
    assert geo._geo_points_from_leapp_records(records) == []


def test_geo_points_from_leapp_records_tolerates_missing_or_malformed_extra():
    records = [
        {"artifact_type": "leapp_wifi_network", "title": "x", "url": "", "value": "", "timestamp": None, "extra": None},
        {"artifact_type": "leapp_wifi_network", "title": "x", "url": "", "value": "", "timestamp": None, "extra": {}},
        {"artifact_type": "leapp_wifi_network", "title": "x", "url": "", "value": "", "timestamp": None, "extra": {"row": "not a dict"}},
    ]
    assert geo._geo_points_from_leapp_records(records) == []  # tolerated, not raised


def test_geo_points_from_leapp_records_feeds_build_geo_kml_unchanged():
    # The actual point of this adapter: reuse _build_geo_kml() completely
    # unchanged once fed the right shape.
    records = [_leapp_record(
        "leapp_wifi_network", "HomeNetwork",
        {"Lat": "37.7749", "Lon": "-122.4194"}, module="Wifi",
    )]
    points = geo._geo_points_from_leapp_records(records)
    kml = geo._build_geo_kml(points, "Test Doc")
    assert kml is not None
    assert "<Placemark>" in kml
    assert "-122.4194000,37.7749000" in kml  # lon,lat order per KML spec, per _build_geo_kml's own convention


def test_build_geo_kml_returns_none_for_zero_points():
    assert geo._build_geo_kml([], "Empty") is None
