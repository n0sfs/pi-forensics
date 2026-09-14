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


# --- 2026-09-14: real KML <TimeStamp><when> elements. Until now a point's time
# was written ONLY into the free-text <description>, so every reader got it back
# as an undated point and the Geolocation view reported "no timestamp - KML
# placemarks never carry one". They can, and the round trip below is the whole
# point: a time written here has to survive being read back. ---
def _point(lat, lon, timestamp=None, name="p", directory="d", alt=None):
    return {"name": name, "directory": directory, "lat": lat, "lon": lon,
            "alt": alt, "timestamp": timestamp}


def test_build_geo_kml_writes_a_real_timestamp_element():
    kml = geo._build_geo_kml([_point(37.7749, -122.4194, timestamp=1771690591.0)], "T")
    assert "<TimeStamp><when>2026-02-21T16:16:31Z</when></TimeStamp>" in kml


def test_build_geo_kml_omits_the_element_entirely_for_an_undated_point():
    # A missing time must be absent, never defaulted to an epoch or "now".
    kml = geo._build_geo_kml([_point(37.7749, -122.4194, timestamp=None)], "T")
    assert "<TimeStamp>" not in kml


def test_kml_timestamp_when_rejects_unusable_values_rather_than_guessing():
    assert geo._kml_timestamp_when(None) is None
    assert geo._kml_timestamp_when("") is None
    assert geo._kml_timestamp_when(float("nan")) is None


def test_kml_timestamp_when_passes_through_an_already_formatted_string():
    assert geo._kml_timestamp_when("2026-02-21T16:16:31Z") == "2026-02-21T16:16:31Z"


def test_leapp_record_timestamp_reaches_the_written_kml_end_to_end():
    # The chain this change exists to close: an ALEAPP row's own timestamp ->
    # geo point -> a real KML element a reader can recover.
    recs = [_leapp_record("leapp_module_finding", "DJI point",
                          {"Timestamp": "2026-02-21 16:16:31+00:00",
                           "Latitude": "37.7749000", "Longitude": "-122.4194000"},
                          timestamp=1771690591.0,
                          module="DJI Drone - Flight GPS Track (MCDatFlightRecords)")]
    points = geo._geo_points_from_leapp_records(recs)
    assert points and points[0]["timestamp"] == 1771690591.0
    kml = geo._build_geo_kml(points, "DJI")
    assert "<when>2026-02-21T16:16:31Z</when>" in kml
