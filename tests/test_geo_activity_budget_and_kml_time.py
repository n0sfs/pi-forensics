"""Two Pattern of Life geolocation defects, both fixed 2026-09-15.

1. `points[:GEO_ACTIVITY_MAX_POINTS]` was a head-slice of a list built by
   appending every Takeout row first and every KML placemark second. A case
   with 5,200 Takeout rows and a 30-point EXIF photo KML therefore kept 5,000
   Takeout rows and ZERO photo pins - an entire evidence source deleted from
   the map, from Frequent Locations, from Home/Work and from the exported
   report, under a note reading "list truncated - too many points to show
   all", which reads as a display limit.

2. `_parse_kml_when()` handed a zone-less <when> value straight to
   datetime.fromisoformat().timestamp(), which resolves a naive datetime
   against the SERVER's timezone. The same KML produced a different epoch on
   a station set to Etc/UTC than on one set to America/New_York, and the
   docstring claimed UTC while the code did neither. These values feed the
   visit/dwell counting, the implausible-speed check and the Home/Work
   inference, so a shifted one manufactures a conclusion rather than merely
   mislabelling a row.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.reporting as reporting
from routes.reporting import _parse_kml_when


# --- KML <when> timezone handling -------------------------------------------

def test_kml_when_accepts_utc_z_form():
    """The form this app's own exporter writes (core/geo_utils.py)."""
    assert _parse_kml_when("2026-03-14T22:15:00Z") == 1773526500.0


def test_kml_when_accepts_an_explicit_offset():
    """Same instant, expressed with a real offset instead of Z."""
    assert _parse_kml_when("2026-03-14T18:15:00-04:00") == 1773526500.0


def test_kml_when_rejects_a_naive_datetime():
    """The bug: this used to resolve against the server's TZ, so the answer
    depended on where the station was configured rather than on the evidence.
    A point with no usable time is simply undated - which the UI states."""
    assert _parse_kml_when("2026-03-14T22:15:00") is None


def test_kml_when_rejects_a_date_only_value():
    """Also legal KML, also zone-less. The old docstring claimed this was
    read as midnight UTC; it was read as midnight station-local."""
    assert _parse_kml_when("2026-03-14") is None


def test_kml_when_rejects_junk_and_empty():
    for value in (None, "", "   ", "not a date", "2026-13-45T99:99:99Z"):
        assert _parse_kml_when(value) is None


# --- Per-source point budget ------------------------------------------------

def _allocate(points):
    """Drives the real allocation by calling the collector with a stubbed
    point set - the allocation is inline in _collect_case_geo_activity, so
    exercise it through the function rather than duplicating the algorithm
    here (a reimplementation would test itself, not the code)."""
    import routes.reporting as r
    monkey_points = list(points)

    def fake_open(_folder):
        return None

    def fake_geoloc(_folder, _files):
        # One "KML entry" per distinct source, replaying the stub points.
        by_source = {}
        for p in monkey_points:
            by_source.setdefault(p["source"], []).append(p)
        return [{"name": source,
                 "placemarks": [{"lat": p["lat"], "lon": p["lon"],
                                 "name": p.get("name") or "", "description": "",
                                 "timestamp": p.get("timestamp")} for p in pts]}
                for source, pts in by_source.items()]

    orig_open, orig_geo = r._case_index_open_readonly, r._collect_case_geolocation
    r._case_index_open_readonly, r._collect_case_geolocation = fake_open, fake_geoloc
    try:
        return r._collect_case_geo_activity("/nonexistent", [])
    finally:
        r._case_index_open_readonly, r._collect_case_geolocation = orig_open, orig_geo


def _mk(source, n, lat=37.0):
    return [{"lat": lat + i * 1e-6, "lon": -122.0, "timestamp": 1_700_000_000 + i,
             "name": f"{source}-{i}", "source": source} for i in range(n)]


def test_a_small_source_is_never_wiped_out_by_a_large_one():
    """The original report, at the real cap: a long Takeout history plus a
    small photo KML. Before the fix the small source kept zero points."""
    cap = reporting.GEO_ACTIVITY_MAX_POINTS
    points, _frequent, truncated, detail = _allocate(_mk("big", cap + 200) + _mk("small", 30, lat=40.0))
    assert truncated
    kept = {}
    for p in points:
        kept[p["source"]] = kept.get(p["source"], 0) + 1
    assert kept.get("small") == 30, "the small source must survive intact"
    assert kept.get("big") == cap - 30
    assert len(points) == cap


def test_truncation_detail_names_only_the_reduced_source():
    cap = reporting.GEO_ACTIVITY_MAX_POINTS
    _points, _frequent, _truncated, detail = _allocate(_mk("big", cap + 200) + _mk("small", 30, lat=40.0))
    assert [d["source"] for d in detail] == ["big"]
    assert detail[0]["kept"] == cap - 30
    assert detail[0]["available"] == cap + 200


def test_two_large_sources_split_the_budget_evenly():
    cap = reporting.GEO_ACTIVITY_MAX_POINTS
    points, _frequent, truncated, detail = _allocate(
        _mk("a", cap) + _mk("b", cap, lat=40.0))
    kept = {}
    for p in points:
        kept[p["source"]] = kept.get(p["source"], 0) + 1
    assert truncated
    assert kept["a"] == kept["b"] == cap // 2
    assert {d["source"] for d in detail} == {"a", "b"}


def test_a_case_under_the_cap_is_untouched():
    points, _frequent, truncated, detail = _allocate(_mk("a", 10) + _mk("b", 5, lat=40.0))
    assert not truncated
    assert detail == []
    assert len(points) == 15


def test_a_reduced_source_keeps_its_most_recent_points():
    """Before the fix the surviving rows were whatever order the list happened
    to be in - not "the most recent", despite that being what the note implies."""
    cap = reporting.GEO_ACTIVITY_MAX_POINTS
    big = _mk("big", cap + 100)
    points, _frequent, _truncated, _detail = _allocate(big + _mk("small", 10, lat=40.0))
    big_kept = [p for p in points if p["source"] == "big"]
    oldest_kept = min(p["timestamp"] for p in big_kept)
    newest_dropped_candidates = [p["timestamp"] for p in big if p["timestamp"] < oldest_kept]
    assert newest_dropped_candidates, "expected some points to be dropped"
    assert max(newest_dropped_candidates) < oldest_kept
