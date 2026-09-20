"""The exported Geolocation section's coordinate-table cap (2026-09-20).

Measured on the station before this existed: a real phone case's CASE/UCO
export rendered 2,826 placemark rows, and that one section was 1,875 KB of a
2,098 KB HTML file - 89% of the document - while the PDF ran to 53 pages,
overwhelmingly raw coordinates. Nothing capped or disclosed it, which was out
of step with every other large section here (the timeline caps and returns
truncation_reasons; the interactive geo endpoint caps at GEO_ACTIVITY_MAX_POINTS
under the comment "cap, never silently truncate without disclosure").

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import re

import pytest

reporting = pytest.importorskip(
    "routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")


def _kml_entry(n, name="track.kml"):
    return [{
        "name": name,
        "path": "/evidence/%s" % name,
        "placemarks": [
            {"name": "pt%d" % i, "lat": 40.0 + i / 10000.0, "lon": -73.0 - i / 10000.0,
             "description": "sample %d" % i}
            for i in range(n)
        ],
    }]


def _rows(html_text):
    # minus one for the header row
    return len(re.findall(r"<tr>", html_text)) - 1


def test_small_sets_are_not_truncated():
    """A case with an ordinary number of points must be completely unchanged -
    the cap exists for the pathological case, not the normal one."""
    out = reporting._html_geolocation_block(_kml_entry(25))
    assert _rows(out) == 25
    assert "Showing the first" not in out


def test_large_sets_are_capped_in_html():
    n = reporting.REPORT_GEO_MAX_TABLE_ROWS + 400
    out = reporting._html_geolocation_block(_kml_entry(n))
    assert _rows(out) == reporting.REPORT_GEO_MAX_TABLE_ROWS


def test_truncation_is_disclosed_with_real_numbers():
    """Silently dropping coordinates from a forensic report would be the worst
    possible outcome - worse than an unreadable report. The notice has to name
    both counts and say where the full set lives."""
    n = reporting.REPORT_GEO_MAX_TABLE_ROWS + 1
    out = reporting._html_geolocation_block(_kml_entry(n, name="pixel_track.kml"))
    assert "Showing the first" in out
    assert "%s" % format(n, ",") in out, "the true total must appear"
    assert "pixel_track.kml" in out, "must point at the KML holding every point"


def test_the_map_still_receives_every_point():
    """Only the table is capped. The map is the representation that actually
    conveys a movement pattern, and each point costs ~100 bytes of JSON there
    versus ~600 bytes of markup as a table row."""
    n = reporting.REPORT_GEO_MAX_TABLE_ROWS + 300
    out = reporting._html_geolocation_block(_kml_entry(n))
    # The inline script gets the placemarks as a JSON literal; every point's
    # latitude should still be present in it even though the table is capped.
    assert out.count('"lat"') >= n, "the map payload must not be capped"


def test_both_renderers_share_one_wording():
    """A PDF and an HTML export of the same case disclosing truncation
    differently is exactly the kind of drift this codebase keeps getting bitten
    by - so both call the same helper."""
    note = reporting._geo_table_truncation_note(2826, 500, "track.kml")
    assert "2,826" in note and "500" in note and "track.kml" in note


def test_cap_is_large_enough_to_be_useful():
    """Guards against someone 'tidying' this down to a token 50 - the cap is
    meant to stop a 53-page coordinate dump, not to hide the data."""
    assert reporting.REPORT_GEO_MAX_TABLE_ROWS >= 250


def test_map_unavailable_notice_stays_honest_when_the_table_is_also_capped():
    """The nastiest case: Leaflet failed to inline AND the table is truncated,
    so the reader can see neither the full track nor the full list. The
    pre-existing message claimed unconditionally that the table "lists every
    point in full" - capping the table turned that into a false statement in
    precisely the situation where the reader has nothing else to go on."""
    truncated = reporting._geo_map_unavailable_note(2826, 500, "track.kml")
    assert "every point in full" not in truncated
    assert "500" in truncated and "2,826" in truncated
    assert "track.kml" in truncated

    # ...and when nothing was dropped, the original reassurance is still correct.
    complete = reporting._geo_map_unavailable_note(120, 120, "track.kml")
    assert "every point in full" in complete


def test_map_unavailable_notice_is_embedded_as_a_json_literal():
    """It reaches the browser inside an inline <script>, so it goes through
    json.dumps rather than raw interpolation - a KML filename is untrusted
    content and could otherwise carry a quote that breaks the script."""
    out = reporting._html_geolocation_block(
        _kml_entry(reporting.REPORT_GEO_MAX_TABLE_ROWS + 1, name='we"ird.kml'))
    assert '\\"' in out or 'we\\"ird' in out or "we&quot;ird" in out
    # the script block must still be syntactically intact
    assert out.count("<script>") == out.count("</script>")
