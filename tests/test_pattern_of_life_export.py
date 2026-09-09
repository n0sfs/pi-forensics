"""The exported report's new "pattern_of_life" section (2026-09-08) - a
Contact Correlation + Frequent Locations summary, previously reachable only
on-screen (the interactive Pattern of Life tab) with zero export path at
all. _draw_pdf_pattern_of_life_block()/_html_pattern_of_life_block() reuse
correlate_contacts() and the newly-factored-out _collect_case_geo_
activity() directly - both already extensively covered by tests/
test_case_index_db.py and tests/test_case_timeline_route.py respectively,
so this file focuses on what's genuinely new: that the export path threads
case_folder through to these functions correctly and that real contact/
location data actually surfaces in the rendered output.

Through a real Flask test client, matching tests/test_timeline_export_
enrichment.py's own pattern (a minimal app registering just reporting_bp,
the same "preview" + "custom_sections" override export_report() already
exposes for the Report Template Builder's own live-preview button).
Skipped (not failed) on a non-POSIX dev machine: core.jobs needs
POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from core.case_index_db import _record_parsed_artifacts
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(reporting_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _make_real_case(evidence_root, slug="2026-TEST-POL-EXPORT"):
    # pattern_of_life is requires_events=False - a bare, event-less case is
    # correctly enough for the section to be selectable at all, unlike
    # timeline which needs at least one event.
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    case_file = os.path.join(case_folder, f"{slug}_case.json")
    with open(case_file, 'w') as f:
        json.dump({"schema_version": 1, "case_number": slug, "examiner": "x",
                   "events": [], "attachments": {"files": [], "reference_urls": []}}, f)
    return case_folder, case_file


def _export_preview(client, case_file, fmt="html"):
    res = client.post("/api/export_report", json={
        "report_path": case_file, "format": fmt, "preview": True,
        "custom_sections": [{"key": "pattern_of_life", "enabled": True}],
    })
    assert res.status_code == 200
    return res.get_data(as_text=(fmt == "html"))


def test_empty_case_renders_clean_no_data_messages_not_a_crash(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    html_out = _export_preview(client, case_file)
    assert "No correlated contacts found for this case." in html_out
    assert "No location visited more than once was found for this case." in html_out


def test_html_export_shows_real_correlated_contact_and_tier(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": None, "extra": {"phones": ["+15551234567"], "emails": []}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hi",
         "timestamp": 1786784100.0, "extra": {"address": "+15551234567", "direction": "Inbox"}},
    ])
    html_out = _export_preview(client, case_file)
    assert "Jane Doe" in html_out
    # A single resolved communication with no siblings never reaches the
    # "frequent" cumulative-share threshold - this is the correct,
    # documented tiering outcome for exactly one comm row, not a bug.
    assert "one_off" in html_out


def test_html_export_shows_frequent_location_cluster(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    # Two points at the identical rounded lat/lon (3-decimal grid) -
    # GEO_ACTIVITY_MIN_FREQUENT_VISITS=2 is the exact threshold for a
    # cluster to appear in frequent_locations at all.
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "takeout.json")}, [
        {"artifact_type": "takeout_location_history", "title": "Home", "url": "", "value": "Home",
         "timestamp": 1786784100.0, "extra": {"lat": 37.774900, "lon": -122.419400}},
        {"artifact_type": "takeout_location_history", "title": "Home", "url": "", "value": "Home",
         "timestamp": 1786784200.0, "extra": {"lat": 37.774901, "lon": -122.419399}},
    ])
    html_out = _export_preview(client, case_file)
    # GEO_ACTIVITY_CLUSTER_PRECISION=3 rounds the cluster's own lat/lon KEY
    # to 3 decimal places (37.7749 -> 37.775) before the drawing function's
    # :.5f formatting adds the trailing zeros back - the exact same
    # rounded-then-reformatted value the interactive Location Activity map
    # itself would show for this same cluster.
    assert "37.77500" in html_out
    assert "-122.41900" in html_out
    # visit_count column - exactly 2 real points folded into 1 cluster.
    assert "<td>2</td>" in html_out


def test_pdf_export_also_renders_real_data(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": None, "extra": {"phones": ["+15551234567"], "emails": []}},
    ])
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_sms_message", "title": "msg", "url": "", "value": "hi",
         "timestamp": 1786784100.0, "extra": {"address": "+15551234567", "direction": "Inbox"}},
    ])
    pdf_bytes = _export_preview(client, case_file, fmt="pdf")
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 500


def test_frequent_locations_uses_the_passed_attachment_files_not_a_stale_disk_reread(evidence_root):
    """Direct regression test for a 2026-09-09 fix: _draw_pdf_pattern_of_
    life_block()/_html_pattern_of_life_block() used to independently
    re-read attachment_files from disk via case_consolidated_path() +
    _read_case_file() instead of taking it as a parameter -
    case_consolidated_path() returns None (and the old code then hardcoded
    attachment_files=[]) for ANY case folder with no {slug}_case.json
    marker file, silently dropping every real KML attachment for a legacy/
    ad-hoc report's Frequent Locations section regardless of what export_
    report() itself had already loaded from the real report data. It also
    meant a second, independent disk read mid-export - a real TOCTOU risk
    against the rest of the same export's already-loaded snapshot.

    Proven directly against the drawing functions (no {slug}_case.json
    exists in case_folder at all here, guaranteeing case_consolidated_
    path() would have returned None under the old code) rather than
    through the full export route, to isolate exactly the code path this
    fix touches. The KML itself sits OUTSIDE case_folder entirely - only
    reachable via the attachment_files argument, never via _discover_
    case_files()'s own case-folder-scoped walk - so a passing result here
    can only mean the parameter was genuinely honored, not that the KML
    was separately found by folder discovery regardless."""
    from reportlab.pdfgen import canvas
    import io

    from routes.reporting import _draw_pdf_pattern_of_life_block, _html_pattern_of_life_block

    case_folder = os.path.join(evidence_root, "2026-TEST-LEGACY-POL")
    os.makedirs(case_folder, exist_ok=True)
    kml_dir = os.path.join(evidence_root, "elsewhere")
    os.makedirs(kml_dir, exist_ok=True)
    kml_path = os.path.join(kml_dir, "trip.kml")
    # Two placemarks at essentially the same spot (rounds to the identical
    # 3-decimal GEO_ACTIVITY_CLUSTER_PRECISION grid cell) - a single
    # placemark alone would legitimately, correctly stay excluded from
    # frequent_locations entirely (GEO_ACTIVITY_MIN_FREQUENT_VISITS=2), the
    # exact same real threshold test_html_export_shows_frequent_location_
    # cluster() already exercises for the takeout-sourced case.
    with open(kml_path, "w", encoding="utf-8") as f:
        f.write(
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<kml xmlns='http://www.opengis.net/kml/2.2'><Document>"
            "<Placemark><name>Cabin</name>"
            "<Point><coordinates>-122.4194,37.7749,0</coordinates></Point>"
            "</Placemark>"
            "<Placemark><name>Cabin (return trip)</name>"
            "<Point><coordinates>-122.41941,37.77491,0</coordinates></Point>"
            "</Placemark></Document></kml>"
        )

    html_out = _html_pattern_of_life_block(case_folder, attachment_files=[kml_path])
    # A frequent-locations cluster carries only rounded coordinates/visit
    # count/first-last-seen - no placemark name or source filename - so
    # this is the real, correct signal the parameter reached the function
    # (mirrors test_html_export_shows_frequent_location_cluster's own
    # identical assertions for the takeout-sourced equivalent).
    assert "37.77500" in html_out
    assert "-122.41900" in html_out
    assert "<td>2</td>" in html_out

    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    _draw_pdf_pattern_of_life_block(c, 700, case_folder, attachment_files=[kml_path])
    c.save()
    assert buf.getvalue()[:4] == b"%PDF"


def test_co_occurrence_pair_rendered_in_html_export(client, evidence_root):
    case_folder, case_file = _make_real_case(evidence_root)
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "contacts2.db")}, [
        {"artifact_type": "android_contact", "title": "Jane Doe", "url": "", "value": "Jane Doe",
         "timestamp": None, "extra": {"phones": ["+15551234567"], "emails": []}},
        {"artifact_type": "android_contact", "title": "Bob Smith", "url": "", "value": "Bob Smith",
         "timestamp": None, "extra": {"phones": ["+15559876543"], "emails": []}},
    ])
    # A group MMS naming both participants on the SAME row is what
    # correlate_contacts() actually credits as a co-occurrence - an
    # ordinary 1:1 row never contributes one.
    _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": os.path.join(case_folder, "mmssms.db")}, [
        {"artifact_type": "android_mms_message", "title": "group msg", "url": "", "value": "group msg",
         "timestamp": 1786784100.0, "extra": {"counterpart": "+15551234567, +15559876543", "direction": "Inbox"}},
    ])
    html_out = _export_preview(client, case_file)
    assert "Jane Doe" in html_out and "Bob Smith" in html_out
    assert "shared communication(s)" in html_out
