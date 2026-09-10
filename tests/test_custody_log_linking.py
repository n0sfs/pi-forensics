"""Link Physical Custody Log entries to exhibits (2026-09-09, item 8 of the
investigation-workflow backlog) - a custody-transfer entry (from/to/reason/
method) previously had no way to say WHICH exhibit changed hands. Mirrors
add_case_note()'s own already-established linked_files precedent exactly:
only an already-attached exhibit or an already-tagged real-fs item is
accepted, anything else silently dropped rather than failing the save over
a stale reference.

Through a real Flask test client, matching tests/test_report_save_updated_
at.py's own pattern (a minimal app registering just reporting_bp). Skipped
(not failed) on a non-POSIX dev machine: core.jobs needs POSIX-only pwd/
fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
from core.case_index_db import case_index_db_path, _case_index_connect
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


def _make_real_case(evidence_root, slug="2026-CASE-CUSTODY-LINK", attached_files=None):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, f"{slug}_case.json")
    with open(report_path, 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_folder,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "events": [], "custody_log": [],
            "attachments": {"files": attached_files or [], "reference_urls": []},
        }, f)
    return case_folder, report_path


def _tag_real_fs_path(case_folder, path, tag_name="Notable Item"):
    """Opens (creating/seeding if absent) the case's own per-case SQLite
    index and inserts one real tagged_items row against the given real-fs
    path - by default the schema's own always-seeded 'Notable Item' tag, so
    no extra tag-creation step is needed for the common case. Matches
    tagged_real_fs_paths_for_case()'s own exact read shape (source_type=
    'real_fs', a real non-null path)."""
    db_path = case_index_db_path(case_folder)
    conn = _case_index_connect(db_path)
    try:
        tag_id = conn.execute("SELECT id FROM tags WHERE name = ?", (tag_name,)).fetchone()[0]
        conn.execute(
            "INSERT INTO tagged_items (tag_id, source_type, path, name, tagged_at) "
            "VALUES (?, 'real_fs', ?, ?, datetime('now'))",
            (tag_id, path, os.path.basename(path)),
        )
        conn.commit()
    finally:
        conn.close()


def test_add_custody_entry_links_an_attached_exhibit(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/photo.jpg"
    case_folder, report_path = _make_real_case(evidence_root, attached_files=[exhibit_path])

    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "Field Examiner", "to_custodian": "Evidence Locker",
        "linked_files": [exhibit_path],
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["entry"]["linked_files"] == [exhibit_path]

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["custody_log"][0]["linked_files"] == [exhibit_path]


def test_add_custody_entry_links_a_tagged_but_unattached_item(client, evidence_root):
    """Mirrors Case Notes' own identical capability - an examiner can
    reference something already flagged Notable/Critical even before it's
    ever attached as a report exhibit."""
    tagged_path = "/mnt/fake_evidence/DCIM/IMG_0042.jpg"
    case_folder, report_path = _make_real_case(evidence_root)
    _tag_real_fs_path(case_folder, tagged_path)

    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
        "linked_files": [tagged_path],
    })
    assert res.status_code == 200
    assert res.get_json()["entry"]["linked_files"] == [tagged_path]


def test_add_custody_entry_silently_drops_an_unlinkable_path(client, evidence_root):
    """A path that's neither attached nor tagged must never fail the save
    over a stale reference - just silently excluded, matching add_case_
    note()'s own identical tolerance."""
    case_folder, report_path = _make_real_case(evidence_root)

    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
        "linked_files": ["/mnt/fake_evidence/never_attached_or_tagged.jpg"],
    })
    assert res.status_code == 200
    assert res.get_json()["entry"]["linked_files"] == []


def test_add_custody_entry_with_no_linked_files_field_is_backward_compatible(client, evidence_root):
    """The pre-existing request shape (no linked_files key at all) must
    keep working exactly as it always has."""
    case_folder, report_path = _make_real_case(evidence_root)

    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["entry"]["linked_files"] == []


def test_add_custody_entry_tolerates_a_non_list_linked_files_value(client, evidence_root):
    """A malformed/unexpected value (not a real JSON array) must degrade to
    an empty list, never a 500."""
    case_folder, report_path = _make_real_case(evidence_root)

    res = client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
        "linked_files": "not-a-list",
    })
    assert res.status_code == 200
    assert res.get_json()["entry"]["linked_files"] == []


def _export_preview(client, case_file, fmt="html"):
    res = client.post("/api/export_report", json={
        "report_path": case_file, "format": fmt, "preview": True,
        "custom_sections": [{"key": "custody_log", "enabled": True}],
    })
    assert res.status_code == 200
    return res.get_data(as_text=(fmt == "html"))


def test_html_export_shows_the_linked_exhibit_number(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, report_path = _make_real_case(evidence_root, attached_files=[exhibit_path])
    client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "Field Examiner", "to_custodian": "Evidence Locker",
        "reason": "transport to lab", "linked_files": [exhibit_path],
    })

    html_out = _export_preview(client, report_path)
    assert "Linked Exhibit(s)" in html_out
    assert "Exhibit 1 - drive_image.dd" in html_out


def test_html_export_shows_tagged_not_attached_disclosure(client, evidence_root):
    tagged_path = "/mnt/fake_evidence/DCIM/IMG_0042.jpg"
    case_folder, report_path = _make_real_case(evidence_root)
    _tag_real_fs_path(case_folder, tagged_path)
    client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
        "linked_files": [tagged_path],
    })

    html_out = _export_preview(client, report_path)
    assert "IMG_0042.jpg (tagged, not an exhibit)" in html_out


def test_html_export_with_no_linked_files_renders_a_clean_empty_cell_not_a_crash(client, evidence_root):
    case_folder, report_path = _make_real_case(evidence_root)
    client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
    })
    html_out = _export_preview(client, report_path)
    assert "Linked Exhibit(s)" in html_out


def test_pdf_export_also_renders_with_a_linked_exhibit(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, report_path = _make_real_case(evidence_root, attached_files=[exhibit_path])
    client.post("/api/cases/custody/add", json={
        "report_path": report_path, "from_custodian": "A", "to_custodian": "B",
        "linked_files": [exhibit_path],
    })
    pdf_bytes = _export_preview(client, report_path, fmt="pdf")
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 500
