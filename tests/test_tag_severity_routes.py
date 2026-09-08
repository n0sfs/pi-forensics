"""Tag severity/priority field (2026-09-09) - the route-level half of the
feature: case_index_create_tag()/case_index_update_tag()'s severity
validation (falls back to 'none' for anything outside ALLOWED_TAG_
SEVERITIES, mirroring how `color`/`notable` are already handled - never a
400, just a silent, safe default), case_index_tag_item()'s inline-create-new-
tag path (`new_tag_severity`), and case_index_summary()'s tags list carrying
severity through end to end. The schema/migration/_tags_for_paths() half is
covered directly in tests/test_case_index_db.py.

Through a real Flask test client, mirroring tests/test_reporting_stats.py's
own established pattern (a minimal app registering just case_index_bp).
Skipped (not failed) on a non-POSIX dev machine: routes.case_index needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.case_index needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.case_index import case_index_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(case_index_bp)
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


@pytest.fixture
def case_folder(evidence_root):
    """A real, minimal consolidated case folder - matches tests/
    test_case_index_db.py's own identical fixture (kept as a local copy
    here rather than a cross-file import, matching that file's own
    established convention of each test module owning its fixtures)."""
    import pathlib
    folder = pathlib.Path(evidence_root) / "2026-CASE-SEVERITY-TEST"
    folder.mkdir()
    (folder / "2026-CASE-SEVERITY-TEST_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-SEVERITY-TEST", "events": [],
    }))
    return str(folder)


def test_create_tag_with_valid_severity_persists_it(client, case_folder):
    res = client.post('/api/case_index/tags/create', json={
        "case_folder": case_folder, "name": "Confirmed Malware", "color": "danger",
        "notable": True, "severity": "critical",
    })
    data = res.get_json()
    assert data["success"] is True
    assert data["tag"]["severity"] == "critical"

    # And it comes back the same way through the summary route every
    # File-Views/Manage-Tags/Tag-modal surface actually reads from.
    summary = client.post('/api/case_index/summary', json={"case_folder": case_folder}).get_json()
    tag = next(t for t in summary["tags"] if t["name"] == "Confirmed Malware")
    assert tag["severity"] == "critical"


def test_create_tag_with_invalid_severity_falls_back_to_none(client, case_folder):
    """Mirrors this route's own existing color/notable handling exactly -
    an out-of-range value is silently normalized, never a 400 error."""
    res = client.post('/api/case_index/tags/create', json={
        "case_folder": case_folder, "name": "Whatever Tag", "severity": "apocalyptic",
    })
    data = res.get_json()
    assert data["success"] is True
    assert data["tag"]["severity"] == "none"


def test_create_tag_with_no_severity_field_defaults_to_none(client, case_folder):
    res = client.post('/api/case_index/tags/create', json={"case_folder": case_folder, "name": "Plain Tag"})
    data = res.get_json()
    assert data["success"] is True
    assert data["tag"]["severity"] == "none"


def test_update_tag_changes_severity(client, case_folder):
    created = client.post('/api/case_index/tags/create', json={
        "case_folder": case_folder, "name": "Rename Me", "severity": "low",
    }).get_json()
    tag_id = created["tag"]["id"]

    res = client.post('/api/case_index/tags/update', json={
        "case_folder": case_folder, "tag_id": tag_id, "name": "Rename Me",
        "color": "secondary", "notable": False, "severity": "high",
    })
    assert res.get_json()["success"] is True

    summary = client.post('/api/case_index/summary', json={"case_folder": case_folder}).get_json()
    tag = next(t for t in summary["tags"] if t["id"] == tag_id)
    assert tag["severity"] == "high"


def test_default_seeded_tags_have_none_severity_through_the_route(client, case_folder):
    """A fresh case's 8 always-seeded default tags (Bookmark/Notable
    Item/etc.) never get an asserted severity out of the box - confirmed
    through the real summary route, not just the schema directly."""
    summary = client.post('/api/case_index/summary', json={"case_folder": case_folder}).get_json()
    assert len(summary["tags"]) == 8
    assert all(t["severity"] == "none" for t in summary["tags"])


def test_tag_item_inline_create_new_tag_with_severity(client, case_folder, tmp_path_factory):
    """The File Explorer 'Tag...' modal's own quick-create-and-apply path
    (new_tag_name/new_tag_color/new_tag_notable/new_tag_severity) - a
    genuinely separate code path from Manage Tags' own create route, and the
    one an examiner is most likely to actually use in the moment."""
    target_file = os.path.join(case_folder, "evidence.jpg")
    with open(target_file, "w") as f:
        f.write("fake jpeg bytes")

    res = client.post('/api/case_index/tag_item', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "evidence.jpg",
        "new_tag_name": "Contraband", "new_tag_color": "danger",
        "new_tag_notable": True, "new_tag_severity": "critical", "comment": "flagged during triage",
    })
    data = res.get_json()
    assert data["success"] is True
    assert data["tag"]["severity"] == "critical"
    assert data["tag"]["name"] == "Contraband"

    # And the applied tag's own per-item lookup (case_index_item_tags, what
    # the Tag modal re-queries to show "already applied" state) carries the
    # same severity through too - a real, separate code path from tag_item
    # itself, not assumed correct just because the create half worked.
    item_tags = client.post('/api/case_index/item_tags', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "evidence.jpg",
    }).get_json()
    assert item_tags["success"] is True
    applied = next(t for t in item_tags["tags"] if t["name"] == "Contraband")
    assert applied["severity"] == "critical"


def test_tag_item_with_existing_tag_id_returns_its_real_severity(client, case_folder):
    """Applying an ALREADY-EXISTING tag (tag_id, not new_tag_name) still
    correctly reports that tag's own real severity in the response - the
    tag_id branch reads a different SELECT than the new-tag branch, and both
    need to agree."""
    created = client.post('/api/case_index/tags/create', json={
        "case_folder": case_folder, "name": "Pre-Existing Tag", "severity": "medium",
    }).get_json()
    tag_id = created["tag"]["id"]

    target_file = os.path.join(case_folder, "other_evidence.txt")
    with open(target_file, "w") as f:
        f.write("x")

    res = client.post('/api/case_index/tag_item', json={
        "case_folder": case_folder, "source_type": "real_fs", "path": target_file, "name": "other_evidence.txt",
        "tag_id": tag_id,
    })
    data = res.get_json()
    assert data["success"] is True
    assert data["tag"]["severity"] == "medium"
