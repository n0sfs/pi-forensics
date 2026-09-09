"""routes/case_management.py's /api/cases/set_status - the Case Manager
list's new Archive/Re-open button (2026-09-09), a fast single-field write
straight to a case's own marker file, instead of the full report load/save
round trip saveReportMetadata() otherwise requires.

Mirrors tests/test_case_management_permissions.py's exact fixture/helper
pattern (same broad acquisition/mobile/recovery/reporting OR create_case()
already uses, since a status flip is the same kind of "prerequisite for
using this case elsewhere" lifecycle action, not a reporting-specific one).

Skipped (not failed) on a non-POSIX dev machine: routes/case_management.py
needs core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import json
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.case_management needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.case_management import case_management_bp
from tests.conftest import RemoteTestClient


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(case_management_bp)
    return flask_app


@pytest.fixture
def client(app):
    return RemoteTestClient(app.test_client())


def _save_group(group_id, **perms):
    cfg = config.load_runtime_config()
    base = {"acquisition": False, "mobile": False, "recovery": False,
            "file_explorer": False, "reporting": False, "settings": False, "manage_users": False}
    base.update(perms)
    cfg.setdefault("user_groups", []).append({"id": group_id, "name": group_id, "permissions": base})
    config.save_runtime_config(cfg)


def _save_user(username, password, group_id):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": group_id,
    })
    config.save_runtime_config(cfg)


def _login(client, username):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["last_activity"] = time.time()


def _login_as_operational_user(client, evidence_root, tag):
    """One quick, reusable "any real operational account" login - the
    exact permission-gating behavior itself is covered by its own
    dedicated tests below, so every other test just needs SOME account
    that's allowed through."""
    _save_group(f"ops_{tag}", reporting=True)
    _save_user(f"user_{tag}", "pw", f"ops_{tag}")
    _login(client, f"user_{tag}")


def _make_consolidated_case(evidence_root, slug="2026-CASE-STATUS-TEST"):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir)
    with open(os.path.join(case_dir, f"{slug}_case.json"), "w") as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_dir,
            "case_status": "Open", "created_at": "2026-09-01 00:00:00",
            "updated_at": "2026-09-01 00:00:00", "events": [],
        }, f)
    return case_dir


def _make_legacy_case(evidence_root, slug="2026-LEGACY-STATUS-TEST"):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir)
    with open(os.path.join(case_dir, "case_info.json"), "w") as f:
        json.dump({"case_number": slug, "case_status": "Open"}, f)
    return case_dir


# --- Permission gating (mirrors test_case_management_permissions.py's own
# create_case() coverage exactly, applied to this new route) ---

def test_set_status_rejects_a_user_with_none_of_the_four_permissions(client, runtime_config_file, evidence_root):
    case_dir = _make_consolidated_case(evidence_root)
    _save_group("no_access", **{})
    _save_user("limited", "pw", "no_access")
    _login(client, "limited")
    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    assert res.status_code == 403


@pytest.mark.parametrize("perm", ["acquisition", "mobile", "recovery", "reporting"])
def test_set_status_allowed_with_any_one_of_the_four_permissions(client, runtime_config_file, evidence_root, perm):
    case_dir = _make_consolidated_case(evidence_root, f"2026-CASE-PERM-{perm.upper()}")
    _save_group(f"has_{perm}", **{perm: True})
    _save_user(f"user_{perm}", "pw", f"has_{perm}")
    _login(client, f"user_{perm}")
    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    assert res.status_code == 200
    assert res.get_json()["success"] is True


# --- Real functional behavior ---

def test_set_status_archives_a_consolidated_case_and_persists_it(client, runtime_config_file, evidence_root):
    case_dir = _make_consolidated_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "archive")

    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    assert data["case_status"] == "Archived"

    # Real, independent proof - re-read the actual file on disk, not just
    # trust the response.
    with open(os.path.join(case_dir, "2026-CASE-STATUS-TEST_case.json")) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Archived"
    assert on_disk["updated_at"] != "2026-09-01 00:00:00"  # refreshed, not left stale


def test_set_status_re_opens_an_archived_case(client, runtime_config_file, evidence_root):
    case_dir = _make_consolidated_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "reopen")

    client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Open"})
    assert res.get_json()["success"] is True

    with open(os.path.join(case_dir, "2026-CASE-STATUS-TEST_case.json")) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Open"


def test_set_status_records_status_before_archive_and_restores_it_on_reopen(client, runtime_config_file, evidence_root):
    """The actual case/2026-09-09 fix: a case archived from a non-"Open"
    status ("In Review" here) records that value, and re-opening to
    exactly that value (mirroring what the Case Manager's own Re-open
    button now sends - c.status_before_archive || 'Open') both restores
    the real prior status AND clears the now-served-its-purpose field
    from the case record, so a later archive cycle captures a fresh
    snapshot rather than reusing this one."""
    case_dir = _make_consolidated_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "restore")
    case_file = os.path.join(case_dir, "2026-CASE-STATUS-TEST_case.json")

    # Start from "In Review", not the fixture's default "Open" - the whole
    # point of this test is proving something OTHER than "Open" survives.
    client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "In Review"})

    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    assert res.get_json()["success"] is True
    with open(case_file) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Archived"
    assert on_disk["status_before_archive"] == "In Review"

    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "In Review"})
    assert res.get_json()["success"] is True
    with open(case_file) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "In Review"
    assert "status_before_archive" not in on_disk  # cleared, not left stale


def test_set_status_re_archiving_an_already_archived_case_never_clobbers_the_recorded_prior_status(client, runtime_config_file, evidence_root):
    """A re-archive of an already-Archived case (e.g. a double-click, or
    two examiners both hitting Archive) must not overwrite the real
    remembered prior status with "Archived" itself - that would make a
    later Re-open restore "Archived" (a no-op status, functionally
    identical to the original bug this whole fix closes)."""
    case_dir = _make_consolidated_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "idempotent")
    case_file = os.path.join(case_dir, "2026-CASE-STATUS-TEST_case.json")

    client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Closed"})
    client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    # Re-archive while already Archived.
    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    assert res.get_json()["success"] is True

    with open(case_file) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Archived"
    assert on_disk["status_before_archive"] == "Closed"  # still the real original value


def test_set_status_works_against_a_legacy_case_marker_too(client, runtime_config_file, evidence_root):
    """Confirms the route targets case_info.json (not just {slug}_case.json)
    for a not-yet-migrated case, matching list_case_folders()'s own
    identical top-level-key read for both schemas."""
    case_dir = _make_legacy_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "legacy")

    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Archived"})
    assert res.get_json()["success"] is True

    with open(os.path.join(case_dir, "case_info.json")) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Archived"


def test_set_status_rejects_an_invalid_status_value(client, runtime_config_file, evidence_root):
    case_dir = _make_consolidated_case(evidence_root)
    _login_as_operational_user(client, evidence_root, "invalid")

    res = client.post("/api/cases/set_status", json={"case_folder": case_dir, "status": "Deleted Forever"})
    assert res.status_code == 400
    assert res.get_json()["success"] is False

    # And confirms it never touched the file at all.
    with open(os.path.join(case_dir, "2026-CASE-STATUS-TEST_case.json")) as f:
        on_disk = json.load(f)
    assert on_disk["case_status"] == "Open"


def test_set_status_rejects_a_nonexistent_case_folder(client, runtime_config_file, evidence_root):
    _login_as_operational_user(client, evidence_root, "missing")
    res = client.post("/api/cases/set_status", json={
        "case_folder": os.path.join(evidence_root, "does-not-exist"), "status": "Archived",
    })
    assert res.status_code == 400


def test_set_status_rejects_a_folder_with_no_case_marker_at_all(client, runtime_config_file, evidence_root):
    plain_dir = os.path.join(evidence_root, "just-a-folder")
    os.makedirs(plain_dir)
    _login_as_operational_user(client, evidence_root, "nomarker")
    res = client.post("/api/cases/set_status", json={"case_folder": plain_dir, "status": "Archived"})
    assert res.status_code == 400
    assert "marker" in res.get_json()["error"].lower()
