"""set_file_caption() (routes/reporting.py, 2026-09-09) - the last of the
investigation-workflow backlog's own items: an exhibit's caption used to
live only in Reporting's own staged "Save Report Changes" flow, a real
data-loss trap for anything typed via File Explorer's Tag/Attach modal
(which has no Save button at all). This route commits a caption straight
to the case JSON on disk, immediately, mirroring attach_file_to_case()'s
own already-established immediacy exactly.

Through a real Flask test client, matching tests/test_custody_log_
linking.py's own pattern (a minimal app registering just reporting_bp).
Skipped (not failed) on a non-POSIX dev machine: core.jobs needs
POSIX-only pwd/fcntl.
"""
import json
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.reporting import reporting_bp
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


def _save_group(group_id, file_explorer, reporting):
    cfg = config.load_runtime_config()
    cfg.setdefault("user_groups", []).append({
        "id": group_id, "name": group_id,
        "permissions": {
            "acquisition": False, "mobile": False, "recovery": False,
            "file_explorer": file_explorer, "reporting": reporting,
            "settings": False, "manage_users": False,
        },
    })
    config.save_runtime_config(cfg)


def _save_user(username, password, group_id):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": username, "password_hash": generate_password_hash(password), "group_id": group_id,
    })
    config.save_runtime_config(cfg)


def _make_real_case(evidence_root, slug="2026-CASE-CAPTION-TEST", attached_files=None, file_captions=None):
    case_folder = os.path.join(evidence_root, slug)
    os.makedirs(case_folder, exist_ok=True)
    report_path = os.path.join(case_folder, f"{slug}_case.json")
    with open(report_path, 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": slug, "case_folder": case_folder,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
            "events": [], "custody_log": [],
            "attachments": {
                "files": attached_files or [], "reference_urls": [],
                "file_captions": file_captions or {},
            },
        }, f)
    return case_folder, report_path


def test_set_file_caption_on_an_attached_exhibit(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, report_path = _make_real_case(evidence_root, attached_files=[exhibit_path])

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": exhibit_path, "caption": "Suspect's primary laptop drive",
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["caption"] == "Suspect's primary laptop drive"
    assert "updated_at" in body

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["attachments"]["file_captions"][exhibit_path] == "Suspect's primary laptop drive"
    assert on_disk["updated_at"] == body["updated_at"]


def test_set_file_caption_updates_an_already_captioned_exhibit(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, report_path = _make_real_case(
        evidence_root, attached_files=[exhibit_path],
        file_captions={exhibit_path: "old caption"},
    )

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": exhibit_path, "caption": "new caption",
    })
    assert res.status_code == 200
    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["attachments"]["file_captions"][exhibit_path] == "new caption"


def test_set_file_caption_with_empty_string_clears_an_existing_caption(client, evidence_root):
    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, report_path = _make_real_case(
        evidence_root, attached_files=[exhibit_path],
        file_captions={exhibit_path: "will be cleared"},
    )

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": exhibit_path, "caption": "",
    })
    assert res.status_code == 200
    assert res.get_json()["caption"] == ""

    with open(report_path) as f:
        on_disk = json.load(f)
    # Cleared entirely, not left present with an empty-string value - a
    # clean state, not a phantom entry a future export would still see.
    assert exhibit_path not in on_disk["attachments"]["file_captions"]


def test_set_file_caption_rejects_a_path_that_is_not_an_attached_exhibit(client, evidence_root):
    case_folder, report_path = _make_real_case(evidence_root, attached_files=["/mnt/fake_evidence/other.jpg"])

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": "/mnt/fake_evidence/never_attached.jpg", "caption": "nope",
    })
    assert res.status_code == 400
    assert "isn't an attached exhibit" in res.get_json()["error"]

    with open(report_path) as f:
        on_disk = json.load(f)
    assert on_disk["attachments"]["file_captions"] == {}


def test_set_file_caption_rejects_a_non_consolidated_legacy_case(client, evidence_root):
    case_folder = os.path.join(evidence_root, "2026-CASE-LEGACY-CAPTION")
    os.makedirs(case_folder, exist_ok=True)
    # No {slug}_case.json marker at all - case_consolidated_path() returns
    # None for this, matching attach_file_to_case()'s own identical check.
    with open(os.path.join(case_folder, "case_info.json"), "w") as f:
        json.dump({"case_number": "2026-CASE-LEGACY-CAPTION"}, f)

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": "/mnt/fake_evidence/anything.jpg", "caption": "x",
    })
    assert res.status_code == 400
    assert "hasn't been migrated" in res.get_json()["error"]


def test_set_file_caption_rejects_a_missing_case_folder(client, evidence_root):
    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": os.path.join(evidence_root, "does-not-exist"),
        "file_path": "/mnt/fake_evidence/anything.jpg", "caption": "x",
    })
    assert res.status_code == 400


def test_set_file_caption_rejects_a_user_with_neither_reporting_nor_file_explorer_permission(app, runtime_config_file, evidence_root):
    _save_group("no_access", file_explorer=False, reporting=False)
    _save_user("limited", "pw", "no_access")
    client = RemoteTestClient(app.test_client())
    login_user_session(client._raw, "limited")

    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, _ = _make_real_case(evidence_root, attached_files=[exhibit_path])

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": exhibit_path, "caption": "x",
    })
    assert res.status_code == 403


def test_set_file_caption_allowed_with_file_explorer_permission_alone(app, runtime_config_file, evidence_root):
    """The Tag/Attach modal is a File Explorer surface with no Reporting
    permission of its own to lean on - confirms the OR-gate actually lets
    a file_explorer-only account use it, matching attach_file_to_case()'s
    own identical dual-permission precedent."""
    _save_group("fe_only", file_explorer=True, reporting=False)
    _save_user("fe_user", "pw", "fe_only")
    client = RemoteTestClient(app.test_client())
    login_user_session(client._raw, "fe_user")

    exhibit_path = "/mnt/fake_evidence/drive_image.dd"
    case_folder, _ = _make_real_case(evidence_root, attached_files=[exhibit_path])

    res = client.post("/api/cases/set_file_caption", json={
        "case_folder": case_folder, "file_path": exhibit_path, "caption": "x",
    })
    assert res.status_code == 200
    assert res.get_json()["success"] is True
