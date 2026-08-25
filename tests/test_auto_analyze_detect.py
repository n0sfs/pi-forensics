"""routes/auto_analyze.py's /api/auto_analyze/detect (Phase 3, 2026-08-25) -
figures out an evidence item's profile (Windows/Linux disk image, memory
image, iOS/Android mobile backup) before Auto Analyze runs anything.

Through a real Flask test client, matching tests/test_custom_case_fields_
key_stability.py's own pattern (a minimal app registering just
auto_analyze_bp, not the full app.py). Skipped (not failed) on a
non-POSIX dev machine: core.jobs needs POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.auto_analyze needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.auto_analyze import auto_analyze_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(auto_analyze_bp)
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


def _detect(client, path, case_folder=None):
    body = {"path": path}
    if case_folder:
        body["case_folder"] = case_folder
    return client.post("/api/auto_analyze/detect", json=body)


def test_nonexistent_path_returns_a_clean_error(client, evidence_root):
    res = _detect(client, os.path.join(evidence_root, "does_not_exist"))
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_unrecognized_extension_returns_unknown_profile(client, evidence_root):
    p = os.path.join(evidence_root, "notes.txt")
    with open(p, 'w') as f:
        f.write("just a text file")
    res = _detect(client, p)
    assert res.status_code == 200
    assert res.get_json()["profile"] == "unknown"


def test_unambiguous_memory_extension_is_detected_without_opening_the_file(client, evidence_root):
    # .vmem/.dmp/.lime never need filesystem inspection at all - a
    # deliberately garbage/empty file still detects correctly by extension
    # alone, proving this path doesn't accidentally depend on the file's
    # real content.
    p = os.path.join(evidence_root, "capture.vmem")
    with open(p, 'wb') as f:
        f.write(b"not a real memory image")
    res = _detect(client, p)
    assert res.get_json()["profile"] == "memory"
    assert res.get_json()["signal"] == "extension"


def test_ambiguous_raw_extension_with_no_real_filesystem_is_flagged_ambiguous(client, evidence_root):
    p = os.path.join(evidence_root, "capture.raw")
    with open(p, 'wb') as f:
        f.write(b"\x00" * 4096)  # not a real filesystem of any kind
    res = _detect(client, p)
    data = res.get_json()
    assert data["profile"] == "ambiguous"
    assert "memory" in data["candidates"]


def test_directory_with_no_case_event_and_no_ios_markers_is_unknown_mobile(client, evidence_root):
    d = os.path.join(evidence_root, "some_pulled_folder")
    os.makedirs(os.path.join(d, "system"))  # looks like SOME kind of dump, but no reliable signal
    res = _detect(client, d)
    assert res.get_json()["profile"] == "unknown_mobile"
    assert res.get_json()["signal"] == "none"


def test_directory_with_real_ios_backup_markers_is_detected_structurally(client, evidence_root):
    udid = "a" * 40
    backup_dir = os.path.join(evidence_root, udid)
    os.makedirs(backup_dir)
    with open(os.path.join(backup_dir, "Manifest.db"), 'wb') as f:
        f.write(b"fake sqlite")
    with open(os.path.join(backup_dir, "Info.plist"), 'wb') as f:
        f.write(b"fake plist")
    res = _detect(client, backup_dir)
    assert res.get_json()["profile"] == "mobile_ios"
    assert res.get_json()["signal"] == "structural"


def test_directory_containing_an_ios_backup_subfolder_is_also_detected(client, evidence_root):
    # The parent-of-the-UDID-folder shape - an examiner selecting the
    # containing directory rather than the UDID folder itself.
    udid = "b" * 40
    parent = os.path.join(evidence_root, "mobile_acquisitions")
    backup_dir = os.path.join(parent, udid)
    os.makedirs(backup_dir)
    with open(os.path.join(backup_dir, "Manifest.db"), 'wb') as f:
        f.write(b"fake sqlite")
    with open(os.path.join(backup_dir, "Info.plist"), 'wb') as f:
        f.write(b"fake plist")
    res = _detect(client, parent)
    assert res.get_json()["profile"] == "mobile_ios"


def test_case_event_lookup_is_authoritative_over_structural_guessing(client, evidence_root, monkeypatch):
    # A directory that would otherwise structurally look like "unknown" -
    # but a real, matching case event should win outright, even for an
    # Android target where no structural signal could ever exist anyway.
    android_dir = os.path.join(evidence_root, "android_pull_output")
    os.makedirs(os.path.join(android_dir, "data"))

    case_folder = os.path.join(evidence_root, "2026-TEST-CASE")
    os.makedirs(case_folder)
    case_file = os.path.join(case_folder, "2026-test-case_case.json")
    with open(case_file, 'w') as f:
        json.dump({
            "schema_version": 1,
            "events": [{
                "acquisition_status": "COMPLETED",
                "tool": "android_pull",
                "acquisition_parameters": {"output_destination": android_dir},
            }],
        }, f)

    # routes/auto_analyze.py does a bare `from core.paths import
    # case_consolidated_path` - that creates an independent name binding
    # in ITS OWN module namespace at import time (the same class of gotcha
    # this project has already been bitten by twice before, e.g.
    # active_proc/RUNTIME_CONFIG_FILE), so the target to monkeypatch is
    # routes.auto_analyze's own bound name, not core.paths' - patching
    # core.paths.case_consolidated_path directly would silently do nothing.
    import routes.auto_analyze as auto_analyze_module
    monkeypatch.setattr(auto_analyze_module, "case_consolidated_path", lambda p: case_file if p == case_folder else None)

    res = _detect(client, android_dir, case_folder=case_folder)
    data = res.get_json()
    assert data["profile"] == "mobile_android"
    assert data["signal"] == "case_event"


def test_ios_backup_case_event_is_recognized_too(client, evidence_root, monkeypatch):
    ios_dir = os.path.join(evidence_root, "some_ios_output")
    os.makedirs(ios_dir)

    case_folder = os.path.join(evidence_root, "2026-TEST-CASE-2")
    os.makedirs(case_folder)
    case_file = os.path.join(case_folder, "2026-test-case-2_case.json")
    with open(case_file, 'w') as f:
        json.dump({
            "schema_version": 1,
            "events": [{
                "acquisition_status": "COMPLETED",
                "tool": "ios_backup",
                "acquisition_parameters": {"output_destination": ios_dir},
            }],
        }, f)

    # routes/auto_analyze.py does a bare `from core.paths import
    # case_consolidated_path` - that creates an independent name binding
    # in ITS OWN module namespace at import time (the same class of gotcha
    # this project has already been bitten by twice before, e.g.
    # active_proc/RUNTIME_CONFIG_FILE), so the target to monkeypatch is
    # routes.auto_analyze's own bound name, not core.paths' - patching
    # core.paths.case_consolidated_path directly would silently do nothing.
    import routes.auto_analyze as auto_analyze_module
    monkeypatch.setattr(auto_analyze_module, "case_consolidated_path", lambda p: case_file if p == case_folder else None)

    res = _detect(client, ios_dir, case_folder=case_folder)
    assert res.get_json()["profile"] == "mobile_ios"


def test_case_event_with_wrong_status_is_ignored(client, evidence_root, monkeypatch):
    d = os.path.join(evidence_root, "in_progress_pull")
    os.makedirs(d)

    case_folder = os.path.join(evidence_root, "2026-TEST-CASE-3")
    os.makedirs(case_folder)
    case_file = os.path.join(case_folder, "2026-test-case-3_case.json")
    with open(case_file, 'w') as f:
        json.dump({
            "schema_version": 1,
            "events": [{
                "acquisition_status": "IN_PROGRESS",  # not COMPLETED - must not match
                "tool": "android_pull",
                "acquisition_parameters": {"output_destination": d},
            }],
        }, f)

    # routes/auto_analyze.py does a bare `from core.paths import
    # case_consolidated_path` - that creates an independent name binding
    # in ITS OWN module namespace at import time (the same class of gotcha
    # this project has already been bitten by twice before, e.g.
    # active_proc/RUNTIME_CONFIG_FILE), so the target to monkeypatch is
    # routes.auto_analyze's own bound name, not core.paths' - patching
    # core.paths.case_consolidated_path directly would silently do nothing.
    import routes.auto_analyze as auto_analyze_module
    monkeypatch.setattr(auto_analyze_module, "case_consolidated_path", lambda p: case_file if p == case_folder else None)

    res = _detect(client, d, case_folder=case_folder)
    assert res.get_json()["profile"] == "unknown_mobile"
