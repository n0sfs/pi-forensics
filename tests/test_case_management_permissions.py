"""routes/case_management.py's create_case() - originally carried NO
permission check at all (just @requires_auth), a real finding from the
2026-08-22 security audit: a custom group with every permission key False
could still create case folders.

create_case() uses a broad OR (acquisition/mobile/recovery/reporting) since
it's reachable from the global Active Case Bar on every tab and is a
prerequisite for using any of them.

The migrate_case_apply()/migrate_case_preview() tests that also lived here
were removed on 2026-09-15 with the routes themselves - legacy-case support
is gone, so there is no longer a second case format to migrate from.

list_cases()/log_case_select() are deliberately left @requires_auth-only
(read-only/logging, matching this app's "reads are open, writes are gated"
convention) - not tested here since nothing changed about them.

Skipped (not failed) on a non-POSIX dev machine: routes/case_management.py
needs core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import json
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


def test_create_case_rejects_a_user_with_none_of_the_four_permissions(client, runtime_config_file, evidence_root):
    _save_group("no_access", **{})
    _save_user("limited", "pw", "no_access")
    _login(client, "limited")
    res = client.post("/api/cases/create", json={"case_number": "2026-TEST-01", "examiner": "x", "parent_dir": evidence_root})
    assert res.status_code == 403


@pytest.mark.parametrize("perm", ["acquisition", "mobile", "recovery", "reporting"])
def test_create_case_allowed_with_any_one_of_the_four_permissions(client, runtime_config_file, evidence_root, perm):
    _save_group(f"has_{perm}", **{perm: True})
    _save_user(f"user_{perm}", "pw", f"has_{perm}")
    _login(client, f"user_{perm}")
    res = client.post("/api/cases/create", json={"case_number": f"2026-TEST-{perm}", "examiner": "x", "parent_dir": evidence_root})
    assert res.status_code == 200
    assert res.get_json()["success"] is True


def test_create_case_seeds_the_examiners_list_from_the_single_typed_examiner(client, runtime_config_file, evidence_root):
    """Multiple Examiner Names per Case (item 7 of the investigation-
    workflow backlog) - a fresh case's own "examiner" field is still the
    single string typed at creation (auto-filled from the logged-in
    account, unchanged), but "examiners" (the new, editable list) must be
    seeded with that same name as its first entry, not left empty - that's
    what makes core.case_index_db.derive_examiner_display() show exactly
    the same name a brand-new case has always shown, before any additional
    examiner is ever added."""
    import os
    _save_group("has_reporting", reporting=True)
    _save_user("exam_user", "pw", "has_reporting")
    _login(client, "exam_user")
    res = client.post("/api/cases/create", json={
        "case_number": "2026-TEST-EXAM-SEED", "examiner": "Jane Doe", "parent_dir": evidence_root,
    })
    assert res.status_code == 200
    case_record = res.get_json()["case"]
    assert case_record["examiner"] == "Jane Doe"
    assert case_record["examiners"] == ["Jane Doe"]

    # Also confirmed on the actual written file, not just the response body.
    case_dir = os.path.join(evidence_root, "2026-TEST-EXAM-SEED")
    with open(os.path.join(case_dir, "2026-TEST-EXAM-SEED_case.json")) as f:
        on_disk = json.load(f)
    assert on_disk["examiners"] == ["Jane Doe"]


def test_create_case_seeds_an_empty_examiners_list_when_no_examiner_was_typed(client, runtime_config_file, evidence_root):
    """A blank examiner (whoami/currentUsername came back empty, or a
    caller other than the real UI omits it) must seed [] rather than
    [""], or derive_examiner_display() would show a bare blank string
    instead of correctly falling through to its own default."""
    _save_group("has_reporting2", reporting=True)
    _save_user("exam_user2", "pw", "has_reporting2")
    _login(client, "exam_user2")
    res = client.post("/api/cases/create", json={
        "case_number": "2026-TEST-EXAM-BLANK", "parent_dir": evidence_root,
    })
    assert res.status_code == 200
    assert res.get_json()["case"]["examiners"] == []


def test_create_case_returns_a_clean_409_on_a_genuine_directory_creation_race(client, runtime_config_file, evidence_root, monkeypatch):
    """Real bug, fixed 2026-09-09 (a 3rd Case/Reporting review pass's own
    lower-confidence findings): the os.path.exists() check and the
    os.makedirs() call are two separate steps - a concurrent request for
    the identical case number/parent location can create the directory in
    the narrow window between them. os.makedirs() itself never half-
    creates or overwrites anything if the directory already exists, so
    this was never a data-safety issue, only a UX one: the old broad
    `except Exception` classified this as a generic 500 with a raw errno
    message instead of the same clean 409 a non-racing duplicate request
    already gets from the exists() check itself.

    Simulated deterministically (not a genuine race, which single-threaded
    Flask test-client calls can't produce) by making os.makedirs() itself
    raise FileExistsError regardless of what the exists() check already
    saw - directly proves the new except branch, not just that the happy
    path still works."""
    import routes.case_management as case_management_mod

    def _raise_file_exists(path):
        raise FileExistsError(17, "File exists")

    monkeypatch.setattr(case_management_mod.os, "makedirs", _raise_file_exists)

    _save_group("race_group", reporting=True)
    _save_user("race_user", "pw", "race_group")
    _login(client, "race_user")
    res = client.post("/api/cases/create", json={"case_number": "2026-TEST-RACE", "examiner": "x", "parent_dir": evidence_root})
    assert res.status_code == 409
    assert "already exists" in res.get_json()["error"]


def test_create_case_still_returns_500_for_a_genuine_unrelated_makedirs_failure(client, runtime_config_file, evidence_root, monkeypatch):
    """The new FileExistsError-specific except must not swallow every other
    real makedirs() failure (permission denied, disk full, etc.) - those
    still need to surface as the existing generic 500, not be silently
    misreported as a 409 'already exists'."""
    import routes.case_management as case_management_mod

    def _raise_permission_error(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(case_management_mod.os, "makedirs", _raise_permission_error)

    _save_group("perm_err_group", reporting=True)
    _save_user("perm_err_user", "pw", "perm_err_group")
    _login(client, "perm_err_user")
    res = client.post("/api/cases/create", json={"case_number": "2026-TEST-PERMERR", "examiner": "x", "parent_dir": evidence_root})
    assert res.status_code == 500
    assert "Could not create case folder" in res.get_json()["error"]
