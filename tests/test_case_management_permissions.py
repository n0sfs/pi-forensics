"""routes/case_management.py's create_case()/migrate_case_apply() -
originally carried NO permission check at all (just @requires_auth), a real
finding from the 2026-08-22 security audit: a custom group with every
permission key False could still create case folders and rewrite on-disk
report files via migration.

create_case() uses a broad OR (acquisition/mobile/recovery/reporting) since
it's reachable from the global Active Case Bar on every tab and is a
prerequisite for using any of them. migrate_case_apply() is narrower
('reporting' only) since it's specifically about report-file format, not a
prerequisite for selecting/using an unmigrated case elsewhere.

list_cases()/log_case_select()/migrate_case_preview() are deliberately left
@requires_auth-only (read-only/logging, matching this app's "reads are
open, writes are gated" convention) - not tested here since nothing changed
about them.

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


def _make_legacy_case(evidence_root, slug="2026-LEGACY-01"):
    import os
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir)
    with open(os.path.join(case_dir, "case_info.json"), "w") as f:
        json.dump({"case_number": slug, "examiner": "x"}, f)
    return case_dir


def test_migrate_apply_rejects_a_user_without_reporting_permission(client, runtime_config_file, evidence_root):
    case_dir = _make_legacy_case(evidence_root, "2026-LEGACY-A")
    _save_group("ops_only", acquisition=True, mobile=True, recovery=True)  # everything but reporting
    _save_user("ops_user", "pw", "ops_only")
    _login(client, "ops_user")
    res = client.post("/api/cases/migrate_apply", json={"case_folder": case_dir})
    assert res.status_code == 403


def test_migrate_apply_allowed_with_reporting_permission(client, runtime_config_file, evidence_root):
    case_dir = _make_legacy_case(evidence_root, "2026-LEGACY-B")
    _save_group("reporting_group", reporting=True)
    _save_user("rep_user", "pw", "reporting_group")
    _login(client, "rep_user")
    res = client.post("/api/cases/migrate_apply", json={"case_folder": case_dir})
    assert res.status_code == 200
    assert res.get_json()["success"] is True
