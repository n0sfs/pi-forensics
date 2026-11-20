"""/api/acquisition_precheck (2026-11-20): says BEFORE Start what Start
would refuse - a Closed/Archived destination case, or a Case #/Evidence ID
already used in the destination - and suggests the next free ITEM-NN. It
shares _existing_acquisition_outputs() with start_imaging()'s own refusal,
so the two cannot disagree. Read-only: it must never claim the job slot.

Skipped (not failed) on a non-POSIX dev machine: core.jobs (imported by
routes.acquisition) needs POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.acquisition as acq
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def client(runtime_config_file):
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(acq.acquisition_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(flask_app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _case(evidence_root, name, status="Open"):
    folder = os.path.join(evidence_root, name)
    os.mkdir(folder)
    with open(os.path.join(folder, f"{name}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": name, "case_status": status, "events": []}, f)
    return folder


def _check(client, folder, case_number, evidence_id=""):
    res = client.post("/api/acquisition_precheck",
                      json={"destination": folder, "case_number": case_number, "evidence_id": evidence_id})
    assert res.status_code == 200
    return res.get_json()


def test_clean_destination_has_nothing_to_warn_and_suggests_item_01(client, evidence_root):
    folder = _case(evidence_root, "2026-PRE-1")
    data = _check(client, folder, "2026-PRE-1")
    assert data["closed_status"] is None and data["collision"] is None
    assert data["suggested_evidence_id"] == "ITEM-01"
    assert jobs.current_job["active"] is False


def test_a_used_evidence_id_is_named_and_the_next_free_one_suggested(client, evidence_root):
    folder = _case(evidence_root, "2026-PRE-2")
    for n in ("2026-PRE-2_ITEM-01.dd", "2026-PRE-2_ITEM-01_dc3dd.log", "2026-PRE-2_ITEM-02.E01"):
        open(os.path.join(folder, n), "w").close()
    data = _check(client, folder, "2026-PRE-2", "ITEM-01")
    assert data["collision"] == "2026-PRE-2_ITEM-01.dd"
    assert data["suggested_evidence_id"] == "ITEM-03"
    # blank Evidence ID means ITEM-01 at Start, so it collides too
    assert _check(client, folder, "2026-PRE-2")["collision"] == "2026-PRE-2_ITEM-01.dd"
    assert _check(client, folder, "2026-PRE-2", "ITEM-03")["collision"] is None


def test_a_lone_hash_log_still_counts_as_used(client, evidence_root):
    folder = _case(evidence_root, "2026-PRE-3")
    open(os.path.join(folder, "2026-PRE-3_ITEM-01_sha256.log"), "w").close()
    data = _check(client, folder, "2026-PRE-3", "ITEM-01")
    assert data["collision"] == "2026-PRE-3_ITEM-01_sha256.log"
    assert data["suggested_evidence_id"] == "ITEM-02"


def test_a_closed_case_is_reported(client, evidence_root):
    folder = _case(evidence_root, "2026-PRE-4", status="Closed")
    assert _check(client, folder, "2026-PRE-4")["closed_status"] == "Closed"


def test_a_missing_destination_is_quiet_not_an_error(client, evidence_root):
    data = _check(client, os.path.join(evidence_root, "nope"), "X")
    assert data == {"success": True, "closed_status": None, "collision": None, "suggested_evidence_id": None}
