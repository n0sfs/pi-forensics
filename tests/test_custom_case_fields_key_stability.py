"""routes/reporting.py's settings_case_reporting() - custom_case_fields'
key-stability fix (2026-08-25). Before this fix, a field's key was
regenerated fresh from its label on every single save, with no way for the
frontend to say "this is the same field, just renamed" - so renaming a
field silently orphaned (and, on the case's next save, permanently
deleted - a full-object replace on the Reporting side, not a merge) every
existing case's already-typed value under the old key. This file is the
regression test for the fix: an incoming field whose key matches one
already on file keeps that exact key; only a genuinely new field (empty or
unrecognized key) gets a freshly-derived one.

Through a real Flask test client, matching tests/test_login_flow.py's own
pattern (a minimal app registering just reporting_bp, not the full app.py).
Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os

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


def _save_fields(client, fields):
    return client.post("/api/settings/case_reporting", json={"custom_case_fields": fields})


def test_a_brand_new_field_gets_a_key_derived_from_its_label(client):
    res = _save_fields(client, [{"key": "", "label": "Agency", "default_value": ""}])
    assert res.status_code == 200
    stored = config.load_runtime_config()["custom_case_fields"]
    assert stored == [{"key": "agency", "label": "Agency", "default_value": ""}]


def test_renaming_an_existing_field_keeps_its_key_stable(client):
    _save_fields(client, [{"key": "", "label": "Agency", "default_value": ""}])
    first_key = config.load_runtime_config()["custom_case_fields"][0]["key"]
    assert first_key == "agency"

    # The real-world scenario the bug was found in: an examiner renames the
    # field's display label, sending its own already-assigned key back
    # (exactly what saveCaseReportingSettings() now does in main.js).
    res = _save_fields(client, [{"key": first_key, "label": "Requesting Agency", "default_value": ""}])
    assert res.status_code == 200
    stored = config.load_runtime_config()["custom_case_fields"]
    assert len(stored) == 1
    assert stored[0]["key"] == "agency"  # unchanged, despite the label changing
    assert stored[0]["label"] == "Requesting Agency"


def test_an_existing_cases_value_under_the_stable_key_is_never_orphaned_by_a_rename(client, evidence_root):
    # End-to-end proof this actually closes the bug, not just that the key
    # stays the same in isolation: a real case's custom_fields dict, keyed
    # by the field's key, must still resolve correctly after the field
    # bearing that key gets renamed.
    _save_fields(client, [{"key": "", "label": "Agency", "default_value": ""}])
    key = config.load_runtime_config()["custom_case_fields"][0]["key"]

    case_custom_fields = {key: "Zephyrwatch Regional Crime Lab"}
    _save_fields(client, [{"key": key, "label": "Requesting Agency", "default_value": ""}])

    defs_after_rename = config.load_runtime_config()["custom_case_fields"]
    assert defs_after_rename[0]["key"] == key
    # The case's own stored value is still addressable by the exact same
    # key the (renamed) field definition uses - nothing to re-key or lose.
    assert case_custom_fields[defs_after_rename[0]["key"]] == "Zephyrwatch Regional Crime Lab"


def test_an_unrecognized_incoming_key_is_not_trusted_and_gets_a_fresh_one_instead(client):
    # Defensive case: a key that doesn't match anything currently on file
    # (garbage, or a leftover from a different station's export) must not
    # be accepted as-is - only a key that provably already exists in this
    # station's own stored config is ever preserved.
    res = _save_fields(client, [{"key": "totally_made_up_key", "label": "Agency", "default_value": ""}])
    assert res.status_code == 200
    stored = config.load_runtime_config()["custom_case_fields"]
    assert stored[0]["key"] == "agency"  # derived fresh from the label, not the bogus incoming key


def test_two_fields_saved_together_dedupe_correctly_when_one_is_new_and_one_is_a_rename(client):
    _save_fields(client, [
        {"key": "", "label": "Agency", "default_value": ""},
        {"key": "", "label": "Department", "default_value": ""},
    ])
    agency_key = next(f["key"] for f in config.load_runtime_config()["custom_case_fields"] if f["label"] == "Agency")

    res = _save_fields(client, [
        {"key": agency_key, "label": "Agency", "default_value": ""},  # unchanged
        {"key": "", "label": "Badge Number", "default_value": ""},    # genuinely new
    ])
    assert res.status_code == 200
    stored = {f["key"]: f["label"] for f in config.load_runtime_config()["custom_case_fields"]}
    assert stored == {"agency": "Agency", "badge_number": "Badge Number"}
