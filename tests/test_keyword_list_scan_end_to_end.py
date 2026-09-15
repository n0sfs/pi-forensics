"""Keyword lists actually FINDING things, through the real scan route.

The existing coverage stops short of this. tests/test_keyword_lists.py covers
the CRUD API, tests/test_scan_patterns.py covers build_scan_patterns() in
isolation, and tests/test_redos_defense.py covers the ReDoS gate - but nothing
exercised a saved list all the way through POST /api/files/quick_triage_scan to
real hits in the response. That is the path an examiner actually uses, and the
one where a regression would look like "the feature quietly finds nothing".

Written after verifying the same behaviour by hand against the real station
(2026-09-15): a plain-term list and a gitleaks-style regex list both produced
correct hits on a probe file, built-ins stayed opt-out-free, and an unknown
list id degraded instead of failing.

Skipped (not failed) on a non-POSIX dev machine: routes/file_explorer.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import os
import time

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.file_explorer import file_explorer_bp
from tests.conftest import RemoteTestClient


# Deliberately contains one hit for each list plus one built-in-category hit,
# so a test can tell "the keyword list ran" from "the scan ran at all".
PROBE_TEXT = """Install log excerpt.
User ran BleachBit and then sdelete -p 3 on the temp folder.
A VeraCrypt container was mounted from the desktop.
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----
Contact: someone@example.com
Nothing about clean disks here otherwise.
"""

PLAIN_LIST = {
    "id": "af_tools", "name": "Anti-Forensics Tools",
    "terms": ["BleachBit", "CCleaner", "DBAN", "sdelete", "VeraCrypt", "Eraser"],
    "is_regex": False,
}
# Shaped like the gitleaks rules a credentials list would be built from.
REGEX_LIST = {
    "id": "creds", "name": "Credentials",
    "terms": [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}",
              r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"],
    "is_regex": True,
}


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(file_explorer_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    cfg["keyword_lists"] = [dict(PLAIN_LIST), dict(REGEX_LIST)]
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    with c.session_transaction() as sess:
        sess["username"] = "admin_user"
        sess["last_activity"] = time.time()
    return c


@pytest.fixture
def probe(evidence_root):
    path = os.path.join(evidence_root, "keyword_scan_probe.txt")
    with open(path, "w") as f:
        f.write(PROBE_TEXT)
    return path


def _scan(client, path, keyword_list_ids=None):
    body = {"path": path}
    if keyword_list_ids is not None:
        body["keyword_list_ids"] = keyword_list_ids
    res = client.post("/api/files/quick_triage_scan", json=body)
    assert res.status_code == 200, res.get_data(as_text=True)
    data = res.get_json()
    assert data["success"] is True
    return data


def test_a_plain_term_list_finds_its_terms_case_insensitively(client, probe):
    data = _scan(client, probe, ["af_tools"])
    out = data["output"]
    assert "Anti-Forensics Tools" in out
    # "sdelete" appears lowercase in the probe and mixed-case in the list.
    for expected in ("BleachBit", "VeraCrypt", "sdelete"):
        assert expected in out, f"{expected} not reported"
    # Terms that genuinely are not present must not be reported.
    assert "CCleaner" not in out
    assert "DBAN" not in out


def test_a_regex_list_finds_real_pattern_matches(client, probe):
    data = _scan(client, probe, ["creds"])
    out = data["output"]
    assert "Credentials" in out
    assert "AKIAIOSFODNN7EXAMPLE" in out
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in out


def test_keyword_lists_are_never_included_unless_selected(client, probe):
    """The opt-in contract build_scan_patterns() documents: a list is never
    force-included just because it exists on the station."""
    data = _scan(client, probe)
    out = data["output"]
    assert "Anti-Forensics Tools" not in out
    assert "Credentials" not in out
    # The built-in categories still ran.
    assert "someone@example.com" in out


def test_selecting_one_list_does_not_pull_in_the_other(client, probe):
    out = _scan(client, probe, ["creds"])["output"]
    assert "Credentials" in out
    assert "Anti-Forensics Tools" not in out


def test_both_lists_together_report_both_categories(client, probe):
    data = _scan(client, probe, ["af_tools", "creds"])
    out = data["output"]
    assert "Anti-Forensics Tools" in out
    assert "Credentials" in out
    # One built-in hit (the email) plus three from each list.
    assert data["total_hits"] == 7


def test_an_unknown_list_id_degrades_instead_of_failing_the_scan(client, probe):
    """A stale id left in a saved selection (a list deleted since) must not
    fail a scan an examiner is waiting on - it falls back to the built-ins."""
    data = _scan(client, probe, ["no_such_list_id"])
    assert "Anti-Forensics Tools" not in data["output"]
    assert data["total_hits"] == 1


def test_a_plain_term_list_does_not_interpret_regex_metacharacters(client, evidence_root):
    """A literal term is re.escape()'d at scan time, so '.' must match itself
    and never act as a wildcard. This is what makes a domain or a price safe to
    paste straight in as a plain term."""
    cfg = config.load_runtime_config()
    cfg["keyword_lists"] = [{"id": "iocs", "name": "IOCs",
                             "terms": ["evil.example.com"], "is_regex": False}]
    config.save_runtime_config(cfg)

    decoy = os.path.join(evidence_root, "decoy.txt")
    with open(decoy, "w") as f:
        f.write("connects to evilXexampleXcom, a different host entirely\n")
    assert _scan(client, decoy, ["iocs"])["total_hits"] == 0

    real = os.path.join(evidence_root, "real.txt")
    with open(real, "w") as f:
        f.write("connects to evil.example.com every hour\n")
    data = _scan(client, real, ["iocs"])
    assert "evil.example.com" in data["output"]
    assert data["total_hits"] == 1


def test_a_list_with_a_catastrophic_regex_is_dropped_not_run(client, probe):
    """The ReDoS gate runs at pattern-assembly time, and a failing list is
    skipped rather than hanging the single shared job slot. The scan itself
    must still complete and still report the built-ins."""
    cfg = config.load_runtime_config()
    cfg["keyword_lists"] = [{"id": "evil", "name": "Evil",
                             "terms": [r"(a+)+$"], "is_regex": True}]
    config.save_runtime_config(cfg)
    data = _scan(client, probe, ["evil"])
    assert "Evil" not in data["output"]
    assert data["total_hits"] == 1   # the built-in email hit only
