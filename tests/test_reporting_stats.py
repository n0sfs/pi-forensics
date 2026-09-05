"""Reporting's header-row "stat cards" (Total Cases, Active Cases, Evidence
Items, Reports Exported - 2026-09-03) - REPORTING_STAT_DEFINITIONS,
_compute_reporting_stats(), the two new GET /api/reporting/stats* routes,
and settings_case_reporting()'s new reporting_stats persistence (extending
the exact save/load pattern custom_case_fields already established there).

Through a real Flask test client, matching test_custom_case_fields_key_
stability.py's own pattern (a minimal app registering just reporting_bp).
Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.reporting as reporting
from routes.reporting import reporting_bp, _compute_reporting_stats
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


def _redirect_evidence_root(monkeypatch, evidence_root):
    # _compute_reporting_stats() -> list_case_folders() reads config.
    # EVIDENCE_ROOT module-qualified - the shared evidence_root fixture only
    # patches core.paths.EVIDENCE_ROOT, a separate binding (see test_cross_
    # case_search.py's own identical note/helper for the same reason).
    monkeypatch.setattr(config, "EVIDENCE_ROOT", evidence_root)


def _write_consolidated_case(evidence_root, slug, case_number, case_status, event_count):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    events = [{"tool": "dd"} for _ in range(event_count)]
    with open(os.path.join(case_dir, f"{slug}_case.json"), 'w') as f:
        json.dump({
            "case_number": case_number, "examiner": "x", "case_folder": case_dir,
            "created_at": "2026-01-01", "notes": "", "case_status": case_status, "events": events,
        }, f)
    return case_dir


def _tag_item_notable(case_dir, tag_name="Notable Item", item_name="evidence.jpg"):
    """Opens (creating/seeding if absent) the case's own per-case SQLite
    index and inserts one tagged_items row against the given tag - by
    default the schema's own always-seeded 'Notable Item' default tag, so
    no extra tag-creation step is needed for the common case."""
    db_path = case_index_db_path(case_dir)
    conn = _case_index_connect(db_path)
    try:
        tag_id = conn.execute("SELECT id FROM tags WHERE name = ?", (tag_name,)).fetchone()[0]
        conn.execute(
            "INSERT INTO tagged_items (tag_id, source_type, name, tagged_at) VALUES (?, 'real_fs', ?, datetime('now'))",
            (tag_id, item_name),
        )
        conn.commit()
    finally:
        conn.close()


def _redirect_coc_log(monkeypatch, tmp_path):
    # _read_coc_entries() (routes/reporting.py) reads the bare COC_LOG_FILE
    # name it imported from core.config at module load time - patching
    # core.config.COC_LOG_FILE would have zero effect on that already-bound
    # copy, so the patch target has to be routes.reporting's own namespace.
    log_file = tmp_path / "chain_of_custody.log"
    monkeypatch.setattr(reporting, "COC_LOG_FILE", str(log_file))
    return str(log_file)


def _write_coc_entries(path, actions):
    with open(path, 'w') as f:
        for action in actions:
            f.write(json.dumps({
                "timestamp": "2026-01-01 00:00:00", "action": action, "details": {},
                "source_ip": None, "user": "x",
            }) + "\n")


# --- _compute_reporting_stats() unit tests ---

def test_total_cases_active_cases_and_evidence_items_share_one_case_list(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Open", 2)
    _write_consolidated_case(evidence_root, "2026-CASE-B", "2026-CASE-B", "Closed", 3)
    _write_consolidated_case(evidence_root, "2026-CASE-C", "2026-CASE-C", "Archived", 1)

    stats = _compute_reporting_stats(["total_cases", "active_cases", "evidence_items"])
    by_key = {s["key"]: s for s in stats}
    assert by_key["total_cases"]["value"] == 3
    assert by_key["total_cases"]["breakdown"] == {"Open": 1, "Closed": 1, "Archived": 1}
    assert by_key["active_cases"]["value"] == 1  # only the Open one - Closed/Archived don't count
    assert by_key["evidence_items"]["value"] == 6  # 2 + 3 + 1


def test_a_legacy_schema_case_is_normalized_to_open_and_excluded_from_evidence_items(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    case_dir = os.path.join(evidence_root, "2026-CASE-LEGACY")
    os.makedirs(case_dir)
    with open(os.path.join(case_dir, "case_info.json"), 'w') as f:
        json.dump({"case_number": "2026-CASE-LEGACY", "examiner": "x", "created_at": "2026-01-01"}, f)

    stats = _compute_reporting_stats(["total_cases", "active_cases", "evidence_items"])
    by_key = {s["key"]: s for s in stats}
    # list_case_folders() itself already normalizes a missing case_status to
    # 'Open' for both schemas (confirmed by reading its own source, not
    # assumed) - so a legacy case never actually shows up as a distinct
    # "Legacy" breakdown bucket in practice, only ever as "Open".
    assert by_key["total_cases"]["value"] == 1
    assert by_key["total_cases"]["breakdown"] == {"Open": 1}
    assert by_key["active_cases"]["value"] == 1
    assert by_key["evidence_items"]["value"] == 0  # legacy schema has no events[] to count


def test_reports_exported_counts_only_report_exported_actions(evidence_root, monkeypatch, tmp_path):
    _redirect_evidence_root(monkeypatch, evidence_root)
    log_path = _redirect_coc_log(monkeypatch, tmp_path)
    _write_coc_entries(log_path, ["report_exported", "case_create", "report_exported", "user_login"])
    stats = _compute_reporting_stats(["reports_exported"])
    assert stats[0]["value"] == 2


def test_reports_exported_is_zero_with_no_log_file_at_all(evidence_root, monkeypatch, tmp_path):
    _redirect_evidence_root(monkeypatch, evidence_root)
    monkeypatch.setattr(reporting, "COC_LOG_FILE", str(tmp_path / "does_not_exist.log"))
    stats = _compute_reporting_stats(["reports_exported"])
    assert stats[0]["value"] == 0


def test_tags_flagged_sums_notable_tagged_items_across_every_case(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    case_a = _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Open", 1)
    case_b = _write_consolidated_case(evidence_root, "2026-CASE-B", "2026-CASE-B", "Open", 1)
    _tag_item_notable(case_a, item_name="a1.jpg")
    _tag_item_notable(case_a, item_name="a2.jpg")
    _tag_item_notable(case_b, item_name="b1.jpg")

    stats = _compute_reporting_stats(["tags_flagged"])
    assert stats[0]["value"] == 3


def test_tags_flagged_excludes_non_notable_tags(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    case_a = _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Open", 1)
    _tag_item_notable(case_a, tag_name="Bookmark", item_name="a1.jpg")  # not notable
    _tag_item_notable(case_a, tag_name="Notable Item", item_name="a2.jpg")

    stats = _compute_reporting_stats(["tags_flagged"])
    assert stats[0]["value"] == 1


def test_tags_flagged_is_zero_when_no_case_has_ever_been_indexed(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Open", 1)  # never tagged/indexed
    stats = _compute_reporting_stats(["tags_flagged"])
    assert stats[0]["value"] == 0


def test_an_unrecognized_key_is_silently_skipped_not_fatal(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    stats = _compute_reporting_stats(["total_cases", "made_up_stat"])
    assert [s["key"] for s in stats] == ["total_cases"]


def test_stat_order_follows_the_requested_key_order_not_registry_order(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    stats = _compute_reporting_stats(["evidence_items", "total_cases"])
    assert [s["key"] for s in stats] == ["evidence_items", "total_cases"]


# --- Route-level tests ---

def test_registry_route_returns_all_five_definitions(client):
    res = client.get("/api/reporting/stats/registry")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    keys = {d["key"] for d in data["stats"]}
    assert keys == {"total_cases", "active_cases", "evidence_items", "reports_exported", "tags_flagged"}
    # Every definition needs a real label an examiner-facing checkbox can
    # show, not just an internal key.
    assert all(d.get("label") for d in data["stats"])


def test_stats_route_defaults_to_total_cases_only_when_never_configured(client, evidence_root, monkeypatch):
    # A brand-new station's saved config has no 'reporting_stats' key at all
    # - must default to exactly what Reporting showed before this feature
    # existed, not silently expand to every stat.
    _redirect_evidence_root(monkeypatch, evidence_root)
    res = client.get("/api/reporting/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert [s["key"] for s in data["stats"]] == ["total_cases"]


def test_stats_route_respects_a_saved_enabled_list_and_its_order(client, evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    save_res = client.post("/api/settings/case_reporting", json={"reporting_stats": {"enabled": ["evidence_items", "active_cases"]}})
    assert save_res.status_code == 200
    res = client.get("/api/reporting/stats")
    data = res.get_json()
    assert [s["key"] for s in data["stats"]] == ["evidence_items", "active_cases"]


def test_stats_route_falls_back_to_default_when_saved_list_is_all_unrecognized(client, evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    client.post("/api/settings/case_reporting", json={"reporting_stats": {"enabled": ["nonsense_key"]}})
    res = client.get("/api/reporting/stats")
    data = res.get_json()
    assert [s["key"] for s in data["stats"]] == ["total_cases"]


def test_settings_save_filters_out_unrecognized_stat_keys(client):
    res = client.post("/api/settings/case_reporting", json={
        "reporting_stats": {"enabled": ["total_cases", "bogus", "reports_exported"]}
    })
    assert res.status_code == 200
    stored = config.load_runtime_config()["reporting_stats"]
    assert stored == {"enabled": ["total_cases", "reports_exported"]}


def test_settings_get_returns_the_saved_reporting_stats_config(client):
    client.post("/api/settings/case_reporting", json={"reporting_stats": {"enabled": ["active_cases"]}})
    res = client.get("/api/settings/case_reporting")
    data = res.get_json()
    assert data["reporting_stats"] == {"enabled": ["active_cases"]}


def test_settings_save_without_a_reporting_stats_key_leaves_the_saved_value_untouched(client):
    # Mirrors custom_case_fields' own established behavior for this route:
    # a save that only touches OTHER fields (e.g. just report_defaults)
    # must never silently reset/clear a setting it wasn't asked to change.
    client.post("/api/settings/case_reporting", json={"reporting_stats": {"enabled": ["reports_exported"]}})
    client.post("/api/settings/case_reporting", json={"report_defaults": {"template": "standard"}})
    stored = config.load_runtime_config()["reporting_stats"]
    assert stored == {"enabled": ["reports_exported"]}
