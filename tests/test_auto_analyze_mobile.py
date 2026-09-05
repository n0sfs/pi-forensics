"""routes/file_explorer.py's Mobile/Android Auto Analyze orchestrator
(2026-09-05) - `execution_worker_auto_analyze_mobile()`,
`auto_analyze_mobile_steps()` (target_kind resolution), and the two new
best-effort WhatsApp file-finder helpers.

Tests the orchestrator's control flow in isolation by mocking each of the
8 step functions (via _AUTO_ANALYZE_MOBILE_STEP_FUNCTIONS) - matching
tests/test_chained_auto_analyze.py's own established precedent of testing
control flow with mocked workers, since the real subprocess/parsing work
each step function does is already covered by this project's existing
tests for the underlying core/*_utils.py functions (or, for hashdeep/
ALEAPP/exiftool/MVT, by this project's own established "verify live"
discipline elsewhere). One test deliberately uses the REAL
begin_suppress_active_false()/end_suppress_active_false()/update_job() to
directly prove the safety-critical suppress mechanism, rather than mocking
it away - matching this project's own "prove it the strong way" precedent
(e.g. the reporting-stats throttle tests).

Skipped (not failed) on a non-POSIX dev machine: routes/file_explorer.py
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os

import pytest
from unittest import mock

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.jobs as jobs
import routes.file_explorer as file_explorer
from tests.conftest import RemoteTestClient, login_user_session


# --- _find_whatsapp_crypt_file() / _find_whatsapp_key_file() ---

def test_find_whatsapp_crypt_file_finds_a_real_crypt_file(tmp_path):
    (tmp_path / "unrelated.txt").write_text("x")
    nested = tmp_path / "WhatsApp" / "Databases"
    nested.mkdir(parents=True)
    crypt_path = nested / "msgstore.db.crypt14"
    crypt_path.write_bytes(b"fake encrypted content")

    found = file_explorer._find_whatsapp_crypt_file(str(tmp_path))
    assert found == str(crypt_path)


def test_find_whatsapp_crypt_file_returns_none_when_absent(tmp_path):
    (tmp_path / "unrelated.txt").write_text("x")
    assert file_explorer._find_whatsapp_crypt_file(str(tmp_path)) is None


def test_find_whatsapp_key_file_matches_pull_whatsapp_key_naming_convention(tmp_path):
    (tmp_path / "R58M12345_whatsapp_key").write_bytes(b"fakekey")
    found = file_explorer._find_whatsapp_key_file(str(tmp_path))
    assert found == str(tmp_path / "R58M12345_whatsapp_key")


def test_find_whatsapp_key_file_returns_none_for_a_nonexistent_directory():
    assert file_explorer._find_whatsapp_key_file(None) is None
    assert file_explorer._find_whatsapp_key_file("/definitely/not/a/real/path") is None


# --- GET /api/files/auto_analyze/mobile/steps - target_kind resolution ---

@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(file_explorer.file_explorer_bp)
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


def test_steps_route_resolves_pull_folder_target_kind(client, evidence_root):
    folder = os.path.join(evidence_root, "pull_folder")
    os.makedirs(folder, exist_ok=True)
    res = client.get(f"/api/files/auto_analyze/mobile/steps?path={folder}")
    data = res.get_json()
    assert data["success"] is True
    assert data["target_kind"] == "pull_folder"
    assert data["default_steps"] == file_explorer.AUTO_ANALYZE_MOBILE_PULL_FOLDER_DEFAULT_STEPS
    assert data["extra_steps"] == file_explorer.AUTO_ANALYZE_MOBILE_PULL_FOLDER_EXTRA_STEPS


def test_steps_route_resolves_backup_file_target_kind(client, evidence_root):
    ab_path = os.path.join(evidence_root, "PIXEL-01_backup.ab")
    with open(ab_path, "wb") as f:
        f.write(b"fake ab bytes")
    res = client.get(f"/api/files/auto_analyze/mobile/steps?path={ab_path}")
    data = res.get_json()
    assert data["target_kind"] == "backup_file"
    assert data["default_steps"] == file_explorer.AUTO_ANALYZE_MOBILE_BACKUP_FILE_DEFAULT_STEPS
    assert data["extra_steps"] == []


def test_steps_route_resolves_bugreport_file_target_kind(client, evidence_root):
    zip_path = os.path.join(evidence_root, "PIXEL-01_bugreport.zip")
    with open(zip_path, "wb") as f:
        f.write(b"fake zip bytes")
    res = client.get(f"/api/files/auto_analyze/mobile/steps?path={zip_path}")
    data = res.get_json()
    assert data["target_kind"] == "bugreport_file"
    assert data["default_steps"] == file_explorer.AUTO_ANALYZE_MOBILE_BUGREPORT_FILE_DEFAULT_STEPS


def test_steps_route_resolves_unknown_target_kind_for_an_unrecognized_file(client, evidence_root):
    other_path = os.path.join(evidence_root, "notes.txt")
    with open(other_path, "w") as f:
        f.write("x")
    res = client.get(f"/api/files/auto_analyze/mobile/steps?path={other_path}")
    data = res.get_json()
    assert data["target_kind"] == "unknown"
    assert data["default_steps"] == []


def test_steps_route_rejects_a_missing_path(client, evidence_root):
    res = client.get(f"/api/files/auto_analyze/mobile/steps?path={os.path.join(evidence_root, 'nope')}")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


# --- execution_worker_auto_analyze_mobile() control flow ---

def _mock_job_functions():
    """Mirrors test_chained_auto_analyze.py's exact mocking style - the
    real current_job dict is never touched by these control-flow tests,
    only the dedicated suppress-mechanism test below uses the real thing."""
    return (
        mock.patch.object(file_explorer, "update_job"),
        mock.patch.object(file_explorer, "snapshot_job", return_value={"status": "Running"}),
        mock.patch.object(file_explorer, "begin_suppress_active_false"),
        mock.patch.object(file_explorer, "end_suppress_active_false"),
        mock.patch.object(file_explorer, "log_chain_of_custody"),
    )


def test_orchestrator_runs_every_step_and_records_ok_results():
    fake_steps = {k: mock.Mock(return_value={"success": True, "detail": "done"}) for k in file_explorer.AUTO_ANALYZE_MOBILE_ALL_VALID_STEPS}
    with mock.patch.dict(file_explorer._AUTO_ANALYZE_MOBILE_STEP_FUNCTIONS, fake_steps), \
         mock.patch.object(file_explorer, "update_job") as m_update, \
         mock.patch.object(file_explorer, "snapshot_job", return_value={"status": "Running"}), \
         mock.patch.object(file_explorer, "begin_suppress_active_false") as m_begin, \
         mock.patch.object(file_explorer, "end_suppress_active_false") as m_end, \
         mock.patch.object(file_explorer, "log_chain_of_custody") as m_log:
        file_explorer.execution_worker_auto_analyze_mobile(
            "/mnt/case/pull_folder", "/mnt/case", ["hash_manifest", "aleapp_scan", "mvt_scan"],
            source_ip="1.2.3.4", user="examiner1",
        )

    for step in ("hash_manifest", "aleapp_scan", "mvt_scan"):
        fake_steps[step].assert_called_once_with("/mnt/case/pull_folder", "/mnt/case", source_ip="1.2.3.4", user="examiner1")
    m_begin.assert_called_once()
    m_end.assert_called_once()
    log_call = m_log.call_args
    assert log_call[0][0] == "auto_analyze_mobile_complete"
    assert log_call[0][1]["steps_ok"] == 3
    assert log_call[0][1]["steps_failed"] == 0
    assert log_call[1]["source_ip"] == "1.2.3.4"
    assert log_call[1]["user"] == "examiner1"


def test_orchestrator_reports_not_applicable_steps_distinctly_from_ok_and_error():
    fake_steps = {
        "android_backup_extract": mock.Mock(return_value={"success": True, "status": "not_applicable", "detail": "Not a .ab file."}),
        "mvt_scan": mock.Mock(return_value={"success": True, "detail": "scan ran"}),
    }
    logged = {}
    def _capture_log(action, details=None, source_ip=None, user=None):
        logged.update(details or {})

    with mock.patch.dict(file_explorer._AUTO_ANALYZE_MOBILE_STEP_FUNCTIONS, fake_steps), \
         mock.patch.object(file_explorer, "update_job"), \
         mock.patch.object(file_explorer, "snapshot_job", return_value={"status": "Running"}), \
         mock.patch.object(file_explorer, "begin_suppress_active_false"), \
         mock.patch.object(file_explorer, "end_suppress_active_false"), \
         mock.patch.object(file_explorer, "log_chain_of_custody", side_effect=_capture_log):
        file_explorer.execution_worker_auto_analyze_mobile(
            "/mnt/case/pull_folder", "/mnt/case", ["android_backup_extract", "mvt_scan"],
        )

    assert logged["steps_ok"] == 1
    assert logged["steps_not_applicable"] == 1
    assert logged["steps_failed"] == 0
    result_statuses = {r["step"]: r["status"] for r in logged["results"]}
    assert result_statuses["android_backup_extract"] == "not_applicable"
    assert result_statuses["mvt_scan"] == "ok"


def test_orchestrator_stop_mid_sequence_skips_remaining_steps_and_never_marks_them_ok():
    call_order = []

    def _step_one(path, dest_dir, source_ip=None, user=None):
        call_order.append("step_one")
        return {"success": True, "detail": "done"}

    def _step_two(path, dest_dir, source_ip=None, user=None):
        call_order.append("step_two - SHOULD NEVER RUN")
        return {"success": True, "detail": "done"}

    status_sequence = iter([{"status": "Running"}, {"status": "Stopped"}, {"status": "Stopped"}])
    logged = {}
    def _capture_log(action, details=None, source_ip=None, user=None):
        logged.update(details or {})

    with mock.patch.dict(file_explorer._AUTO_ANALYZE_MOBILE_STEP_FUNCTIONS,
                          {"hash_manifest": _step_one, "mvt_scan": _step_two}), \
         mock.patch.object(file_explorer, "update_job"), \
         mock.patch.object(file_explorer, "snapshot_job", side_effect=lambda: next(status_sequence)), \
         mock.patch.object(file_explorer, "begin_suppress_active_false"), \
         mock.patch.object(file_explorer, "end_suppress_active_false"), \
         mock.patch.object(file_explorer, "log_chain_of_custody", side_effect=_capture_log):
        file_explorer.execution_worker_auto_analyze_mobile(
            "/mnt/case/pull_folder", "/mnt/case", ["hash_manifest", "mvt_scan"],
        )

    # Stop is checked BETWEEN steps (matching the disk-image orchestrator's
    # own established behavior) - the first step still completes, the
    # second is correctly skipped, never invoked at all.
    assert call_order == ["step_one"]
    assert logged["steps_ok"] == 1
    assert logged["steps_skipped"] == 1


def test_orchestrator_suppresses_active_false_for_real_so_the_shared_job_slot_survives_a_mid_run_stop():
    # Unlike every other test above, this one uses the REAL core.jobs
    # implementation (not mocked) to directly prove the safety-critical
    # mechanism this orchestrator depends on: a step function's own
    # internal update_job(active=False) (mirroring how execution_worker_
    # leapp_scan() really behaves) must NOT release the shared job slot
    # while a later step is still genuinely about to run.
    jobs.current_job.clear()
    jobs.current_job.update({"active": True, "status": "Running"})
    jobs._suppress_active_false = False
    mid_run_active_snapshot = {}
    try:
        def _step_that_tries_to_release_the_slot(path, dest_dir, source_ip=None, user=None):
            # Exactly what execution_worker_leapp_scan()'s own finally
            # block does - if suppression isn't in effect, this would
            # prematurely free the shared job slot mid-sequence.
            jobs.update_job(active=False)
            return {"success": True, "detail": "done"}

        def _second_step_captures_mid_run_state(path, dest_dir, source_ip=None, user=None):
            # Called AFTER the first step's own premature active=False
            # attempt - captures whether the slot is still held at exactly
            # the moment suppression is supposed to be protecting it.
            mid_run_active_snapshot["active"] = jobs.current_job["active"]
            return {"success": True, "detail": "done"}

        with mock.patch.dict(file_explorer._AUTO_ANALYZE_MOBILE_STEP_FUNCTIONS,
                              {"hash_manifest": _step_that_tries_to_release_the_slot,
                               "mvt_scan": _second_step_captures_mid_run_state}), \
             mock.patch.object(file_explorer, "log_chain_of_custody"):
            file_explorer.execution_worker_auto_analyze_mobile(
                "/mnt/case/pull_folder", "/mnt/case", ["hash_manifest", "mvt_scan"],
            )

        # Proves suppression genuinely intercepted the first step's own
        # premature active=False call - the second step still found the
        # slot held when it ran.
        assert mid_run_active_snapshot["active"] is True
        # After the whole orchestrator run finishes, active correctly
        # becomes False for real (suppression is lifted in the finally
        # block before the orchestrator's own final update_job(active=False)).
        assert jobs.current_job["active"] is False
        assert jobs.current_job["status"] == "Completed Successfully"
    finally:
        jobs.current_job.clear()
        jobs.current_job.update({"active": False, "status": "IDLE"})
        jobs._suppress_active_false = False
