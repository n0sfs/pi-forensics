"""routes/mobile.py's execution_worker_android_companion_sms() - the
non-rooted companion-app SMS extraction worker (2026-09-04).

Tests control flow in isolation by mocking _adb_run()/update_job()/
log_chain_of_custody()/_write_report()/_record_parsed_artifacts()/
_auto_tag_case_artifact() - matching this project's own established
"mock the real subprocess/device work, test control flow" split (see
tests/test_chained_auto_analyze.py's own identical approach).

The single most important test here (test_log_chain_of_custody_called_
with_explicit_source_ip_and_user) is a REAL regression test for a REAL
bug this feature shipped with and caught during its own live verification:
log_chain_of_custody() was called from inside this worker with no
source_ip/user override, which raises "Working outside of application
context" when running in a background daemon thread with no Flask request
context - the exception was silently eating the tail of the worker's own
`finally` block, so the shared job slot never got released
(current_job["active"] stayed True forever, confirmed live: a real fake-
serial test against the deployed Pi left it stuck exactly this way).
Fixed the same way this codebase has already fixed the identical bug
class elsewhere (network config's delayed-revert thread, chained_auto_
analyze) - capture source_ip/user in the real request thread, thread them
through explicitly.

Skipped (not failed) on a non-POSIX dev machine: routes/mobile.py needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest
from unittest import mock

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


def _base_report_data():
    return {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}


def _patched_worker(**overrides):
    """Context manager building the standard set of mocks every test here
    needs, with per-test overrides layered on top (e.g. a failing
    _adb_run for the install step)."""
    defaults = {
        "_adb_run": mock.DEFAULT,
        "update_job": mock.DEFAULT,
        "snapshot_job": mock.DEFAULT,
        "log_chain_of_custody": mock.DEFAULT,
        "_write_report": mock.DEFAULT,
        "_record_parsed_artifacts": mock.DEFAULT,
        "_auto_tag_case_artifact": mock.DEFAULT,
    }
    patcher = mock.patch.multiple(mobile, **defaults)
    return patcher


def test_log_chain_of_custody_called_with_explicit_source_ip_and_user():
    """The real bug: this call must never rely on log_chain_of_custody()'s
    own request/g fallback, since this worker runs in a background thread
    with no Flask request context."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")  # every adb step "succeeds" - isolates this one check
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_sms(
            "SERIAL123", "readonly", "/mnt/case/ITEM-01_android_companion_sms_extraction.json",
            "report_target", report_data, "/mnt/case",
            requester_ip="10.0.0.5", requester_user="examiner_jane",
        )

        mocks["log_chain_of_custody"].assert_called_once()
        call_args, call_kwargs = mocks["log_chain_of_custody"].call_args
        assert call_kwargs.get("source_ip") == "10.0.0.5"
        assert call_kwargs.get("user") == "examiner_jane"


def test_job_slot_always_released_even_when_install_fails():
    """Reproduces the exact real scenario this bug was caught with: adb
    install fails against a bad/disconnected serial. The job slot
    (active=False) must still be the LAST update_job() call - a stuck
    slot blocks every other acquisition/recovery job station-wide."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device 'SERIAL123' not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        mobile.execution_worker_android_companion_sms(
            "SERIAL123", "readonly", "/mnt/case/ITEM-01_android_companion_sms_extraction.json",
            "report_target", report_data, "/mnt/case",
            requester_ip="127.0.0.1", requester_user="local-kiosk",
        )

        # The final call to update_job() must set active=False.
        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert report_data["acquisition_status"] == "FAILED"


def test_cleanup_skips_uninstall_when_install_never_succeeded():
    """A failed install means the collector was never actually placed on
    the device - uninstall must not be attempted (and, if it somehow were,
    it would be harmless/idempotent, but this proves the worker correctly
    tracks apk_installed rather than blindly cleaning up every step)."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        mobile.execution_worker_android_companion_sms(
            "SERIAL123", "readonly", "/mnt/case/ITEM-01_android_companion_sms_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        # Only the one failed "install" call should have happened - no
        # pm_grant/query/pm_revoke/uninstall calls, since install itself
        # never succeeded.
        assert mocks["_adb_run"].call_count == 1
        assert mocks["_adb_run"].call_args[0][1] == ["install", "-r", mobile.PIF_COMPANION_APK]


def test_stop_requested_before_query_skips_query_but_still_cleans_up():
    """A real correctness bug caught by this exact test before shipping:
    the first version of this worker unconditionally marked a Stopped run
    "COMPLETED", falsely claiming success for an extraction that never
    actually queried anything. Fixed to match execution_worker_android()'s
    own established convention - a genuinely stopped job's acquisition_
    status is simply left at its starting "IN_PROGRESS" value, and the
    final update_job() call must NOT overwrite the job's own status text
    (already "Stopped", set by stop_imaging()'s own earlier call) with a
    misleading "Failed" - only active=False must always happen."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Stopped"}

        mobile.execution_worker_android_companion_sms(
            "SERIAL123", "readonly", "/mnt/case/ITEM-01_android_companion_sms_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        called_steps = [c.args[1][0] for c in mocks["_adb_run"].call_args_list]
        assert "content" not in called_steps  # the query step was skipped
        assert "install" in called_steps      # but install + cleanup still ran
        assert any(s == "shell" for s in called_steps)  # pm revoke, a cleanup step

        # Neither COMPLETED nor FAILED - a genuinely stopped run stays at
        # its starting IN_PROGRESS value.
        assert report_data["acquisition_status"] == "IN_PROGRESS"

        # The final update_job() call must set active=False without
        # overwriting `status` (no status= kwarg at all in that call).
        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert "status" not in last_call.kwargs
