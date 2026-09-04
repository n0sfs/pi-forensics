"""routes/mobile.py's execution_worker_android_companion_contacts_calllog()
- the non-rooted companion-app Contacts/Call Log extraction worker
(2026-09-04).

Mirrors tests/test_android_companion_sms_worker.py's own established
approach exactly: mock the real subprocess/device work
(_adb_run()/update_job()/log_chain_of_custody()/_write_report()/
_record_parsed_artifacts()/_auto_tag_case_artifact()), test control flow
in isolation. The same real bug class that feature's own tests were
written to guard against (log_chain_of_custody() needing explicit
source_ip/user since this worker runs in a background thread with no
Flask request context) is guarded here too, from the start, rather than
being a second bug to find live.

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
    """The same real bug class already caught once for the SMS companion:
    this call must never rely on log_chain_of_custody()'s own request/g
    fallback, since this worker runs in a background thread with no Flask
    request context."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
            requester_ip="10.0.0.5", requester_user="examiner_jane",
        )

        mocks["log_chain_of_custody"].assert_called_once()
        call_args, call_kwargs = mocks["log_chain_of_custody"].call_args
        assert call_kwargs.get("source_ip") == "10.0.0.5"
        assert call_kwargs.get("user") == "examiner_jane"


def test_job_slot_always_released_even_when_install_fails():
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device 'SERIAL123' not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
            requester_ip="127.0.0.1", requester_user="local-kiosk",
        )

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert report_data["acquisition_status"] == "FAILED"


def test_cleanup_skips_permission_revoke_when_install_never_succeeded():
    """If install itself fails, neither permission was ever granted -
    only the one failed install call should have happened, confirming the
    worker correctly tracks apk_installed/contacts_granted/calllog_granted
    rather than blindly attempting every cleanup step regardless."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        assert mocks["_adb_run"].call_count == 1
        assert mocks["_adb_run"].call_args[0][1] == ["install", "-r", mobile.PIF_COMPANION_APK]


def test_data_types_contacts_only_never_grants_calllog_permission():
    """A real, distinct correctness requirement from the SMS worker: this
    feature has two independently-selectable data types, and selecting
    only one must not touch the permission the examiner didn't ask for."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "contacts", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        granted_perms = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                          if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == "grant"]
        assert "android.permission.READ_CONTACTS" in granted_perms
        assert "android.permission.READ_CALL_LOG" not in granted_perms


def test_data_types_calllog_only_never_grants_contacts_permission():
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "calllog", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        granted_perms = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                          if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == "grant"]
        assert "android.permission.READ_CALL_LOG" in granted_perms
        assert "android.permission.READ_CONTACTS" not in granted_perms


def test_stop_requested_before_any_query_skips_queries_but_still_cleans_up():
    """Same, already-established convention as the SMS worker's own
    identical test: a genuinely stopped job stays at its starting
    IN_PROGRESS acquisition_status, never falsely marked COMPLETED, and
    the final update_job() call must not overwrite the job's own status
    text (already "Stopped") with a misleading "Failed"."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Stopped"}

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        called_steps = [c.args[1][0] for c in mocks["_adb_run"].call_args_list]
        assert "content" not in called_steps  # neither query step ran
        assert "install" in called_steps      # but install + cleanup still ran

        assert report_data["acquisition_status"] == "IN_PROGRESS"

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert "status" not in last_call.kwargs


def test_stop_between_the_two_queries_still_reports_completed_with_the_gap_visible():
    """The deliberate asymmetry the worker's own docstring documents: a
    Stop that lands AFTER the Contacts query already succeeded (unlike a
    Stop before any query ran, tested above) still marks the run
    COMPLETED, since real data was captured - but the Call Log query is
    genuinely skipped and call_log_count stays 0, so the case record
    honestly reflects what did and didn't happen rather than either
    silently claiming "everything" or discarding the real Contacts data
    that was already captured."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "Row: 0 _id=1, contact_id=1, mimetype=vnd.android.cursor.item/"
                                              "phone_v2, data1=5551234567, data2=2, data3=, display_name=Test", "")
        # snapshot_job() is called 3 times in the "both" happy path before
        # cleanup: once before the Contacts query (not Stopped), once
        # before the Call Log query (Stopped this time), and it's not
        # called again after that in this worker.
        mocks["snapshot_job"].side_effect = [{"status": "Running"}, {"status": "Stopped"}]
        mocks["_record_parsed_artifacts"].return_value = 1

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        query_uris = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                      if len(c.args[1]) > 4 and c.args[1][1] == "content"]
        assert any("pif.companion.contacts" in u for u in query_uris)
        assert not any("pif.companion.calllog" in u for u in query_uris)

        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["contact_records_captured"] == 1
        assert report_data["acquisition_parameters"]["call_log_records_captured"] == 0


def test_both_permissions_revoked_and_apk_uninstalled_on_success():
    """The full happy-path cleanup sequence, confirming both permissions
    are independently revoked and the collector uninstalled - not just
    the install/grant/query half of the sequence."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_contacts_calllog(
            "SERIAL123", "both", "/mnt/case/ITEM-01_android_companion_contacts_calllog_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        revoked_perms = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                          if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == "revoke"]
        assert "android.permission.READ_CONTACTS" in revoked_perms
        assert "android.permission.READ_CALL_LOG" in revoked_perms

        uninstall_calls = [c.args[1] for c in mocks["_adb_run"].call_args_list if c.args[1][0] == "uninstall"]
        assert len(uninstall_calls) == 1
        assert report_data["acquisition_status"] == "COMPLETED"
