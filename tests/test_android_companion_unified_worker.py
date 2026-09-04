"""routes/mobile.py's execution_worker_android_companion_extraction() - the
non-rooted companion-app UNIFIED extraction worker (2026-09-04), replacing
the three earlier separate per-type workers (SMS, Contacts/Call Log,
Calendar - each with its own separately-deleted test file) with one
checklist-driven flow covering all six data types (SMS/Contacts/Call Log/
Calendar/Photos/Video).

Mirrors those earlier workers' own established test approach exactly: mock
the real subprocess/device work (_adb_run()/update_job()/
log_chain_of_custody()/_write_report()/_record_parsed_artifacts()/
_auto_tag_case_artifact()), test control flow in isolation. The same real
bug class those earlier features' own tests were written to guard against
(log_chain_of_custody() needing explicit source_ip/user since this worker
runs in a background thread with no Flask request context) is guarded here
too, from the start.

Genuinely new coverage this consolidated worker needs that no single-type
predecessor did: permission isolation across SIX possible types at once
(selecting only a subset must never touch the others' permissions), the
install-once/uninstall-once guarantee (never once per type), and the
combined single-report-event/single-manifest shape.

Skipped (not failed) on a non-POSIX dev machine: routes/mobile.py needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest
from unittest import mock

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


def _base_report_data():
    return {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}


def _patched_worker():
    defaults = {
        "_adb_run": mock.DEFAULT,
        "update_job": mock.DEFAULT,
        "snapshot_job": mock.DEFAULT,
        "log_chain_of_custody": mock.DEFAULT,
        "_write_report": mock.DEFAULT,
        "_record_parsed_artifacts": mock.DEFAULT,
        "_auto_tag_case_artifact": mock.DEFAULT,
    }
    return mock.patch.multiple(mobile, **defaults)


def _run(selected_types, sms_tier="readonly", **kw):
    report_data = kw.pop("report_data", None) or _base_report_data()
    mobile.execution_worker_android_companion_extraction(
        "SERIAL123", selected_types, sms_tier,
        "/mnt/case/ITEM-01_android_companion_extraction_extraction.json",
        "report_target", report_data, "/mnt/case",
        requester_ip=kw.pop("requester_ip", "127.0.0.1"),
        requester_user=kw.pop("requester_user", "local-kiosk"),
    )
    return report_data


def _pm_calls(mocks, verb):
    """Every ['shell', 'pm', verb, PKG, perm] call, returning just the perm string."""
    return [c.args[1][4] for c in mocks["_adb_run"].call_args_list
            if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == verb]


def test_log_chain_of_custody_called_with_explicit_source_ip_and_user():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"sms"}, requester_ip="10.0.0.5", requester_user="examiner_jane")

        mocks["log_chain_of_custody"].assert_called_once()
        _, call_kwargs = mocks["log_chain_of_custody"].call_args
        assert call_kwargs.get("source_ip") == "10.0.0.5"
        assert call_kwargs.get("user") == "examiner_jane"


def test_job_slot_always_released_even_when_install_fails():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device 'SERIAL123' not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        report_data = _run({"sms", "contacts"})

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert report_data["acquisition_status"] == "FAILED"


def test_apk_installed_and_uninstalled_exactly_once_regardless_of_type_count():
    """The single most important consolidation guarantee: installing once
    for six selected types, not six times."""
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"sms", "contacts", "calllog", "calendar", "images", "video"})

        install_calls = [c for c in mocks["_adb_run"].call_args_list if c.args[1][0] == "install"]
        uninstall_calls = [c for c in mocks["_adb_run"].call_args_list if c.args[1][0] == "uninstall"]
        assert len(install_calls) == 1
        assert len(uninstall_calls) == 1


def test_cleanup_skips_permission_revoke_when_install_never_succeeded():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        _run({"contacts"})

        assert mocks["_adb_run"].call_count == 1
        assert mocks["_adb_run"].call_args[0][1] == ["install", "-r", mobile.PIF_COMPANION_APK]


def test_stop_requested_before_any_permission_grant_skips_everything_but_still_cleans_up():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Stopped"}

        report_data = _run({"sms", "contacts", "calllog", "calendar", "images", "video"})

        called_verbs = [c.args[1][2] for c in mocks["_adb_run"].call_args_list
                         if len(c.args[1]) > 2 and c.args[1][1] == "pm"]
        assert "grant" not in called_verbs
        assert report_data["acquisition_status"] == "IN_PROGRESS"

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert "status" not in last_call.kwargs


def test_stop_after_one_query_still_reports_completed_not_in_progress():
    """The same asymmetry the Contacts/Call Log worker's own docstring
    already established: a Stop landing AFTER at least one query already
    ran must still report COMPLETED, since real data was already captured,
    never falsely regress to IN_PROGRESS."""
    status_calls = {"n": 0}

    def fake_snapshot():
        # Running for install/grant/first-query, Stopped from then on.
        status_calls["n"] += 1
        return {"status": "Running" if status_calls["n"] <= 3 else "Stopped"}

    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].side_effect = fake_snapshot
        mocks["_record_parsed_artifacts"].return_value = 1

        report_data = _run({"sms", "contacts"})

        assert report_data["acquisition_status"] == "COMPLETED"


def test_only_selected_types_permissions_granted_others_untouched():
    """Selecting only Contacts+Video must never touch SMS/Call Log/
    Calendar permissions at all."""
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"contacts", "video"})

        granted = _pm_calls(mocks, "grant")
        assert "android.permission.READ_CONTACTS" in granted
        assert "android.permission.READ_MEDIA_VIDEO" in granted
        assert "android.permission.READ_SMS" not in granted
        assert "android.permission.READ_CALL_LOG" not in granted
        assert "android.permission.READ_CALENDAR" not in granted


def test_sms_full_tier_assumes_and_restores_default_sms_role():
    with _patched_worker() as mocks:
        def fake_adb_run(serial, args, timeout):
            if args[:4] == ["shell", "cmd", "role", "get-role-holders"]:
                return (0, "com.original.smsapp\n", "")
            return (0, "", "")

        mocks["_adb_run"].side_effect = fake_adb_run
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"sms"}, sms_tier="full")

        add_role_calls = [c.args[1] for c in mocks["_adb_run"].call_args_list
                           if c.args[1][:4] == ["shell", "cmd", "role", "add-role-holder"]]
        assert len(add_role_calls) == 2  # assume, then restore
        assert add_role_calls[0][-1] == mobile.PIF_COMPANION_PACKAGE
        assert add_role_calls[1][-1] == "com.original.smsapp"
        # READ_SMS permission-grant path must NOT have run for the full tier.
        granted = _pm_calls(mocks, "grant")
        assert "android.permission.READ_SMS" not in granted


def test_media_permissions_granted_when_either_images_or_video_selected():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"images"})

        granted = set(_pm_calls(mocks, "grant"))
        assert granted == {"android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                            "android.permission.READ_EXTERNAL_STORAGE"}


def test_full_happy_path_all_six_types_one_combined_record_call():
    """A real end-to-end pass across every data type at once: one
    _record_parsed_artifacts() call combining records from every selected
    type, and per-type counts all correctly reflected in the one combined
    report event."""
    sms_output = ("Row: 0 _id=1, thread_id=1, address=5551234567, date=1700000000000, "
                  "date_sent=1700000000000, type=1, read=1, body=Real SMS")
    contacts_output = ("Row: 0 _id=1, contact_id=5, mimetype=vnd.android.cursor.item/phone_v2, "
                        "data1=+15551234567, data2=2, data3=, display_name=Real Contact")
    calllog_output = ("Row: 0 _id=1, number=5559876543, date=1700000000000, duration=30, "
                       "type=1, numbertype=1, numberlabel=, name=Real Caller")

    def fake_adb_run(serial, args, timeout):
        if args[0] == "shell" and args[1] == "content" and args[2] == "query":
            uri = args[4]
            if uri.endswith(mobile.PIF_COMPANION_SMS_AUTHORITY):
                return (0, sms_output, "")
            if uri.endswith("/data"):
                return (0, contacts_output, "")
            if uri.endswith("/calls"):
                return (0, calllog_output, "")
        return (0, "", "")

    with _patched_worker() as mocks:
        mocks["_adb_run"].side_effect = fake_adb_run
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 3

        report_data = _run({"sms", "contacts", "calllog"})

        assert report_data["acquisition_status"] == "COMPLETED"
        params = report_data["acquisition_parameters"]
        assert params["sms_records_captured"] == 1
        assert params["contact_records_captured"] == 1
        assert params["call_log_records_captured"] == 1

        # Exactly ONE combined _record_parsed_artifacts() call.
        assert mocks["_record_parsed_artifacts"].call_count == 1
        indexed_records = mocks["_record_parsed_artifacts"].call_args[0][2]
        types_seen = {r["artifact_type"] for r in indexed_records}
        assert types_seen == {"android_companion_sms_message", "android_companion_contact",
                               "android_companion_call_log_entry"}


def test_photos_and_video_query_correct_media_uris():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"images", "video"})

        query_uris = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                      if len(c.args[1]) > 4 and c.args[1][1] == "content"]
        assert any(u.endswith("/external/images/media") for u in query_uris)
        assert any(u.endswith("/external/video/media") for u in query_uris)


def test_permission_revoked_and_apk_uninstalled_on_success_only_for_selected_types():
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        _run({"calendar"})

        revoked = _pm_calls(mocks, "revoke")
        assert revoked == ["android.permission.READ_CALENDAR"]

        uninstall_calls = [c.args[1] for c in mocks["_adb_run"].call_args_list if c.args[1][0] == "uninstall"]
        assert len(uninstall_calls) == 1
