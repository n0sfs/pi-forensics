"""routes/mobile.py's execution_worker_android_companion_calendar() - the
non-rooted companion-app Calendar extraction worker (2026-09-04).

Mirrors tests/test_android_companion_contacts_calllog_worker.py's own
established approach exactly: mock the real subprocess/device work
(_adb_run()/update_job()/log_chain_of_custody()/_write_report()/
_record_parsed_artifacts()/_auto_tag_case_artifact()), test control flow
in isolation. The same real bug class those two features' own tests were
written to guard against (log_chain_of_custody() needing explicit
source_ip/user since this worker runs in a background thread with no
Flask request context) is guarded here too, from the start, rather than
being a third bug to find live.

Genuinely simpler than the Contacts/Call Log worker's own test file:
Calendar has no data_types selector (events and their attendees are
always queried together, since an attendee record is meaningless without
its parent event), so there's no permission-isolation test needed the way
Contacts/Call Log's "only grant what was asked for" tests exist for.

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
    """The same real bug class already caught once for the SMS companion
    (and guarded from the start for Contacts/Call Log): this call must
    never rely on log_chain_of_custody()'s own request/g fallback, since
    this worker runs in a background thread with no Flask request
    context."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
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

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
            requester_ip="127.0.0.1", requester_user="local-kiosk",
        )

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert report_data["acquisition_status"] == "FAILED"


def test_cleanup_skips_permission_revoke_when_install_never_succeeded():
    """If install itself fails, READ_CALENDAR was never granted - only the
    one failed install call should have happened, confirming the worker
    correctly tracks apk_installed/calendar_granted rather than blindly
    attempting every cleanup step regardless."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (1, "", "adb: device not found")
        mocks["snapshot_job"].return_value = {"status": "Running"}

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        assert mocks["_adb_run"].call_count == 1
        assert mocks["_adb_run"].call_args[0][1] == ["install", "-r", mobile.PIF_COMPANION_APK]


def test_stop_requested_before_any_query_skips_queries_but_still_cleans_up():
    """Same, already-established convention as the SMS/Contacts-Call-Log
    workers' own identical tests: a genuinely stopped job stays at its
    starting IN_PROGRESS acquisition_status, never falsely marked
    COMPLETED, and the final update_job() call must not overwrite the
    job's own status text (already "Stopped") with a misleading "Failed"."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Stopped"}

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        called_steps = [c.args[1][0] for c in mocks["_adb_run"].call_args_list]
        assert "content" not in called_steps  # neither query step ran
        assert "install" in called_steps      # but install + cleanup still ran

        assert report_data["acquisition_status"] == "IN_PROGRESS"

        last_call = mocks["update_job"].call_args_list[-1]
        assert last_call.kwargs.get("active") is False
        assert "status" not in last_call.kwargs


def test_permission_granted_before_either_query_runs():
    """READ_CALENDAR must be granted once, before both the events and
    attendees queries - not requested per-query or skipped entirely."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        granted_perms = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                          if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == "grant"]
        assert granted_perms == ["android.permission.READ_CALENDAR"]


def test_both_events_and_attendees_queried_against_the_calendar_authority():
    """The full happy-path query sequence - both real content:// URIs
    under the shared pif.companion.calendar authority, events before
    attendees."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        query_uris = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                      if len(c.args[1]) > 4 and c.args[1][1] == "content"]
        assert any(u.endswith("pif.companion.calendar/events") for u in query_uris)
        assert any(u.endswith("pif.companion.calendar/attendees") for u in query_uris)
        # Events queried before attendees, matching the worker's own
        # documented ordering.
        events_idx = next(i for i, u in enumerate(query_uris) if u.endswith("/events"))
        attendees_idx = next(i for i, u in enumerate(query_uris) if u.endswith("/attendees"))
        assert events_idx < attendees_idx


def test_full_happy_path_indexes_real_records_and_reports_completed():
    """A real end-to-end pass, not just a query-shape check: two real
    events (via _adb_run's side_effect distinguishing the events vs.
    attendees query by URI) get correctly parsed, counted, and reported."""
    report_data = _base_report_data()
    events_output = ("Row: 0 _id=1, calendar_id=1, dtstart=1700000000000, dtend=1700003600000, "
                      "eventTimezone=UTC, allDay=0, eventStatus=1, availability=0, "
                      "selfAttendeeStatus=1, organizer=boss@example.com, rrule=, "
                      "title=Real Meeting, eventLocation=HQ, description=Agenda")
    attendees_output = ("Row: 0 event_id=1, attendeeRelationship=1, attendeeType=1, attendeeStatus=1, "
                         "attendeeEmail=real@example.com, attendeeName=Real Attendee")

    def fake_adb_run(serial, args, timeout):
        if len(args) > 4 and args[1] == "content" and args[4].endswith("/events"):
            return (0, events_output, "")
        if len(args) > 4 and args[1] == "content" and args[4].endswith("/attendees"):
            return (0, attendees_output, "")
        return (0, "", "")

    with _patched_worker() as mocks:
        mocks["_adb_run"].side_effect = fake_adb_run
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 1

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["event_records_captured"] == 1
        assert report_data["acquisition_parameters"]["attendee_records_captured"] == 1

        # _record_parsed_artifacts() must have been called with the real,
        # correctly-built event record (attendee folded in, not a
        # separate row).
        indexed_records = mocks["_record_parsed_artifacts"].call_args[0][2]
        assert len(indexed_records) == 1
        assert indexed_records[0]["title"] == "Real Meeting"
        assert len(indexed_records[0]["extra"]["attendees"]) == 1
        assert indexed_records[0]["extra"]["attendees"][0]["name"] == "Real Attendee"


def test_permission_revoked_and_apk_uninstalled_on_success():
    """The full happy-path cleanup sequence."""
    report_data = _base_report_data()
    with _patched_worker() as mocks:
        mocks["_adb_run"].return_value = (0, "", "")
        mocks["snapshot_job"].return_value = {"status": "Running"}
        mocks["_record_parsed_artifacts"].return_value = 0

        mobile.execution_worker_android_companion_calendar(
            "SERIAL123", "/mnt/case/ITEM-01_android_companion_calendar_extraction.json",
            "report_target", report_data, "/mnt/case",
        )

        revoked_perms = [c.args[1][4] for c in mocks["_adb_run"].call_args_list
                          if len(c.args[1]) > 4 and c.args[1][1] == "pm" and c.args[1][2] == "revoke"]
        assert revoked_perms == ["android.permission.READ_CALENDAR"]

        uninstall_calls = [c.args[1] for c in mocks["_adb_run"].call_args_list if c.args[1][0] == "uninstall"]
        assert len(uninstall_calls) == 1
        assert report_data["acquisition_status"] == "COMPLETED"
