"""routes/acquisition.py's execution_worker_chained_auto_analyze() - the
Guided Workflow automation Tier 2 orchestrator (2026-08-27) that lets an
acquisition automatically hand off into Auto Analyze's step sequence when
the examiner opted into it up front. Tests the control flow in isolation
(begin/end suppress ordering, the COMPLETED-status gate, the profile ->
steps mapping, and the "undetermined profile" disclosed-skip path) by
mocking execution_worker()/execution_worker_auto_analyze_image()/
classify_image_profile() themselves - the real subprocess/pytsk3 work those
do is already covered by this project's own established "verify live
against real hardware" discipline elsewhere, matching the same precedent
already set for _luks_unlock()/_dislocker_unlock()/_veracrypt_unlock().

Skipped (not failed) on a non-POSIX dev machine: routes/acquisition.py
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest
from unittest import mock

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.acquisition as acquisition


def _base_report_data():
    return {"acquisition_status": "IN_PROGRESS"}


def test_completed_windows_profile_chains_into_auto_analyze_and_never_releases_the_slot_itself():
    report_data = _base_report_data()

    def fake_execution_worker(cmd, fmt, total_bytes, out_file, report_target, rd, hashes):
        rd["acquisition_status"] = "COMPLETED"

    with mock.patch.object(acquisition, "execution_worker", side_effect=fake_execution_worker) as m_worker, \
         mock.patch.object(acquisition, "classify_image_profile", return_value={"profile": "windows", "filesystems": []}) as m_classify, \
         mock.patch.object(acquisition, "execution_worker_auto_analyze_image") as m_analyze, \
         mock.patch.object(acquisition, "begin_suppress_active_false") as m_begin, \
         mock.patch.object(acquisition, "end_suppress_active_false") as m_end, \
         mock.patch.object(acquisition, "update_job") as m_update, \
         mock.patch.object(acquisition, "log_chain_of_custody") as m_log:
        acquisition.execution_worker_chained_auto_analyze(
            ["cmd"], "dd", 1000, "/mnt/case/ITEM-01.dd", "report_target", report_data, ["sha256"],
            "/mnt/case", "1.2.3.4", "examiner1",
        )

    m_begin.assert_called_once()
    m_worker.assert_called_once()
    m_classify.assert_called_once_with("/mnt/case/ITEM-01.dd")
    m_analyze.assert_called_once_with(
        "/mnt/case/ITEM-01.dd", "/mnt/case", acquisition.AUTO_ANALYZE_WINDOWS_DEFAULT_STEPS,
        source_ip="1.2.3.4", user="examiner1",
    )
    # execution_worker_auto_analyze_image() is the last stage - its own
    # internal end_suppress_active_false()/update_job(active=False) is what
    # finishes the chain, so THIS function must not also call them (that
    # would be a real double-release bug, not just redundant).
    m_end.assert_not_called()
    m_update.assert_not_called()
    m_log.assert_not_called()


def test_completed_linux_profile_uses_the_linux_default_steps():
    report_data = _base_report_data()

    def fake_execution_worker(cmd, fmt, total_bytes, out_file, report_target, rd, hashes):
        rd["acquisition_status"] = "COMPLETED"

    with mock.patch.object(acquisition, "execution_worker", side_effect=fake_execution_worker), \
         mock.patch.object(acquisition, "classify_image_profile", return_value={"profile": "linux", "filesystems": []}), \
         mock.patch.object(acquisition, "execution_worker_auto_analyze_image") as m_analyze, \
         mock.patch.object(acquisition, "begin_suppress_active_false"), \
         mock.patch.object(acquisition, "end_suppress_active_false") as m_end, \
         mock.patch.object(acquisition, "update_job") as m_update, \
         mock.patch.object(acquisition, "log_chain_of_custody"):
        acquisition.execution_worker_chained_auto_analyze(
            ["cmd"], "dd", 1000, "/mnt/case/ITEM-01.dd", "report_target", report_data, ["sha256"],
            "/mnt/case", None, None,
        )

    m_analyze.assert_called_once_with(
        "/mnt/case/ITEM-01.dd", "/mnt/case", acquisition.AUTO_ANALYZE_LINUX_DEFAULT_STEPS,
        source_ip=None, user=None,
    )
    m_end.assert_not_called()
    m_update.assert_not_called()


@pytest.mark.parametrize("final_status", ["FAILED", "IN_PROGRESS"])  # IN_PROGRESS == the job was Stopped mid-run (acquisition_status is never literally set to "STOPPED", see execution_worker()'s own real behavior)
def test_non_completed_acquisition_never_chains_and_releases_the_slot_itself(final_status):
    report_data = _base_report_data()

    def fake_execution_worker(cmd, fmt, total_bytes, out_file, report_target, rd, hashes):
        rd["acquisition_status"] = final_status

    with mock.patch.object(acquisition, "execution_worker", side_effect=fake_execution_worker), \
         mock.patch.object(acquisition, "classify_image_profile") as m_classify, \
         mock.patch.object(acquisition, "execution_worker_auto_analyze_image") as m_analyze, \
         mock.patch.object(acquisition, "begin_suppress_active_false") as m_begin, \
         mock.patch.object(acquisition, "end_suppress_active_false") as m_end, \
         mock.patch.object(acquisition, "update_job") as m_update, \
         mock.patch.object(acquisition, "log_chain_of_custody") as m_log:
        acquisition.execution_worker_chained_auto_analyze(
            ["cmd"], "dd", 1000, "/mnt/case/ITEM-01.dd", "report_target", report_data, ["sha256"],
            "/mnt/case", "1.2.3.4", "examiner1",
        )

    m_begin.assert_called_once()
    m_classify.assert_not_called()  # never even attempted - nothing to analyze
    m_analyze.assert_not_called()
    m_log.assert_not_called()  # this isn't the "profile undetermined" disclosed-skip path
    # This function's OWN safety net must fire, since execution_worker()'s
    # own update_job(active=False) was suppressed by begin_suppress_active_false()
    # above and never got a chance to actually release the slot.
    m_end.assert_called_once()
    m_update.assert_called_once_with(active=False)


def test_undetermined_profile_is_a_disclosed_skip_not_a_silent_guess():
    report_data = _base_report_data()

    def fake_execution_worker(cmd, fmt, total_bytes, out_file, report_target, rd, hashes):
        rd["acquisition_status"] = "COMPLETED"

    for undetermined_profile in ["unknown", "mixed", "ambiguous", None]:
        with mock.patch.object(acquisition, "execution_worker", side_effect=fake_execution_worker), \
             mock.patch.object(acquisition, "classify_image_profile", return_value={"profile": undetermined_profile, "filesystems": []}), \
             mock.patch.object(acquisition, "execution_worker_auto_analyze_image") as m_analyze, \
             mock.patch.object(acquisition, "begin_suppress_active_false"), \
             mock.patch.object(acquisition, "end_suppress_active_false") as m_end, \
             mock.patch.object(acquisition, "update_job") as m_update, \
             mock.patch.object(acquisition, "log_chain_of_custody") as m_log:
            report_data["acquisition_status"] = "IN_PROGRESS"  # reset between iterations
            acquisition.execution_worker_chained_auto_analyze(
                ["cmd"], "dd", 1000, "/mnt/case/ITEM-01.dd", "report_target", report_data, ["sha256"],
                "/mnt/case", "1.2.3.4", "examiner1",
            )

        m_analyze.assert_not_called()
        m_end.assert_called_once()
        # A real, visible audit-log entry, not silence - matches Auto
        # Analyze's own detect route never guessing at an uncertain profile.
        m_log.assert_called_once()
        assert m_log.call_args[0][0] == "chained_auto_analyze_skipped"
        assert m_log.call_args[0][1]["image_path"] == "/mnt/case/ITEM-01.dd"
        # A real, visible status update too, not just the audit log.
        status_calls = [c for c in m_update.call_args_list if "status" in c.kwargs]
        assert any("skipped" in c.kwargs["status"] for c in status_calls)
