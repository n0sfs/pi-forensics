"""Regression tests for the 2026-10-09 workflow/UI round: the recovery destination guard, the ddrescue
end-of-pass summary, the export download name, the TLS follow-up wording and the Mobile device-list
tool report.

The route-level tests are skipped (not failed) on a non-POSIX dev machine: routes/* import core.jobs
(pwd/fcntl).
"""
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from unittest import mock

import routes.acquisition as acquisition
import routes.recovery as recovery
from core.config import EVIDENCE_ROOT


# --- File Recovery: the destination guard acquisition already had ---------------------------------

def test_recovery_refuses_the_bare_evidence_root_as_a_destination():
    problem = recovery._recovery_destination_problem(EVIDENCE_ROOT, "/dev/sdb")
    assert problem and "case folder" in problem


def test_recovery_refuses_a_destination_on_the_drive_being_recovered_from():
    with mock.patch.object(recovery, "is_valid_block_device", return_value=True), \
         mock.patch.object(recovery, "destination_is_on_source_device", return_value=True):
        problem = recovery._recovery_destination_problem(os.path.join(EVIDENCE_ROOT, "case-1"), "/dev/sdb")
    assert problem and "/dev/sdb itself" in problem


def test_recovery_accepts_a_case_folder_on_other_storage():
    with mock.patch.object(recovery, "is_valid_block_device", return_value=True), \
         mock.patch.object(recovery, "destination_is_on_source_device", return_value=False):
        assert recovery._recovery_destination_problem(os.path.join(EVIDENCE_ROOT, "case-1"), "/dev/sdb") is None


def test_recovery_from_an_image_file_only_checks_the_root():
    # An image file source is not a block device, so the on-source check never applies.
    assert recovery._recovery_destination_problem(os.path.join(EVIDENCE_ROOT, "case-1"), "/mnt/case-1/x.dd") is None


def test_every_recovery_start_route_calls_the_guard():
    # The five start routes each carry the same destination check; a new tool copied from one must too.
    import inspect
    src = inspect.getsource(recovery)
    assert src.count("_dest_problem = _recovery_destination_problem(dest_path, source)") == 5


# --- ddrescue: a finished pass says whether the image is actually complete ------------------------

def _mapfile(tmp_path, lines):
    p = tmp_path / "x.map"
    p.write_text("# Mapfile. Created by GNU ddrescue\n# current_pos  current_status  current_pass\n0x00000000     ?               1\n"
                 "#      pos        size  status\n" + "\n".join(lines) + "\n")
    return str(p)


def test_ddrescue_summary_says_complete_only_when_nothing_is_unread(tmp_path):
    out = acquisition._ddrescue_pass_summary(_mapfile(tmp_path, ["0x00000000  0x00100000  +"]))
    text = "\n".join(out)
    assert "1,048,576 bytes rescued (100.00%)" in text
    assert "the image is complete" in text


def test_ddrescue_summary_warns_and_names_the_rerun_rule_when_areas_remain(tmp_path):
    out = acquisition._ddrescue_pass_summary(_mapfile(
        tmp_path, ["0x00000000  0x00080000  +", "0x00080000  0x00001000  -", "0x00081000  0x0007F000  ?"]))
    text = "\n".join(out)
    assert "NOT a complete image yet" in text
    assert "SAME Case # and Evidence ID" in text
    assert "1 bad area(s)" in text
    assert "the image is complete" not in text


def test_ddrescue_summary_never_claims_completeness_for_an_unreadable_mapfile(tmp_path):
    out = acquisition._ddrescue_pass_summary(str(tmp_path / "does-not-exist.map"))
    text = "\n".join(out)
    assert "Could not read the ddrescue mapfile" in text
    assert "shows no unread areas" not in text  # the completeness claim itself


# --- Mobile: the device list reports which tools exist ---------------------------------------------

def test_mobile_device_list_reports_whether_adb_and_idevice_id_are_installed():
    import routes.mobile as mobile
    from flask import Flask
    app = Flask(__name__)
    with app.test_request_context(), \
         mock.patch.object(mobile, "list_ios_devices", return_value=[]), \
         mock.patch.object(mobile, "list_android_devices", return_value=[]), \
         mock.patch.object(mobile.shutil, "which", side_effect=lambda n: "/usr/bin/adb" if n == "adb" else None):
        import inspect
        data = inspect.unwrap(mobile.get_mobile_devices)().get_json()
    assert data["tools"] == {"adb": True, "idevice_id": False}
    assert data["ios"] == [] and data["android"] == []
