"""core/paths.py's case_status_blocking_new_work() - the guard that stops a
new acquisition landing in a case an examiner has already marked finished.

From a live end-to-end walkthrough (2026-09-16). Nothing anywhere read
case_status except the Active-Cases count tile, so on the real station a case
could be Archived and *still be the active case* afterwards - surviving a full
page reload, with no badge anywhere, its folder pre-filled as the destination
on every tab. A Triage Scan then ran to completion and wrote a second
acquisition event into it:

    status: Archived | events: 2
      - logical_acquisition  ITEM-01       COMPLETED
      - triage_scan          ITEM-01-SCAN  COMPLETED

with no warning at any point.

core/paths.py has no POSIX-only imports, so this runs everywhere.
"""
import json
import os

import pytest

from core.paths import CASE_STATUSES_CLOSED_TO_NEW_WORK, case_status_blocking_new_work


def _make_case(evidence_root, slug, status):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": case_dir,
                   "case_status": status, "events": []}, f)
    return case_dir


@pytest.mark.parametrize("status", CASE_STATUSES_CLOSED_TO_NEW_WORK)
def test_a_finished_case_blocks_new_work_and_names_the_status(evidence_root, status):
    case_dir = _make_case(evidence_root, f"2026-CASE-{status.upper()}", status)
    assert case_status_blocking_new_work(case_dir) == status


@pytest.mark.parametrize("status", ["Open", "In Progress", "In Review", "On Hold"])
def test_an_unfinished_case_does_not_block(evidence_root, status):
    case_dir = _make_case(evidence_root, f"2026-CASE-{status.replace(' ', '')}", status)
    assert case_status_blocking_new_work(case_dir) is None


def test_a_subfolder_of_a_finished_case_is_caught_too(evidence_root):
    """The destination is frequently a subfolder rather than the case root -
    that is still landing evidence in a finished case."""
    case_dir = _make_case(evidence_root, "2026-CASE-SUB", "Archived")
    nested = os.path.join(case_dir, "2026-CASE-SUB_ITEM-01_logical", "deeper")
    os.makedirs(nested, exist_ok=True)
    assert case_status_blocking_new_work(nested) == "Archived"


def test_a_destination_that_is_not_in_any_case_does_not_block(evidence_root):
    """Running a job with no active case writes a flat report into the
    evidence root - a supported workflow, not something to refuse."""
    loose = os.path.join(evidence_root, "loose_output")
    os.makedirs(loose, exist_ok=True)
    assert case_status_blocking_new_work(loose) is None
    assert case_status_blocking_new_work(evidence_root) is None


def test_a_sibling_case_is_never_consulted(evidence_root):
    """Walking up must stop at the case it is actually in - an Archived
    neighbour must not block work on an Open case."""
    _make_case(evidence_root, "2026-CASE-9", "Archived")
    open_case = _make_case(evidence_root, "2026-CASE-90", "Open")
    assert case_status_blocking_new_work(open_case) is None


def test_a_path_outside_the_evidence_root_is_not_consulted(evidence_root, tmp_path):
    """The walk is bounded by EVIDENCE_ROOT so it can never climb out of the
    evidence store looking for a case marker."""
    outside = tmp_path / "somewhere_else"
    outside.mkdir()
    assert case_status_blocking_new_work(str(outside)) is None


def test_an_unreadable_case_file_does_not_block(evidence_root):
    """A guard against a mistake must not become a second way to be unable to
    work. core/jobs.py's CaseFileUnreadable handling is where that condition
    is deliberately surfaced instead."""
    case_dir = os.path.join(evidence_root, "2026-CASE-BROKEN")
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "2026-CASE-BROKEN_case.json"), "w") as f:
        f.write("{not valid json")
    assert case_status_blocking_new_work(case_dir) is None


def test_a_case_file_with_no_status_does_not_block(evidence_root):
    case_dir = os.path.join(evidence_root, "2026-CASE-NOSTATUS")
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "2026-CASE-NOSTATUS_case.json"), "w") as f:
        json.dump({"case_number": "2026-CASE-NOSTATUS"}, f)
    assert case_status_blocking_new_work(case_dir) is None


@pytest.mark.parametrize("bad", [None, "", 123])
def test_a_missing_or_nonsense_destination_is_not_an_error(bad):
    assert case_status_blocking_new_work(bad) is None


def test_closed_case_refusal_checks_every_path_given(evidence_root):
    from core.paths import closed_case_refusal
    closed = _make_case(evidence_root, "2026-CASE-CLOSED-MULTI", "Closed")
    open_out = os.path.join(evidence_root, "loose_output")
    os.makedirs(open_out)
    assert closed_case_refusal(open_out, None) is None
    # output folder outside any case, but the request names a Closed case
    assert closed_case_refusal(open_out, closed) == "Closed"
    # output folder is a SUBFOLDER of the closed case
    sub = os.path.join(closed, "analysis")
    os.makedirs(sub)
    assert closed_case_refusal(sub) == "Closed"
