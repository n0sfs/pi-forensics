"""routes/recovery.py's execution_worker_triage_scan() against a FOLDER
source - added 2026-09-16.

The triage scan accepted only a block device or a single file
(`os.path.isfile(source)`), and it is the only place in the app where keyword
lists can be selected at all - Settings' own help text says so. Net effect: no
keyword list could ever be run against a Logical Acquisition, a mobile pull or
a Live Collection import, i.e. against most of what this app produces.
Confirmed live by pointing it at a logical acquisition's own evidence folder:

    Start failed: Source '.../WORKFLOW_SUSPECT_USB' is not a recognized device
    or a valid image file in the permitted evidence directory.

which also mis-stated the reason - the path WAS in the permitted directory.

Uses a real temp folder and the real worker, mocking only the job-state
boundary, matching tests/test_case_bundle_export_worker.py's precedent.

Skipped (not failed) on a non-POSIX dev machine: routes.recovery needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.recovery needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.recovery as recovery


def _seed_folder(tmp_path):
    """A folder shaped like a real logical acquisition: nested, mixed content,
    with the hits split across different files so a per-file scan is the only
    way to find all of them."""
    root = tmp_path / "ITEM-01_logical"
    (root / "Documents").mkdir(parents=True)
    (root / "Downloads").mkdir(parents=True)
    (root / "Documents" / "notes.txt").write_text(
        "Contact: jane@example.com\nCall +15555550172 about the shipment.\n")
    (root / "Downloads" / "receipt.txt").write_text(
        "Sent to dave@example.net\nhttps://example.org/receipt/44\n")
    (root / "empty.bin").write_bytes(b"")
    return root


def _run(source, dest_dir, stopped_after=None):
    report = {"tool": "triage_scan", "acquisition_status": "IN_PROGRESS"}
    calls = {"n": 0}

    def fake_snapshot():
        calls["n"] += 1
        if stopped_after is not None and calls["n"] > stopped_after:
            return {"status": "Stopped"}
        return {"status": "Running"}

    with mock.patch.object(recovery, "update_job"), \
         mock.patch.object(recovery, "clear_active_proc"), \
         mock.patch.object(recovery, "snapshot_job", side_effect=fake_snapshot), \
         mock.patch.object(recovery, "_write_report"):
        recovery.execution_worker_triage_scan(
            str(source), str(dest_dir), str(dest_dir / "report.json"), report, 0)
    return report


def _hits(dest_dir, category):
    path = os.path.join(str(dest_dir), f"{category}.txt")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def test_a_folder_source_scans_every_file_under_it(tmp_path):
    root = _seed_folder(tmp_path)
    dest = tmp_path / "out"
    report = _run(root, dest)

    assert report["acquisition_status"] == "COMPLETED"
    # One hit from each of two different files - proof it did not stop at the
    # first one, and did not need a single flat stream.
    assert sorted(_hits(dest, "emails")) == ["dave@example.net", "jane@example.com"]
    assert _hits(dest, "urls") == ["https://example.org/receipt/44"]


def test_a_folder_source_finds_the_e164_phone_number(tmp_path):
    """Ties the two halves of this fix together: folder scanning is what makes
    keyword lists reachable for this evidence shape, and the widened phone
    pattern is what makes the hit inside it findable."""
    root = _seed_folder(tmp_path)
    dest = tmp_path / "out"
    _run(root, dest)
    assert _hits(dest, "phone_numbers") == ["+15555550172"]


def test_a_folder_scan_records_its_own_coverage(tmp_path):
    """A partial scan that looks complete is the failure worth guarding
    against, so how many files were actually read is part of the result, not
    only a line in a job log the exported report never shows."""
    root = _seed_folder(tmp_path)
    dest = tmp_path / "out"
    report = _run(root, dest)

    coverage = report["triage_scan_coverage"]
    # notes.txt + receipt.txt + empty.bin. The empty one counts: it was opened
    # and read, which is what "scanned" claims.
    assert coverage["files_scanned"] == 3
    assert coverage["files_unreadable"] == 0
    assert coverage["file_limit_reached"] is False


def test_the_file_limit_is_reported_when_it_bites(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, "TRIAGE_FOLDER_MAX_FILES", 2)
    root = _seed_folder(tmp_path)
    dest = tmp_path / "out"
    report = _run(root, dest)

    coverage = report["triage_scan_coverage"]
    assert coverage["file_limit_reached"] is True
    assert coverage["files_scanned"] == 2


def test_a_single_file_source_still_works(tmp_path):
    """The folder branch must be additive - the existing single-file path is
    what every previous scan used."""
    target = tmp_path / "one.txt"
    target.write_text("just jane@example.com here")
    dest = tmp_path / "out"
    report = _run(target, dest)

    assert report["acquisition_status"] == "COMPLETED"
    assert _hits(dest, "emails") == ["jane@example.com"]
    assert "triage_scan_coverage" not in report  # only meaningful for a folder


def test_the_overlap_buffer_does_not_carry_between_two_files(tmp_path):
    """The chunk-overlap buffer exists so a match straddling a chunk boundary
    inside ONE source isn't missed. Carried across two unrelated files it would
    manufacture a match that exists in neither - the reason `tail` is local to
    the per-stream loop."""
    root = tmp_path / "split"
    root.mkdir()
    (root / "a.txt").write_text("the start is jane@exam")
    (root / "b.txt").write_text("ple.com and nothing else")
    dest = tmp_path / "out"
    _run(root, dest)
    assert _hits(dest, "emails") == []


def test_an_unreadable_file_is_counted_not_fatal(tmp_path, monkeypatch):
    root = _seed_folder(tmp_path)
    dest = tmp_path / "out"
    real_open = open

    def flaky_open(path, *args, **kwargs):
        if str(path).endswith("receipt.txt"):
            raise OSError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", flaky_open)
    report = _run(root, dest)

    assert report["acquisition_status"] == "COMPLETED"
    assert report["triage_scan_coverage"]["files_unreadable"] == 1
    # The readable files were still scanned.
    assert "jane@example.com" in _hits(dest, "emails")


# --- Hits reach the case's analysis index (2026-09-16) ---

def test_hits_are_written_into_the_case_analysis_index(tmp_path, evidence_root):
    """This worker is the only one that can use keyword lists, and the one an
    examiner reaches for to scan a whole device or folder - but its results
    lived only in the .txt files it writes. They never reached File Views'
    Keyword Hits tree, the case Overview's counts, or the exported report's
    Analysis Results section. The most thorough scan in the app was the one
    whose findings went nowhere."""
    import json as _json
    import core.case_index_db as case_index_db

    case_dir = os.path.join(evidence_root, "2026-CASE-INDEXED")
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "2026-CASE-INDEXED_case.json"), "w") as f:
        _json.dump({"schema_version": 1, "case_number": "2026-CASE-INDEXED",
                    "case_folder": case_dir, "case_status": "Open", "events": []}, f)

    source = tmp_path / "evidence.txt"
    source.write_text("reach jane@example.com or +15555550172")
    dest = tmp_path / "out"

    report = {"tool": "triage_scan", "acquisition_status": "IN_PROGRESS"}
    with mock.patch.object(recovery, "update_job"), \
         mock.patch.object(recovery, "clear_active_proc"), \
         mock.patch.object(recovery, "snapshot_job", return_value={"status": "Running"}), \
         mock.patch.object(recovery, "_write_report"):
        recovery.execution_worker_triage_scan(
            str(source), str(dest), str(dest / "report.json"), report, 0, None, case_dir)

    findings = case_index_db.collect_case_analysis_findings(case_dir)
    by_cat = {h["category"]: h for h in findings["keyword_hits"]}
    assert by_cat["emails"]["samples"] == ["jane@example.com"]
    assert by_cat["phone_numbers"]["samples"] == ["+15555550172"]


def test_a_scan_with_no_case_still_completes_and_indexes_nothing(tmp_path):
    """Running a job with no active case is a supported workflow - it must not
    become an error just because there is no index to write to."""
    source = tmp_path / "evidence.txt"
    source.write_text("jane@example.com")
    dest = tmp_path / "out"
    report = {"tool": "triage_scan", "acquisition_status": "IN_PROGRESS"}
    with mock.patch.object(recovery, "update_job"), \
         mock.patch.object(recovery, "clear_active_proc"), \
         mock.patch.object(recovery, "snapshot_job", return_value={"status": "Running"}), \
         mock.patch.object(recovery, "_write_report"):
        recovery.execution_worker_triage_scan(
            str(source), str(dest), str(dest / "report.json"), report, 0, None, None)
    assert report["acquisition_status"] == "COMPLETED"
