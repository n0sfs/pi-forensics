"""_case_history_entries()'s case-number match, and the report renderers'
SMART / telemetry honesty (both fixed 2026-09-15).

Two separate defects, tested together because both are the same failure mode:
the exported report stating something the underlying record does not support.

1. _case_history_entries() filtered chain-of-custody entries with a bare
   `case_number in str(value)`. Chain-of-custody details routinely carry full
   paths, so with CASE-1 and CASE-12 on one station every CASE-12 entry
   (case_folder="/mnt/CASE-12") matched CASE-1 - CASE-1's exported Audit Trail
   contained another case's acquisitions, note edits and verification results.
   A purely numeric case number was worse: "2026" matched the %Y%m%d stamp in
   bundle/report filenames.

2. `'PASSED' if drive.get('smart_healthy') else 'FAILING'` rendered a
   three-valued fact as two values, over a source value that DEFAULTED to
   True when no SMART data came back at all. Together those produced both
   errors available: "PASSED" for a USB stick never queried, and "FAILING"
   for a mobile acquisition that has no source_drive_telemetry key at all.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.reporting as reporting
from routes.reporting import _case_history_entries, _format_smart_status, _pdf_cell


def _entries(monkeypatch, *detail_dicts):
    rows = [{"action": f"action_{i}", "details": d} for i, d in enumerate(detail_dicts)]
    monkeypatch.setattr(reporting, "_read_coc_entries", lambda limit=None: list(rows))
    return rows


def test_prefix_case_number_does_not_absorb_the_longer_case(monkeypatch):
    """The original report: CASE-1 claiming CASE-12's activity."""
    _entries(monkeypatch,
             {"case_folder": "/mnt/CASE-1", "image_path": "/mnt/CASE-1/disk.dd"},
             {"case_folder": "/mnt/CASE-12", "image_path": "/mnt/CASE-12/disk.dd"})
    matched = _case_history_entries("CASE-1")
    assert [e["action"] for e in matched] == ["action_0"]

    # ...and the longer case still finds its own, which a naive "require an
    # exact whole-value match" fix would have broken.
    assert [e["action"] for e in _case_history_entries("CASE-12")] == ["action_1"]


def test_numeric_case_number_does_not_match_a_date_stamp(monkeypatch):
    """Case "2026" vs the %Y%m%d-%H%M%S stamp in an exported bundle name."""
    _entries(monkeypatch,
             {"zip_path": "/mnt/OTHER/OTHER_case_bundle_20260915-104233.zip"},
             {"case_folder": "/mnt/2026"})
    assert [e["action"] for e in _case_history_entries("2026")] == ["action_1"]


def test_case_number_still_matches_as_a_filename_prefix(monkeypatch):
    """The legacy flat-file layout this heuristic exists to cover: the case
    number as a filename prefix, delimited by _ or - rather than a path
    separator. Anchoring the match must not break it."""
    _entries(monkeypatch,
             {"image_path": "/mnt/CASE-7_evidence.E01"},
             {"report_path": "/mnt/reports/CASE-7-report.pdf"},
             {"note": "unrelated"})
    assert [e["action"] for e in _case_history_entries("CASE-7")] == ["action_0", "action_1"]


def test_case_history_respects_limit(monkeypatch):
    _entries(monkeypatch, *[{"case_folder": "/mnt/CASE-9"} for _ in range(5)])
    assert len(_case_history_entries("CASE-9", limit=3)) == 3


def test_case_number_with_regex_metacharacters_is_matched_literally(monkeypatch):
    """A case number is free text, so it can contain '.', '+', '(' etc. Those
    must match themselves, not act as regex operators."""
    _entries(monkeypatch,
             {"case_folder": "/mnt/CASE.1"},
             {"case_folder": "/mnt/CASEX1"})
    assert [e["action"] for e in _case_history_entries("CASE.1")] == ["action_0"]


def test_smart_status_not_reported_is_neither_pass_nor_fail():
    """The core of the fix: an unknown is a gap in the record, and must read
    as one. Asserting either PASSED or FAILING here is a claim about hardware
    that was never queried."""
    text = _format_smart_status(None)
    assert "PASSED" not in text
    assert "FAILING" not in text
    assert "not reported" in text.lower()


def test_smart_status_still_reports_real_results():
    assert _format_smart_status(True) == "PASSED"
    assert _format_smart_status(False) == "FAILING"


def test_pdf_cell_marks_a_truncated_value():
    """A fixed-width cell must never cut silently - the reader has no way to
    tell a serial that really is short from one that was trimmed."""
    assert _pdf_cell("WD-WX51A8D9F2C", 8) == "WD-WX51…"
    assert len(_pdf_cell("WD-WX51A8D9F2C", 8)) == 8


def test_pdf_cell_leaves_a_fitting_value_untouched():
    assert _pdf_cell("SHORT", 12) == "SHORT"
    assert _pdf_cell("EXACTLYTWELVE", 13) == "EXACTLYTWELVE"
    assert _pdf_cell(None, 10) == "None"
