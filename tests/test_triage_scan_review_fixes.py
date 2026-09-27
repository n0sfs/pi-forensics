"""Triage scan fixes from the 2026-09-27 review.

- The chunk-boundary overlap re-matched the SUFFIX of a value already found
  in full ("mith@example.com" out of "joe.smith@example.com") - a hit that
  does not exist in the evidence.
- A selected keyword list that was dropped (bad regex, deleted, no terms)
  vanished without trace.

Skipped (not failed) on a non-POSIX dev machine: routes.recovery imports
core.jobs (pwd/fcntl).
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.recovery needs core.jobs, which imports POSIX-only pwd/fcntl")

import core.case_index_db as cidb
import routes.recovery as recovery


def _scan_file(tmp_path, content):
    src = tmp_path / "src.bin"
    src.write_bytes(content)
    dest = tmp_path / "out"
    report_data = {"acquisition_status": "IN_PROGRESS"}
    with mock.patch.object(recovery, "_write_report"),          mock.patch.object(recovery, "clear_active_proc"),          mock.patch.object(recovery, "is_valid_block_device", return_value=False),          mock.patch.object(recovery, "snapshot_job", return_value={"status": "Running"}):
        recovery.execution_worker_triage_scan(str(src), str(dest), str(tmp_path / "r.json"), report_data,
                                              len(content), None)
    emails = (dest / "emails.txt").read_text().split() if (dest / "emails.txt").exists() else []
    return emails, report_data


def test_no_suffix_fragments_are_reported_at_a_chunk_boundary(tmp_path, monkeypatch):
    # Put the address so the 8 MB chunk boundary splits it: the tail then
    # starts mid-token unless it is trimmed to a token boundary.
    chunk = 8 * 1024 * 1024
    addr = b"joe.smith@example.com"
    content = b"x" * (chunk - 12) + b" " + addr + b" trailing text\n"
    emails, _ = _scan_file(tmp_path, content)
    assert "joe.smith@example.com" in emails
    assert not any(e != "joe.smith@example.com" and e.endswith("@example.com") for e in emails), emails


def test_a_dropped_keyword_list_is_recorded(monkeypatch):
    monkeypatch.setattr(cidb, "get_keyword_lists", lambda: [
        {"id": "bad", "name": "Broken", "is_regex": True, "terms": ["(unclosed"]},
        {"id": "empty", "name": "Empty", "terms": []},
    ])
    skipped = []
    patterns = cidb.build_scan_patterns(["bad", "empty", "gone"], skipped_out=skipped)
    assert not any(k.startswith(cidb.KEYWORD_CATEGORY_PREFIX) for k in patterns)
    reasons = {s["id"]: s["reason"] for s in skipped}
    assert set(reasons) == {"bad", "empty", "gone"}
    assert "no longer exists" in reasons["gone"]
