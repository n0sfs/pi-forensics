"""A job whose case record cannot be written must say so loudly (2026-09-23).

write_initial_report()/_write_report() used to print() the failure to stdout,
so an acquisition into a case whose JSON was corrupt ran to completion and
then simply never appeared in that case. The warning is now pinned to the top
of the live job log (surviving every worker's wholesale log rewrite) until the
job ends, and recorded durably in the chain-of-custody log.

Skipped (not failed) on a non-POSIX dev machine: core.jobs needs pwd/fcntl.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="core.jobs imports POSIX-only pwd/fcntl")

import core.jobs as jobs


def test_lost_case_write_is_pinned_to_the_log_and_recorded(tmp_path):
    case_dir = tmp_path / "2026-CASE-BROKEN"
    case_dir.mkdir()
    case_file = case_dir / "2026-CASE-BROKEN_case.json"
    case_file.write_text("{not json")
    target = jobs.CaseEventTarget(str(case_file), "evt1")

    with mock.patch("core.paths.log_chain_of_custody") as coc:
        jobs.update_job(active=True, log="[*] starting")
        jobs.write_initial_report(target, {"status": "IN_PROGRESS"})
        # a worker then rebuilds the log from its own buffer, as every worker does
        jobs.update_job(log="[*] imaging 10%")
        log = jobs.snapshot_job()["log"]
        assert "CASE RECORD NOT WRITTEN (job start)" in log
        assert log.endswith("[*] imaging 10%")
        assert coc.call_args[0][0] == "case_record_write_failed"
        # the corrupt file is left exactly as it was
        assert case_file.read_text() == "{not json"

        jobs.update_job(active=False)
        jobs.update_job(log="[*] next job")
        assert "CASE RECORD NOT WRITTEN" not in jobs.snapshot_job()["log"]
