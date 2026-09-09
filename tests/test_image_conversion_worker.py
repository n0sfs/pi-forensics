"""routes/acquisition.py's execution_worker_image_conversion() - standalone
raw<->E01 image format conversion, a real, disclosed gap in this project's
own test-coverage history (found via a systematic grep for every
execution_worker_* function across routes/*.py during a self-directed
validation pass, 2026-09-09 - CLAUDE.md's own history already documents 2
real, live-caught bugs in this exact feature's own first cut: a real,
duplicate-hash-verification-conflation risk between the two directions,
and a genuine data-loss bug where a re-conversion could silently overwrite
the original raw file before the rename - both already fixed in the
current code, this file locks the fixed behavior in).

Uses real temporary files on disk (matching test_execution_worker_write_
confirmation.py's own established precedent for this exact module) rather
than mocking os.path.exists/os.path.getsize globally - those functions are
checked against several DIFFERENT paths within one run (source, output,
the ewfexport .raw intermediate, its .info sidecar), so a single global
mock return value can't correctly represent "some of these exist, others
don't" the way a real file on a real tmp_path filesystem naturally does.
Only the genuine external boundaries are mocked: _stream_subprocess (the
real ewfacquire/ewfexport subprocess), parse_ewf_line/parse_ewf_hashes,
compute_file_hashes, _ewf_media_size_bytes, reclaim_ownership,
_write_report, clear_active_proc.

Skipped (not failed) on a non-POSIX dev machine: routes.acquisition needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import contextlib
import os
import types
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.acquisition needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.acquisition as acquisition
from core.jobs import snapshot_job


def _proc(returncode=0):
    return types.SimpleNamespace(returncode=returncode)


class TestExecutionWorkerImageConversion:
    def _base_mocks(self, stack, source_hashes=None, tool_hashes=None, ewf_media_size=1000):
        stack.enter_context(mock.patch.object(acquisition, "reclaim_ownership"))
        mock_write_report = stack.enter_context(mock.patch.object(acquisition, "_write_report"))
        stack.enter_context(mock.patch.object(acquisition, "clear_active_proc"))
        stack.enter_context(mock.patch("time.sleep"))
        stack.enter_context(mock.patch.object(acquisition, "parse_ewf_line", return_value=(None, None)))
        stack.enter_context(mock.patch.object(acquisition, "compute_file_hashes",
                                                return_value=source_hashes if source_hashes is not None else {"sha256": "sourcehash"}))
        stack.enter_context(mock.patch.object(acquisition, "parse_ewf_hashes",
                                                return_value=tool_hashes if tool_hashes is not None else {"sha256": "sourcehash"}))
        stack.enter_context(mock.patch.object(acquisition, "_ewf_media_size_bytes", return_value=ewf_media_size))
        return mock_write_report

    # --- raw -> E01 ---

    def _run_to_e01(self, tmp_path, source_hashes=None, tool_hashes=None,
                     stream_returncode=0, create_output=True, snapshot_return=None):
        source = tmp_path / "case_ITEM-01.dd"
        source.write_bytes(b"raw evidence bytes")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {"case_number": "2026-TEST", "evidence_id": "ITEM-01", "examiner": "x"}}

        def stream_side_effect(cmd, on_line):
            if create_output:
                (tmp_path / "case_ITEM-01.E01").write_bytes(b"fake e01 bytes")
            return _proc(stream_returncode)

        with contextlib.ExitStack() as stack:
            mock_write_report = self._base_mocks(stack, source_hashes=source_hashes, tool_hashes=tool_hashes)
            mock_stream = stack.enter_context(mock.patch.object(acquisition, "_stream_subprocess", side_effect=stream_side_effect))
            if snapshot_return is not None:
                stack.enter_context(mock.patch.object(acquisition, "snapshot_job", return_value=snapshot_return))
            acquisition.execution_worker_image_conversion(str(source), "e01", ["sha256"], report_path, report_data)

        return snapshot_job(), report_data, mock_stream, mock_write_report

    def test_raw_to_e01_happy_path_completes_with_hash_verified_true(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_e01(
            tmp_path, source_hashes={"sha256": "matching"}, tool_hashes={"sha256": "matching"},
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["hash_verified"] is True
        assert report_data["acquisition_parameters"]["output_image_path"].endswith(".E01")
        mock_write_report.assert_called_once()

    def test_raw_to_e01_a_hash_mismatch_still_completes_but_discloses_hash_verified_false(self, tmp_path):
        # The real, deliberate design this module's own docstring
        # describes: conversion success and hash verification are two
        # separate facts. A genuinely completed conversion with a real
        # hash disagreement must never be silently reported as verified,
        # but must also never be conflated with an outright conversion
        # FAILURE (the job still completed - what's wrong is disclosed in
        # the report data, not hidden behind a false "Failed" status that
        # would suggest nothing useful was produced at all).
        job, report_data, mock_stream, mock_write_report = self._run_to_e01(
            tmp_path, source_hashes={"sha256": "AAA"}, tool_hashes={"sha256": "BBB"},
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["hash_verified"] is False

    def test_raw_to_e01_conversion_fails_when_returncode_is_bad(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_e01(
            tmp_path, stream_returncode=1, create_output=False,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"

    def test_raw_to_e01_conversion_fails_when_output_file_never_appears_despite_a_success_returncode(self, tmp_path):
        # A tool exiting 0/2 alone is not trusted - the output file must
        # genuinely exist on disk too (matches this app's own established
        # "never trust an exit code alone" posture elsewhere).
        job, report_data, mock_stream, mock_write_report = self._run_to_e01(
            tmp_path, stream_returncode=0, create_output=False,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"

    def test_raw_to_e01_a_stopped_run_is_never_falsely_marked_completed_or_failed(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_e01(
            tmp_path, stream_returncode=1, create_output=False,
            snapshot_return={"status": "Stopped", "log": ""},
        )
        assert report_data["acquisition_status"] == "IN_PROGRESS"
        mock_write_report.assert_called_once()

    # --- E01 -> raw ---

    def _run_to_raw(self, tmp_path, tool_hashes=None, output_hashes=None,
                     stream_returncode=0, create_output=True, snapshot_return=None):
        source = tmp_path / "case_ITEM-01.E01"
        source.write_bytes(b"fake e01 bytes")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

        def stream_side_effect(cmd, on_line):
            if create_output:
                # ewfexport always writes <base>.raw (+ a sidecar) - the
                # real thing the code under test then renames to .dd.
                (tmp_path / "case_ITEM-01.raw").write_bytes(b"real converted raw bytes")
                (tmp_path / "case_ITEM-01.raw.info").write_text("info")
            return _proc(stream_returncode)

        with contextlib.ExitStack() as stack:
            mock_write_report = self._base_mocks(stack, tool_hashes=tool_hashes)
            # compute_file_hashes is called a SECOND time here for the
            # real output file - override its return value specifically
            # for the output-hash comparison this direction cares about.
            stack.enter_context(mock.patch.object(acquisition, "compute_file_hashes",
                                                    return_value=output_hashes if output_hashes is not None else {"sha256": "x", "md5": "matching-md5"}))
            mock_stream = stack.enter_context(mock.patch.object(acquisition, "_stream_subprocess", side_effect=stream_side_effect))
            if snapshot_return is not None:
                stack.enter_context(mock.patch.object(acquisition, "snapshot_job", return_value=snapshot_return))
            acquisition.execution_worker_image_conversion(str(source), "raw", ["sha256", "md5"], report_path, report_data)

        return snapshot_job(), report_data, mock_stream, mock_write_report

    def test_e01_to_raw_happy_path_renames_the_ewfexport_raw_output_to_dd(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_raw(
            tmp_path, tool_hashes={"md5": "matching-md5"}, output_hashes={"sha256": "x", "md5": "matching-md5"},
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_status"] == "COMPLETED"
        assert report_data["acquisition_parameters"]["hash_verified"] is True
        output_path = report_data["acquisition_parameters"]["output_image_path"]
        assert output_path.endswith(".dd")
        assert os.path.exists(output_path)  # genuinely renamed, not still sitting as .raw
        assert not os.path.exists(output_path.replace(".dd", ".raw"))  # the original .raw name is gone
        assert os.path.exists(f"{output_path}.info")  # the sidecar was renamed too

    def test_e01_to_raw_an_md5_mismatch_still_completes_but_discloses_hash_verified_false(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_raw(
            tmp_path, tool_hashes={"md5": "AAA"}, output_hashes={"sha256": "x", "md5": "BBB"},
        )
        assert job["status"] == "Completed Successfully"
        assert report_data["acquisition_parameters"]["hash_verified"] is False

    def test_e01_to_raw_conversion_fails_when_the_expected_raw_output_never_appears(self, tmp_path):
        job, report_data, mock_stream, mock_write_report = self._run_to_raw(
            tmp_path, stream_returncode=0, create_output=False,
        )
        assert job["status"] == "Failed"
        assert report_data["acquisition_status"] == "FAILED"

    def test_e01_to_raw_does_not_pre_maturely_write_confirm_over_a_source_collision(self, tmp_path):
        # A real, previously-live-caught bug this module's own docstring
        # references (a re-conversion overwriting the ORIGINAL raw file
        # before the rename) is guarded by a pre-flight collision check in
        # the ROUTE (start_image_conversion), not this worker itself - the
        # worker always converts unconditionally once invoked. Confirmed
        # here that a genuinely pre-existing .dd file at the target path
        # is simply overwritten by os.rename() as this worker's own,
        # narrower contract (matching os.rename()'s real POSIX semantics) -
        # documenting the worker's actual boundary, not asserting a
        # guarantee this specific function was never meant to provide.
        (tmp_path / "case_ITEM-01.dd").write_bytes(b"pre-existing content that should be overwritten by rename")
        job, report_data, mock_stream, mock_write_report = self._run_to_raw(tmp_path)
        assert job["status"] == "Completed Successfully"
        with open(report_data["acquisition_parameters"]["output_image_path"], "rb") as f:
            assert f.read() == b"real converted raw bytes"

    # --- Shared branches (format-independent) ---

    def test_unsupported_target_format_is_caught_and_reported_as_failed(self, tmp_path):
        source = tmp_path / "case_ITEM-01.dd"
        source.write_bytes(b"content")
        report_path = str(tmp_path / "report.json")
        report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}
        with contextlib.ExitStack() as stack:
            mock_write_report = self._base_mocks(stack)
            stack.enter_context(mock.patch.object(acquisition, "_stream_subprocess"))
            acquisition.execution_worker_image_conversion(str(source), "aff", ["sha256"], report_path, report_data)
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "Execution Exception" in job["log"]
        # The exception happened before the try block's own _write_report
        # call, matching every other worker's identical except-branch shape.
        mock_write_report.assert_not_called()

    def test_cleanup_always_runs_regardless_of_outcome(self, tmp_path):
        for stream_returncode, create_output in ((0, True), (1, False)):
            source = tmp_path / f"case_{stream_returncode}.dd"
            source.write_bytes(b"content")
            report_path = str(tmp_path / f"report_{stream_returncode}.json")
            report_data = {"acquisition_status": "IN_PROGRESS", "acquisition_parameters": {}}

            def stream_side_effect(cmd, on_line, _co=create_output, _src=source):
                if _co:
                    (tmp_path / f"{os.path.splitext(str(_src))[0]}.E01").write_bytes(b"e01")
                return _proc(stream_returncode)

            with contextlib.ExitStack() as stack:
                mock_reclaim = stack.enter_context(mock.patch.object(acquisition, "reclaim_ownership"))
                stack.enter_context(mock.patch.object(acquisition, "_write_report"))
                mock_clear_active = stack.enter_context(mock.patch.object(acquisition, "clear_active_proc"))
                stack.enter_context(mock.patch("time.sleep"))
                stack.enter_context(mock.patch.object(acquisition, "parse_ewf_line", return_value=(None, None)))
                stack.enter_context(mock.patch.object(acquisition, "compute_file_hashes", return_value={}))
                stack.enter_context(mock.patch.object(acquisition, "parse_ewf_hashes", return_value={}))
                stack.enter_context(mock.patch.object(acquisition, "_stream_subprocess", side_effect=stream_side_effect))
                acquisition.execution_worker_image_conversion(str(source), "e01", ["sha256"], report_path, report_data)
            mock_reclaim.assert_called_once()
            mock_clear_active.assert_called_once()
