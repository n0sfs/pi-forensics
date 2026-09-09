"""routes/image_browser.py's execution_worker_materialize_shadow_copy() -
the 8th of 10 execution_worker_* functions found with zero pytest coverage
during a self-directed validation pass (2026-09-09) - see that dated
CLAUDE.md section for the discovery/scoping rationale.

The structurally simplest of the 10 workers - almost all the real logic
lives in core/vshadow_utils.py's materialize_shadow_copy(), mocked here
as the genuine external boundary (a real pyvshadow call this station has
no genuine Volume Shadow Copy sample to exercise against, an already-
disclosed gap that's separate from this worker's own control flow).

A real, deliberate design confirmed by reading BOTH functions before
writing any test, not assumed: unlike every other worker tested so far in
this pass, this one has NO outer try/except Exception wrapping its own
body - if materialize_shadow_copy() itself somehow raised, the exception
would propagate straight out of this worker (only the try/finally's own
`update_job(active=False)` would still run). This is NOT a bug to fix -
materialize_shadow_copy() has its own internal `except Exception as e:
return {"success": False, "error": str(e), ...}` and is documented to
always return a {success, error, bytes_written} dict, never raise, so the
missing outer handler here is a deliberate, correct reliance on that
already-guaranteed callee contract, not an oversight. Locked in with a
dedicated test proving both halves: a genuinely unexpected exception DOES
propagate (this worker offers no safety net of its own), AND the
finally-block cleanup still runs regardless, per normal Python try/finally
semantics.

Skipped (not failed) on a non-POSIX dev machine: routes.image_browser
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.image_browser as image_browser
from core.jobs import snapshot_job


class TestExecutionWorkerMaterializeShadowCopy:
    def _run(self, result, source_ip="127.0.0.1", user="test-user"):
        with mock.patch.object(image_browser, "materialize_shadow_copy", return_value=result) as mock_materialize, \
             mock.patch.object(image_browser, "log_chain_of_custody") as mock_log:
            image_browser.execution_worker_materialize_shadow_copy(
                "/mnt/case/img.dd", 2048, 0, "/mnt/case/shadow0.dd", source_ip=source_ip, user=user)
        return snapshot_job(), mock_materialize, mock_log

    def test_happy_path_completes_and_logs_chain_of_custody_with_the_real_byte_count(self, tmp_path):
        job, mock_materialize, mock_log = self._run(
            {"success": True, "error": None, "bytes_written": 123456},
        )
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0
        assert "123,456 bytes" in job["log"]
        assert "Browse it via File Explorer" in job["log"]

        mock_log.assert_called_once()
        args, kwargs = mock_log.call_args
        assert args[0] == "vss_shadow_copy_materialized"
        assert args[1]["bytes_written"] == 123456
        assert args[1]["store_index"] == 0
        assert kwargs == {"source_ip": "127.0.0.1", "user": "test-user"}

    def test_a_genuine_failure_is_reported_as_failed_and_never_logs_chain_of_custody(self, tmp_path):
        job, mock_materialize, mock_log = self._run(
            {"success": False, "error": "libvshadow-python (pyvshadow) is not installed on this station.", "bytes_written": 0},
        )
        assert job["status"] == "Failed"
        assert "Shadow copy materialization failed" in job["log"]
        assert "pyvshadow" in job["log"]
        mock_log.assert_not_called()  # only the success branch ever logs

    def test_a_stopped_run_is_reported_as_stopped_not_failed(self, tmp_path):
        # materialize_shadow_copy()'s own real error text on a cooperative
        # stop is literally "Stopped by user." - the worker's own
        # case-insensitive "stopped" substring check is what maps this to
        # the distinct Stopped status rather than a generic Failed one.
        job, mock_materialize, mock_log = self._run(
            {"success": False, "error": "Stopped by user.", "bytes_written": 5000},
        )
        assert job["status"] == "Stopped"
        assert "Shadow copy materialization stopped" in job["log"]
        mock_log.assert_not_called()

    def test_materialize_shadow_copy_is_called_with_the_real_positional_arguments_and_real_callables(self, tmp_path):
        job, mock_materialize, mock_log = self._run(
            {"success": True, "error": None, "bytes_written": 1},
        )
        mock_materialize.assert_called_once()
        args, kwargs = mock_materialize.call_args
        assert args == ("/mnt/case/img.dd", 2048, 0, "/mnt/case/shadow0.dd")
        assert callable(kwargs["progress_callback"])
        assert callable(kwargs["should_stop"])
        # The real progress_callback genuinely drives update_job() - not
        # just present, but functional.
        kwargs["progress_callback"](500, 1000)
        assert snapshot_job()["transferred_bytes"] == 500
        assert snapshot_job()["progress_percent"] == 50.0
        # And should_stop() genuinely reflects the real shared job state.
        assert kwargs["should_stop"]() is False

    def test_cleanup_always_sets_active_false_on_both_success_and_failure(self, tmp_path):
        for result in (
            {"success": True, "error": None, "bytes_written": 1},
            {"success": False, "error": "some real failure", "bytes_written": 0},
        ):
            self._run(result)
            assert snapshot_job()["active"] is False

    def test_an_unexpected_exception_from_the_callee_propagates_but_cleanup_still_runs(self, tmp_path):
        # The real, confirmed design this file's own docstring describes:
        # this worker has no try/except of its own, only try/finally - a
        # genuinely unexpected exception (materialize_shadow_copy() itself
        # is documented to never raise one under normal operation) is NOT
        # swallowed here the way every other tested worker's own top-level
        # except Exception would swallow it.
        with mock.patch.object(image_browser, "materialize_shadow_copy", side_effect=RuntimeError("simulated catastrophic failure")), \
             mock.patch.object(image_browser, "log_chain_of_custody"):
            with pytest.raises(RuntimeError, match="simulated catastrophic failure"):
                image_browser.execution_worker_materialize_shadow_copy(
                    "/mnt/case/img.dd", 2048, 0, "/mnt/case/shadow0.dd", source_ip="127.0.0.1", user="test-user")
        # Despite the exception propagating, the finally block's own
        # cleanup still ran - the shared job slot is never left stuck.
        assert snapshot_job()["active"] is False
