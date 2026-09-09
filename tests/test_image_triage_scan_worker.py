"""routes/image_browser.py's execution_worker_image_triage_scan() - the
second of two execution_worker_* functions found with zero control-flow
test coverage during a 2026-09-09 follow-up sweep to this session's own
10-item execution_worker_* backlog closure (see test_triage_scan_worker.py's
own docstring for how the coverage gap was found - tests/test_scan_
patterns.py only exercises the shared build_scan_patterns()/resolve_scan_
category_label() helper this worker consumes, never the worker's own
control flow).

Mocks the low-level pytsk3 boundary this worker walks through
(_tsk_resolve_filesystems/_tsk_open_fs/_tsk_walk/_tsk_stream_file, all
imported from core.tsk_utils into routes.image_browser's own namespace -
mocked there, not at their original definition site, matching this
project's own already-established "mock where the code actually looks it
up" discipline - see test_image_geolocation_kml_worker.py's own docstring
for the same pattern), plus the case-index SQLite boundary
(case_consolidated_path/case_index_db_path/_case_index_connect). Lets
_tsk_parse_inode (a pure, zero-I/O function) and real regex matching
against TRIAGE_PATTERNS run for real, matching this project's own
established "real logic beats mocking it away" precedent.

A real, previously-hit gotcha specific to THIS worker (not present in the
geolocation-KML worker's own simpler single-pass walk): _tsk_walk(fs) is
called TWICE per filesystem (a cheap counting pass, then the real scanning
pass) - mocking it with a plain return_value=iter([...]) would silently
exhaust the SAME iterator object on the second call, making the scanning
pass see zero entries even though the counting pass worked. Fixed here by
mocking it with a side_effect callable that builds a genuinely fresh
iterator on every call.

Matches the real production calling convention this project has already
been bitten by getting wrong in a test once before: the real route
(start_image_triage_scan()) always captures requester_ip/user in the live
request thread before spawning this worker, so its own log_chain_of_
custody() call (only reached on a non-early-return exit) never falls back
to reading request/g outside a real Flask request - every test that
reaches that line passes explicit, non-None source_ip/user.

Skipped (not failed) on a non-POSIX dev machine: routes.image_browser
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.image_browser as image_browser
from core.jobs import snapshot_job


def _entry(name, is_dir=False, deleted=False, is_virtual=False, size=1000, inode="12",
           mtime=0, atime=0, ctime=0, crtime=0):
    return {
        "name": name, "inode": inode, "is_dir": is_dir, "deleted": deleted,
        "is_virtual": is_virtual, "size": size,
        "mtime": mtime, "atime": atime, "ctime": ctime, "crtime": crtime,
    }


class TestExecutionWorkerImageTriageScan:
    def _run(self, tmp_path, filesystems=None, walk_entries=None, stream_file_side_effect=None,
              source_ip="127.0.0.1", user="test-user", snapshot_side_effect=None,
              open_fs_side_effect=None, keyword_list_ids=None,
              case_consolidated=False):
        image_path = str(tmp_path / "case_ITEM-01.dd")
        (tmp_path / "case_ITEM-01.dd").write_bytes(b"fake image bytes")
        dest_dir = str(tmp_path)
        walk_entries = walk_entries if walk_entries is not None else [_entry("a.txt")]
        filesystems = filesystems if filesystems is not None else [{"offset": 0, "label": "Whole Image"}]

        fake_fs = mock.MagicMock()
        fake_fs.open_meta.return_value = mock.MagicMock()

        def default_stream_file(tsk_file, write_fn, max_bytes=None):
            write_fn(b"contact test@example.com now")

        def fresh_walk_iter(fs):
            # A NEW iterator every call - see this file's own docstring for
            # why a plain return_value would silently break the second
            # (scanning) pass after the first (counting) pass exhausts it.
            return iter([(e, f"/{e['name']}") for e in walk_entries])

        mock_index_conn = mock.MagicMock()

        with mock.patch.object(image_browser, "_tsk_resolve_filesystems", return_value=filesystems), \
             mock.patch.object(image_browser, "_tsk_open_fs",
                                side_effect=open_fs_side_effect if open_fs_side_effect else (lambda p, o: fake_fs)), \
             mock.patch.object(image_browser, "_tsk_walk", side_effect=fresh_walk_iter), \
             mock.patch.object(image_browser, "_tsk_stream_file",
                                side_effect=stream_file_side_effect if stream_file_side_effect else default_stream_file), \
             mock.patch.object(image_browser, "case_consolidated_path",
                                return_value=(str(tmp_path / "case.json") if case_consolidated else None)), \
             mock.patch.object(image_browser, "case_index_db_path", return_value=str(tmp_path / "case_index.db")), \
             mock.patch.object(image_browser, "_case_index_connect", return_value=mock_index_conn), \
             mock.patch.object(image_browser, "log_chain_of_custody") as mock_log:
            if snapshot_side_effect is not None:
                with mock.patch.object(image_browser, "snapshot_job", side_effect=snapshot_side_effect):
                    image_browser.execution_worker_image_triage_scan(
                        image_path, dest_dir, source_ip=source_ip, user=user, keyword_list_ids=keyword_list_ids)
            else:
                image_browser.execution_worker_image_triage_scan(
                    image_path, dest_dir, source_ip=source_ip, user=user, keyword_list_ids=keyword_list_ids)

        return snapshot_job(), dest_dir, image_path, mock_log, mock_index_conn

    def test_no_recognized_filesystem_fails_immediately_and_never_walks_anything(self, tmp_path):
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(tmp_path, filesystems=[])
        assert job["status"] == "Failed"
        assert "No recognized filesystem found" in job["log"]
        mock_log.assert_not_called()

    def test_happy_path_finds_a_real_regex_match_and_writes_a_real_report_file(self, tmp_path):
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("note.txt")],
        )
        assert job["status"] == "Completed Successfully"
        assert job["progress_percent"] == 100.0

        image_base = os.path.splitext(os.path.basename(image_path))[0]
        report_path = os.path.join(dest_dir, f"{image_base}_triage_scan_report.txt")
        assert os.path.isfile(report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test@example.com" in content
        assert "## Email Addresses (1 found)" in content

        mock_log.assert_called_once()
        args, kwargs = mock_log.call_args
        assert args[0] == "image_triage_scan_complete"
        assert args[1]["files_scanned"] == 1
        assert args[1]["total_hits"] == 1
        assert kwargs == {"source_ip": "127.0.0.1", "user": "test-user"}

    def test_directories_and_virtual_entries_are_never_content_scanned(self, tmp_path):
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("subdir", is_dir=True), _entry("$MBR", is_virtual=True)],
        )
        assert job["status"] == "Completed Successfully"
        args, kwargs = mock_log.call_args
        assert args[1]["files_scanned"] == 0  # neither entry was ever content-scanned

    def test_deleted_entries_are_counted_but_never_content_scanned(self, tmp_path):
        # Same reasoning as the app's other deleted-entry-aware tools - a
        # deleted file's data blocks may already be partially overwritten,
        # so it's counted toward files_scanned but its (mocked) content is
        # never regex-matched.
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("gone.txt", deleted=True)],
        )
        assert job["status"] == "Completed Successfully"
        args, kwargs = mock_log.call_args
        assert args[1]["files_scanned"] == 1
        assert args[1]["total_hits"] == 0  # never scanned, so the real "test@example.com" content is never seen

    def test_a_file_that_fails_to_read_is_counted_as_errored_and_the_scan_continues(self, tmp_path):
        def stream_side_effect(tsk_file, write_fn, max_bytes=None):
            raise IOError("simulated corrupt file read")

        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("bad.txt"), _entry("good.txt", inode="13")],
            stream_file_side_effect=stream_side_effect,
        )
        assert job["status"] == "Completed Successfully"
        args, kwargs = mock_log.call_args
        assert args[1]["files_errored"] == 2  # both entries used the same failing side_effect
        assert args[1]["files_scanned"] == 0

    def test_a_stop_during_the_scanning_pass_is_never_falsely_marked_completed_or_failed(self, tmp_path):
        # The outer per-filesystem loop checks snapshot_job() once before
        # ever entering the per-entry walk - it must read Running there or
        # the scan breaks before reaching the walk at all (a different,
        # earlier Stop point than what this test means to exercise). A
        # small stateful counter lets the first call through as Running and
        # every call after it as Stopped, landing the Stop genuinely inside
        # the per-entry walk loop instead.
        calls = {"n": 0}

        def snapshot_side_effect():
            calls["n"] += 1
            return {"status": "Running"} if calls["n"] == 1 else {"status": "Stopped"}

        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("a.txt")],
            snapshot_side_effect=snapshot_side_effect,
        )
        assert job["status"] != "Completed Successfully"
        assert job["status"] != "Failed"
        assert "Scan stopped by user" in job["log"]
        # The report file and the chain-of-custody entry are still written
        # even on a Stop - never silently skipped.
        mock_log.assert_called_once()

    def test_a_filesystem_that_fails_to_open_is_swallowed_and_skipped_not_a_crash(self, tmp_path):
        # _tsk_open_fs is called inside its own per-filesystem
        # try/except continue in both the counting and scanning passes -
        # a failure there is deliberately non-fatal, matching this app's
        # own established "a single bad filesystem/partition shouldn't
        # abort the whole scan" tolerance elsewhere.
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, open_fs_side_effect=RuntimeError("simulated failure - swallowed by the walk's own try/except continue"),
        )
        assert job["status"] == "Completed Successfully"
        args, kwargs = mock_log.call_args
        assert args[1]["files_scanned"] == 0

    def test_a_genuinely_unguarded_exception_is_caught_and_reported_as_failed(self, tmp_path):
        # Unlike _tsk_open_fs above, the case-index SQLite connect step has
        # no inner try/except of its own - a real failure there (a
        # corrupted/locked index database, for instance) has to reach the
        # function's own outer except Exception handler.
        with mock.patch.object(image_browser, "case_consolidated_path", return_value=str(tmp_path / "case.json")), \
             mock.patch.object(image_browser, "case_index_db_path", return_value=str(tmp_path / "case_index.db")), \
             mock.patch.object(image_browser, "_case_index_connect", side_effect=RuntimeError("simulated database connect failure")), \
             mock.patch.object(image_browser, "_tsk_resolve_filesystems", return_value=[{"offset": 0, "label": "Whole Image"}]):
            image_browser.execution_worker_image_triage_scan(
                str(tmp_path / "img.dd"), str(tmp_path), source_ip="127.0.0.1", user="test-user")
        job = snapshot_job()
        assert job["status"] == "Failed"
        assert "Execution Exception" in job["log"]
        assert "simulated database connect failure" in job["log"]

    def test_the_case_index_integration_writes_real_rows_when_a_consolidated_case_is_active(self, tmp_path):
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("note.txt")], case_consolidated=True,
        )
        assert job["status"] == "Completed Successfully"
        mock_index_conn.execute.assert_any_call(
            "DELETE FROM indexed_files WHERE image_path=?", (image_path,))
        mock_index_conn.executemany.assert_called()
        mock_index_conn.close.assert_called_once()
        args, kwargs = mock_log.call_args
        assert args[1]["indexed_files_count"] == 1

    def test_no_active_case_never_touches_the_case_index_at_all(self, tmp_path):
        job, dest_dir, image_path, mock_log, mock_index_conn = self._run(
            tmp_path, walk_entries=[_entry("note.txt")], case_consolidated=False,
        )
        assert job["status"] == "Completed Successfully"
        mock_index_conn.execute.assert_not_called()
        mock_index_conn.executemany.assert_not_called()
        mock_index_conn.close.assert_not_called()

    def test_cleanup_always_sets_active_false_regardless_of_outcome(self, tmp_path):
        for i, snapshot_side_effect in enumerate((None, lambda: {"status": "Stopped"})):
            iter_root = tmp_path / f"iter_{i}"
            iter_root.mkdir()
            self._run(iter_root, walk_entries=[_entry("a.txt")], snapshot_side_effect=snapshot_side_effect)
            assert snapshot_job()["active"] is False
