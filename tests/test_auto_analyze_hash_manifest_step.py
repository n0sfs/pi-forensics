"""Regression test for a real, previously-shipped bug found during the
2026-09-07 DFIR-tool comparison pass: routes/image_browser.py's
_auto_analyze_step_hash_manifest() called _run_hash_manifest_body(...,
hash_sets={}) with a hardcoded empty dict - meaning an Auto Analyze run's
own Hash Manifest step never actually cross-referenced anything against the
station's configured Hash Sets, even though the standalone
/api/image/hash_manifest route (image_hash_manifest()) already did this
correctly for whatever hash_list_ids an examiner explicitly picked. Since
Auto Analyze has no per-run selection UI, the fix loads every currently-
configured hash set automatically (matching the already-established "check
every configured list automatically, no examiner selection" precedent this
app already uses for URL Lists' own cross-referencing), filtered to sha256
only - the one algorithm this step actually computes.

Skipped (not failed) on a non-POSIX dev machine: routes/image_browser.py
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest
from unittest import mock

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.image_browser as image_browser


def _ok_result():
    return {"success": True, "manifest_path": "/mnt/case/img_hash_manifest_sha256.txt",
            "files_hashed": 10, "files_errored": 0, "truncated": False,
            "hash_list_match_count": 0, "hash_list_matches": []}


def test_hash_manifest_step_loads_every_configured_sha256_hash_set_automatically():
    """The core regression: hash_sets reaching _run_hash_manifest_body() must
    be genuinely non-empty when the station has a configured sha256 set -
    before the fix, this was unconditionally {}."""
    configured = [
        {"id": "badlist1", "name": "Known Bad", "label": "known_bad", "algorithm": "sha256"},
        {"id": "goodlist1", "name": "Known Good", "label": "known_good", "algorithm": "md5"},
    ]
    loaded = {
        "badlist1": {"name": "Known Bad", "label": "known_bad", "algorithm": "sha256", "hashes": {"deadbeef"}},
        "goodlist1": {"name": "Known Good", "label": "known_good", "algorithm": "md5", "hashes": {"cafebabe"}},
    }

    captured = {}

    def fake_run_hash_manifest_body(image_path, dest_dir, algo, hash_sets):
        captured["hash_sets"] = hash_sets
        return _ok_result()

    with mock.patch.object(image_browser, "get_hash_lists", return_value=configured), \
         mock.patch.object(image_browser, "load_hash_list_sets", return_value=loaded) as m_load, \
         mock.patch.object(image_browser, "_run_hash_manifest_body", side_effect=fake_run_hash_manifest_body), \
         mock.patch.object(image_browser, "log_chain_of_custody") as m_log:
        result = image_browser._auto_analyze_step_hash_manifest("/mnt/case/img.dd", "/mnt/case", source_ip="10.0.0.1", user="admin")

    assert result["success"] is True
    # Every configured id was requested, not just a hardcoded/empty selection.
    m_load.assert_called_once_with(["badlist1", "goodlist1"])
    # And the result was filtered to sha256-only before being handed to the
    # real hashing walk - the md5 set must never appear here.
    assert list(captured["hash_sets"].keys()) == ["badlist1"]
    assert captured["hash_sets"]["badlist1"]["algorithm"] == "sha256"
    m_log.assert_called_once()
    assert m_log.call_args.kwargs == {"source_ip": "10.0.0.1", "user": "admin"}


def test_hash_manifest_step_still_works_with_zero_configured_hash_sets():
    """A station with no hash sets configured at all must still run the
    manifest cleanly (an empty dict is the correct, not a broken, input in
    this one case) - the fix must never turn "nothing configured" into a
    crash."""
    with mock.patch.object(image_browser, "get_hash_lists", return_value=[]), \
         mock.patch.object(image_browser, "load_hash_list_sets", return_value={}) as m_load, \
         mock.patch.object(image_browser, "_run_hash_manifest_body", return_value=_ok_result()) as m_body, \
         mock.patch.object(image_browser, "log_chain_of_custody"):
        result = image_browser._auto_analyze_step_hash_manifest("/mnt/case/img.dd", "/mnt/case")

    assert result["success"] is True
    m_load.assert_called_once_with([])
    m_body.assert_called_once_with("/mnt/case/img.dd", "/mnt/case", "sha256", {})


def test_hash_manifest_step_never_logs_on_failure():
    with mock.patch.object(image_browser, "get_hash_lists", return_value=[]), \
         mock.patch.object(image_browser, "load_hash_list_sets", return_value={}), \
         mock.patch.object(image_browser, "_run_hash_manifest_body", return_value={"success": False, "error": "boom"}), \
         mock.patch.object(image_browser, "log_chain_of_custody") as m_log:
        result = image_browser._auto_analyze_step_hash_manifest("/mnt/case/img.dd", "/mnt/case")

    assert result["success"] is False
    m_log.assert_not_called()
