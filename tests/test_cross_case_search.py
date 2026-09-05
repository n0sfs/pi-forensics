"""core/case_index_db.py's list_case_folders() (factored out of routes/
case_management.py's list_cases() as a pure code motion once
cross_case_hash_search() below became a 2nd caller) and
cross_case_hash_search() (2026-08-26, gap-closing round) - "has this hash
shown up in any OTHER case on this station?", scoped to exact hash-lookup
across every case's own case JSON.

No pytest.importorskip guard needed - confirmed core/case_index_db.py
itself imports no POSIX-only module (unlike routes/case_management.py,
which needs core.jobs -> pwd/fcntl), matching test_case_index_db.py's own
existing (guard-free) precedent.
"""
import json
import os

import core.case_index_db as case_index_db


def _write_consolidated_case(evidence_root, slug, case_number, examiner, created_at, events):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, f"{slug}_case.json"), 'w') as f:
        json.dump({
            "schema_version": 1, "case_number": case_number, "examiner": examiner,
            "case_folder": case_dir, "created_at": created_at, "notes": "", "events": events,
        }, f)
    return case_dir


def _write_legacy_case(evidence_root, slug, case_number):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, "case_info.json"), 'w') as f:
        json.dump({"case_number": case_number, "examiner": "x", "created_at": "2026-01-01"}, f)
    return case_dir


def _redirect_evidence_root(monkeypatch, evidence_root):
    """list_case_folders() reads config.EVIDENCE_ROOT module-qualified -
    redirect that directly (the shared evidence_root fixture only patches
    core.paths.EVIDENCE_ROOT, a separate binding, which safe_path() itself
    relies on but list_case_folders()'s own os.walk() does not)."""
    import core.config as config
    monkeypatch.setattr(config, "EVIDENCE_ROOT", evidence_root)


def test_list_case_folders_finds_consolidated_and_legacy_cases(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Alice", "2026-01-02 00:00:00", [])
    _write_legacy_case(evidence_root, "2026-CASE-B", "2026-CASE-B")
    cases = case_index_db.list_case_folders()
    schemas = {c['case_number']: c['schema'] for c in cases}
    assert schemas == {"2026-CASE-A": "consolidated", "2026-CASE-B": "legacy"}


def test_list_case_folders_sorts_newest_created_first(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-OLD", "2026-CASE-OLD", "x", "2026-01-01 00:00:00", [])
    _write_consolidated_case(evidence_root, "2026-CASE-NEW", "2026-CASE-NEW", "x", "2026-06-01 00:00:00", [])
    cases = case_index_db.list_case_folders()
    assert [c['case_number'] for c in cases] == ["2026-CASE-NEW", "2026-CASE-OLD"]


def test_list_case_folders_tolerates_a_corrupt_case_json(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    good_dir = _write_consolidated_case(evidence_root, "2026-CASE-GOOD", "2026-CASE-GOOD", "x", "2026-01-01", [])
    bad_dir = os.path.join(evidence_root, "2026-CASE-BAD")
    os.makedirs(bad_dir)
    with open(os.path.join(bad_dir, "2026-CASE-BAD_case.json"), 'w') as f:
        f.write("{ not valid json")
    cases = case_index_db.list_case_folders()
    assert [c['case_number'] for c in cases] == ["2026-CASE-GOOD"]


def test_list_case_folders_prunes_bulk_tool_output_dirs_without_missing_real_cases(evidence_root, monkeypatch):
    """A real, live-caught performance bug (2026-09-05): loose recovery-
    tool output sitting directly under the evidence root (never a case,
    never containing one) was being fully walked on every single call, a
    real, avoidable NFS round-trip cost on the deployed station. Proven the
    strong way, not just "the final case list looks right": os.walk() must
    never even be given the chance to descend into the pruned directory's
    own subtree - confirmed here by planting a case-shaped marker file one
    level INSIDE a bulk-tool-output-named directory and asserting it's
    never found, which would only happen if pruning genuinely stopped
    os.walk() before it got there."""
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-REAL", "2026-CASE-REAL", "x", "2026-01-01", [])

    # A real recovery-tool output dir, with something case-shaped hidden
    # one level inside it - if pruning didn't work, os.walk() would find
    # and report this as a bogus extra case.
    junk_dir = os.path.join(evidence_root, "2026-CASE-REAL_ITEM-01_photorec")
    nested = os.path.join(junk_dir, "recup_dir.1")
    os.makedirs(nested)
    with open(os.path.join(nested, "recup_dir.1_case.json"), 'w') as f:
        json.dump({"case_number": "SHOULD-NEVER-BE-FOUND", "case_folder": nested,
                    "created_at": "2026-01-01", "events": []}, f)

    # A NAS-internal recycle-bin folder, same trap.
    recycle_dir = os.path.join(evidence_root, "#recycle")
    os.makedirs(os.path.join(recycle_dir, "some_deleted_case"))
    with open(os.path.join(recycle_dir, "some_deleted_case", "some_deleted_case_case.json"), 'w') as f:
        json.dump({"case_number": "ALSO-SHOULD-NEVER-BE-FOUND", "case_folder": recycle_dir,
                    "created_at": "2026-01-01", "events": []}, f)

    cases = case_index_db.list_case_folders()
    assert [c['case_number'] for c in cases] == ["2026-CASE-REAL"]


def test_list_case_folders_still_finds_a_case_nested_inside_a_mounted_share(evidence_root, monkeypatch):
    """Guards against the naive, unsafe alternative fix (reducing the
    depth-6 cap instead of pruning by name) - create_case() accepts an
    arbitrary parent_dir, so a real case can legitimately be nested 2+
    levels deep (e.g. one level inside a mounted network share, exactly
    this app's own real deployed shape). Confirms the bulk-tool-output
    pruning above didn't come at the cost of this still-supported
    scenario."""
    _redirect_evidence_root(monkeypatch, evidence_root)
    mounted_share = os.path.join(evidence_root, "network_nfs_some_share")
    os.makedirs(mounted_share)
    _write_consolidated_case(mounted_share, "2026-CASE-NESTED", "2026-CASE-NESTED", "x", "2026-01-01", [])
    cases = case_index_db.list_case_folders()
    assert [c['case_number'] for c in cases] == ["2026-CASE-NESTED"]


def test_cross_case_hash_search_finds_a_real_match_in_a_different_case(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "Alice", "2026-01-01", [
        {"tool": "dd", "case_metadata": {"evidence_id": "USB-1"},
         "acquisition_status": "COMPLETED",
         "computed_verification_hashes": {"sha256": "abc123deadbeef"}},
    ])
    _write_consolidated_case(evidence_root, "2026-CASE-B", "2026-CASE-B", "Bob", "2026-01-02", [
        {"tool": "dd", "case_metadata": {"evidence_id": "USB-2"},
         "acquisition_status": "COMPLETED",
         "computed_verification_hashes": {"sha256": "abc123deadbeef"}},
    ])
    results, truncated = case_index_db.cross_case_hash_search("abc123deadbeef")
    assert truncated is False
    assert len(results) == 2
    case_numbers = {r['case_number'] for r in results}
    assert case_numbers == {"2026-CASE-A", "2026-CASE-B"}
    assert all(r['algorithm'] == 'sha256' for r in results)


def test_cross_case_hash_search_is_case_insensitive(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "x", "2026-01-01", [
        {"tool": "dd", "acquisition_status": "COMPLETED",
         "computed_verification_hashes": {"md5": "ABCDEF1234567890"}},
    ])
    results, truncated = case_index_db.cross_case_hash_search("abcdef1234567890")
    assert len(results) == 1


def test_cross_case_hash_search_returns_empty_for_no_match(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "x", "2026-01-01", [
        {"tool": "dd", "acquisition_status": "COMPLETED",
         "computed_verification_hashes": {"sha256": "real-hash-here"}},
    ])
    results, truncated = case_index_db.cross_case_hash_search("completely-different-hash")
    assert results == []
    assert truncated is False


def test_cross_case_hash_search_ignores_legacy_cases_and_empty_query(evidence_root, monkeypatch):
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_legacy_case(evidence_root, "2026-CASE-LEGACY", "2026-CASE-LEGACY")
    results, truncated = case_index_db.cross_case_hash_search("anything")
    assert results == []
    results2, truncated2 = case_index_db.cross_case_hash_search("")
    assert results2 == []
    assert truncated2 is False


def test_cross_case_hash_search_skips_events_with_empty_hash_dict(evidence_root, monkeypatch):
    # Mirrors this app's own already-documented real bug (a past E01
    # acquisition could reach COMPLETED with computed_verification_hashes
    # == {}) - must never crash or false-match on an empty dict.
    _redirect_evidence_root(monkeypatch, evidence_root)
    _write_consolidated_case(evidence_root, "2026-CASE-A", "2026-CASE-A", "x", "2026-01-01", [
        {"tool": "dd", "acquisition_status": "COMPLETED", "computed_verification_hashes": {}},
    ])
    results, truncated = case_index_db.cross_case_hash_search("anything")
    assert results == []
