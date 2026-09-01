"""core/paths.py - safe_path() (the single security boundary preventing path
traversal into the rest of the station's filesystem from any path-accepting
endpoint), sanitize_case_slug(), and classify_extension()."""
import os

import pytest

import core.paths as paths


def test_safe_path_allows_root_itself(evidence_root):
    assert paths.safe_path(evidence_root) == evidence_root


def test_safe_path_allows_a_real_child_path(evidence_root):
    child_dir = os.path.join(evidence_root, "2026-CASE-01")
    os.makedirs(child_dir)
    child_file = os.path.join(child_dir, "evidence.dd")
    open(child_file, "w").close()
    assert paths.safe_path(child_file) == os.path.realpath(child_file)


def test_safe_path_rejects_dotdot_traversal_out_of_root(evidence_root, tmp_path):
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("nope")
    traversal = os.path.join(evidence_root, "..", "outside_secret.txt")
    assert paths.safe_path(traversal) is None


def test_safe_path_rejects_absolute_paths_outside_root(evidence_root):
    assert paths.safe_path(os.path.abspath(os.sep + os.path.join("etc", "passwd"))) is None


def test_safe_path_rejects_empty_or_none(evidence_root):
    assert paths.safe_path(None) is None
    assert paths.safe_path("") is None


def test_safe_path_does_not_accept_a_sibling_with_a_shared_prefix(evidence_root):
    # A real bug class for any prefix-based sandbox check: EVIDENCE_ROOT
    # "/mnt/evidence" must not also accept "/mnt/evidence_other" just
    # because the raw string happens to start with the same characters -
    # this is exactly why safe_path() checks `resolved == EVIDENCE_ROOT or
    # resolved.startswith(EVIDENCE_ROOT + os.sep)`, not a bare startswith().
    sibling = evidence_root + "_other"
    os.makedirs(sibling, exist_ok=True)
    assert paths.safe_path(sibling) is None


def test_sanitize_case_slug_passes_through_a_clean_case_number():
    assert paths.sanitize_case_slug("2026-CASE-01") == "2026-CASE-01"


def test_sanitize_case_slug_neutralizes_traversal_attempts():
    # Whitelist-based, not blacklist-based: a traversal attempt becomes a
    # literal, safely-nested folder name, never an actual escape.
    slug = paths.sanitize_case_slug("../../etc")
    assert slug is not None
    assert ".." not in slug
    assert "/" not in slug and "\\" not in slug


def test_sanitize_case_slug_collapses_whitespace_and_punctuation():
    assert paths.sanitize_case_slug("  My Case #1!!  ") == "My_Case_1"


@pytest.mark.parametrize("raw", ["", None, "...", "***"])
def test_sanitize_case_slug_returns_none_for_nothing_usable(raw):
    assert paths.sanitize_case_slug(raw) is None


def test_sanitize_case_slug_caps_length():
    slug = paths.sanitize_case_slug("A" * 200)
    assert len(slug) <= 80


@pytest.mark.parametrize("name,expected_category,expected_ext", [
    ("photo.JPG", "images", "jpg"),
    ("clip.mp4", "videos", "mp4"),
    ("report.PDF", "documents", "pdf"),
    ("archive.tar.gz", "archives", "gz"),
    ("payload.exe", "executables", "exe"),
    ("mystery.xyz123", "other", "xyz123"),
    ("no_extension", "other", ""),
])
def test_classify_extension(name, expected_category, expected_ext):
    category, ext = paths.classify_extension(name)
    assert category == expected_category
    assert ext == expected_ext
    assert category in paths.FILE_VIEW_EXTENSION_CATEGORIES


@pytest.mark.parametrize("name,expected_role", [
    ("2026-CASE-01_case.json", "report"),
    ("2026-CASE-01_case.pdf", "report"),
    ("2026-CASE-01_case_index.db", "report"),
    ("case_info.json", "report"),
    ("ITEM-01_report.json", "report"),
    ("2026-CASE-01_USBDrive-1_hash_manifest_sha256.txt", "analysis_log"),
    ("2026-CASE-01_USBDrive-1_triage_scan_report.txt", "analysis_log"),
    ("2026-CASE-01_USBDrive-1_vol3_pslist.json", "analysis_log"),
    ("dc3dd_output.log", "analysis_log"),
    ("msgstore.db.crypt14_sqlite_dissect_recovery", "analysis_log"),
    ("app-release_apk_analysis.json", "analysis_log"),
    ("bugreport-2026-08-30_bugreport_parsed.json", "analysis_log"),
    ("00008030-001A2B3C4D5E6F7A_ios_crash_reports", "analysis_log"),
    ("2026-CASE-01_USBDrive-1_mft_analysis.json", "analysis_log"),
    ("2026-CASE-01_USBDrive-1_usnjrnl_parsed.json", "analysis_log"),
    ("live_collection_import_20260831_142530", "analysis_log"),
    ("thumbcache_256_thumbcache_extracted", "analysis_log"),
    # Anchored to the exact timestamp shape - a similarly-named real evidence
    # folder an examiner happens to create must never be misclassified.
    ("live_collection_import_notes", None),
    ("my_live_collection_import_20260831_142530", None),
    ("geolocation_export.kml", "geolocation"),
    ("2026-CASE-01_case.json.pre_restore_backup", "backup"),
    ("2026-CASE-01_case.json.pre_consolidation_backup", "backup"),
    # A5 (Case Bundle Export): matched by its own timestamped pattern, NOT
    # by the plain .zip extension - a real bug the design review caught
    # before this shipped (an examiner-added .zip must stay unclassified).
    ("2026-CASE-01_case_bundle_20260825-080000.zip", "case_bundle"),
    ("evidence_photos.zip", None),
    ("suspect_photo.jpg", None),
    ("random_notes.txt", None),
])
def test_classify_case_role(name, expected_role):
    assert paths.classify_case_role(name) == expected_role


def test_is_valid_block_device_whitelist():
    assert paths.is_valid_block_device("/dev/sda")
    assert paths.is_valid_block_device("/dev/nvme0n1")
    assert paths.is_valid_block_device("/dev/mmcblk0")
    # Partitions, not whole disks - this whitelist is deliberately for
    # whole-disk device paths only (see the function's own docstring).
    assert not paths.is_valid_block_device("/dev/sda1")


def _make_case_folder(root, name="2026-CASE-TEST"):
    import json
    import pathlib
    folder = pathlib.Path(root) / name
    folder.mkdir()
    (folder / f"{name}_case.json").write_text(json.dumps({"schema_version": 1, "events": []}))
    return str(folder)


def test_case_consolidated_path_resolves_a_real_case_folder_inside_evidence_root(evidence_root):
    folder = _make_case_folder(evidence_root)
    result = paths.case_consolidated_path(folder)
    assert result == os.path.join(os.path.realpath(folder), "2026-CASE-TEST_case.json")


def test_case_consolidated_path_rejects_a_lookalike_folder_outside_evidence_root(evidence_root, tmp_path):
    # THE FIX: before this, case_consolidated_path() only checked
    # os.path.isdir() + a marker-file-name match - neither implies the
    # path is anywhere near EVIDENCE_ROOT. Several routes pass a raw,
    # client-supplied case_folder straight to functions gated only by this
    # check (see core/paths.py's own docstring on this function) - a
    # directory outside the sandbox with the right marker filename would
    # have satisfied it. A downstream function happened to safe_path() its
    # own derived path anyway, which is what kept this from being directly
    # exploitable, but that was two functions incidentally agreeing, not a
    # designed guarantee - and it left a real os.walk() side-channel open
    # in at least one caller before that downstream check ever ran.
    outside = tmp_path / "not_the_evidence_root"
    outside.mkdir()
    folder = _make_case_folder(str(outside))
    assert paths.case_consolidated_path(folder) is None


def test_case_consolidated_path_returns_none_for_a_folder_with_no_marker_file(evidence_root):
    import pathlib
    folder = pathlib.Path(evidence_root) / "not_a_real_case"
    folder.mkdir()
    assert paths.case_consolidated_path(str(folder)) is None


def test_case_consolidated_path_returns_none_for_none_or_a_nonexistent_path(evidence_root):
    assert paths.case_consolidated_path(None) is None
    assert paths.case_consolidated_path("") is None
    assert paths.case_consolidated_path(os.path.join(evidence_root, "does_not_exist")) is None
    assert not paths.is_valid_block_device("/dev/sda; rm -rf /")
    assert not paths.is_valid_block_device("")
    assert not paths.is_valid_block_device(None)
