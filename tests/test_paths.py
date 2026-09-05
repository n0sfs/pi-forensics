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
    # Real-fs "Hash Directory Tree" output - a distinct naming convention
    # from the whole-image hash manifest above (routes/file_explorer.py's
    # own _hashdeep_{algo}_manifest.txt vs. routes/image_browser.py's
    # _hash_manifest_{algo}.txt) - a real gap found and fixed 2026-09-04
    # while auditing this regex for the Android manifest gap below.
    ("evidence_folder_hashdeep_sha256_manifest.txt", "analysis_log"),
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
    # Android pull manifests (routes/mobile.py) - a real gap found 2026-09-04:
    # these three were never in the regex at all, so File Explorer's tree
    # never grouped them and they were never auto-tagged into the case index.
    ("2026-CASE-01_PIXEL8A-01_app_inventory.json", "analysis_log"),
    ("2026-CASE-01_PIXEL8A-01_accounts.json", "analysis_log"),
    ("2026-CASE-01_PIXEL8A-01_notifications.json", "analysis_log"),
    ("2026-CASE-01_PIXEL8A-01_android_companion_sms_extraction.json", "analysis_log"),
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


@pytest.mark.parametrize("name,expected", [
    ("RECOVERED_FILES", True),  # extundelete's fixed output dir name
    ("2026-CASE-01_ITEM-01_photorec", True),
    ("2026-CASE-01_ITEM-01_foremost", True),
    ("2026-CASE-01_ITEM-01_scalpel", True),
    ("2026-CASE-01_ITEM-01_triagescan", True),
    ("#recycle", True),  # Synology's own NAS-internal trash folder
    ("@Recycle", True),
    ("@recycle", True),
    (".@__thumb", True),
    # A similarly-suffixed real case/evidence folder name must never be
    # misclassified - only an exact/suffix match on the known patterns
    # counts, not a loose substring anywhere in the name.
    ("2026-CASE-photorec-review", False),
    ("recovered_files", False),  # case-sensitive - not the exact known name
    ("evidence_folder", False),
    ("2026-CASE-01", False),
])
def test_is_bulk_tool_output_dir(name, expected):
    assert paths.is_bulk_tool_output_dir(name) == expected


def _real_sda_path(subport):
    """The exact real sysfs shape confirmed live on the deployed Pi 4B
    (2026-09-05, one real USB drive physically moved through all 4 ports
    in turn) for a device on bus1's own internal 4-port hub."""
    return (f"/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/"
            f"usb1/1-1/1-1.{subport}/1-1.{subport}:1.0/host0/target0:0:0/0:0:0:0/block/sda")


@pytest.mark.parametrize("subport,expected", [
    (1, "blue"),   # confirmed live: top blue port
    (2, "blue"),   # confirmed live: bottom blue port
    (3, "black"),  # confirmed live: top black port
    (4, "black"),  # confirmed live: bottom black port
])
def test_classify_usb_port_matches_the_real_verified_pi4b_mapping(monkeypatch, subport, expected):
    monkeypatch.setattr(paths.os.path, "realpath", lambda p: _real_sda_path(subport))
    assert paths.classify_usb_port("/dev/sda") == expected


def test_classify_usb_port_anything_on_the_superspeed_bus_is_always_blue():
    # On this board the SuperSpeed root hub (usb2) is only ever wired to
    # the 2 blue ports at all - a genuine SuperSpeed negotiation is
    # unconditionally blue with no sub-port lookup needed.
    import core.paths as _paths
    real_path = ("/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/"
                 "usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0/block/sda")
    orig = _paths.os.path.realpath
    _paths.os.path.realpath = lambda p: real_path
    try:
        assert _paths.classify_usb_port("/dev/sda") == "blue"
    finally:
        _paths.os.path.realpath = orig


def test_classify_usb_port_fails_closed_behind_an_intermediate_hub(monkeypatch):
    # A device plugged into a USB hub that's itself plugged into a
    # physical port adds an extra path segment (e.g. "1-1.3.1" instead of
    # "1-1.3") - the anchored regex must not mis-parse this as port 3,
    # since an examiner-attached hub genuinely changes what's plugged in
    # where; fail closed ('unknown', never 'black') rather than guess.
    hub_path = ("/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/"
                "usb1/1-1/1-1.3/1-1.3.1/1-1.3.1:1.0/host0/target0:0:0/0:0:0:0/block/sda")
    monkeypatch.setattr(paths.os.path, "realpath", lambda p: hub_path)
    assert paths.classify_usb_port("/dev/sda") == "unknown"


def test_classify_usb_port_fails_closed_for_an_unrecognized_topology(monkeypatch):
    monkeypatch.setattr(paths.os.path, "realpath", lambda p: "/some/completely/different/shape")
    assert paths.classify_usb_port("/dev/sda") == "unknown"


def test_classify_usb_port_fails_closed_when_the_device_does_not_exist(monkeypatch):
    # os.path.realpath() on a nonexistent path just returns it unchanged
    # (no symlink to resolve) - must not be mistaken for a real match.
    monkeypatch.setattr(paths.os.path, "realpath", lambda p: p)
    assert paths.classify_usb_port("/dev/sda") == "unknown"


@pytest.mark.parametrize("subport,expected_color", [
    (1, "blue"), (2, "blue"), (3, "black"), (4, "black"),
])
def test_describe_usb_port_returns_both_color_and_specific_port_index(monkeypatch, subport, expected_color):
    monkeypatch.setattr(paths.os.path, "realpath", lambda p: _real_sda_path(subport))
    info = paths.describe_usb_port("/dev/sda")
    assert info == {"color": expected_color, "port_index": str(subport)}


def test_describe_usb_port_leaves_port_index_none_on_the_superspeed_bus():
    # The specific bus2-root-port-to-physical-connector correspondence was
    # never itself empirically confirmed (no genuine SuperSpeed-capable
    # drive was available) - color is still confidently 'blue' (bus2 is
    # only ever reachable from a blue port at all), but a specific slot
    # must never be guessed.
    import core.paths as _paths
    real_path = ("/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0/"
                 "usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0/block/sda")
    orig = _paths.os.path.realpath
    _paths.os.path.realpath = lambda p: real_path
    try:
        assert _paths.describe_usb_port("/dev/sda") == {"color": "blue", "port_index": None}
    finally:
        _paths.os.path.realpath = orig


def test_describe_usb_port_returns_none_for_an_invalid_device_path():
    assert paths.describe_usb_port("/dev/sda1") is None
    assert paths.describe_usb_port(None) is None


def test_classify_usb_port_returns_none_for_an_invalid_device_path():
    assert paths.classify_usb_port("/dev/sda1") is None  # a partition, not a whole disk
    assert paths.classify_usb_port("/dev/sda; rm -rf /") is None
    assert paths.classify_usb_port(None) is None


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
