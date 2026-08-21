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


def test_is_valid_block_device_whitelist():
    assert paths.is_valid_block_device("/dev/sda")
    assert paths.is_valid_block_device("/dev/nvme0n1")
    assert paths.is_valid_block_device("/dev/mmcblk0")
    # Partitions, not whole disks - this whitelist is deliberately for
    # whole-disk device paths only (see the function's own docstring).
    assert not paths.is_valid_block_device("/dev/sda1")
    assert not paths.is_valid_block_device("/dev/sda; rm -rf /")
    assert not paths.is_valid_block_device("")
    assert not paths.is_valid_block_device(None)
