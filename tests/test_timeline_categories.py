"""Evidence Timeline category assignment.

The map's stated design is that anything unlisted falls through to the
"Device & System" catch-all rather than being dropped - a safe default for the
desktop/server types a phone-oriented timeline has no bucket for. It is NOT a
safe default for a type that plainly belongs to an existing category, because
the category filter then HIDES that type from the examiner who narrowed to
exactly the category it belongs in.

A 2026-09-15 review pass found five such types. The worst is webcache_entry -
Legacy IE/Edge browsing history: the map covered Chrome, Firefox and Safari
but not the Microsoft equivalent, so ticking only "Web Activity" on a Windows
image showed nothing and read as "this machine has no browser history."

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from routes.reporting import (
    _timeline_row_category, CASE_TIMELINE_ACTIVITY_CATEGORY,
    CASE_TIMELINE_CATEGORIES, CASE_TIMELINE_DEFAULT_CATEGORY,
)
from routes.case_index import PARSED_ARTIFACT_TYPE_LABELS


@pytest.mark.parametrize("artifact_type", ["webcache_entry", "registry_typed_urls"])
def test_windows_web_history_types_are_web_activity(artifact_type):
    assert _timeline_row_category("parsed_artifact", artifact_type) == "Web Activity"


@pytest.mark.parametrize("artifact_type", [
    "mft_file_record", "usnjrnl_change_record", "recyclebin_deleted_file"])
def test_ntfs_filesystem_types_are_filesystem(artifact_type):
    """$MFT and $UsnJrnl are the richest filesystem timeline an NTFS image
    offers. Ticking only "Filesystem" used to hide all of them."""
    assert _timeline_row_category("parsed_artifact", artifact_type) == "Filesystem"


def test_macb_rows_are_always_filesystem_regardless_of_activity():
    assert _timeline_row_category("macb", "M") == "Filesystem"
    assert _timeline_row_category("macb", "anything") == "Filesystem"


def test_an_unmapped_type_still_falls_through_rather_than_being_dropped():
    """The catch-all behaviour itself must survive - a row must never vanish
    from the timeline just because nobody categorised its type."""
    assert _timeline_row_category("parsed_artifact", "some_future_type") == CASE_TIMELINE_DEFAULT_CATEGORY


def test_every_mapped_category_is_one_the_filter_actually_offers():
    """A typo'd category value would put rows in a bucket that has no
    checkbox, making them unreachable under every filter combination."""
    unknown = {v for v in CASE_TIMELINE_ACTIVITY_CATEGORY.values()
               if v not in CASE_TIMELINE_CATEGORIES}
    assert not unknown, f"categories with no filter checkbox: {sorted(unknown)}"


def test_every_mapped_type_is_a_real_artifact_type():
    """Guards the other direction: a mapping keyed on a type this app never
    produces is dead weight that reads as coverage it does not have."""
    dead = {k for k in CASE_TIMELINE_ACTIVITY_CATEGORY if k not in PARSED_ARTIFACT_TYPE_LABELS}
    assert not dead, f"mapped types that no parser emits: {sorted(dead)}"
