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


# --- 2026-09-15: the global cap was a uniform newest-first slice, despite
# CASE_TIMELINE_MAX_TOTAL_ENTRIES' own comment claiming it leaves room for
# parsed artifacts "without starving the MACB one". An adb pull with no
# device-timestamp manifest stamps every copied file's M/A/C with the COPY
# time, so its 5,000 MACB rows are the newest events in the case by a wide
# margin and took 5,000 of 6,000 slots - leaving only the ~1,000 most recent
# artifacts. Unticking "Filesystem (MACB)" then showed a thousand rows from
# the last few days and read as "this phone has almost no history". ---
def _rows(source, n, base_ts):
    return [{"timestamp": base_ts + i, "source": source, "activity": "x", "detail": "",
             "evidence_id": None, "deleted": False, "suspicious": False,
             "category": "Filesystem" if source == "macb" else "Communications",
             "counterparts": [], "content_preview": None}
            for i in range(n)]


# The REAL allocation, not a copy of it - a reimplementation here would test
# itself rather than the shipped rule.
from routes.reporting import _apply_timeline_source_shares as _apply_cap


def test_copy_time_macb_rows_cannot_evict_almost_every_artifact():
    """The reported scenario: 5,000 MACB rows all newer than 3,000 artifacts."""
    from routes.reporting import CASE_TIMELINE_MAX_TOTAL_ENTRIES
    combined = _rows("macb", 5000, 2_000_000_000) + _rows("parsed_artifact", 3000, 1_700_000_000)
    combined.sort(key=lambda r: r["timestamp"], reverse=True)
    kept, starved = _apply_cap(combined)

    artifacts_kept = sum(1 for r in kept if r["source"] != "macb")
    assert len(kept) == CASE_TIMELINE_MAX_TOTAL_ENTRIES
    # Before the fix this was ~1000; the reserved share is 6000 - 5000.
    assert artifacts_kept == 1000
    assert starved is True


def test_a_case_with_few_artifacts_loses_no_macb_rows():
    """The reserve must not cost anything when the other side does not need
    it - unused share flows across."""
    combined = _rows("macb", 5000, 2_000_000_000) + _rows("parsed_artifact", 50, 1_700_000_000)
    combined.sort(key=lambda r: r["timestamp"], reverse=True)
    kept, starved = _apply_cap(combined)
    assert sum(1 for r in kept if r["source"] == "macb") == 5000
    assert sum(1 for r in kept if r["source"] != "macb") == 50
    assert starved is False


def test_an_artifact_heavy_case_can_use_more_than_its_reserve():
    """Symmetry: with few MACB rows, artifacts take the rest of the budget."""
    from routes.reporting import CASE_TIMELINE_MAX_TOTAL_ENTRIES
    combined = _rows("macb", 200, 2_000_000_000) + _rows("parsed_artifact", 12000, 1_700_000_000)
    combined.sort(key=lambda r: r["timestamp"], reverse=True)
    kept, _starved = _apply_cap(combined)
    assert sum(1 for r in kept if r["source"] == "macb") == 200
    assert sum(1 for r in kept if r["source"] != "macb") == CASE_TIMELINE_MAX_TOTAL_ENTRIES - 200


def test_a_case_under_the_cap_is_untouched():
    combined = _rows("macb", 100, 2_000_000_000) + _rows("parsed_artifact", 100, 1_700_000_000)
    kept, starved = _apply_cap(combined)
    assert len(kept) == 200
    assert starved is False
