"""A missing case folder must not look like a negative finding (2026-09-20).

`_case_index_open_readonly()` used to return None for three different
situations, which collapsed them into one empty result. The dangerous one is
the third: with the evidence share unmounted, EVERY case path under it becomes
invalid at once, and Pattern of Life would report "no contacts found" for a
case whose data is merely unreachable. This station's NAS is documented to
stall and drop under load, so that is a real scenario.

The codebase already argues this principle against itself - the privacy-tools
renderer insists that "544 apps checked, none found" and "no app inventory has
been parsed" must never collapse into the same empty box.
"""
import json
import os
import pathlib

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    folder = pathlib.Path(evidence_root) / "2026-CASE-FOLDERCHECK"
    folder.mkdir()
    (folder / "2026-CASE-FOLDERCHECK_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-FOLDERCHECK", "events": [],
    }))
    return str(folder)


@pytest.fixture(autouse=True)
def _clear_schema_memo():
    case_index_db._schema_ready.clear()
    yield
    case_index_db._schema_ready.clear()


def test_no_case_selected_is_still_an_empty_result_not_an_error():
    """This app's standing convention: case selection is optional and nothing
    breaks when none is active. Must survive the change."""
    assert case_index_db._case_index_open_readonly(None) is None
    assert case_index_db._case_index_open_readonly("") is None


def test_a_real_case_that_was_never_indexed_is_still_an_empty_result(case_folder):
    """Also not an error - the index is created lazily on the first scan or
    tag, so a brand-new case legitimately has none."""
    assert not os.path.exists(case_index_db.case_index_db_path(case_folder))
    assert case_index_db._case_index_open_readonly(case_folder) is None


def test_a_supplied_but_unresolvable_case_folder_raises(evidence_root):
    """The case this exists for. Previously indistinguishable from 'this case
    genuinely has no contacts'."""
    missing = os.path.join(evidence_root, "2026-CASE-THAT-IS-NOT-THERE")
    with pytest.raises(case_index_db.CaseFolderUnavailable):
        case_index_db._case_index_open_readonly(missing)


def test_a_folder_without_a_case_marker_raises(evidence_root):
    """A directory that exists but is not a case - e.g. what an unmounted
    share's mountpoint looks like: present, empty, and not a case."""
    plain = pathlib.Path(evidence_root) / "just_a_directory"
    plain.mkdir()
    with pytest.raises(case_index_db.CaseFolderUnavailable):
        case_index_db._case_index_open_readonly(str(plain))


def test_the_case_disappearing_after_indexing_raises(case_folder):
    """The live failure mode: the case was fine, work was done against it, and
    then the storage went away mid-examination."""
    conn = case_index_db._case_index_open_write(case_folder)
    conn.close()
    assert case_index_db._case_index_open_readonly(case_folder) is not None

    # Simulate the share vanishing: the case marker is no longer readable.
    os.remove(os.path.join(case_folder, "2026-CASE-FOLDERCHECK_case.json"))
    with pytest.raises(case_index_db.CaseFolderUnavailable):
        case_index_db._case_index_open_readonly(case_folder)


def test_the_message_does_not_assert_which_cause_it_was(evidence_root):
    """From here an unmounted share and a deleted case are genuinely
    indistinguishable. The message leads with the likelier cause but must not
    claim certainty, and must say nothing was changed."""
    missing = os.path.join(evidence_root, "2026-CASE-GONE")
    try:
        case_index_db._case_index_open_readonly(missing)
        raise AssertionError("should have raised")
    except case_index_db.CaseFolderUnavailable as e:
        text = str(e).lower()
        assert "unmounted" in text or "unreachable" in text
        assert "moved or deleted" in text
        assert "nothing was changed" in text


def test_export_of_tag_state_tolerates_a_vanished_case(evidence_root):
    """Best-effort by design: a snapshot failure must never fail the tagging
    action that triggered it, and by the time it runs the case may be gone."""
    missing = os.path.join(evidence_root, "2026-CASE-GONE-TOO")
    assert case_index_db.export_case_tag_state(missing) is None
