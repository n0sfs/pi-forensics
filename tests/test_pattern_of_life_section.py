"""Pattern of Life as an exportable report section (2026-09-20).

The renderer pair (_html_pattern_of_life_block / _draw_pdf_pattern_of_life_block)
has existed since 2026-09-08, but the block was `in_legacy_default: False` and
_expand_legacy_sections_dict() skips such blocks UNCONDITIONALLY - so even a
caller explicitly sending {"pattern_of_life": True} was silently ignored, and
none of the four built-in templates included it. It was the only one of the 18
registry keys with no presence in reporting.html or main.js at all, which meant
a whole top-level analysis tab could not reach an exported report unless the
examiner first hand-built a custom template.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

reporting = pytest.importorskip(
    "routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")


def _keys(sections_dict):
    return [b["key"] for b in reporting._expand_legacy_sections_dict(sections_dict)]


def test_checkbox_on_includes_the_section():
    """The whole point: the Standard template's checkbox now reaches it."""
    assert "pattern_of_life" in _keys({"pattern_of_life": True})


def test_checkbox_off_excludes_the_section():
    assert "pattern_of_life" not in _keys({"pattern_of_life": False})


def test_absent_key_means_off():
    """The convention CLAUDE.md records for any section added after the
    original checkbox set: _expand_legacy_sections_dict() treats an absent key
    as INCLUDED, which is right for every block that predates the convention
    and wrong for anything newer - it would silently change the shape of every
    existing export. Membership of LEGACY_SECTIONS_OFF_WHEN_UNSPECIFIED is
    what makes absent mean off."""
    assert "pattern_of_life" not in _keys({})
    assert "pattern_of_life" in reporting.LEGACY_SECTIONS_OFF_WHEN_UNSPECIFIED


def test_enabling_it_does_not_disturb_the_other_sections():
    """Turning the new section on must add exactly one key and reorder
    nothing - the registry's own fixed order still governs."""
    without = _keys({})
    with_pol = _keys({"pattern_of_life": True})
    assert [k for k in with_pol if k != "pattern_of_life"] == without
    assert len(with_pol) == len(without) + 1


def test_it_renders_in_the_registry_order_not_appended_last():
    """force_page_break sections are positioned by the registry; a section
    that silently sorted to the end would read as an afterthought in a report
    whose section order is deliberate."""
    keys = [b["key"] for b in reporting.REPORT_SECTION_BLOCKS]
    assert keys.index("pattern_of_life") < keys.index("analysis_results")


def test_both_renderers_are_registered():
    """A block in the registry but missing from a dispatch dict raises a
    KeyError mid-export, so the registry and both renderers have to agree.
    This block was previously only reachable via a custom template, which
    exercised a different code path - worth pinning now that the checkbox
    path reaches it too."""
    assert callable(reporting._html_pattern_of_life_block)
    assert callable(reporting._draw_pdf_pattern_of_life_block)
