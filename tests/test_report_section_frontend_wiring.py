"""Every report section checkbox must be wired end to end (2026-09-20).

Deliberately NOT gated behind routes.reporting's POSIX import: this reads
template and JS files as text, so it runs on the Windows dev machine too. That
matters because the bug it guards against is frontend-side, and CLAUDE.md
records that the test suites do not exercise static/js/main.js at all.

The gap that prompted it: `pattern_of_life` was the only one of the report
registry's 18 keys with no presence in reporting.html or main.js. Its backend
renderers worked fine and the section was reachable through a hand-built custom
template, so nothing failed - the whole Pattern of Life tab simply could not
reach an exported report through the normal UI. That is the same "two
independent copies must be kept in sync" trap CLAUDE.md already lists for
PARSED_ARTIFACT_TYPE_LABELS and TRIAGE_CATEGORY_LABELS, one layer up.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    return io.open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def test_pattern_of_life_is_wired_from_markup_through_to_the_payload():
    markup = _read("templates", "tabs", "reporting.html")
    defaults = _read("templates", "tabs", "settings", "case_reporting.html")
    js = _read("static", "js", "main.js")

    assert 'id="expSecPatternOfLife"' in markup, "export checkbox missing from the Export pane"
    assert 'id="defSecPatternOfLife"' in defaults, "station-default checkbox missing from Settings"
    assert "expSecPatternOfLife" in js, "export checkbox is never read by main.js"
    assert "defSecPatternOfLife" in js, "station-default checkbox is never read by main.js"
    assert "pattern_of_life" in js, "the key is never sent in a sections payload"


def test_every_export_checkbox_is_read_by_the_frontend():
    """A checkbox present in the markup but never read is dead UI - the
    examiner ticks it and the export ignores them."""
    import re
    markup = _read("templates", "tabs", "reporting.html")
    js = _read("static", "js", "main.js")
    ids = set(re.findall(r'id="(expSec[A-Za-z]+)"', markup))
    assert ids, "no export-section checkboxes found - has the markup moved?"
    unread = sorted(i for i in ids if i not in js)
    assert not unread, "export checkboxes never read by main.js: %s" % ", ".join(unread)


def test_every_station_default_checkbox_is_read_by_the_frontend():
    import re
    defaults = _read("templates", "tabs", "settings", "case_reporting.html")
    js = _read("static", "js", "main.js")
    ids = set(re.findall(r'id="(defSec[A-Za-z]+)"', defaults))
    assert ids, "no station-default section checkboxes found - has the markup moved?"
    unread = sorted(i for i in ids if i not in js)
    assert not unread, "default checkboxes never read by main.js: %s" % ", ".join(unread)
