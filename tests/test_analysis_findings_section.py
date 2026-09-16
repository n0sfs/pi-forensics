"""The exported report's Analysis Results section (2026-09-16) - the renderer
half. See tests/test_analysis_findings_collector.py for the data half and for
why this section had to be added at all.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

reporting = pytest.importorskip(
    "routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

def test_the_section_is_registered_for_both_output_formats():
    """A block present in the registry but missing from a dispatch dict raises
    a KeyError mid-export - the registry and the two renderers have to agree."""
    keys = [b["key"] for b in reporting.REPORT_SECTION_BLOCKS]
    assert "analysis_results" in keys


def test_the_html_section_reports_all_three_kinds_of_finding():
    findings = {
        "indexed": True,
        "flagged": [{"tag": "Notable Item", "notable": True, "name": "meeting_notes.txt",
                     "path": "/evidence/meeting_notes.txt", "comment": "Coded references.",
                     "tagged_by": "examiner", "tagged_at": "2026-09-16 10:00:00"}],
        "flagged_total": 1,
        "keyword_hits": [{"category": "emails", "label": "Email Addresses", "count": 2,
                          "samples": ["dave@example.net", "jane@example.com"], "samples_truncated": False}],
        "parsed_artifacts": [{"artifact_type": "chrome_history", "count": 5}],
    }
    out = reporting._html_analysis_findings_block(findings, anchor_id="sec-analysis-results")
    assert "Flagged Items" in out
    assert "meeting_notes.txt" in out
    assert "Coded references." in out
    assert "Email Addresses" in out and "jane@example.com" in out
    assert "Chrome/Chromium History" in out and ">5<" in out


def test_the_html_section_states_when_a_sample_was_capped():
    findings = {"indexed": True, "flagged": [], "flagged_total": 0,
                "keyword_hits": [{"category": "emails", "label": "Email Addresses", "count": 900,
                                  "samples": ["a@example.com"], "samples_truncated": True}],
                "parsed_artifacts": []}
    out = reporting._html_analysis_findings_block(findings)
    assert "900 total" in out


def test_the_html_section_distinguishes_never_analysed_from_found_nothing():
    out = reporting._html_analysis_findings_block({"indexed": False})
    assert "not that a tool was run and found nothing" in out


def test_examiner_supplied_text_is_escaped():
    """A tag comment and an evidence filename are both attacker-influenced in
    the general case, and this document is opened in a browser."""
    findings = {"indexed": True, "flagged_total": 1,
                "flagged": [{"tag": "Notable Item", "notable": False,
                             "name": "<img src=x onerror=alert(1)>", "path": "/e/x",
                             "comment": "<script>alert(2)</script>",
                             "tagged_by": "e", "tagged_at": "t"}],
                "keyword_hits": [], "parsed_artifacts": []}
    out = reporting._html_analysis_findings_block(findings)
    assert "<img src=x" not in out
    assert "<script>alert(2)</script>" not in out
    assert "&lt;script&gt;" in out


def test_an_unspecified_sections_dict_does_not_turn_the_new_section_on():
    """Every block predating this one is included when a caller's sections dict
    omits it. A section added later must not appear in exports that never asked
    for it - see LEGACY_SECTIONS_OFF_WHEN_UNSPECIFIED."""
    resolved = reporting._expand_legacy_sections_dict({"case_info": True})
    assert "analysis_results" not in [s["key"] for s in resolved]


def test_asking_for_it_includes_it():
    resolved = reporting._expand_legacy_sections_dict({"analysis_results": True})
    assert "analysis_results" in [s["key"] for s in resolved]
