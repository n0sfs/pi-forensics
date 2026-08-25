"""routes/reporting.py's custom-template source_field remapping (added this
session): lets a Report Template Builder row point one of the 7 free-text
sections at a different narrative field than its own default. Covers the
validation/defaulting in _custom_report_template_from_payload() and the
resolution logic in _resolve_section_order() - including the backward-
compatibility case a custom template saved *before* this feature existed
must still hit (no source_field key on its stored sections at all).

Skipped (not failed) on a non-POSIX dev machine: routes/reporting.py needs
core.jobs, which imports POSIX-only pwd/fcntl at module level - see
tests/conftest.py's module docstring.
"""
import ast
import inspect

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.reporting as reporting


def _local_dict_literal_keys(func, var_name="dispatch"):
    """Parses func's own source to find `var_name = {...}` and returns the
    dict literal's string keys - used to check the PDF/HTML per-key
    dispatch dicts (both are plain local variables inside their builder
    functions, not module-level, so they can't be imported/introspected
    directly). This is the regression test the A3 (Physical Evidence
    Custody Log) plan called for: a REPORT_SECTION_BLOCKS entry with no
    matching key in either dispatch dict is an uncaught KeyError on every
    default Standard export that includes it (in_legacy_default=True means
    that's every existing case, immediately on deploy) - this must fail
    loudly here instead."""
    tree = ast.parse(inspect.getsource(func))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == var_name \
                and isinstance(node.value, ast.Dict):
            return {k.value for k in node.value.keys}
    raise AssertionError(f"no '{var_name} = {{...}}' dict literal found in {func.__name__}")


def test_pdf_standard_dispatch_dict_covers_every_report_section_block():
    all_keys = {b["key"] for b in reporting.REPORT_SECTION_BLOCKS}
    dispatch_keys = _local_dict_literal_keys(reporting._build_pdf_report_standard)
    assert dispatch_keys == all_keys


def test_html_standard_dispatch_dict_covers_every_report_section_block():
    all_keys = {b["key"] for b in reporting.REPORT_SECTION_BLOCKS}
    dispatch_keys = _local_dict_literal_keys(reporting._build_html_report_standard)
    assert dispatch_keys == all_keys


def test_registry_marks_exactly_the_seven_narrative_blocks_remappable():
    remappable = {b["key"] for b in reporting.REPORT_SECTION_BLOCKS if b["remappable"]}
    assert remappable == set(reporting.NARRATIVE_BLOCK_FIELD_MAP.keys())
    assert remappable == {
        "executive_summary", "objectives", "relevant_findings",
        "limitations", "conclusion", "iocs", "recommendations",
    }


def test_payload_validation_defaults_source_field_when_omitted():
    record, error = reporting._custom_report_template_from_payload({
        "name": "Test Template",
        "sections": [{"key": "executive_summary", "title": "Overview", "enabled": True}],
    })
    assert error is None
    row = next(s for s in record["sections"] if s["key"] == "executive_summary")
    assert row["source_field"] == "executive_summary"


def test_payload_validation_accepts_a_real_remap():
    # The actual feature: point "Executive Summary" at the Objectives text.
    record, error = reporting._custom_report_template_from_payload({
        "name": "Remapped",
        "sections": [{"key": "executive_summary", "title": "Overview", "enabled": True, "source_field": "objectives"}],
    })
    assert error is None
    row = next(s for s in record["sections"] if s["key"] == "executive_summary")
    assert row["source_field"] == "objectives"


def test_payload_validation_rejects_bogus_source_field_by_falling_back_to_default():
    # An unrecognized value (stale client, hand-edited request) must not be
    # stored verbatim - falls back to the block's own default rather than
    # erroring, matching this function's existing self-healing posture.
    record, error = reporting._custom_report_template_from_payload({
        "name": "Bogus",
        "sections": [{"key": "conclusion", "enabled": True, "source_field": "not_a_real_field"}],
    })
    assert error is None
    row = next(s for s in record["sections"] if s["key"] == "conclusion")
    assert row["source_field"] == "conclusion"


def test_payload_validation_ignores_source_field_on_a_non_remappable_block():
    # Evidence Inventory isn't remappable - even if a client sends
    # source_field for it, the stored record must not carry one (nothing
    # downstream would use it, and storing it would be misleading).
    record, error = reporting._custom_report_template_from_payload({
        "name": "Ignore Me",
        "sections": [{"key": "evidence_inventory", "enabled": True, "source_field": "iocs"}],
    })
    assert error is None
    row = next(s for s in record["sections"] if s["key"] == "evidence_inventory")
    assert "source_field" not in row


def test_resolve_section_order_custom_mode_carries_a_real_remap_through():
    custom_record = {"sections": [
        {"key": "relevant_findings", "title": "My Findings", "enabled": True, "source_field": "iocs"},
    ]}
    resolved = reporting._resolve_section_order("custom", {}, custom_record, event_count=0)
    assert len(resolved) == 1
    assert resolved[0]["key"] == "relevant_findings"
    assert resolved[0]["title"] == "My Findings"
    assert resolved[0]["source_field"] == "iocs"


def test_resolve_section_order_custom_mode_backward_compat_no_source_field_at_all():
    # The exact regression this session's own review caught: a custom
    # template saved BEFORE this feature existed has sections with no
    # source_field key whatsoever - must resolve to the block's own default
    # field, not None (which would have silently blanked the section).
    custom_record = {"sections": [
        {"key": "conclusion", "title": "Wrap-up", "enabled": True},  # no source_field at all
    ]}
    resolved = reporting._resolve_section_order("custom", {}, custom_record, event_count=0)
    assert resolved[0]["source_field"] == "conclusion"


def test_resolve_section_order_non_remappable_block_has_no_source_field():
    custom_record = {"sections": [{"key": "audit_trail", "title": "Log", "enabled": True}]}
    resolved = reporting._resolve_section_order("custom", {}, custom_record, event_count=0)
    assert resolved[0]["source_field"] is None


def test_resolve_section_order_accepts_the_exact_shape_the_builders_live_preview_constructs():
    # export_report()'s custom_sections preview override (added for the
    # Report Template Builder's own "Preview" button, 2026-08-25) builds a
    # custom_record dict in exactly this shape from the in-progress editor
    # state, before anything's been saved - confirms it resolves correctly
    # through the same path a real saved template already does, with no
    # special-casing needed for "this record was never actually persisted."
    custom_record = {
        "sections": [
            {"key": "case_info", "title": "", "enabled": True, "source_field": None},
            {"key": "relevant_findings", "title": "Key Findings", "enabled": True, "source_field": "iocs"},
            {"key": "exhibits", "title": "", "enabled": False, "source_field": None},
        ],
        "job_fields": {"telemetry": True, "params": True, "hashes": True},
    }
    resolved = reporting._resolve_section_order("custom", {}, custom_record, event_count=0)
    # exhibits was enabled=False - only the 2 enabled entries survive, in order.
    assert [r["key"] for r in resolved] == ["case_info", "relevant_findings"]
    assert resolved[1]["title"] == "Key Findings"
    assert resolved[1]["source_field"] == "iocs"


def test_resolve_section_order_legacy_mode_always_uses_each_blocks_own_default():
    # The plain Export-modal-checkbox path has no per-section remapping
    # capability at all - every remappable block must resolve to its own
    # default field, every time.
    resolved = reporting._resolve_section_order("legacy", {}, None, event_count=0)
    by_key = {e["key"]: e for e in resolved}
    assert by_key["executive_summary"]["source_field"] == "executive_summary"
    assert by_key["relevant_findings"]["source_field"] == "findings_summary"
    # in_legacy_default=False (opt-in via a custom template only) - never
    # appears in the legacy-mode resolution at all, not just unmapped.
    assert "recommendations" not in by_key
