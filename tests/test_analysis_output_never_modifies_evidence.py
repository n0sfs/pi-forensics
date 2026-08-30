"""_resolve_analysis_output_dir() (routes/file_explorer.py, added 2026-08-30):
the shared safety check for hashdeep, Geolocation Export, and MVT scan's
output-destination handling. Regression test for a real, live-caught bug -
each of those 3 tools independently defaulted its own generated output
(a hash manifest, a KML file, an MVT scan folder) to be written directly
INSIDE the real evidence folder it was analyzing (found live against a real
acquired Android pull folder: _geolocation_export.kml and _mvt_android_scan
had both landed inside 2026-CASE-01_PIXEL8A-01_android_pull itself). This
app's own stated invariant is that acquired evidence must never be modified
by a later analysis step - this test locks that in at the one shared
function all three tools' routes now go through.

Skipped (not failed) on a non-POSIX dev machine: routes/file_explorer.py
needs core.jobs, which imports POSIX-only pwd/fcntl at module level - see
tests/conftest.py's own docstring.
"""
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.file_explorer as file_explorer


def test_rejects_destination_equal_to_source(evidence_root):
    source = os.path.join(evidence_root, "case1", "PIXEL8A_android_pull")
    os.makedirs(source)
    assert file_explorer._resolve_analysis_output_dir(source, source) is None


def test_rejects_destination_nested_inside_source(evidence_root):
    source = os.path.join(evidence_root, "case1", "PIXEL8A_android_pull")
    nested = os.path.join(source, "some_subfolder")
    os.makedirs(nested)
    assert file_explorer._resolve_analysis_output_dir(nested, source) is None


def test_accepts_a_real_sibling_case_folder_destination(evidence_root):
    case_folder = os.path.join(evidence_root, "case1")
    source = os.path.join(case_folder, "PIXEL8A_android_pull")
    os.makedirs(source)
    result = file_explorer._resolve_analysis_output_dir(case_folder, source)
    assert result == case_folder


def test_falls_back_to_source_own_parent_when_no_destination_given(evidence_root):
    case_folder = os.path.join(evidence_root, "case1")
    source = os.path.join(case_folder, "PIXEL8A_android_pull")
    os.makedirs(source)
    result = file_explorer._resolve_analysis_output_dir(None, source)
    assert os.path.realpath(result) == os.path.realpath(case_folder)


def test_rejects_a_destination_outside_the_evidence_root(evidence_root, tmp_path):
    source = os.path.join(evidence_root, "case1", "PIXEL8A_android_pull")
    os.makedirs(source)
    outside = tmp_path / "not_evidence"
    outside.mkdir()
    assert file_explorer._resolve_analysis_output_dir(str(outside), source) is None


def test_a_sibling_folder_with_a_shared_string_prefix_is_not_treated_as_nested(evidence_root):
    """The prefix check must compare full path segments (with a trailing
    separator), not a bare string prefix - 'evidence2' must never be
    rejected as if it were nested inside 'evidence'."""
    source = os.path.join(evidence_root, "evidence")
    sibling = os.path.join(evidence_root, "evidence2")
    os.makedirs(source)
    os.makedirs(sibling)
    result = file_explorer._resolve_analysis_output_dir(sibling, source)
    assert result == sibling
