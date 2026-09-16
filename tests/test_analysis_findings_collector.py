"""core/case_index_db.py::collect_case_analysis_findings() - the data behind
the exported report's Analysis Results section (2026-09-16).

From a live end-to-end walkthrough. REPORT_SECTION_BLOCKS had seventeen blocks
and not one carried what the analysis actually produced - the word "keyword"
did not appear in routes/reporting.py at all. A case with 5 parsed Chrome
history entries, a download record, two email hits, a Bitcoin address and a
Notable-flagged file exported with "Relevant Findings: (Not provided)" and no
trace of any of it. The known workaround, per a comment on the exhibits code,
was attaching a keyword-hit CSV as an exhibit by hand.

core/case_index_db.py has no POSIX-only imports, so this runs everywhere. The
renderer half is in tests/test_analysis_findings_section.py, POSIX-gated with
the rest of routes/reporting.py.
"""

import json
import os
import sqlite3

import pytest

import core.case_index_db as case_index_db
from core.case_index_db import CASE_ROLE_TAG_NAMES, collect_case_analysis_findings


def _make_case(evidence_root, slug="2026-CASE-FINDINGS"):
    case_dir = os.path.join(evidence_root, slug)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": case_dir,
                   "case_status": "Open", "events": []}, f)
    return case_dir


def _seed_index(case_dir, hits=(), artifacts=(), tags=()):
    """hits: (category, value). artifacts: (artifact_type,). tags: (tag_name,
    notable, item_name, comment)."""
    db_path = case_index_db.case_index_db_path(case_dir)
    conn = case_index_db._case_index_connect(db_path)
    try:
        for category, value in hits:
            conn.execute("INSERT INTO triage_hits (source_type, path, category, value, found_at) "
                         "VALUES ('real_fs', '/x', ?, ?, '2026-09-16 10:00:00')", (category, value))
        for (artifact_type,) in artifacts:
            conn.execute("INSERT INTO parsed_artifacts (source_type, source_path, artifact_type, value, found_at) "
                         "VALUES ('real_fs', '/x', ?, 'v', '2026-09-16 10:00:00')", (artifact_type,))
        for name, notable, item_name, comment in tags:
            row = conn.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()
            if row:
                tag_id = row[0]
            else:
                cur = conn.execute("INSERT INTO tags (name, color, notable, is_default, created_at, severity) "
                                   "VALUES (?, 'danger', ?, 0, '2026-09-16 10:00:00', 'none')",
                                   (name, 1 if notable else 0))
                tag_id = cur.lastrowid
            conn.execute("INSERT INTO tagged_items (tag_id, source_type, path, name, comment, tagged_by, tagged_at) "
                         "VALUES (?, 'real_fs', ?, ?, ?, 'examiner', '2026-09-16 10:00:00')",
                         (tag_id, f"/evidence/{item_name}", item_name, comment))
        conn.commit()
    finally:
        conn.close()


# --- collect_case_analysis_findings() ---

def test_a_case_with_no_index_says_so_rather_than_reporting_nothing_found(evidence_root):
    """"No tool has been run" and "a tool ran and found nothing" are different
    statements and an examiner must not have to guess which one a blank
    section means."""
    case_dir = _make_case(evidence_root, "2026-CASE-NOINDEX")
    result = collect_case_analysis_findings(case_dir)
    assert result["indexed"] is False
    assert result["keyword_hits"] == []
    assert result["flagged"] == []


def test_keyword_hits_are_counted_with_a_sample_of_values(evidence_root):
    case_dir = _make_case(evidence_root)
    _seed_index(case_dir, hits=[("emails", "jane@example.com"), ("emails", "dave@example.net"),
                                ("btc_addresses", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")])
    result = collect_case_analysis_findings(case_dir)

    assert result["indexed"] is True
    by_cat = {h["category"]: h for h in result["keyword_hits"]}
    assert by_cat["emails"]["count"] == 2
    assert sorted(by_cat["emails"]["samples"]) == ["dave@example.net", "jane@example.com"]
    assert by_cat["emails"]["samples_truncated"] is False
    assert by_cat["btc_addresses"]["count"] == 1


def test_a_capped_sample_says_it_is_capped(evidence_root):
    """A report must never summarise silently - the whole point of the cap is
    that an examiner can see it was applied."""
    case_dir = _make_case(evidence_root, "2026-CASE-CAPPED")
    _seed_index(case_dir, hits=[("emails", f"user{i}@example.com") for i in range(40)])
    result = collect_case_analysis_findings(case_dir, max_samples=5)

    hit = result["keyword_hits"][0]
    assert hit["count"] == 40
    assert len(hit["samples"]) == 5
    assert hit["samples_truncated"] is True


def test_a_custom_keyword_list_category_gets_its_real_label(evidence_root):
    """A kw_<id> category is meaningless in a report without the list's own
    name - resolve_scan_category_label() is what turns it back into one."""
    case_dir = _make_case(evidence_root, "2026-CASE-KWLABEL")
    _seed_index(case_dir, hits=[("emails", "jane@example.com")])
    result = collect_case_analysis_findings(case_dir)
    assert result["keyword_hits"][0]["label"] == "Email Addresses"


def test_parsed_artifacts_are_counted_by_type(evidence_root):
    case_dir = _make_case(evidence_root, "2026-CASE-ARTIFACTS")
    _seed_index(case_dir, artifacts=[("chrome_history",)] * 5 + [("chrome_downloads",)])
    result = collect_case_analysis_findings(case_dir)

    by_type = {a["artifact_type"]: a["count"] for a in result["parsed_artifacts"]}
    assert by_type == {"chrome_history": 5, "chrome_downloads": 1}


def test_examiner_flagged_items_are_reported_with_their_note(evidence_root):
    case_dir = _make_case(evidence_root, "2026-CASE-FLAGGED")
    _seed_index(case_dir, tags=[("Notable Item", True, "meeting_notes.txt", "Coded product references.")])
    result = collect_case_analysis_findings(case_dir)

    assert result["flagged_total"] == 1
    item = result["flagged"][0]
    assert item["tag"] == "Notable Item"
    assert item["notable"] is True
    assert item["name"] == "meeting_notes.txt"
    assert item["comment"] == "Coded product references."
    assert item["tagged_by"] == "examiner"


def test_the_apps_own_generated_files_are_never_reported_as_flagged(evidence_root):
    """_auto_tag_case_artifact() tags this app's own exports, hash manifests,
    KMLs and the case index itself. Measured live: a brand-new empty case
    already showed "2 Tagged Items", both of them its own case.json and
    case_index.db. A report that opened by listing those as flagged evidence
    would be worse than one that omitted the section."""
    case_dir = _make_case(evidence_root, "2026-CASE-SYSTAGS")
    system_tagged = [(name, False, f"file_{i}.json", None)
                     for i, name in enumerate(CASE_ROLE_TAG_NAMES.values())]
    _seed_index(case_dir, tags=system_tagged + [("Notable Item", True, "real_evidence.txt", "Matters.")])
    result = collect_case_analysis_findings(case_dir)

    assert result["flagged_total"] == 1
    assert [i["name"] for i in result["flagged"]] == ["real_evidence.txt"]


def test_notable_items_survive_the_flagged_cap(evidence_root):
    """If the list is trimmed, what stays must be what matters most."""
    case_dir = _make_case(evidence_root, "2026-CASE-FLAGCAP")
    ordinary = [("Bookmark", False, f"file{i}.txt", None) for i in range(10)]
    _seed_index(case_dir, tags=ordinary + [("Notable Item", True, "the_important_one.txt", "Read this.")])
    result = collect_case_analysis_findings(case_dir, max_flagged=3)

    assert result["flagged_total"] == 11
    assert len(result["flagged"]) == 3
    assert result["flagged"][0]["name"] == "the_important_one.txt"
