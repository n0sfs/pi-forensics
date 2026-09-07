"""core/case_index_db.py - the per-case SQLite analysis index's schema
seeding, the auto-tagging helper (_auto_tag_case_artifact) that report
export / hash manifest / geolocation KML export call directly whenever they
write a real file to a case folder, the self-healing backfill sweep
(_backfill_case_artifact_tags), and the one-time migration off the original
single lump 'Case Artifact' tag onto four role-specific default tags
(_migrate_legacy_case_artifact_tag)."""
import json
import os
import sqlite3

import pytest

import core.case_index_db as case_index_db


@pytest.fixture
def case_folder(evidence_root):
    """A real, minimal consolidated case folder - just enough for
    case_consolidated_path() to recognize it (a {slug}_case.json marker
    file with the right basename-derived name). Lives inside evidence_root
    (see conftest.py) since case_index_db_path()/safe_path() both sandbox
    to core.paths.EVIDENCE_ROOT - a case folder outside it is correctly
    rejected, matching every other path-accepting function in this app."""
    import pathlib
    folder = pathlib.Path(evidence_root) / "2026-CASE-TEST"
    folder.mkdir()
    (folder / "2026-CASE-TEST_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-TEST", "events": [],
    }))
    return str(folder)


def test_schema_seeds_exactly_eight_default_tags_and_is_idempotent(case_folder):
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    rows = conn.execute("SELECT name, is_default FROM tags ORDER BY name").fetchall()
    conn.close()
    names = {r[0] for r in rows}
    assert names == {
        "Bookmark", "Follow Up", "Notable Item",
        "Report Export", "Analysis Log / Hash", "Geolocation Export", "Backup Snapshot",
        "Case Bundle Export",
    }
    assert all(r[1] == 1 for r in rows)  # every seeded default tag is_default=1

    # Re-running the schema (as every _case_index_connect() call does) must
    # not duplicate the seed rows.
    conn2 = case_index_db._case_index_connect(db_path)
    count = conn2.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
    conn2.close()
    assert count == 8


def test_auto_tag_case_artifact_creates_a_real_row(case_folder):
    target = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    case_index_db._auto_tag_case_artifact(case_folder, target)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    row = conn.execute(
        "SELECT t.name, ti.source_type, ti.path, ti.name, ti.tagged_by "
        "FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE ti.path=?",
        (target,)).fetchone()
    conn.close()
    assert row == ("Report Export", "real_fs", target, "2026-CASE-TEST_case.pdf", "system")


@pytest.mark.parametrize("filename,expected_tag", [
    ("2026-CASE-TEST_case.pdf", "Report Export"),
    ("2026-CASE-TEST_case.html", "Report Export"),
    ("2026-CASE-TEST_case_index.db", "Report Export"),
    ("2026-CASE-TEST_USBDrive-1_hash_manifest_sha256.txt", "Analysis Log / Hash"),
    ("2026-CASE-TEST_USBDrive-1_triage_scan_report.txt", "Analysis Log / Hash"),
    ("2026-CASE-TEST_USBDrive-1_dc3dd.log", "Analysis Log / Hash"),
    ("geolocation_export.kml", "Geolocation Export"),
    ("case_info.json.pre_consolidation_backup", "Backup Snapshot"),
    ("2026-CASE-TEST_report.json.pre_restore_backup", "Backup Snapshot"),
])
def test_auto_tag_case_artifact_picks_the_correct_role_specific_tag(case_folder, filename, expected_tag):
    target = os.path.join(case_folder, filename)
    case_index_db._auto_tag_case_artifact(case_folder, target)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    row = conn.execute(
        "SELECT t.name FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id WHERE ti.path=?",
        (target,)).fetchone()
    conn.close()
    assert row == (expected_tag,)


def test_auto_tag_case_artifact_is_a_no_op_for_an_unrecognized_filename(case_folder):
    # Not one of the four recognized roles - must not create any tagged_items
    # row, and (since nothing else has touched the DB in this test) must not
    # even create the index file.
    target = os.path.join(case_folder, "batmanlego.JPG")
    case_index_db._auto_tag_case_artifact(case_folder, target)
    db_path = case_index_db.case_index_db_path(case_folder)
    assert not os.path.isfile(db_path)


def test_auto_tag_case_artifact_does_not_duplicate_on_repeat_calls(case_folder):
    # Matches the real-world case this exists for: a report export
    # overwrites the same output filename on every re-export, so tagging it
    # again and again must stay a no-op after the first time, not pile up
    # duplicate tagged_items rows.
    target = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    for _ in range(3):
        case_index_db._auto_tag_case_artifact(case_folder, target)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM tagged_items WHERE path=?", (target,)).fetchone()[0]
    conn.close()
    assert count == 1


def test_auto_tag_case_artifact_is_a_silent_no_op_for_a_non_case_folder(tmp_path):
    # Not a real consolidated case (no {slug}_case.json marker) - must not
    # raise, and must not create a database file at all.
    not_a_case = tmp_path / "just_a_folder"
    not_a_case.mkdir()
    case_index_db._auto_tag_case_artifact(str(not_a_case), str(not_a_case / "whatever.txt"))
    assert not any(f.endswith('.db') for f in os.listdir(not_a_case))


def test_auto_tag_case_artifact_is_a_silent_no_op_for_none_or_empty_folder():
    # Must not raise for the "no active case" states every other best-effort
    # case-index write in this app already tolerates (see
    # _record_analysis_result's own docstring for the same contract).
    case_index_db._auto_tag_case_artifact(None, "/some/path.txt")
    case_index_db._auto_tag_case_artifact("", "/some/path.txt")


def test_two_different_files_get_two_distinct_tagged_rows(case_folder):
    a = os.path.join(case_folder, "a_hash_manifest_sha256.txt")
    b = os.path.join(case_folder, "b_geolocation_export.kml")
    case_index_db._auto_tag_case_artifact(case_folder, a)
    case_index_db._auto_tag_case_artifact(case_folder, b)

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM tagged_items").fetchone()[0]
    conn.close()
    assert count == 2


def _all_tagged_role_paths(case_folder):
    """Every path currently tagged under one of the four role-specific
    default tags (not Bookmark/Follow Up/Notable Item) - used by tests that
    only care about backfill/sweep membership, not which exact one of the
    four buckets a file landed in (see the parametrized role-mapping test
    above for that)."""
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    placeholders = ",".join("?" * len(case_index_db.CASE_ROLE_TAG_NAMES))
    rows = conn.execute(
        f"SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id = ti.tag_id "
        f"WHERE t.name IN ({placeholders})",
        list(case_index_db.CASE_ROLE_TAG_NAMES.values())).fetchall()
    conn.close()
    return {r[0] for r in rows}


def test_backfill_tags_pre_existing_artifact_files_never_seen_by_auto_tag(case_folder):
    # The exact gap this exists to close: a report/log/kml file that landed
    # on disk (a legacy case, a manual copy, or simply predates the
    # per-write-site auto-tag call) with no _auto_tag_case_artifact() call
    # ever having run against it. Note the case_folder fixture's own
    # {slug}_case.json marker is itself a recognized report artifact - it
    # gets swept too, correctly, so this asserts membership rather than an
    # exact set.
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    hashlog = os.path.join(case_folder, "2026-CASE-TEST_USBDrive-1_hash_manifest_sha256.txt")
    kml = os.path.join(case_folder, "geolocation_export.kml")
    evidence = os.path.join(case_folder, "batmanlego.JPG")  # not a recognized artifact - must stay untagged
    for p in (report, hashlog, kml, evidence):
        with open(p, "w") as f:
            f.write("x")

    case_index_db._backfill_case_artifact_tags(case_folder)

    tagged_paths = _all_tagged_role_paths(case_folder)
    assert {report, hashlog, kml} <= tagged_paths
    assert evidence not in tagged_paths


def test_backfill_is_idempotent_and_skips_recovery_tool_output_dirs(case_folder):
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    with open(report, "w") as f:
        f.write("x")
    carved_dir = os.path.join(case_folder, "2026-CASE-TEST_ITEM-01_photorec")
    os.makedirs(carved_dir)
    # Same base name pattern classify_case_role() would otherwise match -
    # sitting inside a bulk carved-file output dir must never be swept.
    carved_lookalike = os.path.join(carved_dir, "recovered_case.pdf")
    with open(carved_lookalike, "w") as f:
        f.write("x")

    case_index_db._backfill_case_artifact_tags(case_folder)
    first_paths = _all_tagged_role_paths(case_folder)
    assert report in first_paths
    assert carved_lookalike not in first_paths

    # Re-run - a second sweep may legitimately pick up one new real artifact
    # this app itself just created (the per-case SQLite index file, which is
    # itself a recognized report artifact once it exists on disk), but must
    # never re-tag anything it already tagged, and must still never reach
    # into the carve-output dir. Clear this case_folder's own throttle entry
    # first (2026-09-01, a real performance fix - see the function's own
    # docstring) - without this, the second call below would be a silent
    # no-op (still within the same 300s throttle window as the first call),
    # which would make this test pass for the wrong reason (nothing ran a
    # second time at all) instead of genuinely proving idempotency.
    case_index_db._artifact_backfill_last_run.pop(case_folder, None)
    case_index_db._backfill_case_artifact_tags(case_folder)
    second_paths = _all_tagged_role_paths(case_folder)
    assert carved_lookalike not in second_paths
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    dupes = conn.execute(
        "SELECT path, COUNT(*) c FROM tagged_items GROUP BY tag_id, path HAVING c > 1").fetchall()
    conn.close()
    assert not dupes


def test_backfill_throttle_skips_a_second_sweep_within_the_window(case_folder, monkeypatch):
    # The real 2026-09-01 performance fix, proven directly: a second call
    # within _ARTIFACT_BACKFILL_INTERVAL_SECONDS must not walk the
    # filesystem again at all - confirmed here by monkeypatching os.walk
    # itself to fail loudly if it's ever called a second time, rather than
    # just asserting on the (harder-to-distinguish) end state.
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    with open(report, "w") as f:
        f.write("x")

    case_index_db._backfill_case_artifact_tags(case_folder)
    assert report in _all_tagged_role_paths(case_folder)

    real_walk = case_index_db.os.walk
    def _walk_that_fails_if_called(*a, **k):
        raise AssertionError("os.walk() was called on a throttled second sweep - the throttle didn't take effect")
    monkeypatch.setattr(case_index_db.os, "walk", _walk_that_fails_if_called)
    case_index_db._backfill_case_artifact_tags(case_folder)  # must return immediately, never reach os.walk()
    monkeypatch.setattr(case_index_db.os, "walk", real_walk)


def test_backfill_throttle_records_last_run_time_and_clearing_it_allows_a_real_second_sweep(case_folder):
    assert case_folder not in case_index_db._artifact_backfill_last_run
    case_index_db._backfill_case_artifact_tags(case_folder)
    assert case_folder in case_index_db._artifact_backfill_last_run

    new_report = os.path.join(case_folder, "2026-CASE-TEST_case.html")
    with open(new_report, "w") as f:
        f.write("x")
    # Still throttled - a file created AFTER the first sweep must not be
    # picked up by a second, still-within-the-window call.
    case_index_db._backfill_case_artifact_tags(case_folder)
    assert new_report not in _all_tagged_role_paths(case_folder)

    # Clearing the throttle entry (simulating the window having elapsed)
    # lets the next call genuinely re-sweep and pick it up.
    case_index_db._artifact_backfill_last_run.pop(case_folder, None)
    case_index_db._backfill_case_artifact_tags(case_folder)
    assert new_report in _all_tagged_role_paths(case_folder)


def test_backfill_migrates_legacy_case_artifact_tag_into_role_specific_tags(case_folder):
    # Simulates a case whose index predates the 4-way split: a lump 'Case
    # Artifact' tag with two real files tagged under it, one report-shaped
    # and one geolocation-shaped.
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    kml = os.path.join(case_folder, "geolocation_export.kml")
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    conn.execute("INSERT INTO tags (name, color, notable, is_default, created_at) VALUES ('Case Artifact', 'secondary', 0, 1, datetime('now'))")
    old_tag_id = conn.execute("SELECT id FROM tags WHERE name='Case Artifact'").fetchone()[0]
    for path in (report, kml):
        conn.execute(
            "INSERT INTO tagged_items (tag_id, source_type, path, name, tagged_by, tagged_at) "
            "VALUES (?, 'real_fs', ?, ?, 'system', datetime('now'))",
            (old_tag_id, path, os.path.basename(path)))
    conn.commit()
    conn.close()

    migrate_conn = case_index_db._case_index_connect(db_path)
    case_index_db._migrate_legacy_case_artifact_tag(migrate_conn)
    migrate_conn.close()

    conn = case_index_db._case_index_connect(db_path)
    remaining_old_tag = conn.execute("SELECT id FROM tags WHERE name='Case Artifact'").fetchone()
    report_tag_path = conn.execute(
        "SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id=ti.tag_id WHERE t.name='Report Export'").fetchone()
    geo_tag_path = conn.execute(
        "SELECT ti.path FROM tagged_items ti JOIN tags t ON t.id=ti.tag_id WHERE t.name='Geolocation Export'").fetchone()
    conn.close()
    assert remaining_old_tag is None  # legacy tag deleted once emptied
    assert report_tag_path == (report,)
    assert geo_tag_path == (kml,)


def test_backfill_migration_drops_a_duplicate_rather_than_creating_one(case_folder):
    # A file already tagged under BOTH the legacy lump tag and its correct
    # new role-specific tag (e.g. from a partial migration, or a station
    # that ran an older build after already re-tagging manually) - the
    # migration must not leave two tagged_items rows for the same
    # (tag_id, path) once the legacy tag is folded in.
    report = os.path.join(case_folder, "2026-CASE-TEST_case.pdf")
    case_index_db._auto_tag_case_artifact(case_folder, report)  # tags it under the real 'Report Export' tag first

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    conn.execute("INSERT INTO tags (name, color, notable, is_default, created_at) VALUES ('Case Artifact', 'secondary', 0, 1, datetime('now'))")
    old_tag_id = conn.execute("SELECT id FROM tags WHERE name='Case Artifact'").fetchone()[0]
    conn.execute(
        "INSERT INTO tagged_items (tag_id, source_type, path, name, tagged_by, tagged_at) "
        "VALUES (?, 'real_fs', ?, ?, 'system', datetime('now'))",
        (old_tag_id, report, os.path.basename(report)))
    conn.commit()
    conn.close()

    migrate_conn = case_index_db._case_index_connect(db_path)
    case_index_db._migrate_legacy_case_artifact_tag(migrate_conn)
    migrate_conn.close()

    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM tagged_items ti JOIN tags t ON t.id=ti.tag_id "
        "WHERE t.name='Report Export' AND ti.path=?", (report,)).fetchone()[0]
    conn.close()
    assert count == 1


def test_backfill_is_a_silent_no_op_for_a_non_case_folder(tmp_path):
    not_a_case = tmp_path / "just_a_folder"
    not_a_case.mkdir()
    (not_a_case / "whatever_case.pdf").write_text("x")
    case_index_db._backfill_case_artifact_tags(str(not_a_case))
    assert not any(f.endswith('.db') for f in os.listdir(not_a_case))


def test_backfill_is_a_silent_no_op_for_none_or_empty_folder():
    case_index_db._backfill_case_artifact_tags(None)
    case_index_db._backfill_case_artifact_tags("")


# --- _record_parsed_artifacts / _parsed_artifact_counts (core/browser_artifacts.py's write side) ---

def _sample_history_records():
    return [
        {"artifact_type": "chrome_history", "title": "Example", "url": "https://example.com",
         "value": "3 visit(s)", "timestamp": 1700000000.0, "extra": {"visit_count": 3}},
        {"artifact_type": "chrome_downloads", "title": "evidence.zip", "url": "https://example.com/evidence.zip",
         "value": "/home/user/Downloads/evidence.zip", "timestamp": 1700000100.0, "extra": {"state": "complete"}},
    ]


def test_record_parsed_artifacts_writes_real_rows(case_folder):
    identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": os.path.join(case_folder, "History")}
    written = case_index_db._record_parsed_artifacts(case_folder, identity, _sample_history_records())
    assert written == 2

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    rows = conn.execute(
        "SELECT artifact_type, title, url, value, timestamp, extra_json FROM parsed_artifacts ORDER BY artifact_type").fetchall()
    conn.close()
    assert len(rows) == 2
    history_row = next(r for r in rows if r[0] == "chrome_history")
    assert history_row[1] == "Example"
    assert history_row[2] == "https://example.com"
    assert history_row[4] == 1700000000.0
    assert json.loads(history_row[5]) == {"visit_count": 3}


def test_record_parsed_artifacts_replaces_prior_rows_for_the_same_source(case_folder):
    identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": os.path.join(case_folder, "History")}
    case_index_db._record_parsed_artifacts(case_folder, identity, _sample_history_records())
    # Re-parse with just one record (e.g. a newer, smaller History snapshot) -
    # must replace, not accumulate on top of the first pass's 2 rows.
    case_index_db._record_parsed_artifacts(case_folder, identity, _sample_history_records()[:1])

    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM parsed_artifacts").fetchone()[0]
    conn.close()
    assert count == 1


def test_record_parsed_artifacts_from_different_sources_do_not_collide(case_folder):
    id_a = {"source_type": "real_fs", "path": os.path.join(case_folder, "History")}
    id_b = {"source_type": "real_fs", "path": os.path.join(case_folder, "Cookies")}
    case_index_db._record_parsed_artifacts(case_folder, id_a, _sample_history_records())
    case_index_db._record_parsed_artifacts(case_folder, id_b, [
        {"artifact_type": "chrome_cookies", "title": "session_id", "url": "example.com",
         "value": "[encrypted]", "timestamp": None, "extra": {"secure": True}},
    ])
    db_path = case_index_db.case_index_db_path(case_folder)
    conn = case_index_db._case_index_connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM parsed_artifacts").fetchone()[0]
    conn.close()
    assert count == 3  # 2 from History + 1 from Cookies, both preserved


def test_record_parsed_artifacts_is_a_silent_no_op_for_no_active_case(tmp_path):
    identity = {"source_type": "real_fs", "path": str(tmp_path / "History")}
    written = case_index_db._record_parsed_artifacts(None, identity, _sample_history_records())
    assert written == 0
    written2 = case_index_db._record_parsed_artifacts(str(tmp_path), identity, _sample_history_records())
    assert written2 == 0  # tmp_path isn't a real consolidated case


def test_parsed_artifact_counts_reflects_real_types_and_counts(case_folder):
    id_a = {"source_type": "real_fs", "path": os.path.join(case_folder, "History")}
    case_index_db._record_parsed_artifacts(case_folder, id_a, _sample_history_records())
    counts = case_index_db._parsed_artifact_counts(case_folder)
    assert counts == {"chrome_history": 1, "chrome_downloads": 1}


def test_parsed_artifact_counts_empty_dict_when_never_indexed(case_folder):
    assert case_index_db._parsed_artifact_counts(case_folder) == {}


# --- has_case_analysis_activity (the Home tab Guided Workflow's step-3 signal) ---

def _tag(is_default, count):
    return {"is_default": is_default, "count": count}


def test_has_case_analysis_activity_false_when_nothing_has_happened():
    assert case_index_db.has_case_analysis_activity(0, 0, 0, {}, []) is False


def test_has_case_analysis_activity_false_for_only_default_role_tags():
    # The exact false-positive this function exists to avoid: an acquisition
    # (or a report export) alone gets the case auto-tagged under one of the
    # four role-specific default tags (Report Export etc.) with zero real
    # analysis ever having run - that must not read as "tools were run".
    tags = [_tag(is_default=True, count=1), _tag(is_default=True, count=3)]
    assert case_index_db.has_case_analysis_activity(0, 0, 0, {}, tags) is False


@pytest.mark.parametrize("analysis_results_count,total_files,keyword_hit_total,parsed_artifact_counts,tags,label", [
    (1, 0, 0, {}, [], "a Binwalk/ClamAV/Strings/Memory-Forensics analysis_results row"),
    (0, 1, 0, {}, [], "the whole-image Triage Scan indexed at least one file"),
    (0, 0, 1, {}, [], "a keyword/Quick-Triage-Scan hit was found"),
    (0, 0, 0, {"chrome_history": 2}, [], "a browser artifact was parsed"),
    (0, 0, 0, {}, [_tag(is_default=False, count=1)], "an examiner applied a real (non-default) tag"),
])
def test_has_case_analysis_activity_true_for_each_independent_signal(
        analysis_results_count, total_files, keyword_hit_total, parsed_artifact_counts, tags, label):
    assert case_index_db.has_case_analysis_activity(
        analysis_results_count, total_files, keyword_hit_total, parsed_artifact_counts, tags) is True, label


def test_has_case_analysis_activity_false_for_a_real_tag_that_was_created_but_never_applied():
    # A custom tag can exist (created via Settings > Manage Tags) with
    # nothing tagged under it yet - count=0 - which must not count as
    # activity even though it's not one of the four default role tags.
    tags = [_tag(is_default=False, count=0)]
    assert case_index_db.has_case_analysis_activity(0, 0, 0, {}, tags) is False


# --- normalize_phone_number / correlate_contacts (Android/iOS pattern-of-life, 2026-09-04) ---

@pytest.mark.parametrize("raw,expected", [
    ("+15551234567", "5551234567"),      # E.164 US -> country code dropped
    ("(555) 123-4567", "5551234567"),    # US formatted, no country code
    ("555-123-4567", "5551234567"),
    ("5551234567", "5551234567"),        # already bare 10-digit
    ("15551234567@s.whatsapp.net", "5551234567"),  # WhatsApp JID, country-coded
    ("5551234567@s.whatsapp.net", "5551234567"),   # WhatsApp JID, no country code
])
def test_normalize_phone_number_converges_every_real_format_to_the_same_key(raw, expected):
    assert case_index_db.normalize_phone_number(raw) == expected


def test_normalize_phone_number_does_not_strip_a_non_us_country_code():
    # Only an exactly-11-digit result starting with '1' gets the leading
    # digit dropped (the real US/NANP shape) - a 12-digit international
    # number (e.g. a UK +44 number) is a genuinely different length and
    # must be left alone, not have its own leading digit wrongly treated
    # as a US country code.
    assert case_index_db.normalize_phone_number("+442079460958") == "442079460958"


@pytest.mark.parametrize("raw", [None, "", "911", "12", "g.us", "123456789012345678"])
def test_normalize_phone_number_returns_none_for_implausible_values(raw):
    assert case_index_db.normalize_phone_number(raw) is None


def _contact_record(artifact_type, title, phones=None, single_number=None):
    extra = {}
    if phones is not None:
        extra["phones"] = phones
    if single_number is not None:
        extra["number"] = single_number
    return {"artifact_type": artifact_type, "title": title, "url": "",
            "value": title, "timestamp": None, "extra": extra}


def _comm_record(artifact_type, counterpart_key, counterpart_value, timestamp=1700000000.0):
    return {"artifact_type": artifact_type, "title": "msg", "url": "",
            "value": "hello", "timestamp": timestamp, "extra": {counterpart_key: counterpart_value}}


def _identity(case_folder, path):
    return {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None, "path": path}


def test_correlate_contacts_resolves_sms_counterpart_despite_different_raw_formats(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "mmssms.db"),
        [_comm_record("android_sms_message", "address", "(555) 123-4567")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 1
    assert len(result["contacts"]) == 1
    contact = result["contacts"][0]
    assert contact["normalized_number"] == "5551234567"
    assert contact["display_names"] == ["Jane Doe"]
    assert contact["contact_sources"] == ["android_contact"]
    assert contact["communication_counts"] == {"SMS": 1}
    assert contact["total_communications"] == 1
    assert result["unresolved_communication_count"] == 0


def test_correlate_contacts_corroborates_a_number_seen_by_more_than_one_contact_source(case_folder):
    # Real, disclosed value of this correlation: a number independently
    # named "Jane Doe" by BOTH the phone's own contacts AND WhatsApp's own
    # contacts is stronger corroboration than either alone.
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "wa.db"),
        [_contact_record("whatsapp_contact", "Jane W.", single_number="15551234567")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 1  # same normalized number, one entry
    # No communications seeded, so no aggregated "contacts" list entry -
    # this test only proves the contact-side indexing merges both sources.


def test_correlate_contacts_counts_an_unmatched_counterpart_as_unresolved_not_a_ghost_contact(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "mmssms.db"),
        [_comm_record("android_sms_message", "address", "+15559999999")])  # a different, unknown number

    result = case_index_db.correlate_contacts(case_folder)
    assert result["unresolved_communication_count"] == 1
    assert result["contacts"] == []


def test_correlate_contacts_sorts_by_total_communication_count_descending(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Busy Contact", phones=["+15551111111"]),
         _contact_record("android_contact", "Quiet Contact", phones=["+15552222222"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "mmssms.db"),
        [_comm_record("android_sms_message", "address", "+15552222222"),
         _comm_record("android_sms_message", "address", "+15551111111"),
         _comm_record("android_sms_message", "address", "+15551111111")])

    result = case_index_db.correlate_contacts(case_folder)
    assert [c["display_names"] for c in result["contacts"]] == [["Busy Contact"], ["Quiet Contact"]]
    assert result["contacts"][0]["total_communications"] == 2
    assert result["contacts"][1]["total_communications"] == 1


def test_correlate_contacts_deliberately_excludes_leapp_sourced_types(case_folder):
    # See core/case_index_db.py's own module comment: leapp_contact/
    # leapp_sms_message store ALEAPP's raw TSV columns generically under
    # extra["row"], with no confirmed real column name for a phone number
    # - correlating them would mean guessing, which this app's own
    # established discipline treats as worse than not covering it. Seed
    # rows that WOULD match if these types were (wrongly) included, and
    # confirm they are not.
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "leapp_contacts.tsv"),
        [{"artifact_type": "leapp_contact", "title": "Should Not Correlate", "url": "",
          "value": "x", "timestamp": None, "extra": {"phones": ["+15551234567"]}}])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "leapp_sms.tsv"),
        [{"artifact_type": "leapp_sms_message", "title": "x", "url": "", "value": "x",
          "timestamp": 1700000000.0, "extra": {"address": "+15551234567"}}])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 0
    assert result["contacts"] == []
    assert result["unresolved_communication_count"] == 0  # leapp_sms_message isn't a scanned comm type at all


def test_correlate_contacts_returns_the_empty_shape_for_a_case_never_indexed(case_folder):
    # case_folder exists (a real consolidated case) but _record_parsed_
    # artifacts() was never called, so no analysis-index DB file exists
    # yet - must return the correctly-shaped empty result, not raise.
    result = case_index_db.correlate_contacts(case_folder)
    assert result == {"contacts_indexed_count": 0, "unresolved_communication_count": 0,
                       "truncated": False, "contacts": [], "frequent_contact_count": 0,
                       "frequent_cumulative_share_threshold": case_index_db.CONTACT_CORRELATION_FREQUENT_CUMULATIVE_SHARE}


# --- 2026-09-05 fixes: companion-app + .ab-backup-sourced Android types
# were confirmed (via a real code-grounded review) to have real, correct
# extra_json shapes but were never wired into either correlation dict -
# not a deliberate scope decision like the leapp_* exclusion above, an
# unaddressed gap. ---

def _companion_contact_row(display_name, mimetype, data1):
    return {"artifact_type": "android_companion_contact", "title": display_name, "url": "",
            "value": data1, "timestamp": None,
            "extra": {"mimetype": mimetype, "data1": data1}}


def test_correlate_contacts_includes_companion_sms_contact_and_call_log_types(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "companion_contacts.json"),
        [_companion_contact_row("Jane Doe", "vnd.android.cursor.item/phone_v2", "+15551234567")])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "companion_sms.json"),
        [_comm_record("android_companion_sms_message", "address", "(555) 123-4567")])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "companion_calllog.json"),
        [_comm_record("android_companion_call_log_entry", "number", "555-123-4567")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 1
    contact = result["contacts"][0]
    assert contact["normalized_number"] == "5551234567"
    assert contact["contact_sources"] == ["android_companion_contact"]
    assert contact["communication_counts"] == {"SMS": 1, "Call": 1}
    assert contact["total_communications"] == 2
    assert result["unresolved_communication_count"] == 0


def test_correlate_contacts_companion_contact_only_treats_phone_mimetype_rows_as_a_number(case_folder):
    # A companion-contact record is one row per ContactsContract.Data item -
    # an email-type row's data1 must never be silently misread as a phone
    # number just because it shares the single_key "data1" with a real
    # phone-type row.
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "companion_contacts.json"),
        [_companion_contact_row("Jane Doe", "vnd.android.cursor.item/email_v2", "jane@example.com")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 0
    assert result["contacts"] == []


def test_correlate_contacts_includes_native_mms_and_ab_backup_sms_mms_types(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "mmssms.db"),
        [_comm_record("android_mms_message", "counterpart", "+15551234567")])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "backup1.ab"),
        [_comm_record("android_ab_sms_message", "address", "+15551234567")])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "backup2.ab"),
        [{"artifact_type": "android_ab_mms_message", "title": "mms", "url": None, "value": "hi",
          "timestamp": 1700000000.0, "extra": {"addresses": ["+15551234567"]}}])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 1
    contact = result["contacts"][0]
    assert contact["communication_counts"] == {"MMS": 2, "SMS": 1}
    assert contact["total_communications"] == 3
    assert result["unresolved_communication_count"] == 0


def test_correlate_contacts_resolves_each_participant_of_a_group_mms_separately(case_folder):
    # A real correctness risk this fix specifically guards against: naively
    # normalize_phone_number()-ing a comma-joined "addr1, addr2" string (or
    # a genuine list) as one blob glues two real numbers into one bogus,
    # coincidentally-plausible-length digit string instead of crediting
    # each real participant.
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Alice", phones=["+15551111111"]),
         _contact_record("android_contact", "Bob", phones=["+15552222222"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "mmssms.db"),
        # android_mms_message's own real comma-joined convention
        [_comm_record("android_mms_message", "counterpart", "+15551111111, +15552222222")])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "backup.ab"),
        # android_ab_mms_message's own real genuine-list shape
        [{"artifact_type": "android_ab_mms_message", "title": "mms", "url": None, "value": "hi",
          "timestamp": 1700000001.0, "extra": {"addresses": ["+15551111111", "+15552222222"]}}])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts_indexed_count"] == 2
    by_number = {c["normalized_number"]: c for c in result["contacts"]}
    assert set(by_number.keys()) == {"5551111111", "5552222222"}
    # Each of the 2 comm rows credited BOTH real participants once each -
    # never one glued-together bogus number, never only the first/last.
    assert by_number["5551111111"]["total_communications"] == 2
    assert by_number["5552222222"]["total_communications"] == 2
    assert result["unresolved_communication_count"] == 0


# --- 2026-09-07: direction/duration extraction + relationship tiering,
# built for the new Pattern of Life relationship graph. Every value used
# below (which extra_json key, which raw values mean incoming/outgoing)
# was individually confirmed against the real parser source that writes
# it - see CONTACT_CORRELATION_COMM_TYPES's own comments in
# core/case_index_db.py for exactly where each came from. ---

def _comm_row(artifact_type, counterpart_key, counterpart_value, extra_extra=None, timestamp=1700000000.0):
    """Like _comm_record() above, but lets a test also set direction/
    duration/etc. fields in extra - _comm_record() itself only ever sets
    the one counterpart key, too narrow for these tests."""
    extra = {counterpart_key: counterpart_value}
    extra.update(extra_extra or {})
    return {"artifact_type": artifact_type, "title": "msg", "url": "",
            "value": "hello", "timestamp": timestamp, "extra": extra}


def test_classify_comm_direction_reads_the_already_resolved_string_label_for_native_types():
    spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_call_log"]
    assert case_index_db._classify_comm_direction(spec, {"direction": "Incoming"}) == "incoming"
    assert case_index_db._classify_comm_direction(spec, {"direction": "Outgoing"}) == "outgoing"


def test_classify_comm_direction_leaves_missed_voicemail_rejected_blocked_unclassified():
    # A call this app can't honestly call "incoming" or "outgoing" - it
    # still counts toward total_communications elsewhere, just not toward
    # direction_counts.
    spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_call_log"]
    for value in ("Missed", "Voicemail", "Rejected", "Blocked", "Type 99", None):
        assert case_index_db._classify_comm_direction(spec, {"direction": value}) is None


def test_classify_comm_direction_reads_the_raw_numeric_message_box_code_for_ab_backup_types():
    # android_ab_sms_message/android_ab_mms_message store the RAW int, not
    # a resolved string, under "type"/"msg_box" - confirmed the numeric
    # convention (1=incoming, {2,4}=outgoing) holds for both despite each
    # module's own differing string label at value 1 ("Received" vs
    # "Inbox") - see the module comment this test is grounded in.
    sms_spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_ab_sms_message"]
    assert case_index_db._classify_comm_direction(sms_spec, {"type": 1}) == "incoming"
    assert case_index_db._classify_comm_direction(sms_spec, {"type": 2}) == "outgoing"
    assert case_index_db._classify_comm_direction(sms_spec, {"type": 4}) == "outgoing"
    assert case_index_db._classify_comm_direction(sms_spec, {"type": 3}) is None  # Draft
    mms_spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_ab_mms_message"]
    assert case_index_db._classify_comm_direction(mms_spec, {"msg_box": 1}) == "incoming"
    assert case_index_db._classify_comm_direction(mms_spec, {"msg_box": 2}) == "outgoing"


def test_classify_comm_direction_returns_none_for_a_comm_type_with_no_direction_concept():
    # A hypothetical spec with no direction_field at all (matches how a
    # future comm type could be added without direction support yet).
    assert case_index_db._classify_comm_direction({}, {"direction": "Incoming"}) is None


def test_extract_comm_duration_seconds_reads_the_real_field_when_present():
    spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_call_log"]
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": 42}) == 42.0
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": "37.5"}) == 37.5


def test_extract_comm_duration_seconds_is_zero_for_a_type_with_no_duration_concept():
    # android_sms_message's own spec has no duration_field at all.
    spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_sms_message"]
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": 999}) == 0.0


def test_extract_comm_duration_seconds_never_raises_or_goes_negative_on_garbage():
    spec = case_index_db.CONTACT_CORRELATION_COMM_TYPES["android_call_log"]
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": None}) == 0.0
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": "not a number"}) == 0.0
    assert case_index_db._extract_comm_duration_seconds(spec, {}) == 0.0
    assert case_index_db._extract_comm_duration_seconds(spec, {"duration_seconds": -50}) == 0.0


def test_correlate_contacts_aggregates_direction_and_duration_per_contact(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "calls.db"),
        [_comm_row("android_call_log", "number", "+15551234567",
                   {"direction": "Incoming", "duration_seconds": 60}, timestamp=1700000001.0),
         _comm_row("android_call_log", "number", "+15551234567",
                   {"direction": "Outgoing", "duration_seconds": 120}, timestamp=1700000002.0),
         _comm_row("android_call_log", "number", "+15551234567",
                   {"direction": "Missed", "duration_seconds": 0}, timestamp=1700000003.0)])

    result = case_index_db.correlate_contacts(case_folder)
    contact = result["contacts"][0]
    assert contact["total_communications"] == 3
    # 2 classified (1 incoming, 1 outgoing) - the Missed call counts
    # toward the total above but not toward either direction bucket.
    assert contact["direction_counts"] == {"incoming": 1, "outgoing": 1}
    assert contact["total_duration_seconds"] == 180.0


def test_correlate_contacts_total_duration_is_zero_for_a_contact_with_only_non_call_communications(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Jane Doe", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "sms.db"),
        [_comm_record("android_sms_message", "address", "+15551234567")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts"][0]["total_duration_seconds"] == 0.0


def test_correlate_contacts_tiers_a_frequent_contact_covering_the_cumulative_share(case_folder):
    # 3 contacts: 50, 30, and 5 communications (grand_total=85). The 80%
    # cumulative cut is reached at 50+30=80 (94% >= 80%), so both the
    # top-2 contacts are "frequent" (each well above the min-count floor)
    # and the 3rd, lower-volume contact is "regular" (5 > 1, not one-off).
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Alice", phones=["+15551111111"]),
         _contact_record("android_contact", "Bob", phones=["+15552222222"]),
         _contact_record("android_contact", "Carol", phones=["+15553333333"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "sms.db"),
        [_comm_record("android_sms_message", "address", "+15551111111", t) for t in range(50)] +
        [_comm_record("android_sms_message", "address", "+15552222222", t) for t in range(30)] +
        [_comm_record("android_sms_message", "address", "+15553333333", t) for t in range(5)])

    result = case_index_db.correlate_contacts(case_folder)
    tiers_by_name = {c["display_names"][0]: c["tier"] for c in result["contacts"]}
    assert tiers_by_name == {"Alice": "frequent", "Bob": "frequent", "Carol": "regular"}
    assert result["frequent_contact_count"] == 2
    assert result["frequent_cumulative_share_threshold"] == 0.80


def test_correlate_contacts_tiers_exactly_one_communication_as_one_off(case_folder):
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Solo Contact", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "sms.db"),
        [_comm_record("android_sms_message", "address", "+15551234567")])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts"][0]["tier"] == "one_off"
    # The min-count floor (3) must keep a single, tiny dataset's only
    # contact from being mislabeled "frequent" purely from being
    # mathematically 100% of a trivial total - see CONTACT_CORRELATION_
    # FREQUENT_MIN_COUNT's own comment in core/case_index_db.py.
    assert result["frequent_contact_count"] == 0


def test_correlate_contacts_tiers_a_moderate_repeat_contact_as_regular_not_frequent_or_one_off(case_folder):
    # 2 communications, below the min-count-3 floor for "frequent" even
    # though it could mathematically clear the 80% cumulative share on
    # its own in a tiny dataset, and more than the single "one_off" case.
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "contacts2.db"),
        [_contact_record("android_contact", "Twice Contact", phones=["+15551234567"])])
    case_index_db._record_parsed_artifacts(
        case_folder, _identity(case_folder, "sms.db"),
        [_comm_record("android_sms_message", "address", "+15551234567", 1700000001.0),
         _comm_record("android_sms_message", "address", "+15551234567", 1700000002.0)])

    result = case_index_db.correlate_contacts(case_folder)
    assert result["contacts"][0]["tier"] == "regular"
    assert result["frequent_contact_count"] == 0
