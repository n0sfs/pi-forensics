"""core/browser_artifacts.py - Chrome/Chromium-family, Firefox, and Safari
real per-app artifact parsing (History, Downloads, Bookmarks, Cookies). No
POSIX dependency - runs on every platform. Builds real SQLite files/JSON/
plists/binarycookies matching each browser's actual on-disk schema rather
than mocking the parser, so a schema-shape mistake would actually fail
these tests.
"""
import json
import os
import plistlib
import sqlite3
import struct

import pytest

import core.browser_artifacts as ba


# --- _evidence_path_basename: a real bug caught by running this suite on
# the Pi's Linux venv, not just the Windows dev machine (see
# test_parse_chrome_downloads_real_rows_with_state_labels below, which
# passed on Windows and failed on Linux before this helper existed) ---

def test_evidence_path_basename_handles_windows_separators_on_any_platform():
    # os.path.basename() alone only recognizes the RUNNING process's own
    # separator - '\\' is not a separator on POSIX, so this must not
    # silently return the whole Windows path unchanged.
    assert ba._evidence_path_basename(r"C:\Users\suspect\Downloads\evidence.zip") == "evidence.zip"


def test_evidence_path_basename_handles_posix_separators():
    assert ba._evidence_path_basename("/home/suspect/Downloads/evidence.zip") == "evidence.zip"


def test_evidence_path_basename_empty_or_none_returns_empty_string():
    assert ba._evidence_path_basename("") == ""
    assert ba._evidence_path_basename(None) == ""


# --- WebKit/Chrome epoch conversion ---

def test_webkit_epoch_zero_point_round_trips_to_unix_epoch():
    # 1970-01-01 00:00:00 UTC expressed in WebKit microseconds-since-1601.
    webkit_us = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    assert ba.webkit_time_to_unix(webkit_us) == 0.0


def test_webkit_time_zero_or_empty_means_no_timestamp():
    assert ba.webkit_time_to_unix(0) is None
    assert ba.webkit_time_to_unix(None) is None
    assert ba.webkit_time_to_unix("") is None


def test_webkit_time_accepts_a_numeric_string_like_bookmarks_json_stores():
    webkit_us = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    assert ba.webkit_time_to_unix(str(webkit_us)) == 0.0


def test_webkit_time_unparseable_value_returns_none():
    assert ba.webkit_time_to_unix("not-a-number") is None


# --- Chrome History (urls + visits + downloads share one SQLite file) ---

def _build_chrome_history_db(path, url_rows, download_rows=()):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER, hidden INTEGER)")
    conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER)")
    conn.executemany("INSERT INTO urls (url, title, visit_count, last_visit_time, hidden) VALUES (?,?,?,?,0)", url_rows)
    if download_rows:
        conn.execute(
            "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, "
            "start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER)")
        conn.executemany(
            "INSERT INTO downloads (target_path, tab_url, start_time, end_time, received_bytes, total_bytes, state) "
            "VALUES (?,?,?,?,?,?,?)", download_rows)
    conn.commit()
    conn.close()


def test_parse_chrome_history_returns_real_url_rows(tmp_path):
    db_path = str(tmp_path / "History")
    webkit_now = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    _build_chrome_history_db(db_path, [
        ("https://example.com/page", "Example Page", 3, webkit_now),
        ("https://evil.example.net/phish", "Totally Legit Bank Login", 1, webkit_now),
    ])
    result = ba.parse_chrome_history_db(db_path)
    urls = {h["url"] for h in result["history"]}
    assert urls == {"https://example.com/page", "https://evil.example.net/phish"}
    entry = next(h for h in result["history"] if h["url"] == "https://example.com/page")
    assert entry["title"] == "Example Page"
    assert entry["timestamp"] == 0.0
    assert entry["extra"]["visit_count"] == 3
    assert result["downloads"] == []  # no downloads table in this fixture - must degrade gracefully, not crash


def test_parse_chrome_history_caps_at_the_documented_limit(tmp_path):
    db_path = str(tmp_path / "History")
    webkit_now = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    rows = [(f"https://example.com/{i}", f"Page {i}", 1, webkit_now + i) for i in range(ba.BROWSER_ARTIFACT_MAX_HISTORY + 50)]
    _build_chrome_history_db(db_path, rows)
    result = ba.parse_chrome_history_db(db_path)
    assert len(result["history"]) == ba.BROWSER_ARTIFACT_MAX_HISTORY


def test_parse_chrome_downloads_real_rows_with_state_labels(tmp_path):
    db_path = str(tmp_path / "History")
    webkit_now = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    _build_chrome_history_db(db_path, [], download_rows=[
        (r"C:\Users\suspect\Downloads\evidence.zip", "https://example.com/evidence.zip",
         webkit_now, webkit_now + 5_000_000, 1024, 1024, 1),
    ])
    result = ba.parse_chrome_history_db(db_path)
    assert len(result["downloads"]) == 1
    dl = result["downloads"][0]
    assert dl["title"] == "evidence.zip"
    assert dl["value"].endswith("evidence.zip")
    assert dl["extra"]["state"] == "complete"
    assert dl["extra"]["total_bytes"] == 1024


def test_parse_history_on_a_file_with_no_recognizable_tables_returns_empty_not_error(tmp_path):
    db_path = str(tmp_path / "History")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE something_unrelated (id INTEGER)")
    conn.commit()
    conn.close()
    result = ba.parse_chrome_history_db(db_path)
    assert result == {"history": [], "downloads": []}


# --- Chrome Cookies ---

def _build_chrome_cookies_db(path, rows):
    """rows: list of (host_key, name, value, encrypted_value_bytes, path, expires_utc, is_secure, is_httponly, creation_utc)."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, "
        "path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, creation_utc INTEGER)")
    conn.executemany(
        "INSERT INTO cookies (host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc) "
        "VALUES (?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def test_parse_chrome_cookies_plaintext_value_shown_directly(tmp_path):
    db_path = str(tmp_path / "Cookies")
    webkit_now = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    _build_chrome_cookies_db(db_path, [
        ("example.com", "session_id", "abc123", b"", "/", webkit_now, 1, 1, webkit_now),
    ])
    cookies = ba.parse_chrome_cookies_db(db_path)
    assert len(cookies) == 1
    assert cookies[0]["value"] == "abc123"
    assert cookies[0]["extra"]["secure"] is True
    assert cookies[0]["extra"]["httponly"] is True


def test_parse_chrome_cookies_encrypted_value_is_disclosed_not_guessed(tmp_path):
    # Modern Chrome: 'value' is empty, real data lives (encrypted) in
    # encrypted_value - must never be silently blank or fabricated.
    db_path = str(tmp_path / "Cookies")
    webkit_now = ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000
    _build_chrome_cookies_db(db_path, [
        ("bank.example.com", "auth_token", "", b"\x01\x02\x03encryptedgarbage", "/", webkit_now, 1, 0, webkit_now),
    ])
    cookies = ba.parse_chrome_cookies_db(db_path)
    assert cookies[0]["value"] == "[encrypted]"
    assert cookies[0]["title"] == "auth_token"
    assert cookies[0]["url"] == "bank.example.com"


def test_parse_cookies_on_a_file_with_no_cookies_table_returns_empty(tmp_path):
    db_path = str(tmp_path / "Cookies")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE nope (id INTEGER)")
    conn.commit()
    conn.close()
    assert ba.parse_chrome_cookies_db(db_path) == []


# --- Chrome Bookmarks (JSON, not SQLite) ---

def _chrome_bookmarks_fixture():
    webkit_now = str(ba.WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000)
    return {
        "roots": {
            "bookmark_bar": {
                "type": "folder", "name": "Bookmarks Bar",
                "children": [
                    {"type": "url", "name": "Example", "url": "https://example.com", "date_added": webkit_now},
                    {
                        "type": "folder", "name": "Work",
                        "children": [
                            {"type": "url", "name": "Nested Link", "url": "https://work.example.com", "date_added": webkit_now},
                        ],
                    },
                ],
            },
            "other": {"type": "folder", "name": "Other Bookmarks", "children": []},
        },
    }


def test_parse_chrome_bookmarks_flat_and_nested(tmp_path):
    path = tmp_path / "Bookmarks"
    path.write_text(json.dumps(_chrome_bookmarks_fixture()))
    bookmarks = ba.parse_chrome_bookmarks_json(str(path))
    by_name = {b["title"]: b for b in bookmarks}
    assert by_name["Example"]["url"] == "https://example.com"
    assert by_name["Example"]["value"] == "Bookmarks Bar"
    assert by_name["Nested Link"]["url"] == "https://work.example.com"
    assert by_name["Nested Link"]["value"] == "Bookmarks Bar/Work"  # folder breadcrumb preserved
    assert by_name["Example"]["timestamp"] == 0.0


def test_parse_bookmarks_on_malformed_json_returns_empty_not_error(tmp_path):
    path = tmp_path / "Bookmarks"
    path.write_text("{not valid json")
    assert ba.parse_chrome_bookmarks_json(str(path)) == []


def test_parse_bookmarks_missing_roots_key_returns_empty(tmp_path):
    path = tmp_path / "Bookmarks"
    path.write_text(json.dumps({"version": 1}))
    assert ba.parse_chrome_bookmarks_json(str(path)) == []


# --- Dispatcher ---

def test_dispatch_routes_by_exact_filename(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ba, "parse_chrome_history_db", lambda p: calls.append(("history", p)) or {"history": [{"a": 1}], "downloads": []})
    monkeypatch.setattr(ba, "parse_chrome_cookies_db", lambda p: calls.append(("cookies", p)) or [{"b": 2}])
    monkeypatch.setattr(ba, "parse_chrome_bookmarks_json", lambda p: calls.append(("bookmarks", p)) or [{"c": 3}])

    assert ba.parse_browser_profile_file("/x/History", "History") == [{"a": 1}]
    assert ba.parse_browser_profile_file("/x/Cookies", "Cookies") == [{"b": 2}]
    assert ba.parse_browser_profile_file("/x/Bookmarks", "Bookmarks") == [{"c": 3}]
    assert ba.parse_browser_profile_file("/x/Unrelated", "Unrelated") == []
    assert {c[0] for c in calls} == {"history", "cookies", "bookmarks"}


def test_dispatch_swallows_a_parse_exception_and_returns_empty(tmp_path):
    # A file matching the name 'History' but not actually a valid SQLite
    # database (corrupted, truncated, or just coincidentally named).
    bad_path = tmp_path / "History"
    bad_path.write_text("not a real sqlite file")
    result = ba.parse_browser_profile_file(str(bad_path), "History")
    assert result == []


# --- find_browser_artifact_files (real-fs candidate discovery) ---

def test_find_browser_artifact_files_matches_by_exact_basename_anywhere_nested(tmp_path):
    deep = tmp_path / "Users" / "suspect" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    deep.mkdir(parents=True)
    (deep / "History").write_text("x")
    (deep / "Cookies").write_text("x")
    (deep / "Bookmarks").write_text("x")
    (deep / "Preferences").write_text("x")  # not a recognized artifact filename - must not match
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"History", "Cookies", "Bookmarks"}
    assert truncated is False


def test_find_browser_artifact_files_skips_bulk_carve_output_dirs(tmp_path):
    real = tmp_path / "Default"
    real.mkdir()
    (real / "History").write_text("x")
    carved = tmp_path / "CASE_ITEM-01_photorec" / "Default"
    carved.mkdir(parents=True)
    (carved / "History").write_text("x")  # same filename, inside a carve-output dir - must never be found
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    assert len(found) == 1
    assert "photorec" not in found[0]


def test_find_browser_artifact_files_empty_dir_returns_empty(tmp_path):
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    assert found == []
    assert truncated is False


def test_find_browser_artifact_files_truncates_at_the_candidate_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ba, "BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES", 2)
    for i in range(4):
        d = tmp_path / f"profile{i}"
        d.mkdir()
        (d / "History").write_text("x")
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is True


def test_find_browser_artifact_files_matches_firefox_filenames_too(tmp_path):
    # Firefox profile folders are randomly-named (<hash>.default-release) -
    # basename-only matching (same approach as Chrome) finds the files
    # regardless of what the containing profile folder is called.
    profile = tmp_path / "Users" / "suspect" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "a1b2c3d4.default-release"
    profile.mkdir(parents=True)
    (profile / "places.sqlite").write_text("x")
    (profile / "cookies.sqlite").write_text("x")
    (profile / "prefs.js").write_text("x")  # not a recognized artifact filename - must not match
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"places.sqlite", "cookies.sqlite"}
    assert truncated is False


def test_find_browser_artifact_files_matches_chrome_and_firefox_in_one_walk(tmp_path):
    chrome_dir = tmp_path / "chrome_profile"
    chrome_dir.mkdir()
    (chrome_dir / "History").write_text("x")
    firefox_dir = tmp_path / "firefox_profile"
    firefox_dir.mkdir()
    (firefox_dir / "places.sqlite").write_text("x")
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"History", "places.sqlite"}


# --- Firefox epoch conversion (PRTime - microseconds since the Unix epoch,
# NOT the WebKit epoch Chrome uses above) ---

def test_firefox_epoch_zero_point_round_trips_to_unix_epoch():
    assert ba.firefox_time_to_unix(0) is None  # 0 means "unset", not the epoch itself
    # A known, hand-computed real PRTime: 2024-01-01 00:00:00 UTC.
    prtime_us = 1704067200 * 1_000_000
    assert ba.firefox_time_to_unix(prtime_us) == 1704067200.0


def test_firefox_time_zero_or_empty_means_no_timestamp():
    assert ba.firefox_time_to_unix(0) is None
    assert ba.firefox_time_to_unix(None) is None
    assert ba.firefox_time_to_unix("") is None


def test_firefox_time_accepts_a_numeric_string():
    assert ba.firefox_time_to_unix(str(1704067200 * 1_000_000)) == 1704067200.0


def test_firefox_time_unparseable_value_returns_none():
    assert ba.firefox_time_to_unix("not-a-number") is None


def test_firefox_and_chrome_epochs_are_genuinely_different_conversions():
    # The exact real-world gotcha this module's own docstring warns about -
    # the same raw microsecond value must NOT produce the same Unix
    # timestamp under both conversions (they differ by exactly the WebKit
    # epoch offset, ~369 years). A copy-paste bug routing Firefox values
    # through webkit_time_to_unix() would silently produce timestamps
    # centuries off, so this is asserted directly rather than trusted.
    raw_us = 1704067200 * 1_000_000
    assert ba.firefox_time_to_unix(raw_us) != ba.webkit_time_to_unix(raw_us)
    assert ba.webkit_time_to_unix(raw_us) == ba.firefox_time_to_unix(raw_us) - ba.WEBKIT_EPOCH_OFFSET_SECONDS


# --- Firefox History + Bookmarks (moz_places/moz_bookmarks, both live in
# 'places.sqlite') ---

def _build_firefox_places_db(path, place_rows, bookmark_rows=(), anno_rows=()):
    """place_rows: [(id, url, title, visit_count, last_visit_date), ...]
    bookmark_rows: [(id, type, fk, parent, title, dateAdded), ...] - type=1
    is a real bookmark, type=2 a folder (used as a parent, never inserted
    as a moz_places row itself).
    anno_rows: [(place_id, anno_attribute_id, content, dateAdded), ...] -
    the download-tracking annotation rows; anno_attribute_id must match a
    real id from moz_anno_attributes."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)")
    conn.executemany("INSERT INTO moz_places VALUES (?,?,?,?,?)", place_rows)
    conn.execute("CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER)")
    conn.executemany("INSERT INTO moz_bookmarks VALUES (?,?,?,?,?,?)", bookmark_rows)
    conn.execute("CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI')")
    conn.execute("CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER)")
    conn.executemany("INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?,?,?,?)", anno_rows)
    conn.commit()
    conn.close()


def test_parse_firefox_history_returns_real_url_rows(tmp_path):
    db_path = tmp_path / "places.sqlite"
    visit_us = 1704067200 * 1_000_000
    _build_firefox_places_db(str(db_path), [
        (1, "https://mail.example.com/inbox", "Example Mail - Inbox", 12, visit_us),
        (2, "https://never-visited.example.com", "No visits yet", 0, None),  # last_visit_date NULL - must be excluded (WHERE clause)
    ])
    result = ba.parse_firefox_places_db(str(db_path))
    assert len(result["history"]) == 1
    row = result["history"][0]
    assert row["artifact_type"] == "firefox_history"
    assert row["url"] == "https://mail.example.com/inbox"
    assert row["title"] == "Example Mail - Inbox"
    assert row["value"] == "12 visit(s)"
    assert row["timestamp"] == 1704067200.0


def test_parse_firefox_bookmarks_real_row_with_parent_folder_title(tmp_path):
    db_path = tmp_path / "places.sqlite"
    added_us = 1704067200 * 1_000_000
    _build_firefox_places_db(str(db_path),
        place_rows=[(1, "https://darkweb-market.example.onion", "Suspicious Site", 1, None)],
        bookmark_rows=[
            (100, 2, None, 0, "Bookmarks Toolbar", None),  # type=2 folder, itself a bookmark record's parent
            (101, 1, 1, 100, "Suspicious Site", added_us),  # type=1 real bookmark, parent=100
        ])
    result = ba.parse_firefox_places_db(str(db_path))
    assert len(result["bookmarks"]) == 1
    row = result["bookmarks"][0]
    assert row["artifact_type"] == "firefox_bookmarks"
    assert row["title"] == "Suspicious Site"
    assert row["url"] == "https://darkweb-market.example.onion"
    assert row["value"] == "Bookmarks Toolbar"  # the immediate parent folder's own title
    assert row["timestamp"] == 1704067200.0


def test_parse_firefox_downloads_via_moz_annos_join(tmp_path):
    db_path = tmp_path / "places.sqlite"
    dl_us = 1704067200 * 1_000_000
    _build_firefox_places_db(str(db_path),
        place_rows=[(1, "https://evil.example.net/dl", "evil download page", 1, None)],
        anno_rows=[(1, 1, "file:///C:/Users/suspect/Downloads/stolen_data.zip", dl_us)])
    result = ba.parse_firefox_places_db(str(db_path))
    assert len(result["downloads"]) == 1
    row = result["downloads"][0]
    assert row["artifact_type"] == "firefox_downloads"
    assert row["title"] == "stolen_data.zip"  # basename extracted from the file:// URI, Windows separators and all
    assert row["url"] == "https://evil.example.net/dl"
    assert row["value"] == "C:/Users/suspect/Downloads/stolen_data.zip"
    assert row["timestamp"] == 1704067200.0


def test_parse_firefox_places_on_a_file_with_no_recognizable_tables_returns_empty_not_error(tmp_path):
    db_path = tmp_path / "places.sqlite"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE unrelated_table (x INTEGER)")
    conn.commit()
    conn.close()
    result = ba.parse_firefox_places_db(str(db_path))
    assert result == {"history": [], "bookmarks": [], "downloads": []}


# --- Firefox Cookies (moz_cookies, in the separate 'cookies.sqlite' file) ---

def _build_firefox_cookies_db(path, rows):
    """rows: [(host, name, value, path, expiry, isSecure, isHttpOnly, creationTime), ...]"""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, creationTime INTEGER)")
    conn.executemany("INSERT INTO moz_cookies (host,name,value,path,expiry,isSecure,isHttpOnly,creationTime) VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def test_parse_firefox_cookies_real_plaintext_value_shown_directly(tmp_path):
    # Unlike Chrome, Firefox does NOT encrypt cookie values with an OS-level
    # key - the real value is directly recoverable, and must be shown as-is
    # (not "[encrypted]", which is a Chrome-specific disclosure that would
    # be actively wrong/misleading if reused here).
    db_path = tmp_path / "cookies.sqlite"
    creation_us = 1704067200 * 1_000_000
    expiry_s = 1800000000  # moz_cookies.expiry is SECONDS, not PRTime microseconds - the one exception on this table
    _build_firefox_cookies_db(str(db_path), [
        ("mail.example.com", "session_token", "abc123realvalue", "/", expiry_s, 1, 1, creation_us),
    ])
    result = ba.parse_firefox_cookies_db(str(db_path))
    assert len(result) == 1
    row = result[0]
    assert row["artifact_type"] == "firefox_cookies"
    assert row["title"] == "session_token"
    assert row["url"] == "mail.example.com"
    assert row["value"] == "abc123realvalue"  # real plaintext, not "[encrypted]"
    assert row["timestamp"] == 1704067200.0
    assert row["extra"]["expires"] == expiry_s  # stored as-is, no PRTime conversion applied to this one column
    assert row["extra"]["secure"] is True
    assert row["extra"]["httponly"] is True


def test_parse_firefox_cookies_on_a_file_with_no_cookies_table_returns_empty(tmp_path):
    db_path = tmp_path / "cookies.sqlite"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE unrelated_table (x INTEGER)")
    conn.commit()
    conn.close()
    assert ba.parse_firefox_cookies_db(str(db_path)) == []


# --- Dispatcher: Firefox filenames ---

def test_dispatch_routes_firefox_filenames_too(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ba, "parse_firefox_places_db", lambda p: calls.append(("places", p)) or {"history": [{"a": 1}], "bookmarks": [{"b": 2}], "downloads": [{"c": 3}]})
    monkeypatch.setattr(ba, "parse_firefox_cookies_db", lambda p: calls.append(("cookies", p)) or [{"d": 4}])

    assert ba.parse_browser_profile_file("/x/places.sqlite", "places.sqlite") == [{"a": 1}, {"b": 2}, {"c": 3}]
    assert ba.parse_browser_profile_file("/x/cookies.sqlite", "cookies.sqlite") == [{"d": 4}]
    assert {c[0] for c in calls} == {"places", "cookies"}


def test_dispatch_swallows_a_firefox_parse_exception_and_returns_empty(tmp_path):
    bad_path = tmp_path / "places.sqlite"
    bad_path.write_text("not a real sqlite file")
    result = ba.parse_browser_profile_file(str(bad_path), "places.sqlite")
    assert result == []


# --- URL list IOC matching (2026-08-26, Linux-DFIR-tools follow-up) ---

def test_match_urls_against_lists_flags_a_real_match_and_ignores_non_matches():
    records = [
        {"artifact_type": "chrome_history", "url": "http://evil.example/bin.sh", "value": "evil page", "timestamp": 123},
        {"artifact_type": "chrome_history", "url": "https://example.com/", "value": "safe page", "timestamp": 456},
        {"artifact_type": "chrome_cookies", "url": "", "value": "no url on a cookie record", "timestamp": None},
    ]
    url_list_sets = {"bad1": {"name": "Test Bad List", "urls": {"http://evil.example/bin.sh"}}}
    matches = ba._match_urls_against_lists(records, url_list_sets)
    assert len(matches) == 1
    m = matches[0]
    assert m["artifact_type"] == "browser_url_ioc_match"
    assert m["url"] == "http://evil.example/bin.sh"
    assert m["extra"]["matched_lists"] == ["Test Bad List"]
    assert m["extra"]["source_artifact_type"] == "chrome_history"
    assert m["timestamp"] == 123


def test_match_urls_against_lists_names_every_list_that_matched():
    records = [{"artifact_type": "chrome_history", "url": "http://evil.example/x", "value": "v", "timestamp": None}]
    url_list_sets = {
        "a": {"name": "List A", "urls": {"http://evil.example/x"}},
        "b": {"name": "List B", "urls": {"http://evil.example/x"}},
        "c": {"name": "List C", "urls": {"http://something-else"}},
    }
    matches = ba._match_urls_against_lists(records, url_list_sets)
    assert len(matches) == 1
    assert sorted(matches[0]["extra"]["matched_lists"]) == ["List A", "List B"]


def test_parse_browser_profile_file_appends_ioc_matches_without_url_list_sets_being_a_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(ba, "parse_chrome_bookmarks_json",
                         lambda p: [{"artifact_type": "chrome_bookmarks", "title": "t", "url": "http://evil.example/x",
                                     "value": "v", "timestamp": None, "extra": {}}])
    url_list_sets = {"bad1": {"name": "Test Bad List", "urls": {"http://evil.example/x"}}}
    # No url_list_sets at all - identical to today's pre-existing behavior, no IOC records appended.
    result_without = ba.parse_browser_profile_file("/x/Bookmarks", "Bookmarks")
    assert len(result_without) == 1
    assert result_without[0]["artifact_type"] == "chrome_bookmarks"
    # With url_list_sets - the original record survives untouched, plus one new IOC match record.
    result_with = ba.parse_browser_profile_file("/x/Bookmarks", "Bookmarks", url_list_sets=url_list_sets)
    assert len(result_with) == 2
    assert result_with[0]["artifact_type"] == "chrome_bookmarks"
    assert result_with[1]["artifact_type"] == "browser_url_ioc_match"


# --- Safari (2026-09-01) ---
# Real research grounding before any code was written: schema/key names
# confirmed against real forensic-tool source (ydkhatri/mac_apt's own
# safari.py plugin, a Velociraptor artifact definition) and the
# .binarycookies byte layout triangulated across four independent sources
# incl. a 2024 peer-reviewed paper - see core/browser_artifacts.py's own
# module docstring and the Safari section's inline comments for citations.

def test_find_browser_artifact_files_matches_safari_filenames_too(tmp_path):
    profile = tmp_path / "Users" / "suspect" / "Library" / "Safari"
    profile.mkdir(parents=True)
    (profile / "History.db").write_text("x")
    (profile / "Bookmarks.plist").write_text("x")
    (profile / "Downloads.plist").write_text("x")
    (profile / "Cookies.binarycookies").write_text("x")
    (profile / "LastSession.plist").write_text("x")  # not a recognized artifact filename - must not match
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"History.db", "Bookmarks.plist", "Downloads.plist", "Cookies.binarycookies"}
    assert truncated is False


def test_find_browser_artifact_files_matches_all_three_families_in_one_walk(tmp_path):
    (tmp_path / "chrome_profile").mkdir()
    (tmp_path / "chrome_profile" / "History").write_text("x")
    (tmp_path / "firefox_profile").mkdir()
    (tmp_path / "firefox_profile" / "places.sqlite").write_text("x")
    (tmp_path / "safari_profile").mkdir()
    (tmp_path / "safari_profile" / "History.db").write_text("x")
    found, truncated = ba.find_browser_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"History", "places.sqlite", "History.db"}


# --- Safari's Mac-epoch (Core Data / Cocoa) timestamp conversion ---

def test_safari_epoch_zero_point_round_trips_to_unix_epoch():
    # 1970-01-01 00:00:00 UTC expressed as seconds-since-2001-01-01 is
    # exactly -978307200 (negative, since 1970 is BEFORE the 2001 epoch).
    assert ba.safari_time_to_unix(-978307200) == 0


def test_safari_epoch_a_real_worked_example():
    # 2024-01-01 00:00:00 UTC is 1704067200 in real Unix epoch seconds.
    # In Safari's own Mac-epoch convention that's 1704067200 - 978307200 =
    # 725760000 seconds since 2001-01-01.
    assert ba.safari_time_to_unix(725760000) == 1704067200


def test_safari_time_supports_fractional_seconds():
    # History.db's visit_time is a SQLite REAL with real sub-second
    # precision - confirmed via a real worked example in the research
    # (732093296.5, a genuine .5-second value) - must not be truncated.
    result = ba.safari_time_to_unix(500.5)
    assert result == pytest.approx(978307700.5)


def test_safari_time_zero_or_empty_means_no_timestamp():
    assert ba.safari_time_to_unix(0) is None
    assert ba.safari_time_to_unix(None) is None
    assert ba.safari_time_to_unix("") is None


def test_safari_time_accepts_a_numeric_string():
    assert ba.safari_time_to_unix("725760000") == 1704067200


def test_safari_time_unparseable_value_returns_none():
    assert ba.safari_time_to_unix("not a number") is None


def test_safari_and_webkit_and_firefox_epochs_are_genuinely_different_conversions():
    # Same raw numeric input, three genuinely different real-world answers -
    # proves this isn't a copy-paste of an existing epoch helper, matching
    # this codebase's own established "prove it's different, not
    # copy-pasted" discipline for every epoch conversion added so far.
    raw = 1_000_000_000
    webkit_result = ba.webkit_time_to_unix(raw)
    firefox_result = ba.firefox_time_to_unix(raw)
    safari_result = ba.safari_time_to_unix(raw)
    assert len({webkit_result, firefox_result, safari_result}) == 3


# --- Safari History.db ---

def _build_safari_history_db(path, item_rows, visit_rows):
    """item_rows: [(id, url, visit_count), ...]
    visit_rows: [(id, history_item_fk, visit_time, title), ...]"""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)")
    conn.executemany("INSERT INTO history_items VALUES (?,?,?)", item_rows)
    conn.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT)")
    conn.executemany("INSERT INTO history_visits (id, history_item, visit_time, title) VALUES (?,?,?,?)", visit_rows)
    conn.commit()
    conn.close()


def test_parse_safari_history_returns_real_joined_rows(tmp_path):
    db_path = tmp_path / "History.db"
    _build_safari_history_db(str(db_path),
        [(1, "https://mail.example.com/inbox", 5)],
        [(1, 1, 725760000.0, "Example Mail - Inbox")])  # 2024-01-01 UTC in Mac-epoch seconds
    result = ba.parse_safari_history_db(str(db_path))
    assert len(result) == 1
    row = result[0]
    assert row["artifact_type"] == "safari_history"
    assert row["url"] == "https://mail.example.com/inbox"
    assert row["title"] == "Example Mail - Inbox"
    assert row["value"] == "5 visit(s)"
    assert row["timestamp"] == 1704067200


def test_parse_safari_history_on_a_file_with_no_recognizable_tables_returns_empty(tmp_path):
    db_path = tmp_path / "History.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE unrelated_table (x INTEGER)")
    conn.commit()
    conn.close()
    assert ba.parse_safari_history_db(str(db_path)) == []


# --- Safari Bookmarks.plist ---

def test_parse_safari_bookmarks_real_leaf_and_folder_nesting(tmp_path):
    plist_path = tmp_path / "Bookmarks.plist"
    data = {
        "WebBookmarkType": "WebBookmarkTypeList",
        "Title": "",
        "Children": [
            {
                "WebBookmarkType": "WebBookmarkTypeList",
                "Title": "Bookmarks Bar",
                "Children": [
                    {
                        "WebBookmarkType": "WebBookmarkTypeLeaf",
                        "URLString": "https://example.com/work",
                        "URIDictionary": {"title": "Work Portal"},
                    },
                    {
                        "WebBookmarkType": "WebBookmarkTypeList",
                        "Title": "Nested Folder",
                        "Children": [
                            {
                                "WebBookmarkType": "WebBookmarkTypeLeaf",
                                "URLString": "https://example.com/deep",
                                "URIDictionary": {"title": "Deep Link"},
                            },
                        ],
                    },
                ],
            },
        ],
    }
    with open(plist_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
    result = ba.parse_safari_bookmarks_plist(str(plist_path))
    assert len(result) == 2
    top = next(r for r in result if r["url"] == "https://example.com/work")
    assert top["title"] == "Work Portal"
    assert top["artifact_type"] == "safari_bookmarks"
    assert top["value"] == "Bookmarks Bar"
    nested = next(r for r in result if r["url"] == "https://example.com/deep")
    assert nested["title"] == "Deep Link"
    assert nested["value"] == "Bookmarks Bar/Nested Folder"


def test_parse_safari_bookmarks_handles_both_xml_and_binary_plist_format(tmp_path):
    data = {
        "WebBookmarkType": "WebBookmarkTypeList",
        "Children": [{
            "WebBookmarkType": "WebBookmarkTypeLeaf",
            "URLString": "https://example.com/x",
            "URIDictionary": {"title": "X"},
        }],
    }
    xml_path = tmp_path / "xml.plist"
    with open(xml_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_XML)
    bin_path = tmp_path / "bin.plist"
    with open(bin_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
    xml_result = ba.parse_safari_bookmarks_plist(str(xml_path))
    bin_result = ba.parse_safari_bookmarks_plist(str(bin_path))
    assert len(xml_result) == len(bin_result) == 1
    assert xml_result[0]["url"] == bin_result[0]["url"] == "https://example.com/x"


def test_parse_safari_bookmarks_a_reading_list_proxy_walks_into_its_own_children(tmp_path):
    # WebBookmarkTypeProxy (e.g. the Reading List container) has no URL of
    # its own but its Children are real bookmarks - must not be silently
    # dropped, and the proxy itself must never be recorded as a bookmark.
    plist_path = tmp_path / "Bookmarks.plist"
    data = {
        "WebBookmarkType": "WebBookmarkTypeList",
        "Children": [{
            "WebBookmarkType": "WebBookmarkTypeProxy",
            "Title": "com.apple.ReadingList",
            "Children": [{
                "WebBookmarkType": "WebBookmarkTypeLeaf",
                "URLString": "https://example.com/read-later",
                "URIDictionary": {"title": "Read Later Article"},
            }],
        }],
    }
    with open(plist_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
    result = ba.parse_safari_bookmarks_plist(str(plist_path))
    assert len(result) == 1
    assert result[0]["url"] == "https://example.com/read-later"
    assert all(r["url"] != "" or r["title"] != "com.apple.ReadingList" for r in result)


def test_parse_safari_bookmarks_on_a_non_plist_file_returns_empty_not_error(tmp_path):
    bad_path = tmp_path / "Bookmarks.plist"
    bad_path.write_text("not a real plist file")
    assert ba.parse_safari_bookmarks_plist(str(bad_path)) == []


# --- Safari Downloads.plist ---

def test_parse_safari_downloads_real_row_with_native_plist_dates(tmp_path):
    import datetime
    plist_path = tmp_path / "Downloads.plist"
    # plistlib can only WRITE a timezone-NAIVE datetime for a plist <date>
    # (raises TypeError on an aware one - confirmed directly, a real
    # constraint of the library, not a test-authoring choice) - and
    # crucially, this is also exactly what plistlib.load() hands back for
    # a REAL plist's <date> field too, even though the value is always UTC
    # by the plist/NSDate spec. This naive-but-really-UTC round trip is
    # precisely the gotcha _plist_date_to_unix() exists to correct - see
    # its own docstring for the real, confirmed 5-hour silent-error case
    # this test's own values are built to catch if that fix regresses.
    added = datetime.datetime(2024, 1, 1, 0, 0, 0)
    finished = datetime.datetime(2024, 1, 1, 0, 0, 30)
    data = {
        "DownloadHistory": [{
            "DownloadEntryURL": "https://example.com/evidence.zip",
            "DownloadEntryPath": r"C:\Users\suspect\Downloads\evidence.zip",
            "DownloadEntryDateAddedKey": added,
            "DownloadEntryDateFinishedKey": finished,
            "DownloadEntryProgressBytesSoFar": 2048,
            "DownloadEntryProgressTotalToLoad": 2048,
            "DownloadEntryRemoveWhenDoneKey": False,
        }],
    }
    with open(plist_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
    result = ba.parse_safari_downloads_plist(str(plist_path))
    assert len(result) == 1
    row = result[0]
    assert row["artifact_type"] == "safari_downloads"
    assert row["title"] == "evidence.zip"  # cross-platform basename extraction, same helper Chrome/Firefox already use
    assert row["url"] == "https://example.com/evidence.zip"
    # Compare against the value explicitly stamped UTC, NOT bare
    # added.timestamp() (which would itself hit the same naive-datetime-
    # means-local-time bug this fixture exists to catch, making the
    # assertion pass by matching the bug instead of the correct answer).
    assert row["timestamp"] == added.replace(tzinfo=datetime.timezone.utc).timestamp()
    assert row["timestamp"] == 1704067200  # 2024-01-01 00:00:00 UTC, the real known-correct value
    assert row["extra"]["finished"] == finished.replace(tzinfo=datetime.timezone.utc).timestamp()
    assert row["extra"]["bytes_so_far"] == 2048
    assert row["extra"]["private_browsing"] is False


def test_parse_safari_downloads_private_browsing_flag_is_surfaced(tmp_path):
    plist_path = tmp_path / "Downloads.plist"
    data = {"DownloadHistory": [{
        "DownloadEntryURL": "https://example.com/secret.pdf",
        "DownloadEntryPath": "/Users/suspect/Downloads/secret.pdf",
        "DownloadEntryRemoveWhenDoneKey": True,
    }]}
    with open(plist_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
    result = ba.parse_safari_downloads_plist(str(plist_path))
    assert result[0]["extra"]["private_browsing"] is True


def test_parse_safari_downloads_on_a_file_with_no_download_history_key_returns_empty(tmp_path):
    plist_path = tmp_path / "Downloads.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({"SomeOtherKey": []}, f, fmt=plistlib.FMT_BINARY)
    assert ba.parse_safari_downloads_plist(str(plist_path)) == []


# --- Safari Cookies.binarycookies (hand-built real byte layout, not mocked -
# a schema-shape mistake here would actually fail these tests, matching
# this test module's own stated design principle) ---

def _build_binarycookies_record_bytes(domain, name, cookie_path, value, flags, expiry, creation):
    domain_b = domain.encode('utf-8') + b'\x00'
    name_b = name.encode('utf-8') + b'\x00'
    path_b = cookie_path.encode('utf-8') + b'\x00'
    value_b = value.encode('utf-8') + b'\x00'
    header_len = 56  # size+version+flags+unknown(16) + 4 offsets(16) + 8 zero + expiry+creation(16)
    domain_off = header_len
    name_off = domain_off + len(domain_b)
    path_off = name_off + len(name_b)
    value_off = path_off + len(path_b)
    total_size = value_off + len(value_b)
    rec = struct.pack('<IIII', total_size, 0, flags, 0)
    rec += struct.pack('<IIII', domain_off, name_off, path_off, value_off)
    rec += b'\x00' * 8
    rec += struct.pack('<dd', expiry, creation)
    rec += domain_b + name_b + path_b + value_b
    assert len(rec) == total_size
    return rec


def _build_binarycookies_file(path, cookie_specs):
    """cookie_specs: [(domain, name, path, value, flags, expiry, creation), ...] -
    all packed into a single page, matching this format's real confirmed
    layout: b'cook' magic, big-endian page-count/page-size-table header,
    then a little-endian page (marker/count/offset-table/records/footer)."""
    records = [_build_binarycookies_record_bytes(*spec) for spec in cookie_specs]
    offset_table_start = 8
    offsets, pos = [], offset_table_start + len(records) * 4
    for rec in records:
        offsets.append(pos)
        pos += len(rec)
    page = b'\x00\x00\x01\x00'
    page += struct.pack('<I', len(records))
    for off in offsets:
        page += struct.pack('<I', off)
    for rec in records:
        page += rec
    page += b'\x00\x00\x00\x00'
    file_bytes = b'cook' + struct.pack('>I', 1) + struct.pack('>I', len(page)) + page
    with open(path, 'wb') as f:
        f.write(file_bytes)


def test_parse_safari_cookies_real_hand_built_binary_file(tmp_path):
    cookies_path = tmp_path / "Cookies.binarycookies"
    # flags=5 means Secure+HttpOnly (1|4), a real bit-flag combination
    # confirmed across every source consulted.
    _build_binarycookies_file(str(cookies_path), [
        ("example.com", "session_id", "/", "abc123def456", 5, 725760000.0, 725670000.0),
    ])
    result = ba.parse_safari_cookies_binarycookies(str(cookies_path))
    assert len(result) == 1
    row = result[0]
    assert row["artifact_type"] == "safari_cookies"
    assert row["url"] == "example.com"
    assert row["title"] == "session_id"
    assert row["value"] == "abc123def456"
    assert row["extra"]["path"] == "/"
    assert row["extra"]["secure"] is True
    assert row["extra"]["httponly"] is True
    assert row["timestamp"] == 1704067200 - 90000  # 725670000 in Mac-epoch -> Unix


def test_parse_safari_cookies_plaintext_value_never_encrypted_unlike_chrome(tmp_path):
    # Unlike Chrome's own '[encrypted]' placeholder for a value it can't
    # recover, Safari's format has no encryption layer at all - the real
    # value must be directly readable.
    cookies_path = tmp_path / "Cookies.binarycookies"
    _build_binarycookies_file(str(cookies_path), [
        ("bank.example", "auth_token", "/account", "genuinely-sensitive-plaintext-value", 0, 0.0, 725760000.0),
    ])
    result = ba.parse_safari_cookies_binarycookies(str(cookies_path))
    assert result[0]["value"] == "genuinely-sensitive-plaintext-value"
    assert result[0]["value"] != "[encrypted]"


def test_parse_safari_cookies_zero_expiry_means_session_cookie_no_fixed_expiry(tmp_path):
    cookies_path = tmp_path / "Cookies.binarycookies"
    _build_binarycookies_file(str(cookies_path), [
        ("example.com", "sess", "/", "v", 0, 0.0, 725760000.0),
    ])
    result = ba.parse_safari_cookies_binarycookies(str(cookies_path))
    assert result[0]["extra"]["expires"] is None


def test_parse_safari_cookies_multiple_records_in_one_page(tmp_path):
    cookies_path = tmp_path / "Cookies.binarycookies"
    _build_binarycookies_file(str(cookies_path), [
        ("a.example", "n1", "/", "v1", 0, 0.0, 1.0),
        ("b.example", "n2", "/x", "v2", 1, 0.0, 2.0),
        ("c.example", "n3", "/y", "v3", 4, 0.0, 3.0),
    ])
    result = ba.parse_safari_cookies_binarycookies(str(cookies_path))
    assert len(result) == 3
    assert {r["url"] for r in result} == {"a.example", "b.example", "c.example"}


def test_parse_safari_cookies_wrong_magic_returns_empty_not_error(tmp_path):
    bad_path = tmp_path / "Cookies.binarycookies"
    bad_path.write_bytes(b"NOTC" + b"\x00" * 100)
    assert ba.parse_safari_cookies_binarycookies(str(bad_path)) == []


def test_parse_safari_cookies_empty_file_returns_empty_not_error(tmp_path):
    empty_path = tmp_path / "Cookies.binarycookies"
    empty_path.write_bytes(b"")
    assert ba.parse_safari_cookies_binarycookies(str(empty_path)) == []


def test_parse_safari_cookies_truncated_file_returns_partial_not_error(tmp_path):
    # A real page-size table entry claiming more bytes than the file
    # actually has - must stop cleanly, never raise or read past the
    # buffer.
    cookies_path = tmp_path / "Cookies.binarycookies"
    _build_binarycookies_file(str(cookies_path), [("a.example", "n", "/", "v", 0, 0.0, 1.0)])
    real_bytes = cookies_path.read_bytes()
    truncated_path = tmp_path / "Cookies_truncated.binarycookies"
    truncated_path.write_bytes(real_bytes[:len(real_bytes) - 10])
    # Must not raise - either returns [] (page-size mismatch caught) or a
    # partial/degraded result, never an exception.
    result = ba.parse_safari_cookies_binarycookies(str(truncated_path))
    assert isinstance(result, list)


def test_parse_safari_cookies_respects_the_max_cookies_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ba, "BROWSER_ARTIFACT_MAX_COOKIES", 2)
    cookies_path = tmp_path / "Cookies.binarycookies"
    _build_binarycookies_file(str(cookies_path), [
        ("a.example", "n1", "/", "v1", 0, 0.0, 1.0),
        ("b.example", "n2", "/", "v2", 0, 0.0, 2.0),
        ("c.example", "n3", "/", "v3", 0, 0.0, 3.0),
    ])
    result = ba.parse_safari_cookies_binarycookies(str(cookies_path))
    assert len(result) == 2


# --- Dispatcher: Safari filenames ---

def test_dispatch_routes_safari_filenames_too(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ba, "parse_safari_history_db", lambda p: calls.append(("history", p)) or [{"a": 1}])
    monkeypatch.setattr(ba, "parse_safari_bookmarks_plist", lambda p: calls.append(("bookmarks", p)) or [{"b": 2}])
    monkeypatch.setattr(ba, "parse_safari_downloads_plist", lambda p: calls.append(("downloads", p)) or [{"c": 3}])
    monkeypatch.setattr(ba, "parse_safari_cookies_binarycookies", lambda p: calls.append(("cookies", p)) or [{"d": 4}])

    assert ba.parse_browser_profile_file("/x/History.db", "History.db") == [{"a": 1}]
    assert ba.parse_browser_profile_file("/x/Bookmarks.plist", "Bookmarks.plist") == [{"b": 2}]
    assert ba.parse_browser_profile_file("/x/Downloads.plist", "Downloads.plist") == [{"c": 3}]
    assert ba.parse_browser_profile_file("/x/Cookies.binarycookies", "Cookies.binarycookies") == [{"d": 4}]
    assert {c[0] for c in calls} == {"history", "bookmarks", "downloads", "cookies"}


def test_dispatch_swallows_a_safari_parse_exception_and_returns_empty(tmp_path):
    bad_path = tmp_path / "Cookies.binarycookies"
    bad_path.write_bytes(b"not a real binarycookies file at all, no magic")
    result = ba.parse_browser_profile_file(str(bad_path), "Cookies.binarycookies")
    assert result == []
