"""core/browser_artifacts.py - Chrome/Chromium-family real per-app artifact
parsing (History, Downloads, Bookmarks, Cookie metadata), added this
session. No POSIX dependency - runs on every platform. Builds real SQLite
files/JSON matching Chrome's actual on-disk schemas rather than mocking the
parser, so a schema-shape mistake would actually fail these tests.
"""
import json
import os
import sqlite3

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

    assert ba.parse_chrome_profile_file("/x/History", "History") == [{"a": 1}]
    assert ba.parse_chrome_profile_file("/x/Cookies", "Cookies") == [{"b": 2}]
    assert ba.parse_chrome_profile_file("/x/Bookmarks", "Bookmarks") == [{"c": 3}]
    assert ba.parse_chrome_profile_file("/x/Unrelated", "Unrelated") == []
    assert {c[0] for c in calls} == {"history", "cookies", "bookmarks"}


def test_dispatch_swallows_a_parse_exception_and_returns_empty(tmp_path):
    # A file matching the name 'History' but not actually a valid SQLite
    # database (corrupted, truncated, or just coincidentally named).
    bad_path = tmp_path / "History"
    bad_path.write_text("not a real sqlite file")
    result = ba.parse_chrome_profile_file(str(bad_path), "History")
    assert result == []


# --- find_chrome_artifact_files (real-fs candidate discovery) ---

def test_find_chrome_artifact_files_matches_by_exact_basename_anywhere_nested(tmp_path):
    deep = tmp_path / "Users" / "suspect" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    deep.mkdir(parents=True)
    (deep / "History").write_text("x")
    (deep / "Cookies").write_text("x")
    (deep / "Bookmarks").write_text("x")
    (deep / "Preferences").write_text("x")  # not a recognized artifact filename - must not match
    found, truncated = ba.find_chrome_artifact_files(str(tmp_path))
    names = {os.path.basename(p) for p in found}
    assert names == {"History", "Cookies", "Bookmarks"}
    assert truncated is False


def test_find_chrome_artifact_files_skips_bulk_carve_output_dirs(tmp_path):
    real = tmp_path / "Default"
    real.mkdir()
    (real / "History").write_text("x")
    carved = tmp_path / "CASE_ITEM-01_photorec" / "Default"
    carved.mkdir(parents=True)
    (carved / "History").write_text("x")  # same filename, inside a carve-output dir - must never be found
    found, truncated = ba.find_chrome_artifact_files(str(tmp_path))
    assert len(found) == 1
    assert "photorec" not in found[0]


def test_find_chrome_artifact_files_empty_dir_returns_empty(tmp_path):
    found, truncated = ba.find_chrome_artifact_files(str(tmp_path))
    assert found == []
    assert truncated is False


def test_find_chrome_artifact_files_truncates_at_the_candidate_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ba, "BROWSER_ARTIFACT_SCAN_MAX_CANDIDATES", 2)
    for i in range(4):
        d = tmp_path / f"profile{i}"
        d.mkdir()
        (d / "History").write_text("x")
    found, truncated = ba.find_chrome_artifact_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is True
