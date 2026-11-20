"""File Views list caps (2026-11-20): /api/case_index/files, /hits,
/tagged_files and /parsed_artifacts each cap their rows, and now say so with
`truncated`/`limit` instead of returning exactly the cap with no hint that
more exist (the tree label shows the full count).

Same minimal-app pattern as tests/test_unified_search_route.py.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.case_index needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import core.case_index_db as case_index_db
from routes.case_index import case_index_bp
from tests.conftest import RemoteTestClient, login_user_session

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def app():
    flask_app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(case_index_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


@pytest.fixture
def case_folder(evidence_root):
    """A real, minimal consolidated case folder - matches tests/
    test_case_index_db.py's own identical fixture (kept as a local copy
    here rather than a cross-file import, matching that file's own
    established convention of each test module owning its fixtures)."""
    import pathlib
    folder = pathlib.Path(evidence_root) / "2026-CASE-FILEVIEWS-CAP"
    folder.mkdir()
    (folder / "2026-CASE-FILEVIEWS-CAP_case.json").write_text(json.dumps({
        "schema_version": 1, "case_number": "2026-CASE-FILEVIEWS-CAP", "events": [],
    }))
    return str(folder)




def _seed_files(case_folder, n, category):
    conn = case_index_db._case_index_connect(case_index_db.case_index_db_path(case_folder))
    try:
        conn.executemany(
            "INSERT INTO indexed_files (image_path, fs_offset, inode, path, name, extension, category, size, "
            "deleted, is_virtual, mtime, atime, ctime, crtime, indexed_at) "
            "VALUES ('/mnt/img.dd', 0, ?, ?, ?, 'jpg', ?, 1, 0, 0, 0, 0, 0, 0, '2026-11-20 00:00:00')",
            [(str(i), f"/p/f{i:04d}.jpg", f"f{i:04d}.jpg", category) for i in range(n)])
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def small_cap(monkeypatch):
    import routes.case_index as ci
    monkeypatch.setattr(ci, "FILE_VIEWS_ROW_LIMIT", 3)
    return 3


def _category():
    import routes.case_index as ci
    return sorted(ci.FILE_VIEW_EXTENSION_CATEGORIES)[0]


def test_a_list_longer_than_the_cap_is_cut_and_says_so(client, case_folder, small_cap):
    cat = _category()
    _seed_files(case_folder, small_cap + 2, cat)
    data = client.post('/api/case_index/files', json={"case_folder": case_folder, "category": cat}).get_json()
    assert data["success"] is True
    assert len(data["rows"]) == small_cap
    assert data["truncated"] is True
    assert data["limit"] == small_cap


def test_a_list_exactly_at_the_cap_is_not_flagged(client, case_folder, small_cap):
    cat = _category()
    _seed_files(case_folder, small_cap, cat)
    data = client.post('/api/case_index/files', json={"case_folder": case_folder, "category": cat}).get_json()
    assert len(data["rows"]) == small_cap
    assert data["truncated"] is False


def test_an_unindexed_case_is_not_flagged(client, case_folder, small_cap):
    data = client.post('/api/case_index/files', json={"case_folder": case_folder, "category": _category()}).get_json()
    assert data["rows"] == [] and data["truncated"] is False


def test_summary_unique_keyword_values_do_not_double_on_a_rescan(client, case_folder):
    # 2026-11-20: re-running a scan writes the same hit again; the Overview
    # used the row total, which doubled, while the report counts distinct values.
    conn = case_index_db._case_index_connect(case_index_db.case_index_db_path(case_folder))
    try:
        cat = sorted(case_index_db.TRIAGE_PATTERNS)[0]
        rows = [("real_fs", None, None, None, "/p/a.txt", cat, "value-1", "2026-11-20 00:00:00"),
                ("real_fs", None, None, None, "/p/a.txt", cat, "value-2", "2026-11-20 00:00:00")]
        for _ in range(2):  # the same scan, run twice
            conn.executemany("INSERT INTO triage_hits (source_type, image_path, fs_offset, inode, path, category, value, found_at) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    data = client.post('/api/case_index/summary', json={"case_folder": case_folder}).get_json()
    assert data["keyword_hits"][sorted(case_index_db.TRIAGE_PATTERNS)[0]] == 4  # File Views lists rows
    assert data["keyword_hits"]["unique_values"] == 2  # the Overview/report number
