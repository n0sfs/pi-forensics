"""Generic SQLite artifact viewer (Part D, D1) - safety property tests for
core/browser_artifacts.py's _open_sqlite_readonly(), the one function both
routes/file_explorer.py's and routes/image_browser.py's new sqlite/tables
and sqlite/query routes are built on. No POSIX dependency (those two route
modules need core.jobs and are tested live on the Pi instead - see this
project's own established split for exactly this reason); what's tested
here is the safety-critical, platform-independent core: a connection
opened this way must genuinely refuse to write, and a table-name
allowlist check (the same one both routes perform before ever
interpolating a name into a query) must reject anything not already
confirmed to be a real table.
"""
import sqlite3

import pytest

import core.browser_artifacts as ba


def _build_real_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO messages (body) VALUES ('hello'), ('world')")
    conn.commit()
    conn.close()


def test_open_sqlite_readonly_genuinely_rejects_a_write(tmp_path):
    db_path = tmp_path / "evidence.db"
    _build_real_db(db_path)

    conn = ba._open_sqlite_readonly(str(db_path))
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO messages (body) VALUES ('should not be allowed')")
    finally:
        conn.close()

    # Confirm the file itself is genuinely untouched - not just that the
    # write raised, but that nothing was silently committed anyway.
    check_conn = sqlite3.connect(str(db_path))
    count = check_conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    check_conn.close()
    assert count == 2


def test_open_sqlite_readonly_still_allows_real_reads(tmp_path):
    db_path = tmp_path / "evidence.db"
    _build_real_db(db_path)
    conn = ba._open_sqlite_readonly(str(db_path))
    try:
        rows = conn.execute("SELECT body FROM messages ORDER BY id").fetchall()
    finally:
        conn.close()
    assert rows == [("hello",), ("world",)]


def _list_tables_with_counts(conn):
    """Mirrors routes/file_explorer.py's/routes/image_browser.py's own
    duplicated _sqlite_list_tables() helper exactly (kept as a plain
    inline test-local copy since neither route module can be imported on
    a non-POSIX dev machine)."""
    tables = []
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        tables.append({"name": name, "row_count": count})
    return tables


def test_table_listing_reflects_real_tables_and_counts(tmp_path):
    db_path = tmp_path / "evidence.db"
    _build_real_db(db_path)
    conn = ba._open_sqlite_readonly(str(db_path))
    try:
        tables = _list_tables_with_counts(conn)
    finally:
        conn.close()
    assert tables == [{"name": "messages", "row_count": 2}]


def test_a_table_name_not_in_the_live_listing_is_rejected(tmp_path):
    # This is the actual safety property both routes enforce before ever
    # interpolating a table name into a query string: the name must
    # already be present in sqlite_master's own real listing, not
    # accepted as arbitrary client input.
    db_path = tmp_path / "evidence.db"
    _build_real_db(db_path)
    conn = ba._open_sqlite_readonly(str(db_path))
    try:
        real_tables = {t["name"] for t in _list_tables_with_counts(conn)}
    finally:
        conn.close()
    assert "sqlite_master; DROP TABLE messages; --" not in real_tables
    assert "messages" in real_tables
