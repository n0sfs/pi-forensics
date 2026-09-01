"""Tests for core/stickynotes_utils.py, built against a real SQLite
database matching the confirmed real Note table schema (2026-09-01
research, cross-validated against StickyParser's own real source) - not
mocks."""
import os
import sqlite3
import shutil
import datetime

import core.stickynotes_utils as snu

_DOTNET_TICKS_EPOCH_OFFSET_SECONDS = 62_135_596_800
_DOTNET_TICKS_PER_SECOND = 10_000_000


def _unix_to_dotnet_ticks(unix_seconds):
    return int((unix_seconds + _DOTNET_TICKS_EPOCH_OFFSET_SECONDS) * _DOTNET_TICKS_PER_SECOND)


def _dt_ticks(dt):
    return _unix_to_dotnet_ticks(dt.replace(tzinfo=datetime.timezone.utc).timestamp())


def _build_plum_sqlite(path, rows, wal_mode=False):
    """rows: [(id, text, created_dt, updated_dt, deleted_dt_or_None, is_always_on_top, theme), ...]"""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE Note (Id TEXT, Text TEXT, CreatedAt INTEGER, UpdatedAt INTEGER, "
        "DeletedAt INTEGER, IsAlwaysOnTop INTEGER, Theme TEXT)")
    for note_id, text, created_dt, updated_dt, deleted_dt, is_pinned, theme in rows:
        conn.execute(
            "INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt, DeletedAt, IsAlwaysOnTop, Theme) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (note_id, text, _dt_ticks(created_dt), _dt_ticks(updated_dt),
             _dt_ticks(deleted_dt) if deleted_dt else None, int(is_pinned), theme))
    conn.commit()
    if wal_mode:
        conn.execute('PRAGMA journal_mode=WAL')
    return conn  # caller decides when to close (WAL tests need it held open)


def test_dotnet_ticks_to_unix_is_genuinely_different_math_from_filetime():
    """Direct regression test: .NET DateTime.Ticks (epoch 0001-01-01) and
    Windows FILETIME (epoch 1601-01-01) share the same 100ns-tick UNIT but
    have a completely different offset constant - the same raw tick value
    must produce two different real answers under the two conversions."""
    import core.registry_utils as ru
    raw_ticks = 638_600_000_000_000_000  # an arbitrary large real-looking tick count
    dotnet_result = snu.dotnet_ticks_to_unix(raw_ticks)
    filetime_result = ru.filetime_to_unix(raw_ticks)
    assert dotnet_result != filetime_result
    assert dotnet_result is not None and filetime_result is not None


def test_dotnet_ticks_to_unix_known_value():
    known_dt = datetime.datetime(2026, 8, 30, 12, 0, 0, tzinfo=datetime.timezone.utc)
    ticks = _unix_to_dotnet_ticks(known_dt.timestamp())
    assert snu.dotnet_ticks_to_unix(ticks) == known_dt.timestamp()


def test_dotnet_ticks_to_unix_handles_none_and_zero():
    assert snu.dotnet_ticks_to_unix(None) is None
    assert snu.dotnet_ticks_to_unix(0) is None


def test_parse_sticky_notes_directory_real_plain_text_note(tmp_path):
    created = datetime.datetime(2026, 8, 25, 10, 0, 0)
    updated = datetime.datetime(2026, 8, 30, 14, 30, 0)
    conn = _build_plum_sqlite(str(tmp_path / snu.STICKY_NOTES_FILENAME), [
        ('note-1', 'Call John about the case tomorrow', created, updated, None, False, 'Yellow'),
    ])
    conn.close()

    records = snu.parse_sticky_notes_directory(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "sticky_note"
    assert r["title"] == 'Call John about the case tomorrow'
    assert r["value"] == 'Call John about the case tomorrow'
    assert r["timestamp"] == updated.replace(tzinfo=datetime.timezone.utc).timestamp()
    assert r["extra"]["deleted"] is False
    assert r["extra"]["theme"] == 'Yellow'
    assert r["extra"]["is_always_on_top"] is False


def test_parse_sticky_notes_directory_rtf_note_is_stripped_to_plain_text(tmp_path):
    rtf_text = r'{\rtf1\ansi\deff0 {\fonttbl{\f0 Segoe UI;}}\fs22 password is hunter2\par}'
    created = updated = datetime.datetime(2026, 8, 20, 9, 0, 0)
    conn = _build_plum_sqlite(str(tmp_path / snu.STICKY_NOTES_FILENAME), [
        ('note-rtf', rtf_text, created, updated, None, False, 'Blue'),
    ])
    conn.close()

    records = snu.parse_sticky_notes_directory(str(tmp_path))
    assert len(records) == 1
    # The stripped text should contain the real readable content, with none
    # of the raw RTF control-word markup left in it.
    assert 'password is hunter2' in records[0]["value"]
    assert '\\rtf1' not in records[0]["value"]
    assert '\\fonttbl' not in records[0]["value"]


def test_parse_sticky_notes_directory_plain_text_starting_with_braces_is_left_alone(tmp_path):
    # A plain note that happens to start with '{' but isn't RTF (no real
    # '{\rtf' signature) must never be mistaken for RTF and mangled.
    text = '{shopping list} milk, eggs, bread'
    created = updated = datetime.datetime(2026, 8, 20, 9, 0, 0)
    conn = _build_plum_sqlite(str(tmp_path / snu.STICKY_NOTES_FILENAME), [
        ('note-brace', text, created, updated, None, False, 'Green'),
    ])
    conn.close()

    records = snu.parse_sticky_notes_directory(str(tmp_path))
    assert len(records) == 1
    assert records[0]["value"] == text


def test_parse_sticky_notes_directory_deleted_note_still_surfaced_and_flagged(tmp_path):
    # DeletedAt is a soft-delete tombstone, not a row removal - a deleted
    # note is still real, recoverable evidentiary content and must be
    # included, clearly flagged, never silently dropped.
    created = datetime.datetime(2026, 8, 1, 8, 0, 0)
    updated = datetime.datetime(2026, 8, 2, 8, 0, 0)
    deleted = datetime.datetime(2026, 8, 3, 8, 0, 0)
    conn = _build_plum_sqlite(str(tmp_path / snu.STICKY_NOTES_FILENAME), [
        ('note-deleted', 'incriminating reminder', created, updated, deleted, False, 'Pink'),
    ])
    conn.close()

    records = snu.parse_sticky_notes_directory(str(tmp_path))
    assert len(records) == 1
    r = records[0]
    assert r["extra"]["deleted"] is True
    assert r["extra"]["deleted_timestamp"] == deleted.replace(tzinfo=datetime.timezone.utc).timestamp()
    assert r["value"] == 'incriminating reminder'


def test_parse_sticky_notes_directory_empty_or_whitespace_notes_excluded(tmp_path):
    created = updated = datetime.datetime(2026, 8, 20, 9, 0, 0)
    conn = _build_plum_sqlite(str(tmp_path / snu.STICKY_NOTES_FILENAME), [
        ('note-empty', '', created, updated, None, False, 'Yellow'),
        ('note-whitespace', '   \n  ', created, updated, None, False, 'Yellow'),
        ('note-real', 'real content', created, updated, None, False, 'Yellow'),
    ])
    conn.close()

    records = snu.parse_sticky_notes_directory(str(tmp_path))
    assert len(records) == 1
    assert records[0]["value"] == 'real content'


def test_parse_sticky_notes_directory_missing_main_file_returns_empty(tmp_path):
    assert snu.parse_sticky_notes_directory(str(tmp_path)) == []


def test_parse_sticky_notes_directory_not_a_real_sqlite_file_returns_empty(tmp_path):
    (tmp_path / snu.STICKY_NOTES_FILENAME).write_bytes(b'not a real sqlite database at all')
    assert snu.parse_sticky_notes_directory(str(tmp_path)) == []


def test_parse_sticky_notes_directory_recovers_data_stranded_only_in_the_wal_sidecar(tmp_path):
    """The single most important real-world gotcha this module exists to
    handle, proven directly rather than just documented: a second
    connection is held open (preventing SQLite's own automatic
    checkpoint-on-close), a WAL-mode insert is made and committed, then
    the whole file set is copied elsewhere WHILE both connections are
    still open - simulating extracting evidence from a live/recently-
    used system. The copied -wal file genuinely holds data the main
    .sqlite file alone does not."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    main_path = str(src_dir / snu.STICKY_NOTES_FILENAME)

    created = updated = datetime.datetime(2026, 8, 20, 9, 0, 0)
    conn = _build_plum_sqlite(main_path, [
        ('note-checkpointed', 'already checkpointed note', created, updated, None, False, 'Yellow'),
    ], wal_mode=True)
    # Second connection held open specifically to prevent auto-checkpoint
    # on close (confirmed live before writing this test - see the
    # dated CLAUDE.md entry for the real experiment this was based on).
    conn2 = sqlite3.connect(main_path)
    conn2.execute('SELECT 1')

    conn.execute(
        "INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt, DeletedAt, IsAlwaysOnTop, Theme) "
        "VALUES (?, ?, ?, ?, NULL, 0, ?)",
        ('note-wal-only', 'wal-only note never checkpointed', _dt_ticks(updated), _dt_ticks(updated), 'Blue'))
    conn.commit()

    assert os.path.isfile(main_path + '-wal')  # sanity: WAL sidecar genuinely exists at this point

    # Copy the whole file set elsewhere WHILE both connections remain open.
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    for name in os.listdir(src_dir):
        shutil.copy2(str(src_dir / name), str(dest_dir / name))

    conn.close()
    conn2.close()

    records = snu.parse_sticky_notes_directory(str(dest_dir))
    values = {r["value"] for r in records}
    assert 'already checkpointed note' in values
    assert 'wal-only note never checkpointed' in values, \
        "the WAL-only note must be recovered - this is the module's whole reason for existing"


def test_parse_sticky_notes_directory_without_the_wal_sidecar_misses_the_wal_only_data():
    """Negative-control counterpart to the WAL-recovery test above - if
    the -wal file is genuinely absent (e.g. it really was already
    checkpointed, or an examiner only copied the main file), the module
    must not crash, and must simply reflect only what the main file
    itself actually contains - not a bug, the expected behavior."""
    import tempfile
    src_dir = tempfile.mkdtemp()
    dest_dir = tempfile.mkdtemp()
    try:
        main_path = os.path.join(src_dir, snu.STICKY_NOTES_FILENAME)
        created = updated = datetime.datetime(2026, 8, 20, 9, 0, 0)
        conn = _build_plum_sqlite(main_path, [
            ('note-checkpointed', 'already checkpointed note', created, updated, None, False, 'Yellow'),
        ], wal_mode=True)
        conn2 = sqlite3.connect(main_path)
        conn2.execute('SELECT 1')
        conn.execute(
            "INSERT INTO Note (Id, Text, CreatedAt, UpdatedAt, DeletedAt, IsAlwaysOnTop, Theme) "
            "VALUES (?, ?, ?, ?, NULL, 0, ?)",
            ('note-wal-only', 'wal-only note', _dt_ticks(updated), _dt_ticks(updated), 'Blue'))
        conn.commit()
        # Copy ONLY the main file, deliberately leaving the -wal/-shm behind.
        shutil.copy2(main_path, os.path.join(dest_dir, snu.STICKY_NOTES_FILENAME))
        conn.close()
        conn2.close()

        records = snu.parse_sticky_notes_directory(dest_dir)
        values = {r["value"] for r in records}
        assert 'already checkpointed note' in values
        assert 'wal-only note' not in values
    finally:
        shutil.rmtree(src_dir, ignore_errors=True)
        shutil.rmtree(dest_dir, ignore_errors=True)


def test_find_sticky_notes_files_matches_only_the_main_file_case_insensitively(tmp_path):
    (tmp_path / 'plum.sqlite').write_bytes(b'x')
    (tmp_path / 'plum.sqlite-wal').write_bytes(b'x')  # sidecar - never itself a "found" candidate
    (tmp_path / 'plum.sqlite-shm').write_bytes(b'x')
    (tmp_path / 'not_plum.sqlite').write_bytes(b'x')
    nested = tmp_path / 'Packages' / 'Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe' / 'LocalState'
    nested.mkdir(parents=True)
    (nested / 'PLUM.SQLITE').write_bytes(b'x')  # real-world casing can vary

    found, truncated = snu.find_sticky_notes_files(str(tmp_path))
    basenames = sorted(os.path.basename(p) for p in found)
    assert basenames == ['PLUM.SQLITE', 'plum.sqlite']
    assert truncated is False


def test_find_sticky_notes_files_skips_recovery_tool_output_dirs(tmp_path):
    skip_dir = tmp_path / 'evidence_photorec'
    skip_dir.mkdir()
    (skip_dir / 'plum.sqlite').write_bytes(b'x')
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    (real_dir / 'plum.sqlite').write_bytes(b'x')

    found, _truncated = snu.find_sticky_notes_files(str(tmp_path))
    assert len(found) == 1
    assert 'real' in found[0]


def test_sticky_notes_canonical_filename():
    assert snu.sticky_notes_canonical_filename('plum.sqlite') == 'plum.sqlite'
    assert snu.sticky_notes_canonical_filename('PLUM.SQLITE') == 'plum.sqlite'
    assert snu.sticky_notes_canonical_filename('Plum.Sqlite-WAL') == 'plum.sqlite-wal'
    assert snu.sticky_notes_canonical_filename('plum.sqlite-shm') == 'plum.sqlite-shm'
    assert snu.sticky_notes_canonical_filename('unrelated.sqlite') is None
