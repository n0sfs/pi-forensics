"""Windows Sticky Notes (plum.sqlite) parsing - a genuinely different
artifact FAMILY from every other parser in this app: real, examiner-
relevant USER-GENERATED CONTENT (the literal text of a note), not
execution/access metadata like Registry hives, Prefetch, Jump Lists, etc.

Format confirmed via real, cross-corroborated research (2026-09-01):
StickyParser's own real, working open-source implementation (read
directly, not paraphrased) confirms the exact Note table schema and
timestamp-conversion formula, independently corroborated for the .NET-
DateTime.Ticks timestamp scheme and the legacy RTF-vs-plain-text stream
split by multiple independent DFIR write-ups (Forensics Wiki, quoting
Harlan Carvey's original analysis; two independent write-ups).

Scope: the modern, UWP-packaged SQLite format only
(%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\
LocalState\\plum.sqlite, Windows 10 1607 onward). The pre-1607 legacy
format (a single StickyNotes.snt OLE2/Compound-File-Binary file, RTF in
stream '0', plain Unicode text in stream '3') is deliberately out of
scope - a structurally different parsing technique (raw OLE2 stream
enumeration, not SQL), and pre-1607 Windows 10/Windows 7 (long out of
support) is realistically extinct in 2025/2026 casework - matching this
app's own established "target the single dominant modern format, disclose
the cutoff" precedent (Shimcache, Jump Lists' AutomaticDestinations-only
scope).

A genuinely new, sixth timestamp epoch/unit for this app: .NET
DateTime.Ticks (100-nanosecond intervals since 0001-01-01) - NOT Windows
FILETIME (100ns since 1601-01-01: same UNIT, a completely different
OFFSET constant) and NOT any of this app's other five existing
conversions (WebKit/Firefox-PRTime/FILETIME/Cocoa/Android-milliseconds).
Confirmed directly from StickyParser's own real source, whose literal SQL
expression is `CreatedAt/10000000 - 62135596800`.

The Text column's real format (plain text, or RTF requiring stripping)
was NOT confirmed by any source real research could find, despite
extensive searching - a genuinely open question, disclosed rather than
silently assumed either way. Handled defensively instead: every Text
value is sniffed for the real RTF signature (b'{\\rtf') and passed through
a minimal, real RTF-control-word strip if present, used as-is otherwise -
correct regardless of which way the real answer turns out.

A real, sourced, easy-to-miss gotcha (confirmed by 3 independent sources,
including the real StickyParser tool's own README explicitly warning
about it): the most recent notes/edits often live only in adjacent
-wal/-shm sidecar files, not yet checkpointed into the main plum.sqlite
file itself. Unlike this app's other SQLite-based parsers (browser
history/cookies databases, opened via a hard read-only/immutable URI
mode), this module deliberately opens a normal, non-immutable read-write
connection against a FRESH COPY of the file (and its sidecars, if
present - never the original evidence file itself) specifically so
SQLite's own engine performs its standard WAL checkpoint on open - the
safer, sourced approach real tooling in this space actually uses, rather
than assuming an immutable/ro connection would still consult an adjacent
WAL file (unconfirmed).

The "extended schema" fields sometimes cited online (CreatedById/
UpdatedById/Revision/SyncRevision/CreationWidth/CreationHeight) were
found, during research, to trace back to unrelated pages, not a real
DFIR source - deliberately NOT included in the query here; only the
column set confirmed directly from real, working parser source code is
used.
"""
import os
import re
import shutil
import sqlite3
import tempfile

STICKY_NOTES_FILENAME = 'plum.sqlite'
_STICKY_NOTES_SIDECAR_SUFFIXES = ('-wal', '-shm')
STICKY_NOTES_MAX_NOTES = 2_000

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')
STICKY_NOTES_SCAN_MAX_CANDIDATES = 20
STICKY_NOTES_SCAN_MAX_WALKED = 20_000

_DOTNET_TICKS_EPOCH_OFFSET_SECONDS = 62_135_596_800  # seconds between 0001-01-01 and 1970-01-01
_DOTNET_TICKS_PER_SECOND = 10_000_000

_RTF_SIGNATURE = b'{\\rtf'

_NOTE_QUERY = "SELECT Id, Text, CreatedAt, UpdatedAt, DeletedAt, IsAlwaysOnTop, Theme FROM Note"


def dotnet_ticks_to_unix(ticks):
    """.NET DateTime.Ticks (100ns intervals since 0001-01-01) -> Unix
    epoch seconds - see this module's own docstring for why this is a
    genuinely different offset from FILETIME despite sharing the same
    100ns-tick unit."""
    if ticks is None:
        return None
    try:
        ticks = int(ticks)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    try:
        return (ticks / _DOTNET_TICKS_PER_SECOND) - _DOTNET_TICKS_EPOCH_OFFSET_SECONDS
    except (OverflowError, ValueError):
        return None


def _strip_rtf(text):
    """Minimal, real RTF-control-word strip for a Text value that turns
    out to be RTF-encoded - genuinely not a full RTF parser, just enough
    to recover readable plain text, matching this module's own disclosed,
    deliberately narrow scope for this defensive path."""
    if not text:
        return text
    stripped = re.sub(r'\\par[d]?\b', '\n', text)
    stripped = re.sub(r'\\\'[0-9A-Fa-f]{2}', '', stripped)  # hex-escaped chars, drop rather than guess
    stripped = re.sub(r'\\[a-zA-Z]+-?\d*[ ]?', '', stripped)
    stripped = stripped.replace('{', '').replace('}', '')
    stripped = re.sub(r'\n{3,}', '\n\n', stripped)
    return stripped.strip()


def _extract_note_text(raw_text):
    if raw_text is None:
        return ''
    if isinstance(raw_text, bytes):
        raw_bytes = raw_text
        try:
            raw_text = raw_text.decode('utf-8', errors='replace')
        except Exception:
            return ''
    else:
        raw_bytes = raw_text.encode('utf-8', errors='ignore')
    if raw_bytes.lstrip().startswith(_RTF_SIGNATURE):
        return _strip_rtf(raw_text)
    return raw_text


def find_sticky_notes_files(root_dir):
    """Recursively finds real plum.sqlite files (the main database, not
    its -wal/-shm sidecars, which are discovered alongside it later by
    the caller) anywhere under root_dir. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > STICKY_NOTES_SCAN_MAX_WALKED:
                return found, True
            if fname.lower() == STICKY_NOTES_FILENAME:
                found.append(os.path.join(root, fname))
                if len(found) >= STICKY_NOTES_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def sticky_notes_canonical_filename(entry_name):
    """Normalizes a case-insensitively-matched filename to its canonical
    lowercase form (plum.sqlite / plum.sqlite-wal / plum.sqlite-shm), or
    None if it doesn't match any of the three known names - used by the
    in-image route so extracted files always land under the exact name
    parse_sticky_notes_directory() looks for, regardless of the real
    on-disk casing."""
    lower = entry_name.lower()
    if lower == STICKY_NOTES_FILENAME:
        return STICKY_NOTES_FILENAME
    for suffix in _STICKY_NOTES_SIDECAR_SUFFIXES:
        if lower == STICKY_NOTES_FILENAME + suffix:
            return STICKY_NOTES_FILENAME + suffix
    return None


def _parse_note_rows(conn, max_notes):
    records = []
    try:
        cur = conn.execute(_NOTE_QUERY)
    except sqlite3.Error:
        return records
    try:
        for row in cur:
            if len(records) >= max_notes:
                break
            note_id, raw_text, created_ticks, updated_ticks, deleted_ticks, is_always_on_top, theme = row
            text = _extract_note_text(raw_text)
            if not text or not text.strip():
                continue
            is_deleted = bool(deleted_ticks)
            timestamp = dotnet_ticks_to_unix(updated_ticks)
            if timestamp is None:
                timestamp = dotnet_ticks_to_unix(created_ticks)
            first_line = text.strip().splitlines()[0][:80]
            title = first_line if first_line else '(empty note)'
            records.append({
                "artifact_type": "sticky_note", "title": title, "url": "", "value": text,
                "timestamp": timestamp,
                "extra": {
                    "note_id": note_id,
                    "deleted": is_deleted,
                    "created_timestamp": dotnet_ticks_to_unix(created_ticks),
                    "deleted_timestamp": dotnet_ticks_to_unix(deleted_ticks) if is_deleted else None,
                    "theme": theme,
                    "is_always_on_top": bool(is_always_on_top),
                },
            })
    except sqlite3.Error:
        pass
    return records


def parse_sticky_notes_directory(source_dir, max_notes=STICKY_NOTES_MAX_NOTES):
    """source_dir: a real local directory already containing plum.sqlite
    (required) and, if present, its plum.sqlite-wal/plum.sqlite-shm
    sidecars, named exactly - the caller (real-fs or in-image route) is
    responsible for gathering these together first, since SQLite's own
    WAL mechanism locates its sidecars by filename convention relative to
    the main db file. Everything is copied into a fresh scratch temp
    directory (never touches source_dir's own files, even though those
    are themselves typically already an extracted/copied working set, not
    the original evidence - defense in depth) and opened with a plain,
    non-immutable read-write connection so SQLite performs its own
    standard WAL checkpoint before this module queries it. Returns
    list[{artifact_type, title, url, value, timestamp, extra}] - empty on
    any failure (missing file, not really a Sticky Notes database despite
    the matching name, corrupted, etc.), the same best-effort tolerance
    every other parser in this app already applies."""
    main_src = os.path.join(source_dir, STICKY_NOTES_FILENAME)
    if not os.path.isfile(main_src):
        return []
    tmp_dir = tempfile.mkdtemp(prefix='pif_stickynotes_')
    try:
        tmp_main = os.path.join(tmp_dir, STICKY_NOTES_FILENAME)
        try:
            shutil.copy2(main_src, tmp_main)
        except OSError:
            return []
        for suffix in _STICKY_NOTES_SIDECAR_SUFFIXES:
            sidecar_src = main_src + suffix
            if os.path.isfile(sidecar_src):
                try:
                    shutil.copy2(sidecar_src, tmp_main + suffix)
                except OSError:
                    pass
        try:
            conn = sqlite3.connect(tmp_main)
        except sqlite3.Error:
            return []
        try:
            return _parse_note_rows(conn, max_notes)
        finally:
            conn.close()
    except Exception:
        return []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
