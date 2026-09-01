"""core/jumplist_utils.py - Windows Jump List parsing (AutomaticDestinations
+ CustomDestinations). Builds real, byte-correct fixtures (a real OLE2/CFBF
container via pycfb.CFBWriter, real DestList stream bytes matching the
confirmed layout, real concatenated LNK blobs) rather than mocking the
parser, so a schema-shape mistake would actually fail these tests -
matching this test suite's own established convention for every other
binary-format parser in this codebase.

Skipped (not failed) if olefile/pycfb/LnkParse3 aren't installed - genuine
optional dependencies, not a platform limitation.
"""
import datetime
import struct
import uuid

import pytest

pytest.importorskip("olefile", reason="olefile not installed")
pytest.importorskip("pycfb", reason="pycfb not installed (test-fixture-only dependency)")
pytest.importorskip("LnkParse3", reason="LnkParse3 not installed")

import olefile
import pycfb

import core.jumplist_utils as ju


# --- Shared LNK-blob builder, mirroring tests/test_lnk_utils.py's own
# _build_test_lnk() exactly, just returning bytes instead of writing a
# file - kept as its own local copy per this test suite's established
# "self-contained test files" convention. ---

def _filetime(dt):
    epoch = datetime.datetime(1601, 1, 1)
    return int((dt - epoch).total_seconds() * 10_000_000)


def _utf16_str(s):
    return struct.pack('<H', len(s)) + s.encode('utf-16-le')


def _build_lnk_bytes(target='C:\\Windows\\System32\\notepad.exe', description='Notepad',
                      modified=datetime.datetime(2026, 8, 1, 12, 0, 0)):
    clsid = bytes([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])
    link_flags = 0x0002 | 0x0004 | 0x0080  # HasLinkInfo | HasName | IsUnicode
    header = struct.pack('<I', 0x4C) + clsid
    header += struct.pack('<I', link_flags)
    header += struct.pack('<I', 0x20)
    header += struct.pack('<Q', _filetime(modified)) * 3
    header += struct.pack('<I', 1000) + struct.pack('<i', -1) + struct.pack('<I', 1)
    header += struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<I', 0) + struct.pack('<I', 0)
    local_base_path = target.encode('ascii') + b'\x00'
    volume_label = b'\x00'
    volume_id = (struct.pack('<I', 16 + len(volume_label)) + struct.pack('<I', 3)
                 + struct.pack('<I', 0xDEADBEEF) + struct.pack('<I', 16) + volume_label)
    link_info_header_size = 28
    volume_id_offset = link_info_header_size
    local_base_path_offset = volume_id_offset + len(volume_id)
    common_path_suffix_offset = local_base_path_offset + len(local_base_path)
    body = (struct.pack('<I', volume_id_offset) + struct.pack('<I', local_base_path_offset)
            + struct.pack('<I', 0) + struct.pack('<I', common_path_suffix_offset))
    total = link_info_header_size + len(volume_id) + len(local_base_path) + 1
    link_info = (struct.pack('<I', total) + struct.pack('<I', link_info_header_size)
                 + struct.pack('<I', 1) + body + volume_id + local_base_path + b'\x00')
    string_data = _utf16_str(description)
    return header + link_info + string_data


# --- DestList stream builder, matching the confirmed byte layout exactly
# (core/jumplist_utils.py's own docstring/inline comments cite the 4
# sources this was cross-checked against) ---

def _build_destlist_bytes(entries, version=1):
    """entries: [{'entry_number', 'hostname', 'modified' (datetime),
    'pin_status', 'path', 'access_count', 'interaction_count'}, ...]."""
    header = struct.pack('<II', version, len(entries)) + b'\x00' * 24  # 32-byte header total
    body = b''
    for e in entries:
        rec = struct.pack('<q', 0)  # offset 0: checksum/unknown, unused by the parser
        rec += b'\x11' * 16  # volume droid (unused/unparsed)
        rec += b'\x22' * 16  # file droid (unused/unparsed)
        rec += b'\x33' * 16  # volume birth droid (unused/unparsed)
        rec += b'\x44' * 16  # file birth droid (unused/unparsed)
        hostname_bytes = e['hostname'].encode('ascii') + b'\x00'
        rec += hostname_bytes.ljust(16, b'\x00')[:16]
        rec += struct.pack('<I', e['entry_number'])
        rec += struct.pack('<I', 0)  # unknown
        rec += struct.pack('<f', e.get('access_count', 0.0))
        rec += struct.pack('<Q', _filetime(e['modified']))
        rec += struct.pack('<i', e.get('pin_status', -1))
        assert len(rec) == 112  # the shared prefix both v1 and v2+ layouts have in common
        path = e['path']
        if version == 1:
            # v1's path-length field sits directly at offset 112 - nothing
            # else follows the shared 112-byte prefix.
            rec += struct.pack('<H', len(path))
            rec += path.encode('utf-16-le')
            assert len(rec) == 114 + len(path) * 2
        else:
            # v2+: offset 112 (4 bytes) unknown, offset 116 (4 bytes)
            # interaction_count, offset 120 (8 bytes) two unknown fields,
            # THEN the path-length field at offset 128 - matching the
            # production parser's own confirmed read offsets exactly.
            rec += struct.pack('<I', 0)  # offset 112: unknown
            rec += struct.pack('<i', e.get('interaction_count') or 0)  # offset 116: interaction_count
            rec += b'\x00' * 8  # offset 120-127: two unknown 4-byte fields
            assert len(rec) == 128
            rec += struct.pack('<H', len(path))
            rec += path.encode('utf-16-le')
            assert len(rec) == 130 + len(path) * 2
            rec += struct.pack('<I', 0)  # SPS block size = 0, no SPS data
        body += rec
    return header + body


def test_build_destlist_v1_entry_sizing_matches_the_confirmed_layout():
    data = _build_destlist_bytes([{
        'entry_number': 1, 'hostname': 'WORKSTATION1',
        'modified': datetime.datetime(2026, 8, 1, 12, 0, 0),
        'pin_status': -1, 'path': 'C:\\test.exe',
    }], version=1)
    assert len(data) == 32 + 114 + len('C:\\test.exe') * 2


# --- DestList parsing (the internal _parse_destlist/_parse_one_destlist_entry) ---

def test_parse_destlist_v1_real_entry():
    modified = datetime.datetime(2026, 8, 1, 12, 0, 0)
    data = _build_destlist_bytes([{
        'entry_number': 5, 'hostname': 'DESKTOP-ABC', 'modified': modified,
        'pin_status': -1, 'path': 'C:\\Users\\suspect\\Documents\\report.docx',
        'access_count': 3.0,
    }], version=1)
    entries = ju._parse_destlist(data)
    assert 5 in entries
    e = entries[5]
    assert e['hostname'] == 'DESKTOP-ABC'
    assert e['path'] == 'C:\\Users\\suspect\\Documents\\report.docx'
    assert e['pin_status'] == -1
    assert e['version'] == 1
    assert e['interaction_count'] is None  # v1 has no interaction_count field at all
    assert e['timestamp'] == modified.replace(tzinfo=datetime.timezone.utc).timestamp()


def test_parse_destlist_v2_real_entry_with_interaction_count():
    modified = datetime.datetime(2026, 8, 1, 12, 0, 0)
    data = _build_destlist_bytes([{
        'entry_number': 7, 'hostname': 'DESKTOP-XYZ', 'modified': modified,
        'pin_status': 0, 'path': 'C:\\evidence.pdf', 'interaction_count': 42,
    }], version=3)
    entries = ju._parse_destlist(data)
    assert 7 in entries
    e = entries[7]
    assert e['path'] == 'C:\\evidence.pdf'
    assert e['pin_status'] == 0  # 0 (not -1) means pinned
    assert e['interaction_count'] == 42
    assert e['version'] == 3


def test_parse_destlist_pin_status_negative_one_means_unpinned():
    data = _build_destlist_bytes([{
        'entry_number': 1, 'hostname': 'H', 'modified': datetime.datetime(2026, 1, 1),
        'pin_status': -1, 'path': 'C:\\x.exe',
    }], version=1)
    assert ju._parse_destlist(data)[1]['pin_status'] == -1


def test_parse_destlist_multiple_entries_correct_offsets():
    modified = datetime.datetime(2026, 1, 1)
    data = _build_destlist_bytes([
        {'entry_number': 1, 'hostname': 'H1', 'modified': modified, 'pin_status': -1, 'path': 'C:\\a.exe'},
        {'entry_number': 2, 'hostname': 'H2', 'modified': modified, 'pin_status': -1, 'path': 'C:\\bb.exe'},
        {'entry_number': 3, 'hostname': 'H3', 'modified': modified, 'pin_status': -1, 'path': 'C:\\ccc.exe'},
    ], version=1)
    entries = ju._parse_destlist(data)
    assert set(entries.keys()) == {1, 2, 3}
    assert entries[1]['path'] == 'C:\\a.exe'
    assert entries[2]['path'] == 'C:\\bb.exe'
    assert entries[3]['path'] == 'C:\\ccc.exe'


def test_parse_destlist_v2_multiple_entries_with_sps_block_correct_offsets():
    # The trickiest offset-correctness case: v2's trailing 4-byte SPS-size
    # field must be skipped correctly or every entry after the first
    # misaligns and the whole rest of the stream fails to parse.
    modified = datetime.datetime(2026, 1, 1)
    data = _build_destlist_bytes([
        {'entry_number': 10, 'hostname': 'H1', 'modified': modified, 'pin_status': -1, 'path': 'C:\\one.exe'},
        {'entry_number': 20, 'hostname': 'H2', 'modified': modified, 'pin_status': -1, 'path': 'C:\\two.exe'},
    ], version=3)
    entries = ju._parse_destlist(data)
    assert set(entries.keys()) == {10, 20}
    assert entries[10]['path'] == 'C:\\one.exe'
    assert entries[20]['path'] == 'C:\\two.exe'


def test_parse_destlist_truncated_stream_returns_partial_not_error():
    data = _build_destlist_bytes([{
        'entry_number': 1, 'hostname': 'H', 'modified': datetime.datetime(2026, 1, 1),
        'pin_status': -1, 'path': 'C:\\x.exe',
    }], version=1)
    truncated = data[:len(data) - 5]
    result = ju._parse_destlist(truncated)
    assert isinstance(result, dict)  # never raises


def test_parse_destlist_empty_or_header_only_returns_empty():
    assert ju._parse_destlist(b'') == {}
    assert ju._parse_destlist(struct.pack('<II', 1, 0) + b'\x00' * 24) == {}


# --- parse_jumplist_automatic() end-to-end, real OLE2 container ---

def _build_automatic_destinations_file(path, lnk_specs, destlist_entries=None, destlist_version=1):
    """lnk_specs: {entry_number_hex_str: lnk_bytes, ...}. Writes a real,
    valid OLE2/CFBF file via pycfb.CFBWriter (round-trip-verified against
    olefile before being trusted - see requirements-dev.txt's own comment)."""
    stream_paths = list(lnk_specs.keys())
    stream_data = list(lnk_specs.values())
    if destlist_entries is not None:
        stream_paths.append('DestList')
        stream_data.append(_build_destlist_bytes(destlist_entries, version=destlist_version))
    writer = pycfb.CFBWriter(stream_paths=stream_paths, stream_data=stream_data, root_clsid=uuid.UUID(int=0))
    with open(path, 'wb') as f:
        f.write(writer.data)


def test_parse_jumplist_automatic_real_entry_with_destlist_correlation(tmp_path):
    modified = datetime.datetime(2026, 8, 1, 12, 0, 0)
    lnk_bytes = _build_lnk_bytes(target='C:\\Users\\suspect\\report.docx', description='Report')
    fpath = tmp_path / "abcdef0123456789.automaticDestinations-ms"
    _build_automatic_destinations_file(
        str(fpath), {'1': lnk_bytes},
        destlist_entries=[{
            'entry_number': 1, 'hostname': 'DESKTOP-CASE01', 'modified': modified,
            'pin_status': -1, 'path': 'C:\\Users\\suspect\\report.docx', 'access_count': 4.0,
        }], destlist_version=1)
    records = ju.parse_jumplist_automatic(str(fpath))
    assert len(records) == 1
    r = records[0]
    assert r['artifact_type'] == 'jumplist_automatic_entry'
    assert r['value'] == 'C:\\Users\\suspect\\report.docx'
    assert r['title'] == 'report.docx'
    assert r['extra']['app_id'] == 'abcdef0123456789'
    assert r['extra']['entry_number'] == 1
    assert r['extra']['hostname'] == 'DESKTOP-CASE01'
    assert r['extra']['pinned'] is False
    # DestList's own last-modified timestamp wins over the LNK's own header timestamp.
    assert r['timestamp'] == modified.replace(tzinfo=datetime.timezone.utc).timestamp()


def test_parse_jumplist_automatic_pinned_entry_flag_true(tmp_path):
    lnk_bytes = _build_lnk_bytes(target='C:\\pinned.exe')
    fpath = tmp_path / "app.automaticDestinations-ms"
    _build_automatic_destinations_file(
        str(fpath), {'1': lnk_bytes},
        destlist_entries=[{
            'entry_number': 1, 'hostname': 'H', 'modified': datetime.datetime(2026, 1, 1),
            'pin_status': 0, 'path': 'C:\\pinned.exe',
        }])
    records = ju.parse_jumplist_automatic(str(fpath))
    assert records[0]['extra']['pinned'] is True


def test_parse_jumplist_automatic_hex_stream_naming_uppercase_no_padding(tmp_path):
    # Entry 10 -> stream name "A" (uppercase hex, no leading zeros) - the
    # real Windows naming convention confirmed via Eric Zimmerman's own
    # JumpList library source.
    lnk_bytes = _build_lnk_bytes(target='C:\\tenth.exe')
    fpath = tmp_path / "app.automaticDestinations-ms"
    _build_automatic_destinations_file(
        str(fpath), {'A': lnk_bytes},
        destlist_entries=[{
            'entry_number': 10, 'hostname': 'H', 'modified': datetime.datetime(2026, 1, 1),
            'pin_status': -1, 'path': 'C:\\tenth.exe',
        }])
    records = ju.parse_jumplist_automatic(str(fpath))
    assert len(records) == 1
    assert records[0]['extra']['entry_number'] == 10
    assert records[0]['value'] == 'C:\\tenth.exe'


def test_parse_jumplist_automatic_multiple_entries_correctly_correlated(tmp_path):
    modified = datetime.datetime(2026, 8, 1)
    lnk1 = _build_lnk_bytes(target='C:\\first.exe', description='First')
    lnk2 = _build_lnk_bytes(target='C:\\second.exe', description='Second')
    fpath = tmp_path / "app.automaticDestinations-ms"
    _build_automatic_destinations_file(
        str(fpath), {'1': lnk1, '2': lnk2},
        destlist_entries=[
            {'entry_number': 1, 'hostname': 'H', 'modified': modified, 'pin_status': -1, 'path': 'C:\\first.exe'},
            {'entry_number': 2, 'hostname': 'H', 'modified': modified, 'pin_status': -1, 'path': 'C:\\second.exe'},
        ])
    records = ju.parse_jumplist_automatic(str(fpath))
    assert len(records) == 2
    by_entry = {r['extra']['entry_number']: r for r in records}
    assert by_entry[1]['value'] == 'C:\\first.exe'
    assert by_entry[2]['value'] == 'C:\\second.exe'


def test_parse_jumplist_automatic_numbered_stream_with_no_destlist_correlation_still_parses(tmp_path):
    # A real, possible case: DestList missing/corrupted, or an entry number
    # with no matching DestList row - the LNK content alone still parses,
    # just without the enrichment fields.
    lnk_bytes = _build_lnk_bytes(target='C:\\orphan.exe')
    fpath = tmp_path / "app.automaticDestinations-ms"
    _build_automatic_destinations_file(str(fpath), {'1': lnk_bytes}, destlist_entries=None)
    records = ju.parse_jumplist_automatic(str(fpath))
    assert len(records) == 1
    assert records[0]['value'] == 'C:\\orphan.exe'
    assert 'hostname' not in records[0]['extra']
    assert records[0]['timestamp'] is not None  # falls back to the LNK's own header timestamp


def test_parse_jumplist_automatic_on_a_non_ole2_file_returns_empty_not_error(tmp_path):
    bad_path = tmp_path / "not_a_real.automaticDestinations-ms"
    bad_path.write_bytes(b"this is not an OLE2 file at all")
    assert ju.parse_jumplist_automatic(str(bad_path)) == []


def test_parse_jumplist_automatic_ignores_streams_with_unrecognized_non_hex_names(tmp_path):
    lnk_bytes = _build_lnk_bytes(target='C:\\real.exe')
    fpath = tmp_path / "app.automaticDestinations-ms"
    # 'SomeOtherStream' isn't a valid hex entry-number name and isn't
    # 'DestList' either - must be skipped, not guessed at or crash.
    writer = pycfb.CFBWriter(
        stream_paths=['1', 'SomeOtherStream'], stream_data=[lnk_bytes, b'unrelated data'],
        root_clsid=uuid.UUID(int=0))
    with open(fpath, 'wb') as f:
        f.write(writer.data)
    records = ju.parse_jumplist_automatic(str(fpath))
    assert len(records) == 1
    assert records[0]['value'] == 'C:\\real.exe'


# --- parse_jumplist_custom() end-to-end, magic-byte-scan segmentation ---

def test_parse_jumplist_custom_single_embedded_shortcut(tmp_path):
    lnk_bytes = _build_lnk_bytes(target='C:\\pinned_item.exe', description='Pinned Item')
    fpath = tmp_path / "app.customDestinations-ms"
    fpath.write_bytes(lnk_bytes)
    records = ju.parse_jumplist_custom(str(fpath))
    assert len(records) == 1
    assert records[0]['artifact_type'] == 'jumplist_custom_shortcut'
    assert records[0]['value'] == 'C:\\pinned_item.exe'


def test_parse_jumplist_custom_multiple_concatenated_shortcuts_segmented_correctly(tmp_path):
    # This is the real, previously-verified-live scenario (during this
    # feature's own grounding pass): LnkParse3 does NOT stop reading
    # exactly at one embedded LNK's own real boundary (confirmed: parsing
    # the first of two concatenated LNKs left the file position at the end
    # of BOTH, not the first one's real end) - the magic-byte-scan
    # approach this function actually uses is what correctly recovers each
    # individual shortcut regardless.
    lnk1 = _build_lnk_bytes(target='C:\\first.exe', description='First')
    lnk2 = _build_lnk_bytes(target='C:\\second.exe', description='Second')
    lnk3 = _build_lnk_bytes(target='C:\\third.exe', description='Third')
    fpath = tmp_path / "app.customDestinations-ms"
    fpath.write_bytes(lnk1 + lnk2 + lnk3)
    records = ju.parse_jumplist_custom(str(fpath))
    assert len(records) == 3
    targets = {r['value'] for r in records}
    assert targets == {'C:\\first.exe', 'C:\\second.exe', 'C:\\third.exe'}


def test_parse_jumplist_custom_with_category_framing_bytes_between_entries(tmp_path):
    # Real CustomDestinations files have category-header/footer bytes
    # between entries (this module deliberately doesn't parse that
    # framing - see its own docstring) - the magic-byte scan must still
    # correctly find and segment each real embedded shortcut regardless of
    # what junk bytes surround them.
    lnk1 = _build_lnk_bytes(target='C:\\one.exe')
    lnk2 = _build_lnk_bytes(target='C:\\two.exe')
    junk = b'\x00\x00\x00\x02' + b'\xab\xfb\xbf\xba'  # a plausible category-type + footer signature
    fpath = tmp_path / "app.customDestinations-ms"
    fpath.write_bytes(b'\x00' * 8 + lnk1 + junk + lnk2)
    records = ju.parse_jumplist_custom(str(fpath))
    assert len(records) == 2
    targets = {r['value'] for r in records}
    assert targets == {'C:\\one.exe', 'C:\\two.exe'}


def test_parse_jumplist_custom_no_embedded_shortcuts_returns_empty(tmp_path):
    fpath = tmp_path / "app.customDestinations-ms"
    fpath.write_bytes(b'no real shortcuts in here at all' * 5)
    assert ju.parse_jumplist_custom(str(fpath)) == []


def test_parse_jumplist_custom_unreadable_file_returns_empty_not_error(tmp_path):
    assert ju.parse_jumplist_custom(str(tmp_path / "does_not_exist.customDestinations-ms")) == []


# --- find_jumplist_files() ---

def test_find_jumplist_files_matches_both_extensions_case_insensitively(tmp_path):
    profile = tmp_path / "Users" / "suspect" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    auto_dir = profile / "AutomaticDestinations"
    custom_dir = profile / "CustomDestinations"
    auto_dir.mkdir(parents=True)
    custom_dir.mkdir(parents=True)
    (auto_dir / "abc123.automaticDestinations-ms").write_bytes(b'x')
    (auto_dir / "def456.AUTOMATICDESTINATIONS-MS").write_bytes(b'x')  # case-insensitive match
    (custom_dir / "ghi789.customDestinations-ms").write_bytes(b'x')
    (auto_dir / "unrelated.txt").write_bytes(b'x')  # must not match
    found, truncated = ju.find_jumplist_files(str(tmp_path))
    names = {p.split('\\')[-1].split('/')[-1] for p in found}
    assert names == {"abc123.automaticDestinations-ms", "def456.AUTOMATICDESTINATIONS-MS", "ghi789.customDestinations-ms"}
    assert truncated is False


def test_find_jumplist_files_truncates_at_the_candidate_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ju, "JUMPLIST_SCAN_MAX_CANDIDATES", 2)
    for i in range(4):
        (tmp_path / f"app{i}.automaticDestinations-ms").write_bytes(b'x')
    found, truncated = ju.find_jumplist_files(str(tmp_path))
    assert len(found) == 2
    assert truncated is True


def test_find_jumplist_files_empty_directory_returns_empty(tmp_path):
    found, truncated = ju.find_jumplist_files(str(tmp_path))
    assert found == []
    assert truncated is False


# --- Dispatcher ---

def test_dispatch_routes_automatic_and_custom_extensions(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ju, "parse_jumplist_automatic", lambda p: calls.append(("auto", p)) or [{"a": 1}])
    monkeypatch.setattr(ju, "parse_jumplist_custom", lambda p: calls.append(("custom", p)) or [{"b": 2}])
    assert ju.parse_jumplist_file("/x/app.automaticDestinations-ms") == [{"a": 1}]
    assert ju.parse_jumplist_file("/x/app.customDestinations-ms") == [{"b": 2}]
    assert {c[0] for c in calls} == {"auto", "custom"}


def test_dispatch_unrecognized_extension_returns_empty():
    assert ju.parse_jumplist_file("/x/unrelated.txt") == []


def test_dispatch_uses_filename_override_not_path_basename(monkeypatch):
    # Mirrors the in-image caller shape (a temp-extraction path's own
    # basename is meaningless; the real evidence filename is passed
    # explicitly).
    calls = []
    monkeypatch.setattr(ju, "parse_jumplist_automatic", lambda p: calls.append(p) or [])
    ju.parse_jumplist_file("/tmp/xyz123.tmp", filename="real_app.automaticDestinations-ms")
    assert calls == ["/tmp/xyz123.tmp"]
