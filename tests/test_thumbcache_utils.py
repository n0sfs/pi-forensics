"""Tests for core/thumbcache_utils.py, built against hand-constructed
CMMM containers matching the real, cross-corroborated format research
documented in that module's own docstring - not mocks, real binary
records assembled the same way tests/test_registry_utils.py and
tests/test_jumplist_utils.py already build their own spec-valid fixtures.
"""
import os
import struct

import core.thumbcache_utils as tcu

_REAL_JPEG_BYTES = b'\xFF\xD8\xFF\xE0' + b'\x00' * 40  # real SOI+APP0 marker prefix, padded
_REAL_PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 40
_REAL_BMP_BYTES = b'BM' + b'\x00' * 40
_GARBAGE_BYTES = b'\x00\x01\x02\x03' * 10


def _build_entry(entry_hash, identifier, image_bytes, width=64, height=64, extra_padding=0):
    """Builds one complete on-disk entry cell: 56-byte header + UTF-16LE
    identifier + padding + image bytes. Returns (entry_bytes, entry_size)."""
    ident_bytes = identifier.encode('utf-16-le') if identifier else b''
    padding = b'\x00' * extra_padding
    header = struct.pack(
        tcu._ENTRY_HEADER_STRUCT,
        tcu._ENTRY_SIGNATURE, 0,  # entry_size patched below
        entry_hash, len(ident_bytes), len(padding), len(image_bytes),
        width, height, 0, 0, 0,
    )
    body = ident_bytes + padding + image_bytes
    entry_size = len(header) + len(body)
    header = struct.pack(
        tcu._ENTRY_HEADER_STRUCT,
        tcu._ENTRY_SIGNATURE, entry_size,
        entry_hash, len(ident_bytes), len(padding), len(image_bytes),
        width, height, 0, 0, 0,
    )
    return header + body, entry_size


def _build_container(entries, version=0x20, cache_type=5):
    """entries: list of (entry_hash, identifier, image_bytes, width, height).
    Returns the full container file bytes."""
    body = b''
    for e in entries:
        entry_hash, identifier, image_bytes = e[0], e[1], e[2]
        width = e[3] if len(e) > 3 else 64
        height = e[4] if len(e) > 4 else 64
        entry_bytes, _size = _build_entry(entry_hash, identifier, image_bytes, width, height)
        body += entry_bytes
    first_entry_offset = tcu._CONTAINER_HEADER_SIZE
    header = struct.pack(
        tcu._CONTAINER_HEADER_STRUCT,
        tcu._CONTAINER_SIGNATURE, version, cache_type,
        first_entry_offset, first_entry_offset + len(body), len(entries),
    )
    return header + body


def _write(tmp_path, name, data):
    p = os.path.join(str(tmp_path), name)
    with open(p, 'wb') as f:
        f.write(data)
    return p


def test_extract_thumbcache_entries_real_jpeg_with_hash_identifier(tmp_path):
    container = _build_container([
        (0xA1B2C3D4E5F60708, 'a1b2c3d4e5f60708', _REAL_JPEG_BYTES, 96, 96),
    ])
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir)

    assert len(records) == 1
    r = records[0]
    assert r['artifact_type'] == 'thumbcache_thumbnail'
    assert r['timestamp'] is None
    assert r['extra']['width'] == 96
    assert r['extra']['height'] == 96
    assert r['extra']['image_format'] == 'jpg'
    assert r['extra']['identifier_is_hash'] is True
    assert r['extra']['possible_filename'] is None
    assert 'a1b2c3d4e5f60708' in r['title']
    assert os.path.isfile(r['value'])
    with open(r['value'], 'rb') as f:
        assert f.read() == _REAL_JPEG_BYTES


def test_extract_thumbcache_entries_real_png_with_filename_like_identifier(tmp_path):
    container = _build_container([
        (0x1122334455667788, r'C:\Users\suspect\Pictures\evidence.png', _REAL_PNG_BYTES),
    ])
    src = _write(tmp_path, 'thumbcache_1920.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_1920.db', out_dir)

    assert len(records) == 1
    r = records[0]
    assert r['extra']['image_format'] == 'png'
    assert r['extra']['identifier_is_hash'] is False
    assert r['extra']['possible_filename'] == r'C:\Users\suspect\Pictures\evidence.png'
    assert 'Possible original filename' in r['title']
    assert os.path.isfile(r['value'])


def test_extract_thumbcache_entries_real_bmp(tmp_path):
    container = _build_container([(0x99, '', _REAL_BMP_BYTES)])
    src = _write(tmp_path, 'thumbcache_32.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_32.db', out_dir)

    assert len(records) == 1
    assert records[0]['extra']['image_format'] == 'bmp'


def test_extract_thumbcache_entries_multiple_entries_all_extracted(tmp_path):
    container = _build_container([
        (0x1, 'a1a1a1a1', _REAL_JPEG_BYTES),
        (0x2, 'b2b2b2b2', _REAL_PNG_BYTES),
        (0x3, 'c3c3c3c3', _REAL_BMP_BYTES),
    ])
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir)

    assert len(records) == 3
    formats = sorted(r['extra']['image_format'] for r in records)
    assert formats == ['bmp', 'jpg', 'png']
    # each extracted to a distinct file, none overwriting another
    paths = {r['value'] for r in records}
    assert len(paths) == 3


def test_extract_thumbcache_entries_unrecognized_image_signature_is_skipped_not_crashed(tmp_path):
    container = _build_container([
        (0x1, 'good', _REAL_JPEG_BYTES),
        (0x2, 'bad', _GARBAGE_BYTES),
    ])
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir)

    assert len(records) == 1
    assert records[0]['extra']['image_format'] == 'jpg'


def test_extract_thumbcache_entries_legacy_win7_version_is_out_of_scope(tmp_path):
    container = _build_container([(0x1, 'x', _REAL_JPEG_BYTES)], version=0x15)
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    assert tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir) == []


def test_extract_thumbcache_entries_thumbcache_idx_db_is_never_attempted(tmp_path):
    # Even if it happened to carry a real CMMM-shaped container (it never
    # would in practice - idx uses a distinct "IMMM" format), the filename
    # check alone must refuse to touch it.
    container = _build_container([(0x1, 'x', _REAL_JPEG_BYTES)])
    src = _write(tmp_path, 'thumbcache_idx.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    assert tcu.extract_thumbcache_entries(src, 'thumbcache_idx.db', out_dir) == []


def test_extract_thumbcache_entries_no_cmmm_signature_returns_empty(tmp_path):
    src = _write(tmp_path, 'thumbcache_256.db', b'NOTATHUMBCACHE' + b'\x00' * 40)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    assert tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir) == []


def test_extract_thumbcache_entries_truncated_file_returns_empty(tmp_path):
    src = _write(tmp_path, 'thumbcache_256.db', b'CMMM\x20\x00\x00\x00')  # far short of 24 bytes
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    assert tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir) == []


def test_extract_thumbcache_entries_out_of_bounds_data_size_is_skipped(tmp_path):
    """A hand-corrupted entry claiming a data_size far larger than the
    real file - must be bounds-checked and skipped, never read past EOF
    or crash."""
    entry_bytes, _size = _build_entry(0x1, 'x', _REAL_JPEG_BYTES)
    # Patch data_size (offset 24 within the 56-byte header) to something
    # absurd, without correspondingly growing the file.
    corrupted = bytearray(entry_bytes)
    struct.pack_into('<I', corrupted, 24, 999_999_999)
    first_entry_offset = tcu._CONTAINER_HEADER_SIZE
    header = struct.pack(
        tcu._CONTAINER_HEADER_STRUCT, tcu._CONTAINER_SIGNATURE, 0x20, 5,
        first_entry_offset, first_entry_offset + len(corrupted), 1,
    )
    src = _write(tmp_path, 'thumbcache_256.db', header + bytes(corrupted))
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    assert tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir) == []


def test_extract_thumbcache_entries_stops_at_end_of_valid_entries_not_the_whole_file(tmp_path):
    """Confirms the walk correctly treats free/reused space beyond the
    last real entry as a stop condition, not a crash - the container's
    own unreliable entry-count field claims more entries than actually
    follow it."""
    container = _build_container([(0x1, 'x', _REAL_JPEG_BYTES)])
    # Append garbage bytes after the one real entry, simulating free space
    # that never carries a valid CMMM signature.
    container += b'\xDE\xAD\xBE\xEF' * 20
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir)
    assert len(records) == 1


def test_extract_thumbcache_entries_respects_max_entries_cap(tmp_path):
    container = _build_container([(i, f'id{i}', _REAL_JPEG_BYTES) for i in range(10)])
    src = _write(tmp_path, 'thumbcache_256.db', container)
    out_dir = str(tmp_path / 'out')
    os.makedirs(out_dir, exist_ok=True)

    records = tcu.extract_thumbcache_entries(src, 'thumbcache_256.db', out_dir, max_entries=3)
    assert len(records) == 3


def test_parse_thumbcache_container_header_reports_version_and_support():
    def _hdr_bytes(version):
        return struct.pack(tcu._CONTAINER_HEADER_STRUCT, tcu._CONTAINER_SIGNATURE, version, 5, 24, 24, 0)

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(_hdr_bytes(0x20))
        path = f.name
    try:
        info = tcu.parse_thumbcache_container_header(path)
        assert info['version'] == 0x20
        assert info['supported'] is True
        assert info['version_label'] == 'Windows 10 or later'
    finally:
        os.remove(path)


def test_parse_thumbcache_container_header_flags_legacy_version_as_unsupported():
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(struct.pack(tcu._CONTAINER_HEADER_STRUCT, tcu._CONTAINER_SIGNATURE, 0x15, 5, 24, 24, 0))
        path = f.name
    try:
        info = tcu.parse_thumbcache_container_header(path)
        assert info['supported'] is False
        assert 'unsupported' in info['version_label'].lower()
    finally:
        os.remove(path)


def test_parse_thumbcache_container_header_returns_none_for_non_cmmm_file():
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'not a thumbcache file at all, just plain text padding here')
        path = f.name
    try:
        assert tcu.parse_thumbcache_container_header(path) is None
    finally:
        os.remove(path)


def test_find_thumbcache_files_matches_real_variant_names_excludes_idx(tmp_path):
    names = [
        'thumbcache_32.db', 'thumbcache_96.db', 'thumbcache_256.db',
        'thumbcache_1024.db', 'thumbcache_1600.db', 'thumbcache_1920.db',
        'thumbcache_exif.db', 'thumbcache_wide.db', 'thumbcache_wide_alternate.db',
        'thumbcache_custom_stream.db', 'thumbcache_sr.db',
        'thumbcache_idx.db',  # must be excluded
        'not_a_thumbcache_file.db', 'thumbcache_256.txt',
    ]
    for n in names:
        _write(tmp_path, n, b'x')

    found, truncated = tcu.find_thumbcache_files(str(tmp_path))

    found_names = {os.path.basename(p) for p in found}
    assert 'thumbcache_idx.db' not in found_names
    assert 'not_a_thumbcache_file.db' not in found_names
    assert 'thumbcache_256.txt' not in found_names
    assert 'thumbcache_32.db' in found_names
    assert 'thumbcache_sr.db' in found_names
    assert 'thumbcache_custom_stream.db' in found_names
    assert truncated is False


def test_find_thumbcache_files_skips_recovery_tool_output_dirs(tmp_path):
    skip_dir = tmp_path / 'evidence_photorec'
    skip_dir.mkdir()
    _write(skip_dir, 'thumbcache_256.db', b'x')
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    _write(real_dir, 'thumbcache_256.db', b'x')

    found, _truncated = tcu.find_thumbcache_files(str(tmp_path))
    assert len(found) == 1
    assert 'real' in found[0]
