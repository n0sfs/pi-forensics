"""Tests for core/rdp_bitmap_cache_utils.py. Builds real, byte-exact
container/tile blobs matching the module's own confirmed layout (see its
docstring) via struct.pack, the same technique already proven for
tests/test_bits_utils.py's own byte-offset parsing - no mocked object
needed since this module never touches pyesedb or any other native
library, it's a plain binary-format walk."""
import struct

import core.rdp_bitmap_cache_utils as rbc


def _bin_tile(key1, key2, width, height, fill=b'\xAA'):
    header = struct.pack('<LLHH', key1, key2, width, height)
    return header + fill * (4 * width * height)


def _bmc_tile(key1, key2, width, height, bpp=4, compressed=False, fill=b'\xBB'):
    data = fill * (bpp * width * height) if not compressed else b'\xF0\x40\x00'  # a minimal RLE-flagged stub
    t_len = len(data)
    t_params = rbc._BMC_COMPRESSION_FLAG if compressed else 0
    header = struct.pack('<LLHH', key1, key2, width, height) + struct.pack('<LL', t_len, t_params)
    return header + data


def test_parse_bin_container_extracts_two_uncompressed_tiles(tmp_path):
    body = rbc.BIN_FILE_MAGIC + struct.pack('<L', 1)  # file-level header + version
    body += _bin_tile(0x11223344, 0x55667788, 64, 64)
    body += _bin_tile(0xAABBCCDD, 0xEEFF0011, 32, 32)
    f = tmp_path / 'Cache0001.bin'
    f.write_bytes(body)

    records = rbc.parse_rdp_bitmap_cache_file(str(f))
    assert len(records) == 2
    r0 = records[0]
    assert r0["artifact_type"] == "rdp_bitmap_cache_tile"
    assert r0["extra"]["container_type"] == 'bin'
    assert r0["extra"]["cache_key"] == '1122334455667788'
    assert r0["extra"]["width"] == 64 and r0["extra"]["height"] == 64
    assert r0["extra"]["compressed"] is False
    assert r0["extra"]["pixel_format"] == 'RGB32'
    r1 = records[1]
    assert r1["extra"]["cache_key"] == 'aabbccddeeff0011'
    assert r1["extra"]["width"] == 32


def test_parse_bmc_container_uncompressed_tile_extracted_with_correct_bpp(tmp_path):
    body = _bmc_tile(1, 2, 64, 64, bpp=3)  # RGB24
    f = tmp_path / 'bcache24.bmc'
    f.write_bytes(body)
    records = rbc.parse_rdp_bitmap_cache_file(str(f))
    assert len(records) == 1
    assert records[0]["extra"]["container_type"] == 'bmc'
    assert records[0]["extra"]["compressed"] is False
    assert records[0]["extra"]["pixel_format"] == 'RGB24'


def test_parse_bmc_container_compressed_tile_flagged_not_decoded(tmp_path):
    body = _bmc_tile(1, 2, 64, 64, compressed=True)
    f = tmp_path / 'bcache22.bmc'
    f.write_bytes(body)
    records = rbc.parse_rdp_bitmap_cache_file(str(f))
    assert len(records) == 1
    assert records[0]["extra"]["compressed"] is True
    assert 'not decoded' in records[0]["extra"]["pixel_format"]


def test_parse_multiple_bmc_tiles_in_sequence(tmp_path):
    body = _bmc_tile(1, 1, 64, 64, bpp=4) + _bmc_tile(2, 2, 64, 64, bpp=4) + _bmc_tile(3, 3, 64, 64, bpp=4)
    f = tmp_path / 'bcache24.bmc'
    f.write_bytes(body)
    records = rbc.parse_rdp_bitmap_cache_file(str(f))
    assert len(records) == 3
    assert [r["extra"]["tile_index"] for r in records] == [0, 1, 2]


def test_parse_truncated_trailing_tile_stops_cleanly_without_error(tmp_path):
    good_tile = _bmc_tile(1, 1, 64, 64, bpp=4)
    truncated = struct.pack('<LLHH', 9, 9, 64, 64) + struct.pack('<LL', 4 * 64 * 64, 0) + b'\x00' * 10  # far too short
    body = good_tile + truncated
    f = tmp_path / 'bcache24.bmc'
    f.write_bytes(body)
    records = rbc.parse_rdp_bitmap_cache_file(str(f))
    assert len(records) == 1  # only the well-formed leading tile


def test_parse_empty_file_returns_empty(tmp_path):
    f = tmp_path / 'Cache0001.bin'
    f.write_bytes(b'')
    assert rbc.parse_rdp_bitmap_cache_file(str(f)) == []


def test_parse_missing_file_returns_empty_not_raises(tmp_path):
    assert rbc.parse_rdp_bitmap_cache_file(str(tmp_path / 'nonexistent.bin')) == []


def test_find_rdp_bitmap_cache_files_requires_terminal_server_client_ancestor(tmp_path):
    tsc_dir = tmp_path / 'Users' / 'bob' / 'AppData' / 'Local' / 'Microsoft' / 'Terminal Server Client' / 'Cache'
    tsc_dir.mkdir(parents=True)
    (tsc_dir / 'Cache0001.bin').write_bytes(b'x')
    other_dir = tmp_path / 'unrelated'
    other_dir.mkdir()
    (other_dir / 'Cache0002.bin').write_bytes(b'x')  # matches filename pattern but NOT under the right ancestor

    found, truncated = rbc.find_rdp_bitmap_cache_files(str(tmp_path))
    assert len(found) == 1
    assert found[0].endswith('Cache0001.bin')
    assert truncated is False


def test_find_rdp_bitmap_cache_files_matches_legacy_bcache_naming(tmp_path):
    tsc_dir = tmp_path / 'Terminal Server Client' / 'Cache'
    tsc_dir.mkdir(parents=True)
    (tsc_dir / 'bcache22.bmc').write_bytes(b'x')
    (tsc_dir / 'bcache24.bmc').write_bytes(b'x')
    (tsc_dir / 'unrelated.txt').write_bytes(b'x')
    found, truncated = rbc.find_rdp_bitmap_cache_files(str(tmp_path))
    assert len(found) == 2
