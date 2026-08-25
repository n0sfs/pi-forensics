"""core/lnk_utils.py - Windows .lnk shortcut parsing (Part C, C3).

_build_test_lnk() hand-constructs a minimal, genuinely MS-SHLLINK-spec-
valid .lnk file - the exact technique used to verify this module live
against the real LnkParse3 library on the deployed Pi (2026-08-25).

Skipped (not failed) if LnkParse3 isn't installed - a genuinely optional
pip dependency (Part C), not a platform limitation.
"""
import struct
import datetime

import pytest

pytest.importorskip("LnkParse3", reason="LnkParse3 not installed")

import core.lnk_utils as lu


def _filetime(dt):
    epoch = datetime.datetime(1601, 1, 1)
    return int((dt - epoch).total_seconds() * 10_000_000)


def _utf16_str(s):
    """MS-SHLLINK StringData entry: CountCharacters(2) + UTF-16LE string
    (no null terminator, per spec, when the Unicode link-flag is set)."""
    return struct.pack('<H', len(s)) + s.encode('utf-16-le')


def _build_test_lnk(path, target='C:\\Windows\\System32\\notepad.exe',
                     description='Notepad Shortcut', arguments='/A test.txt',
                     working_dir='C:\\Windows\\System32', icon_location=None,
                     modified=datetime.datetime(2026, 8, 20, 12, 0, 0)):
    """Writes a real, spec-valid .lnk file to `path` - header + LinkInfo
    (VolumeIDAndLocalBasePath) + StringData (name/relative_path/working_dir/
    arguments/icon_location), no LinkTargetIDList and no ExtraData blocks
    (both optional, gated by their own LinkFlags bits, both left unset)."""
    icon_location = icon_location or target
    clsid = bytes([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])
    link_flags = 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080
    # HasLinkInfo | HasName | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode

    header = struct.pack('<I', 0x4C) + clsid
    header += struct.pack('<I', link_flags)
    header += struct.pack('<I', 0x20)  # FILE_ATTRIBUTE_ARCHIVE
    header += struct.pack('<Q', _filetime(modified - datetime.timedelta(days=19)))  # created
    header += struct.pack('<Q', _filetime(modified - datetime.timedelta(hours=1)))  # accessed
    header += struct.pack('<Q', _filetime(modified))  # written/modified
    header += struct.pack('<I', 12345) + struct.pack('<i', -1) + struct.pack('<I', 1)
    header += struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<I', 0) + struct.pack('<I', 0)
    assert len(header) == 0x4C

    local_base_path = target.encode('ascii') + b'\x00'
    volume_label = b'\x00'
    vol_id_header_size = 16
    volume_id = struct.pack('<I', vol_id_header_size + len(volume_label))
    volume_id += struct.pack('<I', 3) + struct.pack('<I', 0xDEADBEEF)
    volume_id += struct.pack('<I', vol_id_header_size) + volume_label

    link_info_header_size = 28
    volume_id_offset = link_info_header_size
    local_base_path_offset = volume_id_offset + len(volume_id)
    common_path_suffix_offset = local_base_path_offset + len(local_base_path)
    common_path_suffix = b'\x00'
    link_info_body = struct.pack('<I', volume_id_offset) + struct.pack('<I', local_base_path_offset)
    link_info_body += struct.pack('<I', 0) + struct.pack('<I', common_path_suffix_offset)
    total = link_info_header_size + len(volume_id) + len(local_base_path) + len(common_path_suffix)
    link_info = struct.pack('<I', total) + struct.pack('<I', link_info_header_size)
    link_info += struct.pack('<I', 1) + link_info_body + volume_id + local_base_path + common_path_suffix

    string_data = (
        _utf16_str(description) + _utf16_str('..\\..\\' + target.split('\\', 1)[-1])
        + _utf16_str(working_dir) + _utf16_str(arguments) + _utf16_str(icon_location)
    )

    with open(path, 'wb') as f:
        f.write(header + link_info + string_data)


def test_build_test_lnk_is_genuinely_readable_by_lnkparse3(tmp_path):
    """Sanity check on the fixture builder itself."""
    from LnkParse3 import lnk_file
    lnk_path = tmp_path / "shortcut.lnk"
    _build_test_lnk(lnk_path)
    with open(lnk_path, 'rb') as f:
        data = lnk_file(fhandle=f).get_json()
    assert data["link_info"]["local_base_path"] == 'C:\\Windows\\System32\\notepad.exe'
    assert data["data"]["command_line_arguments"] == '/A test.txt'


def test_parse_lnk_file_extracts_target_and_string_data(tmp_path):
    lnk_path = tmp_path / "shortcut.lnk"
    _build_test_lnk(lnk_path)
    records = lu.parse_lnk_file(str(lnk_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "lnk_shortcut"
    assert r["title"] == "notepad.exe"  # basename split off a Windows backslash path
    assert r["value"] == 'C:\\Windows\\System32\\notepad.exe'
    assert r["extra"]["arguments"] == '/A test.txt'
    assert r["extra"]["working_directory"] == 'C:\\Windows\\System32'
    assert r["extra"]["description"] == 'Notepad Shortcut'
    assert r["timestamp"] is not None  # native datetime -> epoch conversion worked, no FILETIME math needed


def test_parse_lnk_file_title_falls_back_when_no_target_path(tmp_path):
    # A shortcut whose LinkInfo has no local_base_path at all (e.g. a
    # network-location-only target) still needs a sensible title.
    lnk_path = tmp_path / "no_target.lnk"
    _build_test_lnk(lnk_path, target='')
    records = lu.parse_lnk_file(str(lnk_path), name_hint='fallback_name.lnk')
    assert len(records) == 1
    assert records[0]["title"] in ("Notepad Shortcut", "fallback_name.lnk")


def test_parse_lnk_file_unreadable_file_returns_empty_not_raises(tmp_path):
    bad_path = tmp_path / "garbage.lnk"
    bad_path.write_bytes(b"not a real lnk file")
    assert lu.parse_lnk_file(str(bad_path)) == []
