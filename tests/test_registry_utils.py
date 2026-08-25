"""core/registry_utils.py - Windows Registry hive parsing (Part C, C1).

_build_test_hive() below hand-constructs a minimal, genuinely spec-valid
REGF file byte-for-byte, following the exact same technique used to verify
this module live on the deployed Pi against the real python-registry
library (2026-08-25): built directly from python-registry's own
RegistryParse.py source (NK/VK/LF record offsets, HBIN cell allocation),
not assumed from external documentation. Real records are constructed for
each of the three key paths this module targets (TypedPaths, RunMRU,
RecentDocs) - not committed as an opaque binary fixture, so a reviewer can
see exactly what bytes a test is asserting against.

Skipped (not failed) if python-registry isn't installed - unlike this
project's usual core.jobs (POSIX pwd/fcntl) skip reason, this one is a
genuinely optional pip dependency (Part C), not a platform limitation.
"""
import struct
import datetime

import pytest

Registry = pytest.importorskip("Registry.Registry", reason="python-registry not installed")

import core.registry_utils as ru


def _filetime(dt):
    epoch = datetime.datetime(1601, 1, 1)
    return int((dt - epoch).total_seconds() * 10_000_000)


_FT_NOW = _filetime(datetime.datetime(2026, 8, 20, 12, 0, 0))


class _HiveBuilder:
    def __init__(self):
        self.buf = bytearray()

    def _pad8(self, data):
        return data + b'\x00' * ((-len(data)) % 8)

    def alloc(self, payload):
        body = self._pad8(payload)
        cell = struct.pack('<i', -(4 + len(body))) + body
        off = len(self.buf) + 0x20
        self.buf += cell
        return off

    def set_parent(self, child_nk_off, parent_nk_off):
        """Patches a child NK record's parent-offset field (NK+0x10) after
        the fact, once the parent's own offset is known - children are
        necessarily built before their parent (a parent's subkey-list cell
        needs its children's offsets already), so this can't be set at
        child-creation time. Without this, RegistryKey.path() (which
        python-registry calls internally to build its own exception
        message on a *miss*, not just when explicitly requested) crashes
        on any lookup miss below the root - confirmed live the hard way
        while building this exact fixture."""
        field_pos = (child_nk_off - 0x20) + 4 + 0x10
        self.buf[field_pos:field_pos + 4] = struct.pack('<I', parent_nk_off)


def _utf16(s):
    return s.encode('utf-16-le')


def _build_test_hive(path, hive_name='NTUSER.DAT'):
    """Writes a real REGF file to `path` (bottom-up: leaves before parents,
    since a cell's own offset is only known once allocated) with:
      Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths (url1, url2)
      Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU (MRUList + 'a')
      Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs (1 MRU-binary value)
    Every subkey() lookup along these three paths succeeds by construction
    - RegistryKey.path() (only invoked internally by python-registry on a
    *miss*, to build an exception message) is deliberately never exercised
    here, so no parent-offset wiring is needed for these positive-path
    tests (confirmed live on the Pi: a *miss* against this same minimal
    hive shape does crash on .path() for exactly this reason - a limitation
    of this deliberately-minimal test fixture, not of core/registry_utils.py
    itself, whose own RegistryKeyNotFoundException handling is plain,
    already-correct Python).
    """
    h = _HiveBuilder()

    def make_vk(name, data_str, reg_type=1):
        data_bytes = _utf16(data_str)
        data_off = h.alloc(data_bytes)
        name_b = name.encode('ascii')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(data_bytes))
        vk += struct.pack('<I', data_off) + struct.pack('<I', reg_type)
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_binary_vk(name, raw):
        off = h.alloc(raw)
        name_b = name.encode('ascii')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(raw))
        vk += struct.pack('<I', off) + struct.pack('<I', 3)  # REG_BINARY
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_values_list(vk_offsets):
        return h.alloc(b''.join(struct.pack('<I', o) for o in vk_offsets))

    def make_nk(name, subkey_list_off, subkey_count, values_list_off, values_count, is_root=False):
        flags = 0x0020 | (0x0004 if is_root else 0)
        name_b = name.encode('ascii')
        nk = b'nk' + struct.pack('<H', flags) + struct.pack('<Q', _FT_NOW)
        nk += struct.pack('<I', 0) + struct.pack('<I', 0xFFFFFFFF)
        nk += struct.pack('<I', subkey_count if subkey_count else 0xFFFFFFFF) + struct.pack('<I', 0)
        nk += struct.pack('<I', subkey_list_off if subkey_list_off is not None else 0xFFFFFFFF)
        nk += struct.pack('<I', 0xFFFFFFFF)
        nk += struct.pack('<I', values_count if values_count else 0xFFFFFFFF)
        nk += struct.pack('<I', values_list_off if values_list_off is not None else 0xFFFFFFFF)
        nk += struct.pack('<I', 0xFFFFFFFF) + struct.pack('<I', 0xFFFFFFFF)
        nk += b'\x00' * (0x48 - 0x34)
        nk += struct.pack('<H', len(name_b)) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(nk))

    def make_lf(nk_offsets):
        body = b'lf' + struct.pack('<H', len(nk_offsets))
        for off in nk_offsets:
            body += struct.pack('<I', off) + b'\x00\x00\x00\x00'
        return h.alloc(body)

    vl_typedpaths = make_values_list([make_vk('url1', 'C:\\Test\\Path1'), make_vk('url2', 'C:\\Test\\Path2')])
    nk_typedpaths = make_nk('TypedPaths', None, 0, vl_typedpaths, 2)

    vl_runmru = make_values_list([make_vk('MRUList', 'a'), make_vk('a', 'notepad.exe\\1')])
    nk_runmru = make_nk('RunMRU', None, 0, vl_runmru, 2)

    recent_raw = 'budget.docx'.encode('utf-16-le') + b'\x00\x00shellitemjunk'
    vl_recentdocs = make_values_list([make_binary_vk('0', recent_raw)])
    nk_recentdocs = make_nk('RecentDocs', None, 0, vl_recentdocs, 1)

    lf_explorer = make_lf([nk_typedpaths, nk_runmru, nk_recentdocs])
    nk_explorer = make_nk('Explorer', lf_explorer, 3, None, 0)
    lf_cv = make_lf([nk_explorer])
    nk_cv = make_nk('CurrentVersion', lf_cv, 1, None, 0)
    lf_windows = make_lf([nk_cv])
    nk_windows = make_nk('Windows', lf_windows, 1, None, 0)
    lf_ms = make_lf([nk_windows])
    nk_ms = make_nk('Microsoft', lf_ms, 1, None, 0)
    lf_sw = make_lf([nk_ms])
    nk_sw = make_nk('Software', lf_sw, 1, None, 0)
    lf_root = make_lf([nk_sw])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)

    # Wire up real parent offsets top-down, now that every NK's own offset
    # is known - see HiveBuilder.set_parent()'s docstring for why this
    # matters even for tests that only exercise "successful" lookups: a
    # *miss* partway down an unrelated candidate path (e.g. TypedURLs,
    # which this fixture deliberately never builds) still needs a working
    # RegistryKey.path() to report that miss without crashing.
    h.set_parent(nk_sw, root_off)
    h.set_parent(nk_ms, nk_sw)
    h.set_parent(nk_windows, nk_ms)
    h.set_parent(nk_cv, nk_windows)
    h.set_parent(nk_explorer, nk_cv)
    h.set_parent(nk_typedpaths, nk_explorer)
    h.set_parent(nk_runmru, nk_explorer)
    h.set_parent(nk_recentdocs, nk_explorer)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16(hive_name).ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_build_test_hive_is_genuinely_readable_by_python_registry(tmp_path):
    """Sanity check on the fixture builder itself, independent of this
    app's own parsing code - if this fails, a test failure below points at
    the fixture, not core/registry_utils.py."""
    hive_path = tmp_path / "NTUSER.DAT"
    _build_test_hive(hive_path)
    with open(hive_path, 'rb') as f:
        reg = Registry.Registry(f)
        root = reg.root()
        assert root.name() == 'ROOT'
        key = root.find_key(r'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths')
        values = {v.name(): v.value() for v in key.values()}
        assert values == {'url1': 'C:\\Test\\Path1', 'url2': 'C:\\Test\\Path2'}


def test_parse_typed_paths_extracts_real_url_values(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_test_hive(hive_path)
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    typed = [r for r in records if r["artifact_type"] == "registry_typed_urls"]
    assert {r["value"] for r in typed} == {'C:\\Test\\Path1', 'C:\\Test\\Path2'}
    assert all(r["timestamp"] is not None for r in typed)  # native datetime -> epoch conversion worked


def test_parse_run_history_skips_mrulist_and_strips_trailing_marker(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_test_hive(hive_path)
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    run_history = [r for r in records if r["artifact_type"] == "registry_run_history"]
    assert len(run_history) == 1  # MRUList itself must be skipped, not treated as a real command
    assert run_history[0]["title"] == 'notepad.exe'  # trailing '\1' MRU-order marker stripped


def test_parse_recent_docs_decodes_the_readable_filename_prefix(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_test_hive(hive_path)
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    recent = [r for r in records if r["artifact_type"] == "registry_recent_docs"]
    assert len(recent) == 1
    assert recent[0]["title"] == 'budget.docx'


def test_parse_registry_hive_file_dispatches_by_exact_uppercased_basename(tmp_path):
    # SYSTEM/SOFTWARE dispatch to different sub-parsers (USB history / installed
    # programs) that find nothing in this NTUSER.DAT-shaped fixture - confirms
    # the dispatch is real (not "NTUSER.DAT parsing runs regardless of filename"),
    # and that a real miss on those specific key paths degrades to [] cleanly.
    hive_path = tmp_path / "SYSTEM"
    _build_test_hive(hive_path, hive_name='SYSTEM')
    assert ru.parse_registry_hive_file(str(hive_path), 'SYSTEM') == []


def test_parse_registry_hive_file_unreadable_file_returns_empty_not_raises(tmp_path):
    bad_path = tmp_path / "NTUSER.DAT"
    bad_path.write_bytes(b"not a real hive")
    assert ru.parse_registry_hive_file(str(bad_path), 'NTUSER.DAT') == []


def test_find_registry_hive_files_matches_case_insensitively(tmp_path):
    (tmp_path / "ntuser.dat").write_bytes(b"x")
    (tmp_path / "System").write_bytes(b"x")
    (tmp_path / "unrelated.txt").write_bytes(b"x")
    found, truncated = ru.find_registry_hive_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"ntuser.dat", "System"}
    assert truncated is False


def test_filetime_to_unix_epoch_boundary_is_exact():
    # 1601-01-01 to 1970-01-01 is exactly 11,644,473,600 seconds (a fixed,
    # well-known constant, not derived from any external sample) -
    # FILETIME 116444736000000000 (that many 100ns intervals) must convert
    # to exactly Unix epoch 0, a self-verifying correctness check that
    # doesn't depend on recalling any external reference value.
    assert ru.filetime_to_unix(116_444_736_000_000_000) == 0.0


def test_filetime_to_unix_is_genuinely_different_math_from_webkit_and_firefox_epochs():
    # The same class of bug this codebase has already been bitten by twice
    # (WebKit vs. Firefox epochs) - a copy-paste of either existing
    # conversion here would silently produce timestamps roughly 369 years
    # off (WebKit's own epoch is also 1601, but in microseconds not
    # 100ns units) or off by a completely different, much larger margin
    # (Firefox's epoch is 1970 in microseconds - dividing a raw FILETIME
    # value by 1_000_000 instead of 10_000_000 would be wrong by 10x on
    # top of the epoch difference). Asserted directly, not just trusted.
    from core.browser_artifacts import webkit_time_to_unix, firefox_time_to_unix
    raw_filetime = 128_930_364_000_000_000  # an arbitrary real-shaped FILETIME value
    assert ru.filetime_to_unix(raw_filetime) != webkit_time_to_unix(raw_filetime)
    assert ru.filetime_to_unix(raw_filetime) != firefox_time_to_unix(raw_filetime)


def test_filetime_to_unix_handles_none_and_zero_without_raising():
    assert ru.filetime_to_unix(None) is None
    assert ru.filetime_to_unix(0) is None


def test_find_registry_hive_files_recognizes_amcache(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(b"x")
    found, truncated = ru.find_registry_hive_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"Amcache.hve"}


# --- Amcache (follow-up, 2026-08-25) ---
# A second, standalone hive-fixture builder for AMCACHE.HVE's own
# Root\InventoryApplicationFile shape - a genuinely different key
# structure from _build_test_hive()'s NTUSER.DAT-shaped fixture above, so
# it gets its own small copy of the same low-level REGF primitives rather
# than trying to force one builder to cover two unrelated shapes.
def _build_amcache_hive(path):
    h = _HiveBuilder()

    def make_vk(name, data_str, reg_type=1):
        data_bytes = _utf16(data_str)
        data_off = h.alloc(data_bytes)
        name_b = name.encode('ascii')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(data_bytes))
        vk += struct.pack('<I', data_off) + struct.pack('<I', reg_type)
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_values_list(vk_offsets):
        return h.alloc(b''.join(struct.pack('<I', o) for o in vk_offsets))

    def make_nk(name, subkey_list_off, subkey_count, values_list_off, values_count, is_root=False):
        flags = 0x0020 | (0x0004 if is_root else 0)
        name_b = name.encode('ascii')
        nk = b'nk' + struct.pack('<H', flags) + struct.pack('<Q', _FT_NOW)
        nk += struct.pack('<I', 0) + struct.pack('<I', 0xFFFFFFFF)
        nk += struct.pack('<I', subkey_count if subkey_count else 0xFFFFFFFF) + struct.pack('<I', 0)
        nk += struct.pack('<I', subkey_list_off if subkey_list_off is not None else 0xFFFFFFFF)
        nk += struct.pack('<I', 0xFFFFFFFF)
        nk += struct.pack('<I', values_count if values_count else 0xFFFFFFFF)
        nk += struct.pack('<I', values_list_off if values_list_off is not None else 0xFFFFFFFF)
        nk += struct.pack('<I', 0xFFFFFFFF) + struct.pack('<I', 0xFFFFFFFF)
        nk += b'\x00' * (0x48 - 0x34)
        nk += struct.pack('<H', len(name_b)) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(nk))

    def make_lf(nk_offsets):
        body = b'lf' + struct.pack('<H', len(nk_offsets))
        for off in nk_offsets:
            body += struct.pack('<I', off) + b'\x00\x00\x00\x00'
        return h.alloc(body)

    vl_entry = make_values_list([
        make_vk('Name', 'chrome.exe'),
        make_vk('LowerCaseLongPath', 'c:\\program files\\google\\chrome\\application\\chrome.exe'),
        make_vk('Publisher', 'Google LLC'),
        make_vk('Version', '120.0.6099.129'),
        make_vk('FileId', '0000abcdef1234567890abcdef1234567890abcd'),
    ])
    nk_entry = make_nk('c1c2d55a08356e5c9c6fbf1f92e3b0b90f2b0000', None, 0, vl_entry, 5)
    lf_entries = make_lf([nk_entry])
    nk_invfile = make_nk('InventoryApplicationFile', lf_entries, 1, None, 0)
    lf_root = make_lf([nk_invfile])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)

    h.set_parent(nk_invfile, root_off)
    h.set_parent(nk_entry, nk_invfile)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('Amcache.hve').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_amcache_extracts_application_inventory_entry(tmp_path):
    hive_path = tmp_path / "Amcache.hve"
    _build_amcache_hive(hive_path)
    records = ru.parse_registry_hive_file(str(hive_path), 'AMCACHE.HVE')
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "registry_amcache"
    assert r["title"] == 'c:\\program files\\google\\chrome\\application\\chrome.exe'
    assert r["value"] == '0000abcdef1234567890abcdef1234567890abcd'
    assert r["extra"]["publisher"] == 'Google LLC'
    assert r["extra"]["version"] == '120.0.6099.129'
    assert r["timestamp"] is not None


def test_parse_amcache_dispatches_only_for_amcache_filename(tmp_path):
    # The same fixture, opened under a different (wrong) declared filename,
    # must not be mistaken for NTUSER.DAT/SYSTEM/SOFTWARE - confirms
    # dispatch is genuinely by exact uppercased basename, not "parse
    # whatever key paths happen to exist."
    hive_path = tmp_path / "NTUSER.DAT"
    _build_amcache_hive(hive_path)
    assert ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT') == []
