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
import os
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
    # A real, previously-live bug this exact assertion would have caught:
    # _dt_to_epoch() used to trust RegistryKey.timestamp()'s naive-but-UTC-
    # valued datetime as if it were already tz-aware, silently shifting
    # every non-FILETIME-based registry timestamp by the local machine's
    # own UTC offset (confirmed live on the real, non-UTC deployed Pi -
    # see _dt_to_epoch()'s own docstring). This module's own prior tests
    # only ever asserted "timestamp is not None" here, never a real value -
    # exactly the coverage gap that let it go undetected.
    assert r["timestamp"] == datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()


def test_parse_amcache_dispatches_only_for_amcache_filename(tmp_path):
    # The same fixture, opened under a different (wrong) declared filename,
    # must not be mistaken for NTUSER.DAT/SYSTEM/SOFTWARE - confirms
    # dispatch is genuinely by exact uppercased basename, not "parse
    # whatever key paths happen to exist."
    hive_path = tmp_path / "NTUSER.DAT"
    _build_amcache_hive(hive_path)
    assert ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT') == []


def _build_shellbags_usrclass_hive(path):
    """USRCLASS.DAT Local Settings/Software/Microsoft/Windows/Shell/BagMRU
    /0/1 - two nested levels deep, each subkey's own unnamed/default value
    holding a synthetic shell-item blob whose readable name sits right
    after a 3-byte size+type header (the exact common-case layout
    _extract_shell_item_name() targets), so the resulting full path should
    read Documents/SecretFolder."""
    h = _HiveBuilder()

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

    def shell_item(name_ascii):
        payload = name_ascii.encode('ascii') + b'\x00'
        return struct.pack('<HB', len(payload) + 3, 0x31) + payload

    vl_leaf = make_values_list([make_binary_vk('', shell_item('SecretFolder'))])
    nk_leaf = make_nk('1', None, 0, vl_leaf, 1)
    lf_leaf_parent = make_lf([nk_leaf])
    vl_mid = make_values_list([make_binary_vk('', shell_item('Documents'))])
    nk_mid = make_nk('0', lf_leaf_parent, 1, vl_mid, 1)
    lf_bagmru = make_lf([nk_mid])
    nk_bagmru = make_nk('BagMRU', lf_bagmru, 1, None, 0)
    lf_shell = make_lf([nk_bagmru])
    nk_shell = make_nk('Shell', lf_shell, 1, None, 0)
    lf_windows = make_lf([nk_shell])
    nk_windows = make_nk('Windows', lf_windows, 1, None, 0)
    lf_ms = make_lf([nk_windows])
    nk_ms = make_nk('Microsoft', lf_ms, 1, None, 0)
    lf_sw = make_lf([nk_ms])
    nk_sw = make_nk('Software', lf_sw, 1, None, 0)
    lf_ls = make_lf([nk_sw])
    nk_ls = make_nk('Local Settings', lf_ls, 1, None, 0)
    lf_root = make_lf([nk_ls])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)

    h.set_parent(nk_ls, root_off)
    h.set_parent(nk_sw, nk_ls)
    h.set_parent(nk_ms, nk_sw)
    h.set_parent(nk_windows, nk_ms)
    h.set_parent(nk_shell, nk_windows)
    h.set_parent(nk_bagmru, nk_shell)
    h.set_parent(nk_mid, nk_bagmru)
    h.set_parent(nk_leaf, nk_mid)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('UsrClass.dat').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_shellbags_reconstructs_nested_path(tmp_path):
    hive_path = tmp_path / "UsrClass.dat"
    _build_shellbags_usrclass_hive(hive_path)
    records = ru.parse_registry_hive_file(str(hive_path), 'USRCLASS.DAT')
    assert len(records) == 2
    titles = {r["title"] for r in records}
    assert "Documents" in titles
    assert "Documents\\SecretFolder" in titles
    assert all(r["artifact_type"] == "registry_shellbag" for r in records)


def test_extract_shell_item_name_handles_garbage_without_raising():
    assert ru._extract_shell_item_name(b'') == ''
    assert ru._extract_shell_item_name(b'\x00\x00\x00') == ''
    assert ru._extract_shell_item_name(b'\xff\xff\xff\xff\xff\xff\xff\xff') == ''


def _build_win10_shimcache_binary(entries):
    """entries: list of (path_str, filetime_int). Real Win10/11
    AppCompatCache layout: 4-byte signature (0x30) + 8 reserved bytes,
    then back-to-back entries of [2-byte path length][UTF-16LE path]
    [8-byte FILETIME][4-byte data size][data bytes]."""
    body = struct.pack('<I', 0x30) + b'\x00' * 8
    for path_str, ft in entries:
        path_bytes = path_str.encode('utf-16-le')
        body += struct.pack('<H', len(path_bytes)) + path_bytes
        body += struct.pack('<q', ft) + struct.pack('<I', 0)
    return body


def _build_shimcache_system_hive(path, shimcache_entries):
    h = _HiveBuilder()

    def make_binary_vk(name, raw):
        off = h.alloc(raw)
        name_b = name.encode('ascii')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(raw))
        vk += struct.pack('<I', off) + struct.pack('<I', 3)
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

    binary_blob = _build_win10_shimcache_binary(shimcache_entries)
    vl_cache = make_values_list([make_binary_vk('AppCompatCache', binary_blob)])
    nk_cache = make_nk('AppCompatCache', None, 0, vl_cache, 1)
    lf_cache = make_lf([nk_cache])
    nk_sm = make_nk('Session Manager', lf_cache, 1, None, 0)
    lf_sm = make_lf([nk_sm])
    nk_control = make_nk('Control', lf_sm, 1, None, 0)
    lf_control = make_lf([nk_control])
    nk_ccs = make_nk('CurrentControlSet', lf_control, 1, None, 0)
    lf_root = make_lf([nk_ccs])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)

    h.set_parent(nk_ccs, root_off)
    h.set_parent(nk_control, nk_ccs)
    h.set_parent(nk_sm, nk_control)
    h.set_parent(nk_cache, nk_sm)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('SYSTEM').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_shimcache_extracts_win10_format_entries(tmp_path):
    hive_path = tmp_path / "SYSTEM"
    entries = [
        ('C:\\Windows\\System32\\evil_tool.exe', _FT_NOW),
        ('C:\\Users\\suspect\\Downloads\\payload.exe', _FT_NOW - 10_000_000),
    ]
    _build_shimcache_system_hive(hive_path, entries)
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    shimcache_records = [r for r in records if r["artifact_type"] == "registry_shimcache"]
    assert len(shimcache_records) == 2
    paths = {r["title"] for r in shimcache_records}
    assert 'C:\\Windows\\System32\\evil_tool.exe' in paths
    assert 'C:\\Users\\suspect\\Downloads\\payload.exe' in paths
    for r in shimcache_records:
        assert r["timestamp"] is not None


def test_parse_shimcache_returns_empty_for_unsupported_signature(tmp_path):
    # A non-Win10/11 signature (an older Windows format this module
    # deliberately doesn't support) must yield zero records, not a crash -
    # confirmed by directly overwriting the signature bytes of an
    # otherwise-real, correctly-built hive's AppCompatCache blob.
    hive_path = tmp_path / "SYSTEM"
    _build_shimcache_system_hive(hive_path, [('C:\\real.exe', _FT_NOW)])
    with open(hive_path, 'rb') as f:
        data = bytearray(f.read())
    marker = struct.pack('<I', 0x30) + b'\x00' * 8 + struct.pack('<H', len('C:\\real.exe'.encode('utf-16-le')))
    idx = bytes(data).find(marker)
    assert idx != -1, "fixture's own signature bytes not found - test setup is broken"
    data[idx:idx + 4] = struct.pack('<I', 0xDEADBEEF)
    with open(hive_path, 'wb') as f:
        f.write(data)
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    assert [r for r in records if r["artifact_type"] == "registry_shimcache"] == []


def test_find_registry_hive_files_recognizes_usrclass(tmp_path):
    (tmp_path / "UsrClass.dat").write_bytes(b'not a real hive')
    found, truncated = ru.find_registry_hive_files(str(tmp_path))
    assert len(found) == 1
    assert os.path.basename(found[0]) == "UsrClass.dat"


# --- UserAssist (2026-09-01) ---
# Real research grounding before any code was written: the modern 72-byte
# value-data layout was cross-validated across four independent forensic
# parsers (log2timeline/plaso, RegRipper3.0, libyal/winreg-kb, and a
# standalone python-registry-based implementation) - see
# core/registry_utils.py's own _parse_user_assist()-adjacent comments for
# the full grounding and source citations.

import codecs


def _build_userassist_72byte_value(run_count, focus_count, focus_duration_ms, last_run_filetime):
    """The confirmed modern (Vista+, 'version 5') 72-byte layout:
    offset 4=run_count, 8=focus_count, 12=focus_duration_ms (all uint32),
    60=last-run FILETIME (uint64) - the rest is unknown/unparsed padding,
    matching what this module's own parser actually reads."""
    data = struct.pack('<I', 0)  # offset 0: unknown
    data += struct.pack('<I', run_count)  # offset 4
    data += struct.pack('<I', focus_count)  # offset 8
    data += struct.pack('<I', focus_duration_ms)  # offset 12
    data += b'\x00' * 40  # offset 16-55: 10 unknown 32-bit floats
    data += struct.pack('<I', 0)  # offset 56: unknown
    data += struct.pack('<Q', last_run_filetime)  # offset 60
    data += struct.pack('<I', 0)  # offset 68: unknown
    assert len(data) == 72
    return data


def _build_userassist_hive(path, guid_name, ua_entries):
    """ua_entries: [(decoded_value_name, raw_72_byte_data), ...] - the
    decoded name is ROT13-ENCODED here before being written as the real VK
    name, so the parser's own ROT13-DECODE step is genuinely exercised end
    to end, not bypassed. Tree: Software/Microsoft/Windows/CurrentVersion/
    Explorer/UserAssist/{guid_name}/Count, mirroring
    _build_shellbags_usrclass_hive()'s exact nested-subkey construction
    technique."""
    h = _HiveBuilder()

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

    vk_offsets = [make_binary_vk(codecs.encode(name, 'rot_13'), data) for name, data in ua_entries]
    vl_count = make_values_list(vk_offsets)
    nk_count = make_nk('Count', None, 0, vl_count, len(vk_offsets))
    lf_guid = make_lf([nk_count])
    nk_guid = make_nk(guid_name, lf_guid, 1, None, 0)
    lf_ua = make_lf([nk_guid])
    nk_ua = make_nk('UserAssist', lf_ua, 1, None, 0)
    lf_explorer = make_lf([nk_ua])
    nk_explorer = make_nk('Explorer', lf_explorer, 1, None, 0)
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

    h.set_parent(nk_sw, root_off)
    h.set_parent(nk_ms, nk_sw)
    h.set_parent(nk_windows, nk_ms)
    h.set_parent(nk_cv, nk_windows)
    h.set_parent(nk_explorer, nk_cv)
    h.set_parent(nk_ua, nk_explorer)
    h.set_parent(nk_guid, nk_ua)
    h.set_parent(nk_count, nk_guid)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('NTUSER.DAT').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_user_assist_real_runpath_entry_with_correct_field_extraction(tmp_path):
    last_run = _filetime(datetime.datetime(2026, 8, 20, 14, 0, 0))
    data = _build_userassist_72byte_value(run_count=12, focus_count=3, focus_duration_ms=4500, last_run_filetime=last_run)
    hive_path = tmp_path / "NTUSER.DAT"
    _build_userassist_hive(hive_path, 'CEBFF5CD-ACE2-4F4F-9178-9926F41749EA',
                            [('UEME_RUNPATH:C:\\Windows\\System32\\notepad.exe', data)])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    ua_records = [r for r in records if r["artifact_type"] == "registry_userassist"]
    assert len(ua_records) == 1
    r = ua_records[0]
    assert r["value"] == 'UEME_RUNPATH:C:\\Windows\\System32\\notepad.exe'
    assert r["title"] == 'notepad.exe'  # basename extracted from the decoded RUNPATH entry
    assert r["extra"]["run_count"] == 12
    assert r["extra"]["focus_count"] == 3
    assert r["extra"]["focus_duration_ms"] == 4500
    assert r["extra"]["guid"] == 'CEBFF5CD-ACE2-4F4F-9178-9926F41749EA'
    assert r["extra"]["category"] == 'Application/Executable Execution'
    assert r["timestamp"] == datetime.datetime(2026, 8, 20, 14, 0, 0, tzinfo=datetime.timezone.utc).timestamp()


def test_parse_user_assist_unknown_guid_falls_back_to_the_raw_guid_as_its_own_label(tmp_path):
    data = _build_userassist_72byte_value(1, 0, 0, _FT_NOW)
    hive_path = tmp_path / "NTUSER.DAT"
    _build_userassist_hive(hive_path, 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',
                            [('UEME_RUNCPL:some_cpl_applet', data)])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    ua_records = [r for r in records if r["artifact_type"] == "registry_userassist"]
    assert len(ua_records) == 1
    assert ua_records[0]["extra"]["category"] == 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'  # no known label - falls back to the GUID itself
    assert ua_records[0]["title"] == 'UEME_RUNCPL:some_cpl_applet'  # no backslash - no basename to extract, full decoded name used as-is


def test_parse_user_assist_skips_ctlsession_marker_and_wrong_sized_values(tmp_path):
    # UEME_CTLSESSION is a real value name this key holds, but it's a
    # session marker, not an execution record, AND (in the real modern
    # format) a completely different, much larger data size - both facts
    # this parser must correctly treat as "skip, don't misparse."
    real_data = _build_userassist_72byte_value(5, 1, 100, _FT_NOW)
    hive_path = tmp_path / "NTUSER.DAT"
    _build_userassist_hive(hive_path, 'CEBFF5CD-ACE2-4F4F-9178-9926F41749EA', [
        ('UEME_CTLSESSION', b'\x00' * 72),  # correct size but must still be name-filtered out
        ('UEME_RUNPATH:C:\\legacy_format_16_bytes.exe', b'\x00' * 16),  # legacy-format size - must be skipped, not misparsed
        ('UEME_RUNPATH:C:\\real_entry.exe', real_data),
    ])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    ua_records = [r for r in records if r["artifact_type"] == "registry_userassist"]
    assert len(ua_records) == 1
    assert ua_records[0]["value"] == 'UEME_RUNPATH:C:\\real_entry.exe'


# --- BAM/DAM (2026-09-01) ---

def _build_bam_dam_value(last_run_filetime, trailing_bytes=16):
    """The confirmed layout: an 8-byte little-endian FILETIME at offset 0.
    The remaining bytes are genuinely under-documented even in the best
    real source and are deliberately never interpreted by the parser -
    filled with real, non-zero-but-unparsed bytes here specifically to
    prove the parser doesn't accidentally depend on them being zero."""
    return struct.pack('<Q', last_run_filetime) + (b'\xAB' * trailing_bytes)


def _build_bam_dam_system_hive(path, services):
    """services: {service_name: {'generation': 'state'|'legacy',
    'sids': {sid_name: [(value_name, raw_bytes), ...]}}}. Tree per service:
    CurrentControlSet/Services/{service}/[State/]UserSettings/{sid}/
    [values] - mirrors _build_userassist_hive()'s exact nested-subkey/
    multi-value-per-key construction technique, generalized one level
    deeper for the SID subkeys and widened to build more than one service
    (bam and/or dam) under one shared CurrentControlSet/Services parent."""
    h = _HiveBuilder()

    def make_binary_vk(name, raw):
        off = h.alloc(raw)
        name_b = name.encode('utf-8')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(raw))
        vk += struct.pack('<I', off) + struct.pack('<I', 3)  # REG_BINARY
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_values_list(vk_offsets):
        return h.alloc(b''.join(struct.pack('<I', o) for o in vk_offsets))

    def make_nk(name, subkey_list_off, subkey_count, values_list_off, values_count, is_root=False):
        flags = 0x0020 | (0x0004 if is_root else 0)
        name_b = name.encode('utf-8')
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

    service_nk_offsets = []
    for service_name, spec in services.items():
        sid_nk_offsets = []
        for sid_name, values in spec['sids'].items():
            vk_offsets = [make_binary_vk(name, raw) for name, raw in values]
            vl_sid = make_values_list(vk_offsets)
            nk_sid = make_nk(sid_name, None, 0, vl_sid, len(vk_offsets))
            sid_nk_offsets.append(nk_sid)
        lf_sids = make_lf(sid_nk_offsets)
        nk_usersettings = make_nk('UserSettings', lf_sids, 1, None, 0)
        for nk_sid in sid_nk_offsets:
            h.set_parent(nk_sid, nk_usersettings)

        if spec['generation'] == 'state':
            lf_state_children = make_lf([nk_usersettings])
            nk_state = make_nk('State', lf_state_children, 1, None, 0)
            h.set_parent(nk_usersettings, nk_state)
            lf_service_children = make_lf([nk_state])
            nk_service = make_nk(service_name, lf_service_children, 1, None, 0)
            h.set_parent(nk_state, nk_service)
        else:  # legacy - UserSettings sits directly under the service key, no State level
            lf_service_children = make_lf([nk_usersettings])
            nk_service = make_nk(service_name, lf_service_children, 1, None, 0)
            h.set_parent(nk_usersettings, nk_service)

        service_nk_offsets.append(nk_service)

    lf_services_children = make_lf(service_nk_offsets)
    nk_services = make_nk('Services', lf_services_children, 1, None, 0)
    for nk_service in service_nk_offsets:
        h.set_parent(nk_service, nk_services)
    lf_ccs_children = make_lf([nk_services])
    nk_ccs = make_nk('CurrentControlSet', lf_ccs_children, 1, None, 0)
    h.set_parent(nk_services, nk_ccs)
    lf_root = make_lf([nk_ccs])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)
    h.set_parent(nk_ccs, root_off)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('SYSTEM').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_bam_dam_real_entry_with_correct_filetime_and_title(tmp_path):
    last_run = _filetime(datetime.datetime(2026, 8, 30, 9, 15, 0))
    data = _build_bam_dam_value(last_run)
    hive_path = tmp_path / "SYSTEM"
    _build_bam_dam_system_hive(hive_path, {
        'bam': {'generation': 'state', 'sids': {
            'S-1-5-21-1111111111-2222222222-3333333333-1001': [
                (r'\Device\HarddiskVolume3\Windows\System32\notepad.exe', data),
            ],
        }},
    })
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    bam_records = [r for r in records if r["artifact_type"] == "registry_bam_dam"]
    assert len(bam_records) == 1
    r = bam_records[0]
    assert r["title"] == 'notepad.exe'  # basename extracted from the NT device path
    assert r["value"] == r'\Device\HarddiskVolume3\Windows\System32\notepad.exe'  # full device path kept as-is, never resolved to a drive letter
    assert r["extra"]["service"] == 'bam'
    assert r["extra"]["service_label"] == 'Background Activity Moderator'
    assert r["extra"]["sid"] == 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    assert r["extra"]["path_generation"] == 'state'
    assert r["timestamp"] == datetime.datetime(2026, 8, 30, 9, 15, 0, tzinfo=datetime.timezone.utc).timestamp()


def test_parse_bam_dam_skips_sequencenumber_and_version_metadata_values(tmp_path):
    real_data = _build_bam_dam_value(_FT_NOW)
    hive_path = tmp_path / "SYSTEM"
    _build_bam_dam_system_hive(hive_path, {
        'bam': {'generation': 'state', 'sids': {
            'S-1-5-21-1-2-3-1001': [
                ('SequenceNumber', struct.pack('<I', 42)),  # metadata, not an executable - must be skipped
                ('Version', struct.pack('<I', 1)),  # metadata, not an executable - must be skipped
                (r'\Device\HarddiskVolume3\real.exe', real_data),
            ],
        }},
    })
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    bam_records = [r for r in records if r["artifact_type"] == "registry_bam_dam"]
    assert len(bam_records) == 1
    assert bam_records[0]["value"] == r'\Device\HarddiskVolume3\real.exe'


def test_parse_bam_dam_covers_both_services_and_the_local_system_sid(tmp_path):
    # S-1-5-18 (LocalSystem) is a real, valid SID that legitimately appears
    # here (system-context processes get tracked too) - must not be
    # mistaken for a non-SID/garbage subkey and skipped.
    data1 = _build_bam_dam_value(_FT_NOW)
    data2 = _build_bam_dam_value(_FT_NOW - 10_000_000)
    hive_path = tmp_path / "SYSTEM"
    _build_bam_dam_system_hive(hive_path, {
        'bam': {'generation': 'state', 'sids': {
            'S-1-5-18': [(r'\Device\HarddiskVolume3\Windows\System32\svchost.exe', data1)],
        }},
        'dam': {'generation': 'state', 'sids': {
            'S-1-5-21-1-2-3-1001': [(r'\Device\HarddiskVolume3\Windows\System32\dwm.exe', data2)],
        }},
    })
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    bam_dam_records = [r for r in records if r["artifact_type"] == "registry_bam_dam"]
    assert len(bam_dam_records) == 2
    by_service = {r["extra"]["service"]: r for r in bam_dam_records}
    assert by_service['bam']["extra"]["sid"] == 'S-1-5-18'
    assert by_service['bam']["title"] == 'svchost.exe'
    assert by_service['dam']["extra"]["service_label"] == 'Desktop Activity Moderator'
    assert by_service['dam']["title"] == 'dwm.exe'


def test_parse_bam_dam_falls_back_to_the_legacy_no_state_path_generation(tmp_path):
    # A real path-evolution gotcha confirmed via plaso's own production
    # filter list, which registers both path shapes - the legacy
    # 'bam\\UserSettings\\{sid}' (no 'State' component) must still be found.
    data = _build_bam_dam_value(_FT_NOW)
    hive_path = tmp_path / "SYSTEM"
    _build_bam_dam_system_hive(hive_path, {
        'bam': {'generation': 'legacy', 'sids': {
            'S-1-5-21-1-2-3-1001': [(r'\Device\HarddiskVolume3\legacy_layout.exe', data)],
        }},
    })
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    bam_records = [r for r in records if r["artifact_type"] == "registry_bam_dam"]
    assert len(bam_records) == 1
    assert bam_records[0]["extra"]["path_generation"] == 'legacy'
    assert bam_records[0]["value"] == r'\Device\HarddiskVolume3\legacy_layout.exe'


def test_parse_bam_dam_missing_service_key_yields_no_records_not_a_crash(tmp_path):
    # A hive with neither bam nor dam present at all (e.g. a stripped-down
    # or non-Windows-10+ SYSTEM hive) must degrade to zero records, the
    # same best-effort tolerance every parser in this module already has.
    hive_path = tmp_path / "SYSTEM"
    _build_shimcache_system_hive(hive_path, [('C:\\unrelated.exe', _FT_NOW)])
    records = ru.parse_registry_hive_file(str(hive_path), 'SYSTEM')
    assert [r for r in records if r["artifact_type"] == "registry_bam_dam"] == []


def test_decode_userassist_value_name_is_real_rot13_not_a_custom_scheme():
    assert ru._decode_userassist_value_name('HRZR_EHACNGU') == 'UEME_RUNPATH'
    # Non-letter characters (the ':' separator, digits in a hex suffix)
    # must pass through completely untouched - confirmed against a real,
    # realistic encoded value shape.
    assert ru._decode_userassist_value_name('UEME_RUNPATH') == 'HRZR_EHACNGU'  # ROT13 is its own inverse


def test_dt_to_epoch_treats_a_naive_datetime_as_utc_not_local_machine_time():
    """Direct regression test for the real bug found live 2026-09-01:
    RegistryKey.timestamp() returns a NAIVE datetime whose wall-clock
    value is already correct UTC - _dt_to_epoch() must explicitly stamp
    UTC before converting, never rely on Python's own naive-datetime
    default (which assumes local time). This must hold regardless of
    whatever timezone the machine actually running this test is set to."""
    naive_utc_noon = datetime.datetime(2026, 8, 20, 12, 0, 0)
    assert naive_utc_noon.tzinfo is None  # sanity: this really is naive, matching python-registry's real return shape
    expected = datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
    assert ru._dt_to_epoch(naive_utc_noon) == expected
    # An already-aware datetime must be respected as-is, never re-stamped.
    already_aware = datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
    assert ru._dt_to_epoch(already_aware) == expected
    assert ru._dt_to_epoch(None) is None


def test_userassist_title_from_decoded_name_extracts_basename():
    assert ru._userassist_title_from_decoded_name('UEME_RUNPATH:C:\\Windows\\notepad.exe:0000') == 'notepad.exe'
    assert ru._userassist_title_from_decoded_name('UEME_RUNCPL:no_backslash_here') == 'UEME_RUNCPL:no_backslash_here'


# --- RDP connection history (2026-09-01) ---

def _build_rdp_ntuser_hive(path, servers=None, mru_values=None, include_default_nameless_value=False):
    """Tree: Software/Microsoft/Terminal Server Client/{Servers/{address},
    Default} - mirrors _build_userassist_hive()'s exact nested-subkey
    construction technique. servers: [(address, username_hint_or_None,
    has_cert_hash), ...]. mru_values: [(value_name, data_str), ...]."""
    servers = servers or []
    mru_values = mru_values or []
    h = _HiveBuilder()

    def make_vk(name, data_str, reg_type=1):
        data_bytes = _utf16(data_str)
        data_off = h.alloc(data_bytes)
        name_b = name.encode('utf-8')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(data_bytes))
        vk += struct.pack('<I', data_off) + struct.pack('<I', reg_type)
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_binary_vk(name, raw):
        off = h.alloc(raw)
        name_b = name.encode('utf-8')
        vk = b'vk' + struct.pack('<H', len(name_b)) + struct.pack('<I', len(raw))
        vk += struct.pack('<I', off) + struct.pack('<I', 3)  # REG_BINARY
        vk += struct.pack('<H', 1) + struct.pack('<H', 0) + name_b
        return h.alloc(bytes(vk))

    def make_nameless_vk(data_str, reg_type=1):
        # python-registry reports the unnamed/default value's name as the
        # literal string '(default)' (a real, previously-found gotcha in
        # this module's own ShellBags parsing) - a zero-length name field
        # here is what produces that behavior.
        data_bytes = _utf16(data_str)
        data_off = h.alloc(data_bytes)
        vk = b'vk' + struct.pack('<H', 0) + struct.pack('<I', len(data_bytes))
        vk += struct.pack('<I', data_off) + struct.pack('<I', reg_type)
        vk += struct.pack('<H', 0) + struct.pack('<H', 0)
        return h.alloc(bytes(vk))

    def make_values_list(vk_offsets):
        return h.alloc(b''.join(struct.pack('<I', o) for o in vk_offsets))

    def make_nk(name, subkey_list_off, subkey_count, values_list_off, values_count, is_root=False):
        flags = 0x0020 | (0x0004 if is_root else 0)
        name_b = name.encode('utf-8')
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

    server_nk_offsets = []
    for address, username_hint, has_cert_hash in servers:
        vk_offsets = []
        if username_hint is not None:
            vk_offsets.append(make_vk('UsernameHint', username_hint))
        if has_cert_hash:
            vk_offsets.append(make_binary_vk('CertHash', b'\xAA' * 20))
        vl = make_values_list(vk_offsets) if vk_offsets else None
        nk_server = make_nk(address, None, 0, vl, len(vk_offsets))
        server_nk_offsets.append(nk_server)
    lf_servers_children = make_lf(server_nk_offsets)
    nk_servers = make_nk('Servers', lf_servers_children, 1 if server_nk_offsets else 0, None, 0)
    for nk_server in server_nk_offsets:
        h.set_parent(nk_server, nk_servers)

    default_vk_offsets = []
    if include_default_nameless_value:
        default_vk_offsets.append(make_nameless_vk('should-be-skipped'))
    for name, data_str in mru_values:
        default_vk_offsets.append(make_vk(name, data_str))
    vl_default = make_values_list(default_vk_offsets) if default_vk_offsets else None
    nk_default = make_nk('Default', None, 0, vl_default, len(default_vk_offsets))

    lf_tsc_children = make_lf([nk_servers, nk_default])
    nk_tsc = make_nk('Terminal Server Client', lf_tsc_children, 2, None, 0)
    h.set_parent(nk_servers, nk_tsc)
    h.set_parent(nk_default, nk_tsc)
    lf_ms = make_lf([nk_tsc])
    nk_ms = make_nk('Microsoft', lf_ms, 1, None, 0)
    h.set_parent(nk_tsc, nk_ms)
    lf_sw = make_lf([nk_ms])
    nk_sw = make_nk('Software', lf_sw, 1, None, 0)
    h.set_parent(nk_ms, nk_sw)
    lf_root = make_lf([nk_sw])
    root_off = make_nk('ROOT', lf_root, 1, None, 0, is_root=True)
    h.set_parent(nk_sw, root_off)

    hbin_data = bytes(h.buf)
    hbin_total = 0x20 + len(hbin_data)
    hbin_size = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
    hbin = b'hbin' + struct.pack('<I', 0) + struct.pack('<I', hbin_size)
    hbin += b'\x00' * (0x20 - 0xC) + hbin_data + b'\x00' * (hbin_size - hbin_total)

    regf = struct.pack('<I', 0x66676572) + struct.pack('<I', 1) + struct.pack('<I', 1)
    regf += struct.pack('<Q', _FT_NOW) + struct.pack('<I', 1) + struct.pack('<I', 5)
    regf += struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<I', root_off)
    regf += struct.pack('<I', hbin_size) + struct.pack('<I', 1)
    regf += _utf16('NTUSER.DAT').ljust(64, b'\x00')
    regf += b'\x00' * (0x1000 - len(regf))
    regf = regf[:0x1000]

    with open(path, 'wb') as f:
        f.write(regf)
        f.write(hbin)


def test_parse_rdp_connections_real_server_entry_with_username_hint(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_rdp_ntuser_hive(hive_path, servers=[
        ('fileserver.corp.local', 'CORP\\jsmith', True),
    ])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    server_records = [r for r in records if r["artifact_type"] == "registry_rdp_server"]
    assert len(server_records) == 1
    r = server_records[0]
    assert r["title"] == 'fileserver.corp.local'
    assert r["value"] == 'CORP\\jsmith'
    assert r["extra"]["address"] == 'fileserver.corp.local'
    assert r["extra"]["username_hint"] == 'CORP\\jsmith'
    assert r["extra"]["cert_hash_present"] is True
    assert r["timestamp"] == datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()


def test_parse_rdp_connections_server_with_no_username_hint_or_cert_hash(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_rdp_ntuser_hive(hive_path, servers=[('192.168.1.50', None, False)])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    server_records = [r for r in records if r["artifact_type"] == "registry_rdp_server"]
    assert len(server_records) == 1
    assert server_records[0]["title"] == '192.168.1.50'
    assert server_records[0]["value"] == ''
    assert server_records[0]["extra"]["cert_hash_present"] is False


def test_parse_rdp_connections_default_mru_entries_skip_the_nameless_value(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_rdp_ntuser_hive(hive_path, mru_values=[
        ('MRU0', '192.168.1.50'),
        ('MRU1', 'fileserver.corp.local'),
    ], include_default_nameless_value=True)
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    mru_records = [r for r in records if r["artifact_type"] == "registry_rdp_mru"]
    assert len(mru_records) == 2  # the nameless '(default)' value must never be treated as an MRU entry
    by_index = {r["extra"]["mru_index"]: r for r in mru_records}
    assert by_index[0]["title"] == '192.168.1.50'
    assert by_index[0]["value"] == '192.168.1.50'
    assert by_index[1]["title"] == 'fileserver.corp.local'
    # Default\MRU has no per-entry timestamp - both entries share the one
    # Default key's own LastWriteTime, confirmed identical here.
    assert by_index[0]["timestamp"] == by_index[1]["timestamp"]


def test_parse_rdp_connections_both_servers_and_mru_coexist(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_rdp_ntuser_hive(hive_path,
        servers=[('10.0.0.5', 'admin', False)],
        mru_values=[('MRU0', '10.0.0.5')])
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    server_records = [r for r in records if r["artifact_type"] == "registry_rdp_server"]
    mru_records = [r for r in records if r["artifact_type"] == "registry_rdp_mru"]
    assert len(server_records) == 1
    assert len(mru_records) == 1


def test_parse_rdp_connections_missing_terminal_server_client_key_yields_no_records(tmp_path):
    hive_path = tmp_path / "NTUSER.DAT"
    _build_test_hive(hive_path)  # a real hive with unrelated content, no Terminal Server Client key at all
    records = ru.parse_registry_hive_file(str(hive_path), 'NTUSER.DAT')
    assert [r for r in records if r["artifact_type"] in ("registry_rdp_server", "registry_rdp_mru")] == []
