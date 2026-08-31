"""Windows Registry hive parsing (NTUSER.DAT / SYSTEM / SOFTWARE / AMCACHE.HVE) - a
curated, not exhaustive, set of forensically useful keys, matching this
app's own established "curated allowlist, not exhaustive" philosophy
already used for Volatility3's plugin list and MVT. Mirrors
core/browser_artifacts.py's exact shape ({artifact_type, title, url,
value, timestamp, extra} records) so the shared, already-generic
_record_parsed_artifacts()/parsed_artifacts table and File Views'
"Parsed Artifacts" rendering need zero changes to support a new source.

Verified end-to-end (2026-08-25), not just API-shape-assumed from
documentation: a minimal, spec-valid REGF hive was hand-built directly
from python-registry's own RegistryParse.py source (read on the deployed
station's real venv) and confirmed to parse correctly via Registry(),
root(), subkey()/subkeys()/find_key(), values(), and timestamp() before
this module was written around that confirmed contract.

No filetime_to_unix()-style helper is needed here, unlike
core/browser_artifacts.py's WebKit/Firefox epoch conversions -
RegistryKey.timestamp() and RegistryValue's own datetime handling already
return native, tz-aware Python datetime objects internally (confirmed via
direct source read, not assumed) - _dt_to_epoch() below is a plain
datetime->Unix-seconds conversion, not a FILETIME decoder.
"""
import os
import re
import struct

from Registry import Registry

REGISTRY_HIVE_FILENAMES = {'NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'AMCACHE.HVE', 'USRCLASS.DAT'}
_REGISTRY_HIVE_FILENAMES_UPPER = {n.upper() for n in REGISTRY_HIVE_FILENAMES}

# Same skip-list convention as core/browser_artifacts.py's own whole-folder
# scanner (and reporting.py's _discover_case_files, the case-index
# artifact-tag backfill sweep) - not re-imported from that module since
# each new scanner in this app keeps its own small local copy rather than
# introducing a cross-module dependency for two constants.
_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

REGISTRY_SCAN_MAX_CANDIDATES = 30  # a case folder can hold multiple users' NTUSER.DAT copies
REGISTRY_SCAN_MAX_WALKED = 20_000


def find_registry_hive_files(root_dir):
    """Recursively finds real files whose basename exactly matches a known
    hive filename (case-insensitive - real-world casing varies) anywhere
    under root_dir. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > REGISTRY_SCAN_MAX_WALKED:
                return found, True
            if fname.upper() in _REGISTRY_HIVE_FILENAMES_UPPER:
                found.append(os.path.join(root, fname))
                if len(found) >= REGISTRY_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _dt_to_epoch(dt):
    if dt is None:
        return None
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


# FILETIME (100-nanosecond intervals since 1601-01-01) -> Unix epoch seconds.
# A genuinely third, distinct epoch/unit from this app's two existing
# conversions (WebKit microseconds-since-1601, Firefox PRTime microseconds-
# since-1970 - core/browser_artifacts.py) - not needed anywhere in this
# module itself (python-registry's own RegistryKey.timestamp() already
# hands back a native datetime, see the module docstring above), but Part C's
# two newest artifact families (core/prefetch_utils.py's pyscca
# get_last_run_time_as_integer(), core/recyclebin_utils.py's raw $I-file
# deletion-time field) both read a raw FILETIME int64 directly with no
# library-side datetime conversion, and both need this exact same math - a
# shared helper here rather than two copies, so a future third instance of
# this exact class of bug (already hit twice before, for the WebKit and
# Firefox epochs) stays one tested conversion, not a third copy-paste.
_FILETIME_EPOCH_OFFSET_SECONDS = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01


def filetime_to_unix(raw_filetime):
    if not raw_filetime:
        return None
    try:
        return (raw_filetime / 10_000_000) - _FILETIME_EPOCH_OFFSET_SECONDS
    except (TypeError, ValueError, OverflowError):
        return None


def _decode_mru_binary_filename(raw):
    """Best-effort extraction of the readable filename portion of a
    RecentDocs MRU binary value - the value's first segment is a
    null-terminated UTF-16LE string, followed by shell-item bytes this
    function doesn't attempt to decode further. A widely-used simplified
    approach for this exact key in real forensic tooling, not a full
    shell-item parser - disclosed as an approximation, not full fidelity.

    The terminator must be searched for at 2-byte-aligned offsets only (a
    genuine null UTF-16 CODE UNIT), not via a plain byte-level
    raw.split(b'\\x00\\x00') - a real bug this module's own test suite
    caught before it ever shipped: any ASCII-named file's last character
    already has 0x00 as its own high byte, which combined with the real
    terminator's two bytes right after it forms three consecutive zero
    bytes - a byte-level split matches the FIRST 00 00 pair in that run
    (the character's own high byte + the terminator's first byte),
    silently truncating the filename's last character on every single
    ASCII-named entry."""
    try:
        end = len(raw)
        for i in range(0, len(raw) - 1, 2):
            if raw[i:i + 2] == b'\x00\x00':
                end = i
                break
        return raw[:end].decode('utf-16-le', errors='ignore').strip('\x00').strip()
    except Exception:
        return ''


def _parse_recent_docs(root_key):
    """NTUSER.DAT\\...\\Explorer\\RecentDocs - recently opened document
    names, both directly under the key and under its per-extension
    subkeys (e.g. ".docx", ".pdf"), one level deep only."""
    records = []
    try:
        key = root_key.find_key(r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs')
    except Registry.RegistryKeyNotFoundException:
        return records

    def _values_of(k):
        ts = _dt_to_epoch(k.timestamp())
        for v in k.values():
            if v.name().upper().startswith('MRULIST'):
                continue
            name = _decode_mru_binary_filename(v.raw_data())
            if name:
                records.append({
                    "artifact_type": "registry_recent_docs", "title": name, "url": "",
                    "value": name, "timestamp": ts, "extra": {"key": "RecentDocs"},
                })

    _values_of(key)
    try:
        for sub in key.subkeys():
            _values_of(sub)
    except Registry.RegistryKeyNotFoundException:
        pass
    return records


def _parse_typed_paths(root_key):
    """Explorer address-bar (TypedPaths) and legacy Internet Explorer
    (TypedURLs) history - plain REG_SZ values, no MRU decoding needed."""
    records = []
    for path, label in (
        (r'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths', 'TypedPaths'),
        (r'Software\Microsoft\Internet Explorer\TypedURLs', 'TypedURLs'),
    ):
        try:
            key = root_key.find_key(path)
        except Registry.RegistryKeyNotFoundException:
            continue
        ts = _dt_to_epoch(key.timestamp())
        for v in key.values():
            name_lower = v.name().lower()
            if not (name_lower.startswith('url') or name_lower == 'default'):
                continue
            try:
                val = v.value()
            except Exception:
                continue
            if isinstance(val, str) and val:
                records.append({
                    "artifact_type": "registry_typed_urls", "title": v.name(), "url": val, "value": val,
                    "timestamp": ts, "extra": {"key": label},
                })
    return records


def _parse_run_history(root_key):
    """NTUSER.DAT\\...\\Explorer\\RunMRU - commands typed into the Windows
    Run dialog. Each entry ends with a literal '\\1' MRU order suffix,
    stripped here for readability."""
    records = []
    try:
        key = root_key.find_key(r'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU')
    except Registry.RegistryKeyNotFoundException:
        return records
    ts = _dt_to_epoch(key.timestamp())
    for v in key.values():
        if v.name().upper() == 'MRULIST':
            continue
        try:
            val = v.value()
        except Exception:
            continue
        if not isinstance(val, str) or not val:
            continue
        cmd = val[:-2] if val.endswith('\\1') else val
        records.append({
            "artifact_type": "registry_run_history", "title": cmd, "url": "", "value": cmd,
            "timestamp": ts, "extra": {"key": "RunMRU"},
        })
    return records


def _parse_usb_history(root_key):
    """SYSTEM\\<ControlSet>\\Enum\\USBSTOR - connected USB storage device
    history (device description, serial number). Only the first
    ControlSet actually holding a USBSTOR key is used - real hives
    typically carry near-identical device history under ControlSet001/
    ControlSet002, and using both would just duplicate the same real
    devices twice."""
    records = []
    for cs in ('ControlSet001', 'ControlSet002', 'CurrentControlSet'):
        try:
            usbstor = root_key.find_key(cs + r'\Enum\USBSTOR')
        except Registry.RegistryKeyNotFoundException:
            continue
        for device_class in usbstor.subkeys():
            for instance in device_class.subkeys():
                serial = instance.name()
                friendly = ''
                try:
                    friendly = instance.value('FriendlyName').value()
                except (Registry.RegistryValueNotFoundException, Exception):
                    pass
                title = friendly or device_class.name()
                records.append({
                    "artifact_type": "registry_usb_history", "title": title, "url": "",
                    "value": serial, "timestamp": _dt_to_epoch(instance.timestamp()),
                    "extra": {"device_class": device_class.name(), "serial": serial, "control_set": cs},
                })
        break
    return records


def _parse_installed_programs(root_key):
    """SOFTWARE\\...\\Uninstall (both the native and Wow6432Node 32-bit-on-
    64-bit view) - installed-program name/version/install date."""
    records = []
    for path in (
        r'Microsoft\Windows\CurrentVersion\Uninstall',
        r'Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    ):
        try:
            key = root_key.find_key(path)
        except Registry.RegistryKeyNotFoundException:
            continue
        for sub in key.subkeys():
            try:
                display_name = sub.value('DisplayName').value()
            except (Registry.RegistryValueNotFoundException, Exception):
                continue
            if not display_name:
                continue
            version = ''
            install_date = ''
            try:
                version = sub.value('DisplayVersion').value()
            except (Registry.RegistryValueNotFoundException, Exception):
                pass
            try:
                install_date = sub.value('InstallDate').value()
            except (Registry.RegistryValueNotFoundException, Exception):
                pass
            records.append({
                "artifact_type": "registry_installed_programs", "title": str(display_name),
                "url": "", "value": str(version), "timestamp": _dt_to_epoch(sub.timestamp()),
                "extra": {"install_date": str(install_date) if install_date else ""},
            })
    return records


def _parse_amcache(root_key):
    """AMCACHE.HVE\\Root\\InventoryApplicationFile - Windows 10/11's
    per-executable inventory (name, full path, publisher, version, and a
    FileId that's a SHA1 hash of the file's contents when present) - a
    genuinely valuable execution-evidence artifact distinct from the
    Uninstall-key based _parse_installed_programs() above (Amcache records
    an executable was present/run even for portable/non-installed
    software, which never touches the Uninstall keys at all).

    Same honest-proxy timestamp choice already established by
    _parse_installed_programs(): Amcache doesn't reliably carry a
    dedicated FILETIME value across every Windows build, so the subkey's
    own LastWriteTime (already available for free via RegistryKey.timestamp(),
    same as every other parser in this module) is used instead of chasing
    a value that may not exist."""
    records = []
    try:
        key = root_key.find_key(r'InventoryApplicationFile')
    except Registry.RegistryKeyNotFoundException:
        return records
    ts_fallback = _dt_to_epoch(key.timestamp())
    for sub in key.subkeys():
        values = {}
        for v in sub.values():
            try:
                values[v.name()] = v.value()
            except Exception:
                continue
        path_val = values.get('LowerCaseLongPath') or values.get('Name') or sub.name()
        if not path_val:
            continue
        records.append({
            "artifact_type": "registry_amcache", "title": str(path_val), "url": "",
            "value": str(values.get('FileId', '')),
            "timestamp": _dt_to_epoch(sub.timestamp()) or ts_fallback,
            "extra": {
                "publisher": str(values.get('Publisher', '')),
                "version": str(values.get('Version', '')),
                "size": str(values.get('Size', '')),
            },
        })
    return records


def _extract_shell_item_name(raw):
    """Best-effort extraction of a shell item's readable folder/file name
    from its raw binary encoding (a ShellBags BagMRU subkey's own default
    value) - NOT a full shell-item-type parser (FOLDER_ENTRY/FILE_ENTRY/
    drive-letter/network/control-panel items each have genuinely different
    internal byte layouts, and a complete parser covering all of them is
    real, substantial scope beyond what this pass covers). Instead: scans
    for the first null-terminated ASCII run of 3+ printable characters
    starting a few bytes in (past the item's own 2-byte size + 1-byte type
    flag header, where most common FOLDER/FILE entries place a short ASCII
    name), falling back to a 2-byte-aligned UTF-16LE scan (mirroring
    _decode_mru_binary_filename()'s own already-proven null-terminator
    search) for entries that only carry a long Unicode name. This is a
    widely-used simplified technique real lightweight ShellBags extractors
    already rely on for the common case - disclosed here as an
    approximation, not full shell-item fidelity, same honesty convention
    _decode_mru_binary_filename() already uses for RecentDocs."""
    if not raw or len(raw) < 4:
        return ''
    # ASCII pass: first null-terminated printable run starting at/after
    # offset 3 (past the size+type header most common entry types share).
    ascii_match = re.search(rb'[\x20-\x7e]{3,}\x00', raw[3:])
    if ascii_match:
        candidate = ascii_match.group(0)[:-1].decode('ascii', errors='ignore').strip()
        if candidate:
            return candidate
    # UTF-16LE fallback, 2-byte-aligned null search (same technique
    # _decode_mru_binary_filename() already proved correct).
    for start in range(2, min(len(raw), 8)):
        chunk = raw[start:]
        end = len(chunk)
        for i in range(0, len(chunk) - 1, 2):
            if chunk[i:i + 2] == b'\x00\x00':
                end = i
                break
        candidate = chunk[:end].decode('utf-16-le', errors='ignore').strip()
        if candidate and candidate.isprintable() and len(candidate) >= 3:
            return candidate
    return ''


SHELLBAGS_MAX_ENTRIES = 2_000
SHELLBAGS_MAX_DEPTH = 40


def _walk_shellbags(key, path_stack, records, ts_fallback, depth=0):
    if depth > SHELLBAGS_MAX_DEPTH or len(records) >= SHELLBAGS_MAX_ENTRIES:
        return
    for sub in key.subkeys():
        name = ''
        try:
            for v in sub.values():
                # python-registry reports an unnamed/default value's own
                # name as the literal string '(default)', never '' - a
                # real bug caught by this module's own test suite before
                # shipping (confirmed live: v.name() == '' never matches a
                # genuine default value, silently falling through to the
                # "unreadable" placeholder for every single BagMRU entry).
                if v.name() in ('', '(default)'):  # the unnamed/default value holds the raw shell item
                    name = _extract_shell_item_name(v.raw_data())
                    break
        except Exception:
            pass
        new_stack = path_stack + ([name] if name else [f"(unreadable:{sub.name()})"])
        full_path = '\\'.join(new_stack)
        records.append({
            "artifact_type": "registry_shellbag", "title": full_path, "url": "",
            "value": "", "timestamp": _dt_to_epoch(sub.timestamp()) or ts_fallback,
            "extra": {"bagmru_key": sub.name()},
        })
        _walk_shellbags(sub, new_stack, records, ts_fallback, depth + 1)
        if len(records) >= SHELLBAGS_MAX_ENTRIES:
            return


def _parse_shellbags(root_key):
    """USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\
    BagMRU - proves a folder was browsed via Windows Explorer, including
    folders on removable/network drives or since-deleted folders that leave
    no other trace once the folder itself is gone. BagMRU is a numbered-
    subkey tree (each subkey = one path component, nested subkeys = deeper
    paths) - _walk_shellbags() reconstructs each leaf's full path by
    joining every ancestor's own extracted name, matching how a real
    examiner would read the tree by hand."""
    records = []
    try:
        key = root_key.find_key(r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU')
    except Registry.RegistryKeyNotFoundException:
        return records
    ts_fallback = _dt_to_epoch(key.timestamp())
    _walk_shellbags(key, [], records, ts_fallback)
    return records


# Shimcache/AppCompatCache: SYSTEM\CurrentControlSet\Control\Session
# Manager\AppCompatCache\AppCompatCache, a single REG_BINARY value whose
# internal layout is notoriously version-specific (XP/Vista/7/8/10/11 each
# use a genuinely different binary format - some compressed, some not,
# different magic signatures and entry sizes). This module supports ONLY
# the Windows 10/11 format (magic 0x30 or 0x34, a fixed 12-byte header
# then back-to-back variable-length entries: 4-byte tag 0x00000030 or
# similar version-dependent framing, a 2-byte path length, the UTF-16LE
# path, an 8-byte FILETIME last-modified, then a data-size-prefixed blob)
# - disclosed as a real, deliberate scope limit, not silently assumed to
# cover every Windows version. An older-format hive simply yields zero
# Shimcache records, the same best-effort "no crash, just no records"
# tolerance every parser in this module already applies to a hive it can't
# fully interpret.
_SHIMCACHE_WIN10_SIGNATURE = 0x30
_SHIMCACHE_MAX_ENTRIES = 5_000


def _parse_shimcache(root_key):
    records = []
    try:
        key = root_key.find_key(r'CurrentControlSet\Control\Session Manager\AppCompatCache')
        raw = None
        for v in key.values():
            if v.name() == 'AppCompatCache':
                raw = v.raw_data()
                break
    except Registry.RegistryKeyNotFoundException:
        return records
    if not raw or len(raw) < 12:
        return records
    try:
        signature = struct.unpack_from('<I', raw, 0)[0]
    except struct.error:
        return records
    if signature != _SHIMCACHE_WIN10_SIGNATURE:
        return records  # a different Windows-version format - not supported, disclosed above

    offset = 12  # Win10/11 header: 4-byte signature + 8 bytes reserved/unknown
    while offset + 2 <= len(raw) and len(records) < _SHIMCACHE_MAX_ENTRIES:
        try:
            path_len = struct.unpack_from('<H', raw, offset)[0]
        except struct.error:
            break
        offset += 2
        if path_len <= 0 or offset + path_len > len(raw):
            break
        try:
            path = raw[offset:offset + path_len].decode('utf-16-le', errors='ignore')
        except Exception:
            break
        offset += path_len
        if offset + 8 > len(raw):
            break
        last_modified_raw = struct.unpack_from('<q', raw, offset)[0]
        offset += 8
        if offset + 4 > len(raw):
            break
        data_size = struct.unpack_from('<I', raw, offset)[0]
        offset += 4 + max(0, data_size)
        if not path.strip():
            continue
        records.append({
            "artifact_type": "registry_shimcache", "title": path, "url": "",
            "value": "", "timestamp": filetime_to_unix(last_modified_raw),
            "extra": {},
        })
    return records


def parse_registry_hive_file(path, filename):
    """Dispatches a candidate hive file (matched by exact basename against
    REGISTRY_HIVE_FILENAMES) to the right curated key set, returning a flat
    list of records already shaped {artifact_type, title, url, value,
    timestamp, extra}. Any parse failure (corrupted/not actually a hive
    despite the matching name) is swallowed and returns an empty list -
    same best-effort tolerance every other whole-folder scanner in this
    app already applies."""
    try:
        with open(path, 'rb') as f:
            reg = Registry.Registry(f)
            root = reg.root()
            upper = filename.upper()
            if upper == 'NTUSER.DAT':
                return _parse_recent_docs(root) + _parse_typed_paths(root) + _parse_run_history(root)
            if upper == 'SYSTEM':
                return _parse_usb_history(root) + _parse_shimcache(root)
            if upper == 'SOFTWARE':
                return _parse_installed_programs(root)
            if upper == 'AMCACHE.HVE':
                return _parse_amcache(root)
            if upper == 'USRCLASS.DAT':
                return _parse_shellbags(root)
    except Exception as e:
        print(f"Warning: could not parse registry hive {path} ({filename}): {e}")
    return []
