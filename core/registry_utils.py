"""Windows Registry hive parsing (NTUSER.DAT / SYSTEM / SOFTWARE) - a
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

from Registry import Registry

REGISTRY_HIVE_FILENAMES = {'NTUSER.DAT', 'SYSTEM', 'SOFTWARE'}
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
                return _parse_usb_history(root)
            if upper == 'SOFTWARE':
                return _parse_installed_programs(root)
    except Exception as e:
        print(f"Warning: could not parse registry hive {path} ({filename}): {e}")
    return []
