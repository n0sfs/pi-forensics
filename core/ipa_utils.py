"""iOS .ipa static analysis - Info.plist metadata, the embedded mobile
provisioning profile, and (optional, best-effort) Mach-O binary analysis
via LIEF.

An .ipa is a plain zip: `Payload/<AppName>.app/Info.plist` (a real
plist, parsed via the stdlib `plistlib` - zero new dependency) and, for
an app that was ever built/signed for a real device,
`Payload/<AppName>.app/embedded.mobileprovision` - a CMS/PKCS#7-signed
blob whose payload IS a plain plist, extracted here via a byte-offset
`<?xml ... <plist ...>...</plist>` boundary read rather than an actual
CMS parse (this app makes no attempt to verify the signature - the same
scope every other non-crypto-focused parser in this codebase already
has, e.g. python-registry/python-evtx never validate their source
filesystem's own integrity either, they just read structured data).

The optional Mach-O layer (`import lief` inside a try/except - confirmed
live installable via a real prebuilt manylinux_2_28_aarch64 wheel on
this station's ARM64 venv, no compile step, resolving the plan's own
explicit uncertainty about wheel availability) parses the app's own
executable (named by Info.plist's own CFBundleExecutable key, found
inside the same .app bundle) for its architecture slice(s) and each
slice's LC_ENCRYPTION_INFO cryptid flag (0 = decrypted-at-rest / never
FairPlay-encrypted, 1 = still FairPlay-encrypted and therefore this
tool's own static disassembly of the binary's actual code is not
meaningful - App Store IPAs are virtually always cryptid=1 unless
already decrypted by a jailbroken-device dump tool upstream of this
app, e.g. frida-ios-dump; a sideloaded/enterprise/dev-signed IPA is
typically cryptid=0). A failure at this layer (LIEF not installed, or a
file LIEF can't parse) never fails the whole analysis - the plist-layer
result is always returned regardless, with macho=None and macho_error
set to explain why.
"""
import io
import os
import plistlib
import re
import zipfile

_MOBILEPROVISION_RE = re.compile(rb'<\?xml.*?</plist>', re.DOTALL)

_USAGE_DESCRIPTION_RE = re.compile(r'UsageDescription$')


def _find_app_bundle(zf):
    """Returns the zip-internal path of the first Payload/*.app/ entry
    found, or None. An .ipa always has exactly one top-level .app under
    Payload/ per Apple's own packaging spec - this doesn't try to
    disambiguate a malformed archive with more than one, it just takes
    the first."""
    for name in zf.namelist():
        m = re.match(r'^Payload/([^/]+\.app)/$', name)
        if m:
            return f"Payload/{m.group(1)}"
        m = re.match(r'^Payload/([^/]+\.app)/', name)
        if m:
            return f"Payload/{m.group(1)}"
    return None


def _parse_info_plist(zf, app_dir):
    plist_path = f"{app_dir}/Info.plist"
    try:
        with zf.open(plist_path) as f:
            data = plistlib.load(f)
    except (KeyError, plistlib.InvalidFileException, Exception):
        return None

    usage_descriptions = {k: v for k, v in data.items()
                           if isinstance(k, str) and _USAGE_DESCRIPTION_RE.search(k)}

    return {
        "bundle_id": data.get("CFBundleIdentifier"),
        "app_name": data.get("CFBundleDisplayName") or data.get("CFBundleName"),
        "version": data.get("CFBundleShortVersionString"),
        "build": data.get("CFBundleVersion"),
        "min_os_version": data.get("MinimumOSVersion"),
        "executable_name": data.get("CFBundleExecutable"),
        "usage_descriptions": usage_descriptions,
    }


def _parse_mobileprovision(zf, app_dir):
    mp_path = f"{app_dir}/embedded.mobileprovision"
    try:
        with zf.open(mp_path) as f:
            raw = f.read()
    except KeyError:
        return None  # no embedded profile - not signed for a real device (e.g. simulator build)

    m = _MOBILEPROVISION_RE.search(raw)
    if not m:
        return {"error": "embedded.mobileprovision present but its XML plist payload could not be located."}

    try:
        data = plistlib.loads(m.group(0))
    except Exception as e:
        return {"error": f"embedded.mobileprovision's plist payload could not be parsed: {e}"}

    entitlements = data.get("Entitlements") or {}
    return {
        "app_id_name": data.get("AppIDName"),
        "team_name": data.get("TeamName"),
        "team_identifiers": data.get("TeamIdentifier"),
        "creation_date": str(data.get("CreationDate")) if data.get("CreationDate") else None,
        "expiration_date": str(data.get("ExpirationDate")) if data.get("ExpirationDate") else None,
        "provisioned_devices": data.get("ProvisionedDevices") or [],
        "entitlements": entitlements,
    }


def _parse_macho(zf, app_dir, executable_name):
    """Best-effort - never raises. Returns (macho_dict_or_None, error_or_None)."""
    if not executable_name:
        return None, "Info.plist has no CFBundleExecutable - cannot locate the app's own binary."

    try:
        import lief
    except ImportError:
        return None, "LIEF is not installed on this station. Check Settings > Service Controls & Diagnostics > Tool Versions."

    exe_path = f"{app_dir}/{executable_name}"
    try:
        raw = zf.read(exe_path)
    except KeyError:
        return None, f"Executable '{executable_name}' (from CFBundleExecutable) not found in the archive at the expected path."

    try:
        fat = lief.MachO.parse(list(raw))
    except Exception as e:
        return None, f"LIEF could not parse this file as Mach-O: {e}"

    if fat is None or fat.size == 0:
        return None, "LIEF could not parse this file as Mach-O (not a recognized Mach-O binary)."

    slices = []
    # Real, live-confirmed correction (found by this module's own first-
    # ever test suite, 2026-09-02): `FatBinary` has no `it_binaries`
    # attribute worth iterating - that name resolves to an internal
    # nanobind type-binding object, not a real iterator, and would raise
    # TypeError the moment this function ever actually ran against a real
    # .ipa. The object is directly iterable instead (confirmed live
    # against the real installed lief 1.0.0: `list(fat)` yields the real
    # per-architecture Binary objects). Also confirmed live: LIEF doesn't
    # reliably raise/return None/report size==0 for genuinely unparseable
    # input with a plausible-looking Mach-O magic prefix - it can instead
    # hand back one all-zero/garbage placeholder Binary (real confirmed
    # symptom: `header.magic == 0`, a real Mach-O's magic is always
    # nonzero) - filtered out here rather than reported as a real slice.
    for binary in fat:
        try:
            if getattr(binary.header, 'magic', None) in (None, 0):
                continue  # a garbage/failed-parse placeholder, not a real architecture slice
        except Exception:
            continue
        try:
            cpu_type = str(binary.header.cpu_type).rsplit('.', 1)[-1]
        except Exception:
            cpu_type = "Unknown"
        slice_info = {"architecture": cpu_type, "is_64bit": bool(binary.header.is_64bit),
                      "cryptid": None, "encrypted": None}
        try:
            if binary.has_encryption_info:
                cryptid = binary.encryption_info.crypt_id
                slice_info["cryptid"] = cryptid
                slice_info["encrypted"] = (cryptid != 0)
        except Exception:
            pass
        slices.append(slice_info)

    if not slices:
        return None, "LIEF could not parse this file as Mach-O (not a recognized Mach-O binary)."

    return {"executable": executable_name, "slices": slices}, None


def analyze_ipa(path, run_macho=True):
    """Returns {"success": bool, "error": str|None, "info_plist": dict|None,
    "mobileprovision": dict|None, "macho": dict|None, "macho_error": str|None}.
    Best-effort throughout a malformed .ipa returns success=False with
    error set, never raises."""
    try:
        zf = zipfile.ZipFile(path, 'r')
    except (zipfile.BadZipFile, OSError) as e:
        return {"success": False, "error": f"Could not open this file as a valid .ipa (zip archive): {e}",
                "info_plist": None, "mobileprovision": None, "macho": None, "macho_error": None}

    try:
        app_dir = _find_app_bundle(zf)
        if not app_dir:
            return {"success": False, "error": "No Payload/*.app/ bundle found - this does not look like a valid .ipa.",
                    "info_plist": None, "mobileprovision": None, "macho": None, "macho_error": None}

        info_plist = _parse_info_plist(zf, app_dir)
        if info_plist is None:
            return {"success": False, "error": f"Found the app bundle ({app_dir}) but its Info.plist could not be parsed.",
                    "info_plist": None, "mobileprovision": None, "macho": None, "macho_error": None}

        mobileprovision = _parse_mobileprovision(zf, app_dir)

        macho = None
        macho_error = None
        if run_macho:
            macho, macho_error = _parse_macho(zf, app_dir, info_plist.get("executable_name"))

        return {"success": True, "error": None, "info_plist": info_plist,
                "mobileprovision": mobileprovision, "macho": macho, "macho_error": macho_error}
    finally:
        zf.close()
