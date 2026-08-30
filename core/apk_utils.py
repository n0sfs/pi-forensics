"""Android APK static analysis via androguard's APK class - permissions,
manifest components (activities/services/receivers/providers), signing
certificate info, and a lightweight embedded-string/URL scan.

Import-based, not subprocess-wrapped (unlike core/sqlite_dissect_utils.py) -
androguard.core.apk.APK is a long-stable, documented public class, and
every method name this module calls was individually confirmed live
against the real installed package (4.1.4) on this station's own ARM64
venv, run against a real, legitimately-signed open-source APK (F-Droid's
own client) before writing this module - not assumed from documentation.

One real, load-bearing correction found during that live testing: a
signing certificate object is `asn1crypto.x509.Certificate`, not
`cryptography.x509.Certificate` as might be assumed from more common
Python X.509 usage elsewhere in this app (core/config.py's TLS handling
uses `cryptography` directly) - `.subject`/`.issuer` need `.human_friendly`
to get a readable string (the bare attribute is a structured Name object,
not directly useful here); `.serial_number`, `.sha256_fingerprint`,
`.not_valid_before`, `.not_valid_after` all work as plain attribute access,
confirmed live with real values from a real certificate.

androguard uses loguru for its own internal logging, which defaults to a
very chatty DEBUG-level stderr sink (confirmed live: hundreds of "Out of
range dimension unit index" warnings from routine resource-table parsing
on a real, valid APK) - silenced here at import time so a single APK
analysis doesn't flood this app's own log output.
"""
import re

try:
    from loguru import logger as _androguard_logger
    _androguard_logger.remove()  # drop loguru's default stderr sink entirely - androguard's own DEBUG/INFO noise is not useful to this app's log output
except ImportError:
    pass

_URL_RE = re.compile(rb'https?://[^\s"\'<>]{4,255}')
_STRING_SCAN_MAX_URLS = 200
_STRING_SCAN_MAX_BYTES = 20 * 1024 * 1024  # cap: a raw byte scan of the whole APK zip, not a per-DEX-string extraction


def analyze_apk(path):
    """Returns {"success": bool, "error": str|None, "package": {...}|None}.
    package holds: package_name, app_name, version_name, version_code,
    min_sdk, target_sdk, permissions (list[str]), activities/services/
    receivers/providers (list[str]), signing (list of cert dicts: subject,
    issuer, serial_number, sha256, valid_from, valid_to - one per signer,
    an APK can be multiply signed), urls_found (list[str], capped, from a
    raw byte-level scan of the whole APK - a Quick-Triage-Scan-style
    surface scan, not a full DEX disassembly/string-table extraction).
    Best-effort throughout - a malformed/corrupted APK returns a dict with
    'error' set rather than raising."""
    try:
        from androguard.core.apk import APK
    except ImportError:
        return {"success": False, "error": "androguard is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions.", "package": None}

    try:
        apk = APK(path)
    except Exception as e:
        return {"success": False, "error": f"Could not parse this file as a valid APK: {e}", "package": None}

    try:
        signing = []
        for cert in (apk.get_certificates() or []):
            try:
                signing.append({
                    "subject": cert.subject.human_friendly,
                    "issuer": cert.issuer.human_friendly,
                    "serial_number": str(cert.serial_number),
                    "sha256": cert.sha256_fingerprint,
                    "valid_from": str(cert.not_valid_before),
                    "valid_to": str(cert.not_valid_after),
                })
            except Exception:
                continue  # one malformed signer block should never fail the whole analysis

        urls_found = set()
        try:
            with open(path, 'rb') as f:
                data = f.read(_STRING_SCAN_MAX_BYTES)
            for m in _URL_RE.finditer(data):
                urls_found.add(m.group(0).decode('utf-8', errors='replace'))
                if len(urls_found) >= _STRING_SCAN_MAX_URLS:
                    break
        except OSError:
            pass

        package = {
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": sorted(apk.get_permissions() or []),
            "activities": sorted(apk.get_activities() or []),
            "services": sorted(apk.get_services() or []),
            "receivers": sorted(apk.get_receivers() or []),
            "providers": sorted(apk.get_providers() or []),
            "signing": signing,
            "urls_found": sorted(urls_found),
        }
    except Exception as e:
        return {"success": False, "error": f"androguard parsed the APK but a field extraction failed: {e}", "package": None}

    return {"success": True, "error": None, "package": package}
