"""adb bugreport deep parsing via dumpstate-py (CERT-EDF) - this app's own
existing bugreport action (routes/mobile.py's `mode == 'bugreport'`
branch of execution_worker_android) already runs `adb bugreport
<output_path>` and stores the resulting zip with zero parsing; this
module is what turns that raw zip into structured sections (mount
points, process list, package install/delete log, loaded kernel
modules, GPS coordinates, crash traces/tombstones, network sockets,
battery stats, power events, and a couple of system services).

Confirmed live against the real installed package on this station's
ARM64 venv before writing this module, not assumed from the plan's own
original placeholder names - the real importable module is `dumpstate`
(not `dumpstate_py`, despite the pip/PyPI-style package name being
`dumpstate-py`), and it exposes a genuinely well-structured
`Dumpstate` dataclass plus per-section `parse_*` functions and a real
`Dumpstate.parse(BytesIO, sections={...})` method - confirmed via direct
introspection (inspect.signature) and a real call against garbage input
(returned cleanly with every field left None, never raised) before
trusting it. Direct import, not subprocess - this is genuinely a
well-structured, introspectable dataclass API (matching the plan's own
stated bar for choosing import over CLI-wrapping), unlike sqlite-dissect,
whose real Python API surface could not be confirmed the same way.

The package's own module-level logging setup (dumpstate/helper/logging.py)
calls logging.basicConfig() at import time, configuring the ROOT Python
logger with a Rich handler writing to stderr - silenced here (the same
"don't let a third-party dependency's own chatty logging pollute this
app's log output" discipline already applied to androguard's loguru
setup in core/apk_utils.py) by raising this one named logger's own level
after import, without touching any other logger this app might rely on
elsewhere.
"""
import dataclasses
import io
import logging
import zipfile


def _make_json_safe(obj):
    """Recursively converts a parsed result (dataclasses already expanded
    via dataclasses.asdict(), so this usually only sees dict/list/tuple/
    bytes/scalar) into something json.dumps()-safe - bytes decode via
    utf-8/replace (this app's own established convention for untrusted
    device-sourced byte content, e.g. core/linux_artifacts.py's auth.log
    handling). Anything else (confirmed live: dumpstate-py's own internal
    RawData helper class is a plain, non-dataclass object that can slip
    through dataclasses.asdict() unconverted on a field that embeds it)
    falls back to str() rather than being passed through unchanged, which
    would otherwise crash json.dumps() downstream."""
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, dict):
        # Confirmed live: some of dumpstate-py's own dicts (e.g. a
        # DumpstateHeader's uptime['duration']) have bytes KEYS too, not
        # just bytes values - a plain regex-derived b'days'/b'hours' etc.
        # never gets decoded by the library itself.
        return {(k.decode('utf-8', errors='replace') if isinstance(k, bytes) else k): _make_json_safe(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def parse_bugreport(path):
    """Returns {"success": bool, "error": str|None, "sections": dict|None}.
    `sections` is a JSON-safe dict of every dumpstate-py field that was
    actually populated (a section not found in this particular bug report
    is simply absent, not present-and-null) - real values throughout, no
    partial/garbage data on a parse failure (parse() itself never raises
    on unrecognized input per live confirmation, it just leaves fields
    unset). Never raises."""
    try:
        import dumpstate
    except ImportError:
        return {"success": False, "error": "dumpstate-py is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions.", "sections": None}

    logging.getLogger('dumpstate-py').setLevel(logging.CRITICAL)

    # Mirrors dumpstate-py's own main.app() entrypoint exactly: an `adb
    # bugreport` output is a zip whose one interesting member is named
    # dumpstate-*; a plain flat dumpstate text file (e.g. one already
    # extracted, or pulled by an older adb) is handled directly too.
    try:
        with open(path, 'rb') as f:
            head = f.read(4)
        if head == b'PK\x03\x04':
            with zipfile.ZipFile(path, 'r') as zf:
                member = next((n for n in zf.namelist() if "dumpstate-" in n), None)
                if not member:
                    return {"success": False, "error": "This zip does not contain a "
                            "dumpstate-* member - not a recognized adb bugreport archive.",
                            "sections": None}
                raw_bytes = zf.read(member)
        else:
            with open(path, 'rb') as f:
                raw_bytes = f.read()
    except (OSError, zipfile.BadZipFile) as e:
        return {"success": False, "error": f"Could not read this file: {e}", "sections": None}

    try:
        ds = dumpstate.Dumpstate()
        ds.parse(io.BytesIO(raw_bytes), sections={})  # {} = exclude nothing, parse every known section
    except Exception as e:
        return {"success": False, "error": f"dumpstate-py failed to parse this file: {e}", "sections": None}

    sections = {}
    for field in dataclasses.fields(ds):
        if field.name.startswith('_'):
            continue  # internal parser state (e.g. the raw-bytes buffer), not a real result section
        value = getattr(ds, field.name)
        if value is None:
            continue
        try:
            if dataclasses.is_dataclass(value):
                sections[field.name] = _make_json_safe(dataclasses.asdict(value))
            elif isinstance(value, list):
                sections[field.name] = [
                    _make_json_safe(dataclasses.asdict(v)) if dataclasses.is_dataclass(v) else _make_json_safe(v)
                    for v in value
                ]
            else:
                sections[field.name] = _make_json_safe(value)
        except Exception:
            continue  # one malformed section should never fail the whole parse

    return {"success": True, "error": None, "sections": sections}
