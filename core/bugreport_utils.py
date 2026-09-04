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
from datetime import datetime


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


def _bytes_to_str(value):
    """Decodes a bytes value the same way _make_json_safe() does above,
    for use by _extract_parsed_artifact_records() below - which runs
    against the RAW Dumpstate dataclass, before _make_json_safe() has
    run, so it needs this same small decode step independently."""
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return value


def _extract_parsed_artifact_records(ds):
    """Turns the genuinely record-shaped, individually-meaningful
    sections of a parsed Dumpstate into this app's standard artifact
    record shape ({artifact_type, title, url, value, timestamp, extra}) -
    2026-09-04, Android pattern-of-life item 6 - closing the "structured
    data, but a dead-end JSON blob" gap this module originally shipped
    with (every section only ever landed in one raw JSON sidecar file and
    one summary analysis_result, never individually searchable or
    Evidence-Timeline-visible). Deliberately runs against the RAW
    dataclass instance `ds`, NOT the already-JSON-safety-converted
    `sections` dict _make_json_safe() produces below - that conversion
    already stringifies every real datetime.datetime object via a bare
    str(), which would mean re-parsing a string back into a timestamp
    instead of using the real object dumpstate-py itself already gives us.

    Scoped to 5 of Dumpstate's 17 real fields (confirmed via direct
    dataclasses.fields() introspection against the real installed
    package, not guessed) - the ones confirmed record-shaped (a real list
    of individually-meaningful items) with either a real per-item
    timestamp or genuine standalone search value:

      package_install_log - PackageInstallInfo/PackageDeleteInfo both
      carry a real datetime.datetime `timestamp` field (confirmed via
      dataclasses.fields()), so this is the cleanest, highest-confidence
      section here.

      gps_data_log - one entry per location PROVIDER (network/gps/etc.),
      each holding last_locations: list[LocationInfo] - a real, nested
      per-fix list, each fix carrying its own real datetime.datetime
      timestamp plus latitude/longitude/accuracy.

      tombstones_log - Tombstone.timestamp is a plain str, but confirmed
      (via reading dumpstate-py's own tombstones.py parser source
      directly) to come from a real, standard Android tombstone file's
      own "Timestamp:" line, whose real format
      ("2025-03-20 11:42:07.312000000+0000") was independently confirmed
      via real Android crash-forensics literature AND confirmed to parse
      correctly via datetime.fromisoformat() on this app's own real
      Python 3.13 venv before being trusted here - not assumed.

      loaded_modules_log - no per-item timestamp exists in this dump
      format at all (a live kernel-module snapshot, not a timestamped
      event log) - timestamp stays honestly None, matching this
      codebase's established "no timestamp exists, don't invent one"
      convention, but the module name/size/used-by list is still real,
      useful, SEARCHABLE data worth indexing even without timeline
      placement (e.g. spotting a suspicious/rootkit-shaped module name).

      power_info_log - PowerEvent.timestamp is confirmed (via reading
      dumpstate-py's own power.py parser source directly:
      `event.timestamp = lines[0]`) to be raw, UN-PARSED first-line text
      from the dump section - not a confirmed structured format at all,
      so it is NEVER converted to a real epoch timestamp here (that would
      risk silently fabricating a wrong value from an unconfirmed
      format). Still indexed as a searchable, timestamp-less record with
      the raw text preserved in `extra`, rather than dropped entirely.

    The other 12 fields (header_log, vm_traces_log, anr_files_log,
    usb_data_log, mount_points_log, package_info_log, process_info_log,
    battery_stats_log, socket_ss_log, socket_netstat_log, socket_dev_log,
    account_service_log, keyguard_service_log) are single "current state
    at dump time" snapshots, not lists of individually-timestamped
    events - battery_stats_log in particular has a confirmed-live but
    genuinely unconfirmed-shape internal structure
    (dict[bytes, list[dict[...]]], no real sample bugreport available to
    check actual key names against) that would risk a wrong guess if
    forced into structured records. All 12 stay exactly as before: in the
    full raw JSON sidecar file and the one summary analysis_result - not
    silently dropped, just genuinely out of this pass's confidently-
    correct scope. A future session with a real sample bugreport archive
    to check against should extend this, not guess now."""
    records = []

    for info in (ds.package_install_log or []):
        # PackageInstallInfo and PackageDeleteInfo share the same
        # timestamp/observer/package_name/result fields (confirmed via
        # dataclasses.fields() on both real classes) - duck-typed here
        # via the one field only PackageInstallInfo has, rather than
        # importing and isinstance-checking both classes by name.
        is_install = hasattr(info, 'version_code')
        title = f"{'Installed' if is_install else 'Deleted'}: {info.package_name}"
        value_parts = [f"Result code: {info.result}"]
        if is_install and getattr(info, 'version_code', None):
            value_parts.append(f"Version code: {info.version_code}")
        ts = info.timestamp.timestamp() if info.timestamp else None
        records.append({
            "artifact_type": "android_bugreport_package_event", "title": title, "url": "",
            "value": " | ".join(value_parts), "timestamp": ts,
            "extra": {"package_name": info.package_name, "event": "install" if is_install else "delete",
                      "result": info.result, "observer": _bytes_to_str(info.observer)},
        })

    for source_entry in (ds.gps_data_log or []):
        for loc in (source_entry.last_locations or []):
            ts = loc.timestamp.timestamp() if loc.timestamp else None
            records.append({
                "artifact_type": "android_bugreport_location", "title": f"GPS: {source_entry.source}",
                "url": "", "value": f"{loc.latitude}, {loc.longitude} (accuracy {loc.accuracy}m)",
                "timestamp": ts,
                "extra": {"source": source_entry.source, "provider": _bytes_to_str(loc.provider),
                          "latitude": loc.latitude, "longitude": loc.longitude, "accuracy": loc.accuracy,
                          "altitude": loc.altitude, "speed": loc.speed},
            })

    for tomb in (ds.tombstones_log or []):
        ts = None
        if tomb.timestamp:
            try:
                ts = datetime.fromisoformat(tomb.timestamp).timestamp()
            except ValueError:
                ts = None
        records.append({
            "artifact_type": "android_bugreport_crash",
            "title": f"Crash: {tomb.process_name} (signal {tomb.signal})", "url": "",
            "value": f"PID {tomb.pid}, {tomb.abort_message or tomb.code or 'no message captured'}",
            "timestamp": ts,
            "extra": {"process_name": tomb.process_name, "pid": tomb.pid, "signal": tomb.signal,
                      "abort_message": tomb.abort_message, "cmdline": tomb.cmdline},
        })

    for mod in (ds.loaded_modules_log or []):
        name = _bytes_to_str(mod.name)
        records.append({
            "artifact_type": "android_bugreport_kernel_module", "title": name, "url": "",
            "value": f"Size: {mod.size} bytes", "timestamp": None,
            "extra": {"name": name, "size": mod.size,
                      "used_by": [_bytes_to_str(u) for u in (mod.used_by or [])]},
        })

    for evt in (ds.power_info_log or []):
        raw_ts = _bytes_to_str(evt.timestamp) if evt.timestamp else None
        reason = _bytes_to_str(evt.reason) if evt.reason else None
        records.append({
            "artifact_type": "android_bugreport_power_event",
            "title": f"Power off/reset: {reason or '(no reason captured)'}", "url": "",
            "value": raw_ts or "(no timestamp text captured)", "timestamp": None,
            "extra": {"reason": reason, "raw_timestamp_text": raw_ts},
        })

    return records


def parse_bugreport(path):
    """Returns {"success": bool, "error": str|None, "sections": dict|None,
    "artifact_records": list|None}. `sections` is a JSON-safe dict of
    every dumpstate-py field that was actually populated (a section not
    found in this particular bug report is simply absent, not present-
    and-null) - real values throughout, no partial/garbage data on a
    parse failure (parse() itself never raises on unrecognized input per
    live confirmation, it just leaves fields unset). `artifact_records`
    (2026-09-04, Android pattern-of-life item 6) is the new, additive
    output of _extract_parsed_artifact_records() above - this app's
    standard {artifact_type, title, url, value, timestamp, extra} shape
    for the genuinely record-shaped sections, so a caller can index them
    into parsed_artifacts (searchable/Evidence-Timeline-visible) on top
    of the existing full raw sections dict, without either output
    changing the other. Never raises."""
    try:
        import dumpstate
    except ImportError:
        return {"success": False, "error": "dumpstate-py is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions.",
                "sections": None, "artifact_records": None}

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
                            "sections": None, "artifact_records": None}
                raw_bytes = zf.read(member)
        else:
            with open(path, 'rb') as f:
                raw_bytes = f.read()
    except (OSError, zipfile.BadZipFile) as e:
        return {"success": False, "error": f"Could not read this file: {e}",
                "sections": None, "artifact_records": None}

    try:
        ds = dumpstate.Dumpstate()
        ds.parse(io.BytesIO(raw_bytes), sections={})  # {} = exclude nothing, parse every known section
    except Exception as e:
        return {"success": False, "error": f"dumpstate-py failed to parse this file: {e}",
                "sections": None, "artifact_records": None}

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

    try:
        artifact_records = _extract_parsed_artifact_records(ds)
    except Exception:
        # The new, less-tested extraction layer must never break the
        # already-working raw-sections output above - a bug here just
        # means no individually-searchable records this run, not a
        # failed parse overall.
        artifact_records = []

    return {"success": True, "error": None, "sections": sections, "artifact_records": artifact_records}
