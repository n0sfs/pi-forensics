"""Mobile Forensics: iOS (via libimobiledevice) and Android (via adb)
device discovery, backup/pull/bugreport acquisition workers, and their
routes.

First real feature blueprint extraction - fully contiguous in the
original app.py, exercises the worker-thread + job-state +
build_report_target pattern on the smallest such surface (2 workers)
before doing it again on recovery/acquisition.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import re
import json
import time
import subprocess
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody
from core.config import EVIDENCE_ROOT
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job, poll_directory_size,
    _stream_subprocess, _stream_piped_subprocess, clear_active_proc, clear_upstream_proc,
    build_report_target, write_initial_report, _write_report, reclaim_ownership,
)
from core.case_index_db import _auto_tag_case_artifact, _record_parsed_artifacts
from core.whatsapp_utils import pull_whatsapp_key_file
from core.idevicecrashreport_utils import pull_ios_crash_reports
from core.sim_utils import list_pcsc_readers, read_sim_card
from core.config import ALLOWED_HASH_ALGOS

# 2026-08-30, physical/raw Android acquisition: dc3dd/dcfldd's progress-line
# and post-completion hash-extraction parsers already live in
# routes/acquisition.py, fully generic (dc3dd/dcfldd's own output format
# doesn't change based on where the input bytes came from - confirmed live
# this session by piping test data through both and getting correctly-
# parsed, byte-correct results). Moving them into core/ would mean touching
# already-shipped, already-tested code in routes/acquisition.py for zero
# functional benefit; a narrow, one-directional, documented cross-Blueprint
# import mirrors the exact precedent already established and explained in
# routes/acquisition.py's own import block (its own import from
# routes/image_browser.py, for the identical "deeply Blueprint-local,
# disproportionately risky to move" reasoning). One-directional, not
# circular: routes/acquisition.py has no import of routes/mobile.py
# (confirmed via a full-repo grep before adding this).
from routes.acquisition import parse_dc3dd_line, parse_dc3dd_hashes, read_hash_log_file

mobile_bp = Blueprint('mobile', __name__)

# --- Mobile Device Discovery (iOS via libimobiledevice, Android via adb) ---
# These only talk to devices that are already unlocked and have already
# granted trust (iOS "Trust This Computer?") or USB debugging authorization
# (Android RSA key prompt) on-device. Nothing here bypasses a lockscreen,
# jailbreaks, or exploits a device - nothing in this app does.
_UDID_RE = re.compile(r'^[a-fA-F0-9\-]{20,64}$')
_ANDROID_SERIAL_RE = re.compile(r'^[a-zA-Z0-9_\-\.:]{4,64}$')

# Validates an on-device (Android) block-device path headed into a REMOTE
# shell command via `adb shell`/`su -c '...'` - a genuinely different
# threat model from core/paths.py's _DEVICE_RE/_PARTITION_RE, which
# validate a Pi-HOST path for local os.path/safe_path() use and must not
# be reused here. Anchored, length-capped, and restricted to characters
# that can never break out of the single-quoted `su -c '...'` string this
# gets interpolated into (routes/mobile.py's _build_physical_upstream_cmd
# below) - same class of care already given to _ANDROID_SERIAL_RE/_UDID_RE
# above.
_ANDROID_BLOCK_PATH_RE = re.compile(r'^/dev/block/[A-Za-z0-9_/.\-]{1,128}$')

# Physical/raw acquisition needs a genuinely seekable destination format -
# confirmed live (2026-08-30) that ewfacquire cannot read from a piped/
# non-seekable source at all ("Illegal seek"), while dc3dd and dcfldd both
# correctly read from stdin. E01 is therefore never offered for this mode.
ANDROID_PHYSICAL_ALLOWED_FORMATS = ('dc3dd', 'dcfldd')


def list_ios_devices():
    devices = []
    try:
        res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=15)
        udids = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        for udid in udids:
            if not _UDID_RE.match(udid):
                continue
            info = {"udid": udid, "name": "Unknown", "model": "Unknown",
                     "ios_version": "Unknown", "serial": "Unknown", "trusted": True,
                     "build_version": "Unknown", "storage_capacity_gb": "Unknown",
                     "imei": "Unknown", "wifi_mac": "Unknown", "bluetooth_mac": "Unknown",
                     "activation_state": "Unknown"}
            try:
                # ideviceinfo's full dump is already being fetched for the 4
                # fields above - parsing more of it here is free (no extra
                # subprocess call), unlike the Android path below.
                info_res = subprocess.run(["ideviceinfo", "-u", udid], capture_output=True, text=True, timeout=15)
                if info_res.returncode == 0:
                    for line in info_res.stdout.splitlines():
                        if ':' not in line:
                            continue
                        key, _, val = line.partition(':')
                        key, val = key.strip(), val.strip()
                        if key == 'DeviceName':
                            info['name'] = val
                        elif key == 'ProductType':
                            info['model'] = val
                        elif key == 'ProductVersion':
                            info['ios_version'] = val
                        elif key == 'SerialNumber':
                            info['serial'] = val
                        elif key == 'BuildVersion':
                            info['build_version'] = val
                        elif key == 'TotalDiskCapacity':
                            try:
                                info['storage_capacity_gb'] = round(int(val) / (1024**3), 1)
                            except ValueError:
                                pass
                        elif key == 'InternationalMobileEquipmentIdentity':
                            info['imei'] = val
                        elif key == 'WiFiAddress':
                            info['wifi_mac'] = val
                        elif key == 'BluetoothAddress':
                            info['bluetooth_mac'] = val
                        elif key == 'ActivationState':
                            info['activation_state'] = val
                else:
                    # Device is plugged in (usbmuxd sees it) but hasn't
                    # granted "Trust This Computer?" yet - not a bypass
                    # target, just needs the examiner to tap Trust on-device.
                    info['trusted'] = False
            except Exception:
                info['trusted'] = False
            devices.append(info)
    except Exception as e:
        print(f"Error listing iOS devices: {e}")
    return devices


# Physical/raw Android acquisition (2026-08-30) needs root - detected
# per-device here, best-effort, so the UI can disclose an honest state
# rather than let an examiner discover mid-acquisition that a device
# can't do this. Deliberately does NOT attempt an actual block-device
# read at this stage (e.g. no speculative `dd if=/dev/block/... of=/dev/
# null count=1`) - this app's own established culture is to avoid a read
# against the evidence source before the examiner has committed to
# starting a real job. `su -c id` and `getenforce` are the two cheapest,
# least-invasive signals available short of that.
#
# Provisional, not yet live-verified against a real rooted device (see
# the plan's own Section 9 checklist) - a first-time Magisk root grant
# can pop an on-device confirmation dialog that this probe has no way to
# detect or wait for; a short subprocess timeout is the only guard
# against that hanging this whole device-list refresh.
ANDROID_ROOT_PROBE_TIMEOUT = 8

def _probe_android_root_status(serial):
    """Best-effort su/SELinux probe for one authorized device. Never
    raises - any failure just means "root not detected", the same
    outcome a genuinely non-rooted device produces. Returns a dict merged
    directly into the device entry: {"root_available": bool,
    "selinux_mode": "Enforcing"|"Permissive"|"Disabled"|"Unknown"}."""
    root_available = False
    try:
        res = subprocess.run(["adb", "-s", serial, "shell", "su", "-c", "id"],
                              capture_output=True, text=True, timeout=ANDROID_ROOT_PROBE_TIMEOUT)
        root_available = res.returncode == 0 and "uid=0" in res.stdout
    except Exception:
        pass

    selinux_mode = "Unknown"
    try:
        res = subprocess.run(["adb", "-s", serial, "shell", "getenforce"],
                              capture_output=True, text=True, timeout=ANDROID_ROOT_PROBE_TIMEOUT)
        out = res.stdout.strip()
        if res.returncode == 0 and out in ("Enforcing", "Permissive", "Disabled"):
            selinux_mode = out
    except Exception:
        pass

    return {"root_available": root_available, "selinux_mode": selinux_mode}


def list_android_devices():
    devices = []
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=15)
        lines = res.stdout.splitlines()
        for line in lines[1:]:  # first line is "List of devices attached"
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            if not _ANDROID_SERIAL_RE.match(serial):
                continue
            state = parts[1] if len(parts) > 1 else "unknown"
            model = "Unknown"
            for tok in parts[2:]:
                if tok.startswith("model:"):
                    model = tok.split(":", 1)[1]

            device = {
                "serial": serial,
                "state": state,  # 'device' = authorized, 'unauthorized' = waiting on RSA prompt, 'offline' = other
                "model": model,
                "authorized": (state == "device"),
                "android_version": "Unknown", "api_level": "Unknown",
                "manufacturer": "Unknown", "build_id": "Unknown",
            }
            # Only query an authorized device - `adb shell` against an
            # unauthorized/offline one just hangs waiting on the RSA prompt
            # or fails outright, unlike iOS where ideviceinfo already runs
            # unconditionally above.
            if device["authorized"]:
                try:
                    props_res = subprocess.run(["adb", "-s", serial, "shell", "getprop"], capture_output=True, text=True, timeout=15)
                    if props_res.returncode == 0:
                        props = {}
                        for line in props_res.stdout.splitlines():
                            m = re.match(r'^\[([^\]]+)\]:\s*\[([^\]]*)\]$', line.strip())
                            if m:
                                props[m.group(1)] = m.group(2)
                        device['android_version'] = props.get('ro.build.version.release', 'Unknown')
                        device['api_level'] = props.get('ro.build.version.sdk', 'Unknown')
                        device['manufacturer'] = props.get('ro.product.manufacturer', 'Unknown')
                        device['build_id'] = props.get('ro.build.display.id', 'Unknown')
                except Exception:
                    pass
                device.update(_probe_android_root_status(serial))
            devices.append(device)
    except Exception as e:
        print(f"Error listing Android devices: {e}")
    return devices


def execution_worker_ios_backup(udid, dest_dir, encrypt_password, report_file_path, report_data):
    """
    idevicebackup2 gives per-file status lines but no global progress
    percentage (open upstream request, unresolved) - so progress here is
    shown as bytes-on-disk (polled from the backup folder), not a percent.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    udid_backup_dir = os.path.join(dest_dir, udid)

    try:
        if encrypt_password:
            append_log("[*] Enabling encrypted backup on device (confirm passcode on-screen if prompted)...")
            update_job(status="Waiting for on-device encryption confirmation...")
            try:
                enc_res = subprocess.run(
                    ["idevicebackup2", "-u", udid, "encryption", "on", encrypt_password],
                    capture_output=True, text=True, timeout=90
                )
                out = (enc_res.stdout + enc_res.stderr).strip()
                if out:
                    append_log(out)
                if enc_res.returncode != 0 and "already" not in out.lower() and "enabled" not in out.lower():
                    update_job(status="Failed")
                    append_log("[-] Could not enable backup encryption. If it's already on with a "
                               "different password, disable it on the device first "
                               "(Settings > General > Transfer or Reset iPhone) or supply that password.")
                    report_data["acquisition_status"] = "FAILED"
                    report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                    _write_report(report_file_path, report_data, append_log)
                    return
            except subprocess.TimeoutExpired:
                update_job(status="Failed")
                append_log("[-] Timed out waiting for encryption confirmation on the device.")
                report_data["acquisition_status"] = "FAILED"
                report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                _write_report(report_file_path, report_data, append_log)
                return

        cmd = ["idevicebackup2", "-u", udid, "backup", "--full", dest_dir]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(format="ios_backup", status="Backing Up Device...", progress_percent=0.0,
                   speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            size = poll_directory_size(udid_backup_dir) if os.path.isdir(udid_backup_dir) else 0
            update_job(transferred_bytes=size)

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=2.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if proc.returncode == 0 and os.path.isdir(udid_backup_dir):
            final_size = poll_directory_size(udid_backup_dir)
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] iOS backup completed successfully. Backup size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] idevicebackup2 exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()


# A full /sdcard walk (find -H, printf %T@ only) took 1.8s for 1819 real
# files on a real Pixel 8a - generous headroom for a much larger phone.
ANDROID_DEVICE_TIMESTAMPS_TIMEOUT = 120


def _capture_android_device_mtimes(serial, output_path):
    """Best-effort: captures each pulled file's REAL on-device modification
    time via one `adb shell find` call, and writes it as a sibling JSON
    manifest next to the pull's own output folder (routes/reporting.py's
    _collect_case_timeline() loads it by this exact naming convention).
    Never raises - a failure here just means the pre-existing,
    already-disclosed copy-time-only Evidence Timeline behavior applies to
    this pull, exactly as it did before this function existed. Returns the
    number of files captured (0 on any failure/empty result).

    Empirically confirmed necessary and correct against a real connected
    Pixel 8a (2026-08-29), not assumed from documentation: `adb pull` does
    not preserve original on-device timestamps at all - the copied files'
    own mtime is always the moment they were copied onto this station,
    confirmed by comparing several real Screenshot_YYYYMMDD-HHMMSS.png
    filenames' embedded dates against their actual copied-file mtime, which
    never matched (a screenshot named ...20260724-102354 had an mtime from
    four days later, the day of the pull). `adb shell find` reads the real
    on-device value directly, closing that gap for any pull made after this
    shipped - a pull made before it has no manifest and keeps the
    pre-existing fallback behavior unchanged.

    -H (not -L, and not omitted) is required by this device's toybox find:
    /sdcard is itself a symlink (-> /storage/self/primary on this Pixel 8a,
    confirmed via readlink) and find does not descend through a symlink
    given directly on its own command line unless told to follow it.
    Without -H, `find /sdcard -type f` silently returns nothing at all -
    confirmed live, this is not a theoretical edge case.

    Only %T@ (modification time) is captured, not a full MACB set - this
    device's toybox find (0.8.13-android) rejects -printf %A@/%C@ outright
    ("bad -printf %A", confirmed live), and toybox stat's own %X/%Z
    equivalents would need one subprocess round-trip per file, far too slow
    for a real device's file count. Modified time is also the one
    timestamp adb pull was actually destroying and the one an examiner
    most cares about, so this is a real, valuable fix even though it's
    narrower than a full MACB set - the interactive Evidence Timeline
    still shows only a single genuine 'M' event per captured file rather
    than a fabricated A/C/B alongside it."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "find -H /sdcard -type f -printf '%p|%T@\\n'"],
            capture_output=True, text=True, timeout=ANDROID_DEVICE_TIMESTAMPS_TIMEOUT,
        )
    except Exception:
        return 0
    if result.returncode != 0 or not result.stdout:
        return 0

    files = {}
    for line in result.stdout.splitlines():
        if '|' not in line:
            continue
        device_path, _, ts_str = line.rpartition('|')
        if not device_path.startswith('/sdcard/'):
            continue
        try:
            ts = float(ts_str)
        except ValueError:
            continue
        rel_path = device_path[len('/sdcard/'):]
        if rel_path:
            files[rel_path] = ts
    if not files:
        return 0

    manifest_path = f"{output_path.rstrip(os.sep)}_device_timestamps.json"
    try:
        with open(manifest_path, "w") as f:
            json.dump({
                "source": "adb shell find -H /sdcard -type f -printf '%p|%T@'",
                "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Real on-device file modification times, captured immediately after the pull "
                        "completed - adb pull itself does not carry these across the transfer.",
                "files": files,
            }, f, indent=2)
    except OSError:
        return 0
    return len(files)


ANDROID_APP_INVENTORY_TIMEOUT = 60
# `Package [<name>] (<hash>):` marks the start of each package's block in
# `dumpsys package packages`'s real output - confirmed directly against
# patrickfav/uber-adb-tools's real, maintained DumpsysPackageParser.java
# (a working third-party tool that already parses this exact command's
# output for the identical purpose), not guessed. MULTILINE so ^ anchors
# each real line, matching that parser's own line-oriented approach.
_ANDROID_PKG_BLOCK_RE = re.compile(r'^\s*Package \[([^\]]+)\] \([0-9a-fA-F]+\):', re.MULTILINE)
# Within one package's block, each of these is a real, confirmed
# `key=value` token followed by whitespace - same non-greedy `(.+?)\s`
# shape as the reference parser above, applied per-block rather than
# across the whole dump so one package's codePath can never be captured
# as another's by accident.
_ANDROID_PKG_FIELD_RES = {
    "version_name": re.compile(r'versionName=(.+?)\s'),
    "version_code": re.compile(r'versionCode=(\d+?)\s'),
    "code_path": re.compile(r'codePath=(.+?)\s'),
    "first_install_time": re.compile(r'firstInstallTime=(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})'),
    "last_update_time": re.compile(r'lastUpdateTime=(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})'),
}


def _android_dumpsys_time_to_unix(value):
    """dumpsys package's firstInstallTime/lastUpdateTime are printed as a
    plain 'YYYY-MM-DD HH:MM:SS' string with no timezone marker at all -
    confirmed via the same real reference parser cited above. This is
    presumably the DEVICE's own local clock, but this app has no reliable
    way to know that device's configured timezone from the dump alone -
    the same honest, disclosed choice already made for the Windows
    Firewall log's own timezone-ambiguous timestamps elsewhere in this
    app: stamp it as UTC deterministically (never the ANALYSIS station's
    own local timezone, which would silently vary station to station)
    rather than guess at an offset. An examiner who knows the device's
    real configured timezone can correct for it manually."""
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _capture_android_app_inventory(serial, output_path, case_folder):
    """Best-effort: captures the device's full installed-app inventory via
    one `adb shell dumpsys package packages` call (no root, no per-package
    round trips) immediately after a successful pull - like _capture_
    android_device_mtimes() above, this is genuinely ephemeral live-device
    state that's gone the moment the device disconnects, not something
    recoverable later from the pulled files themselves. Writes a raw
    manifest sidecar (for auditability/re-parsing) AND records real
    android_installed_app parsed_artifacts rows directly - unlike every
    other artifact parser in this app, which runs later via a File
    Explorer "Parse..." action against an already-acquired file, this data
    only exists to capture while the device is still connected, so
    indexing it happens right here in the acquisition worker instead.
    Never raises - a failure here just means no app inventory was
    captured for this pull, disclosed via the returned count being 0.
    Returns the number of packages captured."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "dumpsys package packages"],
            capture_output=True, text=True, timeout=ANDROID_APP_INVENTORY_TIMEOUT,
        )
    except Exception:
        return 0
    if result.returncode != 0 or not result.stdout:
        return 0

    matches = list(_ANDROID_PKG_BLOCK_RE.finditer(result.stdout))
    if not matches:
        return 0

    records = []
    for i, m in enumerate(matches):
        pkg_name = m.group(1)
        block_start = m.end()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(result.stdout)
        block = result.stdout[block_start:block_end]

        fields = {}
        for key, pattern in _ANDROID_PKG_FIELD_RES.items():
            field_match = pattern.search(block)
            if field_match:
                fields[key] = field_match.group(1)

        code_path = fields.get("code_path", "")
        is_system_app = code_path.startswith(('/system/', '/product/', '/apex/', '/vendor/'))
        first_install = _android_dumpsys_time_to_unix(fields.get("first_install_time"))
        last_update = _android_dumpsys_time_to_unix(fields.get("last_update_time"))

        value_parts = []
        if fields.get("version_name"):
            value_parts.append(f"Version: {fields['version_name']}")
        if fields.get("version_code"):
            value_parts.append(f"Version Code: {fields['version_code']}")
        value_parts.append("System App" if is_system_app else "User-Installed")
        if last_update and last_update != first_install:
            value_parts.append(f"Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(last_update))}")

        records.append({
            "artifact_type": "android_installed_app", "title": pkg_name, "url": "",
            "value": " | ".join(value_parts), "timestamp": first_install,
            "extra": {
                "package": pkg_name, "version_name": fields.get("version_name"),
                "version_code": fields.get("version_code"), "code_path": code_path or None,
                "is_system_app": is_system_app, "last_update_timestamp": last_update,
            },
        })

    if not records:
        return 0

    manifest_path = f"{output_path.rstrip(os.sep)}_app_inventory.json"
    try:
        with open(manifest_path, "w") as f:
            json.dump({
                "source": "adb shell dumpsys package packages",
                "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Raw dumpsys output is not saved here (can run to megabytes of unrelated system "
                        "service state) - only the per-package fields this app parsed out of it. "
                        "Timestamps are the device's own printed local time, stamped as UTC since this "
                        "app has no reliable way to know the device's real configured timezone.",
                "package_count": len(records),
                "packages": [r["extra"] for r in records],
            }, f, indent=2)
    except OSError:
        pass  # the parsed_artifacts rows below are the real record either way
    else:
        _auto_tag_case_artifact(case_folder, manifest_path)

    identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": f"{output_path.rstrip(os.sep)}_app_inventory"}
    _record_parsed_artifacts(case_folder, identity, records)
    return len(records)


# --- Physical/raw Android acquisition: on-device target enumeration ---
# PROVISIONAL - every parsing assumption below is from documented Android/
# Linux convention (kernel /proc, sysfs, and the standard `ls -la` symlink-
# listing format), NOT yet confirmed against this app's own real
# environment (no rooted device was available while this was written -
# see the approved plan's own Section 9 verification checklist). Kept
# deliberately isolated in these small, individually-fixable functions
# rather than woven into the acquisition worker itself, so a wrong
# assumption here (e.g. a different symlink-target format on some OEM
# skin) can be fixed without touching the already-proven pipe-orchestration
# or report-schema code.
ANDROID_TARGET_PROBE_TIMEOUT = 15

def _parse_proc_partitions(text):
    """Parses `cat /proc/partitions` output - 4 whitespace-separated
    columns (major, minor, #blocks, name), a header line, and a blank
    line. #blocks is in 1024-byte units (NOT the 512-byte sector
    convention /sys/class/block/<name>/size uses below - these two units
    must never be conflated). Returns [{"name", "size_bytes"}, ...],
    skipping anything that doesn't look like exactly 4 numeric-then-name
    fields (silently tolerant of header/blank lines rather than assuming
    a fixed line count)."""
    targets = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        major, minor, blocks, name = parts
        if not (major.isdigit() and minor.isdigit() and blocks.isdigit()):
            continue
        targets.append({"name": name, "size_bytes": int(blocks) * 1024})
    return targets


def _parse_block_by_name_listing(text):
    """Parses `su -c "ls -la /dev/block/by-name/"` output - one symlink
    per meaningful partition label (userdata, metadata, system, boot,
    super, etc.) pointing at the real device node. Handles both an
    absolute (`-> /dev/block/sda27`) and a relative (`-> ../../sda27`)
    symlink target, normalizing either to a bare device-node basename
    (e.g. "sda27") for the /sys/class/block/<name>/size lookup below.
    Returns {label: device_node_basename}."""
    labels = {}
    for line in text.splitlines():
        m = re.search(r'\s(\S+)\s*->\s*(\S+)\s*$', line.strip())
        if not m:
            continue
        label, target = m.group(1), m.group(2)
        labels[label] = os.path.basename(target)
    return labels


def _enumerate_android_physical_targets(serial):
    """Best-effort enumeration of physical-acquisition targets for a
    rooted, connected Android device. Returns {"targets": [...], "notes":
    [...]}} - never raises; any failed probe just yields fewer targets
    plus an explanatory note, never a 500. "targets" entries:
    {"label", "device_path", "size_bytes"}. userdata (if found) is
    surfaced first - almost always the forensically interesting target on
    a modern device (see the plan's Dynamic Partitions reasoning)."""
    notes = []
    partitions_by_basename = {}
    try:
        res = subprocess.run(["adb", "-s", serial, "shell", "cat", "/proc/partitions"],
                              capture_output=True, text=True, timeout=ANDROID_TARGET_PROBE_TIMEOUT)
        if res.returncode == 0:
            for p in _parse_proc_partitions(res.stdout):
                partitions_by_basename[p["name"]] = p["size_bytes"]
        else:
            notes.append("Could not read /proc/partitions on the device.")
    except Exception as e:
        notes.append(f"Could not read /proc/partitions on the device: {e}")

    labels = {}
    try:
        res = subprocess.run(["adb", "-s", serial, "shell", "su", "-c", "ls -la /dev/block/by-name/"],
                              capture_output=True, text=True, timeout=ANDROID_TARGET_PROBE_TIMEOUT)
        if res.returncode == 0:
            labels = _parse_block_by_name_listing(res.stdout)
        else:
            notes.append("/dev/block/by-name/ is not readable (needs root, or this device doesn't use it) - "
                         "only raw block devices from /proc/partitions are listed below.")
    except Exception as e:
        notes.append(f"Could not read /dev/block/by-name/ on the device: {e}")

    targets = []
    for label, basename in labels.items():
        size_bytes = partitions_by_basename.get(basename)
        if size_bytes is None:
            # Fall back to the sysfs sector-count reading (512-byte sectors,
            # a different unit from /proc/partitions' 1024-byte blocks above -
            # deliberately not conflated) when the label's basename wasn't
            # already resolved via /proc/partitions.
            try:
                res = subprocess.run(["adb", "-s", serial, "shell", "cat", f"/sys/class/block/{basename}/size"],
                                      capture_output=True, text=True, timeout=ANDROID_TARGET_PROBE_TIMEOUT)
                if res.returncode == 0 and res.stdout.strip().isdigit():
                    size_bytes = int(res.stdout.strip()) * 512
            except Exception:
                pass
        targets.append({"label": label, "device_path": f"/dev/block/{basename}", "size_bytes": size_bytes})

    # userdata first (almost always the forensically interesting target),
    # then alphabetically for everything else.
    targets.sort(key=lambda t: (t["label"] != "userdata", t["label"]))

    if not targets and not labels:
        # /dev/block/by-name/ wasn't usable at all - offer the raw
        # /proc/partitions entries directly as a fallback, so an older/
        # simpler device with no by-name symlinks still gets a usable list
        # rather than an empty one.
        for name, size_bytes in partitions_by_basename.items():
            targets.append({"label": name, "device_path": f"/dev/block/{name}", "size_bytes": size_bytes})

    return {"targets": targets, "notes": notes}


@mobile_bp.route('/api/mobile/android/<serial>/physical_targets', methods=['GET'])
@requires_auth
@requires_permission('mobile')
def android_physical_targets(serial):
    if not _ANDROID_SERIAL_RE.match(serial or ''):
        return jsonify({"success": False, "error": "Invalid device serial."}), 400
    result = _enumerate_android_physical_targets(serial)
    return jsonify({"success": True, "targets": result["targets"], "notes": result["notes"]})


@mobile_bp.route('/api/mobile/android/<serial>/pull_whatsapp_key', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def pull_whatsapp_key(serial):
    if not _ANDROID_SERIAL_RE.match(serial or ''):
        return jsonify({"success": False, "error": "Invalid device serial."}), 400

    req = request.get_json() or {}
    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    dest_path = os.path.join(dest_dir, f"{serial}_whatsapp_key")
    result = pull_whatsapp_key_file(serial, dest_path)
    if not result["success"]:
        return jsonify(result), 500

    log_chain_of_custody("whatsapp_key_pulled", {"serial": serial, "path": result["path"]})
    return jsonify(result)


@mobile_bp.route('/api/mobile/ios/pull_crash_reports', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def pull_ios_crash_reports_route():
    req = request.get_json() or {}
    udid = req.get('udid', '')
    if not _UDID_RE.match(udid or ''):
        return jsonify({"success": False, "error": "Invalid or missing device UDID. Refresh the device list and select a connected, trusted iOS device."}), 400

    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    output_dir = os.path.join(dest_dir, f"{udid}_ios_crash_reports")
    result = pull_ios_crash_reports(udid, output_dir)
    if not result["success"]:
        return jsonify(result), 500

    case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
    _auto_tag_case_artifact(case_folder or dest_dir, output_dir)

    log_chain_of_custody("ios_crash_reports_pulled", {"udid": udid, "output_dir": output_dir, "file_count": len(result["files"])})
    return jsonify(result)


@mobile_bp.route('/api/mobile/sim/readers', methods=['GET'])
@requires_auth
@requires_permission('mobile')
def sim_readers():
    result = list_pcsc_readers()
    return jsonify(result)


@mobile_bp.route('/api/mobile/sim/read', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def sim_read():
    req = request.get_json() or {}
    try:
        reader_index = int(req.get('reader_index', 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid reader index."}), 400

    dest_dir = safe_path(req.get('destination_dir', EVIDENCE_ROOT))
    if not dest_dir or not os.path.isdir(dest_dir):
        return jsonify({"success": False, "error": "Destination directory not found or outside the permitted evidence directory."}), 400

    result = read_sim_card(reader_index)
    if not result["success"]:
        return jsonify(result), 500

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_path = os.path.join(dest_dir, f"sim_read_{timestamp}.log")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result["output"])
        case_folder = safe_path(req.get('case_folder')) if req.get('case_folder') else None
        _auto_tag_case_artifact(case_folder or dest_dir, output_path)
    except OSError as e:
        return jsonify({"success": False, "error": f"Read successfully but could not write output: {e}"}), 500

    log_chain_of_custody("sim_card_read", {"reader_index": reader_index, "output_path": output_path})
    return jsonify({"success": True, "output": result["output"], "output_path": output_path})


def execution_worker_android(mode, serial, output_path, report_file_path, report_data):
    """
    mode 'backup': adb backup (deprecated/unreliable on Android 12+, requires
    on-device 'Back up my data' confirmation, produces a single .ab file).
    mode 'pull': adb pull of accessible shared storage (more universally
    reliable logical copy, no on-device confirmation needed beyond the
    original USB-debugging authorization).
    mode 'bugreport': adb bugreport (system logs/dumpstate snapshot - useful
    supplementary artifact, not a full acquisition).
    Like iOS, adb gives no clean aggregate percentage either way, so
    progress is bytes-on-disk, polled directly.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()

    try:
        update_job(format=f"android_{mode}", status="Initializing...", progress_percent=0.0,
                   speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

        if mode == 'backup':
            cmd = ["adb", "-s", serial, "backup", "-apk", "-shared", "-all", "-f", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            append_log("[*] Waiting for on-device confirmation ('Back up my data') - check the phone screen.")
            update_job(status="Waiting for device confirmation...")

            def on_poll():
                size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                update_job(transferred_bytes=size, status="Backing Up Device...")
        elif mode == 'bugreport':
            cmd = ["adb", "-s", serial, "bugreport", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            update_job(status="Capturing Bug Report (system logs/dumpstate)...")

            def on_poll():
                size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                update_job(transferred_bytes=size)
        else:
            # -a ("preserve file timestamp and mode") is a real, documented
            # flag on this station's own installed adb (confirmed live via
            # `adb help` against the actual binary, platform-tools
            # 34.0.5-debian, 2026-08-29) - request it so the copied files'
            # OWN on-disk mtime is correct too, not just this app's Evidence
            # Timeline. Deliberately NOT relied on as the sole mechanism:
            # -a's actual behavior has not yet been empirically verified
            # against a real connected device (added while the phone was
            # disconnected - a genuine live test is still needed the next
            # time one's plugged in), -a support varies by adb client/device
            # combination (an older platform-tools build or an older Android
            # device's adbd might silently ignore it), and this repo has its
            # own established "verify against real hardware before trusting
            # a tool's documented behavior" discipline. _capture_android_
            # device_mtimes() below still runs unconditionally after every
            # successful pull as the adb-version-independent, already-proven
            # source of truth - if -a genuinely works, the two simply agree;
            # if it doesn't (or only partially does), the manifest is what
            # actually drives the Evidence Timeline regardless.
            cmd = ["adb", "-s", serial, "pull", "-a", "/sdcard/.", output_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            update_job(status="Pulling Accessible Storage...")

            def on_poll():
                update_job(transferred_bytes=poll_directory_size(output_path))

        def on_line(clean_line):
            append_log(clean_line)

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=2.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        output_exists = os.path.exists(output_path) and (
            os.path.getsize(output_path) > 0 if mode in ('backup', 'bugreport') else True
        )

        if proc.returncode == 0 and output_exists:
            final_size = poll_directory_size(output_path)
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] Android {mode} completed successfully. Size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size

            # Best-effort enrichment, only for a genuinely successful pull -
            # never blocks/delays reporting the pull itself as complete, and
            # a failure here (device disconnected right after the pull,
            # capture timed out, etc.) just means the Evidence Timeline's
            # pre-existing copy-time fallback (with its own disclosure note)
            # applies to this pull, same as it always has.
            if mode == 'pull':
                append_log("[*] Capturing original on-device file timestamps (adb shell find)...")
                captured = _capture_android_device_mtimes(serial, output_path)
                if captured:
                    append_log(f"[+] Captured {captured} real on-device file timestamp(s) for the Evidence Timeline.")
                    report_data["acquisition_parameters"]["device_timestamps_captured"] = captured
                    manifest_path = f"{output_path.rstrip(os.sep)}_device_timestamps.json"
                    _auto_tag_case_artifact(os.path.dirname(output_path), manifest_path)
                else:
                    append_log("[-] Could not capture on-device timestamps - Evidence Timeline entries for this "
                               "acquisition will fall back to copy time (disclosed there automatically).")

                append_log("[*] Capturing installed app inventory (adb shell dumpsys package packages)...")
                app_count = _capture_android_app_inventory(serial, output_path, os.path.dirname(output_path))
                if app_count:
                    append_log(f"[+] Captured {app_count} installed app(s) - searchable in File Views and on the "
                               "Evidence Timeline.")
                    report_data["acquisition_parameters"]["apps_captured"] = app_count
                else:
                    append_log("[-] Could not capture installed app inventory (device disconnected, or "
                               "dumpsys returned nothing usable) - this is a best-effort enrichment, the "
                               "pull itself is unaffected.")
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] adb {mode} exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()


def execution_worker_android_physical(serial, target, engine, hashes, total_bytes, out_file,
                                       report_file_path, report_data):
    """Physical/raw Android acquisition (2026-08-30) - the first worker in
    this app that chains two real subprocesses: `adb exec-out su -c "dd
    if=<target> bs=4M"` (the remote read, on the device) piped directly
    into `sudo dc3dd`/`sudo dcfldd` (the local write + hash, on this
    station) via core/jobs.py's _stream_piped_subprocess(). Requires the
    device to already be rooted - see _probe_android_root_status() above
    and the UI's own disclosure text for why this app never tries to root
    a device itself.

    Reuses routes/acquisition.py's dc3dd/dcfldd progress-line parser
    (parse_dc3dd_line) and post-completion hash extraction (parse_dc3dd_
    hashes/read_hash_log_file) completely unmodified - confirmed live this
    session that dc3dd/dcfldd's own output format is unaffected by where
    the input bytes came from (a real pipe test produced byte-identical
    output with a correctly-parsed matching hash)."""
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    upstream_cmd = ["adb", "-s", serial, "exec-out", f"su -c 'dd if={target} bs=4M'"]
    if engine == 'dc3dd':
        dc3dd_log_file = out_file.replace('.dd', '_dc3dd.log')
        downstream_cmd = ["sudo", "/usr/bin/dc3dd", f"of={out_file}", f"log={dc3dd_log_file}"] + [f"hash={h}" for h in hashes]
    else:
        downstream_cmd = ["sudo", "/usr/bin/dcfldd", f"of={out_file}"]
        if hashes:
            downstream_cmd.append(f"hash={','.join(hashes)}")
            for h in hashes:
                downstream_cmd.append(f"{h}log={out_file.replace('.dd', f'_{h}.log')}")

    append_log(f"[*] Starting physical acquisition of {target} using [{engine.upper()}] via adb (rooted device required)...")
    append_log(f"[*] Upstream (device) command: {' '.join(upstream_cmd)}")
    append_log(f"[*] Downstream (station) command: {' '.join(downstream_cmd)}")

    start_time = time.time()
    update_job(format="android_physical", status="Acquiring (piped from device)...",
               progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=total_bytes)

    try:
        def on_line(clean_line):
            append_log(clean_line)
            bytes_copied, speed = parse_dc3dd_line(clean_line)
            updates = {}
            if bytes_copied is not None:
                updates["transferred_bytes"] = bytes_copied
                if total_bytes > 0:
                    updates["progress_percent"] = round((bytes_copied / total_bytes) * 100, 1)
            if speed is not None:
                updates["speed_mbps"] = speed
            if updates:
                update_job(**updates)

        downstream_proc, upstream_proc, upstream_stderr = _stream_piped_subprocess(upstream_cmd, downstream_cmd, on_line)
        time.sleep(1.0)

        computed_hashes = {}
        if engine == 'dc3dd':
            computed_hashes = parse_dc3dd_hashes(out_file.replace('.dd', '_dc3dd.log'))
        else:
            for h in hashes:
                val = read_hash_log_file(out_file.replace('.dd', f'_{h}.log'), h)
                if val:
                    computed_hashes[h] = val

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["computed_verification_hashes"] = computed_hashes

        # Same dc3dd-can-exit-0-while-self-reporting-failure check
        # execution_worker() (routes/acquisition.py) already relies on -
        # the downstream tool here is the identical binary, so it carries
        # the identical risk.
        dc3dd_self_reported_failure = engine == 'dc3dd' and 'dc3dd failed at' in "\n".join(log_history)
        # A non-zero upstream exit with real stderr text is the most likely
        # shape an SELinux denial or a genuinely non-rooted/blocked target
        # would take (confirmed live via a deliberately-failing fake
        # upstream: exits fast, non-zero, downstream correctly ends up with
        # a clean, honest zero-byte output rather than hanging) - surfaced
        # as a specific, distinguishable failure reason rather than a bare
        # "Failed" status.
        upstream_failed = upstream_proc.returncode not in (0, None)

        if downstream_proc.returncode in (0, 2) and not dc3dd_self_reported_failure and not upstream_failed:
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] Physical acquisition completed successfully.")
            report_data["acquisition_status"] = "COMPLETED"
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            if upstream_failed:
                append_log(f"[-] The on-device read failed (adb/su/dd exit code {upstream_proc.returncode}). "
                           f"This usually means the device isn't actually rooted, root access was denied on-device, "
                           f"or SELinux is blocking raw block-device access even as root - "
                           f"{('device stderr: ' + upstream_stderr) if upstream_stderr else 'no further detail was returned by the device.'}")
            elif dc3dd_self_reported_failure:
                append_log("[-] dc3dd reported its own failure despite exiting with a code normally treated as success - treating this run as failed.")
            else:
                append_log(f"[-] {engine} exited with code {downstream_proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # dc3dd/dcfldd ran via sudo (reads the pipe, writes the output) -
        # its output lands root-owned, same as every other sudo'd
        # acquisition tool in this app.
        reclaim_ownership(os.path.dirname(out_file))
        update_job(active=False)
        clear_active_proc()
        clear_upstream_proc()


# --- Mobile Forensics Endpoints ---
@mobile_bp.route('/api/mobile/devices', methods=['GET'])
@requires_auth
def get_mobile_devices():
    return jsonify({"ios": list_ios_devices(), "android": list_android_devices()})


@mobile_bp.route('/api/mobile/ios/pair', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def pair_ios_device():
    req = request.get_json() or {}
    udid = req.get('udid', '')
    if not _UDID_RE.match(udid or ''):
        return jsonify({"success": False, "error": "Invalid or missing device UDID."}), 400

    try:
        res = subprocess.run(["idevicepair", "-u", udid, "pair"], capture_output=True, text=True, timeout=15)
        output = (res.stdout + res.stderr).strip()
        if res.returncode == 0:
            return jsonify({"success": True, "message": output or "Pairing request sent - accept 'Trust This Computer?' on the device if prompted."})
        return jsonify({"success": False, "error": output or "Pairing failed."}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Timed out waiting for the device."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@mobile_bp.route('/api/mobile/start_ios_backup', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def start_ios_backup():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    udid = req.get('udid', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    encrypt_password = req.get('encrypt_password') or None
    metadata = req.get('metadata', {})

    if not _UDID_RE.match(udid or ''):
        update_job(active=False)
        return jsonify({"error": "Invalid or missing device UDID. Refresh the device list and select a connected, trusted iOS device."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_ios_backup"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="ios_backup", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing iOS backup for UDID {udid} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "ios_backup",
        "case_metadata": metadata,
        "device_udid": udid,
        "acquisition_parameters": {
            "platform": "iOS",
            "method": "idevicebackup2 full backup",
            "encrypted": bool(encrypt_password),
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_ios_backup,
        args=(udid, job_dest_dir, encrypt_password, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("ios_backup_start", {"udid": udid, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "iOS backup started."})


@mobile_bp.route('/api/mobile/start_android', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def start_android_acquisition():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    serial = req.get('serial', '')
    mode = req.get('mode', 'pull')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if not _ANDROID_SERIAL_RE.match(serial or ''):
        update_job(active=False)
        return jsonify({"error": "Invalid or missing device serial. Refresh the device list and select a connected, authorized Android device."}), 400

    if mode not in ('backup', 'pull', 'bugreport', 'physical'):
        update_job(active=False)
        return jsonify({"error": "mode must be 'backup', 'pull', 'bugreport', or 'physical'."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_android_{mode}"

    if mode == 'physical':
        target = (req.get('target') or '').strip()
        engine = req.get('format', 'dc3dd')
        hashes = [h for h in req.get('hashes', ['sha256']) if h in ALLOWED_HASH_ALGOS]

        if not _ANDROID_BLOCK_PATH_RE.match(target):
            update_job(active=False)
            return jsonify({"error": "Invalid or missing target device path. Pick a target from the "
                                      "enumerated list, or enter a valid /dev/block/... path manually."}), 400
        if engine not in ANDROID_PHYSICAL_ALLOWED_FORMATS:
            update_job(active=False)
            return jsonify({"error": f"format must be one of {ANDROID_PHYSICAL_ALLOWED_FORMATS} for physical "
                                      f"acquisition - E01/ewfacquire cannot read from a piped adb source."}), 400
        if not hashes:
            update_job(active=False)
            return jsonify({"error": "Select at least one verification hash algorithm."}), 400

        output_path = os.path.join(dest_path, f"{base_name}.dd")
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400
        if os.path.exists(output_path):
            update_job(active=False)
            return jsonify({"error": f"{output_path} already exists - choose a different Evidence ID "
                                      f"rather than overwrite an existing acquisition."}), 409

        # Re-derive the target's size server-side right now, rather than
        # trusting a client-supplied value from an earlier /physical_targets
        # fetch that may be stale - one targeted sysfs lookup, not a full
        # re-enumeration.
        total_bytes = 0
        try:
            basename = os.path.basename(target)
            res = subprocess.run(["adb", "-s", serial, "shell", "cat", f"/sys/class/block/{basename}/size"],
                                  capture_output=True, text=True, timeout=ANDROID_TARGET_PROBE_TIMEOUT)
            if res.returncode == 0 and res.stdout.strip().isdigit():
                total_bytes = int(res.stdout.strip()) * 512
        except Exception:
            pass

        root_status = _probe_android_root_status(serial)

        update_job(
            format="android_physical", progress_percent=0.0, speed_mbps=0.0,
            transferred_bytes=0, total_bytes=total_bytes, status="Initializing...",
            log=f"[*] Initializing physical acquisition of {target} on {serial} -> {output_path}..."
        )

        report_data = {
            "tool": "android_physical",
            "case_metadata": metadata,
            "device_serial": serial,
            "acquisition_parameters": {
                "platform": "Android", "method": f"adb exec-out su -c dd (piped into {engine})",
                "output_destination": output_path, "output_format": engine,
                "target_device_path": target,
                "target_label": "manual" if not target.startswith("/dev/block/by-name/") else os.path.basename(target),
                "requested_hashes": hashes,
                "root_method": "su (method/binary not further identified)" if root_status["root_available"] else "not detected",
                "selinux_mode_at_detection": root_status["selinux_mode"],
                "selinux_caveat": "SELinux enforcing mode can block root's raw block-device read even when su "
                                  "succeeds; this is device- and root-method-specific and was not independently "
                                  "verified for this specific target before the acquisition began.",
                "dynamic_partitions_caveat": "Modern Android (10+) uses a virtual 'super' partition for system/"
                                             "vendor/etc; this acquisition targeted a specific partition/block "
                                             "device, not the whole physical disk, unless explicitly chosen.",
            },
            "attachments": {"files": [], "reference_urls": []},
            "acquisition_status": "IN_PROGRESS",
            "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        report_target = build_report_target(dest_path, dest_path, base_name)
        write_initial_report(report_target, report_data)

        thread = threading.Thread(
            target=execution_worker_android_physical,
            args=(serial, target, engine, hashes, total_bytes, output_path, report_target, report_data)
        )
        thread.daemon = True
        thread.start()

        log_chain_of_custody("android_acquisition_start", {"mode": mode, "serial": serial,
                                                             "target": target, "destination": output_path})
        return jsonify({"success": True, "message": "Physical Android acquisition started."})

    if mode == 'backup':
        output_path = os.path.join(dest_path, f"{base_name}.ab")
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400
    elif mode == 'bugreport':
        output_path = os.path.join(dest_path, f"{base_name}.zip")
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400
    else:
        output_path = os.path.join(dest_path, base_name)
        try:
            os.makedirs(output_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {output_path} is inaccessible: {str(e)}"}), 400

    update_job(
        format=f"android_{mode}", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing Android {mode} for {serial} -> {output_path}..."
    )

    report_data = {
        "tool": f"android_{mode}",
        "case_metadata": metadata,
        "device_serial": serial,
        "acquisition_parameters": {
            "platform": "Android",
            "method": f"adb {mode}",
            "output_destination": output_path,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_android,
        args=(mode, serial, output_path, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("android_acquisition_start", {"mode": mode, "serial": serial, "destination": output_path})
    return jsonify({"success": True, "message": f"Android {mode} started."})
