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

from flask import Blueprint, jsonify, request, g

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody
from core.config import EVIDENCE_ROOT, INSTALL_DIR
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
from core.android_companion_sms_utils import (
    PIF_COMPANION_SMS_AUTHORITY, SMS_QUERY_COLUMNS,
    parse_content_query_output, build_companion_sms_records,
)
from core.android_companion_contacts_calllog_utils import (
    PIF_COMPANION_PACKAGE, PIF_COMPANION_CONTACTS_AUTHORITY, PIF_COMPANION_CALLLOG_AUTHORITY,
    CONTACTS_QUERY_COLUMNS, CALLLOG_QUERY_COLUMNS,
    build_companion_contact_records, build_companion_call_log_records,
)
from core.android_companion_calendar_utils import (
    PIF_COMPANION_CALENDAR_AUTHORITY, CALENDAR_EVENTS_QUERY_COLUMNS, CALENDAR_ATTENDEES_QUERY_COLUMNS,
    build_companion_calendar_records,
)
from core.android_companion_media_utils import (
    PIF_COMPANION_MEDIA_AUTHORITY, MEDIA_QUERY_COLUMNS, build_companion_media_records,
)

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


ANDROID_ACCOUNTS_TIMEOUT = 30
# "User <UserInfo.toString()>:" then, per user, "Accounts: N" followed by N
# "  Account {name=..., type=...}" lines - confirmed directly against the
# real AOSP source (AccountManagerService.java's dump()/dumpUser()) rather
# than guessed: dumpUser() does `fout.println("  " + account.toString())`,
# and Account.toString() (core/java/android/accounts/Account.java) is
# literally `"Account {name=" + name + ", type=" + type + "}"`. The account
# name (a real email/username, e.g. a signed-in Google account) is printed
# in full, never masked - confirmed via the same source, not assumed.
_ANDROID_ACCOUNT_LINE_RE = re.compile(r'^\s*Account \{name=(.*?), type=(.*?)\}\s*$', re.MULTILINE)


def _capture_android_accounts(serial, output_path, case_folder):
    """Best-effort: captures the device's configured accounts (Google,
    Exchange, any other app-registered account type) via one
    `adb shell dumpsys account` call - no root needed, same "ephemeral
    live-device state, capture it now or lose it" reasoning as _capture_
    android_app_inventory() above. Never raises - a failure here just
    means no account list was captured for this pull. Returns the number
    of accounts captured."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "dumpsys account"],
            capture_output=True, text=True, timeout=ANDROID_ACCOUNTS_TIMEOUT,
        )
    except Exception:
        return 0
    if result.returncode != 0 or not result.stdout:
        return 0

    records = []
    for m in _ANDROID_ACCOUNT_LINE_RE.finditer(result.stdout):
        name, acct_type = m.group(1), m.group(2)
        records.append({
            "artifact_type": "android_configured_account", "title": name, "url": "",
            "value": f"Account Type: {acct_type}", "timestamp": None,
            "extra": {"name": name, "type": acct_type},
        })

    if not records:
        return 0

    manifest_path = f"{output_path.rstrip(os.sep)}_accounts.json"
    try:
        with open(manifest_path, "w") as f:
            json.dump({
                "source": "adb shell dumpsys account",
                "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Raw dumpsys output is not saved here - only the account name/type pairs "
                        "this app parsed out of it. dumpsys account has no per-account timestamp "
                        "field at all, so these records carry none.",
                "account_count": len(records),
                "accounts": [r["extra"] for r in records],
            }, f, indent=2)
    except OSError:
        pass
    else:
        _auto_tag_case_artifact(case_folder, manifest_path)

    identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": f"{output_path.rstrip(os.sep)}_accounts"}
    _record_parsed_artifacts(case_folder, identity, records)
    return len(records)


ANDROID_NOTIFICATIONS_TIMEOUT = 30
# Real, confirmed via the real AOSP source (NotificationManagerService.java/
# NotificationRecord.java), not guessed - and worth stating plainly because
# it's easy to oversell: `adb shell dumpsys notification` with no extra
# flags runs in REDACTED mode by default (DumpFilter.redact = true; only
# --noredact/--reveal turns it off, and this app deliberately never passes
# that - see below). Under the default redacted mode, a notification's
# actual TITLE/BODY TEXT is NOT recoverable - NotificationRecord.dump()
# replaces every text-bearing "extras" value with a bare "[length=N]"
# placeholder (dumpNotification()'s own shouldRedactStringExtra() check).
# What IS genuinely, reliably captured: which package posted each currently
# -visible notification, its real post time (StatusBarNotification.
# getPostTime(), a real System.currentTimeMillis() wall-clock value - not
# elapsed-realtime, confirmed via where mCreationTimeMs is actually set),
# its importance ranking, and its stable notification "key" - a real
# activity-timeline signal (which apps were actively notifying, and when),
# not a message-content recovery tool. Deliberately never passes --reveal:
# this app has no way to verify from source alone whether that flag is
# genuinely reachable from an unprivileged `adb shell` context or gated by
# an additional permission this reading didn't surface, and the risk of
# silently exposing real notification content (which could include 2FA
# codes, private messages, etc.) if that assumption were wrong is not one
# to take on unverified - a known, disclosed limitation, not an oversight.
_ANDROID_NOTIF_RECORD_RE = re.compile(
    r'NotificationRecord\(0x[0-9a-fA-F]+: pkg=(\S+) user=(\S+) id=(-?\d+) tag=(\S+) importance=(-?\d+) key=(\S+):'
)
_ANDROID_NOTIF_FIELD_RES = {
    "creation_time_ms": re.compile(r'mCreationTimeMs=(\d+)'),
    "update_time_ms": re.compile(r'mUpdateTimeMs=(\d+)'),
}


def _capture_android_notification_snapshot(serial, output_path, case_folder):
    """Best-effort: captures a snapshot of the device's currently-visible
    notifications (package, post time, importance, key - real content is
    redacted by default, see the module comment above) via one
    `adb shell dumpsys notification` call - no root, no --reveal. Same
    "ephemeral live-device state" reasoning as the two capture functions
    above. Never raises. Returns the number of notification records
    captured."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "dumpsys notification"],
            capture_output=True, text=True, timeout=ANDROID_NOTIFICATIONS_TIMEOUT,
        )
    except Exception:
        return 0
    if result.returncode != 0 or not result.stdout:
        return 0

    matches = list(_ANDROID_NOTIF_RECORD_RE.finditer(result.stdout))
    if not matches:
        return 0

    records = []
    for i, m in enumerate(matches):
        pkg, user, notif_id, tag, importance, key = m.groups()
        block_start = m.end()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(result.stdout)
        block = result.stdout[block_start:block_end]

        fields = {}
        for fkey, pattern in _ANDROID_NOTIF_FIELD_RES.items():
            field_match = pattern.search(block)
            if field_match:
                fields[fkey] = field_match.group(1)

        creation_ms = fields.get("creation_time_ms")
        timestamp = int(creation_ms) / 1000.0 if creation_ms else None
        update_ms = fields.get("update_time_ms")
        update_timestamp = int(update_ms) / 1000.0 if update_ms else None

        records.append({
            "artifact_type": "android_notification_snapshot", "title": pkg, "url": "",
            "value": f"Importance: {importance} | Key: {key} (content redacted - see module docstring)",
            "timestamp": timestamp,
            "extra": {
                "package": pkg, "user": user, "notification_id": notif_id, "tag": tag,
                "importance": importance, "key": key, "update_timestamp": update_timestamp,
            },
        })

    if not records:
        return 0

    manifest_path = f"{output_path.rstrip(os.sep)}_notifications.json"
    try:
        with open(manifest_path, "w") as f:
            json.dump({
                "source": "adb shell dumpsys notification",
                "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Real content (title/body text) is redacted by default by the OS itself - "
                        "not something this app chose to strip. Only package identity, post/update "
                        "time, importance ranking, and the notification's key are real, recoverable "
                        "metadata here. Raw dumpsys output is not saved (can run to hundreds of KB "
                        "of unrelated system-service state).",
                "notification_count": len(records),
                "notifications": [r["extra"] for r in records],
            }, f, indent=2)
    except OSError:
        pass
    else:
        _auto_tag_case_artifact(case_folder, manifest_path)

    identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": f"{output_path.rstrip(os.sep)}_notifications"}
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

                append_log("[*] Capturing configured accounts (adb shell dumpsys account)...")
                account_count = _capture_android_accounts(serial, output_path, os.path.dirname(output_path))
                if account_count:
                    append_log(f"[+] Captured {account_count} configured account(s) - searchable in File "
                               "Views and on the Evidence Timeline.")
                    report_data["acquisition_parameters"]["accounts_captured"] = account_count
                else:
                    append_log("[-] Could not capture configured accounts (device disconnected, no "
                               "accounts configured, or dumpsys returned nothing usable) - best-effort "
                               "enrichment, the pull itself is unaffected.")

                append_log("[*] Capturing a notification snapshot (adb shell dumpsys notification)...")
                notif_count = _capture_android_notification_snapshot(serial, output_path, os.path.dirname(output_path))
                if notif_count:
                    append_log(f"[+] Captured {notif_count} currently-visible notification(s) - package/"
                               "time/importance only, real content is redacted by the OS by default. "
                               "Searchable in File Views and on the Evidence Timeline.")
                    report_data["acquisition_parameters"]["notifications_captured"] = notif_count
                else:
                    append_log("[-] Could not capture a notification snapshot (device disconnected, no "
                               "notifications currently visible, or dumpsys returned nothing usable) - "
                               "best-effort enrichment, the pull itself is unaffected.")
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


# --- Companion-app unified extraction (non-rooted), 2026-09-04 ---
# All six data types (SMS/Contacts/Call Log/Calendar/Photos/Video) share
# ONE consolidated flow now, replacing three earlier separate panels/
# workers/route pairs (one per data type, each independently installing
# and uninstalling the same collector) - a real UX problem the user
# flagged directly once a 4th panel (Calendar) made the "individual boxes"
# approach visibly unwieldy: "wouldn't we just have a drop down or check
# boxes with the items we want to pull and then click start extraction?
# instead of individual boxes?" This installs pif-companion.apk exactly
# ONCE regardless of how many data types are selected, grants only the
# permissions actually needed for whatever's checked, runs each selected
# query in sequence, then reverses every change and uninstalls once at
# the end - one combined case-report event/manifest, not one per type.
#
# core/android_companion_{sms,contacts_calllog,calendar,media}_utils.py's
# own parsing/record-building functions are completely unchanged and
# still each module's own single source of truth for their respective
# data type - only the ORCHESTRATION (what installs/grants/queries/
# cleans up, and in what order) is consolidated here.
ANDROID_COMPANION_APK_DIR = os.path.join(INSTALL_DIR, "android_companion_tools")
# All five providers (SMS/Contacts/Call Log/Calendar/Photos+Video) ship in
# this one app - see android_companion/README.md for its full provenance.
PIF_COMPANION_APK = os.path.join(ANDROID_COMPANION_APK_DIR, "pif-companion.apk")
ANDROID_COMPANION_ADB_TIMEOUT = 30
# A large SMS/media-index content query can genuinely take longer to
# stream out over adb than a short pm/cmd call - given its own headroom,
# distinct from ANDROID_COMPANION_ADB_TIMEOUT above.
ANDROID_COMPANION_QUERY_TIMEOUT = 180

_ANDROID_COMPANION_SMS_TIER_RE = re.compile(r'^(readonly|full)$')
_ANDROID_COMPANION_KNOWN_TYPES = {"sms", "contacts", "calllog", "calendar", "images", "video"}


def _adb_run(serial, args, timeout):
    """Small shared helper for one short adb command against `serial` -
    every step of execution_worker_android_companion_extraction() below is
    exactly one of these, so the worker's own step sequence stays
    readable instead of repeating subprocess.run(...) boilerplate at every
    step. Returns (returncode, stdout, stderr); never raises - a timeout
    or any other exception is folded into a synthetic -1 returncode with
    the exception text as stderr, so every call site can check
    .returncode uniformly without its own try/except."""
    try:
        result = subprocess.run(["adb", "-s", serial] + args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def execution_worker_android_companion_extraction(serial, selected_types, sms_tier, output_path,
                                                     report_file_path, report_data, case_folder,
                                                     requester_ip=None, requester_user=None):
    """Installs the vendored pif-companion collector ONCE, grants exactly
    the permissions needed for whichever of `selected_types` (a set/list
    drawn from {'sms','contacts','calllog','calendar','images','video'})
    was checked, runs each selected type's own query in sequence, then
    ALWAYS reverses every change (revoke every permission actually
    granted, restore the original default SMS app if that role was
    assumed, uninstall the collector) before finishing - cleanup runs in
    the outer `finally` block regardless of success, failure, or a Stop
    request partway through, matching every prior single-type companion
    worker's own established reasoning exactly (a phone left with a
    reassigned default SMS app or a still-permission-granted collector
    would be a real, ongoing problem for the device, not just a loose end
    in this app's own bookkeeping).

    `requester_ip`/`requester_user` are captured by the route handler in
    the real request thread and passed through explicitly - this worker
    runs in a background daemon thread with no Flask request context, the
    identical capture-before-spawn fix this codebase has now applied to
    every companion worker (and several other background-thread call
    sites: network config's delayed-revert thread, the image triage scan
    job, chained_auto_analyze).

    `sms_tier` ('readonly' or 'full') only matters when 'sms' is one of
    the selected types - ignored otherwise. Every permission is granted
    UP FRONT, for every selected type, before any query runs - mirrors the
    exact "grant everything needed, then query everything selected"
    ordering the old Contacts/Call Log worker already established for its
    own two data types, generalized here to as many as six. Stop is
    checked once before permission-granting even begins (a Stop that
    lands there skips both granting and querying entirely, restoring
    nothing since nothing was ever changed beyond the install itself) and
    again between each selected type's own query (a Stop landing there
    still reports COMPLETED with whatever was already captured - the
    exact asymmetry the Contacts/Call Log worker's own docstring already
    documented, generalized: a genuinely stopped run is only ever reported
    IN_PROGRESS if it stopped before EVERY query ran, never after at least
    one succeeded, since real data was already captured and indexed by
    that point).

    device_log (written into both the manifest JSON and the case report
    event's own acquisition_parameters) is the actual chain-of-custody-
    honest record of what changed on the device and when - not a debug
    log, the primary disclosure artifact this whole feature exists to
    produce alongside the extracted data itself."""
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    device_log = {
        "selected_types": sorted(selected_types), "sms_tier": sms_tier if "sms" in selected_types else None,
        "steps": [], "sms_count": 0, "contact_count": 0, "call_log_count": 0,
        "event_count": 0, "attendee_count": 0, "image_count": 0, "video_count": 0,
    }

    def record_step(name, rc, note=""):
        device_log["steps"].append({"step": name, "returncode": rc, "note": note,
                                     "at": time.strftime("%Y-%m-%d %H:%M:%S")})

    apk_installed = False
    original_sms_role_holder = None
    sms_role_assumed = False
    sms_permission_granted = False
    contacts_granted = False
    calllog_granted = False
    calendar_granted = False
    media_granted_any = False
    query_ran_at_least_once = False

    try:
        update_job(format="android_companion_extraction", status="Initializing...", progress_percent=0.0,
                   log=f"[*] Initializing companion-app extraction ({', '.join(sorted(selected_types))}) on {serial}...")

        if not os.path.isfile(PIF_COMPANION_APK):
            raise RuntimeError(
                "pif-companion.apk is not vendored on this station - re-run install.py with internet "
                "access to download it, then retry."
            )

        append_log(f"[*] Installing companion collector ({PIF_COMPANION_PACKAGE})...")
        rc, out, err = _adb_run(serial, ["install", "-r", PIF_COMPANION_APK], ANDROID_COMPANION_ADB_TIMEOUT)
        record_step("install", rc, (out + err).strip()[:500])
        if rc != 0:
            raise RuntimeError(f"adb install failed: {(err or out).strip()[:300]}")
        apk_installed = True
        append_log("[+] Collector installed.")

        if snapshot_job()["status"] == "Stopped":
            append_log("[!] Stop requested before granting any permission - skipping everything below, "
                       "still uninstalling the collector.")
        else:
            if "sms" in selected_types:
                if sms_tier == "full":
                    update_job(status="Checking current default SMS app...")
                    rc, out, err = _adb_run(serial, ["shell", "cmd", "role", "get-role-holders",
                                                      "android.app.role.SMS"], ANDROID_COMPANION_ADB_TIMEOUT)
                    original_sms_role_holder = out.strip().splitlines()[0].strip() if (rc == 0 and out.strip()) else None
                    record_step("get-role-holders", rc, f"original={original_sms_role_holder!r}")
                    append_log(f"[*] Current default SMS app: {original_sms_role_holder or '(none currently set)'}")

                    update_job(status="Assuming default-SMS-app role (full access)...")
                    append_log("[*] Temporarily assuming the default-SMS-app role for full SMS access - the "
                               "phone's own SMS app will not receive/send normal messages until this is "
                               "restored below.")
                    rc, out, err = _adb_run(
                        serial, ["shell", "cmd", "role", "add-role-holder", "android.app.role.SMS",
                                 PIF_COMPANION_PACKAGE], ANDROID_COMPANION_ADB_TIMEOUT)
                    record_step("add-role-holder", rc, (out + err).strip()[:300])
                    if rc != 0:
                        raise RuntimeError(f"Could not assume the default SMS app role: {(err or out).strip()[:300]}")
                    sms_role_assumed = True
                else:
                    update_job(status="Granting READ_SMS permission (read-only tier)...")
                    append_log("[*] Granting READ_SMS permission (read-only tier - inbox/sent only).")
                    rc, out, err = _adb_run(
                        serial, ["shell", "pm", "grant", PIF_COMPANION_PACKAGE, "android.permission.READ_SMS"],
                        ANDROID_COMPANION_ADB_TIMEOUT)
                    record_step("pm_grant_sms", rc, (out + err).strip()[:300])
                    if rc != 0:
                        raise RuntimeError(f"Could not grant READ_SMS: {(err or out).strip()[:300]}")
                    sms_permission_granted = True

            if "contacts" in selected_types:
                update_job(status="Granting READ_CONTACTS permission...")
                append_log("[*] Granting READ_CONTACTS permission.")
                rc, out, err = _adb_run(
                    serial, ["shell", "pm", "grant", PIF_COMPANION_PACKAGE, "android.permission.READ_CONTACTS"],
                    ANDROID_COMPANION_ADB_TIMEOUT)
                record_step("pm_grant_contacts", rc, (out + err).strip()[:300])
                if rc != 0:
                    raise RuntimeError(f"Could not grant READ_CONTACTS: {(err or out).strip()[:300]}")
                contacts_granted = True

            if "calllog" in selected_types:
                update_job(status="Granting READ_CALL_LOG permission...")
                append_log("[*] Granting READ_CALL_LOG permission.")
                rc, out, err = _adb_run(
                    serial, ["shell", "pm", "grant", PIF_COMPANION_PACKAGE, "android.permission.READ_CALL_LOG"],
                    ANDROID_COMPANION_ADB_TIMEOUT)
                record_step("pm_grant_calllog", rc, (out + err).strip()[:300])
                if rc != 0:
                    raise RuntimeError(f"Could not grant READ_CALL_LOG: {(err or out).strip()[:300]}")
                calllog_granted = True

            if "calendar" in selected_types:
                update_job(status="Granting READ_CALENDAR permission...")
                append_log("[*] Granting READ_CALENDAR permission.")
                rc, out, err = _adb_run(
                    serial, ["shell", "pm", "grant", PIF_COMPANION_PACKAGE, "android.permission.READ_CALENDAR"],
                    ANDROID_COMPANION_ADB_TIMEOUT)
                record_step("pm_grant_calendar", rc, (out + err).strip()[:300])
                if rc != 0:
                    raise RuntimeError(f"Could not grant READ_CALENDAR: {(err or out).strip()[:300]}")
                calendar_granted = True

            if "images" in selected_types or "video" in selected_types:
                # All three possible media-read permissions are attempted
                # independently and non-fatally - which one(s) actually
                # exist/matter depends on the connected device's own
                # Android version (READ_MEDIA_IMAGES/VIDEO on 13+,
                # READ_EXTERNAL_STORAGE on older devices), and there's no
                # need to detect the exact API level here when the real
                # query itself is the true signal of whether access
                # worked - see core/android_companion_media_utils.py's
                # own docstring.
                update_job(status="Granting media (Photos/Video) permissions...")
                append_log("[*] Granting media read permissions (attempting all of READ_MEDIA_IMAGES/"
                           "READ_MEDIA_VIDEO/READ_EXTERNAL_STORAGE - which apply depends on the device's "
                           "own Android version).")
                for perm in ("android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                             "android.permission.READ_EXTERNAL_STORAGE"):
                    rc, out, err = _adb_run(serial, ["shell", "pm", "grant", PIF_COMPANION_PACKAGE, perm],
                                             ANDROID_COMPANION_ADB_TIMEOUT)
                    record_step(f"pm_grant_{perm.rsplit('.', 1)[-1].lower()}", rc, (out + err).strip()[:200])
                    if rc == 0:
                        media_granted_any = True
                if not media_granted_any:
                    append_log("[!] Could not grant any media permission - the Photos/Video query below will "
                               "likely fail, but continuing (other selected types may still succeed).")

        if snapshot_job()["status"] == "Stopped":
            append_log("[!] Stop requested before any query ran - skipping every query, still restoring "
                       "device state below.")
        else:
            all_records = []

            if "sms" in selected_types and (sms_permission_granted or sms_role_assumed):
                update_job(status="Querying SMS content...")
                append_log("[*] Querying SMS content via the collector's relay ContentProvider...")
                projection = ":".join(SMS_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query", "--uri", f"content://{PIF_COMPANION_SMS_AUTHORITY}",
                             "--projection", projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_sms", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                if rc != 0:
                    append_log(f"[!] SMS query failed: {(err or out).strip()[:300]}")
                else:
                    rows = parse_content_query_output(out)
                    records = build_companion_sms_records(rows)
                    all_records.extend(records)
                    device_log["sms_count"] = len(records)
                    append_log(f"[+] Parsed {len(records)} SMS record(s).")

            if snapshot_job()["status"] != "Stopped" and "contacts" in selected_types and contacts_granted:
                update_job(status="Querying Contacts...")
                append_log("[*] Querying Contacts via the collector's relay ContentProvider...")
                projection = ":".join(CONTACTS_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query", "--uri", f"content://{PIF_COMPANION_CONTACTS_AUTHORITY}/data",
                             "--projection", projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_contacts", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                if rc != 0:
                    append_log(f"[!] Contacts query failed: {(err or out).strip()[:300]}")
                else:
                    rows = parse_content_query_output(out, columns=CONTACTS_QUERY_COLUMNS)
                    records = build_companion_contact_records(rows)
                    all_records.extend(records)
                    device_log["contact_count"] = len(records)
                    append_log(f"[+] Parsed {len(records)} contact detail record(s).")

            if snapshot_job()["status"] != "Stopped" and "calllog" in selected_types and calllog_granted:
                update_job(status="Querying Call Log...")
                append_log("[*] Querying Call Log via the collector's relay ContentProvider...")
                projection = ":".join(CALLLOG_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query", "--uri", f"content://{PIF_COMPANION_CALLLOG_AUTHORITY}/calls",
                             "--projection", projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_calllog", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                if rc != 0:
                    append_log(f"[!] Call Log query failed: {(err or out).strip()[:300]}")
                else:
                    rows = parse_content_query_output(out, columns=CALLLOG_QUERY_COLUMNS)
                    records = build_companion_call_log_records(rows)
                    all_records.extend(records)
                    device_log["call_log_count"] = len(records)
                    append_log(f"[+] Parsed {len(records)} call log record(s).")

            if snapshot_job()["status"] != "Stopped" and "calendar" in selected_types and calendar_granted:
                update_job(status="Querying Calendar Events...")
                append_log("[*] Querying Calendar Events via the collector's relay ContentProvider...")
                events_projection = ":".join(CALENDAR_EVENTS_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query", "--uri", f"content://{PIF_COMPANION_CALENDAR_AUTHORITY}/events",
                             "--projection", events_projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_events", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                event_rows = []
                if rc != 0:
                    append_log(f"[!] Calendar Events query failed: {(err or out).strip()[:300]}")
                else:
                    event_rows = parse_content_query_output(out, columns=CALENDAR_EVENTS_QUERY_COLUMNS)
                    append_log(f"[+] Found {len(event_rows)} calendar event(s).")

                update_job(status="Querying Calendar Attendees...")
                append_log("[*] Querying Calendar Attendees via the collector's relay ContentProvider...")
                attendees_projection = ":".join(CALENDAR_ATTENDEES_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query", "--uri", f"content://{PIF_COMPANION_CALENDAR_AUTHORITY}/attendees",
                             "--projection", attendees_projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_attendees", rc, f"{len((out or '').splitlines())} line(s) returned")
                attendee_rows = []
                if rc != 0:
                    append_log(f"[!] Calendar Attendees query failed: {(err or out).strip()[:300]}")
                else:
                    attendee_rows = parse_content_query_output(out, columns=CALENDAR_ATTENDEES_QUERY_COLUMNS)
                    append_log(f"[+] Found {len(attendee_rows)} attendee record(s).")

                event_records = build_companion_calendar_records(event_rows, attendee_rows)
                all_records.extend(event_records)
                device_log["event_count"] = len(event_records)
                device_log["attendee_count"] = len(attendee_rows)

            if snapshot_job()["status"] != "Stopped" and "images" in selected_types and media_granted_any:
                update_job(status="Querying Photos (images)...")
                append_log("[*] Querying Photos via the collector's relay ContentProvider...")
                projection = ":".join(MEDIA_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query",
                             "--uri", f"content://{PIF_COMPANION_MEDIA_AUTHORITY}/external/images/media",
                             "--projection", projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_images", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                if rc != 0:
                    append_log(f"[!] Photos query failed: {(err or out).strip()[:300]}")
                else:
                    rows = parse_content_query_output(out, columns=MEDIA_QUERY_COLUMNS)
                    records = build_companion_media_records(rows, "image")
                    all_records.extend(records)
                    device_log["image_count"] = len(records)
                    append_log(f"[+] Parsed {len(records)} photo metadata record(s).")

            if snapshot_job()["status"] != "Stopped" and "video" in selected_types and media_granted_any:
                update_job(status="Querying Video...")
                append_log("[*] Querying Video via the collector's relay ContentProvider...")
                projection = ":".join(MEDIA_QUERY_COLUMNS)
                rc, out, err = _adb_run(
                    serial, ["shell", "content", "query",
                             "--uri", f"content://{PIF_COMPANION_MEDIA_AUTHORITY}/external/video/media",
                             "--projection", projection], ANDROID_COMPANION_QUERY_TIMEOUT)
                record_step("content_query_video", rc, f"{len((out or '').splitlines())} line(s) returned")
                query_ran_at_least_once = True
                if rc != 0:
                    append_log(f"[!] Video query failed: {(err or out).strip()[:300]}")
                else:
                    rows = parse_content_query_output(out, columns=MEDIA_QUERY_COLUMNS)
                    records = build_companion_media_records(rows, "video")
                    all_records.extend(records)
                    device_log["video_count"] = len(records)
                    append_log(f"[+] Parsed {len(records)} video metadata record(s).")

            if all_records:
                identity = {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                            "path": output_path}
                indexed = _record_parsed_artifacts(case_folder, identity, all_records)
                if indexed:
                    append_log(f"[+] Indexed {indexed} record(s) into the case's searchable Parsed "
                               "Artifacts and the Evidence Timeline.")

            if query_ran_at_least_once:
                report_data["acquisition_parameters"]["sms_records_captured"] = device_log["sms_count"]
                report_data["acquisition_parameters"]["contact_records_captured"] = device_log["contact_count"]
                report_data["acquisition_parameters"]["call_log_records_captured"] = device_log["call_log_count"]
                report_data["acquisition_parameters"]["event_records_captured"] = device_log["event_count"]
                report_data["acquisition_parameters"]["attendee_records_captured"] = device_log["attendee_count"]
                report_data["acquisition_parameters"]["image_records_captured"] = device_log["image_count"]
                report_data["acquisition_parameters"]["video_records_captured"] = device_log["video_count"]
                report_data["acquisition_status"] = "COMPLETED"

    except Exception as e:
        error_message = str(e)
        append_log(f"[!] {error_message}")
        report_data["acquisition_status"] = "FAILED"
        report_data["error"] = error_message

    finally:
        # Cleanup always runs here, regardless of the try block's outcome -
        # see this function's own docstring for why. Every step is
        # attempted independently (one failing doesn't skip the next).
        append_log("[*] Restoring device state...")

        if sms_role_assumed:
            if original_sms_role_holder:
                rc, out, err = _adb_run(
                    serial, ["shell", "cmd", "role", "add-role-holder", "android.app.role.SMS",
                             original_sms_role_holder], ANDROID_COMPANION_ADB_TIMEOUT)
                record_step("restore-role-holder", rc, f"restored to {original_sms_role_holder}")
            else:
                rc, out, err = _adb_run(
                    serial, ["shell", "cmd", "role", "remove-role-holder", "android.app.role.SMS",
                             PIF_COMPANION_PACKAGE], ANDROID_COMPANION_ADB_TIMEOUT)
                record_step("remove-role-holder", rc, "no prior default SMS app - role removed entirely")
            if rc != 0:
                append_log("[!!] Could not automatically restore the device's default SMS app - a manual "
                           "fix may be needed on the device itself (Settings > Apps > Default apps > "
                           "SMS app).")
            else:
                append_log("[+] Default SMS app restored.")

        if sms_permission_granted:
            rc, out, err = _adb_run(
                serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, "android.permission.READ_SMS"],
                ANDROID_COMPANION_ADB_TIMEOUT)
            record_step("pm_revoke_sms", rc)

        if contacts_granted:
            rc, out, err = _adb_run(
                serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, "android.permission.READ_CONTACTS"],
                ANDROID_COMPANION_ADB_TIMEOUT)
            record_step("pm_revoke_contacts", rc)

        if calllog_granted:
            rc, out, err = _adb_run(
                serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, "android.permission.READ_CALL_LOG"],
                ANDROID_COMPANION_ADB_TIMEOUT)
            record_step("pm_revoke_calllog", rc)

        if calendar_granted:
            rc, out, err = _adb_run(
                serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, "android.permission.READ_CALENDAR"],
                ANDROID_COMPANION_ADB_TIMEOUT)
            record_step("pm_revoke_calendar", rc)

        if media_granted_any:
            for perm in ("android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                         "android.permission.READ_EXTERNAL_STORAGE"):
                rc, out, err = _adb_run(serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, perm],
                                         ANDROID_COMPANION_ADB_TIMEOUT)
                record_step(f"pm_revoke_{perm.rsplit('.', 1)[-1].lower()}", rc)

        if apk_installed:
            rc, out, err = _adb_run(serial, ["uninstall", PIF_COMPANION_PACKAGE], ANDROID_COMPANION_ADB_TIMEOUT)
            record_step("uninstall", rc)
            if rc != 0:
                append_log(f"[!!] Could not automatically uninstall the collector - manually run "
                           f"'adb uninstall {PIF_COMPANION_PACKAGE}' against the device to remove it.")
            else:
                append_log("[+] Collector uninstalled.")

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["acquisition_parameters"]["device_modification_log"] = device_log

        try:
            with open(output_path, "w") as f:
                json.dump({
                    "source": "pif-companion.apk relay (hand-built for this app, mirroring "
                              "github.com/gonodono/adbsms's own relay-provider design)",
                    "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "selected_types": sorted(selected_types),
                    "sms_count": device_log["sms_count"], "contact_count": device_log["contact_count"],
                    "call_log_count": device_log["call_log_count"], "event_count": device_log["event_count"],
                    "attendee_count": device_log["attendee_count"], "image_count": device_log["image_count"],
                    "video_count": device_log["video_count"],
                    "device_modification_log": device_log,
                    "note": "This action installed a small app on the device once, granted exactly the "
                            "permissions needed for whichever data types were selected, queried each of "
                            "them, then reversed every change and uninstalled the app - see "
                            "device_modification_log above for the exact sequence and outcome of each "
                            "step.",
                }, f, indent=2)
            _auto_tag_case_artifact(case_folder, output_path)
        except OSError:
            pass

        _write_report(report_file_path, report_data, append_log)
        log_chain_of_custody("android_companion_extract", {
            "serial": serial, "selected_types": sorted(selected_types),
            "sms_count": device_log["sms_count"], "contact_count": device_log["contact_count"],
            "call_log_count": device_log["call_log_count"], "event_count": device_log["event_count"],
            "image_count": device_log["image_count"], "video_count": device_log["video_count"],
            "status": report_data["acquisition_status"],
            "device_modification_log": device_log,
        }, source_ip=requester_ip, user=requester_user)

        final_status = None
        if report_data["acquisition_status"] == "COMPLETED":
            final_status = "Completed Successfully"
        elif report_data["acquisition_status"] == "FAILED":
            final_status = "Failed"
        if final_status:
            update_job(status=final_status, progress_percent=100.0, active=False)
        else:
            update_job(active=False)


@mobile_bp.route('/api/mobile/android/companion_extraction/start', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def start_android_companion_extraction():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    serial = req.get('serial', '')
    selected_types = set(req.get('selected_types') or [])
    sms_tier = req.get('sms_tier', 'readonly')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if not _ANDROID_SERIAL_RE.match(serial or ''):
        update_job(active=False)
        return jsonify({"error": "Invalid or missing device serial. Refresh the device list and select "
                                  "a connected, authorized Android device."}), 400
    if not selected_types or not selected_types.issubset(_ANDROID_COMPANION_KNOWN_TYPES):
        update_job(active=False)
        return jsonify({"error": "Select at least one valid data type to extract."}), 400
    if "sms" in selected_types and not _ANDROID_COMPANION_SMS_TIER_RE.match(sms_tier or ''):
        update_job(active=False)
        return jsonify({"error": "sms_tier must be 'readonly' or 'full'."}), 400
    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400
    try:
        os.makedirs(dest_path, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_android_companion_extraction"
    output_path = os.path.join(dest_path, f"{base_name}_extraction.json")

    report_data = {
        "tool": "android_companion_extraction",
        "case_metadata": metadata,
        "device_serial": serial,
        "acquisition_parameters": {
            "platform": "Android",
            "method": "pif-companion.apk relay (installs/modifies/restores device state - see "
                      "device_modification_log)",
            "selected_types": sorted(selected_types),
            "output_destination": output_path,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    # Captured here, in the real request thread, and passed through
    # explicitly - see execution_worker_android_companion_extraction()'s
    # own docstring for why this matters.
    requester_ip = request.remote_addr
    requester_user = getattr(g, 'forensic_user', None)

    thread = threading.Thread(
        target=execution_worker_android_companion_extraction,
        args=(serial, selected_types, sms_tier, output_path, report_target, report_data, dest_path,
              requester_ip, requester_user)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("android_companion_extract_start",
                          {"serial": serial, "selected_types": sorted(selected_types), "destination": output_path})
    return jsonify({"success": True, "message": "Companion-app extraction started."})


@mobile_bp.route('/api/mobile/android/companion_extraction/cleanup', methods=['POST'])
@requires_auth
@requires_permission('mobile')
def cleanup_android_companion_extraction():
    """Manual safety-net cleanup, reachable at any time a device is
    connected, independent of this app's own job state - revokes every
    permission this feature could ever have granted (each attempt is
    independent and harmless if that permission was never actually
    granted in the first place) and reverses the SMS default-app role if
    currently held, then uninstalls the collector. Mirrors every prior
    single-type companion cleanup route's own established reasoning,
    generalized to cover all six data types with one shared action -
    since a previously-interrupted run could have been extracting any
    subset of them, this always attempts every possible reversal rather
    than requiring the examiner to remember which specific run was
    interrupted."""
    req = request.get_json() or {}
    serial = req.get('serial', '')
    if not _ANDROID_SERIAL_RE.match(serial or ''):
        return jsonify({"error": "Invalid or missing device serial."}), 400

    results = {}
    rc, out, err = _adb_run(serial, ["shell", "cmd", "role", "get-role-holders", "android.app.role.SMS"],
                             ANDROID_COMPANION_ADB_TIMEOUT)
    current_holder = out.strip().splitlines()[0].strip() if (rc == 0 and out.strip()) else None
    if current_holder == PIF_COMPANION_PACKAGE:
        rc, out, err = _adb_run(serial, ["shell", "cmd", "role", "remove-role-holder", "android.app.role.SMS",
                                          PIF_COMPANION_PACKAGE], ANDROID_COMPANION_ADB_TIMEOUT)
        results["sms_role_removed"] = (rc == 0)

    for perm in ("android.permission.READ_SMS", "android.permission.READ_CONTACTS",
                 "android.permission.READ_CALL_LOG", "android.permission.READ_CALENDAR",
                 "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                 "android.permission.READ_EXTERNAL_STORAGE"):
        rc, out, err = _adb_run(serial, ["shell", "pm", "revoke", PIF_COMPANION_PACKAGE, perm],
                                 ANDROID_COMPANION_ADB_TIMEOUT)
        results[f"{perm.rsplit('.', 1)[-1].lower()}_revoked"] = (rc == 0)

    rc, out, err = _adb_run(serial, ["uninstall", PIF_COMPANION_PACKAGE], ANDROID_COMPANION_ADB_TIMEOUT)
    results["uninstalled"] = (rc == 0)

    log_chain_of_custody("android_companion_manual_cleanup", {"serial": serial, "results": results})
    return jsonify({"success": True, "results": results})
