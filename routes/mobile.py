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

from flask import Blueprint, jsonify, request

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody
from core.config import EVIDENCE_ROOT
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job, poll_directory_size,
    _stream_subprocess, clear_active_proc,
    build_report_target, write_initial_report, _write_report,
)
from core.case_index_db import _auto_tag_case_artifact

mobile_bp = Blueprint('mobile', __name__)

# --- Mobile Device Discovery (iOS via libimobiledevice, Android via adb) ---
# These only talk to devices that are already unlocked and have already
# granted trust (iOS "Trust This Computer?") or USB debugging authorization
# (Android RSA key prompt) on-device. Nothing here bypasses a lockscreen,
# jailbreaks, or exploits a device - nothing in this app does.
_UDID_RE = re.compile(r'^[a-fA-F0-9\-]{20,64}$')
_ANDROID_SERIAL_RE = re.compile(r'^[a-zA-Z0-9_\-\.:]{4,64}$')


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
            }, f)
    except OSError:
        return 0
    return len(files)


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
            cmd = ["adb", "-s", serial, "pull", "/sdcard/.", output_path]
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

    if mode not in ('backup', 'pull', 'bugreport'):
        update_job(active=False)
        return jsonify({"error": "mode must be 'backup', 'pull', or 'bugreport'."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_android_{mode}"

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
