import os
import time
import subprocess
import threading
import json
import psutil
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

ACTIVE_PROCESS = None

IMAGING_STATE = {
    "active": False,
    "progress_percent": 0.0,
    "speed_mbps": 0.0,
    "transferred_bytes": 0,
    "total_bytes": 0,
    "status": "Idle",
    "log": "[INFO] System initialized.",
    "error_details": ""
}

def execute_cmd(cmd):
    """Utility helper to execute shell commands cleanly."""
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip()}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/system_info', methods=['GET'])
def get_system_info():
    usage = psutil.disk_usage('/')
    cpu_percent = psutil.cpu_percent(interval=None)
    wb_status = "Enabled" if os.path.exists("/etc/udev/rules.d/00-write-block.rules") else "Disabled"
    
    return jsonify({
        "cpu_percent": cpu_percent,
        "local_storage": {
            "total_gb": round(usage.total / (1024**3), 2),
            "used_gb": round(usage.used / (1024**3), 2),
            "free_gb": round(usage.free / (1024**3), 2),
            "percent_used": usage.percent
        },
        "write_blocker_active": wb_status == "Enabled"
    })

@app.route('/api/drives', methods=['GET'])
def list_drives():
    try:
        output = subprocess.check_output(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MODEL,TRAN,RO"]).decode('utf-8')
        devices = json.loads(output).get("blockdevices", [])
        drives = [d for d in devices if d.get("type") == "disk"]
        return jsonify(drives)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/smart_check', methods=['POST'])
def smart_check():
    """Queries smartctl for source drive health telemetry."""
    data = request.json or {}
    drive = data.get("drive", "").strip()

    if not drive or not os.path.exists(drive):
        return jsonify({"success": False, "error": "Invalid drive path specified."}), 400

    try:
        cmd = f"sudo smartctl -a -j {drive}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        try:
            smart_data = json.loads(res.stdout)
        except Exception:
            return jsonify({"success": False, "error": f"Drive does not support SMART or response was unparseable.\n{res.stdout or res.stderr}"}), 400

        healthy = smart_data.get("smart_status", {}).get("passed", True)
        family = smart_data.get("model_family") or smart_data.get("model_name") or "Generic Drive"
        serial = smart_data.get("serial_number", "Unknown")
        temp = smart_data.get("temperature", {}).get("current")

        reallocated = 0
        pending = 0
        power_hours = None

        for attr in smart_data.get("ata_smart_attributes", {}).get("table", []):
            attr_id = attr.get("id")
            if attr_id == 5:
                reallocated = attr.get("raw", {}).get("value", 0)
            elif attr_id == 197:
                pending = attr.get("raw", {}).get("value", 0)
            elif attr_id == 9:
                power_hours = attr.get("raw", {}).get("value")

        if reallocated > 0 or pending > 0:
            healthy = False

        return jsonify({
            "success": True,
            "healthy": healthy,
            "model": family,
            "serial": serial,
            "temperature": temp,
            "reallocated_sectors": reallocated,
            "pending_sectors": pending,
            "power_on_hours": power_hours
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/list_folders', methods=['POST'])
def list_folders():
    data = request.json or {}
    path = data.get("path", "/mnt")
    
    if not os.path.exists(path) or not os.path.isdir(path):
        path = "/"

    try:
        entries = os.listdir(path)
        folders = []
        for entry in sorted(entries):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path) and not entry.startswith('.'):
                folders.append(entry)
        return jsonify({"current_path": os.path.abspath(path), "folders": folders})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/list_server_shares', methods=['POST'])
def list_server_shares():
    data = request.json or {}
    protocol = data.get("protocol", "cifs")
    host = data.get("host", "").strip()
    user = data.get("user", "").strip()
    password = data.get("pass", "").strip()

    if not host:
        return jsonify({"success": False, "error": "Server IP address is required."}), 400

    shares = []

    if protocol == "cifs":
        cred_flag = f"-U '{user}%{password}'" if user else "-N"
        cmd = f"smbclient -L //{host} {cred_flag} -g 2>/dev/null"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "NT_STATUS_ACCESS_DENIED" in res.stderr or "NT_STATUS_LOGON_FAILURE" in res.stderr:
            return jsonify({"success": False, "auth_required": True, "error": "Authentication required."}), 401
            
        for line in res.stdout.splitlines():
            if line.startswith("Disk|"):
                share_name = line.split("|")[1]
                if not share_name.endswith("$"):
                    shares.append(share_name)

    elif protocol == "nfs":
        cmd = f"showmount -e '{host}' --no-headers 2>/dev/null"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if parts:
                shares.append(parts[0])

    return jsonify({"success": True, "shares": shares})

@app.route('/api/mount_network', methods=['POST'])
def mount_network():
    data = request.json or {}
    protocol = data.get("protocol", "cifs")
    host = data.get("host", "").strip()
    share = data.get("share", "").strip()
    user = data.get("user", "").strip()
    password = data.get("pass", "").strip()

    if not host or not share:
        return jsonify({"success": False, "error": "Server IP and Share path are required."}), 400

    mount_point = "/mnt/network_evidence"
    
    try:
        os.makedirs(mount_point, exist_ok=True)
        subprocess.run(f"sudo umount -l '{mount_point}' 2>/dev/null", shell=True)
    except Exception:
        pass

    if protocol == "cifs":
        clean_share = share.strip('/')
        remote_path = f"//{host}/{clean_share}"
        options = ["rw", "file_mode=0777", "dir_mode=0777", "noperm"]
        if user:
            options.append(f'username="{user}"')
            options.append(f'password="{password}"')
        else:
            options.append("guest")

        opt_str = ",".join(options)
        cmd = f"sudo mount -t cifs '{remote_path}' '{mount_point}' -o '{opt_str}'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if res.returncode != 0 and "Permission denied" not in res.stderr:
            for ver in ["3.0", "2.1", "1.0"]:
                fallback_cmd = f"sudo mount -t cifs '{remote_path}' '{mount_point}' -o '{opt_str},vers={ver}'"
                res = subprocess.run(fallback_cmd, shell=True, capture_output=True, text=True)
                if res.returncode == 0:
                    break

    elif protocol == "nfs":
        clean_share = '/' + share.strip('/')
        remote_path = f"{host}:{clean_share}"
        
        cmd_v4 = f"sudo mount -t nfs -o vers=4,rw,soft,timeo=30,retry=1,nolock,proto=tcp '{remote_path}' '{mount_point}'"
        res = subprocess.run(cmd_v4, shell=True, capture_output=True, text=True)
        
        if res.returncode != 0:
            cmd_v3 = f"sudo mount -t nfs -o vers=3,rw,soft,timeo=30,retry=1,nolock,proto=tcp '{remote_path}' '{mount_point}'"
            res = subprocess.run(cmd_v3, shell=True, capture_output=True, text=True)

    elif protocol == "curlftpfs":
        user_pass = f"{user}:{password}@" if user else ""
        clean_share = share.strip('/')
        cmd = f"sudo curlftpfs 'ftp://{user_pass}{host}/{clean_share}' '{mount_point}' -o allow_other"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    else:
        return jsonify({"success": False, "error": "Unsupported protocol."}), 400

    if res.returncode == 0:
        return jsonify({"success": True, "mount_point": mount_point})
    else:
        err_msg = res.stderr.strip() or res.stdout.strip() or "Connection timed out or failed."
        return jsonify({"success": False, "error": f"Mount Failed: {err_msg}"}), 400

@app.route('/api/toggle_write_block', methods=['POST'])
def toggle_write_block():
    data = request.json
    enable = data.get("enable", True)
    rule_path = "/etc/udev/rules.d/00-write-block.rules"
    
    try:
        if enable:
            rule_content = 'ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z]", ATTR{ro}="1"'
            execute_cmd(f'echo \'{rule_content}\' | sudo tee {rule_path}')
            execute_cmd("sudo udevadm control --reload-rules")
            execute_cmd("sudo blockdev --setro /dev/sd* 2>/dev/null || true")
        else:
            if os.path.exists(rule_path):
                execute_cmd(f"sudo rm -f {rule_path}")
            execute_cmd("sudo udevadm control --reload-rules")
            execute_cmd("sudo blockdev --setrw /dev/sd* 2>/dev/null || true")
            
        return jsonify({"success": True, "enabled": enable})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def write_case_manifest(output_base_path, metadata, source_dev, size_bytes, hash_str, start_time, end_time):
    """Generates JSON and human-readable evidence manifest reports."""
    manifest_data = {
        "case_metadata": metadata,
        "acquisition_details": {
            "source_device": source_dev,
            "image_file": os.path.basename(output_base_path),
            "size_bytes": size_bytes,
            "size_gb": round(size_bytes / (1024**3), 2),
            "hashes_configured": hash_str,
            "start_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
            "completion_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time)),
            "elapsed_seconds": int(end_time - start_time)
        },
        "system_info": {
            "platform": "Raspberry Pi ARM Forensic Station",
            "write_blocker_active": os.path.exists("/etc/udev/rules.d/00-write-block.rules")
        }
    }

    # Write JSON Manifest
    json_path = output_base_path + "_manifest.json"
    with open(json_path, "w") as f:
        json.dump(manifest_data, f, indent=4)

    # Write Text Manifest
    txt_path = output_base_path + "_manifest.txt"
    with open(txt_path, "w") as f:
        f.write("========================================================\n")
        f.write("         DIGITAL FORENSIC EVIDENCE MANIFEST\n")
        f.write("========================================================\n\n")
        f.write(f"Case Number      : {metadata.get('case_number')}\n")
        f.write(f"Evidence Item ID : {metadata.get('evidence_id')}\n")
        f.write(f"Examiner Name    : {metadata.get('examiner')}\n")
        f.write(f"Notes / Summary  : {metadata.get('notes')}\n\n")
        f.write("--------------------------------------------------------\n")
        f.write("ACQUISITION METADATA\n")
        f.write("--------------------------------------------------------\n")
        f.write(f"Source Drive     : {source_dev}\n")
        f.write(f"Output Image     : {os.path.basename(output_base_path)}\n")
        f.write(f"Total Bytes      : {size_bytes:,} bytes ({round(size_bytes/(1024**3), 2)} GB)\n")
        f.write(f"Hashes Engine    : {hash_str}\n")
        f.write(f"Start Time       : {manifest_data['acquisition_details']['start_time']}\n")
        f.write(f"Completion Time  : {manifest_data['acquisition_details']['completion_time']}\n")
        f.write(f"Total Duration   : {manifest_data['acquisition_details']['elapsed_seconds']} seconds\n")
        f.write(f"Write Blocker    : {'ACTIVE' if manifest_data['system_info']['write_blocker_active'] else 'DISABLED'}\n")
        f.write("========================================================\n")

def run_imaging_task(source_dev, dest_path, hashes=None, metadata=None, buffer_size="1M"):
    """Background worker executing dc3dd acquisition and manifest generation."""
    global IMAGING_STATE, ACTIVE_PROCESS
    if hashes is None:
        hashes = {"md5": True, "sha1": False, "sha256": False}
    if metadata is None:
        metadata = {}

    IMAGING_STATE["active"] = True
    IMAGING_STATE["status"] = "Imaging in progress..."
    IMAGING_STATE["progress_percent"] = 0.0
    IMAGING_STATE["error_details"] = ""
    IMAGING_STATE["log"] = f"[START] dc3dd if={source_dev} of={dest_path} bufsz={buffer_size}\n"
    
    try:
        size_bytes = int(execute_cmd(f"blockdev --getsize64 {source_dev}"))
    except Exception:
        size_bytes = 0

    IMAGING_STATE["total_bytes"] = size_bytes
    log_file = dest_path + ".log"
    
    cmd = [
        "sudo", "dc3dd", 
        f"if={source_dev}", 
        f"of={dest_path}", 
        f"log={log_file}",
        f"bufsz={buffer_size}"
    ]

    selected_hashes = []
    if hashes.get("md5"):
        cmd.append("hash=md5")
        selected_hashes.append("MD5")
    if hashes.get("sha1"):
        cmd.append("hash=sha1")
        selected_hashes.append("SHA-1")
    if hashes.get("sha256"):
        cmd.append("hash=sha256")
        selected_hashes.append("SHA-256")

    has_hashes = len(selected_hashes) > 0
    hash_str = ", ".join(selected_hashes) if has_hashes else "Disabled"

    start_time = time.time()
    verify_start_time = None
    sync_counter = 0
    
    ACTIVE_PROCESS = subprocess.Popen(
        cmd, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )

    while ACTIVE_PROCESS.poll() is None:
        time.sleep(1)
        sync_counter += 1
        
        if sync_counter >= 3:
            try:
                os.sync()
            except Exception:
                pass
            sync_counter = 0

        if os.path.exists(dest_path):
            current_bytes = os.path.getsize(dest_path)
            elapsed = time.time() - start_time
            
            speed = (current_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0
            raw_percent = (current_bytes / size_bytes * 100) if size_bytes > 0 else 0
            
            percent = min(round(raw_percent, 2), 99.0)
            
            IMAGING_STATE["transferred_bytes"] = current_bytes
            IMAGING_STATE["speed_mbps"] = round(speed, 2)
            IMAGING_STATE["progress_percent"] = percent

            if raw_percent >= 99.0:
                if verify_start_time is None:
                    verify_start_time = time.time()
                v_elapsed = int(time.time() - verify_start_time)
                
                if has_hashes:
                    IMAGING_STATE["status"] = "Verifying Hashes..."
                    IMAGING_STATE["log"] = (
                        f"[RAW WRITE COMPLETE] All blocks transferred ({round(current_bytes/(1024**2), 1)} MB).\n"
                        f"[STATUS] Computing {hash_str} hashes... (Elapsed Verification Time: {v_elapsed}s)\n"
                    )
                else:
                    IMAGING_STATE["status"] = "Flushing Disk Cache..."
                    IMAGING_STATE["log"] = (
                        f"[RAW WRITE COMPLETE] All blocks transferred ({round(current_bytes/(1024**2), 1)} MB).\n"
                        f"[STATUS] Flushing remaining write buffers to storage target... (Elapsed: {v_elapsed}s)\n"
                    )
            else:
                IMAGING_STATE["log"] = (
                    f"[RUNNING] Processed: {round(current_bytes/(1024**2), 1)} MB / {round(size_bytes/(1024**2), 1)} MB ({percent}%)\n"
                    f"[SPEED] Transfer velocity: {round(speed, 2)} MB/s\n"
                    f"[HASHES] {hash_str}"
                )

    return_code = ACTIVE_PROCESS.wait()
    end_time = time.time()

    if return_code == 0:
        IMAGING_STATE["progress_percent"] = 100.0
        IMAGING_STATE["status"] = "Completed Successfully"
        
        # Generate Manifests
        try:
            write_case_manifest(dest_path, metadata, source_dev, size_bytes, hash_str, start_time, end_time)
            manifest_msg = "\n[MANIFEST] Evidence manifest reports generated (.json & .txt)."
        except Exception as e:
            manifest_msg = f"\n[MANIFEST WARNING] Could not generate manifest: {str(e)}"

        IMAGING_STATE["log"] = f"[FINISHED] Acquisition Complete! ({hash_str}){manifest_msg}\n\nImage, log, and manifest saved successfully."
    elif IMAGING_STATE["status"] == "Stopped":
        IMAGING_STATE["log"] += "\n[ABORTED] Process terminated manually by user."
    else:
        IMAGING_STATE["status"] = "Failed"
        IMAGING_STATE["error_details"] = f"dc3dd process returned non-zero exit code {return_code}."
        IMAGING_STATE["log"] = f"[ERROR] Acquisition Failed!\nError Details:\n{IMAGING_STATE['error_details']}"
        
    IMAGING_STATE["active"] = False
    ACTIVE_PROCESS = None

@app.route('/api/start_imaging', methods=['POST'])
def start_imaging():
    if IMAGING_STATE["active"]:
        return jsonify({"error": "An acquisition task is already running."}), 400

    data = request.json
    source_device = data.get("source")
    dest_type = data.get("dest_type", "local")
    hashes = data.get("hashes", {"md5": True, "sha1": False, "sha256": False})
    metadata = data.get("metadata", {})
    
    if not source_device or not os.path.exists(source_device):
        return jsonify({"error": "Invalid source drive selected."}), 400

    timestamp = time.strftime("%Y%m%d_%H%M%S")

    if dest_type == "network":
        output_directory = "/mnt/network_evidence"
    else:
        output_directory = data.get("destination", "/mnt")

    if not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)

    evidence_id_safe = metadata.get("evidence_id", "ITEM").replace(" ", "_")
    output_file = os.path.join(output_directory, f"{evidence_id_safe}_{timestamp}.dd")

    thread = threading.Thread(target=run_imaging_task, args=(source_device, output_file, hashes, metadata))
    thread.start()

    return jsonify({"success": True, "output_file": output_file})

@app.route('/api/stop_imaging', methods=['POST'])
def stop_imaging():
    global ACTIVE_PROCESS, IMAGING_STATE
    if ACTIVE_PROCESS and IMAGING_STATE["active"]:
        IMAGING_STATE["status"] = "Stopped"
        subprocess.run(["sudo", "pkill", "-9", "-f", "dc3dd"])
        return jsonify({"success": True, "message": "Imaging operation aborted."})
    return jsonify({"error": "No active imaging process found."}), 400

@app.route('/api/progress', methods=['GET'])
def get_progress():
    return jsonify(IMAGING_STATE)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
