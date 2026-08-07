import os
import re
import time
import json
import fcntl
import signal
import psutil
import subprocess
import threading
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__)

# Authentication Config (Defaults to admin/forensics if not set via environment)
ADMIN_USER = os.environ.get('FORENSIC_USER', 'admin')
ADMIN_PASS = os.environ.get('FORENSIC_PASS', 'forensics')

HISTORY_FILE = "/opt/pi-forensics/mount_history.json"

# Global State for Live Acquisition Job
current_job = {
    "active": False,
    "format": "dd",
    "progress_percent": 0.0,
    "speed_mbps": 0.0,
    "transferred_bytes": 0,
    "total_bytes": 0,
    "status": "IDLE",
    "log": "[System initialized and idle. Ready for disk acquisition job.]"
}

active_proc = None
last_net_check = {"time": time.time(), "bytes_sent": 0, "bytes_recv": 0}

# --- Persistence Helpers ---
def load_mount_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_mount_history(entry):
    history = load_mount_history()
    # Deduplicate entries by host and share path
    history = [h for h in history if not (h.get("host") == entry.get("host") and h.get("share") == entry.get("share"))]
    history.insert(0, entry)
    history = history[:10]  # Store top 10 most recent mounts
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving mount history: {e}")

# --- Authentication Middleware ---
def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return Response(
        'Authentication required to access ARM Forensic Station.\n',
        401,
        {'WWW-Authenticate': 'Basic realm="Forensic Station Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        
        # Auto-bypass auth for localhost, loopback, and local private subnets
        if client_ip in ['127.0.0.1', '::1', 'localhost'] or \
           client_ip.startswith('192.168.') or \
           client_ip.startswith('10.') or \
           client_ip.startswith('172.'):
            return f(*args, **kwargs)
        
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- Hash Output Parsers ---
def parse_dc3dd_hashes(log_path):
    hashes = {}
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                content = f.read()
                # Captures standard dc3dd log format (case-insensitive): "md5: [hash]" or "sha256 hash: [hash]"
                matches = re.findall(r'(\b(?:md5|sha1|sha256)\b)[^\n:]*:\s*([a-fA-F0-9]{32,64})', content, re.IGNORECASE)
                for algo, val in matches:
                    hashes[algo.lower()] = val
        except Exception as e:
            print(f"Error parsing dc3dd hash log: {e}")
    return hashes

def parse_ewf_hashes(console_log_text):
    hashes = {}
    try:
        # Captures ewfacquire console output format
        matches = re.findall(r'(\b(?:MD5|SHA1|SHA256)\b)\s*(?:hash|hash stored in file)?:?\s*([a-fA-F0-9]{32,64})', console_log_text, re.IGNORECASE)
        for algo, val in matches:
            hashes[algo.lower()] = val
    except Exception as e:
        print(f"Error parsing ewf hashes: {e}")
    return hashes

# --- Regex Progress Parsers ---
def parse_dc3dd_line(line):
    m = re.search(r'(\d+)\s+bytes.*copied.*,\s*([\d\.]+)\s*MB/s', line, re.IGNORECASE)
    if m:
        return int(m.group(1)), float(m.group(2))
    return None, None

def parse_ewf_line(line):
    m_pct = re.search(r'(\d+)%\s*(?:acquired|done|completed|written|verified)?', line, re.IGNORECASE)
    m_spd = re.search(r'([\d\.]+)\s*(?:MiB|MB|KiB|KB)/s', line, re.IGNORECASE)
    pct = float(m_pct.group(1)) if m_pct else None
    spd = float(m_spd.group(1)) if m_spd else None
    return pct, spd

# --- Non-Blocking Worker Thread ---
def execution_worker(cmd, fmt, total_bytes, out_file, report_file_path, report_data):
    global current_job, active_proc
    log_history = []
    
    def append_log(msg):
        log_history.append(msg)
        current_job["log"] = "\n".join(log_history[-100:])

    append_log(f"[*] Starting acquisition process using tool [{fmt.upper()}]...")
    append_log(f"[*] Command: {' '.join(cmd)}")

    start_time = time.time()
    last_check = start_time
    last_bytes = 0

    try:
        active_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            preexec_fn=os.setsid  # Creates process group ID for easy group killing
        )
        current_job["status"] = "Acquiring Evidence..."

        buffer = ""
        fd = active_proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        while True:
            time.sleep(0.2)  # Fast poll loop prevents buffer delay and UI stream freezes
            now = time.time()
            elapsed = now - last_check

            # Direct disk size telemetry check
            if os.path.exists(out_file):
                try:
                    curr_size = os.path.getsize(out_file)
                    delta = curr_size - last_bytes
                    if elapsed > 0:
                        speed_calc = round((delta / (1024 * 1024)) / elapsed, 2)
                        current_job["speed_mbps"] = speed_calc
                        current_job["transferred_bytes"] = curr_size
                        if total_bytes > 0:
                            current_job["progress_percent"] = min(round((curr_size / total_bytes) * 100, 1), 99.9)
                    last_bytes = curr_size
                    last_check = now
                except Exception:
                    pass

            try:
                raw_bytes = os.read(fd, 1024)
                if not raw_bytes and active_proc.poll() is not None:
                    break
                if raw_bytes:
                    text_chunk = raw_bytes.decode('utf-8', errors='ignore')
                    for char in text_chunk:
                        # Flush buffer on carriage returns (\r) OR newlines (\n)
                        if char in ['\r', '\n']:
                            line_str = buffer.strip()
                            buffer = ""
                            if not line_str:
                                continue
                            
                            append_log(line_str)

                            if fmt in ['raw', 'dd']:
                                bytes_copied, speed = parse_dc3dd_line(line_str)
                                if bytes_copied is not None:
                                    current_job["transferred_bytes"] = bytes_copied
                                    if total_bytes > 0:
                                        current_job["progress_percent"] = round((bytes_copied / total_bytes) * 100, 1)
                                if speed is not None:
                                    current_job["speed_mbps"] = speed

                            elif fmt == 'e01':
                                pct, speed = parse_ewf_line(line_str)
                                if "verify" in line_str.lower() or "verifying" in line_str.lower():
                                    current_job["status"] = "Verifying Image Integrity..."
                                
                                if pct is not None:
                                    current_job["progress_percent"] = pct
                                    if total_bytes > 0:
                                        current_job["transferred_bytes"] = int((pct / 100.0) * total_bytes)
                                if speed is not None:
                                    current_job["speed_mbps"] = speed
                        else:
                            buffer += char
            except (OSError, IOError):
                pass

        active_proc.wait()

        if active_proc.returncode == 0:
            current_job["status"] = "Completed Successfully"
            current_job["progress_percent"] = 100.0
            current_job["speed_mbps"] = 0.0
            append_log("[+] Acquisition completed successfully.")

            # Short delay allows network drive buffers to completely flush the log file
            time.sleep(1.0)

            # Parse computed hashes based on selected format engine
            if fmt == 'e01':
                computed_hashes = parse_ewf_hashes(current_job["log"])
            else:
                dc3dd_log = out_file.replace('.dd', '_dc3dd.log')
                computed_hashes = parse_dc3dd_hashes(dc3dd_log)

            report_data["acquisition_status"] = "COMPLETED"
            report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
            report_data["computed_verification_hashes"] = computed_hashes

            try:
                with open(report_file_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                append_log(f"[+] Forensic case report updated: {report_file_path}")
            except Exception as e:
                append_log(f"[-] Warning: Failed updating report JSON: {e}")

        elif current_job["status"] != "Stopped":
            current_job["status"] = "Failed"
            append_log(f"[-] Process exited with exit code: {active_proc.returncode}")
            report_data["acquisition_status"] = "FAILED"
            try:
                with open(report_file_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
            except Exception:
                pass

    except Exception as e:
        current_job["status"] = "Failed"
        append_log(f"[-] Execution error: {str(e)}")

    finally:
        current_job["active"] = False
        active_proc = None

# --- Web Routes & API Endpoints ---
@app.route('/')
@requires_auth
def index():
    return render_template('index.html')

@app.route('/api/system_info', methods=['GET'])
@requires_auth
def system_info():
    global last_net_check
    
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    root_disk = psutil.disk_usage('/')
    
    now = time.time()
    net_counters = psutil.net_io_counters()
    time_delta = max(now - last_net_check["time"], 0.001)
    
    sent_delta = net_counters.bytes_sent - last_net_check["bytes_sent"]
    recv_delta = net_counters.bytes_recv - last_net_check["bytes_recv"]
    
    if last_net_check["bytes_sent"] == 0:
        sent_delta = 0
        recv_delta = 0
        
    upload_mbps = round((sent_delta / (1024 * 1024)) / time_delta, 2)
    download_mbps = round((recv_delta / (1024 * 1024)) / time_delta, 2)
    
    last_net_check = {
        "time": now,
        "bytes_sent": net_counters.bytes_sent,
        "bytes_recv": net_counters.bytes_recv
    }

    wb_active = True
    try:
        res = subprocess.run(['sudo', 'blockdev', '--getro', '/dev/sda'], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip() == '0':
            wb_active = False
    except Exception:
        pass

    return jsonify({
        "cpu_percent": cpu,
        "memory": {
            "used_gb": round(mem.used / (1024**3), 2),
            "total_gb": round(mem.total / (1024**3), 2),
            "percent_used": mem.percent
        },
        "network_speed": {
            "upload_mbps": upload_mbps,
            "download_mbps": download_mbps
        },
        "local_storage": {
            "used_gb": round(root_disk.used / (1024**3), 2),
            "total_gb": round(root_disk.total / (1024**3), 2),
            "percent_used": root_disk.percent
        },
        "write_blocker_active": wb_active
    })

@app.route('/api/drives', methods=['GET'])
@requires_auth
def list_drives():
    drives = []
    try:
        res = subprocess.run(
            ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,MODEL,TRAN,TYPE,SERIAL'],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') == 'disk' and not dev['name'].startswith('loop'):
                    bytes_size = int(dev.get('size', 0))
                    gb_size = round(bytes_size / (1024**3), 1)
                    
                    drives.append({
                        "name": dev['name'],
                        "device": f"/dev/{dev['name']}",
                        "model": dev.get('model') or 'Generic Disk',
                        "size": f"{gb_size} GB",
                        "bytes": bytes_size,
                        "transport": dev.get('tran') or 'sata',
                        "serial": dev.get('serial') or 'N/A'
                    })
    except Exception as e:
        print(f"Error executing lsblk: {e}")
        
    return jsonify(drives)

@app.route('/api/smart_check', methods=['POST'])
@requires_auth
def smart_check():
    req = request.get_json() or {}
    drive = req.get('drive', '')
    
    if not drive or not drive.startswith('/dev/'):
        return jsonify({"success": False, "error": "Invalid drive selection"})

    try:
        res = subprocess.run(['sudo', 'smartctl', '-a', '-j', drive], capture_output=True, text=True)
        data = json.loads(res.stdout)
        
        healthy = data.get('smart_status', {}).get('passed', True)
        
        family = data.get('model_family') or data.get('family_name')
        model = data.get('model_name') or data.get('device', {}).get('name')
        
        if family and model and family.lower() not in model.lower():
            vendor_model_str = f"{family} ({model})"
        elif family:
            vendor_model_str = family
        else:
            vendor_model_str = model or "Generic Media"

        serial = data.get('serial_number', 'N/A')
        temp = data.get('temperature', {}).get('current')
        
        dev_type = data.get('device', {}).get('type', '')
        protocol = data.get('device', {}).get('protocol', '')
        media_type = f"{protocol.upper()} / {dev_type.upper()} Storage" if protocol else "USB / ATA Storage"

        reallocated = 0
        pending = 0
        power_on = None
        
        for attr in data.get('ata_smart_attributes', {}).get('table', []):
            attr_id = attr.get('id')
            if attr_id == 5:
                reallocated = attr.get('raw', {}).get('value', 0)
            elif attr_id == 197:
                pending = attr.get('raw', {}).get('value', 0)
            elif attr_id == 9:
                power_on = attr.get('raw', {}).get('value')

        return jsonify({
            "success": True,
            "healthy": healthy,
            "vendor_model": vendor_model_str,
            "media_type": media_type,
            "serial": serial,
            "temperature": temp,
            "reallocated_sectors": reallocated,
            "pending_sectors": pending,
            "power_on_hours": power_on
        })

    except Exception:
        return jsonify({
            "success": False,
            "error": "SMART telemetry unsupported on this media",
            "vendor_model": "Generic External Drive / Flash Media"
        })

@app.route('/api/mount_history', methods=['GET'])
@requires_auth
def get_mount_history():
    return jsonify(load_mount_history())

@app.route('/api/list_server_shares', methods=['POST'])
@requires_auth
def list_server_shares():
    req = request.get_json() or {}
    protocol = req.get('protocol', 'smb').lower()
    host = req.get('host', '').strip()

    if not host:
        return jsonify({"success": False, "error": "Server IP required."}), 400

    shares = []
    try:
        if protocol == 'nfs':
            res = subprocess.run(['showmount', '-e', '--no-headers', host], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.strip().split('\n'):
                    if line:
                        export_path = line.split()[0]
                        shares.append(export_path)
                return jsonify({"success": True, "shares": shares})
            else:
                return jsonify({"success": False, "error": res.stderr.strip()}), 500
        else:
            user = req.get('user', 'guest')
            pass_val = req.get('pass', '')
            cmd = ['smbclient', '-L', host, '-U', f"{user}%{pass_val}", '-g']
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith('Disk|'):
                        parts = line.split('|')
                        if len(parts) > 1 and not parts[1].endswith('$'):
                            shares.append(parts[1])
                return jsonify({"success": True, "shares": shares})

        return jsonify({"success": True, "shares": shares})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/mount_network', methods=['POST'])
@requires_auth
def mount_network():
    req = request.get_json() or {}
    protocol = req.get('protocol', 'smb').lower()
    host = req.get('host', '').strip()
    share = req.get('share', '').strip()
    user = req.get('user', '').strip()
    password = req.get('pass', '').strip()

    if not host or not share:
        return jsonify({"success": False, "error": "Server IP and Share path are required."}), 400

    share_path = f"/{share.lstrip('/')}"
    safe_folder_name = share_path.replace('/', '_').strip('_')
    mount_point = f"/mnt/network_{protocol}_{safe_folder_name}"
    os.makedirs(mount_point, exist_ok=True)

    try:
        subprocess.run(['sudo', 'umount', '-l', mount_point], capture_output=True)

        if protocol == 'nfs':
            nfs_source = f"{host}:{share_path}"
            
            cmd_v3 = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,soft,timeo=30,retrans=2,vers=3', nfs_source, mount_point]
            res = subprocess.run(cmd_v3, capture_output=True, text=True)

            if res.returncode == 0:
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            cmd_v4 = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,soft,timeo=30,retrans=2,vers=4', nfs_source, mount_point]
            res_v4 = subprocess.run(cmd_v4, capture_output=True, text=True)

            if res_v4.returncode == 0:
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            return jsonify({"success": False, "error": f"NFS Mount Failed: {res_v4.stderr.strip() or res.stderr.strip()}"}), 500

        else:
            unc_source = f"//{host}/{share_path.lstrip('/')}"
            user_arg = user if user else 'guest'
            pass_arg = password if password else ''
            opts = f"username={user_arg},password={pass_arg},noperm,iocharset=utf8"
            
            cmd_smb = ['sudo', 'mount', '-t', 'cifs', unc_source, mount_point, '-o', opts]
            res_smb = subprocess.run(cmd_smb, capture_output=True, text=True)

            if res_smb.returncode == 0:
                save_mount_history({"protocol": protocol, "host": host, "share": share_path, "mount_point": mount_point})
                return jsonify({"success": True, "mount_point": mount_point})

            return jsonify({"success": False, "error": f"SMB Mount Failed: {res_smb.stderr.strip()}"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/toggle_write_block', methods=['POST'])
@requires_auth
def toggle_write_block():
    req = request.get_json() or {}
    enable = req.get('enable', True)
    drive = req.get('drive', '/dev/sda')
    
    if not drive.startswith('/dev/'):
        drive = '/dev/sda'

    action_flag = '--setro' if enable else '--setrw'
    
    try:
        subprocess.run(f"sudo udevil unmount -b {drive}* 2>/dev/null || sudo umount {drive}* 2>/dev/null", shell=True)
        res = subprocess.run(['sudo', 'blockdev', action_flag, drive], capture_output=True, text=True)
        
        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr.strip() or "blockdev execution failed"}), 500

        chk = subprocess.run(['sudo', 'blockdev', '--getro', drive], capture_output=True, text=True)
        is_ro = (chk.returncode == 0 and chk.stdout.strip() == '1')

        return jsonify({"success": True, "write_blocker_active": is_ro, "device": drive})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start_imaging', methods=['POST'])
@requires_auth
def start_imaging():
    global current_job
    
    if current_job["active"]:
        return jsonify({"error": "An acquisition job is already running."}), 400

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = req.get('destination', '/mnt').strip()
    fmt = req.get('format', 'dd')
    hashes = req.get('hashes', ['sha256'])
    metadata = req.get('metadata', {})
    
    if not source or not os.path.exists(source):
        return jsonify({"error": f"Source device {source} not found."}), 400

    if not os.path.exists(dest_path):
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    smart_data = {}
    try:
        res_smart = subprocess.run(['sudo', 'smartctl', '-a', '-j', source], capture_output=True, text=True)
        if res_smart.stdout:
            smart_data = json.loads(res_smart.stdout)
    except Exception:
        pass

    total_bytes = 0
    try:
        res = subprocess.run(['blockdev', '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    if family and family.lower() not in model.lower():
        vendor_model = f"{family} ({model})"
    else:
        vendor_model = model

    serial = smart_data.get('serial_number', 'N/A')
    healthy = smart_data.get('smart_status', {}).get('passed', True)
    temp = smart_data.get('temperature', {}).get('current')
    power_hours = smart_data.get('power_on_time', {}).get('hours')
    
    reallocated = 0
    pending = 0
    for attr in smart_data.get('ata_smart_attributes', {}).get('table', []):
        attr_id = attr.get('id')
        if attr_id == 5:
            reallocated = attr.get('raw', {}).get('value', 0)
        elif attr_id == 197:
            pending = attr.get('raw', {}).get('value', 0)

    drive_telemetry = {
        "device_path": source,
        "vendor_model": vendor_model,
        "serial_number": serial,
        "capacity_bytes": total_bytes,
        "capacity_gb": round(total_bytes / (1024**3), 2),
        "smart_healthy": healthy,
        "temperature_celsius": temp,
        "power_on_hours": power_hours,
        "reallocated_sectors": reallocated,
        "pending_sectors": pending
    }

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    examiner = metadata.get('examiner', 'UNSPECIFIED')
    notes = metadata.get('notes', 'None')
    base_name = f"{case_num}_{evidence_id}"

    if fmt == 'e01':
        ewf_hash_type = "sha256"
        if "sha256" in hashes:
            ewf_hash_type = "sha256"
        elif "sha1" in hashes:
            ewf_hash_type = "sha1"
        elif "md5" in hashes:
            ewf_hash_type = "md5"

        out_file = f"{dest_path}/{base_name}.E01"
        cmd = [
            "ewfacquire", "-u",
            "-t", f"{dest_path}/{base_name}",
            "-C", case_num,
            "-E", evidence_id,
            "-e", examiner,
            "-N", notes,
            "-f", "encase6",
            "-d", ewf_hash_type,
            "-S", "2000M",
            source
        ]
    else:
        out_file = f"{dest_path}/{base_name}.dd"
        cmd = [
            "dc3dd",
            f"if={source}",
            f"of={out_file}",
            f"log={dest_path}/{base_name}_dc3dd.log"
        ]
        for h in hashes:
            cmd.append(f"hash={h}")

    current_job["active"] = True
    current_job["format"] = fmt
    current_job["progress_percent"] = 0.0
    current_job["speed_mbps"] = 0.0
    current_job["transferred_bytes"] = 0
    current_job["total_bytes"] = total_bytes
    current_job["status"] = "Initializing..."
    current_job["log"] = f"[*] Initializing {fmt.upper()} acquisition ({', '.join(hashes).upper()}) for {source} -> {dest_path}..."

    report_file = os.path.join(dest_path, f"{base_name}_report.json")
    report_data = {
        "case_metadata": metadata,
        "source_drive_telemetry": drive_telemetry,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": fmt,
            "requested_hashes": hashes,
            "execution_command": " ".join(cmd)
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    try:
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not write case report JSON: {e}")

    thread = threading.Thread(
        target=execution_worker,
        args=(cmd, fmt, total_bytes, out_file, report_file, report_data)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"success": True, "message": "Acquisition started."})

@app.route('/api/stop_imaging', methods=['POST'])
@requires_auth
def stop_imaging():
    global current_job, active_proc
    if current_job["active"]:
        try:
            if active_proc and active_proc.poll() is None:
                os.killpg(os.getpgid(active_proc.pid), signal.SIGKILL)
        except Exception as e:
            print(f"Error killing process group: {e}")

        for tool in ["dc3dd", "ewfacquire"]:
            try:
                subprocess.run(["pkill", "-9", tool], capture_output=True)
            except Exception:
                pass

        current_job["status"] = "Stopped"
        current_job["active"] = False
        current_job["log"] += "\n[!] Acquisition manually terminated by user."
        return jsonify({"success": True, "message": "Acquisition stopped."})
        
    return jsonify({"error": "No active job running."}), 400

@app.route('/api/progress', methods=['GET'])
@requires_auth
def get_progress():
    return jsonify({
        "active": current_job["active"],
        "format": current_job["format"],
        "progress_percent": current_job["progress_percent"],
        "speed_mbps": current_job["speed_mbps"],
        "transferred_bytes": current_job["transferred_bytes"],
        "total_bytes": current_job["total_bytes"],
        "status": current_job["status"],
        "log": current_job["log"]
    })

@app.route('/api/list_folders', methods=['POST'])
@requires_auth
def list_folders():
    req = request.get_json() or {}
    path = req.get('path', '/mnt')
    if not os.path.exists(path):
        path = '/mnt'
    try:
        folders = [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]
        return jsonify({"current_path": path, "folders": sorted(folders)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
