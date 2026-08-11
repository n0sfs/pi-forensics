import os
import re
import time
import json
import fcntl
import signal
import psutil
import shutil
import hashlib
import subprocess
import threading
import secrets
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response, send_file

app = Flask(__name__)

# Authentication Config – MUST be set via environment (install.py does this)
ADMIN_USER = os.environ.get('FORENSIC_USER', 'admin')
ADMIN_PASS = os.environ.get('FORENSIC_PASS', '')
# Private-network auth bypass is OFF by default. Set FORENSIC_AUTH_BYPASS=1 only for legacy labs.
AUTH_BYPASS_PRIVATE = os.environ.get('FORENSIC_AUTH_BYPASS', '0') == '1'
# Refuse known-weak default password at runtime
_WEAK_PASSWORDS = {'', 'forensics', 'password', 'admin', 'changeme', '123456', 'pi'}

HISTORY_FILE = "/opt/pi-forensics/mount_history.json"
CRED_DIR = Path("/opt/pi-forensics/run")  # ephemeral credential files for mounts

# Allowed roots for file browser / copy / delete / report operations
ALLOWED_ROOTS = [
    Path("/mnt"),
    Path("/media"),
    Path("/opt/pi-forensics"),
    Path("/tmp/forensic"),
]

# Absolute paths matching sudoers
BIN_BLOCKDEV = "/usr/sbin/blockdev"
BIN_SMARTCTL = "/usr/sbin/smartctl"
BIN_MOUNT = "/bin/mount"
BIN_UMOUNT = "/bin/umount"
BIN_UDEVIL = "/usr/bin/udevil"
BIN_PKILL = "/usr/bin/pkill"
BIN_SMBCLIENT = "/usr/bin/smbclient"
BIN_SHOWMOUNT = "/usr/sbin/showmount"
BIN_DC3DD = "/usr/bin/dc3dd"
BIN_DDRESCUE = "/usr/bin/ddrescue"
BIN_EWFACQUIRE = "/usr/bin/ewfacquire"
BIN_LSBLK = "/usr/bin/lsblk"


# Global State for Live Acquisition Job (protected by lock)
job_lock = threading.RLock()
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
        except Exception as e:
            print(f"Error loading mount history: {e}")
            return []
    return []

def save_mount_history(entry):
    history = load_mount_history()
    history = [h for h in history if not (h.get("host") == entry.get("host") and h.get("share") == entry.get("share"))]
    history.insert(0, entry)
    history = history[:10]
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving mount history: {e}")

# --- Path / device sanitization helpers ---
def safe_path(user_path: str, must_exist: bool = True) -> Path:
    """Resolve and validate a user-supplied path against ALLOWED_ROOTS."""
    if not user_path or not isinstance(user_path, str):
        raise ValueError("Path is required")
    if '\0' in user_path:
        raise ValueError("Invalid characters in path")
    try:
        p = Path(user_path).resolve(strict=False)
    except Exception as e:
        raise ValueError(f"Cannot resolve path: {e}")
    allowed = False
    for root in ALLOWED_ROOTS:
        try:
            root_res = root.resolve()
            if p == root_res or root_res in p.parents:
                allowed = True
                break
        except Exception:
            continue
    if not allowed:
        raise ValueError(f"Path '{user_path}' is outside allowed directories")
    if must_exist and not p.exists():
        raise ValueError(f"Path does not exist: {user_path}")
    return p


def sanitize_device(dev: str) -> str:
    """Allow only legitimate block device paths."""
    if not dev or not isinstance(dev, str):
        raise ValueError("Device path required")
    dev = dev.strip()
    if not re.match(r'^/dev/(sd[a-z]+|nvme\d+n\d+|mmcblk\d+|vd[a-z]+|xvd[a-z]+)(\d+p?\d*)?$', dev):
        raise ValueError(f"Invalid or disallowed device: {dev}")
    if not os.path.exists(dev):
        raise ValueError(f"Device does not exist: {dev}")
    return dev


def sanitize_name(name: str, max_len: int = 64) -> str:
    if not name:
        return "UNASSIGNED"
    cleaned = re.sub(r'[^A-Za-z0-9_\-\.]', '_', str(name))[:max_len]
    return cleaned or "UNASSIGNED"


def sanitize_host(host: str) -> str:
    host = (host or '').strip()
    if not host or not re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$', host):
        raise ValueError("Invalid server hostname or IP")
    if '..' in host:
        raise ValueError("Invalid server hostname or IP")
    return host


def sanitize_share(share: str) -> str:
    share = (share or '').strip()
    if not share or re.search(r'[;&|`$<>\\n\\r]', share):
        raise ValueError("Invalid share path")
    # Keep path-ish characters only
    if not re.match(r'^[A-Za-z0-9_/\.\- ]{1,256}$', share):
        raise ValueError("Invalid share path characters")
    return share


def write_smb_credentials(username: str, password: str) -> Path:
    """Write a temporary credentials file (mode 0600) for mount.cifs / smbclient."""
    CRED_DIR.mkdir(parents=True, exist_ok=True)
    # Restrict directory
    try:
        os.chmod(CRED_DIR, 0o700)
    except Exception:
        pass
    path = CRED_DIR / f"smbcred_{secrets.token_hex(8)}.txt"
    content = f"username={username or 'guest'}\npassword={password or ''}\n"
    path.write_text(content)
    os.chmod(path, 0o600)
    return path


def credentials_are_safe() -> bool:
    """Return False if the configured web password is missing or known-weak."""
    if not ADMIN_PASS:
        return False
    if ADMIN_PASS.lower() in _WEAK_PASSWORDS:
        return False
    if len(ADMIN_PASS) < 8:
        return False
    return True


# --- Authentication Middleware ---
def check_auth(username, password):
    if not credentials_are_safe():
        return False
    return secrets.compare_digest(username or '', ADMIN_USER) and \
           secrets.compare_digest(password or '', ADMIN_PASS)

def authenticate():
    if not credentials_are_safe():
        return Response(
            'Server misconfigured: weak or missing FORENSIC_PASS. '
            'Set a strong password via the service environment and restart.\n',
            503,
            {'Content-Type': 'text/plain'}
        )
    return Response(
        'Authentication required to access ARM Forensic Station.\n',
        401,
        {'WWW-Authenticate': 'Basic realm="Forensic Station Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr or ''
        # Optional legacy bypass (disabled by default)
        if AUTH_BYPASS_PRIVATE:
            if client_ip in ('127.0.0.1', '::1', 'localhost') or \
               client_ip.startswith(('192.168.', '10.', '172.')):
                return f(*args, **kwargs)
        # Loopback (kiosk) always allowed unless FORENSIC_FORCE_LOCAL_AUTH=1
        if client_ip in ('127.0.0.1', '::1'):
            if os.environ.get('FORENSIC_FORCE_LOCAL_AUTH', '0') == '1':
                auth = request.authorization
                if not auth or not check_auth(auth.username, auth.password):
                    return authenticate()
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- Hash & Recovery Output Parsers ---
def parse_dc3dd_hashes(log_path):
    hashes = {}
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                content = f.read()
                matches = re.findall(r'([a-fA-F0-9]{32,64})\s*\(\s*(\b(?:md5|sha1|sha256)\b)\s*\)', content, re.IGNORECASE)
                for val, algo in matches:
                    hashes[algo.lower()] = val
                    
                if not hashes:
                    fallback_matches = re.findall(r'(\b(?:md5|sha1|sha256)\b)[^\n:]*:\s*([a-fA-F0-9]{32,64})', content, re.IGNORECASE)
                    for algo, val in fallback_matches:
                        hashes[algo.lower()] = val
        except Exception as e:
            print(f"Error parsing dc3dd log: {e}")
    return hashes

def parse_ewf_hashes(console_log_text):
    hashes = {}
    try:
        matches = re.findall(r'(\b(?:MD5|SHA1|SHA256)\b)\s*(?:hash|hash stored in file)?:?\s*([a-fA-F0-9]{32,64})', console_log_text, re.IGNORECASE)
        for algo, val in matches:
            hashes[algo.lower()] = val
    except Exception as e:
        print(f"Error parsing ewf hashes: {e}")
    return hashes

def parse_dc3dd_line(line):
    m = re.search(r'(\d+)\s+bytes.*copied.*,\s*([\d\.]+)\s*(MB|MiB|KB|GB|M|K)/s', line, re.IGNORECASE)
    if m:
        bytes_copied = int(m.group(1))
        speed_val = float(m.group(2))
        unit = m.group(3).upper()
        
        if unit in ['KB', 'K']:
            speed_val /= 1024.0
        elif unit in ['GB', 'G']:
            speed_val *= 1024.0
            
        return bytes_copied, speed_val
    return None, None

def parse_ewf_line(line):
    m_pct = re.search(r'(\d+)%\s*(?:acquired|done|completed|verified)?', line, re.IGNORECASE)
    m_spd = re.search(r'([\d\.]+)\s*(?:MiB|MB|KiB|KB)/s', line, re.IGNORECASE)
    pct = float(m_pct.group(1)) if m_pct else None
    spd = float(m_spd.group(1)) if m_spd else None
    return pct, spd

def parse_ddrescue_line(line):
    rescued_bytes = None
    pct = None
    spd = None
    
    m_rescued = re.search(r'rescued:\s*([\d\.]+)\s*([KMGT]?B)', line, re.IGNORECASE)
    m_spd = re.search(r'current_rate:\s*([\d\.]+)\s*([KMGT]?B/s)', line, re.IGNORECASE)
    m_pct = re.search(r'pct_rescued:\s*([\d\.]+)\%', line, re.IGNORECASE)

    def to_bytes(val, unit):
        u = unit.upper()
        v = float(val)
        if 'K' in u: return int(v * 1024)
        if 'M' in u: return int(v * 1024**2)
        if 'G' in u: return int(v * 1024**3)
        if 'T' in u: return int(v * 1024**4)
        return int(v)

    if m_rescued:
        rescued_bytes = to_bytes(m_rescued.group(1), m_rescued.group(2))
    if m_pct:
        pct = float(m_pct.group(1))
    if m_spd:
        spd = to_bytes(m_spd.group(1), m_spd.group(2)) / (1024**2)

    return rescued_bytes, pct, spd

def parse_ddrescue_mapfile(map_path):
    summary = {
        "rescued_bytes": 0,
        "non_tried_bytes": 0,
        "bad_sector_bytes": 0,
        "bad_blocks_count": 0
    }
    if os.path.exists(map_path):
        try:
            with open(map_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            size = int(parts[1], 16)
                            status = parts[2]
                            
                            if status == '+':
                                summary["rescued_bytes"] += size
                            elif status in ['?', '*', '/']:
                                summary["non_tried_bytes"] += size
                            elif status == '-':
                                summary["bad_sector_bytes"] += size
                                summary["bad_blocks_count"] += 1
                        except ValueError:
                            pass
        except Exception as e:
            print(f"Error reading mapfile: {e}")
    return summary

# --- Direct Real-time Asynchronous Execution Engine ---
def execution_worker(cmd, fmt, total_bytes, out_file, report_file_path, report_data):
    global current_job, active_proc
    log_history = []
    
    def append_log(msg):
        if msg:
            log_history.append(msg)
            with job_lock:
                current_job["log"] = "\n".join(log_history[-100:])

    append_log(f"[*] Starting execution using [{fmt.upper()}] engine...")
    # Do not log full command if it might contain secrets (cmd is already sanitized)
    append_log(f"[*] Engine: {fmt.upper()} | target bytes: {total_bytes}")

    start_time = time.time()
    with job_lock:
        current_job["status"] = "Processing Media..."

    try:
        active_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            preexec_fn=os.setsid
        )

        fd = active_proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        byte_buffer = b""

        while True:
            time.sleep(0.1)
            
            try:
                raw_chunk = os.read(fd, 1024)
                if raw_chunk:
                    byte_buffer += raw_chunk
                    
                    while b'\r' in byte_buffer or b'\n' in byte_buffer:
                        r_idx = byte_buffer.find(b'\r')
                        n_idx = byte_buffer.find(b'\n')
                        indices = [i for i in (r_idx, n_idx) if i != -1]
                        cut_idx = min(indices)
                        
                        line_bytes = byte_buffer[:cut_idx]
                        byte_buffer = byte_buffer[cut_idx + 1:]
                        
                        line_str = line_bytes.decode('utf-8', errors='ignore')
                        
                        # Strip ANSI escape sequences and carriage return codes
                        clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line_str).replace('\r', '').strip()
                        if not clean_line:
                            continue
                        
                        append_log(clean_line)

                        if fmt in ['raw', 'dd']:
                            bytes_copied, speed = parse_dc3dd_line(clean_line)
                            with job_lock:
                                if bytes_copied is not None:
                                    current_job["transferred_bytes"] = bytes_copied
                                    if total_bytes > 0:
                                        current_job["progress_percent"] = round((bytes_copied / total_bytes) * 100, 1)
                                if speed is not None:
                                    current_job["speed_mbps"] = speed

                        elif fmt == 'e01':
                            pct, speed = parse_ewf_line(clean_line)
                            with job_lock:
                                if "verify" in clean_line.lower() or "verifying" in clean_line.lower():
                                    current_job["status"] = "Verifying Image Integrity..."
                                if pct is not None:
                                    current_job["progress_percent"] = pct
                                    if total_bytes > 0:
                                        current_job["transferred_bytes"] = int((pct / 100.0) * total_bytes)
                                if speed is not None:
                                    current_job["speed_mbps"] = speed

                        elif fmt == 'ddrescue':
                            rescued_bytes, pct, speed = parse_ddrescue_line(clean_line)
                            with job_lock:
                                if rescued_bytes is not None:
                                    current_job["transferred_bytes"] = rescued_bytes
                                if pct is not None:
                                    current_job["progress_percent"] = pct
                                elif rescued_bytes is not None and total_bytes > 0:
                                    current_job["progress_percent"] = round((rescued_bytes / total_bytes) * 100, 1)
                                if speed is not None:
                                    current_job["speed_mbps"] = speed

                elif active_proc.poll() is not None:
                    break
            except (OSError, IOError):
                pass

        active_proc.wait()

        try:
            os.sync()
        except Exception:
            pass

        time.sleep(1.0)
        computed_hashes = {}
        if fmt == 'e01':
            computed_hashes = parse_ewf_hashes(current_job["log"])
        elif fmt in ['raw', 'dd']:
            dc3dd_log = out_file.replace('.dd', '_dc3dd.log')
            computed_hashes = parse_dc3dd_hashes(dc3dd_log)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["computed_verification_hashes"] = computed_hashes

        with job_lock:
            if active_proc.returncode in [0, 2]:
                current_job["status"] = "Completed Successfully"
                current_job["progress_percent"] = 100.0
                current_job["speed_mbps"] = 0.0
                report_data["acquisition_status"] = "COMPLETED"
            elif current_job["status"] != "Stopped":
                current_job["status"] = "Failed"
                report_data["acquisition_status"] = "FAILED"
        if active_proc.returncode in [0, 2]:
            append_log("[+] Recovery/acquisition completed successfully.")
        elif report_data.get("acquisition_status") == "FAILED":
            append_log(f"[-] Process exited with code {active_proc.returncode}")

        try:
            with open(report_file_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            append_log(f"[+] Forensic case report updated: {report_file_path}")
        except Exception as e:
            append_log(f"[-] Warning: Failed updating report JSON: {e}")

    except Exception as e:
        with job_lock:
            current_job["status"] = "Failed"
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        with job_lock:
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

    try:
        target_drive = sanitize_device(request.args.get('drive', '/dev/sda'))
    except ValueError:
        target_drive = '/dev/sda'

    wb_active = True
    if os.path.exists(target_drive):
        try:
            res = subprocess.run(
                ['sudo', BIN_BLOCKDEV, '--getro', target_drive],
                capture_output=True, text=True, timeout=5)
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
        "write_blocker_active": wb_active,
        "monitored_device": target_drive
    })

@app.route('/api/drives', methods=['GET'])
@requires_auth
def list_drives():
    drives = []
    try:
        res = subprocess.run(
            [BIN_LSBLK, '-J', '-b', '-o', 'NAME,SIZE,MODEL,TRAN,TYPE,SERIAL,RO'],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') == 'disk' and not dev['name'].startswith('loop'):
                    bytes_size = int(dev.get('size', 0))
                    gb_size = round(bytes_size / (1024**3), 1)
                    dev_path = f"/dev/{dev['name']}"
                    
                    # Query current RO state only (do not force-set on discovery)
                    is_ro = True
                    try:
                        ro = subprocess.run(
                            ['sudo', BIN_BLOCKDEV, '--getro', dev_path],
                            capture_output=True, text=True, timeout=5)
                        if ro.returncode == 0 and ro.stdout.strip() == '0':
                            is_ro = False
                    except Exception:
                        pass

                    drives.append({
                        "name": dev['name'],
                        "device": dev_path,
                        "model": dev.get('model') or 'Generic Disk',
                        "size": f"{gb_size} GB",
                        "bytes": bytes_size,
                        "transport": dev.get('tran') or 'usb',
                        "serial": dev.get('serial') or 'N/A',
                        "read_only": is_ro
                    })
    except Exception as e:
        print(f"Error executing lsblk: {e}")
        
    return jsonify(drives)

@app.route('/api/smart_check', methods=['POST'])
@requires_auth
def smart_check():
    req = request.get_json() or {}
    try:
        drive = sanitize_device(req.get('drive', ''))
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    try:
        total_bytes = 0
        try:
            res_sz = subprocess.run(['sudo', BIN_BLOCKDEV, '--getsize64', drive], capture_output=True, text=True)
            if res_sz.returncode == 0:
                total_bytes = int(res_sz.stdout.strip())
        except Exception:
            pass

        capacity_str = f"{round(total_bytes / (1024**3), 2)} GB" if total_bytes > 0 else "N/A"

        res = subprocess.run(['sudo', BIN_SMARTCTL, '-a', '-j', drive], capture_output=True, text=True)
        data = json.loads(res.stdout) if res.stdout else {}
        
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
            "capacity": capacity_str,
            "serial": serial,
            "temperature": temp,
            "reallocated_sectors": reallocated,
            "pending_sectors": pending,
            "power_on_hours": power_on
        })

    except Exception:
        return jsonify({
            "success": True,
            "healthy": True,
            "vendor_model": "Generic Media Device",
            "media_type": "USB / Storage Media",
            "capacity": "N/A",
            "serial": "N/A",
            "temperature": None,
            "reallocated_sectors": 0,
            "pending_sectors": 0,
            "power_on_hours": None
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
    try:
        host = sanitize_host(req.get('host', ''))
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    shares = []
    try:
        if protocol == 'nfs':
            res = subprocess.run(
                [BIN_SHOWMOUNT, '-e', '--no-headers', host],
                capture_output=True, text=True, timeout=8)
            if res.returncode == 0:
                for line in res.stdout.strip().split('\n'):
                    if line.strip():
                        export_path = line.split()[0]
                        shares.append(export_path)
                return jsonify({"success": True, "shares": shares})
            return jsonify({"success": False, "error": res.stderr.strip() or "No NFS exports found."}), 500

        user = (req.get('user') or '').strip()
        pass_val = (req.get('pass') or '').strip()
        env = os.environ.copy()
        if user:
            # Avoid putting password on argv – use PASSWD env for smbclient
            env['PASSWD'] = pass_val
            cmd = [BIN_SMBCLIENT, '-L', host, '-I', host, '-U', user, '-g']
        else:
            cmd = [BIN_SMBCLIENT, '-L', host, '-I', host, '-N', '-g']

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8, env=env)

        if res.returncode != 0 and not user:
            env['PASSWD'] = ''
            cmd_guest = [BIN_SMBCLIENT, '-L', host, '-I', host, '-U', 'guest', '-g']
            res = subprocess.run(cmd_guest, capture_output=True, text=True, timeout=8, env=env)

        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith('Disk|'):
                    parts = line.split('|')
                    if len(parts) > 1:
                        share_name = parts[1].strip()
                        if share_name and not share_name.endswith('$'):
                            shares.append(share_name)
            return jsonify({"success": True, "shares": shares})

        err_msg = res.stderr.strip() or res.stdout.strip() or "Failed to query SMB shares."
        return jsonify({"success": False, "error": err_msg}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/mount_network', methods=['POST'])
@requires_auth
def mount_network():
    req = request.get_json() or {}
    protocol = (req.get('protocol') or 'smb').lower()
    try:
        host = sanitize_host(req.get('host', ''))
        share = sanitize_share(req.get('share', ''))
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    user = (req.get('user') or '').strip()
    password = (req.get('pass') or '').strip()

    share_path = f"/{share.lstrip('/')}"
    safe_folder_name = re.sub(r'[^A-Za-z0-9_\-]', '_', share_path).strip('_')[:64]
    mount_point = f"/mnt/network_{protocol}_{safe_folder_name}"
    os.makedirs(mount_point, exist_ok=True)

    cred_file = None
    try:
        subprocess.run(['sudo', BIN_UMOUNT, '-l', mount_point],
                       capture_output=True, timeout=10)

        if protocol == 'nfs':
            nfs_source = f"{host}:{share_path}"
            last_err = ""
            for vers in ('3', '4'):
                cmd = [
                    'sudo', BIN_MOUNT, '-t', 'nfs',
                    '-o', f'nolock,soft,timeo=30,retrans=2,vers={vers}',
                    nfs_source, mount_point
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if res.returncode == 0:
                    save_mount_history({
                        "protocol": protocol, "host": host,
                        "share": share_path, "mount_point": mount_point
                    })
                    return jsonify({"success": True, "mount_point": mount_point})
                last_err = res.stderr.strip() or res.stdout.strip()
            return jsonify({"success": False, "error": f"NFS Mount Failed: {last_err}"}), 500

        # SMB / CIFS – use credentials file so password never appears on argv
        unc_source = f"//{host}/{share_path.lstrip('/')}"
        cred_file = write_smb_credentials(user or 'guest', password)
        opts = f"credentials={cred_file},noperm,iocharset=utf8"
        cmd_smb = [
            'sudo', BIN_MOUNT, '-t', 'cifs',
            unc_source, mount_point, '-o', opts
        ]
        res_smb = subprocess.run(cmd_smb, capture_output=True, text=True, timeout=15)

        if res_smb.returncode == 0:
            save_mount_history({
                "protocol": protocol, "host": host,
                "share": share_path, "mount_point": mount_point
            })
            return jsonify({"success": True, "mount_point": mount_point})

        return jsonify({
            "success": False,
            "error": f"SMB Mount Failed: {res_smb.stderr.strip()}"
        }), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cred_file is not None:
            try:
                cred_file.unlink(missing_ok=True)
            except Exception:
                pass


@app.route('/api/toggle_write_block', methods=['POST'])
@requires_auth
def toggle_write_block():
    req = request.get_json() or {}
    enable = req.get('enable', True)
    drive = req.get('drive', '/dev/sda')
    
    try:
        drive = sanitize_device(drive)
    except ValueError:
        try:
            drive = sanitize_device('/dev/sda')
        except ValueError:
            return jsonify({"success": False, "error": "No valid target drive"}), 400

    action_flag = '--setro' if enable else '--setrw'
    
    try:
        # Safe unmount without shell
        for part in [drive] + [f"{drive}{i}" for i in range(1, 16)]:
            if os.path.exists(part):
                subprocess.run(['sudo', 'umount', '-l', part], capture_output=True, timeout=5)
                subprocess.run(['sudo', 'udevil', 'unmount', '-b', part], capture_output=True, timeout=5)
        res = subprocess.run(['sudo', BIN_BLOCKDEV, action_flag, drive], capture_output=True, text=True, timeout=5)
        
        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr.strip() or "blockdev execution failed"}), 500

        chk = subprocess.run(['sudo', BIN_BLOCKDEV, '--getro', drive], capture_output=True, text=True)
        is_ro = (chk.returncode == 0 and chk.stdout.strip() == '1')

        return jsonify({"success": True, "write_blocker_active": is_ro, "device": drive})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start_imaging', methods=['POST'])
@requires_auth
def start_imaging():
    global current_job
    
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = req.get('destination', '/mnt').strip()
    fmt = req.get('format', 'dd')
    hashes = req.get('hashes', ['sha256'])
    metadata = req.get('metadata', {}) or {}
    
    compression = req.get('compression', 'fast')
    split_size = req.get('split_size', '2000M')

    try:
        source = sanitize_device(source)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        dest_p = safe_path(dest_path, must_exist=False)
        dest_path = str(dest_p)
        if not dest_p.exists():
            dest_p.mkdir(parents=True, exist_ok=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    total_bytes = 0
    try:
        res = subprocess.run(['sudo', BIN_BLOCKDEV, '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    dest_disk_usage = shutil.disk_usage(dest_path)
    if total_bytes > 0 and dest_disk_usage.free < total_bytes:
        free_gb = round(dest_disk_usage.free / (1024**3), 2)
        required_gb = round(total_bytes / (1024**3), 2)
        return jsonify({"error": f"Pre-flight storage check failed: Destination has only {free_gb} GB free, but source requires {required_gb} GB."}), 400

    smart_data = {}
    try:
        res_smart = subprocess.run(['sudo', BIN_SMARTCTL, '-a', '-j', source], capture_output=True, text=True)
        if res_smart.stdout:
            smart_data = json.loads(res_smart.stdout)
    except Exception:
        pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    vendor_model = f"{family} ({model})" if (family and family.lower() not in model.lower()) else model

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

    case_num = sanitize_name(metadata.get('case_number', 'UNASSIGNED'))
    evidence_id = sanitize_name(metadata.get('evidence_id', 'ITEM-01'))
    examiner = sanitize_name(metadata.get('examiner', 'UNSPECIFIED'), max_len=128)
    notes = str(metadata.get('notes', 'None'))[:512]
    base_name = f"{case_num}_{evidence_id}"

    if fmt == 'e01':
        ewf_hash_type = "sha256" if "sha256" in hashes else ("sha1" if "sha1" in hashes else "md5")
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
            "-c", compression,
            "-S", split_size,
            source
        ]
    else:
        out_file = f"{dest_path}/{base_name}.dd"
        dc3dd_log_file = f"{dest_path}/{base_name}_dc3dd.log"
        cmd = [
            "dc3dd",
            f"if={source}",
            f"of={out_file}",
            f"log={dc3dd_log_file}",
            "iflag=direct",
            "oflag=direct"
        ]
        for h in hashes:
            cmd.append(f"hash={h}")

    with job_lock:
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
            "compression": compression if fmt == 'e01' else 'N/A',
            "split_size": split_size if fmt == 'e01' else 'N/A',
            "requested_hashes": hashes,
            "execution_command": " ".join(cmd)
        },
        "attachments": {
            "files": [],
            "reference_urls": []
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    try:
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not write report JSON: {e}")

    thread = threading.Thread(
        target=execution_worker,
        args=(cmd, fmt, total_bytes, out_file, report_file, report_data)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"success": True, "message": "Acquisition started."})

@app.route('/api/ddrescue/inspect_map', methods=['POST'])
@requires_auth
def inspect_ddrescue_map():
    req = request.get_json() or {}
    map_path = req.get('map_path', '')
    try:
        p = safe_path(map_path, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    summary = parse_ddrescue_mapfile(str(p))
    return jsonify({
        "success": True,
        "map_path": map_path,
        "rescued_gb": round(summary["rescued_bytes"] / (1024**3), 3),
        "non_tried_mb": round(summary["non_tried_bytes"] / (1024**2), 2),
        "bad_sector_kb": round(summary["bad_sector_bytes"] / 1024, 2),
        "bad_blocks_count": summary["bad_blocks_count"]
    })

@app.route('/api/start_ddrescue', methods=['POST'])
@requires_auth
def start_ddrescue():
    global current_job
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = req.get('destination', '/mnt').strip()
    strategy = req.get('strategy', 'stage1_fast')
    retry_passes = str(req.get('retry_passes', '3'))
    direct_mode = req.get('direct_mode', True)
    input_pos = req.get('input_position', '')
    max_size = req.get('max_size', '')
    metadata = req.get('metadata', {}) or {}

    try:
        source = sanitize_device(source)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        dest_p = safe_path(dest_path, must_exist=False)
        dest_path = str(dest_p)
        if not dest_p.exists():
            dest_p.mkdir(parents=True, exist_ok=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Limit strategy to known values
    if strategy not in ('stage1_fast', 'stage2_trim', 'stage3_intensive', 'reverse'):
        strategy = 'stage1_fast'
    try:
        int(retry_passes)
    except ValueError:
        retry_passes = '3'

    case_num = sanitize_name(metadata.get('case_number', 'RECOVERY'))
    evidence_id = sanitize_name(metadata.get('evidence_id', 'ITEM-01'))
    base_name = f"{case_num}_{evidence_id}_ddrescue"
    
    out_file = os.path.join(dest_path, f"{base_name}.dd")
    map_file = os.path.join(dest_path, f"{base_name}.map")

    cmd = ["sudo", BIN_DDRESCUE, "--force"]

    if strategy == 'stage1_fast':
        cmd.extend(["--no-scrape", "--no-trim"])
    elif strategy == 'stage2_trim':
        cmd.append("--no-scrape")
    elif strategy == 'stage3_intensive':
        cmd.append(f"--retry-passes={retry_passes}")
    elif strategy == 'reverse':
        cmd.extend(["--reverse", f"--retry-passes={retry_passes}"])

    if direct_mode:
        cmd.append("-d")

    if input_pos:
        cmd.append(f"--input-position={input_pos}")
    if max_size:
        cmd.append(f"--max-size={max_size}")

    cmd.extend([source, out_file, map_file])

    total_bytes = 0
    try:
        res = subprocess.run(['sudo', BIN_BLOCKDEV, '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    with job_lock:
        current_job["active"] = True
        current_job["format"] = "ddrescue"
        current_job["progress_percent"] = 0.0
        current_job["speed_mbps"] = 0.0
        current_job["transferred_bytes"] = 0
        current_job["total_bytes"] = total_bytes
        current_job["status"] = f"ddrescue [{strategy.upper()}]..."
        current_job["log"] = f"[*] Initializing ddrescue ({strategy}) pass for {source} -> {out_file}\n[*] Mapfile: {map_file}..."

    report_file = os.path.join(dest_path, f"{base_name}_report.json")
    report_data = {
        "case_metadata": metadata,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": "ddrescue_raw",
            "mapfile": map_file,
            "strategy": strategy,
            "retry_passes": retry_passes,
            "direct_mode": direct_mode,
            "execution_command": " ".join(cmd)
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    thread = threading.Thread(
        target=execution_worker,
        args=(cmd, "ddrescue", total_bytes, out_file, report_file, report_data)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"success": True, "message": f"ddrescue ({strategy}) started."})

@app.route('/api/stop_imaging', methods=['POST'])
@requires_auth
def stop_imaging():
    global current_job, active_proc
    with job_lock:
        if not current_job["active"]:
            return jsonify({"error": "No active job running."}), 400
        try:
            if active_proc and active_proc.poll() is None:
                os.killpg(os.getpgid(active_proc.pid), signal.SIGKILL)
        except Exception as e:
            print(f"Error killing process group: {e}")

        for tool in ["dc3dd", "ewfacquire", "ddrescue"]:
            try:
                subprocess.run(["sudo", BIN_PKILL, "-9", tool], capture_output=True, timeout=5)
            except Exception:
                pass

        current_job["status"] = "Stopped"
        current_job["active"] = False
        current_job["log"] += "\n[!] Acquisition manually terminated by user."
    return jsonify({"success": True, "message": "Acquisition stopped."})

@app.route('/api/progress', methods=['GET'])
@requires_auth
def get_progress():
    with job_lock:
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

# --- File Explorer Endpoints ---
@app.route('/api/files/browse', methods=['POST'])
@requires_auth
def browse_files():
    req = request.get_json() or {}
    path = req.get('path', '/mnt')
    try:
        p = safe_path(path, must_exist=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    items = []
    try:
        for entry in os.scandir(p):
            try:
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "path": entry.path,
                    "is_dir": entry.is_dir(),
                    "size_bytes": stat.st_size if not entry.is_dir() else 0,
                    "size_str": f"{round(stat.st_size / (1024**2), 2)} MB" if not entry.is_dir() else "--",
                    "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                })
            except Exception:
                pass
        return jsonify({"path": str(p), "items": sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/copy', methods=['POST'])
@requires_auth
def copy_file():
    req = request.get_json() or {}
    src = req.get('source')
    dest_dir = req.get('destination_dir')
    try:
        src_p = safe_path(src, must_exist=True)
        dest_p = safe_path(dest_dir, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    try:
        dest_path = dest_p / src_p.name
        if src_p.is_dir():
            shutil.copytree(src_p, dest_path, dirs_exist_ok=True)
        else:
            shutil.copy2(src_p, dest_path)
        return jsonify({"success": True, "message": f"Copied {src_p.name} to {dest_p}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/files/delete', methods=['POST'])
@requires_auth
def delete_file():
    req = request.get_json() or {}
    path = req.get('path')
    try:
        p = safe_path(path, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    for root in ALLOWED_ROOTS:
        try:
            if p.resolve() == root.resolve():
                return jsonify({"success": False, "error": "Cannot delete root mount points"}), 400
        except Exception:
            pass
    try:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        return jsonify({"success": True, "message": f"Deleted {p.name}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Report Modifier & Attachment Endpoints ---
@app.route('/api/report/load', methods=['POST'])
@requires_auth
def load_report_json():
    req = request.get_json() or {}
    report_file = req.get('report_path')
    try:
        p = safe_path(report_file, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    try:
        with open(p, 'r') as f:
            data = json.load(f)
        return jsonify({"success": True, "report": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/report/save', methods=['POST'])
@requires_auth
def save_report_json():
    req = request.get_json() or {}
    report_file = req.get('report_path')
    data = req.get('report_data')
    try:
        p = safe_path(report_file, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    try:
        with open(p, 'w') as f:
            json.dump(data, f, indent=2)
        return jsonify({"success": True, "message": "Report JSON updated successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Post-Acquisition Hash Verifier ---
@app.route('/api/verify_hash', methods=['POST'])
@requires_auth
def verify_file_hash():
    req = request.get_json() or {}
    file_path = req.get('file_path')
    algo = req.get('algorithm', 'sha256').lower()
    if algo not in ('md5', 'sha1', 'sha256'):
        return jsonify({"success": False, "error": "Unsupported algorithm"}), 400
    try:
        p = safe_path(file_path, must_exist=True)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    try:
        hasher = getattr(hashlib, algo)()
        with open(p, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed = hasher.hexdigest()
        return jsonify({
            "success": True,
            "file_name": p.name,
            "algorithm": algo.upper(),
            "hash": computed
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- PDF Forensic Audit Exporter ---
@app.route('/api/export_pdf', methods=['POST'])
@requires_auth
def export_pdf():
    req = request.get_json() or {}
    report_file = req.get('report_path')

    try:
        p = safe_path(report_file, must_exist=True)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.utils import ImageReader

        with open(p, 'r') as f:
            data = json.load(f)

        pdf_path = str(p).replace('.json', '.pdf')
        if not pdf_path.endswith('.pdf'):
            pdf_path += '.pdf'

        c = canvas.Canvas(pdf_path, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 750, "ARM FORENSIC ACQUISITION AUDIT REPORT")
        c.setLineWidth(1)
        c.line(50, 740, 550, 740)

        c.setFont("Helvetica", 10)
        y = 710
        
        meta = data.get('case_metadata', {})
        c.drawString(50, y, f"Case Number: {meta.get('case_number', 'N/A')}")
        c.drawString(300, y, f"Evidence ID: {meta.get('evidence_id', 'N/A')}")
        y -= 20
        c.drawString(50, y, f"Examiner: {meta.get('examiner', 'N/A')}")
        c.drawString(300, y, f"Date: {data.get('timestamp_start', 'N/A')}")
        y -= 20
        c.drawString(50, y, f"Notes: {meta.get('notes', 'None')}")
        y -= 30

        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Source Media Telemetry")
        y -= 15
        c.setFont("Helvetica", 10)
        drive = data.get('source_drive_telemetry', {})
        c.drawString(50, y, f"Device: {drive.get('device_path')} ({drive.get('capacity_gb')} GB)")
        c.drawString(300, y, f"Model: {drive.get('vendor_model')}")
        y -= 15
        c.drawString(50, y, f"Serial: {drive.get('serial_number')}")
        c.drawString(300, y, f"SMART Status: {'PASSED' if drive.get('smart_healthy') else 'FAILING'}")
        y -= 30

        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Acquisition & Verification Hashes")
        y -= 15
        c.setFont("Helvetica", 10)
        params = data.get('acquisition_parameters', {})
        c.drawString(50, y, f"Format: {params.get('output_format', 'dd').upper()}")
        c.drawString(300, y, f"Status: {data.get('acquisition_status')}")
        y -= 20

        hashes = data.get('computed_verification_hashes', {})
        for k, v in hashes.items():
            c.drawString(50, y, f"{k.upper()}: {v}")
            y -= 15

        attachments = data.get('attachments', {})
        file_list = attachments.get('files', [])
        if not file_list and attachments.get('image_path'):
            file_list = [attachments.get('image_path')]

        ref_urls = attachments.get('reference_urls', [])

        if file_list or ref_urls:
            if y < 150:
                c.showPage()
                y = 730

            y -= 15
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "Case Attachments & References")
            y -= 20
            c.setFont("Helvetica", 10)

            if ref_urls:
                c.drawString(50, y, "Reference Links / URLs:")
                y -= 15
                for url in ref_urls:
                    c.setFillColorRGB(0, 0, 0.8)
                    c.drawString(60, y, f"• {url}")
                    c.setFillColorRGB(0, 0, 0)
                    y -= 15

            if file_list:
                c.drawString(50, y, "Attached Case Files / Media:")
                y -= 15
                for file_path in file_list:
                    if not file_path or not os.path.exists(file_path):
                        continue
                        
                    ext = os.path.splitext(file_path)[1].lower()
                    if ext in ['.jpg', '.jpeg', '.png']:
                        if y < 200:
                            c.showPage()
                            y = 730
                        try:
                            c.drawString(60, y, f"• Photo: {os.path.basename(file_path)}")
                            y -= 140
                            c.drawImage(ImageReader(file_path), 60, y, width=200, height=130, preserveAspectRatio=True)
                            y -= 15
                        except Exception as img_err:
                            c.drawString(60, y, f"• Photo Error ({os.path.basename(file_path)}): {str(img_err)}")
                            y -= 15
                    else:
                        c.drawString(60, y, f"• Document: {os.path.basename(file_path)} ({file_path})")
                        y -= 15

        c.save()
        return send_file(pdf_path, as_attachment=True)

    except Exception as e:
        return jsonify({"error": f"PDF Export Failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
