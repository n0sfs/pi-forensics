#!/usr/bin/env python3
"""
ARM Forensic Acquisition Station – production installer.

Installs system packages, creates a dedicated service user, configures
scoped sudoers, udev write-blocker rules, Python venv, gunicorn service,
nginx reverse-proxy with TLS (self-signed by default), and optional kiosk
autostart.

Usage:
  sudo python3 install.py
"""

import os
import sys
import pwd
import secrets
import subprocess
from pathlib import Path

if os.geteuid() != 0:
    print("[!] This installer must be run as root:  sudo python3 install.py")
    sys.exit(1)

INSTALL_DIR = Path("/opt/pi-forensics")
SSL_DIR = Path("/etc/ssl/pi-forensics")
NGINX_SITE = Path("/etc/nginx/sites-available/pi-forensics")
NGINX_ENABLED = Path("/etc/nginx/sites-enabled/pi-forensics")

print("=" * 56)
print("  ARM Forensic Acquisition Station – Installer")
print("=" * 56)

# ---------------------------------------------------------------------------
# Service user
# ---------------------------------------------------------------------------
default_user = os.environ.get("SUDO_USER") or "pi"
if default_user == "root":
    default_user = "pi"

user_input = input(f"\n[?] Service username [{default_user}]: ").strip()
SERVICE_USER = user_input or default_user

try:
    user_info = pwd.getpwnam(SERVICE_USER)
except KeyError:
    create = input(f"[!] User '{SERVICE_USER}' does not exist. Create it? [Y/n]: ").strip().lower()
    if create in ("", "y", "yes"):
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", SERVICE_USER], check=True)
        print(f"[*] Set password for {SERVICE_USER}:")
        subprocess.run(["passwd", SERVICE_USER], check=True)
        for group in ("sudo", "video", "render", "input", "plugdev", "disk"):
            subprocess.run(["usermod", "-aG", group, SERVICE_USER], capture_output=True)
        user_info = pwd.getpwnam(SERVICE_USER)
        print(f"[+] Created user {SERVICE_USER}")
    else:
        print("[!] Aborted.")
        sys.exit(1)

USER_HOME = Path(user_info.pw_dir)
print(f"[+] Service user: {SERVICE_USER} (home {USER_HOME})")

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
print("\n[?] Web UI credentials (Basic Auth)")
web_user = input("    Username [admin]: ").strip() or "admin"
WEAK = {'', 'forensics', 'password', 'admin', 'changeme', '123456', 'pi'}
while True:
    web_pass = input("    Password (leave blank to generate a strong random one): ").strip()
    if not web_pass:
        web_pass = secrets.token_urlsafe(18)
        print(f"    Generated password: {web_pass}")
        print("    *** SAVE THIS PASSWORD – it will not be shown again ***")
        break
    if web_pass.lower() in WEAK or len(web_pass) < 10:
        print("    [!] Password too weak (min 10 chars, not a common default). Try again.")
        continue
    break

# ---------------------------------------------------------------------------
# APT packages
# ---------------------------------------------------------------------------
print("\n[*] Installing system packages...")
apt_packages = [
    "python3-venv", "python3-pip", "python3-dev", "python3-psutil",
    "dc3dd", "ewf-tools", "gddrescue", "smartmontools",
    "util-linux", "udevil", "cifs-utils", "nfs-common", "smbclient",
    "nginx", "openssl",
    "chromium-browser", "curl", "git",
    "libopenjp2-7", "libtiff6",
]
subprocess.run(["apt-get", "update"], check=True)
subprocess.run(["apt-get", "install", "-y"] + apt_packages, check=True)

subprocess.run(["systemctl", "stop", "udisks2.service"], capture_output=True)
subprocess.run(["systemctl", "disable", "udisks2.service"], capture_output=True)

# ---------------------------------------------------------------------------
# Application tree
# ---------------------------------------------------------------------------
print(f"\n[*] Preparing {INSTALL_DIR}...")
INSTALL_DIR.mkdir(parents=True, exist_ok=True)

src_root = Path(__file__).resolve().parent
for item in ("app.py", "requirements.txt", "templates", "static", "kiosk.sh", "uninstall.py", "nginx"):
    src = src_root / item
    dst = INSTALL_DIR / item
    if src.exists():
        if src.is_dir():
            subprocess.run(["cp", "-a", str(src), str(dst.parent)], check=True)
        else:
            subprocess.run(["cp", "-a", str(src), str(dst)], check=True)

(INSTALL_DIR / "templates").mkdir(exist_ok=True)
(INSTALL_DIR / "static" / "js").mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Python venv
# ---------------------------------------------------------------------------
print("\n[*] Setting up virtual environment...")
venv_dir = INSTALL_DIR / "venv"
if not venv_dir.exists():
    subprocess.run(["python3", "-m", "venv", str(venv_dir)], check=True)

pip = str(venv_dir / "bin" / "pip")
subprocess.run([pip, "install", "--upgrade", "pip"], check=True)

req = INSTALL_DIR / "requirements.txt"
if req.exists():
    subprocess.run([pip, "install", "-r", str(req)], check=True)
else:
    subprocess.run([pip, "install", "flask", "gunicorn", "psutil", "reportlab"], check=True)

# Ephemeral credential directory for SMB mounts (mode 0700)
cred_dir = INSTALL_DIR / "run"
cred_dir.mkdir(parents=True, exist_ok=True)
os.chmod(cred_dir, 0o700)

kiosk_script = INSTALL_DIR / "kiosk.sh"
if kiosk_script.exists():
    kiosk_script.chmod(0o755)

print(f"\n[*] Setting ownership of {INSTALL_DIR} to {SERVICE_USER}...")
subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", str(INSTALL_DIR)], check=True)

# ---------------------------------------------------------------------------
# Sudoers
# ---------------------------------------------------------------------------
print("\n[*] Installing scoped sudoers...")
sudoers = Path("/etc/sudoers.d/pi-forensics")
sudoers.write_text(
    f"{SERVICE_USER} ALL=(ALL) NOPASSWD: "
    "/usr/sbin/blockdev, /sbin/blockdev, "
    "/usr/sbin/smartctl, "
    "/bin/mount, /bin/umount, "
    "/usr/bin/udevil, "
    "/usr/bin/pkill, "
    "/usr/bin/smbclient, /usr/sbin/showmount, "
    "/usr/bin/dc3dd, /usr/bin/ddrescue, "
    "/sbin/poweroff, /sbin/reboot\n"
)
sudoers.chmod(0o440)
r = subprocess.run(["visudo", "-c", "-f", str(sudoers)], capture_output=True, text=True)
if r.returncode != 0:
    print(f"[!] sudoers validation failed: {r.stderr}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# USB read-only udev rule
# ---------------------------------------------------------------------------
print("\n[*] Installing USB read-only udev rules...")
udev = Path("/etc/udev/rules.d/99-usb-read-only.rules")
udev.write_text(
    'ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z]", '
    'RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
    'ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z][0-9]*", '
    'RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
)
subprocess.run(["udevadm", "control", "--reload-rules"], check=True)
subprocess.run(["udevadm", "trigger"], check=True)

# ---------------------------------------------------------------------------
# TLS certificate
# ---------------------------------------------------------------------------
print("\n[*] Generating self-signed TLS certificate...")
SSL_DIR.mkdir(parents=True, exist_ok=True)
key = SSL_DIR / "pi-forensics.key"
crt = SSL_DIR / "pi-forensics.crt"
if not key.exists() or not crt.exists():
    subprocess.run([
        "openssl", "req", "-x509", "-nodes", "-days", "3650",
        "-newkey", "rsa:2048",
        "-keyout", str(key),
        "-out", str(crt),
        "-subj", "/CN=pi-forensics.local/O=ARM Forensic Station"
    ], check=True)
    key.chmod(0o600)
print(f"[+] Certificate: {crt}")

# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------
print("\n[*] Configuring nginx...")
# Auth stays in the Python app (loopback kiosk bypass). Nginx only terminates TLS.
nginx_conf = f"""# ARM Forensic Acquisition Station – TLS reverse proxy
# Authentication is enforced by app.py (not nginx) so the local kiosk and
# health checks on 127.0.0.1 work without an extra Basic-Auth prompt.

server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    ssl_certificate     {crt};
    ssl_certificate_key {key};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy no-referrer always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Local forensic appliance: allow large evidence attachments / JSON reports
    client_max_body_size 0;

    location / {{
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Live acquisition progress streams without buffering delay
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
}}
"""
NGINX_SITE.write_text(nginx_conf)

if NGINX_ENABLED.is_symlink() or NGINX_ENABLED.exists():
    NGINX_ENABLED.unlink()
NGINX_ENABLED.symlink_to(NGINX_SITE)

default_enabled = Path("/etc/nginx/sites-enabled/default")
if default_enabled.exists():
    default_enabled.unlink()

subprocess.run(["nginx", "-t"], check=True)
subprocess.run(["systemctl", "enable", "--now", "nginx"], check=True)
subprocess.run(["systemctl", "reload", "nginx"], check=True)

# ---------------------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------------------
print("\n[*] Installing systemd service...")
service = Path("/etc/systemd/system/pi-forensics.service")
service.write_text(f"""[Unit]
Description=ARM Forensic Acquisition Station (gunicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_USER}
WorkingDirectory={INSTALL_DIR}
Environment="FORENSIC_USER={web_user}"
Environment="FORENSIC_PASS={web_pass}"
Environment="FORENSIC_AUTH_BYPASS=0"
ExecStart={INSTALL_DIR}/venv/bin/python3 -m gunicorn --workers 2 --timeout 300 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=3
PrivateTmp=true

[Install]
WantedBy=multi-user.target
""")

subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "--now", "pi-forensics.service"], check=True)

# Optional systemd kiosk unit (works when a display manager / graphical target is active)
print(f"\n[*] Installing pi-kiosk.service for {SERVICE_USER}...")
try:
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
except KeyError:
    uid = 1000
kiosk_unit = Path("/etc/systemd/system/pi-kiosk.service")
kiosk_unit.write_text(f"""[Unit]
Description=ARM Forensic Station Touchscreen Kiosk UI
After=pi-forensics.service nginx.service graphical.target
Wants=pi-forensics.service

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_USER}
Environment=DISPLAY=:0
Environment=WAYLAND_DISPLAY=wayland-0
Environment=XDG_RUNTIME_DIR=/run/user/{uid}
ExecStart={INSTALL_DIR}/kiosk.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=graphical.target
""")
subprocess.run(["systemctl", "daemon-reload"], check=True)
# Enable but do not force-start here (needs a graphical session)
subprocess.run(["systemctl", "enable", "pi-kiosk.service"], capture_output=True)
print("    enabled pi-kiosk.service (starts on graphical.target)")

# ---------------------------------------------------------------------------
# Kiosk autostart (labwc – used on Raspberry Pi OS Wayland desktop)
# ---------------------------------------------------------------------------
print(f"\n[*] Configuring labwc kiosk autostart for {SERVICE_USER}...")
kiosk_dir = USER_HOME / ".config" / "labwc"
kiosk_dir.mkdir(parents=True, exist_ok=True)
autostart = kiosk_dir / "autostart"
autostart.write_text(f"""#!/bin/bash
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/$(id -u)

wlr-randr --output ALL --on 2>/dev/null || true
killall -9 chromium chromium-browser 2>/dev/null || true
rm -rf {USER_HOME}/.config/chromium/Singleton* 2>/dev/null || true

for i in $(seq 1 45); do
    if curl -sk -o /dev/null -w "%{{http_code}}" https://127.0.0.1/ | grep -qE '200|401'; then
        break
    fi
    sleep 1
done

chromium \\
  --kiosk \\
  --ozone-platform=wayland \\
  --enable-features=UseOzonePlatform \\
  --password-store=basic \\
  --use-mock-keychain \\
  --no-default-browser-check \\
  --no-first-run \\
  --ignore-certificate-errors \\
  --allow-insecure-localhost \\
  --noerrdialogs \\
  --disable-infobars \\
  --disable-session-crashed-bubble \\
  --disable-component-update \\
  --check-for-update-interval=31536000 \\
  https://127.0.0.1/ &
""")
autostart.chmod(0o755)
subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", str(USER_HOME / ".config")], check=True)

print("\n" + "=" * 56)
print("  INSTALLATION COMPLETE")
print("=" * 56)
print(f"  Service user : {SERVICE_USER}")
print(f"  Web user     : {web_user}")
print(f"  Web password : {web_pass}")
print(f"  App bind     : 127.0.0.1:5000 (gunicorn)")
print(f"  Public URL   : https://<pi-ip>/   (nginx TLS)")
print()
print("  IMPORTANT:")
print("  - Change the web password if you used the generated one.")
print("  - Browser will warn about the self-signed certificate – expected.")
print("  - Software write-blocker is active via udev; prefer hardware blockers for court.")
print("  - Reboot to enter touchscreen kiosk mode (labwc).")
print("=" * 56)
