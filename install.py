#!/usr/bin/env python3
import os
import sys
import pwd
import subprocess

if os.geteuid() != 0:
    print("[!] Error: This installation script must be run with root privileges (sudo python3 install.py).")
    sys.exit(1)

INSTALL_DIR = "/opt/pi-forensics"

# Detect non-root sudo invoker as default candidate
default_user = os.environ.get("SUDO_USER")
if not default_user or default_user == "root":
    default_user = "pi"

print("====================================================")
print("  ARM Forensic Acquisition Station Auto-Installer   ")
print("====================================================")

# Interactive Prompt for System Username
print("\n[?] Service Account Setup")
user_input = input(f"Enter system username for the service [default: '{default_user}']: ").strip()
SERVICE_USER = user_input if user_input else default_user

# Check if user exists; offer creation if missing
try:
    user_info = pwd.getpwnam(SERVICE_USER)
except KeyError:
    print(f"\n[!] User '{SERVICE_USER}' does not exist on this system.")
    create_choice = input(f"Would you like to create user '{SERVICE_USER}' now? [Y/n]: ").strip().lower()
    
    if create_choice in ['', 'y', 'yes']:
        try:
            print(f"[*] Creating system user '{SERVICE_USER}'...")
            subprocess.run(["useradd", "-m", "-s", "/bin/bash", SERVICE_USER], check=True)
            
            # Set account password interactively
            subprocess.run(["passwd", SERVICE_USER], check=True)
            
            # Add user to standard kiosk/hardware access groups
            for group in ["sudo", "video", "render", "input", "plugdev", "disk"]:
                subprocess.run(["usermod", "-aG", group, SERVICE_USER], capture_output=True)
                
            user_info = pwd.getpwnam(SERVICE_USER)
            print(f"[+] User '{SERVICE_USER}' created successfully!")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to create user '{SERVICE_USER}': {e}")
            sys.exit(1)
    else:
        print("[!] Installation aborted. Rerun with a valid system user.")
        sys.exit(1)

USER_HOME = user_info.pw_dir
print(f"[+] Service target user set to: '{SERVICE_USER}' (Home: {USER_HOME})")

# 1. Install Required APT Packages (Including gddrescue & ReportLab dependencies)
print("\n[*] Installing system dependencies via APT...")
apt_packages = [
    "python3-venv", "python3-pip", "python3-psutil", "python3-dev",
    "dc3dd", "ewf-tools", "gddrescue", "smartmontools",
    "util-linux", "udevil", "cifs-utils", "nfs-common",
    "smbclient", "chromium-browser", "curl", "git",
    "libopenjp2-7", "libtiff6"
]
subprocess.run(["apt-get", "update"], check=True)
subprocess.run(["apt-get", "install", "-y"] + apt_packages, check=True)

# Disable background udisks2 auto-mounter to prevent desktop race conditions
subprocess.run(["systemctl", "stop", "udisks2.service"], capture_output=True)
subprocess.run(["systemctl", "disable", "udisks2.service"], capture_output=True)

# 2. Configure Virtual Environment & Python Dependencies
print("\n[*] Setting up Python virtual environment...")
venv_dir = os.path.join(INSTALL_DIR, "venv")
if not os.path.exists(venv_dir):
    subprocess.run(["python3", "-m", "venv", venv_dir], check=True)

pip_bin = os.path.join(venv_dir, "bin", "pip")
subprocess.run([pip_bin, "install", "--upgrade", "pip"], check=True)

req_file = os.path.join(INSTALL_DIR, "requirements.txt")
if os.path.exists(req_file):
    subprocess.run([pip_bin, "install", "-r", req_file], check=True)
else:
    subprocess.run([pip_bin, "install", "flask", "gunicorn", "psutil", "reportlab"], check=True)

# 3. Directory Ownership Setup
print(f"\n[*] Setting directory permissions on {INSTALL_DIR} for '{SERVICE_USER}'...")
subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", INSTALL_DIR], check=True)

# 4. Scoped Sudoers Configuration
print("\n[*] Installing scoped sudoers configuration...")
sudoers_path = "/etc/sudoers.d/pi-forensics"
sudoers_content = f"{SERVICE_USER} ALL=(ALL) NOPASSWD: /usr/sbin/blockdev, /sbin/blockdev, /usr/sbin/smartctl, /bin/mount, /bin/umount, /usr/bin/udevil, /usr/bin/pkill, /usr/bin/smbclient, /usr/sbin/showmount, /usr/bin/dcfldd, /usr/bin/dc3dd, /usr/bin/ddrescue, /sbin/poweroff, /sbin/reboot\n"

with open(sudoers_path, "w") as f:
    f.write(sudoers_content)
os.chmod(sudoers_path, 0o440)

# 5. Global Udev USB Read-Only Rule
print("\n[*] Configuring global USB read-only udev rules...")
udev_path = "/etc/udev/rules.d/99-usb-read-only.rules"
udev_content = (
    'ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z]", RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
    'ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z][0-9]*", RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
)
with open(udev_path, "w") as f:
    f.write(udev_content)
subprocess.run(["udevadm", "control", "--reload-rules"], check=True)
subprocess.run(["udevadm", "trigger"], check=True)

# 6. Install Systemd Service Unit
print("\n[*] Installing systemd WSGI production service...")
service_path = "/etc/systemd/system/pi-forensics.service"
service_content = f"""[Unit]
Description=ARM Forensic Acquisition Station (Production WSGI)
After=network.target network-online.target

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_USER}
WorkingDirectory={INSTALL_DIR}
Environment="FORENSIC_USER=admin"
Environment="FORENSIC_PASS=forensics"
ExecStart={INSTALL_DIR}/venv/bin/python3 -m gunicorn --workers 2 --timeout 300 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
with open(service_path, "w") as f:
    f.write(service_content)

subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "--now", "pi-forensics.service"], check=True)

# 7. Configure Touchscreen Kiosk Autostart (Labwc)
print(f"\n[*] Configuring Wayland kiosk autostart for '{SERVICE_USER}' in {USER_HOME}...")
kiosk_dir = os.path.join(USER_HOME, ".config", "labwc")
os.makedirs(kiosk_dir, exist_ok=True)
autostart_path = os.path.join(kiosk_dir, "autostart")

autostart_content = f"""#!/bin/bash
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/{user_info.pw_uid}

wlr-randr --output ALL --on 2>/dev/null || true

killall -9 chromium chromium-browser 2>/dev/null || true
rm -rf {USER_HOME}/.config/chromium/Singleton*
rm -rf {USER_HOME}/.config/chromium/Default/LOCK*

for i in {{1..30}}; do
    if curl -s -I http://127.0.0.1:5000 | grep -q "200 OK"; then
        break
    fi
    sleep 1
done

chromium \\
  --kiosk \\
  --ozone-platform=wayland \\
  --enable-features=UseOzonePlatform \\
  --gpu-subsystem-startup-dialog=0 \\
  --ignore-gpu-blocklist \\
  --password-store=basic \\
  --noerrdialogs \\
  --disable-infobars \\
  --disable-session-crashed-bubble \\
  --disable-component-update \\
  --check-for-update-interval=31536000 \\
  http://127.0.0.1:5000 &
"""
with open(autostart_path, "w") as f:
    f.write(autostart_content)
os.chmod(autostart_path, 0o755)
subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", os.path.join(USER_HOME, ".config")], check=True)

print("\n====================================================")
print("   [+] INSTALLATION COMPLETE!                       ")
print(f"   Service running under account: '{SERVICE_USER}'")
print("   The Forensic Station is running at http://127.0.0.1:5000")
print("   Reboot your Pi to launch into touch kiosk mode.  ")
print("====================================================")