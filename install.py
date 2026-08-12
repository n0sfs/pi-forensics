#!/usr/bin/env python3
import os
import re
import sys
import pwd
import getpass
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
            
            # Add user to standard kiosk/hardware access groups.
            # Deliberately NOT adding 'sudo' here - the scoped
            # /etc/sudoers.d/pi-forensics file (below) already grants
            # exactly the privileged commands the app needs. Blanket sudo
            # group membership would defeat the point of that scoping.
            for group in ["video", "render", "input", "plugdev", "disk"]:
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

# 0b. Web Dashboard Login Credentials
# This is separate from SERVICE_USER above - SERVICE_USER is the Linux
# account the process runs as; this is the HTTP Basic Auth login for the
# dashboard itself. Both default to something ('admin'/'forensics') if you
# just hit Enter, but leaving the password at its default is exactly the
# kind of thing that gets a forensic station compromised on a shared
# network - don't skip this if you can avoid it.
print("\n[?] Web Dashboard Login")
web_user_input = input("Enter dashboard username [default: 'admin']: ").strip()
FORENSIC_USER = web_user_input if web_user_input else "admin"

FORENSIC_PASS = "forensics"
while True:
    pw1 = getpass.getpass("Enter dashboard password (min 8 chars, hidden) "
                           "[leave blank to keep the default 'forensics' - NOT recommended]: ")
    if not pw1:
        print("[!] Keeping default password 'forensics'. Change this immediately after "
              "install via the Advanced Settings tab, or by re-running this installer.")
        break
    if len(pw1) < 8:
        print("[!] Password must be at least 8 characters. Try again.")
        continue
    pw2 = getpass.getpass("Confirm dashboard password: ")
    if pw1 != pw2:
        print("[!] Passwords did not match. Try again.")
        continue
    FORENSIC_PASS = pw1
    print(f"[+] Dashboard login set to '{FORENSIC_USER}' with the password you entered.")
    break

# 1. Install Required APT Packages (Including gddrescue & ReportLab dependencies)
print("\n[*] Installing system dependencies via APT...")
apt_packages = [
    "python3-venv", "python3-pip", "python3-psutil", "python3-dev",
    "dc3dd", "dcfldd", "ewf-tools", "gddrescue", "afflib-tools", "smartmontools",
    "util-linux", "udevil", "cifs-utils", "nfs-common",
    "smbclient", "chromium-browser", "curl", "git",
    "libopenjp2-7", "libtiff6",
    "libimobiledevice-utils", "usbmuxd",  # iOS device backup (idevice_id, ideviceinfo, idevicebackup2)
    "adb", "android-sdk-platform-tools-common",  # Android device backup/pull (udev rules let plugdev group access USB without root)
    "nginx", "openssl",  # optional TLS reverse proxy (examiner is prompted below)
    "wvkbd",  # on-screen keyboard for kiosk touchscreen input (wlroots/labwc-native, see kiosk autostart)
    "testdisk",  # provides photorec (file carving/recovery) - pairs with ddrescue for damaged drives
    "libimage-exiftool-perl",  # exiftool - file metadata viewer
    "sleuthkit", "libewf-dev",  # fls/mmls/icat - browse filesystems inside acquired images; libewf-dev maximizes chance of E01 support (verified at runtime, not guaranteed - see app.py)
    "binwalk",  # embedded filesystem/firmware signature scanning
    "clamav", "clamav-freshclam",  # malware scanning (clamscan) - freshclam keeps virus definitions updated
    "hashdeep",  # recursive directory hashing/manifests
    # NOTE: no bulk-extractor package here. It isn't in Debian's mainline
    # archive (only found in Kali/Parrot's own non-free repos), and since
    # apt-get install with an unrecognized package name fails the whole
    # command, including it here would have crashed this entire install
    # before sudoers/systemd/anything after it in this list ran. The
    # "Quick Triage Scan" feature was rebuilt as a native Python scanner
    # instead (see TRIAGE_PATTERNS in app.py) rather than depending on this
    # tool at all, so there's no external package needed for it anymore.
]
subprocess.run(["apt-get", "update"], check=True)
subprocess.run(["apt-get", "install", "-y"] + apt_packages, check=True)

# Populate ClamAV's virus definition database. The clamav-freshclam package's
# own systemd timer will keep it updated afterward; this just avoids
# clamscan failing/warning against an empty database on first use. Non-fatal
# if this Pi happens to be offline right now - freshclam's own timer will
# catch up once it has connectivity.
print("\n[*] Downloading initial ClamAV virus definitions (this can take a minute)...")
subprocess.run(["systemctl", "stop", "clamav-freshclam"], capture_output=True)
fc_res = subprocess.run(["freshclam"], capture_output=True, text=True, timeout=300)
if fc_res.returncode != 0:
    print("[!] Could not download virus definitions right now - clamscan will warn until this "
          "succeeds later (clamav-freshclam's timer will retry automatically).")
subprocess.run(["systemctl", "enable", "--now", "clamav-freshclam"], capture_output=True)

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

# Packages the Advanced Settings > Tool Versions "Install" button can trigger
# via apt-get. Must match TOOL_INSTALLABLE_PACKAGES in app.py - each gets an
# exact sudoers line below rather than a wildcard, so this can't be used to
# install anything beyond this known, reviewed list.
INSTALLABLE_TOOL_PACKAGES = [
    "dc3dd", "dcfldd", "gddrescue", "ewf-tools", "afflib-tools", "testdisk",
    "sleuthkit", "libimage-exiftool-perl", "binwalk",
    "clamav", "hashdeep", "adb", "libimobiledevice-utils", "smartmontools", "wvkbd",
]
install_lines = ", \\\n".join(f"/usr/bin/apt-get install -y {pkg}" for pkg in INSTALLABLE_TOOL_PACKAGES)

# NOPASSWD is limited to exactly the binaries/invocations app.py uses via
# sudo. Where a command could otherwise do more than intended (systemctl,
# apt-get), the sudoers line pins the exact arguments rather than granting
# the whole binary - e.g. "systemctl restart pi-forensics.service" is
# allowed, but "systemctl restart anything-else" is not.
sudoers_content = f"""{SERVICE_USER} ALL=(ALL) NOPASSWD: \\
/usr/sbin/blockdev, /sbin/blockdev, \\
/usr/sbin/smartctl, \\
/bin/mount, /bin/umount, /bin/mkdir, \\
/usr/bin/udevil, /usr/bin/pkill, \\
/usr/bin/smbclient, /usr/sbin/showmount, \\
/usr/bin/dcfldd, /usr/bin/dc3dd, /usr/bin/ddrescue, \\
/usr/bin/ewfacquire, /usr/bin/dd, /usr/bin/photorec, \\
/bin/chown -R {SERVICE_USER} *, \\
/bin/chgrp -R {SERVICE_USER} *, \\
/sbin/reboot, /sbin/poweroff, \\
/bin/systemctl restart pi-forensics.service, \\
/usr/bin/apt-get update, \\
/usr/bin/apt-get upgrade -y, \\
{install_lines}
"""

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

# 5b. Optional: nginx + self-signed TLS reverse proxy
# Without this, gunicorn is reachable directly over plain HTTP - Basic Auth
# credentials go over the wire unencrypted. With it, nginx terminates TLS
# and gunicorn only listens on loopback, where nginx proxies to it.
print("\n[?] TLS Reverse Proxy Setup")
print("    Without TLS, login credentials are sent over plain HTTP on your network.")
tls_choice = input("    Set up nginx + a self-signed TLS certificate now? [Y/n]: ").strip().lower()
USE_TLS = tls_choice in ('', 'y', 'yes')

SSL_DIR = "/etc/ssl/pi-forensics"
NGINX_SITE = "/etc/nginx/sites-available/pi-forensics"
NGINX_ENABLED = "/etc/nginx/sites-enabled/pi-forensics"
NGINX_DEFAULT_ENABLED = "/etc/nginx/sites-enabled/default"

if USE_TLS:
    print("\n[*] Generating self-signed TLS certificate...")
    os.makedirs(SSL_DIR, exist_ok=True)
    cert_path = os.path.join(SSL_DIR, "pi-forensics.crt")
    key_path = os.path.join(SSL_DIR, "pi-forensics.key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
        "-keyout", key_path, "-out", cert_path,
        "-days", "825", "-subj", "/CN=pi-forensics.local"
    ], check=True)
    os.chmod(key_path, 0o600)
    print(f"[+] Certificate written to {cert_path} / {key_path}")
    print("    Self-signed - browsers will warn on first visit; accept/pin it per client device,")
    print("    or replace these files with a properly trusted certificate later.")

    print("\n[*] Installing nginx site configuration...")
    # Matches pi-forensics.conf shipped in this repo - kept inline here so
    # install.py doesn't depend on a companion file existing at a specific
    # relative path when cloned.
    nginx_conf = """# ARM Forensic Acquisition Station - TLS reverse proxy
# Authentication is enforced by app.py (not nginx) so the local kiosk and
# health checks on 127.0.0.1 work without an extra Basic-Auth prompt.

# HTTP -> HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS - SSL termination & reverse proxy to gunicorn
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    ssl_certificate     /etc/ssl/pi-forensics/pi-forensics.crt;
    ssl_certificate_key /etc/ssl/pi-forensics/pi-forensics.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy no-referrer always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Local forensic appliance: allow large evidence attachments / JSON reports
    client_max_body_size 0;

    location / {
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
    }
}
"""
    with open(NGINX_SITE, "w") as f:
        f.write(nginx_conf)

    if os.path.exists(NGINX_DEFAULT_ENABLED) or os.path.islink(NGINX_DEFAULT_ENABLED):
        os.remove(NGINX_DEFAULT_ENABLED)
    if os.path.exists(NGINX_ENABLED) or os.path.islink(NGINX_ENABLED):
        os.remove(NGINX_ENABLED)
    os.symlink(NGINX_SITE, NGINX_ENABLED)

    test_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test_res.returncode != 0:
        print(f"[!] nginx config test failed, TLS proxy NOT enabled:\n{test_res.stderr}")
        USE_TLS = False
    else:
        subprocess.run(["systemctl", "enable", "--now", "nginx"], check=True)
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        print("[+] nginx TLS reverse proxy enabled.")
else:
    print("    Skipping TLS setup. gunicorn will be reachable directly over plain HTTP.")
    print("    You can run this installer again later, or set up TLS manually - see README.md.")

# gunicorn only needs to be reachable from outside this host if nginx isn't
# fronting it; with nginx handling TLS on 80/443, gunicorn should stay on
# loopback only.
GUNICORN_BIND = "127.0.0.1:5000" if USE_TLS else "0.0.0.0:5000"

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

# Set interactively above. If you need to change these later, either edit
# this file directly or use the Advanced Settings tab in the dashboard
# (password only - the username isn't changeable from the UI).
Environment="FORENSIC_USER={FORENSIC_USER}"
Environment="FORENSIC_PASS={FORENSIC_PASS}"

# Restricts the file-explorer/report/attachment/imaging-destination API
# to this directory tree. Defaults to /mnt if unset.
Environment="FORENSIC_ROOT=/mnt"

# Skips login for the physical kiosk touchscreen only - remote/LAN/WiFi
# access always still requires authentication regardless of this setting.
# Defaults to bypassing (this line is informational; app.py's default is
# already "on" even without it). Uncomment to require login locally too:
# Environment="FORENSIC_KIOSK_AUTH_BYPASS=0"

# Bind address depends on whether nginx+TLS was set up above:
#   - With TLS: gunicorn stays on loopback (127.0.0.1) and nginx is the
#     only thing listening on the network, terminating TLS on 80/443.
#   - Without TLS: gunicorn binds 0.0.0.0 directly so the documented
#     "Remote Web Interface" (LAN access to http://<PI_IP_ADDRESS>:5000)
#     still works. Every request still requires HTTP Basic Auth (see
#     app.py) regardless of which mode is active - just note that without
#     TLS, those credentials go out in the clear.
# Single worker process is required here: current_job/job_lock live in
# Python process memory, not a shared store (Redis, DB, etc.), so multiple
# gunicorn *worker processes* would each get their own independent copy -
# a progress-poll request routed to a different worker than the one
# running the acquisition would show stale/default state. --threads
# still lets gunicorn handle concurrent requests (e.g. polling progress
# while a job runs) within that single process, where the shared state
# actually is shared.
ExecStart={INSTALL_DIR}/venv/bin/python3 -m gunicorn --workers 1 --worker-class gthread --threads 4 --timeout 300 --bind {GUNICORN_BIND} app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
with open(service_path, "w") as f:
    f.write(service_content)
# This file now contains a real plaintext password (FORENSIC_PASS above),
# not just the old harmless default - restrict it to root, matching every
# other secret this installer writes (sudoers file, TLS key).
os.chmod(service_path, 0o600)

subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "pi-forensics.service"], check=True)
# Always restart (not just "enable --now"): if this is a re-run of the
# installer and the service was already active, --now would leave the OLD
# process (with the OLD FORENSIC_USER/FORENSIC_PASS still in memory)
# running, even though the unit file on disk now has new credentials.
# restart works correctly whether the service was stopped or running.
subprocess.run(["systemctl", "restart", "pi-forensics.service"], check=True)

# 7. Configure Touchscreen Kiosk Autostart (Labwc)
print(f"\n[*] Configuring Wayland kiosk autostart for '{SERVICE_USER}' in {USER_HOME}...")
kiosk_dir = os.path.join(USER_HOME, ".config", "labwc")
os.makedirs(kiosk_dir, exist_ok=True)
autostart_path = os.path.join(kiosk_dir, "autostart")

autostart_content = f"""#!/bin/bash
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/run/user/$(id -u)

wlr-randr --output ALL --on 2>/dev/null || true

# Give the display a moment to finish resolution negotiation before
# chromium launches. There's a known bug (github.com/RPi-Distro/chromium
# issue #54) where Chromium in kiosk mode on labwc/Wayland can drop out of
# proper fullscreen if the display's mode changes/settles after Chromium
# has already started - it doesn't crash, it just ends up in a broken
# fullscreen-transition state that can look like a blank/white screen even
# though the process is running fine. This delay reduces the chance of
# racing that.
sleep 3

# On-screen keyboard for touch input - CURRENTLY DISABLED.
#
# wvkbd-mobintl was crash-looping on at least one real deployment (rapid
# restart cycle every ~3s, each cycle's layer-shell surface mapping/
# unmapping briefly, which looked like the whole kiosk screen flashing
# between the keyboard and the app). Since local kiosk login is bypassed
# by default (see FORENSIC_KIOSK_AUTH_BYPASS in app.py), the original
# urgent reason for this - helping type into the native Basic Auth prompt -
# no longer applies, so it's disabled here rather than left actively
# breaking the kiosk display while unresolved. The remaining use case
# (typing case numbers, notes, etc.) can use a physical USB keyboard
# in the meantime.
#
# To re-enable and actually debug the crash, redirect its output to a log
# instead of guessing at flags blind:
#   wvkbd-mobintl --hidden -H 340 -L 230 >> /tmp/wvkbd.log 2>&1
# then check /tmp/wvkbd.log for the actual error after it dies.
#
# while true; do
#     wvkbd-mobintl --hidden -H 340 -L 230
#     echo "[kiosk] wvkbd exited, restarting in 3s..." >&2
#     sleep 3
# done &

# Respawn loop: if chromium crashes or is closed, relaunch it rather than
# leaving a blank screen until the next reboot. This is the equivalent of
# the old pi-kiosk.service's "Restart=on-failure", implemented here instead
# since that unit depended on an X11 session (DISPLAY/XAUTHORITY) this
# Wayland/labwc setup doesn't use. The 3s sleep between attempts avoids a
# tight crash loop if something (e.g. a GPU driver issue) makes chromium
# fail immediately every time.
while true; do
    # Clean up any stale lock/singleton files a crashed chromium left behind
    # - without this, a respawn after a crash can fail to start at all.
    killall -9 chromium chromium-browser 2>/dev/null || true
    rm -rf {USER_HOME}/.config/chromium/Singleton*
    rm -rf {USER_HOME}/.config/chromium/Default/LOCK*
    rm -rf {USER_HOME}/.config/chromium/Default/Preferences.lock

    # Re-check the backend is actually up before each (re)launch - avoids
    # respawning against a dead service if pi-forensics.service is restarting.
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
      --password-store=basic \\
      --use-mock-keychain \\
      --no-default-browser-check \\
      --no-first-run \\
      --gpu-subsystem-startup-dialog=0 \\
      --ignore-gpu-blocklist \\
      --noerrdialogs \\
      --disable-infobars \\
      --disable-session-crashed-bubble \\
      --disable-component-update \\
      --check-for-update-interval=31536000 \\
      http://127.0.0.1:5000

    echo "[kiosk] chromium exited, restarting in 3s..." >&2
    sleep 3
done &

# Periodic watchdog: force-restart chromium every 30 minutes even if it's
# still technically running. This exists specifically for the labwc/
# Chromium fullscreen bug mentioned above - that failure mode leaves
# chromium running but visually stuck, which the crash-recovery loop above
# can't catch on its own since it only reacts to chromium actually exiting.
# A periodic kill is a blunt but reliable self-heal: the crash-recovery
# loop picks the kill up and relaunches fresh within a few seconds.
while true; do
    sleep 1800
    pkill -9 -f "chromium.*--kiosk" 2>/dev/null || true
done &
"""
with open(autostart_path, "w") as f:
    f.write(autostart_content)
os.chmod(autostart_path, 0o755)
subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", os.path.join(USER_HOME, ".config")], check=True)

# 7b. Enable Desktop Autologin for SERVICE_USER
# labwc only runs ~/.config/labwc/autostart when SERVICE_USER's graphical
# desktop session actually starts. On a stock image that requires desktop
# autologin to be explicitly enabled - without it, the Pi boots to a login
# prompt, no desktop session ever starts, and kiosk mode never launches,
# even though everything above was configured correctly.
print(f"\n[*] Enabling desktop autologin for '{SERVICE_USER}'...")
AUTOLOGIN_OK = False
raspi_config_check = subprocess.run(["which", "raspi-config"], capture_output=True, text=True)

if raspi_config_check.returncode == 0:
    # do_boot_behaviour B4 reads $USER from ITS OWN process environment to
    # decide who to autologin (it literally does `autologin-user=$USER`
    # internally) - since this installer runs as root, $USER would resolve
    # to "root" unless we override it here. Getting this wrong silently
    # autologins the wrong account.
    autologin_env = dict(os.environ)
    autologin_env["USER"] = SERVICE_USER
    autologin_res = subprocess.run(
        ["raspi-config", "nonint", "do_boot_behaviour", "B4"],
        capture_output=True, text=True, env=autologin_env
    )
    # Verify rather than trust the exit code - read back what was actually written.
    lightdm_conf = "/etc/lightdm/lightdm.conf"
    if autologin_res.returncode == 0 and os.path.exists(lightdm_conf):
        with open(lightdm_conf) as f:
            conf_text = f.read()
        if re.search(rf"^autologin-user={re.escape(SERVICE_USER)}\s*$", conf_text, re.MULTILINE):
            AUTOLOGIN_OK = True
            print(f"[+] Desktop autologin enabled and verified for '{SERVICE_USER}'.")

    if not AUTOLOGIN_OK:
        print(f"[!] Could not confirm autologin was set correctly for '{SERVICE_USER}'.")
        if autologin_res.stderr.strip():
            print(f"    raspi-config said: {autologin_res.stderr.strip()}")
else:
    print("[!] raspi-config not found (not Raspberry Pi OS, or a Lite/headless image).")

if not AUTOLOGIN_OK:
    print(f"    Kiosk mode will NOT start on boot until this is fixed. Set it manually:")
    print(f"      sudo raspi-config  ->  1 System Options  ->  S5 Boot / Auto Login  ->  B4 Desktop Autologin")
    print(f"    Make sure '{SERVICE_USER}' is the account selected, then reboot.")

print("\n====================================================")
print("   [+] INSTALLATION COMPLETE!                       ")
print(f"   Service running under account: '{SERVICE_USER}'")
print(f"   Dashboard login username: '{FORENSIC_USER}'")
if USE_TLS:
    print("   The Forensic Station is running at https://127.0.0.1 (self-signed cert)")
    print(f"   ...and on your LAN at https://<this Pi's IP address>")
    print("   gunicorn itself is only reachable on loopback - nginx handles TLS.")
else:
    print("   The Forensic Station is running at http://127.0.0.1:5000")
    print(f"   ...and on your LAN at http://<this Pi's IP address>:5000")
    print("   NOTE: this is plain HTTP - credentials are not encrypted in transit.")
if AUTOLOGIN_OK:
    print("   Reboot your Pi to launch into touch kiosk mode.  ")
else:
    print("   Kiosk mode will NOT start on reboot yet - see below.")
print("====================================================")

remaining_steps = []
if not AUTOLOGIN_OK:
    remaining_steps.append(
        f"Fix desktop autologin for kiosk mode (see [!] messages above) - "
        f"sudo raspi-config -> System Options -> Boot / Auto Login -> Desktop Autologin, "
        f"account '{SERVICE_USER}'."
    )
if FORENSIC_PASS == "forensics":
    remaining_steps.append(
        "Change the dashboard password - it's still the default 'forensics'. "
        "Use the Advanced Settings tab, or re-run this installer."
    )
if not USE_TLS:
    remaining_steps.append("Consider re-running this installer to add TLS, or set it up manually.")

if remaining_steps:
    print("\n[ACTION NEEDED]")
    for i, step in enumerate(remaining_steps, 1):
        print(f"  {i}) {step}")
    print("====================================================")

print("\nTo remove this installation later, run: sudo python3 uninstall.py")
print("====================================================")