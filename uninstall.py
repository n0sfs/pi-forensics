#!/usr/bin/env python3
"""
ARM Forensic Acquisition Station – uninstaller.

Reverses the actions of install.py:
  - stops and disables systemd services
  - removes nginx site + TLS materials (optional)
  - removes sudoers and udev rules
  - removes /opt/pi-forensics application tree (optional)
  - optionally removes the service user

Usage:
  sudo python3 uninstall.py
"""

import os
import sys
import pwd
import shutil
import subprocess
from pathlib import Path

if os.geteuid() != 0:
    print("[!] This uninstaller must be run as root:  sudo python3 uninstall.py")
    sys.exit(1)

INSTALL_DIR = Path("/opt/pi-forensics")
SSL_DIR = Path("/etc/ssl/pi-forensics")
SUDOERS = Path("/etc/sudoers.d/pi-forensics")
UDEV_RULE = Path("/etc/udev/rules.d/99-usb-read-only.rules")
SERVICE = Path("/etc/systemd/system/pi-forensics.service")
NGINX_SITE = Path("/etc/nginx/sites-available/pi-forensics")
NGINX_ENABLED = Path("/etc/nginx/sites-enabled/pi-forensics")

print("=" * 56)
print("  ARM Forensic Acquisition Station – Uninstaller")
print("=" * 56)
print()
print("This will stop services and remove configuration created")
print("by install.py. Application data under /mnt is NOT touched.")
print()

confirm = input("Continue with uninstall? [y/N]: ").strip().lower()
if confirm not in ("y", "yes"):
    print("[*] Aborted.")
    sys.exit(0)

# ---------------------------------------------------------------------------
# 1. Stop and disable services
# ---------------------------------------------------------------------------
print("\n[*] Stopping services...")
for unit in ("pi-forensics.service", "pi-kiosk.service"):
    subprocess.run(["systemctl", "stop", unit], capture_output=True)
    subprocess.run(["systemctl", "disable", unit], capture_output=True)
    print(f"    stopped/disabled {unit}")

if SERVICE.exists():
    SERVICE.unlink()
    print(f"[+] Removed {SERVICE}")

# Optional legacy kiosk unit
kiosk_unit = Path("/etc/systemd/system/pi-kiosk.service")
if kiosk_unit.exists():
    kiosk_unit.unlink()
    print(f"[+] Removed {kiosk_unit}")

subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

# ---------------------------------------------------------------------------
# 2. nginx site
# ---------------------------------------------------------------------------
print("\n[*] Removing nginx site configuration...")
if NGINX_ENABLED.exists() or NGINX_ENABLED.is_symlink():
    NGINX_ENABLED.unlink()
    print(f"[+] Removed {NGINX_ENABLED}")
if NGINX_SITE.exists():
    NGINX_SITE.unlink()
    print(f"[+] Removed {NGINX_SITE}")

# Restore default site if nothing else is enabled (best-effort)
sites_enabled = Path("/etc/nginx/sites-enabled")
default_avail = Path("/etc/nginx/sites-available/default")
default_en = sites_enabled / "default"
if default_avail.exists() and not default_en.exists():
    try:
        default_en.symlink_to(default_avail)
        print("[+] Restored nginx default site")
    except Exception:
        pass

if Path("/usr/sbin/nginx").exists() or Path("/bin/nginx").exists():
    subprocess.run(["nginx", "-t"], capture_output=True)
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)

# ---------------------------------------------------------------------------
# 3. TLS certificates
# ---------------------------------------------------------------------------
print("\n[*] TLS certificates")
rm_ssl = input(f"    Remove {SSL_DIR}? [y/N]: ").strip().lower()
if rm_ssl in ("y", "yes"):
    if SSL_DIR.exists():
        shutil.rmtree(SSL_DIR)
        print(f"[+] Removed {SSL_DIR}")
else:
    print(f"    Kept {SSL_DIR}")

# ---------------------------------------------------------------------------
# 4. sudoers + udev
# ---------------------------------------------------------------------------
print("\n[*] Removing sudoers and udev rules...")
if SUDOERS.exists():
    SUDOERS.unlink()
    print(f"[+] Removed {SUDOERS}")
if UDEV_RULE.exists():
    UDEV_RULE.unlink()
    print(f"[+] Removed {UDEV_RULE}")
    subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
    subprocess.run(["udevadm", "trigger"], capture_output=True)

# ---------------------------------------------------------------------------
# 5. Application directory
# ---------------------------------------------------------------------------
print(f"\n[*] Application directory {INSTALL_DIR}")
rm_app = input("    Remove application files (venv, app.py, reports history)? [y/N]: ").strip().lower()
if rm_app in ("y", "yes"):
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        print(f"[+] Removed {INSTALL_DIR}")
else:
    print(f"    Kept {INSTALL_DIR}")

# ---------------------------------------------------------------------------
# 6. Optional service user
# ---------------------------------------------------------------------------
print("\n[*] Service user")
# Try to detect user from a leftover unit or ask
svc_user = os.environ.get("SUDO_USER") or "pi"
try:
    # Best effort: parse User= from a backup if any; otherwise ask
    pass
except Exception:
    pass

user_input = input(f"    Delete system user (and home) created for the service? Enter username or leave blank to skip: ").strip()
if user_input:
    try:
        pwd.getpwnam(user_input)
        # Refuse to delete common interactive accounts by accident unless explicit
        if user_input in ("root", "pi") and input(f"    Really delete '{user_input}'? Type the username again: ").strip() != user_input:
            print("    Skipped user deletion.")
        else:
            subprocess.run(["systemctl", "stop", f"user@{user_input}.service"], capture_output=True)
            r = subprocess.run(["userdel", "-r", user_input], capture_output=True, text=True)
            if r.returncode == 0:
                print(f"[+] Removed user {user_input}")
            else:
                # -r may fail if home already gone
                r2 = subprocess.run(["userdel", user_input], capture_output=True, text=True)
                if r2.returncode == 0:
                    print(f"[+] Removed user {user_input} (home may remain)")
                else:
                    print(f"[!] Could not remove user: {r.stderr or r2.stderr}")
    except KeyError:
        print(f"    User '{user_input}' does not exist – skipped.")
else:
    print("    Skipped user deletion.")

# ---------------------------------------------------------------------------
# 7. Kiosk autostart (labwc) – best effort for common users
# ---------------------------------------------------------------------------
print("\n[*] Checking labwc kiosk autostart stubs...")
for home in Path("/home").iterdir() if Path("/home").exists() else []:
    autostart = home / ".config" / "labwc" / "autostart"
    if autostart.exists():
        try:
            text = autostart.read_text()
            if "pi-forensics" in text or "127.0.0.1:5000" in text or "127.0.0.1/" in text:
                remove = input(f"    Remove kiosk autostart for {home.name}? [y/N]: ").strip().lower()
                if remove in ("y", "yes"):
                    autostart.unlink()
                    print(f"[+] Removed {autostart}")
        except Exception:
            pass

print("\n" + "=" * 56)
print("  UNINSTALL COMPLETE")
print("=" * 56)
print("  Notes:")
print("  - Evidence images under /mnt or network mounts were not deleted.")
print("  - System packages (dc3dd, dcfldd, ewf-tools, gddrescue, afflib-tools,")
print("    smartmontools, libimobiledevice-utils, usbmuxd, adb, nginx, …) were left")
print("    installed. Remove them with apt if desired, e.g.:")
print("      sudo apt remove dc3dd dcfldd ewf-tools gddrescue afflib-tools \\")
print("        smartmontools libimobiledevice-utils usbmuxd adb \\")
print("        android-sdk-platform-tools-common nginx")
print("  - Reboot if you removed a graphical kiosk autostart.")
print("=" * 56)
