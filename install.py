#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import math
import pwd
import getpass
import shutil
import tempfile
import subprocess
import urllib.request

if os.geteuid() != 0:
    print("[!] Error: This installation script must be run with root privileges (sudo python3 install.py).")
    sys.exit(1)

INSTALL_DIR = "/opt/pi-forensics"
# Referenced by both the sudoers block (step 4, below) and the optional TLS
# setup (step 5b, further down) - defined here, once, so the sudoers grant
# for cert/key replacement and the actual cert/key generation can never
# drift out of sync with each other.
SSL_DIR = "/etc/ssl/pi-forensics"

# Detect non-root sudo invoker as default candidate
default_user = os.environ.get("SUDO_USER")
if not default_user or default_user == "root":
    default_user = "pi"

print("====================================================")
print("      Pi Forensics Suite Auto-Installer      ")
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
            #
            # Deliberately NOT adding 'disk' either (removed 2026-08-22,
            # confirmed live and empirically on a real deployed station -
            # see the dated CLAUDE.md entry). 'disk' group membership grants
            # unrestricted read+write to every block device on the system,
            # a much broader ambient capability than this app actually
            # needs - Live Device Preview and LUKS unlock both already grant
            # exactly the narrow, reversible read access they require via a
            # scoped `sudo setfacl` ACL on one specific device at a time
            # (see _grant_device_preview_acl()/_luks_unlock()), and every
            # other device read in this app already goes through a `sudo`-
            # wrapped tool (dc3dd/dcfldd/ewfacquire/ddrescue/photorec/etc.).
            # Confirmed via a full-codebase audit before removing this that
            # nothing else relies on ambient disk-group access (lsblk's
            # FSTYPE/model columns come from the udev database cache, not a
            # direct device open, and were verified to still populate
            # correctly with 'disk' removed).
            for group in ["video", "render", "input", "plugdev"]:
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
    "smbclient", "sshfs",  # SFTP network-share mounting (FUSE-based, provides /usr/bin/sshfs - verified present on Debian trixie/arm64)
    "chromium-browser", "curl", "git",
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
    "extundelete",  # deleted-file recovery for ext2/3/4 filesystems specifically
    "foremost", "scalpel",  # alternate signature-based file carvers to PhotoRec
    "dislocker",  # unlocks BitLocker-encrypted volumes (given a recovery key) for acquisition
                  # or File Explorer browsing - confirmed present on Debian trixie/arm64
                  # (0.7.3+git20240607-3+b1) via apt-cache before adding here, per this
                  # project's own hard-won "verify package existence first" rule.
    "acl",  # provides /usr/bin/setfacl - Live Device Preview's narrow, reversible read-ACL
            # grant on a single block device (the device stays hardware read-only via the
            # existing udev blockdev --setro rule regardless; this only ever adds read).
            # Standard Debian default-set package (Priority: standard) - present on virtually
            # every install, but added explicitly rather than assumed, per this project's own
            # "verify package existence first" rule.
    "cryptsetup-bin",  # unlocks LUKS-encrypted volumes for acquisition or File Explorer
                       # browsing, mirroring dislocker's BitLocker support - deliberately the
                       # minimal-deps variant (not the plain "cryptsetup" metapackage, which
                       # pulls in cryptsetup-initramfs for boot-time root-disk decryption, not
                       # needed here). Confirmed present on Debian trixie/arm64
                       # (2:2.7.5-2, deps: libblkid1/libc6/libcryptsetup12/libpopt0/libuuid1
                       # only) via apt-cache before adding here. losetup/dmsetup (also used by
                       # the LUKS unlock flow) are already provided by util-linux above.
    "cargo", "rustc",  # build-time only, needed to compile mquire (Linux memory forensics,
                       # see the mquire build step below) from source - Trail of Bits publishes
                       # no binary releases at all (confirmed against the GitHub API before
                       # deciding this), so this is genuinely required, not a convenience.
                       # Deliberately the Debian-packaged toolchain (1.85.0+dfsg3-1 on trixie/
                       # arm64, confirmed present via apt-cache first) rather than rustup - a
                       # reproducible, pinned-by-the-distro version instead of pulling whatever
                       # "latest stable" rustup's installer script resolves to at install time,
                       # and a much smaller footprint (~31MB installed vs. rustup's ~600MB full
                       # toolchain-with-docs). Left installed permanently rather than removed
                       # after the build, matching every other apt-installed tool's own
                       # permanent-install pattern in this list.
]
subprocess.run(["apt-get", "update"], check=True)
subprocess.run(["apt-get", "install", "-y"] + apt_packages, check=True)

# scalpel needs this curated config (its own stock config has every file
# signature disabled) - it should already be at INSTALL_DIR since the
# whole repo deploys there, but check explicitly rather than let scalpel
# silently recover nothing later if something about the deployment was
# incomplete.
scalpel_conf_check = os.path.join(INSTALL_DIR, "scalpel.conf")
if not os.path.exists(scalpel_conf_check):
    print(f"[!] scalpel.conf not found at {scalpel_conf_check} - the scalpel recovery "
          f"tool will not work correctly until this file is present (it ships with the repo, "
          f"so this usually means the deployment is missing a file - check your clone/copy).")

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
    subprocess.run([pip_bin, "install", "flask", "gunicorn", "psutil", "reportlab", "mvt", "pytsk3"], check=True)

# 2b. Seed the initial admin account into runtime_config.json (the same
# store app.py's multi-user login manages at runtime - see check_auth() in
# app.py). The password hash MUST be generated via the venv's own werkzeug
# (a transitive Flask dependency, not necessarily present in system
# Python, which is what this installer itself runs under) - hashing with
# the wrong Python risks an ImportError, or worse, a hash format the
# running app's werkzeug can't verify. This is why this step waits until
# now rather than happening right after the dashboard-login prompt above.
print("\n[*] Seeding initial admin account...")
admin_seeded = False
venv_python = os.path.join(venv_dir, "bin", "python3")
hash_res = subprocess.run(
    [venv_python, "-c",
     "from werkzeug.security import generate_password_hash; import sys; print(generate_password_hash(sys.argv[1]))",
     FORENSIC_PASS],
    capture_output=True, text=True
)
if hash_res.returncode != 0:
    print(f"[!] Failed to hash the initial admin password: {hash_res.stderr.strip()}")
    print("    Falling back to the legacy FORENSIC_USER/FORENSIC_PASS env-var login for now - "
          "create a real account from the Settings tab once the station is up.")
else:
    runtime_config_path = os.path.join(INSTALL_DIR, "runtime_config.json")
    runtime_cfg = {}
    if os.path.exists(runtime_config_path):
        try:
            with open(runtime_config_path, "r") as f:
                runtime_cfg = json.load(f)
        except Exception:
            runtime_cfg = {}
    runtime_cfg.setdefault("users", [])
    if not any(u.get("username") == FORENSIC_USER for u in runtime_cfg["users"]):
        runtime_cfg["users"].append({
            "username": FORENSIC_USER,
            "password_hash": hash_res.stdout.strip(),
            "group_id": "admin",
            # Kept in sync for any external tooling that might still read
            # the pre-groups field directly - app.py's get_user_group_id()
            # always prefers group_id when present, this is just a legacy
            # mirror, not something app.py itself reads anymore.
            "role": "admin",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        with open(runtime_config_path, "w") as f:
            json.dump(runtime_cfg, f, indent=2)
        os.chmod(runtime_config_path, 0o600)
        admin_seeded = True
        print(f"[+] Initial admin account '{FORENSIC_USER}' created.")

# MVT (mobile spyware/IOC scanner in the File Explorer's Actions menu) needs
# indicator files to actually match against, same idea as ClamAV's freshclam
# below - try to fetch them now so it's useful immediately, but don't fail
# the install if this Pi happens to be offline right now (the dashboard's
# Tool Versions > "Update MVT Indicators" button covers it later).
print("\n[*] Downloading initial MVT spyware/IOC indicator files...")
mvt_ios_bin = os.path.join(venv_dir, "bin", "mvt-ios")
mvt_android_bin = os.path.join(venv_dir, "bin", "mvt-android")
for mvt_bin in (mvt_ios_bin, mvt_android_bin):
    if os.path.exists(mvt_bin):
        res = subprocess.run([mvt_bin, "download-iocs"], capture_output=True, text=True, timeout=180)
        if res.returncode != 0:
            print(f"[!] Could not download IOC indicators for {os.path.basename(mvt_bin)} right now - "
                  f"use the dashboard's Tool Versions > 'Update MVT Indicators' button once online.")

# 2c. Build mquire (Linux memory forensics, x86_64-only for v1 - see its own
# worker docstring for why) from source. Pinned to a known-tested tag, not
# `main`/HEAD, matching this project's own "pinned known-working version"
# discipline elsewhere (e.g. pytsk3's own version floor in requirements.txt) -
# a moving upstream target here would mean install.py's own success/failure
# on a given day depends on whatever trailofbits/mquire's default branch
# happens to look like at that moment, not something worth risking for a
# build step that already needs real network access and several minutes of
# CPU time. Idempotent - skipped entirely if the binary already exists, the
# same "if not os.path.exists(...)" pattern the venv setup above already
# uses, so re-running install.py doesn't rebuild this every time.
MQUIRE_VERSION = "1.4.1"
mquire_bin_dir = os.path.join(INSTALL_DIR, "bin")
mquire_bin_path = os.path.join(mquire_bin_dir, "mquire")
if not os.path.exists(mquire_bin_path):
    print(f"\n[*] Building mquire {MQUIRE_VERSION} from source (Linux memory forensics)...")
    mquire_build_dir = tempfile.mkdtemp(prefix="mquire_build_")
    try:
        clone_res = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", MQUIRE_VERSION,
             "https://github.com/trailofbits/mquire", mquire_build_dir],
            capture_output=True, text=True, timeout=120,
        )
        if clone_res.returncode != 0:
            print(f"[!] Could not clone mquire (no internet access right now?) - Linux memory "
                  f"forensics will not be available until this is retried. "
                  f"Error: {clone_res.stderr.strip()[:300]}")
        else:
            # -j 2 (not cargo's own default of one job per core) deliberately caps
            # peak memory on this board's own class of hardware - confirmed live on
            # a real low-RAM Pi that an uncapped build risks starving the machine
            # (though the already-running pi-forensics service itself stayed
            # responsive throughout in that test) while an install-time build has
            # no live service running yet anyway, so this is a conservative choice
            # rather than one proven strictly necessary at install time specifically.
            build_res = subprocess.run(
                ["cargo", "build", "--release", "-j", "2"],
                cwd=mquire_build_dir, capture_output=True, text=True, timeout=1800,
            )
            if build_res.returncode != 0:
                print(f"[!] mquire build failed - Linux memory forensics will not be available. "
                      f"Error: {build_res.stderr.strip()[-500:]}")
            else:
                built_binary = os.path.join(mquire_build_dir, "target", "release", "mquire")
                if os.path.exists(built_binary):
                    os.makedirs(mquire_bin_dir, exist_ok=True)
                    shutil.copy2(built_binary, mquire_bin_path)
                    os.chmod(mquire_bin_path, 0o755)
                    print(f"[+] mquire {MQUIRE_VERSION} built and installed to {mquire_bin_path}.")
                else:
                    print("[!] mquire build reported success but the binary wasn't found where expected - "
                          "Linux memory forensics will not be available.")
    except subprocess.TimeoutExpired:
        print("[!] mquire build timed out - Linux memory forensics will not be available. "
              "Retry manually later: git clone the repo, run `cargo build --release`, and copy "
              f"target/release/mquire to {mquire_bin_path}.")
    finally:
        shutil.rmtree(mquire_build_dir, ignore_errors=True)

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
    "extundelete", "foremost", "scalpel",
]
install_lines = ", \\\n".join(f"/usr/bin/apt-get install -y {pkg}" for pkg in INSTALLABLE_TOOL_PACKAGES)

# NOPASSWD is limited to exactly the binaries/invocations app.py uses via
# sudo. Where a command could otherwise do more than intended (systemctl,
# apt-get), the sudoers line pins the exact arguments rather than granting
# the whole binary - e.g. "systemctl restart pi-forensics.service" is
# allowed, but "systemctl restart anything-else" is not.
#
# /usr/bin/setfacl is unqualified (like mount/sshfs/nmcli above) since its
# legitimate argument - the device path being previewed - is examiner-
# selected and too variable to pin exactly; the real security boundary is
# app-level (is_valid_block_device_or_partition() in core/paths.py), which
# only ever lets a whitelisted /dev/sd*|nvme*|mmcblk* whole-disk-or-
# partition path reach this command, and setfacl is only ever asked to
# grant read (never write) on a device that's already hardware read-only
# via the udev blockdev --setro rule regardless.
#
# getfacl (unlike setfacl) needs no sudo grant at all - confirmed live that
# an unprivileged read of a file's ACL/xattrs works regardless of the
# file's own rwx bits for `other` (standard Unix metadata-visibility
# semantics, distinct from data-access permission), even against a
# root:disk-owned device node with no `other` access. Used unprivileged by
# _device_preview_startup_reconciliation() (routes/image_browser.py) to
# detect a stray read-ACL grant left over from a crashed/restarted process,
# mirroring LUKS's own startup loop-device reconciliation.
#
# /usr/sbin/cryptsetup is DELIBERATELY pinned to two exact verbs
# (luksOpen/luksClose), NOT granted unqualified like setfacl above - unlike
# setfacl's device-path argument (genuinely too variable to pin), the
# *verb* cryptsetup is invoked with is a small, fixed set this app only
# ever needs two of, and cryptsetup has genuinely destructive subcommands
# (luksFormat, luksErase, reencrypt) with no setfacl equivalent - an
# unqualified grant would shift the entire safety burden onto "no future
# code change ever lets a bad argument reach a bare `sudo cryptsetup`
# call." Pinning the verb here mirrors this file's own existing
# `/bin/chown -R {SERVICE_USER} *`-style precedent (pin the fixed prefix,
# wildcard only the variable trailing argument) rather than setfacl's
# fully-unqualified one. /sbin/losetup is similarly pinned even though its
# own action space is much less dangerous (attach/detach a loop node,
# no data destruction) - cheap to tighten the same way, and its `-d`
# argument is always a path this app's own prior losetup call itself
# returned, never client-supplied, matching how _dislocker_lock()'s
# mount_dir is already trusted the same way. isLuks needs no sudo grant at
# all - LUKS detection uses blkid (already granted below) and a direct
# unprivileged file read, never cryptsetup itself.
#
# Tightened 2026-08-23 (Informational finding from the 2026-08-22 security
# audit): "luksOpen *" and "luksClose *" as originally written didn't
# actually match this comment's own stated intent - sudo's fnmatch-style
# `*` matches ANY text including spaces, so a single trailing `*` wildcards
# the ENTIRE rest of the command line, not just "the variable trailing
# argument" the comment above describes. Nothing reachable today can
# exploit this (routes/acquisition.py's _luks_unlock()/_luks_lock() build
# every argument server-side, confirmed by reading both functions before
# writing this fix), but the grant itself provided no structural backstop
# if that ever changed. Both patterns are now anchored on both sides
# instead of trailing off into an open wildcard: luksOpen's mapper-name
# argument and trailing "-d -" flags are pinned literally (only the source
# path - which is legitimately either a /dev/* device or an arbitrary
# already-validated evidence file, so it can't be pinned to one shape -
# stays wildcarded), and luksClose's sole argument is pinned to the app's
# own real mapper-name prefix (LUKS_MAPPER_PREFIX, routes/acquisition.py)
# with no free-floating wildcard left at all. Verified live (this file's
# own mandatory discipline for any sudoers change) that the tightened
# patterns still match the exact real command lines
# _luks_unlock()/_luks_lock() build, and that a deliberately malformed
# variant (extra trailing arguments after "-d -") is correctly rejected by
# sudo before ever reaching cryptsetup.
#
# VeraCrypt (2026-08-26, gap-closing round) reuses this exact same
# cryptsetup binary and verb-pinning discipline - confirmed live that
# cryptsetup 2.7.5 (this station's real installed version) has NATIVE
# VeraCrypt-format support built in (`open --type tcrypt --veracrypt`),
# so no new binary/package dependency was needed at all (the real
# `veracrypt` CLI is confirmed NOT in Debian's mainline ARM64 repo; a
# throwaway `tcplay` install - never shipped, only used to build a real
# test container for this verification - confirmed cryptsetup can open
# what it creates). --veracrypt-pim is ALWAYS present in the real command
# (0 when not specified by the examiner, a real valid value, never
# omitted) specifically so this grant can be ONE fully-anchored pattern
# rather than two variants with/without a PIM segment - the two wildcarded
# segments (PIM value, source path) are separated by the literal "-r -q"
# tokens on both sides, giving each `*` real anchoring text immediately
# before and after it, the same principle the LUKS patterns above already
# rely on. Verified live the same mandatory way: the real generated
# command line matches this pattern, and a deliberately malformed variant
# is rejected.
sudoers_content = f"""{SERVICE_USER} ALL=(ALL) NOPASSWD: \\
/usr/sbin/blockdev, /sbin/blockdev, \\
/usr/sbin/smartctl, \\
/bin/mount, /bin/umount, /bin/mkdir, \\
/usr/bin/udevil, /usr/bin/pkill, \\
/usr/bin/smbclient, /usr/sbin/showmount, /usr/bin/sshfs, /usr/bin/nmcli, /usr/bin/setfacl, \\
/usr/bin/dcfldd, /usr/bin/dc3dd, /usr/bin/ddrescue, \\
/usr/bin/ewfacquire, /usr/bin/ewfexport, /usr/bin/ewfinfo, /usr/bin/dd, /usr/bin/photorec, \\
/usr/bin/extundelete, /usr/bin/foremost, /usr/bin/scalpel, /usr/bin/testdisk, \\
/sbin/dislocker, /usr/bin/dislocker, /sbin/blkid, /usr/sbin/blkid, \\
/usr/sbin/cryptsetup luksOpen * pif_luks_* -d -, /usr/sbin/cryptsetup luksClose pif_luks_*, \\
/usr/sbin/cryptsetup open --type tcrypt --veracrypt --veracrypt-pim * -r -q * pif_veracrypt_* -d -, \\
/usr/sbin/cryptsetup close pif_veracrypt_*, \\
/sbin/losetup -o * --show -f *, /sbin/losetup -d /dev/loop*, /sbin/losetup -a, \\
/bin/chown -R {SERVICE_USER} *, \\
/bin/chgrp -R {SERVICE_USER} *, \\
/sbin/reboot, /sbin/poweroff, \\
/bin/systemctl restart pi-forensics.service, \\
/bin/systemctl reload nginx, \\
/bin/cp * {os.path.join(SSL_DIR, "pi-forensics.crt")}, \\
/bin/cp * {os.path.join(SSL_DIR, "pi-forensics.key")}, \\
/bin/chmod 600 {os.path.join(SSL_DIR, "pi-forensics.key")}, \\
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

# 5a. Enable FUSE allow_other for SFTP network mounting
# sshfs mounts run as root (via sudo, see app.py's mount_network()), but
# every other part of this app (dc3dd, the file explorer, etc.) runs
# unprivileged - without allow_other in the mount options (already set by
# app.py) AND user_allow_other enabled system-wide here, those processes
# would get permission-denied trying to read into an otherwise-successful
# mount. Handles all three states: line absent, line present but
# commented out, line already active.
print("\n[*] Enabling FUSE allow_other for SFTP network mounting...")
fuse_conf_path = "/etc/fuse.conf"
fuse_conf_lines = []
if os.path.exists(fuse_conf_path):
    with open(fuse_conf_path, "r") as f:
        fuse_conf_lines = f.readlines()

found_enabled = False
for i, line in enumerate(fuse_conf_lines):
    stripped = line.strip()
    if stripped == "user_allow_other":
        found_enabled = True
        break
    if stripped == "#user_allow_other":
        fuse_conf_lines[i] = "user_allow_other\n"
        found_enabled = True
        break

if not found_enabled:
    fuse_conf_lines.append("user_allow_other\n")

with open(fuse_conf_path, "w") as f:
    f.writelines(fuse_conf_lines)

# 5b. Optional: nginx + self-signed TLS reverse proxy
# Without this, gunicorn is reachable directly over plain HTTP - Basic Auth
# credentials go over the wire unencrypted. With it, nginx terminates TLS
# and gunicorn only listens on loopback, where nginx proxies to it.
print("\n[?] TLS Reverse Proxy Setup")
print("    Without TLS, login credentials are sent over plain HTTP on your network.")
tls_choice = input("    Set up nginx + a self-signed TLS certificate now? [Y/n]: ").strip().lower()
USE_TLS = tls_choice in ('', 'y', 'yes')

NGINX_SITE = "/etc/nginx/sites-available/pi-forensics"
NGINX_ENABLED = "/etc/nginx/sites-enabled/pi-forensics"
NGINX_DEFAULT_ENABLED = "/etc/nginx/sites-enabled/default"

if USE_TLS:
    print("\n[*] Generating self-signed TLS certificate...")
    os.makedirs(SSL_DIR, exist_ok=True)
    cert_path = os.path.join(SSL_DIR, "pi-forensics.crt")
    key_path = os.path.join(SSL_DIR, "pi-forensics.key")
    # keyUsage/extendedKeyUsage=serverAuth: openssl req -x509 leaves these
    # off by default (and marks the cert CA:TRUE), which real browsers -
    # Chrome/Windows in particular - increasingly refuse to trust for TLS
    # even after it's correctly imported into Trusted Root. Confirmed live
    # as the actual cause of a "still not secure after installing the
    # cert" report against the Settings > Security & Privacy "Generate"
    # feature's own cert (same openssl req -x509 pattern); fixed there and
    # mirrored here so a fresh install doesn't ship the same defect.
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
        "-keyout", key_path, "-out", cert_path,
        "-days", "825", "-subj", "/CN=pi-forensics.local",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
        "-addext", "extendedKeyUsage=serverAuth"
    ], check=True)
    os.chmod(key_path, 0o600)
    print(f"[+] Certificate written to {cert_path} / {key_path}")
    print("    Self-signed - browsers will warn on first visit; accept/pin it per client device,")
    print("    or replace these files with a properly trusted certificate later.")

    print("\n[*] Installing nginx site configuration...")
    # Matches pi-forensics.conf shipped in this repo - kept inline here so
    # install.py doesn't depend on a companion file existing at a specific
    # relative path when cloned.
    nginx_conf = """# Pi Forensics Suite - TLS reverse proxy
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

# 5c. Optional: offline OpenStreetMap tile cache
# The Geolocation Viewer (File Explorer / Reporting) renders KML placemarks on a Leaflet map.
# The map *library* is vendored locally (static/vendor/leaflet/ - works with zero internet), but
# the map *imagery* itself is normally fetched live from tile.openstreetmap.org, which just shows
# blank/gray squares (pins still render, just with no background map) on a station with no internet
# after this install finishes. These helpers do a one-time, best-effort local tile cache, downloaded
# now while there IS internet, for stations that will be offline later.


def _latlon_to_tile_xy(lat, lon, zoom):
    """Convert WGS84 lat/lon to slippy-map tile x/y at a zoom level (standard OSM XYZ scheme)."""
    lat = max(min(lat, 85.05112878), -85.05112878)  # Web Mercator's valid latitude range
    lat_rad = math.radians(lat)
    n = 2 ** zoom
    x = int((lon + 180.0) / 360.0 * n)
    y = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)
    return max(0, min(n - 1, x)), max(0, min(n - 1, y))


def _tile_range_for_bbox(min_lon, min_lat, max_lon, max_lat, zoom):
    """Inclusive (x_min, x_max, y_min, y_max) tile range covering a lon/lat box at a zoom level."""
    x1, y1 = _latlon_to_tile_xy(max_lat, min_lon, zoom)  # north-west corner
    x2, y2 = _latlon_to_tile_xy(min_lat, max_lon, zoom)  # south-east corner
    return min(x1, x2), max(x1, x2), min(y1, y2), max(y1, y2)


def _download_tile_set(base_dir, tiles, user_agent, delay_seconds):
    """Download (z, x, y) tiles to base_dir/{z}/{x}/{y}.png, skipping ones already on disk.
    A single failed/blocked tile is counted and skipped, never raised - a flaky connection mid-run
    shouldn't abort the whole install, matching the MVT IOC download's non-fatal precedent above.

    An outright BLOCK from the tile server is a different situation and is NOT treated as a
    per-tile failure to just skip past: tile.openstreetmap.org returns a real HTTP 200 with a
    generic placeholder image and an `X-Blocked` response header when it has denied a source
    (confirmed live during development - a request from a flagged/shared-hosting IP got exactly
    this, a real 200 OK carrying `X-Blocked: Access denied...` and a byte-identical placeholder
    PNG for every distinct tile URL requested). Silently writing that placeholder to disk under
    every tile's real filename would corrupt the whole cache into a pile of identical fake tiles
    while claiming success - detected via the header and treated as an immediate stop instead."""
    downloaded = skipped_existing = failed = 0
    blocked = False
    total = len(tiles)
    for i, (z, x, y) in enumerate(tiles):
        if blocked:
            failed += 1
            continue
        out_dir = os.path.join(base_dir, str(z), str(x))
        out_path = os.path.join(out_dir, f"{y}.png")
        if os.path.exists(out_path):
            skipped_existing += 1
        else:
            url = f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": user_agent})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.headers.get("X-Blocked"):
                        blocked = True
                        failed += 1
                        continue
                    data = resp.read()
                os.makedirs(out_dir, exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                downloaded += 1
            except Exception:
                failed += 1
        if blocked:
            print(f"    ... stopped at tile {i + 1}/{total} - tile.openstreetmap.org returned "
                  f"'X-Blocked: Access denied' for this network. See "
                  f"https://operations.osmfoundation.org/policies/tiles/ - this can happen on "
                  f"shared/hosting/VPN IPs; a normal home/office internet connection is usually fine.")
        elif (i + 1) % 200 == 0 or (i + 1) == total:
            print(f"    ... {i + 1}/{total} tiles processed ({downloaded} downloaded, "
                  f"{skipped_existing} already cached, {failed} failed)")
        time.sleep(delay_seconds)
    return downloaded, skipped_existing, failed, blocked


def download_offline_tiles(install_dir):
    tiles_dir = os.path.join(install_dir, "static", "vendor", "osm_tiles")
    os.makedirs(tiles_dir, exist_ok=True)
    # A real, honest User-Agent and a per-request delay are both required/expected by
    # OpenStreetMap's tile usage policy (operations.osmfoundation.org/policies/tiles/) - this
    # stays a deliberately small, one-time cache, not a scripted bulk-download tool.
    user_agent = "PiForensicsSuite/1.0 (offline tile cache; +https://github.com/n0sfs/pi-forensics)"
    delay = 0.2

    # Always cache a small global overview (zoom 0-5, 1,365 tiles, a few minutes) - enough on its
    # own to place a pin's rough country/continent location on a real map background, regardless
    # of where evidence coordinates turn out to be from.
    print("\n[*] Downloading global overview tiles (zoom 0-5, 1,365 tiles, a few minutes)...")
    overview_tiles = [(z, x, y) for z in range(0, 6) for x in range(2 ** z) for y in range(2 ** z)]
    d, s, f, overview_blocked = _download_tile_set(tiles_dir, overview_tiles, user_agent, delay)
    print(f"[+] Global overview: {d} downloaded, {s} already cached, {f} failed.")
    max_zoom_achieved = 5

    if d + s == 0:
        print("\n[!] No tiles were actually obtained (blocked or unreachable) - not writing an "
              "offline tile cache. The Geolocation Viewer will behave exactly as it did before "
              "this step: pins with no map background when this station has no internet.")
        return

    if overview_blocked:
        print("\n[!] tile.openstreetmap.org blocked further requests partway through - skipping "
              "the optional regional download (it would be blocked too). What was already "
              "downloaded/cached above is still saved and usable.")
    else:
        # Optional second tier: deeper zoom for one specific region, for stations that know
        # roughly where they'll be used. Kept as a separate opt-in, not the default - most
        # installs likely just want the fast/free global overview above.
        print("\n[?] Optional: deeper zoom coverage for a specific region")
        print("    If you know roughly where this station will be used, you can also cache more")
        print("    detailed tiles (city/street level) for just that area. Get a bounding box from")
        print("    a site like bboxfinder.com (draw a box there, copy the 4 numbers it shows).")
        bbox_input = input("    Bounding box as 'min_lon,min_lat,max_lon,max_lat' (blank to skip): ").strip()

        if not bbox_input:
            print("    Skipped - global overview only.")
        else:
            try:
                min_lon, min_lat, max_lon, max_lat = (float(v.strip()) for v in bbox_input.split(","))
                if not (-180 <= min_lon < max_lon <= 180 and -90 <= min_lat < max_lat <= 90):
                    raise ValueError("out of range")
            except Exception:
                print("[!] Could not parse that bounding box - skipping regional tile download.")
            else:
                zoom_input = input("    Max zoom for this region (6-16, higher = more detail/tiles) "
                                    "[default: 13]: ").strip()
                try:
                    requested_max_zoom = max(6, min(16, int(zoom_input))) if zoom_input else 13
                except ValueError:
                    requested_max_zoom = 13

                # Hard cap on regional tile count, independent of requested zoom - a large box at a
                # high zoom could otherwise ask for millions of tiles. Builds up level-by-level and
                # stops (rather than erroring) once the next zoom level would exceed the cap, so the
                # install always finishes with whatever depth actually fit.
                REGION_TILE_CAP = 20000
                region_tiles = []
                achieved_zoom = 5
                for z in range(6, requested_max_zoom + 1):
                    x_min, x_max, y_min, y_max = _tile_range_for_bbox(min_lon, min_lat, max_lon, max_lat, z)
                    level_tiles = [(z, x, y) for x in range(x_min, x_max + 1) for y in range(y_min, y_max + 1)]
                    if len(region_tiles) + len(level_tiles) > REGION_TILE_CAP:
                        print(f"    Stopping at zoom {achieved_zoom} - zoom {z} would exceed the "
                              f"{REGION_TILE_CAP}-tile regional cap for this box.")
                        break
                    region_tiles.extend(level_tiles)
                    achieved_zoom = z

                if not region_tiles:
                    print("[!] That box didn't yield any tiles at zoom 6 - skipping regional download.")
                else:
                    est_minutes = round(len(region_tiles) * delay / 60, 1)
                    print(f"\n[*] Downloading regional tiles (zoom 6-{achieved_zoom}, "
                          f"{len(region_tiles)} tiles, ~{est_minutes} min)...")
                    d, s, f, region_blocked = _download_tile_set(tiles_dir, region_tiles, user_agent, delay)
                    print(f"[+] Regional coverage: {d} downloaded, {s} already cached, {f} failed.")
                    if region_blocked:
                        print("[!] Blocked partway through the regional download - the manifest will "
                              "still only credit the global overview's zoom level, to stay honest "
                              "about what's confirmed fully present (whatever regional tiles did "
                              "download before the block are still saved and will still be used).")
                    else:
                        max_zoom_achieved = achieved_zoom

    manifest = {
        "max_zoom": max_zoom_achieved,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(tiles_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[+] Offline tile cache ready (max zoom {max_zoom_achieved}). The Geolocation Viewer "
          f"will fall back to it automatically whenever a live OpenStreetMap tile can't be reached.")


print("\n[?] Offline Map Imagery for Geolocation Viewer")
print("    If this station will have NO internet access after setup, you can pre-download a")
print("    small cache of OpenStreetMap tile imagery now, while online, so the Geolocation")
print("    Viewer still shows real map backgrounds later (not just placemark pins on a blank grid).")
print("    Note: OpenStreetMap's tile usage policy discourages bulk downloading from its free")
print("    public server, so this stays deliberately small by default. Skip if unsure.")
tiles_choice = input("    Download offline map imagery now? [y/N]: ").strip().lower()
if tiles_choice in ('y', 'yes'):
    download_offline_tiles(INSTALL_DIR)
else:
    print("    Skipped - the Geolocation Viewer will show pins on a blank grid if this station is offline later.")

# gunicorn only needs to be reachable from outside this host if nginx isn't
# fronting it; with nginx handling TLS on 80/443, gunicorn should stay on
# loopback only.
GUNICORN_BIND = "127.0.0.1:5000" if USE_TLS else "0.0.0.0:5000"

# 6. Install Systemd Service Unit
print("\n[*] Installing systemd WSGI production service...")
service_path = "/etc/systemd/system/pi-forensics.service"

# FORENSIC_USER is harmless to leave here (not a secret - see runtime_config.json's
# hashed 'users' list, the actual credential store once seeding above succeeds).
# FORENSIC_PASS is only written here as a fallback for the rare case the admin
# account above failed to seed (see admin_seeded) - once real accounts exist,
# baking a second, plaintext copy of the same password into this file would be
# pure redundant risk with no benefit, so it's deliberately omitted.
env_lines = f'Environment="FORENSIC_USER={FORENSIC_USER}"'
if not admin_seeded:
    env_lines += f'\nEnvironment="FORENSIC_PASS={FORENSIC_PASS}"'

service_content = f"""[Unit]
Description=Pi Forensics Suite (Production WSGI)
After=network.target network-online.target

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_USER}
WorkingDirectory={INSTALL_DIR}

# Set interactively above. If you need to change these later, either edit
# this file directly or use the Settings tab in the dashboard (which manages
# runtime_config.json's real account store, not these env vars, once at
# least one user exists there).
{env_lines}

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
# Restricted to root regardless of whether admin_seeded ended up True (no
# plaintext password written above) or False (the FORENSIC_PASS fallback
# line is present) - matching every other secret this installer writes
# (sudoers file, TLS key).
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

# On-screen keyboard for touch input.
#
# Previously disabled after wvkbd-mobintl was observed crash-looping on at
# least one real deployment (rapid restart cycle every ~3s, each cycle's
# layer-shell surface mapping/unmapping briefly, which looked like the whole
# kiosk screen flashing between the keyboard and the app). Re-enabled after
# live debugging directly against a real deployed station's already-running
# kiosk session (SSH'd in, launched wvkbd-mobintl against the live Wayland
# socket with logging, then stress-tested it with 7 rapid SIGUSR2/SIGUSR1
# show/hide toggles 0.3s apart - the exact layer-shell mapping/unmapping
# the original bug describes) and found it completely stable: no crash, no
# restart, same PID throughout, chromium unaffected. Output still stays
# redirected to a log, and the respawn loop stays capped (not unconditional)
# in case a real cold-boot startup race - not reproducible by attaching to
# an already-running session - still triggers something that live test
# against a warm session couldn't catch.
wvkbd_restarts=0
while [ "$wvkbd_restarts" -lt 10 ]; do
    wvkbd-mobintl --hidden -H 340 -L 230 >> /tmp/wvkbd.log 2>&1
    wvkbd_restarts=$((wvkbd_restarts + 1))
    echo "[kiosk] wvkbd exited (restart $wvkbd_restarts/10), retrying in 3s..." >&2
    sleep 3
done &

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

# 7a. Disable PCManFM's Autorun/Automount Prompts
# The labwc autostart above launches chromium in kiosk mode ON TOP OF the
# stock Raspberry Pi OS desktop session, not instead of it - pcmanfm --desktop
# (the panel/desktop-icon manager) is still part of the normal boot sequence
# underneath. That stock session ships PCManFM's autorun feature enabled by
# default, which pops PCManFM's own "what would you like to do with this
# drive?" dialog whenever removable media is inserted - confirmed live,
# completely independent of and invisible to this app. That's a real
# forensic-soundness gap, not just visual clutter: clicking through it
# browses evidence media via PCManFM, outside this app's audit-logged
# workflow entirely, and its automount can race the udev write-block rule
# at the moment of insertion. Disabling all three of PCManFM's own
# mount/autorun switches means nothing happens at the OS level on insert -
# the only way to interact with a drive stays File Explorer/Acquisition
# inside the app itself.
print(f"\n[*] Disabling PCManFM autorun/automount prompts for '{SERVICE_USER}'...")
pcmanfm_dir = os.path.join(USER_HOME, ".config", "pcmanfm", "default")
os.makedirs(pcmanfm_dir, exist_ok=True)
pcmanfm_conf_path = os.path.join(pcmanfm_dir, "pcmanfm.conf")
PCMANFM_VOLUME_KEYS = ("mount_on_startup", "mount_removable", "autorun")

pcmanfm_conf_text = ""
if os.path.exists(pcmanfm_conf_path):
    with open(pcmanfm_conf_path) as f:
        pcmanfm_conf_text = f.read()

if "[volume]" in pcmanfm_conf_text:
    for key in PCMANFM_VOLUME_KEYS:
        if re.search(rf"^{key}=.*$", pcmanfm_conf_text, re.MULTILINE):
            pcmanfm_conf_text = re.sub(rf"^{key}=.*$", f"{key}=0", pcmanfm_conf_text, flags=re.MULTILINE)
        else:
            pcmanfm_conf_text = pcmanfm_conf_text.replace("[volume]", f"[volume]\n{key}=0", 1)
else:
    pcmanfm_conf_text += "\n[volume]\n" + "\n".join(f"{key}=0" for key in PCMANFM_VOLUME_KEYS) + "\n"

with open(pcmanfm_conf_path, "w") as f:
    f.write(pcmanfm_conf_text)

# Verify rather than trust the write - read back what's actually on disk,
# matching this file's established discipline for anything that silently
# fails in a way that would leave the station worse off than assumed (see
# the autologin verification right below).
with open(pcmanfm_conf_path) as f:
    pcmanfm_verify_text = f.read()
pcmanfm_ok = all(re.search(rf"^{key}=0\s*$", pcmanfm_verify_text, re.MULTILINE) for key in PCMANFM_VOLUME_KEYS)
if pcmanfm_ok:
    print("[+] PCManFM autorun/automount disabled and verified.")
else:
    print(f"[!] Could not confirm PCManFM autorun settings were disabled - check {pcmanfm_conf_path} manually.")

subprocess.run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", os.path.join(USER_HOME, ".config")], check=True)

# 7b. Disable GVFS/udisks2 Automount at the dconf Level (Separate from PCManFM)
# PCManFM's own [volume] autorun/mount switches (above) only control PCManFM's
# reaction to a newly-inserted drive - they do NOT control gvfs-udisks2-volume-
# monitor, a separate background daemon that automounts (and auto-opens a file
# browser on) removable media based on the org.gnome.desktop.media-handling
# gsettings schema. Confirmed live: even with PCManFM's autorun fully disabled,
# this schema's automount/automount-open keys still default to true, so gvfs
# would keep silently auto-mounting evidence media - a second, independent
# path to exactly the same forensic-soundness problem the PCManFM fix above
# addresses, just without even the courtesy of a prompt. Fixed the same way
# any sysadmin permanently overrides a GNOME setting system-wide: a dconf
# database override (not a per-user gsettings call, which only works against
# an already-running session and wouldn't survive re-provisioning), locked so
# it can't be silently re-enabled by any future per-user override. Verified
# live to take effect immediately via `dconf update` with no reboot required
# (unlike the ini-file-based PCManFM fix above, which needs PCManFM to restart
# to reread it).
print("\n[*] Disabling GVFS/udisks2 automount (dconf) globally...")
dconf_locks_dir = "/etc/dconf/db/local.d/locks"
os.makedirs(dconf_locks_dir, exist_ok=True)
dconf_override_path = "/etc/dconf/db/local.d/00_media-handling"
dconf_lock_path = os.path.join(dconf_locks_dir, "media-handling")

with open(dconf_override_path, "w") as f:
    f.write(
        "[org/gnome/desktop/media-handling]\n"
        "automount=false\n"
        "automount-open=false\n"
        "autorun-never=true\n"
    )
with open(dconf_lock_path, "w") as f:
    f.write(
        "/org/gnome/desktop/media-handling/automount\n"
        "/org/gnome/desktop/media-handling/automount-open\n"
        "/org/gnome/desktop/media-handling/autorun-never\n"
    )
subprocess.run(["dconf", "update"], check=True)

# Verify rather than trust dconf update's exit code - read back what a real
# client session would actually see, same discipline as the PCManFM check
# above and the autologin check below.
dconf_verify = subprocess.run(
    ["dconf", "read", "/org/gnome/desktop/media-handling/automount"],
    capture_output=True, text=True
)
if dconf_verify.stdout.strip() == "false":
    print("[+] GVFS/udisks2 automount disabled and verified.")
else:
    print("[!] Could not confirm GVFS/udisks2 automount was disabled - check /etc/dconf/db/local.d/ manually.")

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