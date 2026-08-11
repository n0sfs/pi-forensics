# pi-forensics, arm-forensic-station
Low Budget Forensic Drive Imaging Using Arm Based Single Board Computers such as the Raspberry Pi

# 🛡️ Raspberry Pi & ARM Forensic Acquisition Station

An open-source, web-based digital forensic imaging appliance built for Raspberry Pi and ARM single-board computers. Designed for field kit deployment, evidence collection, and network-streamed disk imaging. Based on original research "Low Budget Forensics using ARM Based Single Board Computers"
https://commons.erau.edu/jdfsl/vol11/iss1/3/

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20ARM64-red)

---

## 🌟 Key Features

- **Works on Pi or ARM SBC:** Install on Raspberry Pi or ARM SBC with Debian.
- **Acquisition:** Multiple raw/forensic-container engines to choose from - `dc3dd` (default, on-the-fly hashing), `dcfldd` (alternate on-the-fly hashing engine), plain GNU `dd` (supports genuine `iflag=direct` page-cache bypass on read, unlike dc3dd/dcfldd; hashed separately after completion since dd has no built-in hashing), `ewfacquire` for E01, and AFF (`.aff`) via a two-phase raw-acquire-then-convert pipeline (see below). All support MD5/SHA-1/SHA-256 verification. Global `udev` rules automatically force all connected USB storage devices (`sd*`) into Read-Only mode at insertion to preserve forensic integrity.
- **AFF Acquisition:** Modern `afflib-tools` no longer ships a direct device-to-AFF tool (the classic `aimage` was dropped from the package), so AFF output is produced in two phases: a hashed raw acquisition via `dc3dd`, then conversion to `.aff` via `affconvert`. The acquisition hashes come from the raw phase (AFF conversion doesn't alter the underlying bytes). The examiner chooses per-job whether to keep or delete the intermediate `.raw` file after a successful, verified conversion.
- **ARM-Friendly:** Acquisition and recovery jobs run in a background thread with the web UI polling for progress, so the interface stays responsive on constrained hardware during long-running imaging jobs.
- **Integrated Network Mounting:** Auto-discovers, authenticates, and mounts remote SMB/CIFS, NFS, and FTP shares natively in the UI with protocol fallback support.
- **SMART Health Diagnostics:** Instant drive health checks (`smartctl`) inspecting reallocated sectors, temperature, power-on hours, and bad block flags prior to imaging.
- **Software Write-Blocker Toggle:** Quick toggle for `udev` read-only rule enforcement (`ATTR{ro}="1"`) to preserve chain of custody.
- **Hardened by Default:** Every request requires authentication (no bypass for local/private networks), runs as an unprivileged service account rather than root, and sandboxes all file-explorer/report/attachment/acquisition-destination operations to a configurable evidence directory. See [Security](#-security) below.
- **Automated Evidence Manifests:** Generates structured `evidence_manifest.json` and human-readable `.txt` reports capturing case numbers, evidence IDs, examiner notes, drive serials, and timestamps.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI with drag and drop interface designed for onboard Pi touchscreen displays or headless browser control over Wi-Fi/Ethernet.
- **File Explorer & DDRescue:** Dedicated `ddrescue` UI module with real-time pass strategy selection (Fast Copy, Trimming, Scraping, Reverse Reading) and `.map` file audit inspection along with Dual Pane File Explorer Tab with copy to or from Device.
- **Mobile Forensics (iOS & Android):** A dedicated tab for acquiring already-unlocked, already-trusted mobile devices - iOS full backup via `idevicebackup2` (with optional encrypted backup to capture Keychain data, plus a manual "Pair Device" trigger via `idevicepair`), and Android via `adb pull` (accessible storage, more reliable), `adb backup` (app data, requires on-device confirmation, unreliable on Android 12+), or `adb bugreport` (system logs/dumpstate snapshot). This does **not** bypass lockscreens, device pairing, or USB-debugging authorization - devices must already be unlocked and trusted/authorized by the examiner before acquisition can start, exactly like plugging a drive into the imaging station.
- **Advanced Settings:** Station password change (persisted independently of the systemd unit), safe USB drive eject, service/kiosk restart, git-pull self-update and OS package update (both require explicit confirmation and a source you trust), reboot/power-off, live network interface listing, and a fixed-allowlist read-only diagnostics panel (`dmesg`, `lsusb`, `df -h`, `ip a`, `uptime`, `lsblk`, `free -h`, `mount`) - deliberately **not** a free-text shell terminal. See [Security](#-security) for why.
- **Reporting & Hash Verification:** Reporting, Case & URL attachments, JSON file raw viewer & PDF File export, and Image Integrity Verification with hash matching.

---

## 📸 Screenshot

<p align="center">
  <img src="docs/images/PIF1.JPG" width="100%" alt="Forensic Acquisition" />
  <br>
  <em>Figure 1: Forensic Acquisition Dashboard with Drive Check, Write Blocker Toggle, Raw/EWF Output, MD5/SHA1/SHA256 Hashes and Native Network Discovery, Drive Mapping and Telemetry.</em>
</p>

<p align="center">
  <img src="docs/images/PIF2.JPG" width="100%" alt="File Explorer" />
  <br>
  <em>Figure 2: DDRescue GUI and Dual Pane File Explorer Tab with copy to or from Device.</em>
</p>

<p align="center">
  <img src="docs/images/PIF3.JPG" width="100%" alt="Reporting" />
  <br>
  <em>Figure 3: Reporting, Case & URL attachments, JSON file raw viewer & PDF File export, and Image Integrity Verification with hash matching.</em>
</p>

---

## Contributors
Contributions welcome! Submit pull requests or open issues for improvements or bug reports.

---

## Disclaimer and License
Provided as-is, without any warranty and distributed under the GNU General Public License v3 or later. You can redistribute and/or modify it under the terms of this license. Its methodology has been vetted to be forensically sound, but always verify the integrity of your images using appropriate forensic tools and procedures.
See prior research here: "Low Budget Forensics using ARM Based Single Board Computers" - https://commons.erau.edu/jdfsl/vol11/iss1/3/

---
## 📋 Prerequisites, Setup & Usage

Pi and bootmedia with Pi OS or other Debian based OS configured
Flash a fresh **Raspberry Pi OS (64-bit) with Desktop** image to your device and connect to the internet. (https://www.raspberrypi.com/documentation/computers/getting-started.html)

> **Kiosk mode requires the Desktop image, not Lite.** The installer's autologin step
> (`raspi-config nonint do_boot_behaviour B4`) and the kiosk browser itself both depend on a
> desktop session (labwc + lightdm) being present. If you flashed the Lite/headless image, the
> web dashboard will still work fine remotely, but there's no desktop for kiosk mode to run in.

### Quick Installation (One-Line Automated Setup)
Open a terminal (or SSH) and run:
```bash
sudo git clone https://github.com/n0sfs/pi-forensics.git /opt/pi-forensics && cd /opt/pi-forensics && sudo python3 install.py
```
### Interactive Installer Options
During execution, install.py will prompt you to specify the system account:

### Account Creation: 
If the specified username does not exist, the installer will offer to create the user, set their password, and assign the required display/hardware groups (video, render, input, plugdev, disk). It does **not** add the account to the `sudo` group - the scoped `/etc/sudoers.d/pi-forensics` file installed alongside it already grants exactly the privileged commands the app needs (mount/umount, blockdev, smartctl, dc3dd/ddrescue, etc.), so the service account never has general root access.

### Dashboard Login:
Separately from the system account above, the installer also prompts for the **web dashboard**
username and password (HTTP Basic Auth) - the password entry is hidden (not echoed to the
terminal) and requires confirmation. You can leave it blank to keep the `admin`/`forensics`
defaults, but the installer will flag that clearly at the end as something to fix before
deploying. Both can also be changed later from the Advanced Settings tab (password only) or by
re-running the installer.

### Automated System Setup: 
Configures scoped /etc/sudoers.d/pi-forensics privileges, systemd WSGI production services, udev write-blocking rules, labwc kiosk autostart, and - if you accept the prompt - an nginx + self-signed TLS reverse proxy (see [Security](#-security) below).

### Accessing the Dashboard
Local Kiosk: Launches automatically at boot in full-screen touchscreen mode - the installer
enables desktop autologin for the service account so this can happen without a manual login. If
Chromium crashes or is closed, the kiosk autostart script relaunches it automatically after a
short delay rather than leaving a blank screen until the next reboot.
If kiosk doesn't appear after a reboot, check the installer's `[ACTION NEEDED]` summary from your
install run, or verify manually: `sudo raspi-config` → System Options → Boot / Auto Login →
Desktop Autologin, and confirm the account shown matches your service user.

### Remote Web Interface
If you set up TLS during install, navigate to `https://<PI_IP_ADDRESS>` (self-signed cert - your
browser will warn on first visit, accept/pin it). Otherwise, navigate to
`http://<PI_IP_ADDRESS>:5000`. Either way, every request requires HTTP Basic Auth - see
[Security](#-security) below for how to set your own credentials before relying on this.

---

## 🔒 Security

This station handles evidence, runs privileged disk-acquisition commands, and is often deployed on
networks the examiner doesn't fully control. It's built with that threat model in mind:

| Area | Behavior |
|---|---|
| **Authentication** | Every API route requires HTTP Basic Auth. There is **no bypass** for loopback or private-subnet clients. |
| **Brute-force protection** | 5 failed logins from an IP triggers a 5-minute lockout (in-memory; resets on service restart). |
| **Service privileges** | `app.py` runs as the service account you chose during install (not root). It only reaches root for the specific, whitelisted commands in `/etc/sudoers.d/pi-forensics` (mount/umount/mkdir under `/mnt`, blockdev, smartctl, dc3dd/ewfacquire/ddrescue, pkill). Raw device reads for imaging work via `disk` group membership, not sudo. |
| **File-system sandboxing** | The file explorer, report load/save, hash verification, PDF export, and imaging/recovery destinations are all restricted to one directory tree (`FORENSIC_ROOT`, default `/mnt`). Paths outside it are rejected, including via symlink or `../` traversal. |
| **Device validation** | Acquisition/recovery source paths must match a whole-disk device pattern (`/dev/sdX`, `/dev/nvme*n*`, `/dev/mmcblk*`) - arbitrary files can't be pointed at the privileged `ddrescue`/`dc3dd` commands. |
| **Evidence-drive-safe UI** | Filenames pulled from mounted/browsed media are rendered as plain text, never parsed as HTML - a maliciously named file on a suspect drive can't inject script into the examiner's session. |
| **Network share credentials** | SMB/CIFS passwords are passed via a private, mode-0600 temporary credentials file rather than on the mount command line, so they don't show up in `ps aux`. |
| **Transport encryption** | `install.py` prompts to set up nginx with a self-signed TLS certificate (generated per-install under `/etc/ssl/pi-forensics`). If accepted, nginx terminates TLS on 80/443 and gunicorn moves to loopback-only; if declined, gunicorn binds directly and Basic Auth credentials travel unencrypted. You can re-run the installer later to add TLS, or set it up manually - see `pi-forensics.conf` in this repo for the exact nginx config used. |
| **No free-text shell access** | The Advanced Settings diagnostics panel runs a fixed allowlist of read-only commands (`dmesg`, `lsusb`, `df -h`, `ip a`, `uptime`, `lsblk`, `free -h`, `mount`) as literal argv lists - there is deliberately no general "run any command" box anywhere in the UI or API. A web-exposed shell is a full remote-code-execution hole on a device that images evidence; that trade-off isn't worth the convenience. |
| **Scoped privileged actions** | Power/service-restart/update controls in Advanced Settings each map to an exact, pinned sudoers entry (e.g. `systemctl restart pi-forensics.service`, `apt-get update`) rather than a wildcarded binary grant - the service account can't use these entries to run anything beyond what's listed. |
| **Password changes persist safely** | Changing the station password from Advanced Settings writes to `runtime_config.json` in the install directory (mode 0600, owned by the service account), not a world-readable file - it takes effect immediately and survives restarts without needing to edit the systemd unit. |

### Configuration (environment variables)

`FORENSIC_USER`/`FORENSIC_PASS` are set interactively during install (see "Dashboard Login"
above) and written into `/etc/systemd/system/pi-forensics.service`, which the installer restricts
to root-readable (`0600`) since it now holds a real password. To change any of these after the
fact, edit that file, then `sudo systemctl daemon-reload && sudo systemctl restart pi-forensics.service`:

| Variable | Default if left blank at install | Purpose |
|---|---|---|
| `FORENSIC_USER` | `admin` | Basic Auth username. |
| `FORENSIC_PASS` | `forensics` | Basic Auth password. Overridden at runtime if changed from the Advanced Settings tab (see above). |
| `FORENSIC_ROOT` | `/mnt` | Root directory that file-explorer/report/attachment/acquisition-destination paths are sandboxed to. |

If you're deploying this on anything other than an isolated, physically-controlled bench, at
minimum change `FORENSIC_USER`/`FORENSIC_PASS` and set up TLS.

**On the git/OS update buttons:** "Update App (Git Pull)" runs `git pull origin main` in the
install directory and restarts the service on success; "Update OS Packages" runs
`apt-get update && apt-get upgrade -y` in the background. Neither takes attacker-controllable
input, so they aren't injectable - but both pull code or packages from external sources by
design. Only use them on a station where you trust the configured git remote and APT sources.

---

## Maintenance Commands
Restart Web Service:
```Bash
sudo systemctl restart pi-forensics.service
```

View Live Web Engine Logs:
```Bash
sudo journalctl -u pi-forensics.service -f
```

If you set up the TLS reverse proxy, these are also useful:
```Bash
sudo nginx -t                        # validate the config after any manual edits
sudo systemctl reload nginx          # apply config changes without dropping connections
sudo journalctl -u nginx -f          # nginx logs
```

> **Note:** the generated systemd unit runs gunicorn with `--workers 1 --worker-class gthread --threads 4`.
> Job progress (`current_job` in `app.py`) is tracked in process memory, not a shared store - running
> multiple gunicorn *worker processes* would give each one its own independent copy of that state, so
> a progress-poll request could land on a different worker than the one running the acquisition and
> show stale/default data. Threads (within the single process) don't have this problem. If you ever
> need more request concurrency, raise `--threads`, not `--workers`.

---

## Troubleshooting

### Kiosk mode doesn't start on boot
This almost always means desktop autologin isn't set up for the service account - labwc (the
kiosk compositor) only runs `~/.config/labwc/autostart` when that account's graphical session
actually starts, which requires autologin on a stock image.

1. Check what the installer reported: it prints `[ACTION NEEDED]` at the end of the run if it
   couldn't confirm autologin was configured.
2. Verify/fix manually: `sudo raspi-config` → **System Options** → **Boot / Auto Login** →
   **B4 Desktop Autologin**, confirm the account selected matches your service user, reboot.
3. Confirm you flashed **Raspberry Pi OS with Desktop**, not the Lite/headless image - kiosk mode
   can't work without a desktop session to autologin into.
4. If autologin is confirmed correct and kiosk still doesn't appear, check
   `~/.config/labwc/autostart` exists and is executable (`ls -la`) for the service account's home
   directory, and that it's owned by that account, not root.

### Web dashboard isn't reachable over the LAN/WiFi
Nothing in this project touches WiFi, network interfaces, or firewall rules - if it was reachable
before and now isn't, check these in order:

1. **Is the service actually running?** `sudo systemctl status pi-forensics.service` - if it's not
   active, check `sudo journalctl -u pi-forensics.service -e` for the actual startup error.
2. **If you set up TLS**, nginx is what's actually listening on the network (gunicorn moves to
   loopback-only). Check `sudo systemctl status nginx` too - if nginx isn't running, the service
   being fine doesn't help you from another device.
3. **Did the Pi's IP address change?** A DHCP lease renewal after reboot is a common, totally
   unrelated cause of "it stopped working" - check `hostname -I` or your router's client list for
   the current address rather than assuming it's the same as last time.
4. **Client isolation on the WiFi network.** Some routers (especially guest networks or mesh
   systems) block device-to-device traffic by design - try from a device on the same network
   segment, or check your router's AP isolation setting.
5. Once you've confirmed the service is up and you have the right IP, use the diagnostics in
   Advanced Settings (`ip a`) from a device that *can* reach it (e.g. the kiosk itself, which talks
   to gunicorn over loopback regardless of LAN status) to see what address it's actually on.

### Login fails even with the right password
Check for the brute-force lockout (5 failed attempts = 5 minute lockout, returns HTTP 429) before
assuming the credentials are wrong - repeated attempts while troubleshooting something else is a
common way to trigger this. See `sudo cat /etc/systemd/system/pi-forensics.service | grep FORENSIC`
to confirm what's actually configured, then `sudo systemctl restart pi-forensics.service` if you
changed it and aren't sure the running process picked it up.

---

## Uninstalling

```bash
cd /opt/pi-forensics
sudo python3 uninstall.py
```

This reverses what `install.py` set up: stops/disables the `pi-forensics` service (and any legacy
`pi-kiosk` unit), removes the nginx site and TLS materials, removes the sudoers and udev rules, and
optionally removes `/opt/pi-forensics` itself and the service system user. Each destructive step
asks for confirmation individually. **Evidence images under `/mnt` or your network mounts are never
touched** - only application/service configuration is removed. System packages (`dc3dd`, `nginx`,
etc.) are intentionally left installed; the script prints the `apt remove` command to run them
yourself if you want them gone too.