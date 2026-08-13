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
- **Case Management:** A persistent bar (below the telemetry strip, visible from every tab) to create or select a case - once active, it auto-fills Case#/Examiner/Destination into every acquisition, recovery, and mobile job launcher, and each case gets a real folder on disk (marked by a `case_info.json` file) instead of evidence just being grouped by filename prefix. Entirely optional - every tool works exactly as before if no case is active, and fields stay editable, not locked.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI with drag and drop interface designed for onboard Pi touchscreen displays or headless browser control over Wi-Fi/Ethernet. An on-screen keyboard (`wvkbd`) is visible by default at boot for the login prompt, auto-hides once you're signed in, and is a tap away in the top navbar after that.
- **Collapsible Sidebar Navigation:** The six main sections (Forensic Acquisition, File Recovery, File Explorer, Mobile Forensics, Reporting, Settings) live in a left sidebar rather than a horizontal tab bar - toggle between icons-with-labels and icons-only via the chevron button at the top, freeing up screen width on smaller displays. The choice persists across visits.
- **Recovery-Aware Acquisition:** `ddrescue` lives as a Format option in the main Acquisition tab (alongside dc3dd/dcfldd/E01/AFF) rather than a separate workflow - select it to get pass-strategy selection (Fast Copy, Trimming, Scraping, Reverse Reading), retry passes, and Direct I/O, sharing the same status display, source drive, and Start/Stop controls as every other format.
- **File Recovery Suite:** A dedicated tab bringing together everything for working with damaged or already-acquired evidence, consolidated into one tool selector rather than a separate card per tool: PhotoRec and Sleuth Kit's Image Browser (already documented above), plus `extundelete` (deleted-file recovery for ext2/3/4 filesystems via the journal, can restore original filenames unlike carving tools), `foremost` and `scalpel` (alternate signature-based file carvers - scalpel is multithreaded and ships with a curated common-format config, since its stock config has every signature disabled by default), a Mapfile Audit Inspector for reviewing a completed ddrescue run's bad-sector summary, and read-only TestDisk partition analysis (uses TestDisk's dedicated `-l` listing flag specifically - never the separate write-capable repair mode, so it can never modify the evidence it's examining).
- **Forensic File Explorer:** Its own sidebar tab - a single-pane browser (local evidence and network mounts) with a live preview pane and right-click/press-and-hold "Copy to..." between folders, plus the "Actions" menu documented below (metadata, hashing, malware/embedded-file scanning, MVT).
- **File Carving & Recovery (PhotoRec):** Recovers files by signature (~480 known types) from a device or an already-acquired image - useful when a filesystem is too damaged for normal file listing. Read-only against the source; never writes back to it (unlike TestDisk's separate partition-repair mode, which this project deliberately does not expose, since rewriting a partition table would modify the evidence).
- **File Metadata Viewer (ExifTool):** One-click metadata (EXIF, document properties, etc.) for any selected file in the File Explorer, without leaving the app.
- **Image Filesystem Browser (Sleuth Kit):** Browse *inside* an acquired image's filesystem - list partitions (`mmls`), navigate directories including deleted-but-still-listed entries (`fls`), and extract a specific file out to the evidence directory (`icat`) - all read-only against the image. E01 support depends on how this system's Sleuth Kit build was linked and is checked at runtime rather than assumed; the UI warns if it looks unsupported.
- **Triage Tools (Binwalk, ClamAV, hashdeep, strings, MVT):** Available from the File Explorer's "Actions" menu - scan a file for embedded firmware/filesystem signatures (Binwalk), scan a file or directory for known malware (ClamAV), extract readable text from a binary (`strings`), generate a recursive SHA-256 manifest for an entire recovered directory (`hashdeep`), or scan an acquired mobile backup for spyware/compromise indicators (MVT - Mobile Verification Toolkit). iOS is a clean fit against `idevicebackup2` output; Android support is best-effort, since `adb pull`/`bugreport` don't match MVT's expected backup format.
- **Audit Log:** Station-wide, append-only log of significant actions (acquisitions started, files deleted/copied, reports edited, image files extracted, cases created/selected) with timestamp and source IP - viewable from the Settings tab (on-screen view capped at 200 entries, most recent first), with a one-click Export to CSV that always includes the complete log, not just what's currently displayed. This station has a single shared login rather than per-examiner accounts, so entries reliably show *what* happened and *when*, not *who* beyond the source IP - see [Security](#-security).
- **Case Index:** A searchable table of every report this station has produced, scanned from the evidence root - click a row to load it straight into the report editor instead of hunting through the file tree.
- **Tool Versions:** A "Check Tool Versions" button in Settings lists the version of every external tool the app uses (`dc3dd`, `ddrescue`, `sleuthkit`, `exiftool`, `mvt-ios`/`mvt-android`, etc.) right in the Service Controls & Diagnostics panel - useful for support requests and for documenting exactly what tooling produced a given piece of evidence. Anything not yet installed gets a one-click Install button, scoped to the exact same allowlist of packages `install.py` itself would have installed - not a general "install anything" tool.
- **Quick Triage Scan:** Scans a device or image for structured data - emails, URLs, IP addresses, card-like numbers, phone numbers - without needing to understand filesystems or partitions. A beginner-friendly first pass; results are one plain-text file per category. Built in-house as a native Python scanner rather than depending on `bulk_extractor` (which isn't in Debian's mainline package archive - only found in Kali/Parrot's own repos, and would have broken `install.py` outright if left in its package list). No external tool dependency at all, so this can never hit a "package not found" wall - the tradeoff is that it's a straightforward single-threaded scan, not a highly-optimized C tool, so it's noticeably slower on very large (multi-TB) images.
- **Built-in Help & Reference:** A "Help" button in the top navbar (visible on every tab) opens a panel with a scenario-based getting-started guide (healthy drive, damaged drive, recovering deleted files, mobile device), an FAQ, a plain-language reference for every tool the app uses, and notes on data location/chain-of-custody/updates. Hovering jargon-heavy tool names (ExifTool, Sleuth Kit, Binwalk, ClamAV, hashdeep) also shows an inline explanation, and the format/strategy/mode dropdowns show live help text for whatever's currently selected - aimed at students and newcomers who shouldn't need to already know what these tools do.
- **Mobile Forensics (iOS & Android):** A dedicated tab for acquiring already-unlocked, already-trusted mobile devices - iOS full backup via `idevicebackup2` (with optional encrypted backup to capture Keychain data, plus a manual "Pair Device" trigger via `idevicepair`), and Android via `adb pull` (accessible storage, more reliable), `adb backup` (app data, requires on-device confirmation, unreliable on Android 12+), or `adb bugreport` (system logs/dumpstate snapshot). This does **not** bypass lockscreens, device pairing, or USB-debugging authorization - devices must already be unlocked and trusted/authorized by the examiner before acquisition can start, exactly like plugging a drive into the imaging station.
- **Settings:** Station password change (persisted independently of the systemd unit), safe USB drive eject, and a combined Service Controls & Diagnostics panel - service/kiosk restart, git-pull self-update, OS package update (both require explicit confirmation and a source you trust), reboot/power-off, Check Tool Versions, the Audit Log (documented above), and a fixed-allowlist read-only diagnostics dropdown (`dmesg`, `lsusb`, `df -h`, `ip a`, `uptime`, `lsblk`, `free -h`, `mount`) - deliberately **not** a free-text shell terminal. Every action in this panel reports into one shared output pane instead of popup alerts. See [Security](#-security) for why there's no free-text shell.
- **Reporting & Hash Verification:** Reporting, Case & URL attachments, JSON file raw viewer & PDF File export, and Image Integrity Verification with hash matching.

---

## 📸 Screenshot

<p align="center">
  <img src="docs/images/PIF1.JPG" width="100%" alt="Forensic Acquisition" />
  <br>
  <em>Figure 1: Forensic Acquisition Dashboard with the active-case bar (auto-fills Case#/Examiner/Destination), Drive Check, Write Blocker Toggle, Raw/EWF/ddrescue Output, MD5/SHA1/SHA256 Hashes, and Native Network Discovery, Drive Mapping and Telemetry.</em>
</p>

<p align="center">
  <img src="docs/images/PIF2.JPG" width="100%" alt="File Recovery Tools" />
  <br>
  <em>Figure 2: File Recovery tab - one unified tool selector (PhotoRec, extundelete, foremost, scalpel, Quick Triage Scan, TestDisk Partition Analysis, ddrescue Mapfile Inspector) sharing a single source/destination/metadata layout and live terminal output.</em>
</p>

<p align="center">
  <img src="docs/images/PIF3.JPG" width="100%" alt="Forensic File Explorer" />
  <br>
  <em>Figure 3: Forensic File Explorer, now its own tab - single-pane browser with a live preview pane, shown here previewing a case's <code>case_info.json</code> marker file inside its real per-case evidence folder.</em>
</p>

<p align="center">
  <img src="docs/images/PIF4.JPG" width="100%" alt="Mobile Forensics" />
  <br>
  <em>Figure 4: Mobile Forensics - device detection plus iOS full backup (idevicebackup2) and Android acquisition (adb pull/backup/bugreport) side by side, with an MVT spyware/IOC scan available afterward from the File Explorer's Actions menu.</em>
</p>

<p align="center">
  <img src="docs/images/PIF5.JPG" width="100%" alt="Reporting & Verification" />
  <br>
  <em>Figure 5: Reporting - case metadata editor, file/URL attachments, PDF export, and Evidence Image Integrity Verification with hash matching.</em>
</p>

<p align="center">
  <img src="docs/images/PIF6.JPG" width="100%" alt="Settings" />
  <br>
  <em>Figure 6: Settings - Security & Account Password, Safe Hardware Detach, the Audit Log (with one-click Export to CSV), and the combined Service Controls & Diagnostics panel (restart/update/power controls, a fixed-allowlist diagnostics dropdown, and Check Tool Versions) all reporting into one shared output pane.</em>
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
deploying. Both can also be changed later from the Settings tab (password only) or by
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
| **Authentication** | Every API route requires HTTP Basic Auth for remote/LAN/WiFi access - there is **no bypass** for private-subnet or proxied clients, even when nginx is in front of gunicorn. The one exception is the physical kiosk touchscreen itself; see below. |
| **Local kiosk auth bypass (opt-out)** | By default (`FORENSIC_KIOSK_AUTH_BYPASS=1`), the physical kiosk skips the login prompt - a working on-screen keyboard for the native Basic Auth dialog proved unreliable in this project's Wayland/labwc environment, so the practical choice was to either fight that indefinitely or accept that physical access to the touchscreen already implies a high trust level (it also gets you the SD card, recovery mode, etc.). This is detected narrowly via genuine loopback origin with no `X-Real-IP` header - a remote client proxied through nginx always has that header set to their real address, so **this never weakens remote/LAN/WiFi access**, which stays fully authenticated. Destructive actions (reboot, delete, etc.) still have confirmation dialogs regardless. Set `FORENSIC_KIOSK_AUTH_BYPASS=0` in the systemd unit to require login locally too. |
| **Brute-force protection** | 5 failed logins from an IP triggers a 5-minute lockout (in-memory; resets on service restart). |
| **Service privileges** | `app.py` runs as the service account you chose during install (not root). It only reaches root for the specific, whitelisted commands in `/etc/sudoers.d/pi-forensics` (mount/umount/mkdir under `/mnt`, blockdev, smartctl, dc3dd/ewfacquire/ddrescue, pkill). Raw device reads for imaging work via `disk` group membership, not sudo. |
| **File-system sandboxing** | The file explorer, report load/save, hash verification, PDF export, and imaging/recovery destinations are all restricted to one directory tree (`FORENSIC_ROOT`, default `/mnt`). Paths outside it are rejected, including via symlink or `../` traversal. |
| **Device validation** | Acquisition/recovery source paths must match a whole-disk device pattern (`/dev/sdX`, `/dev/nvme*n*`, `/dev/mmcblk*`) - arbitrary files can't be pointed at the privileged `ddrescue`/`dc3dd` commands. |
| **Evidence-drive-safe UI** | Filenames pulled from mounted/browsed media are rendered as plain text, never parsed as HTML - a maliciously named file on a suspect drive can't inject script into the examiner's session. |
| **Acquisition tools run via scoped sudo** | dc3dd/dcfldd/plain `dd`/ewfacquire/PhotoRec/ddrescue all need raw read access to the source device, which this unprivileged service account doesn't have by default - each runs via an exact-match NOPASSWD sudoers entry (never a wildcard on the tool itself). Their output lands owned by root as a side effect; the app automatically hands ownership back to the service account (via a similarly scoped `chown`/`chgrp` grant, fixed target user - never attacker-controllable) so later actions (delete, hash verify, copy) work normally. |
| **Chain-of-custody log limitation** | The log records what happened, when, and the source IP - it does **not** reliably attribute actions to a specific examiner, since this station has one shared login rather than per-examiner accounts. If your process needs per-examiner attribution, that requires separate accounts this project doesn't implement. |
| **Network share credentials** | SMB/CIFS passwords are passed via a private, mode-0600 temporary credentials file rather than on the mount command line, so they don't show up in `ps aux`. |
| **Transport encryption** | `install.py` prompts to set up nginx with a self-signed TLS certificate (generated per-install under `/etc/ssl/pi-forensics`). If accepted, nginx terminates TLS on 80/443 and gunicorn moves to loopback-only; if declined, gunicorn binds directly and Basic Auth credentials travel unencrypted. You can re-run the installer later to add TLS, or set it up manually - see `pi-forensics.conf` in this repo for the exact nginx config used. |
| **No free-text shell access** | The Settings tab's diagnostics panel runs a fixed allowlist of read-only commands (`dmesg`, `lsusb`, `df -h`, `ip a`, `uptime`, `lsblk`, `free -h`, `mount`) as literal argv lists - there is deliberately no general "run any command" box anywhere in the UI or API. A web-exposed shell is a full remote-code-execution hole on a device that images evidence; that trade-off isn't worth the convenience. |
| **Scoped privileged actions** | Power/service-restart/update controls in Settings each map to an exact, pinned sudoers entry (e.g. `systemctl restart pi-forensics.service`, `apt-get update`) rather than a wildcarded binary grant - the service account can't use these entries to run anything beyond what's listed. |
| **Password changes persist safely** | Changing the station password from Settings writes to `runtime_config.json` in the install directory (mode 0600, owned by the service account), not a world-readable file - it takes effect immediately and survives restarts without needing to edit the systemd unit. |

### Configuration (environment variables)

`FORENSIC_USER`/`FORENSIC_PASS` are set interactively during install (see "Dashboard Login"
above) and written into `/etc/systemd/system/pi-forensics.service`, which the installer restricts
to root-readable (`0600`) since it now holds a real password. To change any of these after the
fact, edit that file, then `sudo systemctl daemon-reload && sudo systemctl restart pi-forensics.service`:

| Variable | Default if left blank at install | Purpose |
|---|---|---|
| `FORENSIC_USER` | `admin` | Basic Auth username. |
| `FORENSIC_PASS` | `forensics` | Basic Auth password. Overridden at runtime if changed from the Settings tab (see above). |
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

### ddrescue fails with an "unaligned read" error, or fails inconsistently
Check the "Direct I/O Mode" checkbox in the ddrescue tab. It maps to ddrescue's real `-d`/
`--idirect` flag (bypasses the kernel cache when reading the source - verified against the actual
GNU ddrescue manual), which is genuinely useful on a failing drive, but the manual is explicit that
*"not all systems support this"* and *"if the sector size is not correctly set, an unaligned read
error may happen."* USB/SATA bridge adapters - common in budget setups - are a frequent source of
this. It defaults to **off** for that reason; try enabling it only if you're getting inconsistent
results with it off.

### Kiosk shows a blank/white screen (chromium process looks healthy)
This is a known bug ([RPi-Distro/chromium#54](https://github.com/RPi-Distro/chromium/issues/54)):
Chromium in kiosk mode on labwc/Wayland can drop out of proper fullscreen if the display's
resolution negotiation settles after Chromium has already started - it doesn't crash, it just ends
up stuck in a broken fullscreen-transition state, which looks exactly like this (process tree
healthy, screen blank). Two mitigations are already in the kiosk autostart script:

- A short delay after enabling outputs, before Chromium launches, to reduce the chance of racing
  the display's mode negotiation.
- A watchdog that force-restarts Chromium every 30 minutes regardless of whether it's "crashed" -
  since this bug doesn't actually crash the process, the normal crash-recovery loop can't catch it
  on its own.

If it happens between watchdog cycles, `sudo pkill -9 -f "chromium.*--kiosk"` from SSH will trigger
an immediate respawn without a full reboot.

### On-screen keyboard for kiosk mode
Chromium's `--kiosk` mode has no built-in virtual keyboard (that's a tablet-OS feature, not a
browser one), so this project runs `wvkbd` alongside it, starting hidden. Tap the **Keyboard**
button in the top navbar (visible on every tab) to show/hide it for text entry - case number,
evidence ID, examiner name, notes, network share host/path, etc.

**This is local-kiosk-only and never appears for remote access.** `wvkbd` controls a physical
overlay on the Pi's own screen - it has no meaning for someone accessing the dashboard from a
laptop or phone over the LAN, since they can't see the Pi's display at all. The server detects
whether a request came from the local kiosk (loopback, no `X-Real-IP` header - see the local
kiosk auth bypass in [Security](#-security) above, which uses the same detection) and only
renders the Keyboard button for that session.

It doesn't auto-show based on which field has focus, by design: Raspberry Pi OS's own default
on-screen keyboard (Squeekboard) has an [open upstream bug](https://github.com/labwc/labwc/issues/2926)
where it fails to render above fullscreen/kiosk Chromium on labwc. `wvkbd` avoids that problem
entirely by reserving its own strip of the screen via the Wayland layer-shell protocol rather than
trying to float on top of an already-fullscreen window - but that means nothing can automatically
detect "a text field just got focus" without deeper Wayland input-method integration, so it's a
manual toggle instead.

If it doesn't appear at all: confirm `wvkbd` installed correctly (`which wvkbd-mobintl`) and that
its respawn loop is running (`ps aux | grep wvkbd-mobintl` from an SSH session).

### "Browse Image" fails on an E01 file but works fine on .dd/.raw
Sleuth Kit's E01 support depends on whether this system's `sleuthkit` package was built with
`libewf` linked in - `install.py` installs `libewf-dev` to maximize the chance of this working,
but it isn't guaranteed (there's a documented real-world case of a distro shipping `sleuthkit`
without it). The Image Browser checks this at runtime and shows a warning banner if it looks
unsupported. If it fails: confirm with `mmls -i list` from SSH - if `ewf` isn't listed as a
supported type, you'd need a version of `sleuthkit` actually compiled against `libewf` to browse
E01s directly (raw `.dd`/`.raw` images are unaffected either way).

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
   Settings (`ip a`) from a device that *can* reach it (e.g. the kiosk itself, which talks
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