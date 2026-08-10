# pi-forensics, arm-forensic-station
Low Budget Forensic Drive Imaging Using Arm Based Single Board Computers such as the Raspberry Pi

# 🛡️ Raspberry Pi & ARM Forensic Acquisition Station

An open-source, web-based digital forensic imaging appliance built for Raspberry Pi and ARM single-board computers. Designed for field kit deployment, evidence collection, and network-streamed disk imaging. Based on original research "Low Budget Forensics using ARM Based Single Board Computers"
https://commons.erau.edu/jdfsl/vol11/iss1/3/

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20ARM64-red)

---

## 🌟 Key Features

- **Works on Pi or ARM SBC:** Install on Raspberry Pi or ARM SBC with Debian.
- **Acquisition:** Leverages `dc3dd` for raw image acquisition (`.dd`) and 'ewfacquire' for E01 acquisition with hash verification (MD5, SHA-1, SHA-256). Global `udev` rules automatically force all connected USB storage devices (`sd*`) into Read-Only mode at insertion to preserve forensic integrity. Enforces direct block access (`O_DIRECT` / `iflag=direct`) to bypass Linux page caches and prevent buffer dirtying.
- **ARM Memory-Safe Architecture:** Built with non-blocking process pipelines and active memory buffer syncing (`os.sync()`) to eliminate Out-Of-Memory kernel panics on embedded hardware.
- **Integrated Network Mounting:** Auto-discovers, authenticates, and mounts remote SMB/CIFS, NFS, and FTP shares natively in the UI with protocol fallback support.
- **SMART Health Diagnostics:** Instant drive health checks (`smartctl`) inspecting reallocated sectors, temperature, power-on hours, and bad block flags prior to imaging.
- **Software Write-Blocker Toggle:** Quick toggle for `udev` read-only rule enforcement (`ATTR{ro}="1"`) to preserve chain of custody.
- **Automated Evidence Manifests:** Generates structured `evidence_manifest.json` and human-readable `.txt` reports capturing case numbers, evidence IDs, examiner notes, drive serials, and timestamps.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI with drag and drop interface designed for onboard Pi touchscreen displays or headless browser control over Wi-Fi/Ethernet.
- **File Explorer & DDRescue:** Dedicated `ddrescue` UI module with real-time pass strategy selection (Fast Copy, Trimming, Scraping, Reverse Reading) and `.map` file audit inspection along with Dual Pane File Explorer Tab with copy to or from Device.
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

#Pi and bootmedia with Pi OS or other Debian based OS configured
#https://www.raspberrypi.com/documentation/computers/getting-started.html

# Quick Installation (One-Line Automated Setup)
Pi and bootmedia with Pi OS or other Debian based OS configured
1. Flash a fresh **Raspberry Pi OS (64-bit)** image to your device and connect to the internet. (https://www.raspberrypi.com/documentation/computers/getting-started.html)
2. Open a terminal (or SSH) and run:
```bash
sudo git clone [https://github.com/YOUR_USER/pi-forensics.git](https://github.com/YOUR_USER/pi-forensics.git) /opt/pi-forensics && cd /opt/pi-forensics && sudo python3 install.py
```
#Interactive Installer Options
During execution, install.py will prompt you to specify the system account:

Account Creation: If the specified username does not exist, the installer will offer to create the user, set their password, and assign the required display/hardware groups (video, render, input, plugdev, sudo).

Automated System Setup: Configures scoped /etc/sudoers.d/pi-forensics privileges, systemd WSGI production services, udev write-blocking rules, and labwc kiosk autostart.

---

##Accessing the Dashboard
Local Kiosk: Launches automatically at boot in full-screen touchscreen mode.

Remote Web Interface: Navigate to http://<PI_IP_ADDRESS>:5000 in any web browser on your local subnet.

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