# arm-forensic-station
Low Budget Forensic Drive Imaging Using Arm Based Single Board Computers

# 🛡️ Raspberry Pi ARM Forensic Acquisition Station

An open-source, web-based digital forensic imaging appliance built for Raspberry Pi and ARM single-board computers. Designed for field kit deployment, evidence collection, and network-streamed disk imaging. Based on my original research "Low Budget Forensics using ARM Based Single Board Computers"
https://commons.erau.edu/jdfsl/vol11/iss1/3/

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20ARM64-red)

---

## 🌟 Key Features

- **Bit-Stream Acquisition:** Leverages `dc3dd` for raw image acquisition (`.dd`) with hash verification (MD5, SHA-1, SHA-256).
- **ARM Memory-Safe Architecture:** Built with non-blocking process pipelines and active memory buffer syncing (`os.sync()`) to eliminate Out-Of-Memory kernel panics on embedded hardware.
- **Integrated Network Mounting:** Auto-discovers, authenticates, and mounts remote SMB/CIFS, NFS, and FTP shares natively in the UI with protocol fallback support.
- **SMART Health Diagnostics:** Instant drive health checks (`smartctl`) inspecting reallocated sectors, temperature, power-on hours, and bad block flags prior to imaging.
- **Software Write-Blocker Toggle:** Quick toggle for `udev` read-only rule enforcement (`ATTR{ro}="1"`) to preserve chain of custody.
- **Automated Evidence Manifests:** Generates structured `evidence_manifest.json` and human-readable `.txt` reports capturing case numbers, evidence IDs, examiner notes, drive serials, and timestamps.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI designed for onboard Pi touchscreen displays or headless browser control over Wi-Fi/Ethernet.

---

## 📋 Prerequisites

System packages required on the host Raspberry Pi (Debian/Raspberry Pi OS):

```bash
sudo apt update
sudo apt install -y python3 python3-pip dc3dd smartctl smbclient showmount curlftpfs cifs-utils nfs-common

## Screenshots
<img width="1873" height="722" alt="AFS-1" src="https://github.com/user-attachments/assets/d1882c4a-7d46-43bb-8726-4fa79d6e8843" />
<img width="1836" height="692" alt="ASF-2" src="https://github.com/user-attachments/assets/1f530610-f140-4398-905e-0e645e372ad5" />
<img width="1861" height="731" alt="ASF-3" src="https://github.com/user-attachments/assets/8cb612ed-a99b-4a22-b778-82eae0db22ae" />



