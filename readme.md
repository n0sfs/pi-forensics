# 🛡️ Raspberry Pi ARM Forensic Acquisition Station

An open-source, web-based digital forensic imaging appliance built for Raspberry Pi and ARM single-board computers. Designed for field kit deployment, evidence collection, and network-streamed disk acquisition.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20ARM64-red)

---

## 🌟 Key Features

- **Bit-Stream Acquisition:** Leverages `dc3dd` for raw image acquisition (`.dd`) with optional hash verification (MD5, SHA-1, SHA-256).
- **ARM Memory-Safe Architecture:** Non-blocking process pipelines and active write-buffer flushing (`os.sync()`) prevent Out-Of-Memory kernel panics on embedded hardware.
- **Integrated Network Target Discovery:** Auto-discovers, authenticates, and mounts remote SMB/CIFS, NFS, and FTP shares directly in the UI with automatic SMB protocol fallbacks.
- **SMART Health Diagnostics:** On-demand drive health checks (`smartctl`) inspecting reallocated sectors, temperature, power-on hours, and bad block flags prior to imaging.
- **Software Write-Blocker Toggle:** Quick toggle for `udev` read-only rule enforcement (`ATTR{ro}="1"`) to maintain chain of custody.
- **Automated Evidence Manifests:** Generates structured `evidence_manifest.json` and human-readable `.txt` reports capturing case numbers, evidence IDs, examiner notes, drive serial numbers, and acquisition duration.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI optimized for onboard touchscreen displays or remote browser operation over Wi-Fi/Ethernet.

---

## 📁 Repository Structure
pi-forensics/
├── app.py                     # Main Flask Application & dc3dd Backend Engine
├── kiosk.sh                   # Onboard Touchscreen Kiosk UI Launcher
├── requirements.txt           # Python Dependencies
├── README.md                  # Documentation
├── LICENSE                    # MIT License
├── .gitignore                 # Exclusion rules
├── static/
│   └── js/
│       └── main.js            # Frontend REST Poller & Dynamic UI Handlers
├── templates/
│   └── index.html             # Responsive Bootstrap Dark-Mode Dashboard
└── systemd/
├── pi-forensics.service   # Systemd unit file for Flask Backend
└── pi-kiosk.service       # Systemd unit file for Touchscreen Kiosk Mode
