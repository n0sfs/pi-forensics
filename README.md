# pi-forensics / ARM Forensic Acquisition Station

Low-budget forensic disk imaging for Raspberry Pi and other ARM SBCs.

**Repository:** https://github.com/n0sfs/pi-forensics

Supports **dc3dd** (raw), **ewfacquire** (E01), and **ddrescue** (damaged media), with a web UI, dual-pane file explorer, SMART checks, network mounts, evidence manifests, and PDF export.

Based on: [Low Budget Forensics using ARM Based Single Board Computers](https://commons.erau.edu/jdfsl/vol11/iss1/3/)

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
---

## Security model (this release)

| Control | Behaviour |
|--------|-----------|
| Authentication | Basic Auth required for all non-loopback clients |
| Weak passwords | Server refuses to start accepting logins if `FORENSIC_PASS` is missing, &lt; 10 chars, or a known default (`forensics`, `password`, …) |
| Private-network bypass | **Off** by default (`FORENSIC_AUTH_BYPASS=0`) |
| Bind address | App listens on `127.0.0.1:5000` only |
| TLS | nginx terminates HTTPS on 443 (self-signed cert by installer) |
| Path allow-list | File ops limited to `/mnt`, `/media`, `/opt/pi-forensics`, `/tmp/forensic` |
| Device sanitisation | Only legitimate block device names accepted |
| SMB credentials | Written to mode-0600 temp files under `/opt/pi-forensics/run/`; deleted after mount. `smbclient` uses `PASSWD` env, not argv |
| Command execution | No `shell=True`; absolute binary paths matching sudoers |
| Job state | Protected by `threading.RLock` |
| Drive discovery | Queries RO state only; does **not** force `--setro` on every scan |

### Write-blocker warning

The software write-blocker (`blockdev --setro` + udev rules) is **not** a certified hardware write-blocker. For chain-of-custody evidence, always use a hardware write-blocker.

---

## Quick install

```bash
# On Raspberry Pi OS / Debian ARM
Open a terminal (or SSH) and run:
```bash
sudo git clone https://github.com/n0sfs/pi-forensics.git /opt/pi-forensics && cd /opt/pi-forensics && sudo python3 install.py
```

The installer will:

1. Create or select a service user  
2. Require a strong web password (or generate one)  
3. Install packages (`dc3dd`, `ewf-tools`, `gddrescue`, `nginx`, …)  
4. Create venv + install Python deps  
5. Install scoped sudoers and USB RO udev rules  
6. Generate a self-signed TLS certificate  
7. Configure nginx (HTTP→HTTPS redirect, reverse proxy to gunicorn)  
8. Enable the systemd service and optional kiosk autostart  

Then open: **https://<pi-ip>**  
(Accept the self-signed certificate warning.)

### Accessing the Dashboard
Local Kiosk: Launches automatically at boot in full-screen touchscreen mode.


---

## Manual configuration (if needed)

```bash
# Change web credentials
sudo systemctl edit pi-forensics
# Add:
# [Service]
# Environment="FORENSIC_USER=admin"
# Environment="FORENSIC_PASS=your-long-random-password"
# Environment="FORENSIC_AUTH_BYPASS=0"

sudo systemctl restart pi-forensics
```

TLS files live under `/etc/ssl/pi-forensics/`. Replace with an internal-CA certificate for multi-machine trust.

---

## ddrescue usage

Use the **Damaged Drive Recovery** tab:

1. Select the source device  
2. Choose strategy: Stage 1 (fast), Stage 2 (trim), Stage 3 (intensive), or reverse  
3. Optionally enable direct disk access  
4. Start the pass – a `.map` file is written next to the image  
5. Inspect the mapfile to see rescued / non-tried / bad-sector totals  
6. Re-run later stages against the same mapfile for progressive recovery  

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
---

## Uninstall

```bash
cd /opt/pi-forensics   # or wherever the release was unpacked
sudo python3 uninstall.py
```

The uninstaller stops services, removes nginx site/sudoers/udev rules, and can optionally remove TLS certs, `/opt/pi-forensics`, the service user, and kiosk autostart. Evidence under `/mnt` is never deleted. System packages (`dc3dd`, `nginx`, etc.) are left installed so you can remove them with `apt` if you want.

---

## Development / local run

```bash
cd /opt/pi-forensics
source venv/bin/activate
export FORENSIC_USER=admin
export FORENSIC_PASS='a-strong-password-here'
python app.py   # binds 127.0.0.1:5000
```

For production always use the gunicorn unit behind nginx.

---

## License

GNU GPL v3 or later. Provided as-is without warranty. Always verify image integrity with independent tools and follow your organisation’s chain-of-custody procedures.


---

## 📸 Screenshots

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