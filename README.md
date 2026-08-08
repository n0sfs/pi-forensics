# pi-forensics, arm-forensic-station
Low Budget Forensic Drive Imaging Using Arm Based Single Board Computers

# 🛡️ Raspberry Pi ARM Forensic Acquisition Station

An open-source, web-based digital forensic imaging appliance built for Raspberry Pi and ARM single-board computers. Designed for field kit deployment, evidence collection, and network-streamed disk imaging. Based on original research "Low Budget Forensics using ARM Based Single Board Computers"
https://commons.erau.edu/jdfsl/vol11/iss1/3/

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20ARM64-red)

---

## 🌟 Key Features

- **Works on Pi or ARM SBC:** Install on Raspberry Pi or ARM SBC with Debia
- **Bit-Stream Acquisition:** Leverages `dc3dd` for raw image acquisition (`.dd`) and 'ewfacquire' for E01 acquisition with hash verification (MD5, SHA-1, SHA-256).
- **ARM Memory-Safe Architecture:** Built with non-blocking process pipelines and active memory buffer syncing (`os.sync()`) to eliminate Out-Of-Memory kernel panics on embedded hardware.
- **Integrated Network Mounting:** Auto-discovers, authenticates, and mounts remote SMB/CIFS, NFS, and FTP shares natively in the UI with protocol fallback support.
- **SMART Health Diagnostics:** Instant drive health checks (`smartctl`) inspecting reallocated sectors, temperature, power-on hours, and bad block flags prior to imaging.
- **Software Write-Blocker Toggle:** Quick toggle for `udev` read-only rule enforcement (`ATTR{ro}="1"`) to preserve chain of custody.
- **Automated Evidence Manifests:** Generates structured `evidence_manifest.json` and human-readable `.txt` reports capturing case numbers, evidence IDs, examiner notes, drive serials, and timestamps.
- **Touchscreen & Remote Friendly:** Responsive dark-mode UI with drag and drop interface designed for onboard Pi touchscreen displays or headless browser control over Wi-Fi/Ethernet.
- **FIle Explorer:** Dual Pane File Explorer Tab with copy to or from Device.
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
  <em>Figure 2: Dual Pane File Explorer Tab with copy to or from Device.</em>
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

#System packages and services required on the host Raspberry Pi (Debian/Raspberry Pi OS):

```bash
sudo apt update
sudo apt install -y python3-full python3-pip python3-openssl python3-flask python3-dev python3-flask-httpauth python3-venv python3-psutil smartmontools dc3dd ewf-tools util-linux udevil smbclient nfs-common curlftpfs cifs-utils ewf-tools afflib-tools
sudo apt upgrade -y

#Clone Repository & Install Python Requirements
#Modern Raspberry Pi OS releases enforce PEP 668 to protect system Python packages. Modern Raspberry Pi OS releases enforce PEP 668 to protect system Python packages. Setting up a dedicated virtual environment (venv) ensures isolated and reliable package installation: If installing Python requirements via pip, pass --break-system-packages (or rely on the APT packages installed above):
cd /opt
sudo git clone https://github.com/n0sfs/pi-forensics.git
cd pi-forensics

# Create the virtual environment
python3 -m venv /opt/pi-forensics/venv
# Activate and install requirements
/opt/pi-forensics/venv/bin/pip install --upgrade pip
/opt/pi-forensics/venv/bin/pip install -r /opt/pi-forensics/requirements.txt

#Sudoers Configuration (/etc/sudoers.d/pi-forensics)
#app.py invokes system commands using sudo for raw block device manipulation, SMART queries, network mounting, and write-blocker toggling.
#Create a dedicated sudoers file so the service user (e.g., pi or root) can run these specific binaries without password prompts:
sudo visudo -f /etc/sudoers.d/pi-forensics
#Add the following line (replace pi with your actual service user if different):
pi ALL=(ALL) NOPASSWD: /usr/sbin/blockdev, /usr/sbin/smartctl, /bin/mount, /bin/umount, /usr/bin/udevil, /usr/bin/pkill, /usr/bin/smbclient, /usr/sbin/showmount
sudo chmod 0440 /etc/sudoers.d/pi-forensics

Create a dedicated sudoers file so the service user (e.g., pi or root) can run these specific binaries without password prompts:
#Copy Systemd Units & Enable Services
sudo cp /opt/pi-forensics/systemd/pi-forensics.service /etc/systemd/system/
#To register the service with systemd and launch the engine automatically on boot:
sudo systemctl daemon-reload
sudo systemctl enable --now pi-forensics.service
sudo systemctl restart pi-forensics.service

#Login via a web browser from another local network device for headless deployment: http://<your Pi or ARM IP>:5000


#To access via touchscreen and directly on Pi, you can enable the kiosk mode
sudo cp /opt/pi-forensics/systemd/pi-kiosk.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pi-kiosk.service
sudo systemctl restart pi-kiosk.service


