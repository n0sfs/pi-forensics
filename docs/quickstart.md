# Quick-Start Guide

Get from a fresh Raspberry Pi to a completed, hashed acquisition and a PDF report in about 20
minutes. This guide assumes you've never used Pi Forensics Suite before and don't have a forensics
background — every step says exactly what to click.

For the full reference once you're up and running, see the [User Manual](user-manual.md). For a
deeper look at the install process, security model, and troubleshooting, see the main
[README](../README.md).

---

## What you'll need

- A Raspberry Pi (or another ARM64 single-board computer) running **Raspberry Pi OS (64-bit) with
  Desktop** — not the Lite/headless image, if you want the touchscreen kiosk mode. A Pi 4 or 5 with
  4 GB+ RAM is comfortable; a Pi 3 works but acquisitions will be slower.
- A microSD card (or SSD) for the Pi's own operating system, separate from any evidence drive.
- Optional but recommended: a USB write-blocker adapter for the drive you're going to image. (This
  app also enforces a software write-block automatically — see [How write-blocking
  works](#how-write-blocking-works) below — but a hardware blocker is good practice on top of it.)
- A network connection during install (Wi-Fi or Ethernet) to download packages. Not needed
  afterward for day-to-day acquisition work.
- A drive to practice on — ideally something with no real data on it, since this first run is just
  to confirm everything works.

---

## 1. Install the software

Open a terminal on the Pi (or SSH into it) and run:

```bash
sudo git clone https://github.com/n0sfs/pi-forensics.git /opt/pi-forensics && cd /opt/pi-forensics && sudo python3 install.py
```

The installer will ask you a handful of questions. The defaults are fine for a first run — press
Enter to accept each one unless you already know you want something different. It will ask you to:

- Confirm which Linux user account the software should run as (defaults to the account you're
  already logged in as).
- Set a password for that account, if it doesn't already have one.
- Choose a username and password for your **first web dashboard login** — this is the account
  you'll actually log into the app with. Don't leave this blank in a real deployment; for a quick
  first test it's fine to accept the default and change it later.
- Decide whether to set up HTTPS (a self-signed certificate + reverse proxy). Say yes if you plan to
  access this station remotely over the network; you can always add it later from Settings if you
  skip it now.
- Decide whether to download offline map tiles for the Geolocation feature. Safe to skip — it's for
  stations that won't have internet access later, and can be run again anytime.

The install takes several minutes — it's installing every forensic tool this app uses (imaging
engines, file-recovery tools, Sleuth Kit, and more) plus setting up the touchscreen kiosk, the
write-blocking rule, and the web service.

When it finishes, the installer prints a summary. If anything needs your attention (like the
dashboard login still being on its default value), it'll say so clearly under an `[ACTION NEEDED]`
heading.

---

## 2. Open the dashboard

**On the Pi's own touchscreen:** it launches automatically at boot, full-screen, no login required
— physical access to the device is treated as already-trusted. If nothing appears after a reboot,
see the [README's troubleshooting section](../README.md#-troubleshooting).

**From another computer on the same network:** open a browser and go to the Pi's IP address —
`https://<PI_IP_ADDRESS>` if you set up HTTPS during install, otherwise `http://<PI_IP_ADDRESS>:5000`.
You'll see a login page; use the dashboard username/password you set during install. (If you see a
"this connection isn't private" warning on the HTTPS version, that's expected for a self-signed
certificate — see Settings > Security once you're logged in for how to make your browser trust it
permanently.)

Every remote/network connection requires a real login. Only the physical touchscreen skips it.

---

## 3. Create a case

In the top bar, click **Case** and choose **Create New Case**. Give it a case number (letters,
numbers, dashes, and underscores are fine) and your name as examiner, then save.

This isn't required — every tool works fine with no case selected — but it saves real time: once a
case is active, your Case Number, Examiner, and Destination folder auto-fill on every acquisition,
recovery, and mobile job you run afterward, and Reporting automatically finds and loads that case's
data with nothing to browse for.

---

## 4. Image a drive

1. Connect the drive you want to image via USB. (It's write-blocked automatically the moment it's
   plugged in — see [below](#how-write-blocking-works).)
2. Go to the **Forensic Acquisition** tab.
3. Under Target Source Selection, pick your drive from the dropdown.
4. Take a look at the SMART telemetry that appears — it's the drive's own self-reported health data,
   worth a glance before committing to a long imaging job.
5. Leave the write-blocker switched on (it's on by default). The badge at the top of this tab always
   shows the current state for whichever drive is selected.
6. Under Format, leave it on the default (**dc3dd**) — a solid, widely-trusted choice for a first
   acquisition, with hashing built in.
7. Your Case Number, Examiner, and Destination should already be filled in from step 3. If you
   didn't create a case, fill them in by hand now.
8. Click **Start Acquisition**, and wait. Progress, transfer speed, and a live console are all shown
   on the right. For a small test drive this might take a few minutes; a large drive can take hours
   — that's expected for bit-for-bit imaging, not a sign something's wrong.
9. When it finishes, the status will read **Completed Successfully**, with the computed hash shown.

That's a real, verifiable, bit-for-bit forensic image, done.

---

## 5. Generate a report

1. Go to the **Reporting** tab. If you created a case in step 3, it's already loaded.
2. Click **Jobs** in the left-hand list — the acquisition you just ran is there, with its full
   telemetry and hash.
3. Click **Export**. Choose PDF (or HTML), leave the default "Standard" report template selected,
   and leave every section checked for a first export.
4. Click **Export**. The finished report downloads with everything from the case, evidence details,
   and the acquisition's hash all included, ready to hand off or file.

---

## Where to go from here

- **[User Manual](user-manual.md)** — every tab and tool, explained in full: file recovery, mobile
  device acquisition, browsing inside an acquired image, encrypted-drive support, tagging evidence,
  memory forensics, custom report templates, and station security/accounts.
- **The in-app Help button** (bottom of the sidebar) has guided walkthroughs for common real-world
  scenarios — a damaged/clicking drive, recovering deleted files, acquiring a phone, and writing up
  findings — plus a searchable FAQ and tool reference, without leaving the app.
- **[README.md](../README.md)** — the full security model, environment variables, maintenance
  commands, and a longer troubleshooting reference.

---

## How write-blocking works

Every USB storage device connected to the station is forced into hardware-level read-only mode the
moment it's plugged in, by a rule this app installs system-wide — nothing (this app or anything
else running on the Pi) can accidentally write to it. You'll only ever need to turn this off for a
**destination** drive you're deliberately writing an image *to*, from Settings > Drive Management —
never for the drive you're imaging *from*.
