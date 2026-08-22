# Changelog

All notable changes to Pi Forensics Suite are documented in this file, in plain language for anyone
running the application - not a developer's internal engineering log (there is a separate, much more
detailed internal history kept alongside the source for that purpose, not distributed with releases).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/), and this project uses
[Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** - a change that isn't backward compatible (a different installation process, a removed
  feature, a data format an older version can't read).
- **MINOR** - new functionality that's backward compatible (a new tool, a new report section, a new
  tab).
- **PATCH** - bug fixes and small improvements with no new functionality.

Each released version corresponds to an annotated git tag (`vMAJOR.MINOR.PATCH`) in this repository,
so you can always check out the exact code that shipped as a given version. The in-app **Settings >
Service Controls & Diagnostics > Update App (Git Pull)** button updates a station to the latest commit
on its configured branch, which is not necessarily the same as the latest tagged release - check this
file after updating to see what changed.

---

## [1.0.0] - 2026-08-22

Initial tagged release. Pi Forensics Suite has been under continuous development and real-world use
prior to this point; this is the first version to receive a formal version number, changelog, and
release tag, marking it as a stable baseline going forward.

### Acquisition

- Bit-for-bit disk imaging with a choice of engine: `dc3dd` (default, with on-the-fly hashing),
  `dcfldd`, plain `dd` (genuine direct-I/O cache bypass), `ewfacquire` (EnCase/E01), and AFF, all with
  MD5/SHA-1/SHA-256 verification.
- `ddrescue` is a format option on the same acquisition screen, not a separate tool - pass-strategy
  selection (fast/trim/scrape/reverse), retry-pass tuning, and a Mapfile Inspector for reviewing
  bad-sector results.
- A hardware-independent software write-blocker (`udev`-enforced) protects every newly connected USB
  storage device by default, with a Settings toggle to deliberately unlock a destination drive.
- **Live Device Preview** - browse a connected drive read-only, before committing to a full
  acquisition, using the same file-browsing tools available for an already-acquired image.
- **Logical / Custom-Content Acquisition** - select specific folders (rather than an entire device)
  and package them into one hash-verified evidence container with a manifest, optionally as a `.zip`.
- **Image format conversion** - convert an already-acquired image between raw (`.dd`) and E01 after
  the fact, with independent hash verification of the result.
- **Encrypted volume support** - unlock a BitLocker- or LUKS-encrypted drive or partition (with a
  known recovery key/passphrase) before or after acquisition, so acquisition and analysis both work
  against the decrypted contents. The recovery key/passphrase itself is recorded in the case report
  as documentation, never used to re-derive access on its own.

### Mobile Forensics

- iOS full-device backup via `idevicebackup2`, with an optional encrypted-backup mode to capture
  Keychain data.
- Android acquisition via `adb pull`, `adb backup`, and `adb bugreport`.
- Real device detail (model, OS/build version, storage capacity, IMEI, WiFi/Bluetooth MAC, activation
  state for iOS; version, API level, manufacturer, build ID for Android) is read and shown before you
  start. This does not bypass lockscreens or USB-debugging authorization - devices must already be
  unlocked and trusted by the examiner.

### File Recovery

- One shared tool selector and workspace for PhotoRec, `extundelete`, `foremost`, `scalpel`, and
  read-only TestDisk partition analysis, instead of a separate screen per tool.
- **Filesystem-aware deleted file recovery** - unlike signature-based carving, this reads a supported
  filesystem's own directory structure to recover deleted files under their real name and folder
  location, directly from an acquired image.
- A native, dependency-free triage scanner (email/URL/IP/card-number/phone-number pattern matching)
  runs against raw devices or already-acquired images, with support for your own custom keyword and
  regex lists alongside the built-in categories.

### File Explorer & Analysis

- Browse local evidence and mounted network shares (SMB, NFS, SFTP) with inline preview for images,
  PDFs, and sandboxed HTML rendering; other files show a metadata/info panel.
- Double-click (or expand in the folder tree) an acquired image to browse **inside its filesystem**
  directly - no mount step required - with real per-file MACB timestamps, recursive filename search,
  a full MACB timeline view, in-memory preview, and extraction. Supports multiple partitions and
  unallocated space within a single image.
- Right-click any file or folder for ExifTool metadata, Binwalk, ClamAV, `strings`, `hashdeep`, a
  Sleuth-Kit-based whole-filesystem hash manifest, geolocation extraction (GPS EXIF -> viewable/
  exportable KML map), an MVT spyware/IOC scan, and browser-artifact parsing (Chrome/Chromium and
  Firefox history, bookmarks, downloads, and cookie metadata).
- **File Views** - a per-case analysis index (by file-type category, tagged files, keyword/pattern
  hits, and parsed browser artifacts) with live counts, built without re-scanning the evidence on
  every visit.
- **Tagging** - apply Autopsy-style tags (Bookmark, Follow Up, Notable Item, or your own custom tags)
  to individual files, with optional comments, from anywhere a file can be selected.
- **Memory forensics** - analyze an already-captured Windows memory image (RAM dump) with a curated
  set of Volatility 3 plugins (process listings, network connections, DLLs, loaded services,
  malware-indicator scanning, and more), viewable directly in the browser.

### Case Management & Reporting

- Create a case once and every acquisition, recovery, and mobile job auto-fills Case Number,
  Examiner, and Destination against it. Each case is a real folder with one consolidated report file,
  not scattered per-job files.
- A timestamped, append-only Case Notes journal (with file attachments and a local integrity hash per
  note - tamper-evidence, not legal notarization), a separate polished Report Narrative section
  (Executive Summary, Objectives, Findings, Limitations, Conclusion, and more), a per-job Jobs view,
  and a station-wide Audit Trail filtered to the case, plus a search across all of them.
- Exhibits (case attachments) show their tags and any prior analysis-tool results directly, and can
  be linked from a Case Note.
- Export to PDF, HTML, JSON, or CSV, with a choice of report structure: a fully configurable
  "Standard" layout, or one of three fixed structures modeled on established formats - a DFIR
  incident-report style, a law-enforcement examination-report style, and one aligned to the CASE/UCO
  digital-investigation ontology. Custom report templates can also be built by picking, reordering,
  and renaming the same underlying sections. Every export can include a real evidence-location map
  built from any GPS data extracted during analysis, and every PDF/HTML export includes a SHA-256
  integrity hash for the exported file itself.
- Legacy (pre-consolidated) cases can be migrated to the current case format non-destructively - the
  original files are preserved, never deleted.

### Security & Accounts

- Real per-examiner accounts (securely hashed passwords) with configurable permission groups
  (built-in Admin and Analyst groups, plus your own custom groups) controlling access to each major
  area of the application.
- Session-based login with an idle timeout, brute-force lockout on repeated failed logins, and a
  "Switch User" option that doesn't require closing the browser.
- A software write-blocker toggle backed by `udev`, an unprivileged service account with narrowly
  scoped administrative permissions (no general root access), and an append-only chain-of-custody log
  with CSV export.
- Physical access to the station's own touchscreen bypasses login by default (configurable); every
  remote/network connection always requires authentication.
- Self-signed HTTPS out of the box, with in-app certificate generation/replacement and download, plus
  guided per-OS trust instructions.
- Encrypted configuration backup and restore, so a station's accounts, settings, and saved
  credentials can be recovered after a reinstall or hardware swap.

### Network & Remote Access

- Mount network shares (SMB, NFS, SFTP) as evidence sources, with optional encrypted-at-rest saved
  credentials and automatic reconnection on reboot.
- Configure the station's own network settings (static IP or DHCP) from the app, with an automatic
  safety rollback if a change would lock out the connecting device.
- Optional offline map-tile caching for report geolocation maps on a station with no internet access
  at the time a report is generated.

### Kiosk & Station Management

- Runs as a touchscreen kiosk (auto-starting, crash-recovery-supervised) or a normal browser-based
  application on the local network, with a responsive layout for phones, tablets, and desktop
  monitors.
- Built-in Help with guided walkthroughs, an FAQ, and a tool reference, all reachable without leaving
  the app.
- A guided installer (`install.py`) handles system package installation, service setup, and optional
  TLS configuration; a matching uninstaller reverses it.
