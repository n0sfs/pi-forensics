# Pi Forensics Suite — User Manual

A complete reference for every tab and tool. If you're setting this up for the first time, start
with the [Quick-Start Guide](quickstart.md) instead — come back here once you're up and running and
want to understand a specific feature in depth.

This manual assumes no forensics background. Terms like "write-blocker," "hash," and "chain of
custody" are explained the first time they come up.

## 1. What this station is (and isn't)

Pi Forensics Suite turns a Raspberry Pi (or similar ARM single-board computer) into a self-contained
digital forensics acquisition and triage station. It's built for the "image it, verify it, document
it" step that starts almost every examination, plus a genuinely useful set of file-recovery,
analysis, and mobile-acquisition tools on top — not as a replacement for a full forensic workstation
doing deep, courtroom-grade analysis.

Everything runs locally on the Pi. Nothing is uploaded anywhere automatically. Under the hood it
uses the same real tools examiners already trust — `dc3dd`, `dcfldd`, `ewfacquire`, `ddrescue`,
PhotoRec, The Sleuth Kit, ExifTool, Volatility3, MVT — wired together with hashing, write-blocking,
and chain-of-custody logging, not a simplified reimplementation of any of them.

You can use it two ways: as a **touchscreen kiosk** (boots straight into the interface, no login
needed for someone standing at the device), or as a **web application** reachable from any browser
on the same network (always requires a real login).

---

## 2. The Active Case

Before diving into any specific tool, it's worth understanding this one concept, since it touches
every tab.

Click **Case** in the top bar to create or select a case. Once one is active:

- Every acquisition, recovery, and mobile job auto-fills its Case Number, Examiner, and Destination
  folder from it.
- Reporting automatically loads that case's data — no manual file browsing.
- Each case gets its own real folder on disk, with one consolidated report file, rather than
  scattered per-job files.

**This is entirely optional.** Every tool works exactly the same with no case selected — you just
fill in Case Number/Examiner/Destination by hand each time instead.

A case created before this consolidated-file format existed (an older station, or one migrated from
an earlier version) can still be used normally; a **Migrate to Consolidated Format** button appears
next to it in the Case Manager if you want to bring it up to the current format. Migration is
non-destructive — the original files are kept, renamed with a backup suffix, never deleted.

---

## 3. Forensic Acquisition

The **Forensic Acquisition** tab is where you create a forensic image (a bit-for-bit copy) of a
drive.

### Selecting a source and checking its health

Pick the drive from the **Target Source Selection** dropdown. Once selected, a telemetry grid shows
its own self-reported health data (SMART) — model, serial, capacity, temperature, reallocated
sectors, pending sectors, power-on hours. Worth a glance before committing to a multi-hour
acquisition of a drive that's already showing signs of failing.

### Write-blocking

Every USB storage device is forced read-only at the hardware level the instant it's connected — this
happens automatically, station-wide, before you even open this tab. The badge shown here always
reflects the state for whichever drive is currently selected. Leave it on for anything you're
imaging *from*. You'd only ever turn it off for a **destination** drive you're deliberately writing
an image *to* — that toggle lives in Settings > Drive Management, not here, specifically so it's
never one accidental click away.

### Choosing a format

| Format | When to use it |
|---|---|
| **dc3dd** (default) | A safe default for most cases. Hashes as it copies. |
| **dcfldd** | An alternative engine with a similar feature set — pick it if your workflow specifically expects dcfldd's output style. |
| **Plain dd** | No built-in hashing (compute one separately if needed), but supports genuine direct-I/O reads that bypass the OS cache. |
| **E01 (ewfacquire)** | Produces an EnCase-compatible `.E01` image, with optional compression and splitting into segments. Pick this if your later analysis tooling expects E01. |
| **AFF** | A less common format today, supported via a hash-then-convert pipeline if your workflow needs it. |
| **ddrescue (Recovery)** | For a drive that's damaged, clicking, or not detected reliably — see [File Recovery](#6-file-recovery) below for the full workflow. |

Hover the Format dropdown at any time for a live one-line explanation of whichever option is
selected.

### Recording case details

Fill in Case Number, Evidence ID, and Examiner (auto-filled if a case is active) and a Destination
folder for the output. Choose which hash algorithm(s) to compute — MD5, SHA-1, SHA-256, or more than
one.

### Encrypted source drives (BitLocker, LUKS, and VeraCrypt)

If the drive you're about to image is BitLocker-encrypted (Windows), LUKS-encrypted (Linux), or a
VeraCrypt volume, you can unlock it first so the acquisition captures the **decrypted** contents
rather than an unreadable, encrypted blob. All three types share one **Encrypted Volume** panel:

1. Expand **Encrypted Volume** and pick the type (BitLocker / LUKS / VeraCrypt) from the dropdown —
   the credential field's label changes to match (Recovery Key, Passphrase, or Password).
2. For BitLocker or LUKS, optionally click **Detect** for a best-effort check of whether the
   selected device/partition actually looks encrypted with that scheme. VeraCrypt volumes have no
   fixed signature by design (that's the point — a real container is meant to look like random
   noise), so Detect always reports that it can't tell either way for VeraCrypt; a failed **Unlock**
   attempt tells you the real answer instead.
3. Enter the recovery key/passphrase/password and click **Unlock**.
4. Once unlocked, start the acquisition normally — the decrypted volume is now available as the
   source. The same field also records the value directly in the case report as documentation for
   whoever needs to decrypt the image again later (this is stored as plain text in the report by
   design — encrypting it with a station-local key would make it useless the moment the report
   leaves the station), independent of whether you actually check "Also unlock this volume now."
5. Click **Lock** when you're done, or it locks automatically once the acquisition finishes.

Two things worth knowing: `ddrescue` doesn't support an unlocked/decrypted source (it needs direct,
low-level access to a real block device for its bad-sector recovery strategy — decrypt the raw
partition first with a different tool if you need `ddrescue`-level recovery on an encrypted drive).
And you'll need the actual recovery key, passphrase, or password already — this doesn't attempt to
bypass or crack encryption in any way.

### Previewing a drive before acquiring it

The **Preview This Drive (Read-Only)...** button lets you browse a drive's actual file structure —
using the same tools you'd use to browse an already-acquired image — *before* committing to a full
acquisition. Useful for a quick sanity check ("is this actually the drive I think it is? does it
have a readable filesystem at all?") without the time cost of a full image. A clearly-marked warning
banner distinguishes this from real acquired evidence at all times. Click **Exit Image** when
you're done — this also releases the temporary access this feature needed.

### Logical / Custom-Content Acquisition

Sometimes you don't need (or want) a full physical image — just specific folders, packaged with
hash verification. The second card on this tab, **Logical Acquisition (Selected Folders)**, handles
that:

1. Click **Add Folder...** and browse to a folder to include. Repeat for as many folders as needed.
2. Choose which hash algorithm(s) to compute, and optionally check **Also create a .zip archive**
   for a single portable file alongside the folder structure.
3. Fill in case metadata and a destination, then start.

The result is a real folder (preserving each source folder's own structure) plus a manifest listing
every file's hash — a genuine, verifiable evidence container, without a full-disk image.

### Reading progress and results

Status, a live progress bar, transfer speed, a throughput chart, and a scrolling console are all
shown once a job starts. When it finishes, the status reads **Completed Successfully** with the
computed hash(es) shown. If a case is active, this job's full telemetry and hashes are already
recorded there — check the **Jobs** tab in Reporting.

Check **Automatically run Auto Analyze when this finishes** before starting to chain a successful
acquisition straight into [Auto Analyze](#running-a-curated-tool-set-automatically-auto-analyze)
against the image it just produced — one confirmed choice up front instead of a second manual step
once the job completes. Not available for `ddrescue` or AFF, which run their own separate workflows.

---

## 4. Live Collection USB

Everything else in this app captures a *dead* drive — this is for a *live, running* machine you
need volatile information from without powering it off. It's the one place in this app that
deliberately writes to a USB drive it doesn't treat as evidence, so it's built with an unusually
strong safeguard, and it lives in its own tab (not under Forensic Acquisition) since it's a
genuinely different, two-session workflow: build the drive here, walk it to a separate machine,
bring it back — possibly days later — to import.

**Build Live Collection USB:**

1. Insert a blank (or reusable) USB drive — anything already on it will be **erased**.
2. Select it from the drive dropdown. Its model, serial number, and size appear so you can confirm
   it's the right one.
3. Type `WIPE /dev/sdX` (with the real device path shown) into the confirmation box — the Build
   button stays disabled until this matches exactly. This is deliberately more friction than any
   other action in this app.
4. Click **Erase & Build Live Collection USB**. The drive is wiped, formatted (exFAT, for reliable
   read/write across Windows, macOS, and Linux), and loaded with a real open-source collector (UAC)
   for Linux/macOS/BSD targets and a small, fully readable PowerShell script for Windows targets —
   both run directly from the drive with nothing to install. If the station had internet access at
   install time, memory-acquisition tools (AVML for Linux, WinPmem for Windows) are bundled onto the
   drive too, ready to use; if not, the drive still works fully for everything except memory capture.

Take the finished drive to the machine you need to examine, plug it in, and follow the README on
the drive (open a terminal and run `./run_collector.sh` on Linux/macOS, or double-click
`launch_collector.cmd` on Windows). Everything collected is written back onto the same drive.
Nothing here ever touches a network.

**Memory (RAM) capture, if you want it.** Early in the collection run, if the target is running as
root/Administrator, the memory-acquisition tools were bundled onto the drive, and there's enough
free space on the drive for the RAM to fit (checked automatically, with a small safety margin), the
script asks whether to capture a full memory image before continuing — defaulting to **No** if you
just press Enter. Say yes and it captures the entire contents of RAM to the drive (Linux via AVML,
in LiME format; Windows via WinPmem, as a plain raw image) before moving on to everything else,
since RAM is the single most volatile thing being collected. The result — `memory.lime` or
`memory.raw` — lands right alongside every other collected file and gets pulled in like everything
else on import, ready to open with [Memory forensics](#memory-forensics) once it's in the case.
Declining (or if the checks above rule it out) skips straight to the rest of the collection with no
prompt held up.

**What actually gets collected.** On Linux/macOS/BSD, UAC's `ir_triage` profile captures a real
live-response snapshot: running processes (with hashes and open files/sockets), live network
connections, mounted storage, package lists, shell/SSH history, and a live-filesystem timeline, plus
clipboard contents captured separately right after UAC finishes. On Windows, the bundled PowerShell
script gathers running processes with command lines (each executable's own SHA-256 hash computed
too, matching UAC's own process-hashing on the Unix side), TCP/UDP connections with their owning
process, logged-on sessions, ARP and DNS caches, services, scheduled tasks, startup/autorun entries,
installed hotfixes, mapped network drives, and clipboard contents (driver enumeration is attempted
too, and honestly logged as skipped if the script wasn't run elevated). This is the entire point of
the feature: every one of those is volatile state that's **gone the instant the machine is powered
off** — imaging the same machine's disk five minutes later cannot recover any of it.

**Import Collection Results:** plug the drive back into the station (it's read-only again by
default — no separate unlock needed for this half), select it, and click **Scan for Collection
Results**. Check off whichever result run(s) you want, fill in an Evidence ID, and click **Import
Selected Results** — every file is copied into the active case, individually hashed with a
manifest, and recorded as a real case-report event. In File Explorer, the imported folder groups
alongside this app's other generated-analysis-output folders rather than sitting unclassified among
real evidence, and every file in it can be browsed, previewed, hashed, tagged, or scanned like any
other. On top of that, the Windows-side results (processes, network connections, logged-on users,
services, scheduled tasks, autoruns, mapped drives, clipboard) are automatically parsed into File
Explorer's searchable **Parsed Artifacts** category and Reporting's Evidence Timeline — no separate
action needed — and every process executable's hash is checked against every configured [Hash Set,
URL List, and YARA rule](#hash-sets-url-lists-and-yara-rules) automatically, with any match recorded
as its own flagged artifact. A `SUMMARY.txt` (and machine-readable `summary.json`) is generated
alongside the raw files and manifest, giving you counts (processes, connections, services, hash-set
matches, and whether a memory image was captured) at a glance without opening anything else. The
Unix/UAC side's own individual output files aren't yet parsed into structured records the same way
— that's a larger, still-planned piece of work — but every file it produced is fully browsable, and
its captured clipboard text is parsed the same way the Windows side's is.

---

## 5. Mobile Forensics

The **Mobile Forensics** tab acquires data from a connected iPhone or Android device over USB. It
does **not** bypass a lockscreen or USB-debugging authorization — the device must already be
unlocked and (for Android) have USB debugging approved by whoever's holding it.

1. Choose **iOS** or **Android** from the mode selector.
2. Connect the device via USB.
   - **iPhone/iPad:** tap "Trust This Computer?" on the device's own screen when it appears. If the
     device doesn't show that prompt at all, select it in the dropdown (it still shows up, just
     marked **NOT TRUSTED**) and click the **Pair Device** button that appears next to the warning —
     this sends the pairing request that makes the prompt actually appear on the device, then tap
     Trust and click Refresh.
   - **Android:** approve the USB-debugging authorization prompt on the device's own screen.
3. Select the device from the dropdown. Real device detail appears automatically — for iOS: model,
   OS/build version, storage capacity, activation state, serial number, IMEI, WiFi/Bluetooth MAC
   addresses; for Android: model, manufacturer, connection state, OS version, API level, build ID,
   serial number.
4. **iOS** offers a plain backup or an **encrypted backup** (check the box, set a password) — an
   encrypted backup captures additional data (like the Keychain, which holds saved passwords/tokens)
   that a plain backup can't. **Android** offers three modes: **Pull Accessible Storage** (the most
   reliable for most cases), a full **Backup**, or a **Bugreport** (a diagnostic dump, useful for
   system-level detail).
5. Fill in case metadata and a destination, then click **Start**.

Once finished, an acquired backup is a normal folder/file you can browse in File Explorer like any
other evidence — including running an MVT spyware scan against it (see [File
Explorer](#7-file-explorer) below).

### iOS crash reports and SIM/UICC cards

Two more capabilities live in this tab, alongside the main acquisition flow above:

- **Pull Crash Reports** (iOS mode) — once a connected, trusted iPhone/iPad is selected, this button
  appears next to its device details. It copies the device's own crash-report logs (decoded into
  readable `.crash` files) without removing the originals from the device — a quick, non-destructive
  supplementary pull, separate from a full backup.
- **SIM/UICC Card** — a third mode in the device selector. Click **Detect Readers** to list any
  connected PC/SC-compatible card readers, select one, insert a card, and click **Read Card**. The
  result (ICCID, ATR, and any application IDs the card exposes) is shown raw and saved as a `.log`
  file in the case folder. This needs a real PC/SC card reader physically connected to the station —
  the underlying reader service and its access permissions are configured automatically during
  install, nothing extra to set up.

---

## 6. File Recovery

The **File Recovery** tab holds every deleted-file-recovery and damaged-drive tool behind one shared
control panel — pick a tool from the selector on the left, everything below adjusts to match it.

| Tool | What it's for |
|---|---|
| **PhotoRec** | Recovers files by matching known file *signatures* in the raw data, regardless of what the filesystem says — works even on damaged, reformatted, or unrecognized filesystems. Recovered files lose their original names and folder structure (PhotoRec has no way to know them, since it isn't reading filesystem metadata at all). |
| **extundelete** | Recovers deleted files specifically from ext2/3/4 (Linux) filesystems by reading the filesystem's own journal — unlike a signature-based carver, it *can* restore original filenames and folder paths. |
| **foremost / scalpel** | Alternative signature-based carvers to PhotoRec — narrower file-type support, but sometimes faster or more precise for specific formats. `scalpel` ships with a curated signature list (JPEG/PNG/GIF/PDF/ZIP by default). |
| **TestDisk Partition Analysis** | A read-only listing of every partition TestDisk can identify on a device or image. Deliberately read-only — this station never exposes TestDisk's separate write-capable repair mode. |
| **Quick Triage Scan** | Scans a device or image for emails, URLs, IP addresses, card-like numbers, and phone numbers, using this app's own built-in pattern matcher — no external tool needed. Supports your own custom keyword/regex lists too (defined in Settings > Case & Reporting). |
| **ddrescue Mapfile Inspector** | Not a recovery tool itself — reads a `ddrescue` mapfile (produced by the ddrescue *format*, on the Acquisition tab) and shows a clean summary: how much was rescued, how much wasn't attempted, how many bad sectors were found. |

### Recovering data from a damaged or failing drive

This is the one workflow that spans two tabs:

1. On **Forensic Acquisition**, select the drive and change **Format** to **ddrescue (Recovery)**.
2. Start with strategy **1. Fast Copy** — it copies everything readable quickly, without stressing a
   drive that's already struggling.
3. Once it finishes, come here to **File Recovery** and use the **Mapfile Inspector** to check the
   results — rescued/unattempted/bad-sector counts, as clean labeled numbers, not a raw log dump.
4. If bad sectors remain, go back and try strategy **2 (Edge Trimming)**, then **3 (Intensive
   Scraping)** if still needed — each is more thorough but harder on an already-failing drive, so go
   in order rather than jumping straight to the most aggressive pass.
5. Once you have a usable image, any of the recovery tools above (PhotoRec, extundelete, etc.) can
   recover files from it even if parts are still damaged or corrupted.

### Recovering deleted files with original names intact

If you specifically need recovered files to keep their real filenames and folder locations (not
PhotoRec's generic `f0001234.jpg`-style output), go to **File Explorer** instead and use
**filesystem-aware deleted file recovery** — see [File Explorer](#7-file-explorer) below. It reads
the filesystem's own directory structure directly, so a recovered file comes back as itself, at its
real path — a real advantage over signature-based carving, though its success rate genuinely depends
on the filesystem type (NTFS and FAT recover well; ext-family filesystems recover poorly, since the
Linux kernel typically clears a deleted file's data-block pointers on deletion).

---

## 7. File Explorer

**File Explorer** is where you browse evidence, look inside acquired images, and run analysis tools
against individual files or whole images. It's a two-column layout: a folder tree on the left, and a
Listing table + Details pane (Preview / Hex / Metadata) on the right.

### Browsing real files and acquired images together

The folder tree shows your case folder's real contents, with acquired disk images (`.dd`/`.E01`/etc.)
shown among them — click a disk image's own expand arrow to browse **inside its filesystem**
directly, no separate mount step, right there in the same tree. This works because the app reads
the filesystem structure in-process (via an embedded Sleuth Kit engine), including directory
listings with real timestamps, recursive search, and deleted-but-still-listed entries.

Selecting any file shows it in the **Details** pane on the right, with up to four views to switch
between:

- **Preview** — renders the file directly when possible (images, PDFs, HTML rendered safely in a
  sandbox, KML files shown as an actual interactive map, JSON results from certain scans shown as a
  formatted table).
- **Hex** — a raw byte-level view.
- **Metadata** — filesystem details (size, timestamps, permissions) plus, for files ExifTool
  understands, embedded metadata like camera info or GPS coordinates.
- **Database** — appears only for `.db`/`.sqlite`/`.sqlite3` files: browse the file's own tables and
  rows directly, read-only, no separate SQLite tool needed. Works on this station's own per-case
  index, a parsed browser-history database, or any other SQLite file you come across in evidence.

### Right-click actions

Right-click (or press-and-hold on a touchscreen) any file or folder for a context menu. The menu is
context-aware — only actions that could actually apply to the selected file, folder, or image are
shown, and a whole section (Whole-Image Analysis, Artifact Parsers, Mobile & Memory) disappears
entirely if none of its tools apply to the current selection, so a plain document's menu stays short.
A single-file analysis tool (Binwalk, ClamAV, Strings, OCR, Hash Sets, YARA, Fuzzy Hash, SQLite
Dissect, APK/IPA/Bugreport analysis, LNK parsing) that has already been run against the exact selected file
shows a small green checkmark — hover it for the prior result and when it ran. The very
first item, **Auto Analyze...**, is described in its own section below — everything under it is
grouped into collapsible sections so the menu stays manageable:

**Image & Case**
- **Browse as Image (Sleuth Kit)** — same as clicking the tree's expand arrow.
- **Unlock Encrypted Volume & Browse...** — for an already-acquired image of a BitLocker-, LUKS-, or
  VeraCrypt-encrypted drive: pick the type, enter the recovery key/passphrase/password (and, for a
  multi-partition image, the byte offset of the encrypted partition), and browse the decrypted
  contents directly.
- **Verify Image Hash** — recompute a file's hash and compare it against an expected value.
- **Convert Image Format...** — convert an acquired image between raw (`.dd`) and E01, with the
  result's hash independently verified against the source (not just trusted from the tool's own
  self-report).
- **Attach to Case** — adds the file as a case exhibit, shown in Reporting's Files & Artifacts tab.
- **Tag...** — apply Bookmark, Follow Up, Notable Item, or a custom tag (with an optional comment) to
  a file — see [Tagging and File Views](#tagging-and-file-views) below.
- **Recover Deleted Files...** — jumps to File Recovery with this image pre-filled as the source.

**Whole-Image Analysis** (runs a tool across an entire acquired image as a background job)
- **Search Inside Image** / **Generate Timeline** — recursive filename search, or a full MACB
  (Modified/Accessed/Changed/Born) timeline of every file in the image.
- **Extract Geolocation (Whole Image)** — scans every photo in the image for GPS EXIF data and
  builds a KML file you can view as a map (see below).
- **Hash Manifest (Whole Image)** — computes a hash for every real file in the image at once, as a
  single manifest.
- **Triage Scan (Whole Image)** — the same pattern matching as Quick Triage Scan, but filesystem-aware
  (results are tied to real file paths, not raw byte offsets) and run as a background job so it can
  handle a much larger scan.
- **Parse Browser Artifacts / Registry Hives / Event Logs / Prefetch Files / Recycle Bin / Linux
  Artifacts / Mobile Chat-App Artifacts (Whole Image)**, and **Find Crypto Wallet Files (Whole
  Image)** — the whole-image versions of the artifact parsers described in [Artifact
  parsing](#artifact-parsing) below, so you don't need to extract anything first.
- **Recover Deleted (Filesystem-Aware)** — recovers every deleted file the filesystem still has a
  record of, under its real original name and folder path.

**Analyze** (runs against one selected file or folder)
- **Binwalk** — looks for other files or filesystems embedded inside a binary (useful for firmware
  images).
- **ClamAV** — scans against known malware signatures.
- **Extract Strings** — pulls readable text out of a binary file.
- **Quick Triage Scan** — the fast, single-file version of the pattern scanner above.
- **Extract Text (OCR)** — reads readable text out of a screenshot, scanned document, or photograph
  (English only in this version) — text no other tool here can see, since it exists only as rendered
  pixels, not raw file bytes.
- **Generate Video Contact Sheet** — builds a single image showing a 4x3 grid of evenly-spaced frames
  from a video, so you can see what's in it without opening a media player.
- **hashdeep** — generates a hash for every file in a folder at once.
- **Check Against Hash Sets** — hashes the file and checks it against your saved known-good/
  known-bad hash sets — see [Hash Sets, URL Lists, and YARA
  rules](#hash-sets-url-lists-and-yara-rules) below.
- **Scan with YARA Rules** — same section.
- **Extract Geolocation (KML)** — same as the whole-image version, scoped to one real folder.

**Artifact Parsers** (each one recursively finds and parses its artifact type anywhere under the
selected folder — see [Artifact parsing](#artifact-parsing) below for what each recovers)
- **Parse Browser Artifacts (Chrome/Firefox)**, **Parse Registry Hives**, **Parse Event Logs**,
  **Parse Prefetch Files**, **Parse Recycle Bin**, **Parse Linux Artifacts**, **Find Crypto Wallet
  Files**, **Parse Mobile Chat/App Artifacts**, **Parse LNK Shortcut** (this last one parses a
  single selected `.lnk` file directly, rather than scanning a folder).

**Mobile & Memory**
- **MVT Scan (iOS Backup)** / **MVT Scan (Android Backup)** — checks an already-acquired mobile
  backup for spyware/compromise indicators (see [MVT](#mvt-spywarecompromise-scanning) below).
- **Memory Forensics...** — see [Memory forensics](#memory-forensics) below.

**File Operations**
- **Copy to...** / **Delete**

A virtual entry inside an image you're currently browsing gets a shorter menu (Extract, Extract &
Attach to Case, Tag, Binwalk, Extract Strings, Check Against Hash Sets, Scan with YARA Rules, and
Parse LNK Shortcut when the entry is a `.lnk` file) — most other actions need a real path on disk,
which a still-in-image entry doesn't have until it's extracted.

### Running a curated tool set automatically (Auto Analyze)

**Auto Analyze...**, at the very top of the right-click menu, detects what kind of evidence you've
selected — a Windows disk image, a Linux disk image, a memory image, or a mobile backup — and runs a
sensible, curated default set of the tools above against it in one background job, instead of
running each one by hand:

| Detected profile | Runs by default | Available as an extra |
|---|---|---|
| Windows disk image | Hash Manifest, Registry (incl. Amcache), Event Logs, Prefetch, Recycle Bin, Browser Artifacts | Recover Deleted (Filesystem-Aware) |
| Linux disk image | Hash Manifest, Linux Artifacts | Recover Deleted (Filesystem-Aware) |
| Memory image | A curated subset of Volatility 3/`mquire` plugins (info, process list, network connections, and more) | The remaining plugins |
| Mobile backup (iOS/Android) | Hands off to the matching MVT scan, pre-selected | — |

The detected profile is always shown for confirmation (or correction) before anything runs — nothing
starts on a guess. Triage Scan and geolocation extraction are deliberately **not** part of the
default set (they're slower and not always relevant); reach them individually from Whole-Image
Analysis if you want them. A memory or mobile profile can't be interrupted mid-scan the same way a
disk-image scan can — Stop takes effect at the next natural break, not instantly, since the
underlying tool doesn't support cancelling a single already-running scan/plugin.

The Guided Workflow checklist (Help & Reference) links straight into Auto Analyze for the case's own
evidence once step 3 is reached, and Acquisition's own "Automatically run Auto Analyze when this
finishes" checkbox can chain a successful acquisition directly into it.

### Artifact parsing

Beyond browser history, this station recovers several other well-known artifact types directly from
a real folder or from inside an unmounted image — no extraction step required either way:

**Windows**

- **Registry hives** (`NTUSER.DAT`/`SYSTEM`/`SOFTWARE`/`AMCACHE.HVE`/`USRCLASS.DAT`) — one action
  covers all of: recently opened documents, typed Explorer/Internet Explorer paths, Run-dialog
  history, USB device connection history, the installed-programs list, Amcache's own per-executable
  application inventory, ShellBags (proves a folder was browsed via Explorer — including removable/
  network/since-deleted folders that leave no other trace), Shimcache/AppCompatCache (program-
  execution evidence; Windows 10/11 binary format only), UserAssist (proves a program was actually
  *launched* via the GUI shell, with a run count and how long it stayed in focus — distinct from
  Prefetch/Amcache, neither of which distinguishes a GUI launch from a command-line one), BAM/DAM
  (a last-activity timestamp per executable — presence is strong evidence, but absence proves
  nothing, since some launch modes never populate it), RDP connection history (which remote hosts
  this user connected to via Remote Desktop, with the last-used username), Office recent files/
  folders per application (Word/Excel/PowerPoint/Access/Publisher), and Explorer search-box history
  (fully populated on Windows 7 through pre-23H2 Windows 11, but Microsoft stopped writing it
  entirely starting Windows 11 23H2 — an empty result there is expected, not a parsing failure).
- **`$MFT`** — every file record's own creation/modified/access/change timestamps from both
  `$STANDARD_INFORMATION` and `$FILE_NAME` attributes, with records flagged as suspected timestomping
  when those two disagree in a way consistent with backdating (a well-known DFIR heuristic — flagged,
  never asserted as certain).
- **`$UsnJrnl` change journal** — a chronological log of every file create/rename/delete/write on
  the volume, including files created and deleted entirely between two `$MFT` snapshots, which leave
  no trace anywhere else on the volume.
- **Event Logs** (`.evtx`) — a curated set of security-relevant event types: successful and
  failed logons, process creation, account creation, service installation, and audit-log-cleared (a
  classic anti-forensic indicator).
- **Prefetch** (`.pf`) — which executables ran, how many times, and when.
- **Jump Lists** (`.automaticDestinations-ms`/`.customDestinations-ms`) — recently/frequently
  accessed files per application, with pin status and last-access time where available.
- **Recycle Bin** (`$I*` metadata files) — a deleted file's original name, path, size, and
  deletion time.
- **LNK shortcuts** (`.lnk`) — target path, arguments, working directory, icon location, and the
  shortcut's own embedded timestamps. Parsed one file at a time, not scanned across a folder.
- **Thumbcache** (`thumbcache_*.db`) — extracts every embedded thumbnail as a real, viewable image
  file. These can persist after the original photo or document has been deleted; the per-entry
  identifier is usually a one-way hash, not the original filename, shown as such when a real
  filename genuinely can't be recovered.
- **Sticky Notes** (`plum.sqlite`) — the actual text of every note, including deleted ones (Sticky
  Notes uses a soft-delete tombstone, not real removal). Correctly recovers recent notes/edits that
  only exist in an unsaved database sidecar file, not yet folded into the main database.
- **Windows Notification database** (`wpndatabase.db`) — everything sent to the Action Center: which
  app, when, and often the actual text of the notification.
- **Windows Timeline / Activity History** (`ActivitiesCache.db`) — which apps were used, which
  documents were opened, and which websites were visited, each with a timestamp. A Windows 11 image
  made after Microsoft's January 2024 update will show much less activity history than a Windows 10
  image — that's a real change in what Windows itself records, not a parsing gap.
- **SRUM** (`SRUDB.dat`) — one of the single highest-value modern Windows artifacts: per-application
  network data usage and execution/timeline history, tracked over a rolling window, even for
  applications that have since been uninstalled.
- **PowerShell console history** (`ConsoleHost_history.txt` and similar) — every command typed at a
  PowerShell prompt, with multi-line pasted commands correctly reassembled into one entry. This file
  never records a timestamp at all — a real limitation of the format itself, not something missing
  from this feature.
- **Windows Firewall connection log** (`pfirewall.log`) — every logged allowed/blocked connection,
  when an administrator has turned that logging on. It's off by default, so this file is commonly
  not present at all — that's expected, not a problem.
- **Windows Search Index** (`Windows.edb`, Vista through 10) — every file the operating system has
  indexed, with its resolved path, name, size, author, and a preview of the actual text content
  Windows itself extracted from inside it. Windows 11 moved this to a different (SQLite-based) format,
  not yet covered.
- **Legacy Internet Explorer 10/11 and pre-Chromium Edge history/cookies**
  (`WebCacheV01.dat`/`WebCacheV24.dat`) — a fourth browser family alongside the Chrome/Firefox/Safari
  support described above. Modern Chromium-based Edge is already covered by the Chrome-family parser
  instead.
- **BITS job queue** (`qmgr.db`, Windows 10+) — BITS is a legitimate background-download service that
  is also a well-known technique attackers use for stealthy downloads. Recovers each job's name, the
  exact command it ran when the job finished, and who owns it. Doesn't recover individual downloaded-
  file details (source URL, destination path) in this version — a deliberate scope decision rather
  than a guessed, possibly-wrong result.
- **RDP Bitmap Cache** (`Cache0001.bin`/`bcache22.bmc`) — evidence that a Remote Desktop client
  session took place on this machine. This version reports per-tile metadata (a real deduplication
  key, tile dimensions) but doesn't reconstruct the actual on-screen images.

**Linux**

- **Shell history** (`.bash_history`/`.zsh_history`/`.python_history`) — a per-command timestamp is
  captured automatically whenever the shell was configured to record one (bash's `HISTTIMEFORMAT`
  marker convention, or zsh's `EXTENDED_HISTORY` format, including its own multi-line continuation
  scheme) — a genuinely untimestamped file (the common case for either shell, and macOS's own real
  default) still parses correctly, just without a timestamp.
- **`/etc/passwd`**, **cron jobs**, and **`auth.log`**/`secure` authentication events (SSH
  login/logout, `sudo` usage).
- An experimental, opt-in-only `wtmp`/`utmp` login-history parser is also available (offered
  specifically through the Auto Analyze picker for a Linux image, not the default set) — login-record
  binary layout genuinely varies by system, so it includes a built-in sanity check that refuses to
  produce results rather than guess wrong against an unfamiliar layout.

**macOS**

- **LaunchAgents/LaunchDaemons** (`~/Library/LaunchAgents`, `/Library/LaunchAgents`,
  `/Library/LaunchDaemons`, `/System/Library/LaunchDaemons`) — one of the most common real
  techniques Mac malware uses to survive a reboot. Works fully against an already-extracted evidence
  folder (for example, a direct file copy from a connected Mac) regardless of the disk-image
  question below. **A real, disclosed limitation**: this station cannot currently browse *inside* a
  modern Mac's own disk image at all — virtually every Mac sold since 2017-2018 uses a filesystem
  format (APFS) this station's underlying image-browsing library doesn't yet support. The whole-image
  version of this tool still works against an older, pre-APFS Mac's disk image.

**Cross-platform / mobile**

- **Cryptocurrency wallet files** — detects common wallet filenames (Bitcoin Core's `wallet.dat`,
  geth/Ethereum keystore files, Electrum wallets, and others). Detection only — wallet file formats
  are typically encrypted or binary, so this doesn't attempt to open or decrypt them.
- **Email files** (`.eml`/`.mbox`/`.pst`/`.ost`) — subject, sender/recipients, date, a body preview,
  and attachment count per message. Standalone `.msg` files aren't covered yet.
- **Mobile chat/app data** — SMS/iMessage, Contacts, and Call History parsed directly out of an
  already-captured, unencrypted iOS backup (an encrypted backup is detected and reported as such,
  never silently skipped), or out of an Android device's own on-device SMS/contacts/call-log
  databases when a rooted `Physical` acquisition's raw image is right-clicked.
- **Browser artifacts** (Chrome/Chromium, Firefox, and Safari) — see the paragraph below.

Right-click a folder (or a whole acquired image) and choose the matching **Parse...** action, or use
**Auto Analyze** to run the relevant ones for that evidence type automatically. Results show up in
File Views' analysis-index categories and in Reporting's Files & Artifacts tab, all with readable
labels — not raw internal keys.

### Fuzzy hashing and Volume Shadow Copies

**Fuzzy hashing (TLSH)**, reached via right-click → **Compute Fuzzy Hash (TLSH)**, closes a real gap
in exact hash-set matching: a single byte changed in a known-bad file (a recompiled malware variant,
a lightly-edited document) is invisible to MD5/SHA1/SHA256, but similar/near-duplicate to a fuzzy
hash. Compute a file's digest, then compare it against another pasted-in hash for a similarity
distance — the lower the distance, the more similar the two files.

**Volume Shadow Copies (VSS)**, reached via the whole-image toolbar's **List Shadow Copies** button
while browsing an NTFS-formatted acquired image, enumerates any Windows shadow-copy snapshots present
inside that volume. Each one can be materialized as its own separate, fully browsable image file — an
examiner can then inspect a volume's past point-in-time state with every existing File Explorer tool
(search, timeline, hash manifest, artifact parsers, and more) that already works on an ordinary
acquired image, since a materialized shadow copy is just an ordinary raw image once copied out.

### ALEAPP/iLEAPP: a much deeper mobile artifact pass

The built-in mobile chat/app parser above is deliberately small. For a comprehensive pass over an
already-acquired Android `adb pull` extraction or iOS `idevicebackup2` backup, right-click the
extraction folder and choose **Parse with ALEAPP/iLEAPP...** — this runs the same open-source,
community-maintained parsers (ALEAPP for Android, iLEAPP for iOS) many examiners already use outside
this app, covering hundreds of app-specific artifacts: WhatsApp, Signal, Telegram, Chrome, WiFi
connection history, app usage, and far more than the app's own hand-curated parser attempts.

Pick the parser matching the extraction's platform, then click Start Scan. This runs as a background
job (watch the progress bar below the File Explorer toolbar) — a real multi-GB extraction can take
many minutes to run the parser's full artifact catalog, and it can be interrupted with Stop like any
other background job. The result is a real, self-contained HTML report plus TSV data files, written
to a new folder next to the extraction (never inside it — see the note below) and automatically
findable in File Explorer once the scan completes.

Each tool runs in its own separate, isolated Python environment on the station, invisibly — ALEAPP
and iLEAPP have a genuine, incompatible dependency requirement between them, so this app never tries
to run them side by side in the same environment. Nothing about this needs any attention from you;
it's set up once, automatically, the first time the station is installed or updated.

Browser artifact parsing specifically extracts real history, bookmarks, downloads, and cookie
metadata from any Chrome/Chromium or Firefox browser profile found within a folder or image. Cookie
*values* from Chrome specifically can't be recovered — modern Chrome encrypts them with an OS-level
key not present in the evidence file alone; this is disclosed honestly rather than fabricated.
Firefox's cookie values, by contrast, are stored as plain text and *are* recoverable. Safari uses a
different format and isn't covered.

### Mobile-app-specific tools

Five more right-click File Explorer actions, each aimed at a specific mobile-app scenario:

- **Recover Deleted SQLite Records** (any `.db`/`.sqlite`/`.sqlite3` file) — uses SQLite Dissect to
  recover rows still present in a database's own freeblocks, unallocated space, or a surviving WAL/
  rollback-journal sidecar file. Whether anything comes back depends heavily on how the file was
  closed: SQLite's own page management frequently compacts a deleted row's freed bytes away entirely
  the moment a database is cleanly closed, so a database acquired with its own `-wal` file still
  present alongside it (an app caught mid-transaction) is by far the most reliable case.
- **Analyze APK (androguard)** (`.apk` files) — package name, version, every requested Android
  permission, every declared activity/service/receiver/provider, the full signing-certificate chain
  (subject, issuer, serial number, SHA-256 fingerprint, validity window), and a raw scan of the file
  for embedded URLs. This is static analysis only — the app is never run or installed.
- **Analyze IPA** (`.ipa` files) — `Info.plist` metadata (bundle ID, display name, version/build,
  minimum iOS version, and every permission "usage description" string shown to the user), the
  embedded mobile provisioning profile (team name/ID, provisioned device list, entitlements, validity
  dates — no signature verification is attempted), and an optional Mach-O binary layer showing each
  architecture slice and its FairPlay encryption status. The Mach-O layer uses LIEF and degrades
  gracefully — an `.ipa` with no readable binary, or a station where that layer isn't available, still
  returns the full `Info.plist`/provisioning-profile result rather than failing outright.
- **Decrypt WhatsApp Backup** (`.crypt12`/`.crypt14`/`.crypt15` files) — decrypts a WhatsApp local
  backup against the device's own key file into a real, browsable SQLite database, openable directly
  through File Explorer's existing Database preview tab. The key file itself comes from Mobile
  Forensics: once a rooted Android device is selected, a **Pull WhatsApp Key File** button appears.
- **Deep-Parse Bugreport** (`.zip` files) — turns an already-captured `adb bugreport` archive (Mobile
  Forensics' own Bug Report acquisition mode) into structured, searchable sections instead of a raw
  unopened archive: the device header (build, kernel, uptime), mount points, the running process list,
  package install/delete history, loaded kernel modules, GPS coordinates, crash traces and tombstones,
  network socket/connection state, battery stats, and power events. Any `.zip` file can be selected
  here — a file that isn't actually a bug report is rejected with a clear message rather than
  producing garbage output.

Each of these writes its own result (a recovered-rows folder, a decrypted database, a JSON report)
through the same evidence-integrity guard as every other analysis action in this app — never into, or
next to, the exact file or folder being analyzed.

### Hash Sets, URL Lists, and YARA rules

Three station-wide reference lists, managed from Settings > Case & Reporting > Analysis & IOC Lists,
and checked on demand from File Explorer:

- **Hash Sets** — your own known-good/known-bad hash lists (one hash per line, all in the same
  algorithm), checked automatically during a Hash Manifest run or on demand via **Check Against Hash
  Sets** on a single file. An optional one-click **Import/Refresh MalwareBazaar Recent** pulls a
  current recent-malware hash feed from [abuse.ch](https://abuse.ch)'s MalwareBazaar (needs a free
  personal Auth-Key, entered once).
- **URL Lists** — known-bad URL lists, checked automatically against every URL a browser-artifact
  scan extracts (a match shows up as its own "Known-Bad URL Match" result). An optional one-click
  **Import/Refresh URLhaus Recent** pulls the current URLhaus recent-malicious-URLs feed — no
  account needed.
- **YARA Rulesets** — save your own YARA rules (validated at save time, so a syntax error is caught
  immediately rather than mid-scan) and run them against a single file via **Scan with YARA Rules**,
  on a real file or inside an acquired image.

### Generic SQLite viewer

Selecting any `.db`/`.sqlite`/`.sqlite3` file shows a **Database** tab in the Details pane — browse
its tables and rows directly, read-only, without needing a separate SQLite tool. Works the same way
whether the file is a real one on disk or sitting inside an unmounted acquired image.

### Tagging and File Views

Every file or folder can be tagged — right-click → **Tag...** — with a built-in tag (Bookmark,
Follow Up, Notable Item) or one you define yourself, plus an optional comment. This is meant to work
the way it does in professional forensic tools: mark something interesting the moment you find it,
without leaving what you're doing.

The folder tree's **File Views** section (a separate branch alongside your real folders) gives you a
whole-case view built automatically from what's been tagged and scanned: files grouped by type
(Images, Documents, Videos, etc.), everything tagged so far, every keyword/pattern hit recorded
across any Triage Scan you've run, and every parsed artifact (browser, Registry, Event Log,
Prefetch, Recycle Bin, LNK, Linux, mobile chat/app, and crypto-wallet-file results all land here,
each under its own readable category) — all with live counts, and all without re-scanning anything
each time you look. Manage your station's own custom tags from Settings > Case & Reporting > Manage
Tags.

### Memory forensics

If you have an already-captured memory image (a `.raw`/`.mem`/`.vmem`/`.dmp`/`.lime` file — captured
with a separate tool like WinPmem, LiME, or AVML, since this station only ever *analyzes* an
already-captured image, it never captures memory itself), right-click it and choose **Memory
Forensics...**. An engine selector picks which analysis backend runs:

- **Volatility 3**, for Windows memory images — process list, process tree, command lines, network
  connections, loaded DLLs, file scan, malware-indicator scanning, services, open handles, and more,
  from a curated set of plugins.
- **`mquire`**, for x86_64 Linux memory images — kernel/OS version, process list, network
  connections, loaded kernel modules, process memory mappings, kernel log (`dmesg`), and several
  opt-in extras (open file handles, process capabilities, `ftrace` hooks, and more), reading BTF and
  `kallsyms` symbol information the kernel itself embeds in the image — no separate symbol download
  needed. ARM Linux targets aren't supported yet (only x86_64).

Either way it runs as a background job, and results are saved as real files you can browse and
preview like any other evidence — this station's own tagging/File Views pick them up automatically.
macOS memory analysis isn't supported by either engine.

### MVT (spyware/compromise scanning)

Right-click an already-acquired mobile backup folder and choose the MVT scan for its platform. iOS
backups work cleanly, since they match this station's own backup format exactly. Android is
best-effort — MVT expects a decrypted `adb backup` folder, a different format than the Pull/Backup/
Bugreport modes this station's Mobile Forensics tab produces, so it may error against those rather
than silently finding nothing; still offered for the case where you have a compatible Android backup
from elsewhere.

---

## 8. Reporting

The **Reporting** tab is where a case's data lives once collected — and where you write it up. It
only shows content once a case is active (create or select one via the Case button, same as
everywhere else).

- **Overview** (the default view) — a dashboard for the case: evidence item count, tag counts
  (Notable items called out), analysis activity, case notes, case age, plus two case-wide actions:
  **Verify All Evidence** (re-hashes every completed acquisition's own output file and compares it
  against the hash recorded at acquisition time — the case-wide equivalent of File Explorer's
  single-file "Verify Image Hash," run as a background job) and **Export Case Bundle** (zips the
  entire case folder — everything it actually contains, not just the exported report — for archival
  or handoff to another examiner; optionally including the raw acquisition images, which can make it
  very large).
- **Report Narrative** — Case Status, any custom fields your station defines, and the polished
  write-up sections: Executive Summary, Objectives, Relevant Findings, Limitations & Statement of
  Uncertainty, Conclusion, Indicators of Compromise, Recommendations/Next Steps. This is the closing
  narrative you write once, generally near the end.
- **Case Notes** — a running, timestamped, **append-only** journal, genuinely distinct from Report
  Narrative above. Add a note as you work, not just at the end — each one gets an author and a local
  integrity hash automatically, and editing a note preserves the original text rather than
  overwriting it (an edit history, not a silent change). This becomes the report's "Forensic
  Analysis / Steps Taken" section.
- **Custody Log** — a dedicated, **append-only** record of *physical* evidence handoffs between
  people (from/to custodian, reason, method, notes) — genuinely distinct from both Case Notes above
  (your own investigative notes) and Audit Trail below (a log of actions taken in the software).
  There's no edit option by design; a correction is logged as a new entry.
- **Files & Artifacts** — every exhibit attached to the case (with thumbnails, tags, and
  analysis-tool history shown inline), plus other files discovered sitting in the case folder that
  haven't been explicitly attached yet, files this app generated itself (reports, hash manifests,
  KML exports — grouped separately from real evidence), every parsed artifact record, and a list of
  reference URLs.
- **Geolocation** — an inline map built from any KML files attached to or found in the case.
- **Jobs** — every acquisition, recovery, and mobile job run against this case, with full telemetry
  and hashes for each.
- **Evidence Timeline** — every acquired image's filesystem (MACB) timeline (plus real file
  timestamps from a mobile pull/backup or Logical Acquisition folder — anything with no walkable
  disk image still gets a timeline from its own copied files) merged with parsed artifact
  timestamps, shown as a stacked density chart by source (click a bar to filter the table
  below it) plus a filterable, exportable table, with **Year** and **Month** drop-downs to narrow
  a case spanning years down to one period. For an Android pull specifically, the timeline uses
  each file's genuine on-device modification time (captured from the phone directly via `adb
  shell` right after the pull, since `adb pull` itself does not carry original timestamps across
  the transfer) — a pull made before this shipped, or one where the device disconnected before
  that capture step ran, falls back to copy-time entries with a clear note explaining why.
  Anti-forensic indicators (like a cleared audit log)
  and deleted-file entries are flagged directly in the table.
- **Audit Trail** — the station-wide activity log, filtered to just this case number.
- **Search** — a live keyword search across the Report Narrative (including Case Details), Jobs,
  Case Notes, Files & Artifacts, and Audit Trail all at once.
- **Export** — produce the actual deliverable.

Checking a specific hash against **every other case** on the station, not just this one, is a
separate, station-wide tool — see [Cross-Case Search](#case-reporting) under Settings below.

### Exporting a report

Choose a **Format**: PDF, HTML, JSON (the raw case data), or CSV (an evidence-inventory spreadsheet).

Choose a **Report Template**:

- **Standard** — fully configurable; pick exactly which sections to include.
- **DFIR Report** — a fixed structure modeled on standard incident-response report conventions.
- **Police Report** — a fixed structure modeled on a law-enforcement forensic examination report,
  including a "Chain of Custody" section — disclosed honestly as this app's own Audit Trail (a log
  of actions taken in the software), not a literal record of physical evidence handoffs between
  people.
- **CASE/UCO Report** — aligned to the CASE/UCO digital-investigation ontology's structure.
- **A custom template** you've built yourself (Settings > Case & Reporting > Custom Report
  Templates) — pick which of this report's sections to include, in what order, and under what
  headings.

For PDF/HTML, a live preview renders right there before you commit to downloading. Every export of a
PDF or HTML report also gets a SHA-256 integrity hash — shown after export, and saved alongside the
file — so you can prove later that the report itself hasn't been altered since it left this station.

---

## 9. Settings

**Settings** is split into five categories.

### Security

- **User Accounts** — create real, individually-logged-in accounts for each examiner, each assigned
  to a group.
- **User Groups** — Admin (built-in, always full access, can't be weakened) and Analyst (built-in,
  full day-to-day operational access, no station configuration or user management) are always
  available; you can also create your own custom groups with a checkbox for exactly which
  capabilities they should have (Acquisition, Mobile, Recovery, File Explorer, Reporting, Settings,
  and User & Group Management, each independently toggleable).
- **Configuration Backup & Restore** — an encrypted file capturing this station's accounts, groups,
  saved network credentials, and custom settings, so it can be recovered after a reinstall.
- **HTTPS Certificate** — view the currently-installed certificate, generate a fresh self-signed one
  (correctly including this station's actual IP addresses, so a browser doesn't *also* flag a
  hostname mismatch on top of the expected self-signed warning), download it, or install your own
  (e.g. one signed by a real certificate authority). Step-by-step trust instructions are included for
  Windows, macOS, Linux, iOS/iPadOS, Android, and Firefox specifically (Firefox keeps its own
  certificate store, separate from the operating system's).
- **Audit Log** — the full station-wide chain-of-custody log: every significant action, who did it,
  and when, searchable, with CSV export.

### Drive Management

Check or manually toggle the software write-blocker for a specific drive, and safely detach a drive
before physically disconnecting it.

### Service Controls & Diagnostics

Restart the web service or reload the touchscreen kiosk display; update the app itself (`git pull`)
or the underlying OS packages; check installed tool versions with one-click install for anything
missing; run a fixed set of read-only diagnostic commands; reboot or power off the station.

### Case & Reporting

Set a station-wide default report template and export settings; build custom report templates;
configure report branding (a header/logo shown on every export); define custom case fields your
station wants to track; manage the tags available for tagging evidence; and, under **Analysis &
IOC Lists**, define custom keyword/regex lists that Triage Scan can use in addition to its five
built-in categories, plus the **Hash Sets**, **URL Lists**, and **YARA Rulesets** described in
[Hash Sets, URL Lists, and YARA rules](#hash-sets-url-lists-and-yara-rules) above.

**Cross-Case Search**, its own section here rather than inside any one case's Reporting tab (since
it deliberately isn't scoped to one), checks whether a specific hash has shown up in *any* case on
this station — useful for spotting the same file reappearing across unrelated cases. Scoped to exact
hash matches for now, not free-text/keyword search across cases.

### Network

Mount a network share (NFS, SMB, or SFTP) as an evidence source, with optional encrypted,
auto-reconnecting saved credentials. Configure the station's own network settings — static IP or
DHCP — with an automatic safety rollback if a change would otherwise lock you out of the station.

---

## 10. Getting help

- The **Help** button at the bottom of the sidebar opens guided walkthroughs for common real-world
  situations, a searchable FAQ, and a full tool reference — all without leaving the app.
- This manual and the [Quick-Start Guide](quickstart.md) live in the project's `docs/` folder and are
  always available offline on the station itself.
- [README.md](../README.md) has the full security model, environment variables, a system
  architecture diagram, and a longer troubleshooting reference for install-time and system-level
  issues.
- [CHANGELOG.md](../CHANGELOG.md) lists what's changed in each released version.
