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

## [1.27.3] - 2026-09-02

Documentation only - no code behavior changed. This app installs, imports, vendors, or loads a large
number of pre-existing third-party forensic tools and libraries to do its job (`dc3dd`, The Sleuth
Kit, ClamAV, Volatility 3, MVT, Bootstrap, Leaflet, and dozens more); this release makes clear that
none of them are covered by this project's own GPLv3 license - each keeps its own separate one.

### Added

- **THIRD_PARTY_NOTICES.md** (repo root) - a full, researched list of every third-party tool, Python
  package, vendored tool, and frontend library this station installs or loads, organized by how it
  reaches the station, with its actual license. A few carry non-standard terms worth reading directly
  rather than assuming they behave like a typical open-source license - MVT's own license adds a
  binding informed-consent requirement, Volatility 3 uses a custom non-OSI license, and SQLite Dissect
  was issued under specific US Department of Defense statutory authority. Also viewable in-app under
  **Help > Third-Party Notices**, and linked from **Settings > Service Controls & Diagnostics >
  Updates**.
- `LICENSE` now opens with a short note pointing to THIRD_PARTY_NOTICES.md before the GPLv3 text
  itself, and the README's own license section does the same.

## [1.27.2] - 2026-09-02

A full UI/UX audit and cleanup pass - no new tools or features, just fixing what a systematic review
of every tab, template, and the frontend's own JavaScript/CSS turned up. Three research passes plus a
design review covered the whole app; the fixes below are the low-risk, worth-doing subset that came
out of it.

### Fixed

- Memory Forensics' plugin/table checklist could carry over stale selections from a previous scan
  after reopening the modal for a different file - it now resets to its defaults every time it opens,
  so a scan can no longer silently run with leftover checkboxes from an earlier file.
- Settings > Restore From Backup (which replaces every user account, group, and setting on the
  station) now requires typing `RESTORE` before the button enables - previously it only needed a
  passphrase and a single click-through confirmation, noticeably less friction than Live Collection
  USB's own drive-wipe step already has for a comparable or smaller blast radius.

### Changed

- Case Number / Evidence ID / Examiner fields across Acquisition, Mobile, File Recovery, and Live
  Collection USB now have real accessible labels, not just placeholder text (which disappears the
  moment you start typing and was never a reliable label for a screen reader).
- Icon-only buttons on File Explorer's image toolbar and the sidebar collapse toggle now have
  accessible names, not just hover tooltips - tooltips don't fire on a touchscreen, which is how this
  app is meant to run.
- File Recovery's card header now matches its own sidebar label ("File Recovery," it previously read
  "Recovery Tools" nowhere else in the app), gained the "Case & Evidence Metadata" heading its sibling
  tabs already had above the same three fields, and its placeholder text now shows example values
  like the rest of the app already does.
- Reporting's Export button is no longer styled red - exporting a report isn't a destructive action,
  and every other export/download button in the app already used a neutral color.
- A handful of inconsistently-worded toast messages ("Mount Failed" vs. "Mount failed", etc.) were
  normalized to the app's own dominant style.
- Settings' Diagnostics dropdown now shows what each raw command actually does (e.g. "lsusb
  (connected USB devices)") instead of a bare Unix command name with no explanation.
- Settings' User Groups accordion now clarifies that a permission group ("Analyst") and the
  "Examiner" name recorded per case are two different things - one is what a login is allowed to do,
  the other is who did the work.
- A number of hardcoded colors that already had a matching design token now use it (no visible
  change), and a few leftover/stale code comments from earlier tab restructuring were cleaned up.

---

## [1.27.1] - 2026-09-02

### Fixed

- **iOS `.ipa` static analysis's optional Mach-O binary layer would crash the whole analysis on any
  real app with a real executable inside it**, instead of the graceful "LIEF couldn't parse this"
  fallback it was designed to show. Found and fixed while adding the first-ever automated tests for
  six mobile-forensics tools that had shipped without them (SQLite Dissect, APK static analysis,
  WhatsApp backup decryption, iOS crash-report pull, SIM/UICC card reading, `adb bugreport` parsing) -
  all now have real test coverage. No change to what any of these tools actually do; the `.ipa`
  Mach-O fix is the only functional change.

---

## [1.27.0] - 2026-09-01

### New

- **A real, filtered phone timeline: text messages, web history, and social media/messaging apps now
  show up with real timestamps on the Evidence Timeline, and can be filtered by category.** ALEAPP/
  iLEAPP's parsed mobile-app data (SMS, MMS, call logs, WhatsApp, Instagram, Snapchat, Facebook
  Messenger, Telegram, Signal, TikTok, Reddit chats, plus Chrome/Firefox web history and visits) now
  carries a real timestamp instead of always showing "no time recorded" - so it actually appears in
  the chronological timeline, not just in the searchable artifact list.
- **A new Category filter on the Evidence Timeline** (Reporting > Evidence Timeline): Communications,
  Web Activity, Social Media, Device & System, and Filesystem, each with its own checkbox and a
  colored badge on every row. A "Phone Activity Only" button narrows straight to just Communications +
  Web Activity + Social Media in one click; "All Categories" resets. The exported CSV now includes the
  category too.

### Fixed

- **The in-app version number (shown on the login page, the navbar, and Settings > Diagnostics) had
  been stuck at v1.11.0 for many releases** - the file it reads from was never updated as part of the
  normal release process, even though README/CHANGELOG kept moving forward. Fixed going forward.

---

## [1.26.1] - 2026-09-01

### Fixed

- **A fresh install could fail to build `mquire` (Linux memory forensics for x86_64 images) at all.**
  The build step relied on the Debian-packaged Rust compiler, which turned out to be too old for one
  of `mquire`'s own dependencies. The installer now installs and uses an up-to-date Rust toolchain
  specifically for this one step (via `rustup`, run as the station's own unprivileged service account,
  never as root), so this no longer depends on how current Debian's own Rust package happens to be.
  No change to `mquire` itself or what it does - already-working stations are unaffected.

---

## [1.26.0] - 2026-09-01

### New

- **Windows Search Index parsing** (Windows.edb, Vista through 10) - the operating system's own
  search index of files it has scanned, including indexed files' resolved paths, names, and a preview
  of the actual text content Windows extracted from inside each one. A prior internal note in this
  project had declined this artifact as too unreliable to correlate correctly - re-examined with fresh
  research and found that assessment was wrong, so it's built now.
- **Legacy Internet Explorer 10/11 and pre-Chromium Microsoft Edge browsing history/cookies**
  (WebCacheV01.dat/WebCacheV24.dat) - a fourth real browser family added to the existing Chrome/
  Firefox/Safari support, useful on any older Windows image (modern Chromium-based Edge is already
  covered by the existing Chrome-family parser).
- **BITS job queue parsing** (qmgr.db, Windows 10+) - BITS is a legitimate Windows background-download
  service that's also a real, well-known technique attackers use for stealthy downloads. Recovers each
  job's name, the exact command it ran on completion, and who owns it. Deliberately does not attempt to
  recover individual downloaded-file details in this version - a real, disclosed scope decision rather
  than a guessed, possibly-wrong result.
- **RDP Bitmap Cache detection** (Cache0001.bin / bcache22.bmc) - evidence that a Remote Desktop client
  session took place on this machine, with per-tile metadata (a real deduplication key, tile
  dimensions) even though this version doesn't reconstruct the actual on-screen images.
- **OCR text extraction** - pulls readable text out of screenshots, scanned documents, or photographed
  notes/signage right-clicked in File Explorer - evidence no other tool here can see, since it exists
  only as pixels, not raw file bytes. English text only in this version.
- **Video contact sheets** - generates a single image showing a grid of evenly-spaced frames from a
  video file, so you can see what's in it at a glance without opening a media player.

All six new tools are reachable the same way as every other artifact parser in this app - right-click
a folder or file, or run against a whole acquired disk image.

---

## [1.25.0] - 2026-09-01

### New

- **This app's first macOS-specific artifact support**: LaunchAgents/LaunchDaemons persistence items -
  the small program-launch configuration files macOS itself uses to auto-start background processes,
  and one of the most common real-world techniques Mac malware uses to survive a reboot. Reached the
  same way as every other new artifact this session - right-click a folder, or run against a whole
  acquired image. **Important, disclosed limitation**: this app cannot currently browse a modern Mac's
  disk image at all - virtually every Mac sold since 2017-2018 uses a filesystem format (APFS) this
  app's underlying browsing library doesn't yet support. This new tool still works fully against an
  already-extracted evidence folder (for example, a direct file copy from a connected Mac) regardless
  of that limitation, and works against an image only if it's an older, HFS+-formatted Mac disk.
- **Mac/Linux shell history can now capture real per-command timestamps when the shell was configured
  to record them** (zsh's EXTENDED_HISTORY option - not the default on a stock, unmodified Mac, but
  common on a security-conscious or professionally-managed one). Detected automatically per line, so
  a stock Mac's plain, un-timestamped history file is completely unaffected.

---

## [1.24.0] - 2026-09-01

### New

- **PowerShell command history can now be parsed and read directly** - every command typed at a
  PowerShell prompt, including multi-line pasted commands (correctly reassembled into one readable
  entry). Note: this file never records a timestamp at all - that's a real limitation of the format
  itself, not something missing from this feature.
- **Windows Firewall connection logs can now be parsed and read directly**, when an administrator has
  turned that logging on (it's off by default, so this file is commonly not present at all - that's
  expected, not a problem). Shows every logged allowed/blocked connection with source/destination
  address and port. Both reached the same way as every other new artifact this session - right-click a
  folder, or run against a whole acquired image - and both shown as optional extra steps in Auto
  Analyze. Neither has been tested against a real Windows-produced sample file yet - flagged in each
  tool's own tooltip as not yet verified.

---

## [1.23.0] - 2026-09-01

### New

- **SRUM can now be parsed and read directly** - widely considered one of the single most valuable
  pieces of evidence a modern Windows system keeps: which applications actually used the network
  (how much data sent/received) and how much CPU time they consumed, tracked over a rolling window -
  even for applications that have since been uninstalled. Reached the same way as every other new
  artifact this session (right-click a folder, or run it against a whole acquired image), and shown
  as an optional extra step in Auto Analyze. Not yet tested against a real Windows-produced sample
  file - flagged in the tool's own tooltip as not yet verified.

---

## [1.22.0] - 2026-09-01

### New

- **Two more Windows artifacts can now be parsed and read directly**: the built-in **Notification
  history** (everything sent to the Action Center - which app, when, and often the actual text of
  the notification) and **Windows Timeline / Activity History** (which apps were used, which
  documents were opened, and which websites were visited, each with a timestamp). Both are reached
  the same way as Sticky Notes - right-click a folder, or run it against a whole acquired image - and
  both correctly recover the most recent entries even when they've only been saved to a temporary
  companion file, not yet folded into the main database. Note: Microsoft trimmed how much the
  Timeline feature records starting in a January 2024 Windows 11 update, so a Windows 11 image made
  after that update will show much less activity history than a Windows 10 image - that's expected,
  not a parsing failure.

---

## [1.21.1] - 2026-09-01

### Fixed

- **A deleted Sticky Note (or any future artifact type with a similar concept) could show as "not
  deleted" in the Evidence Timeline.** The timeline never actually checked that flag for anything
  parsed out of an acquired image - fixed so it now does.

---

## [1.21.0] - 2026-09-01

### New

- **Windows Sticky Notes can now be parsed and read directly.** A new "Parse Sticky Notes" action
  (right-click a folder, or run it against a whole acquired image) finds the built-in Sticky Notes
  app's own database and reads the actual text of every note - including deleted ones, which the app
  keeps rather than truly erasing. Correctly recovers the most recent notes and edits even when
  they've only been saved to a temporary companion file the app hasn't yet folded into its main
  database - a real gap a naive copy of just the main file would silently miss.

---

## [1.20.0] - 2026-09-01

### New

- **Two more Windows Registry artifacts, parsed automatically** ("Parse Registry Hives" - no new
  action needed): **Office recent files/folders**, tracked separately per application (Word, Excel,
  PowerPoint, Access, Publisher) - a more specific signal than the existing shell-wide recent-
  documents list, including both signed-in and local-account Office profiles. **Explorer search-box
  history**, what a user has typed into the Windows Explorer search box - fully populated on Windows
  7 through pre-23H2 Windows 11, but Microsoft changed how Explorer search works starting Windows 11
  23H2, so this key stops being written entirely on newer builds - a blank result there is expected
  and disclosed, not a parsing failure.

---

## [1.19.0] - 2026-09-01

### New

- **Two more Windows Registry artifacts are now parsed automatically** alongside every existing one
  ("Parse Registry Hives" - no new action needed): **BAM/DAM** (Background/Desktop Activity
  Moderator), a last-activity execution timestamp per program that's distinct from Prefetch/Amcache/
  UserAssist (updated both when a process starts and when it ends, with no run-count history); and
  **RDP connection history**, which remote hosts this user connected to via the built-in Remote
  Desktop client, with the last-used username. For both: presence is strong evidence, but absence
  proves nothing - several legitimate ways to bypass either (mstsc's "/public" mode, the newer Store
  Remote Desktop app, BAM/DAM's own 7-day retention window) mean an empty result should never be read
  as "this didn't happen."

### Fixed

- **A real, previously-live timestamp bug**: several existing Registry artifacts (recently opened
  documents, typed Explorer/browser paths, Run-dialog history, USB device history, installed
  programs, Amcache, and ShellBags) could report a timestamp shifted by several hours from the true
  time on any station not configured to the UTC timezone - including this project's own real
  deployed test station. Every one of these now reports the correct time regardless of the station's
  local timezone setting.
- **Auto Analyze's own step checklist could never actually offer two already-shipped steps.** The
  modal's list of available analysis steps had silently fallen out of sync with what the app could
  actually run, meaning "Parse Jump Lists" and "Android SMS/Contacts/Call Log" could never be
  selected there even though every other way of running them already worked. Fixed, and restructured
  so this specific class of drift can't recur.

---

## [1.18.0] - 2026-09-01

### New

- **Windows Thumbcache thumbnails can now be extracted and viewed.** A new "Extract Thumbcache
  Thumbnails" action (right-click a folder, or run it against a whole acquired image) finds every
  `thumbcache_*.db` file (Windows 8 through 10/11) and pulls out each embedded thumbnail as a real,
  directly-viewable image file - these can persist in the cache long after the original photo or
  document has been deleted from the drive. The internal identifier is usually a one-way hash rather
  than the original filename, but for deleted files and files on removable/network drives it's
  sometimes the real filename or path instead - shown as such whenever that's the case, never guessed
  at. Older Windows Vista/7-format cache files use a different, unsupported layout and are skipped
  with a clear note rather than silently misread.

---

## [1.17.0] - 2026-09-01

### New

- **UserAssist is now parsed from Registry hives** - evidence a program was actually clicked/launched
  through the Windows Explorer shell (not just command-line-invoked), with a run count and how long
  it stayed in focus. A different signal from Prefetch/Amcache (already covered): a high run count
  with near-zero focus time is a real "launched then immediately closed or crashed" pattern neither of
  those artifacts can show on their own. No new action needed - it's picked up automatically the same
  place Registry hives already are ("Parse Registry Hives").

### Fixed

- **File Views could take 6+ minutes to load on a case with a lot of accumulated data.** A background
  self-healing sweep was re-walking the entire case folder on every single load instead of on a
  reasonable interval - fixed with the same throttling approach already used elsewhere in the app for
  an identical class of problem. A routine File Views visit should now always be fast, regardless of
  how large the case folder has grown.

---

## [1.16.0] - 2026-09-01

### New

- **Windows Jump Lists are now parsed** - "recently/frequently accessed files per application," a
  different angle from Prefetch's own "did this program ever run" evidence. Both real Jump List file
  types are covered: AutomaticDestinations (`.automaticDestinations-ms`, with pin status/last-access
  time/hostname where available) and CustomDestinations (`.customDestinations-ms`, pinned/custom
  items). Right-click a folder (or an acquired image) and choose "Parse Jump Lists" the same way
  Registry hives/Event Logs/Prefetch already work - real folder or unmounted image, no extraction
  needed, results land in the same searchable Parsed Artifacts index and Evidence Timeline.

---

## [1.15.0] - 2026-09-01

### New

- **Browser artifact parsing now covers Safari, not just Chrome/Chromium and Firefox.** History,
  Bookmarks, Downloads, and Cookies from a Safari profile (real folder or inside an acquired image)
  parse into the same searchable index and Evidence Timeline as every other browser artifact -
  right-click the profile folder and choose "Parse Browser Artifacts (Chrome/Firefox/Safari)"
  exactly as before, no new action needed. Cookie values are shown in plain text (Safari doesn't
  encrypt them the way Chrome does).

---

## [1.14.0] - 2026-09-01

### New

- **Import an already-extracted Apple "Data & Privacy" export** (from privacy.apple.com), the same
  way Google Takeout archives were added last release. Apple emails you a password and delivers the
  export as an encrypted zip - this app never handles that password, so you extract the archive
  yourself first, then point it at the resulting folder. Contacts and Calendars/Reminders parse
  reliably (vCard and iCalendar are genuine open, published standards, not something Apple could
  quietly change the shape of); Safari Bookmarks and Photos metadata are labeled Best-Effort. Any
  GPS-tagged photo it finds exports as a map the same way a photo's own EXIF data already does -
  Apple's export has no location-history category at all (Find My/Significant Locations never leaves
  the device, encrypted end-to-end even from Apple itself), so there's nothing else to look for
  there. Like Google Takeout, this only ever reads a file you already obtained yourself; it never
  logs into an Apple account or touches the network.

---

## [1.13.0] - 2026-09-01

### New

- **Android acquisitions now get parsed straight into File Explorer's searchable index, instead of
  just sitting as raw files.** Running ALEAPP or iLEAPP (already a right-click action) now
  automatically pulls its own structured output into the same searchable Parsed Artifacts category
  Registry hives, Event Logs, and browser artifacts already use - WiFi networks, installed apps,
  accounts, SMS, call logs, contacts, browser history, WhatsApp data, and more, wherever the scan
  actually finds them. Note that a plain, non-rooted "Pull Accessible Storage" acquisition can only
  ever reach a phone's shared storage (`/sdcard`) - most of what ALEAPP looks for lives in app-
  private storage that needs root, so how much shows up here depends heavily on what kind of
  acquisition you ran.
- **A dedicated Android SMS/Contacts/Call Log parser for rooted physical acquisitions.** If you've
  captured a full raw image from a rooted device (the "Physical" acquisition mode), a new right-click
  action reads the phone's actual SMS, contacts, and call log databases straight out of the image and
  drops them into the same searchable Parsed Artifacts index.
- **Location history from ALEAPP/iLEAPP scans can now be exported as a map.** A new "Export
  ALEAPP/iLEAPP Location History (KML)" action scans whatever's already been parsed for anything with
  plausible GPS coordinates and builds a map you can view right in File Explorer or in Reporting's
  Geolocation tab, the same as a photo's EXIF GPS data already does.
- **Import an already-downloaded Google Takeout archive.** If you (or the account holder) have
  already exported data through Google's own official Takeout tool, a new "Import Google Takeout
  Archive" action reads it - either an already-extracted folder or the downloaded `.zip` file(s) -
  and pulls Search History, YouTube History, Location History, Maps saved places, and photo metadata
  into the same searchable index and map view as everything else. This only ever reads a file you
  already obtained yourself; it never logs into a Google account or touches the network. Search and
  YouTube History use a reliable format; Location History, Maps, and Photos are labeled "Best-Effort"
  since Google's own export format for these has changed recently and isn't fully documented.

---

## [1.12.0] - 2026-09-01

### New

- **Live Collection USB can now capture a full memory (RAM) image, not just process/network/session
  data.** Early in a collection run - on a target running elevated, with the tools available on the
  drive, and only if there's enough free space to fit the RAM - the collector script asks whether to
  capture memory before continuing (defaulting to No). Say yes and it captures the entire contents of
  RAM before moving on to everything else, since RAM is the single most volatile thing being
  collected: AVML for Linux targets (in LiME format), WinPmem for Windows targets (as a plain raw
  image, via a real acquire-then-extract sequence so no new dependency was needed to read it back).
  The result lands on the drive alongside everything else and imports into the case ready to open
  with Memory Forensics.
- **A few more genuinely volatile things are now collected.** Windows collection now also gathers
  mapped network drives and clipboard contents, and hashes every process's own executable file
  (matching what the Linux/macOS/BSD side already did) - closing a real gap where the two platforms'
  results weren't apples-to-apples. Unix/macOS/BSD targets now also capture clipboard contents right
  after the main collection finishes.
- **Imported results are now automatically turned into something you can actually search and
  cross-reference, not just a pile of raw files.** On import, the Windows-side results (processes,
  network connections, logged-on users, services, scheduled tasks, autoruns, mapped drives,
  clipboard) are parsed straight into File Explorer's searchable Parsed Artifacts category and the
  Evidence Timeline - no separate action needed. Every process executable's hash is checked against
  every Hash Set you've configured, and any match is recorded as its own flagged artifact. A plain
  `SUMMARY.txt` (and a machine-readable `summary.json`) is generated alongside the raw files and
  manifest, giving you process/connection/service/hash-match counts and whether a memory image was
  captured, without needing to open anything else first.

---

## [1.11.0] - 2026-08-31

### New

- **USB-deployable live-forensics collector.** A new "Live Collection USB" section on the Forensic
  Acquisition tab prepares a USB drive to gather *volatile* evidence (running processes, network
  connections, logged-on users, and more) from a separate, running machine you don't want to power
  off - the opposite problem from this app's own dead-box disk imaging.

  - **Build Live Collection USB** wipes and formats a confirmed-blank USB drive (exFAT, for reliable
    read/write on Windows, macOS, and Linux) and copies onto it a real, open-source Linux/macOS/BSD
    collector (UAC) plus a small, fully readable PowerShell script for Windows - both run directly
    from the drive with nothing to install on the target machine. This is the first time this app
    ever writes to a USB drive it doesn't treat as evidence, so it's gated behind the strongest
    confirmation in the app: you have to type the exact device path to enable the button, not just
    click through a pop-up.
  - Plug the drive into the machine you want to examine, run the included script (a README on the
    drive walks through it), and everything it collects is written back onto the same drive. Nothing
    it does ever touches a network.
  - **Import Collection Results** reads the drive back (read-only - no write access needed for this
    part) once you bring it back to the station, shows you what it found, and copies whatever you
    select into your case with a full hash-verified manifest.

### Fixed

- A background status check could silently re-enable the "Build Live Collection USB" button a couple
  of seconds after you'd correctly left it disabled by not finishing the confirmation text - found and
  fixed during this feature's own testing, before release.

---

## [1.10.0] - 2026-08-30

### Changed

- **File Explorer's right-click menu is now compact and context-aware.** Only tools that could
  actually apply to the selected file, folder, or image are shown - a plain document now shows a
  handful of relevant items instead of the full list with most of them greyed out, and a whole
  section (Whole-Image Analysis, Artifact Parsers, Mobile & Memory) disappears entirely when none of
  its tools apply. Single-file analysis tools that have already been run against the exact selected
  file (Binwalk, ClamAV, Strings, Hash Sets, YARA, Fuzzy Hash, SQLite Dissect, APK/IPA/Bugreport
  analysis, LNK parsing) now show a small checkmark with the prior result summary and timestamp, so
  you can tell at a glance whether you've already analyzed a file before running it again.

---

## [1.9.0] - 2026-08-30

### New

- **NTFS $MFT analysis with timestomping detection.** File Explorer gained "Analyze $MFT" - parses a
  Master File Table's file records (creation/modified/access/change timestamps from both attributes
  Windows keeps per file) and flags records where those two disagree in a way consistent with
  timestomping (a suspected-not-certain indicator - a well-known DFIR heuristic, not a guarantee).

- **NTFS $UsnJrnl change-journal parsing.** File Explorer gained "Parse $UsnJrnl Change Journal" - a
  chronological log of every file create/rename/delete/write on an NTFS volume, including files that
  were created and deleted entirely between two snapshots and leave no other trace anywhere else.

- **ShellBags and Shimcache/AppCompatCache.** "Parse Registry Hives" now also covers USRCLASS.DAT's
  ShellBags (proves a folder was browsed via Windows Explorer, including removable/network/deleted
  folders) and SYSTEM's Shimcache (program-execution evidence; Windows 10/11 format only).

- **Email parsing.** File Explorer gained "Parse Email Files" - .eml (single message), .mbox (Unix
  mailbox), and .pst/.ost (Outlook) files are parsed into subject/sender/recipients/date/body
  preview/attachment-count records, searchable and timeline-integrated like every other artifact type.

- **Fuzzy hashing (TLSH).** A new "Compute Fuzzy Hash (TLSH)" action computes a similarity-based
  digest for a file and lets you compare it against another - catches a lightly-modified or
  recompiled variant of a known file that an exact hash-set match would completely miss.

- **Volume Shadow Copy (VSS) support.** File Explorer's image toolbar gained a "List Shadow Copies"
  action for NTFS volumes - each shadow copy found can be materialized as a separate, fully browsable
  image file, letting you inspect a volume's past point-in-time state with every existing tool
  (search, timeline, hash manifest, and more) that already works on an ordinary acquired image.

---

## [1.8.0] - 2026-08-30

### New

- **Pull iOS crash reports.** Mobile Forensics gained a "Pull Crash Reports" button, shown once a
  connected iOS device is selected - copies the device's own `CrashReporter` logs (decoded into
  readable `.crash` files) without ever removing the originals from the device.

- **SIM/UICC card forensics.** Mobile Forensics' device-mode selector gained a "SIM/UICC Card" option -
  detects connected PC/SC card readers and reads a card's basic identity (ICCID, ATR, EID for eSIM,
  and any application IDs present). Requires a PC/SC-compatible card reader connected to the station;
  the underlying reader daemon and its access permissions are set up automatically during install.

---

## [1.7.0] - 2026-08-30

### New

Five more analysis tools, closing gaps found during a follow-up mobile-forensics-tool research pass.
All five write their generated output through the same evidence-integrity guard shipped in 1.6.0 - a
report can never land inside, or next to, the exact folder being analyzed.

- **Recover deleted SQLite records.** File Explorer's right-click menu on any `.db`/`.sqlite`/
  `.sqlite3` file gained "Recover Deleted SQLite Records" (using SQLite Dissect) - recovers rows still
  present in a database's own freeblocks, unallocated space, or a surviving WAL/rollback-journal file.
  Recovery reliability depends heavily on how the file was closed: a database acquired with its own
  WAL file still present alongside it is the most reliable case, since SQLite's own page management
  frequently compacts a deleted row's freed bytes away entirely on a normal close.

- **Android APK static analysis.** Right-click an `.apk` file and choose "Analyze APK (androguard)" -
  package/version metadata, every requested permission, every declared activity/service/receiver/
  provider, the full signing-certificate chain (subject, issuer, serial, SHA-256 fingerprint, validity
  dates), and a scan for URLs embedded in the raw file. Never runs or installs the app.

- **WhatsApp local-backup decryption.** Two pieces: Mobile Forensics can now pull a rooted Android
  device's own WhatsApp key file directly ("Pull WhatsApp Key File", shown once a connected device's
  root access is confirmed); File Explorer's right-click menu on a `msgstore.db.crypt12/14/15` file
  gained "Decrypt WhatsApp Backup" - decrypts it against that key file into a real, browsable SQLite
  database (openable directly via File Explorer's existing Database preview tab, no separate viewer
  needed).

- **iOS IPA static analysis.** Right-click an `.ipa` file and choose "Analyze IPA" - `Info.plist`
  metadata (bundle ID, version, every permission usage-description string), the embedded mobile
  provisioning profile (team, entitlements, provisioned devices, validity dates - no signature
  verification is attempted), and an optional Mach-O binary layer (architecture and FairPlay
  encryption status per slice) that degrades gracefully to "unavailable" rather than failing the whole
  analysis if it can't run.

- **Deep-parse an `adb bugreport` archive.** File Explorer's right-click menu on a `.zip` file gained
  "Deep-Parse Bugreport" - turns an already-captured bug report (Mobile Forensics' own Bug Report mode)
  into structured sections instead of a raw, unsearched archive: mount points, the running process
  list, package install/delete history, loaded kernel modules, GPS coordinates, crash traces and
  tombstones, network socket/connection state, battery stats, and power events.

---

## [1.6.0] - 2026-08-30

### New

- **ALEAPP/iLEAPP mobile artifact parsing.** File Explorer's right-click menu gained "Parse with
  ALEAPP/iLEAPP...", a much deeper, comprehensive artifact-parsing pass over an already-acquired
  Android `adb pull` extraction or iOS `idevicebackup2` backup, using the same open-source, community-
  maintained parsers (ALEAPP/iLEAPP) many examiners already reach for outside this app - hundreds of
  app-specific artifacts (WhatsApp, Signal, Telegram, Chrome, WiFi history, app usage, and far more),
  well beyond this app's own small built-in mobile parser. Runs as a background job with full progress
  tracking (parsed live from the tool's own per-module output) and Stop-button support, since a real
  multi-GB extraction can take many minutes to run the full artifact catalog. The result is a real,
  self-contained HTML report plus TSV data files, saved as a new folder next to the extraction and
  automatically found by File Explorer/File Views.

  Each tool runs in its own dedicated, isolated Python environment on the station, not this app's own
  shared one - a real, hard dependency conflict was found and confirmed before deciding this (ALEAPP
  pins an old `packaging` version, iLEAPP needs a much newer one; pip's own resolver refuses outright
  to install both together). Neither tool needed a new always-on background process - both are plain
  command-line scripts, invoked as a subprocess exactly like every other external tool this app already
  shells out to.

### Fixed

- **Analysis output could land directly inside the evidence folder being analyzed**, silently adding
  non-evidence content to it - a real, live bug affecting Geolocation Export and MVT scan (Hash
  Directory Tree carried the same defect, not yet triggered against real data but present in the code).
  All three now write their generated file(s) into the active case's folder instead (falling back to
  the analyzed folder's own parent if no case is selected) - never into, or nested inside, the folder
  or image actually being examined. Enforced at the server, not just assumed from the client: any
  request whose destination resolves to the same path as the source, or somewhere underneath it, is
  now rejected outright rather than silently honored. This also covers Auto Analyze's own hand-off into
  MVT for a Mobile-profile scan, since it reaches the same route. A small number of already-affected
  evidence folders from before this fix were found and corrected as part of shipping it.

---

## [1.5.0] - 2026-08-30

### New

- **Physical/raw Android acquisition**, for an already-rooted device only. Mobile Forensics' Android
  mode gained a fourth option, "Physical / Raw Acquisition (rooted device only)" - it pipes the
  device's own raw block storage directly through `adb exec-out su -c dd` into this app's existing
  `dc3dd`/`dcfldd` acquisition engine (the same hashing/write pipeline already used for a locally-
  attached drive), instead of the app's previous logical-only acquisition methods. E01 isn't offered
  for this mode - confirmed live that `ewfacquire` cannot read from a piped, non-seekable source at
  all. The examiner picks a target partition from an on-device enumeration (`userdata` pre-selected
  when found, since modern Android's Dynamic Partitions make it almost always the forensically
  interesting target - a naive whole-disk image is available only via an explicit manual path), or
  types a raw device path manually for an older/simpler device.

  Root access and SELinux enforcement mode are detected and disclosed per-device before the examiner
  can start a job - a clear red banner when root isn't detected, a clear yellow banner when root is
  confirmed but block-device readability genuinely isn't knowable until attempted (SELinux enforcing
  mode can block even root from raw block access). A failed on-device read produces a specific,
  distinguishable error rather than a generic failure message.

  Built and verified in two halves, since no rooted Android device was available to build against:
  the actual two-process pipe mechanism (a new `_stream_piped_subprocess()` in `core/jobs.py`,
  chaining the device-side read into the station-side dc3dd/dcfldd write) was fully proven with a
  real dry-run test on the deployed station - byte-identical output with a matching hash, both
  processes cleanly killable mid-transfer with zero orphans, and a deliberately-failing upstream
  leaving the write side in a clean, honest state rather than hanging. The on-device root/SELinux
  detection and target-enumeration commands are grounded in documented Android/Linux convention but
  are explicitly disclosed as provisional pending a real end-to-end test against a rooted device -
  see the approved plan's own verification checklist for exactly what still needs confirming.

---

## [1.4.1] - 2026-08-29

### Fixed

- Android pull acquisitions now pass `-a` ("preserve file timestamp and mode") to `adb pull`, so the
  copied files' own on-disk modification time is correct too - not just the value the Evidence
  Timeline shows. Confirmed as a real, documented flag on this project's own installed `adb`
  (platform-tools 34.0.5) via its `help` output. The v1.4.0 on-device timestamp capture (a separate
  `adb shell find` call after the pull, writing a sidecar manifest) is kept as-is alongside this -
  it doesn't depend on `-a` support, which can vary by `adb` client/device combination, so it stays
  the actual source of truth for the Evidence Timeline regardless of whether `-a` is honored on a
  given station/device pairing. `-a`'s real effect has not yet been empirically re-verified against
  a connected device (added while the phone was disconnected) - worth confirming directly the next
  time one's available.

---

## [1.4.0] - 2026-08-29

### New

- **Android pull acquisitions now capture each file's genuine on-device modification time**, closing
  the gap the v1.3.0 disclosure note only worked around. Immediately after a successful `adb pull`,
  the acquisition worker makes one `adb shell find` call against the connected device to read every
  pulled file's real modification timestamp directly from the phone, and writes it as a sidecar
  manifest next to the pull's own output folder. The Evidence Timeline (and the exported PDF/HTML
  report's Filesystem Timeline section) now use that real value in place of the copied file's own
  copy-time modification date whenever it's available - a single genuine "Modified" entry per file,
  not a fabricated Accessed/Changed/Created alongside it. A pull made before this shipped, or one
  where the device disconnected right after the pull before the capture step could run, has no
  manifest and falls back to the pre-existing copy-time behavior with its existing disclosure note,
  unchanged. If only some files in a pull have a captured timestamp (e.g. a file was added to the
  phone between the capture and the pull finishing), only those specific files fall back - the rest
  still show real device times.

  Confirmed empirically on a real connected Pixel 8a before building this: `/sdcard` on Android is
  itself a symlink, so the on-device `find` needs `-H` to actually descend into it (without it, the
  walk silently returns nothing); this device's `find` only supports capturing modification time
  this way (not access/change time), which is also the one timestamp `adb pull` was actually
  destroying and the one that matters most for a timeline. A full 1,819-file walk of a real device
  completed in under 2 seconds.

- The interactive Evidence Timeline table now shows a green **"Device Time"** badge on any row using
  a genuine, captured-from-the-phone timestamp - previously this distinction only ever showed up in
  an exported PDF/HTML report, never in the live table an examiner is actually looking at day to day.
  Included in the CSV export as its own column too.

  Verified against a real, brand-new ~15-minute, 8.77 GB `adb pull` against a real connected Pixel
  8a, run through the actual application end to end: 1,823 real on-device timestamps captured, and
  independently cross-checked three separate ways - a trashed photo's own filename (Android embeds
  its original deletion timestamp directly in `.trashed-<epoch>-<epoch>.jpg`-style filenames)
  matched the captured value to within 73ms; the Evidence Timeline's density chart showed a real,
  varied spread of activity across several months instead of one spike on the pull's own run date;
  and all 714 timeline rows for the new evidence item correctly carried the new "Device Time" badge.

---

## [1.3.0] - 2026-08-29

### New

- The **Evidence Timeline** (Reporting) now has **Year** and **Month** drill-down filters, sitting
  next to the existing "All Evidence Items" filter. Year lists only the years that actually have
  data for the case (a case can genuinely span years - filesystem timestamps from an acquired
  image, artifact-parsed dates, etc.); Month unlocks once a specific year is picked and narrows
  further within it. Both feed the same chart the "All Evidence Items" filter already did, so
  picking a year renders daily/weekly bars for that year instead of the whole case's history
  getting flattened into two or three unreadable clusters on a multi-year chart.

### Fixed

- The Evidence Timeline (and the exported PDF/HTML report's Filesystem Timeline section) now
  explicitly discloses a real, confirmed limitation for any Android pull-mode acquisition:
  `adb pull` does not preserve a phone's original file timestamps - it stamps the local copy time
  on every file instead. Confirmed empirically against a real device pull, where every copied
  file's timestamp landed on the pull's own run date despite several filenames carrying real,
  materially earlier dates from the phone itself (e.g. `Screenshot_20260724-102354.png`). This is a
  limitation of `adb pull` itself, not of pi-forensics' own timeline walk - the walk correctly
  reads whatever timestamp the copied file actually has - but it went undisclosed, so an examiner
  could mistake "today" for genuine on-device activity. A clear note now surfaces automatically
  for any affected evidence item, both in the interactive Evidence Timeline and in exported
  reports. Deliberately scoped to `adb pull` only - Logical Acquisition's own file copy preserves
  the original source timestamp by design, and iOS backup's behavior in this regard hasn't been
  verified either way, so nothing is claimed about either of those.

---

## [1.2.0] - 2026-08-29

### New

- The **Evidence Timeline** (Reporting) and the exported PDF/HTML report's **Filesystem Timeline
  (MACB)** section now cover mobile pull/backup acquisitions and Logical Acquisition, not just
  disk images. These don't produce a walkable raw/E01/AFF image at all - `adb pull`,
  `idevicebackup2`, and Logical Acquisition all copy real files onto this station's own filesystem
  one at a time - so there was previously no timeline option for them whatsoever. The files
  themselves still carry real Modified/Accessed/Changed timestamps once copied, so this walks the
  acquisition's own output folder directly and merges the result into the same timeline a disk
  image's Sleuth Kit walk already produces, with the same dedup/budget-splitting safeguards a
  disk-image timeline already has (a re-run acquisition landing in the same output folder is
  deduplicated to the latest pass; one very large pulled folder can't crowd out every other
  evidence item's own timeline contribution in the same case).

### Fixed

- The exported PDF and HTML report's Filesystem Timeline (MACB) section was rendering raw Unix
  epoch numbers (e.g. `1428959741`) instead of a real date/time for every entry - a pre-existing
  defect (present since this feature first shipped) that had gone unnoticed because the in-app,
  browser-rendered Evidence Timeline view formats these correctly client-side; only the two
  server-rendered export paths had the bug. Found and fixed alongside the mobile-pull/Logical
  Acquisition timeline work above, since the new folder-based entries would otherwise have hit the
  identical bug.

---

## [1.1.6] - 2026-08-29

A documentation release. No functional changes.

### Fixed

- [README.md](../README.md)'s Security section had one table row ("Service privileges") whose cell
  content contained a raw line break, which breaks GitHub-Flavored Markdown table syntax - the row
  rendered as a broken table with an orphaned, blank-second-column row underneath it instead of one
  clean cell. Pre-existing (introduced 2026-08-29, before this same day's other doc work), not
  something this release's own changes caused. Verified via a full-file scan (no other table row in
  the file has this problem) and by rendering the fixed file through Python's own Markdown table
  parser: all 3 tables (30 rows total) now render with zero malformed rows, versus 1 before the fix.

---

## [1.1.5] - 2026-08-29

A documentation release. No functional changes.

### Documentation

- Merged the [project website](https://n0sfs.github.io/pi-forensics/)'s separate "What's on the
  station" (feature list) and "On Screen" (screenshot gallery) sections into one - each capability
  is now shown directly beside the screenshot that illustrates it, instead of two lists a reader
  had to cross-reference themselves.
- Dropped the "01 -", "02 -" ... numeric prefixes from the feature labels.
- Curated the combined section down to 7 paired rows (one representative screenshot per
  capability) rather than the previous 10-screenshot gallery - Hex View, Metadata, and User
  Groups are no longer shown on the website specifically, though all 11 screenshots remain in
  [README.md](../README.md)'s own full gallery.

---

## [1.1.4] - 2026-08-29

A documentation release. No functional changes.

### Documentation

- Restyled the in-app **Help & Reference** tab with the same "kicker" visual language as the
  project website's own refreshed look - a small mono, uppercase, cyan-dot label above the nav,
  and the same treatment on the FAQ group headers, Tool Reference table, and Report Field Mapping
  table. Deliberately still zero external font/CDN dependency (a system monospace stack, not a
  Google-Fonts face), since this page has to read correctly on a station with no internet access.
- The rendered User Manual, Quick-Start Guide, and Release Notes pages (opened from Help) now use
  the same kicker treatment and mono-set headings, so they read as one documentation system with
  the Help tab around them instead of a plain-text page dropped into an iframe.

---

## [1.1.3] - 2026-08-29

A documentation release. No functional changes.

### Documentation

- Restyled the [project website](https://n0sfs.github.io/pi-forensics/) with a cleaner, more
  legible visual system - IBM Plex Mono/Sans, a near-black ground, and a single restrained cyan
  accent (red reserved for the Security section) - shared with the project's internal System
  Architecture reference doc, so the two read as one family instead of two differently-themed sites.
  Every existing section, screenshot, and piece of copy is unchanged; only the presentation.

---

## [1.1.2] - 2026-08-29

A documentation release. No functional changes.

### Documentation

- Refreshed the screenshots in [README.md](../README.md) and the
  [project website](https://n0sfs.github.io/pi-forensics/) against the current UI - the last set
  predated the horizontal Settings navigation (2026-08-21) and several 1.1.0 features, so a few no
  longer matched what a fresh install actually looks like.
- Corrected captions/alt text to match: Home's workspace-tile picker, the compact Acquisition card
  with the consolidated Encrypted Volume panel, File Explorer's grouped folder tree, Reporting's new
  case-wide Overview dashboard, and Settings' current Service Controls/Security panes.
- The project website's screenshot grid grew from 8 to 10 shots, adding a dedicated Acquisition card
  and grouping all three File Explorer detail shots (Hex, Metadata, Geolocation) together.

---

## [1.1.1] - 2026-08-29

A documentation release. No functional changes - upgrading isn't necessary for the running
application, but is recommended if you rely on the in-app Help, the User Manual, or the project
website to learn a feature.

### Documentation

- The [User Manual](../docs/user-manual.md) now covers everything added in 1.1.0: the consolidated
  BitLocker/LUKS/VeraCrypt Encrypted Volume panel, Auto Analyze, every new artifact parser (Registry/
  Event Log/Prefetch/Recycle Bin/LNK/Linux/crypto-wallet/mobile chat), Hash Sets/URL Lists/YARA
  rulesets, the generic SQLite viewer, mquire Linux memory forensics, and Reporting's new Overview
  dashboard, Custody Log, Evidence Timeline, Verify All Evidence, Case Bundle Export, and Cross-Case
  Search.
- The in-app Help tab (Guided Workflow, FAQ, Tool Reference) was updated to match - new FAQ entries,
  an updated Tool Reference table (now 29 tools), and refreshed guided walkthroughs for encrypted
  drives and report-writing that mention Auto Analyze.
- The [Quick-Start Guide](../docs/quickstart.md) now points toward Auto Analyze as a next step after
  a first acquisition.
- [README.md](../README.md) and the [project website](https://n0sfs.github.io/pi-forensics/) were
  updated with the same new capabilities, an updated tool count, and the corrected gunicorn thread
  count from 1.1.0's own stability fix.

---

## [1.1.0] - 2026-08-29

A large feature release - new artifact-parsing capability across Windows, Linux, and mobile
evidence, several new analysis tools, a substantially expanded case-management/reporting toolkit,
and one-click tool orchestration. Fully backward compatible - no removed features, no install
process changes, and every new case-JSON field is additive (older stations and older cases keep
working unchanged).

### New: Windows artifact parsing

- **Registry hive parsing** - recently-opened documents, typed URLs/paths, run history, USB device
  history, and installed-programs list, plus Amcache application-inventory data.
- **Windows Event Log (.evtx) parsing** - a curated set of security-relevant event types: logon
  success/failure, process creation, account creation, service installation, and audit-log-cleared
  (a classic anti-forensic indicator).
- **Prefetch and Recycle Bin parsing** - program run history/counts, and metadata for deleted files
  (original name, path, and deletion time) recovered from Recycle Bin index files.
- **LNK (shortcut) file parsing** - target path, arguments, working directory, and embedded
  timestamps from a single selected `.lnk` file.
- All of the above work both against a real extracted folder and directly inside an already-acquired
  disk image, with no extraction step required.

### New: Linux artifact parsing

- Shell history (`bash`/`zsh`/Python), `/etc/passwd` account listings, cron jobs, `auth.log`/`secure`
  authentication logs, and systemd journal (`journald`) entries.
- An experimental, clearly-labeled `wtmp`/`utmp` login-history parser, opt-in only (login-record
  binary layout varies by system, so this includes a built-in sanity check that refuses to produce
  results rather than guess wrong on an unfamiliar layout).

### New: Mobile and cryptocurrency artifacts

- **Mobile chat/app data** - SMS/iMessage, Contacts, and Call History parsed directly from an
  unencrypted iOS backup already captured by this station.
- **Cryptocurrency artifact detection** - common wallet-file names (Bitcoin Core, geth/Ethereum
  keystores, Electrum, and others), plus new Bitcoin- and Ethereum-address pattern matching in the
  Triage Scan tool.
- iOS device pairing can now be triggered directly from Mobile Forensics - useful for a device
  that's connected but hasn't shown the "Trust This Computer?" prompt yet.

### New: Auto Analyze - one-click tool orchestration

- Detects what kind of evidence you've selected (Windows disk image, Linux disk image, memory image,
  or mobile backup) and runs a curated, sensible default set of analysis tools against it in one
  background job, instead of running each tool by hand. Every detected profile can be confirmed or
  overridden before anything runs, and extra (non-default) tools can be added in.
- The Guided Workflow checklist (now living under Help & Reference) can hand off straight into Auto
  Analyze for the case's own evidence, and a new opt-in checkbox on Acquisition can chain a
  successful acquisition directly into an Auto Analyze run against the image it just produced.

### New: analysis tools

- **Generic SQLite artifact viewer** - browse the tables and rows of any `.db`/`.sqlite` file
  directly in File Explorer, read-only, no separate tool needed.
- **Hash Sets** - station-wide known-good/known-bad hash lists, checked automatically during a Hash
  Manifest run or on demand against a single file, with an optional one-click import of recent
  malware hashes from MalwareBazaar (a free personal key is required).
- **URL Lists** - station-wide known-bad URL lists, checked automatically against every URL a
  browser-artifact scan extracts, with an optional one-click import of the URLhaus recent-malicious-
  URLs feed (no account needed).
- **YARA rule scanning** - save your own YARA rulesets and run them against a single file, real
  filesystem or inside an acquired image.
- **Linux memory forensics** - analyze an x86_64 Linux memory image (captured elsewhere, e.g. via
  LiME/AVML) with a curated set of `mquire` queries, alongside the existing Windows-focused
  Volatility 3 support.

### New: case management and reporting

- **Case Dashboard** (Reporting's new Overview tab) - evidence item counts, tag counts (with Notable
  items called out), analysis activity, case notes, and case age, all at a glance.
- **Evidence Timeline** - every acquired image's filesystem timeline merged with parsed artifact
  timestamps, with a stacked density chart by source (click a bar to filter the table), anti-
  forensic-indicator highlighting, deleted-file badges, a per-evidence-item filter, and CSV export.
- **Physical Evidence Custody Log** - a dedicated, append-only record of physical evidence handoffs
  between people, distinct from the software Audit Trail and the investigative Case Notes journal.
- **Verify All Evidence** - a case-wide integrity re-check that re-hashes every completed
  acquisition's own output and compares it against the hash recorded at acquisition time.
- **Case Bundle Export** - zip an entire case folder (optionally including the raw acquisition
  images) for archival or handoff to another examiner.
- **Cross-Case Search** - check whether a specific hash has shown up in any other case on this
  station.
- Case Manager gained a search box and a status filter (defaults to hiding Archived cases).

### New: encrypted volumes

- **VeraCrypt support** added alongside the existing BitLocker and LUKS support, all three now
  reachable through one consolidated "Encrypted Volume" interface instead of separate per-type
  controls.

### Changed

- Reporting's "Files" tab renamed "Files & Artifacts" to better reflect its scope (attached
  exhibits, discovered case files, generated reports/logs, and parsed artifact records all in one
  place).
- "Hash Lists" renamed "Hash Sets" throughout, matching standard forensic terminology.
- The Guided Workflow checklist moved from the Home tab into Help & Reference.
- Settings' Case & Reporting and Service Controls & Diagnostics sections were condensed for less
  scrolling.
- The Forensic Acquisition tab's Format dropdown now includes Logical Acquisition directly, and the
  Preview-drive button sits next to the drive-scan button instead of its own row.

### Fixed

- A background analysis job's result (Hash Manifest, Triage Scan, and similar) could silently fail
  to record itself against the case if it ran outside a normal request - it's recorded correctly now.
- Fixed the drive write-blocker's status check bypassing its own "another job is running" guard
  during a Stop request.
- Fixed a data-loss bug where renaming a custom case field could silently orphan that field's
  already-saved value on existing cases.
- Fixed several display bugs: Amcache/Prefetch/Recycle Bin records showing raw internal keys instead
  of readable labels in File Views, an in-image Linux artifact showing a meaningless temporary
  filename instead of its real one, and a low-contrast button in the Report Template Builder.
- Fixed the File Explorer right-click menu not closing (and logging a harmless-but-noisy console
  error) when dismissed with the Escape key.
- Bumped gunicorn's thread count to improve responsiveness under load from a large acquisition or
  analysis job running alongside normal browsing.

### Security

- Hardened KML (geolocation) file parsing against malicious XML entity attacks.
- Closed a brief window where a newly-created secret/key file could exist with overly permissive
  file permissions.

---

## [1.0.1] - 2026-08-23

A security-hardening and documentation release. No new features - upgrading is recommended for every
station, especially any station reachable outside a fully trusted physical network.

### Security

- Fixed a way the physical-kiosk login bypass could be spoofed by a remote client under certain
  network configurations, potentially skipping login entirely.
- Updated the Sleuth Kit library to a version that fixes a denial-of-service vulnerability
  triggerable by a malicious ISO9660 filesystem inside an acquired image.
- Fixed the login lockout so failed attempts from one remote client can no longer lock out every
  other client sharing the same network path (e.g. behind the same router or reverse proxy).
- Closed a gap where two File Explorer actions (text/HTML preview, raw hex view) had no permission
  check, letting any authenticated account use them regardless of their assigned group.
- Case-folder path handling is now sandboxed the same way as every other evidence path in the app,
  closing a narrow path-traversal gap.
- Examiner-defined custom keyword/regex scan lists are now checked for catastrophic-backtracking
  patterns before being accepted, so a malformed pattern can no longer be used to hang the scanning
  engine.
- Live Device Preview access grants are now reconciled automatically if the app restarts mid-session,
  so an interrupted preview can't leave a live drive's read-access grant open indefinitely.
- Network-share mount fields (host, share path, username) are now validated to reject values that
  could be misinterpreted as command-line flags by the underlying mount tools.
- Tightened permissions on case creation/migration and the MVT spyware-indicator update action;
  bumped the bundled `gunicorn` dependency past a known vulnerability.

### Fixed

- PDF preview inside an acquired (e.g. BitLocker-decrypted) image showed garbled bytes instead of the
  actual PDF.

### Documentation

- Added a Quick-Start Guide and a full User Manual (`docs/`), covering every tab and every tool -
  including several that had never been documented anywhere before.
- Updated the in-app Help (guided walkthroughs, FAQ, tool reference) to match - encrypted-volume
  support, Live Device Preview, Logical Acquisition, image format conversion, memory forensics, and
  browser-artifact parsing are now all covered there too.
- The Quick-Start Guide, User Manual, and this changelog are now readable directly inside the app
  (linked from Help and from Settings > Service Controls & Diagnostics) - no separate GitHub access
  or internet connection needed to read them on an already-installed station.

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
