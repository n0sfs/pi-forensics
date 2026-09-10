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

## [1.89.0] - 2026-09-10

### Added
- Case status now has a sixth value, **In Progress**, between Open and In Review - Open means a
  case has been created but not yet actively worked, In Progress means an examiner is actively
  working it, and In Review means it's been handed off to another examiner or a supervisor to
  check. Shows up everywhere a case's status already did: the Status dropdown in Reporting's
  header, the Case Manager's status filter, the Total Cases stat's breakdown, and colored badges
  throughout.
- **Examiners are now added to a case automatically** the moment someone does real work on it - adds
  a note, logs a custody transfer, tags an item, or attaches/captions an exhibit - without a manual
  "+ Add" click. The examiner set at case creation is still recorded separately and never changes;
  this only adds to the case's own growing Examiners list, and only for a real logged-in account
  (never the physical-kiosk shared identity).

### Changed
- Case Status and Examiners moved directly into Reporting's persistent header, right next to the
  case number - visible and editable from any Reporting sub-tab, not just Report Narrative, and
  laid out as a single compact row instead of two stacked cards.

## [1.88.1] - 2026-09-10

### Changed
- The Case #/Examiner display used to appear twice at the top of the screen - once in the
  persistent case bar, and again (redundantly) in Reporting's own "Case Report" header. The case
  bar version is gone; the header version now shows the case's full, real list of examiners
  (not just the one name recorded when the case was created) and doubles as a shortcut into
  Report Narrative, where both are actually edited. The Total Cases stat row (and whichever other
  station-wide stats you've enabled in Settings) moved up into the same row as the case bar,
  right-aligned, instead of its own separate row underneath it.

## [1.88.0] - 2026-09-10

### Added
- The exported report's Evidence Inventory table now shows each evidence item's hash-verification
  status ("Hash Verified", "HASH MISMATCH", "File Missing", "Unverifiable", "Not Yet Re-Verified",
  "No Hash Recorded"), right alongside its acquisition hash. Previously this information only ever
  showed up in the raw JSON export or the on-screen Overview dashboard - it now appears directly in
  the PDF and HTML report, for every report format that already includes this table (Standard,
  Police, and CASE/UCO templates). Run "Verify All Evidence" from the Reporting > Overview tab first
  if you want an up-to-date status shown; a case that's never had it run shows a plain "Not Checked".

## [1.87.7] - 2026-09-10

### Changed
- Reorganized Reporting's Overview tab. "Case-wide Integrity Check" (the "Verify All Evidence"
  button) previously sat in its own differently-styled box below the 8 dashboard tiles - it's now
  a matching 9th tile, completing the grid to a clean 3x3 with no visual gap. "Case Bundle Export"
  (the full case-folder zip) moved to its own clearly-labeled section on the Export tab, next to
  the report-export preview it's a genuinely different kind of export from - it no longer clutters
  Overview at all. No functionality changed for either action, only where they live on screen.

## [1.87.6] - 2026-09-10

### Fixed
- A case's Examiners list (Reporting > Report Narrative) accepted any typed name with no check
  against this station's own registered user accounts - an examiner-of-record is a chain-of-
  custody-adjacent fact and should correspond to a real, accountable account, not an arbitrary
  string. Adding an examiner is now a select-only picker restricted to this station's actual user
  accounts, not a free-text field. A station with no user accounts configured at all (the legacy
  single-shared-login mode) still falls back to typing a name, since there's no real account list
  to check against in that case. Any name already recorded before this fix (or typed during that
  fallback) is left exactly as it was - only *adding* a new name is now restricted - but a name
  that doesn't match a real account is now flagged with a warning icon so it's not mistaken for one.

## [1.87.5] - 2026-09-10

### Fixed
- The same middle-of-the-screen tooltip bug fixed for Quick Search in the previous release could
  also happen on any right-click context menu item in File Explorer whose menu had a short label
  sitting next to a longer one (for example "Tag..." next to "Attach to Case" or "Browse as Image
  (Sleuth Kit)") - the short item's own clickable box stretched to match the menu's full width, so
  its hover tooltip could land away from the actual text. Every context-menu tooltip now hugs its
  own icon and label instead, without changing the button's own click target size.
- The green "already run" checkmark that appears next to a context-menu action after it's been
  used on a file never actually showed a tooltip on hover, even though it looked like it should -
  it was missing the one line of code that turns a hover-help attribute into a working tooltip.
  Hovering it now correctly shows which tool ran and when.

## [1.87.4] - 2026-09-10

### Fixed
- The Quick Search info tooltip (Reporting > Overview) could pop up in the middle of the screen
  instead of next to the label. Its trigger was a full-width block element, so Popper centered the
  tooltip on that whole invisible row rather than the actual "Quick Search" text - it now hugs its
  own content, and the tooltip lands right next to it as expected.

## [1.87.3] - 2026-09-10

### Fixed
- Reporting's Overview dashboard could send two different tiles to the same tab - "Evidence Items"
  and "Analysis Activity" both jumped to Evidence Activity, and "Tagged Items" and "Exhibits
  Attached" both jumped to Files & Artifacts. Every tab is now linked from exactly one place: the
  two duplicate pairs are merged into a single two-stat tile each (same numbers, same click target,
  one card instead of two). Every button on the dashboard was re-checked against its real target tab.

## [1.87.2] - 2026-09-10

### Changed
- **Reporting's Overview tab is a bit tidier.** "Case-wide Integrity Check" and "Case Bundle Export"
  are now two side-by-side cards instead of two long always-expanded sections, each with its
  explanation moved to a hover/click info icon on the heading (same pattern as Quick Search's own
  icon). The "Ready to generate a report?" text link is gone too - there's now a proper clickable
  Export Report card in the dashboard grid above, alongside the other case-summary tiles.
- Fixed a real visual leftover from the last release: the empty Quick Search results box showed as a
  bare bordered strip with nothing in it once its placeholder text was removed. It's hidden now until
  there's actually something to show in it.

## [1.87.1] - 2026-09-10

### Changed
- **Reporting's Case Report tab is a little less cluttered.** The paragraph explaining what Quick
  Search covers is now an info icon next to the "Quick Search" label - hover or click it (or the
  label itself) to see the same explanation as a tooltip instead of it always taking up a line. The
  "Type a keyword above to search" placeholder under the search box is gone too - it now just stays
  blank until you type something.
- **The Total Cases stat row moved out of the Reporting tab.** It was already station-wide (visible
  with no case selected), so it now lives in its own row right below the top header, visible from
  every tab instead of only when you're on Reporting.

## [1.87.0] - 2026-09-10

### Changed
- **Exhibit captions now save the instant you type them, from either place you'd edit one.** A
  caption used to live only in Reporting > Files & Artifacts, and only actually persisted once you
  clicked "Save Report Changes" - a real trap if you navigated away first. File Explorer's own
  Tag/Attach modal now has its own caption field too (enabled once the file is an attached exhibit -
  attach it right there with one click if it isn't yet), and both it and the Files & Artifacts field
  save immediately, the same way tagging already does.

## [1.86.0] - 2026-09-09

### Added
- **Physical Custody Log entries can now say which exhibit(s) actually changed hands.** A
  custody-transfer entry (from custodian / to custodian / reason / method) previously had no way to
  reference the specific evidence involved - just who handed it to whom. Logging a transfer now
  shows a checklist of the case's attached exhibits and any tagged-but-not-yet-attached items, and
  the entry displays "Linked: Exhibit N - filename" (or "tagged, not attached" for something flagged
  but not formally attached yet). Both the PDF and HTML exported report show the same linkage under
  each custody entry.

## [1.85.0] - 2026-09-09

### Added
- **Multiple Examiner Names per Case.** A case used to record exactly one examiner, set once at
  creation and never editable again. Reporting > Report Narrative now has an "Examiners" list -
  the case's original examiner of record is pre-added, and you can add or remove additional
  examiners as more than one analyst works the case. Shown wherever a case's examiner already
  appeared - the Case Manager list, and both the PDF and HTML exported report - as every name
  joined together. Existing cases with just the one original examiner are completely unaffected.

## [1.84.0] - 2026-09-09

### Changed
- **Reporting condensed from 13 tabs down to 9.** Case Notes and Physical Custody Log now share one
  tab; Jobs, Analysis Coverage, and Case Activity Log are now one "Evidence Activity" tab (all three
  are "what's been done to this evidence" at different levels of detail); Search moved directly onto
  Overview instead of its own tab. Export stays its own tab (too much to fit on a dashboard), but
  Overview now has a quick link straight to it.
- **Overview's stat tiles are clickable.** Click "Tagged Items" and jump straight to Files &
  Artifacts; click "Case Notes" and jump to Case Notes & Custody Log; every tile now goes somewhere.

## [1.83.0] - 2026-09-09

### Added
- **Follow-up/task flag on Case Notes.** Every note now has a Status (Open/Resolved) and an
  optional "Assigned to" name, both changeable with a click right on the note - no need to edit the
  note's own text to hand something off to a colleague or mark it done. Neither field touches the
  note's own edit history; they're metadata about the note, not corrections to it.

## [1.82.0] - 2026-09-09

### Added
- **Inline tag/severity indicators in File Explorer.** A tagged file's real-file listing row now shows
  a small notable-star and/or severity badge (High/Critical/etc.) right next to its name, with a
  tooltip listing every applied tag and comment - no need to open the Tag panel or switch to File
  Views just to notice something was already flagged during an earlier pass.

## [1.81.0] - 2026-09-09

### Added
- **Unified case search.** Reporting's Search tab now also searches parsed evidence (browser history,
  registry entries, event logs, and every other indexed record type), tagged items, and known contacts
  for the active case, alongside the existing Report Narrative/Files & Artifacts/Jobs/Case Notes/Case
  Activity Log results - one search box, in one place, instead of checking File Explorer's own File
  Views tree, the Tag list, and Contact Correlation separately. Click any result to jump straight to
  the tab it lives in.

## [1.80.0] - 2026-09-09

### Added
- **Multi-select batch actions in File Explorer.** Every real-folder file listing (not disk-image
  browsing) now shows a checkbox per row plus a "select all" checkbox in the column header. Selecting
  one or more files shows a small toolbar above the listing with three batch actions:
  - **Attach to Case** - attaches every selected file to the active case as an exhibit in one click,
    instead of one file at a time.
  - **Tag...** - applies one existing tag (or a brand-new one you create right there, with its own
    color/notable flag/severity) to every selected file at once, with an optional shared comment.
  - **Check Hash Sets...** - hashes every selected file and checks each one against your saved hash
    sets, showing a clear per-file Clean/Match result table.
  The selection is cleared automatically whenever you navigate to a different folder, and stays intact
  across a batch action so you can, for example, tag a set of files and then immediately attach the
  same set as exhibits.

## [1.79.1] - 2026-09-09

### Fixed
- **A real, serious bug: two analysts editing the same case at once could have one silently overwrite
  the other's changes.** Saving Report Narrative, Case Status, Custom Case Fields, or the attached-
  files list sent the entire cached report from whenever that browser tab last loaded the case, with
  no check against what's on disk now - a second analyst's concurrent save (or even a later action
  from a DIFFERENT tab) could be silently reverted the next time the first tab's own stale copy was
  saved, with zero warning. Now rejected outright with a clear message ("this case was edited
  elsewhere - reload to see the latest version") instead of silently overwriting - matches how this
  app already handles the identical class of problem elsewhere (case-folder name collisions, etc.).
  Case Notes, tags, the Physical Custody Log, and attaching a file were never affected by this - only
  the "Save Report Changes" round trip was.

### Changed
- **Clearer naming for two easily-confused features.** "Cross-Case Search" (Settings > Case &
  Reporting) is renamed "Cross-Case Hash Lookup" - it only ever checks an exact hash against every
  other case, not a general search, and the old name overpromised. "Audit Log" (Settings > Security)
  and "Audit Trail" (Reporting) were the exact same underlying log - filtered vs. unfiltered - with
  near-identical names that didn't say so; renamed to "Station Audit Log" (the full, station-wide
  version in Settings) and "Case Activity Log" (the same log, filtered to one case, in Reporting).

## [1.79.0] - 2026-09-09

### Added
- **A "Case Highlights" summary at the top of Pattern of Life** - a few plain-English badges (most-
  contacted person, likely home location, busiest time of day) computed automatically from whatever
  the pane's own sections have already loaded, so there's something worth noticing at a glance
  before scrolling into the detailed sections below. Fills in progressively as each section's data
  becomes available; shows a "not enough data yet" note if nothing has been parsed for this case yet.

### Fixed
- **The standalone Geolocation report tab only ever checked for KML files, so a case with real
  Google Takeout location-history data (already shown correctly on Pattern of Life) misleadingly
  reported "no geolocation data found" if it had no KML file attached.** Now pulls from the same
  merged data source Pattern of Life's own map already uses - every already-indexed Takeout point
  plus every KML file, grouped and labeled by source.

### Changed
- **Pattern of Life moved to the 2nd tab in Reporting**, right after Overview (previously 7th of 11,
  well past Report Narrative/Case Notes/Physical Custody Log/Files & Artifacts) - it's one of the
  most useful "quick look, find something of value" views in the app and was buried behind several
  editing-focused tabs a first-time reviewer of a case is less likely to need immediately.

## [1.78.0] - 2026-09-09

### Added
- **A new "Cases Needing Migration" option for Reporting's customizable header stats** (Settings >
  Case & Reporting > Reporting Header Stats), alongside the existing Total Cases/Active Cases/
  Evidence Items/Reports Exported/Tags Flagged options - counts how many cases on the station are
  still on the older, pre-2026-08-13 per-job report layout and haven't yet been migrated to the
  current consolidated one-file-per-case format. Off by default, matching how every other optional
  header stat already behaves.

### Fixed
- **Two USB drives could, in a narrow timing window, both end up mounted as an F2FS filesystem at the
  same folder in File Explorer** - a real but low-severity race in the F2FS browse-mount feature that
  needed two nearly-simultaneous requests for the exact same drive/destination to trigger (a
  double-click, or two browser tabs open to the same action). Never a data-integrity risk (both
  mounts always showed identical, correct, read-only content), but could leave one mount silently
  still attached after unmounting the other. Found during a systematic internal review, not reported
  by a user.

## [1.77.4] - 2026-09-09

### Fixed
- **An MTP fallback pull (Mobile Forensics > Android Device > MTP File Transfer) could leave the
  station's shared acquisition/recovery/mobile job slot stuck as "busy" forever**, blocking every
  other job on the station - a new acquisition, a recovery run, another mobile pull, anything - until
  the app itself was restarted. This affected every MTP pull regardless of whether it succeeded,
  failed, or was stopped early; the standard `adb pull`/Backup/Bugreport modes were never affected.
  Found during a systematic internal review, not reported by a user - fixed and confirmed against the
  station's real running code.

## [1.77.3] - 2026-09-09

### Fixed
- **A Case Bundle export stopped partway through could still report "100% complete" and the full
  expected size**, even though the resulting zip file only actually contains whatever was added before
  the stop. The progress bar and byte count now correctly reflect the real, partial amount whenever a
  bundle export is stopped early.

## [1.77.2] - 2026-09-09

### Fixed
- **Creating a case with the exact same case number/parent location at the exact same time (two
  browser tabs, two examiners) could return a confusing generic error instead of the normal "already
  exists" message.** No data was ever at risk from this - it was purely a wrong error message in a
  rare timing scenario, now reported the same clean way a non-racing duplicate already is.
- **The Export screen's "checklist mismatch" warning only ever caught one direction.** Checking the
  "Exhibits" section while leaving every individual file/URL unchecked already warned that the section
  would be missing - now the reverse (files/URLs checked, but "Exhibits" itself unchecked) is caught
  too, so an export that would otherwise silently show an empty Exhibits section gets a heads-up
  before it's generated.

### Changed
- **Re-opening an archived case now restores whatever status it actually had before being archived**
  (e.g. "In Review" or "Closed"), instead of always resetting it to "Open." The Case Manager's confirm
  dialog now says exactly which status will be restored. A case archived before this change, or
  archived by directly editing its file, falls back to "Open" as before.

## [1.77.1] - 2026-09-09

### Fixed
- **Report Narrative and Files & Artifacts edits could be silently discarded by an unrelated action.**
  Adding a Case Note, logging a Custody entry, attaching a file, or even a background job (like
  Verify All Evidence) finishing on its own, refreshed Reporting's whole screen from the server -
  which used to overwrite every Report Narrative field, Case Status, custom fields, and the Files &
  Artifacts checklist with whatever was last saved, silently throwing away anything typed but not yet
  saved. These background-triggered refreshes now only ever touch their own read-only views (Case
  Notes, Custody Log, Jobs, the Dashboard) - typed-but-unsaved narrative or attachment changes are
  preserved, with a brief notice confirming what happened, and the "Unsaved changes" indicator stays
  correctly shown until it's actually saved.
- **The exported report's Pattern of Life section could show an empty Frequent Locations table for a
  legacy (not-yet-migrated) or ad-hoc report even when a location file was genuinely attached.** The
  export was independently re-reading the case's attachment list from disk instead of using the same
  data the rest of that export already had loaded, and that re-read only ever worked for a fully
  migrated case - a legacy report's real attachments were silently treated as empty. Fixed to reuse
  the export's own already-loaded attachment list, which also closes a narrow window where that
  second disk read could have disagreed with the rest of the same export.

## [1.77.0] - 2026-09-09

### Added
- **Six case-workflow improvements, from a review of the path between "something significant is
  found" and "it shows up correctly in the final report".**
  - **Tag-to-exhibit bridge.** A file tagged while browsing inside an acquired disk image (Sleuth
    Kit) previously lost that tag entirely if it was later extracted out onto the real filesystem -
    the tag stayed attached to the now-inaccessible in-image identity. Extracting a tagged file now
    automatically carries its tags (and any comment) over to the extracted copy.
  - **Export mismatch warning.** The Export Report screen's checklist (which sections/fields to
    include) and its file-attachment checklist are two separate controls - checking "Exhibits" as a
    section while leaving every individual attachment unchecked (or vice versa) previously produced a
    silently empty or silently missing Exhibits section with no warning. A clear on-screen notice now
    appears whenever the two are inconsistent, before the export is generated.
  - **Coverage-gap quick-fill.** The Reporting > Coverage tab already shows which analysis steps have
    and haven't been run against each piece of evidence. A new "Insert Outstanding Analysis into
    Limitations" button drafts a dated summary of exactly what hasn't been run yet, straight into the
    report's Limitations section, instead of requiring it to be retyped by hand.
  - **Case Notes can now reference a tagged-but-not-yet-attached file.** Previously a Case Note could
    only link to a file already formally attached as a case exhibit - a file that had been tagged for
    attention but not yet attached had no way to be referenced from a note at all. The note-linking
    picker now offers both, clearly labeled, and a note's own displayed link no longer silently
    disappears if the linked file isn't a numbered exhibit.
  - **Richer exported Timeline.** The exported report's own Filesystem Timeline section (a niche,
    opt-in section reachable through a custom report template) previously only ever showed raw
    filesystem MACB events, unlike the interactive Evidence Timeline tab, which had since been
    enriched with parsed-artifact records, resolved contact names, and suspicious-activity flags.
    The export now uses the exact same enriched data. A new, separate, off-by-default station setting
    (Settings > Case & Reporting > Report Export Defaults) additionally controls whether a
    communication's own actual recovered text is embedded in the exported timeline, or just the
    structural facts (who/when/what) - a real message/note leaving the station in a portable file is
    treated as a deliberate, opt-in decision, not a default.
  - **Export Contact Correlation and frequent locations.** The Pattern of Life tab's Contact
    Correlation (who a device communicated with, how often, and who those people were seen
    communicating with each other) and Location Activity (frequently-visited places) previously had no
    export path at all - reachable only on-screen. A new, opt-in "Pattern of Life" report section
    (also reachable through a custom report template) now includes both as tables in the exported PDF/
    HTML report, reusing the exact same data the on-screen tabs already show.

## [1.76.1] - 2026-09-09

### Fixed
- **Reporting: 4 real bugs found during a review pass, all fixed.** Pattern of Life's Location
  Activity map could silently drop location points past its own display cap without ever flagging
  that it had done so, if a case's Google Takeout location history alone exceeded the cap - fixed so
  the "list truncated" notice always fires when it should. The Total Cases stat's status breakdown
  never actually distinguished a not-yet-migrated (legacy) case from a normal "Open" one, despite the
  code clearly intending to - fixed so a legacy case now shows up correctly as its own bucket.
  "Save Report Changes" never updated the case's own last-modified timestamp on save, unlike every
  other case-editing action in the app - fixed to match. Migrating an older case to the newer report
  format didn't preserve that case's existing status (Closed/Archived, etc.) or seed any station-wide
  custom case fields, unlike creating a brand-new case - fixed to match.

## [1.76.0] - 2026-09-09

### Added
- **macOS APFS disk-image browsing.** File Explorer's "Browse as Image" flow could never open an
  APFS-formatted image before this - APFS is the only filesystem virtually every Mac sold since
  ~2017-2018 uses, and the underlying Sleuth Kit library this app has always relied on has never had
  the extension needed to open one at all. A new library closes that gap: an APFS image now opens,
  browses, extracts, and hashes exactly like any other image already supported, with zero change to
  any of File Explorer's existing tools. A container holding multiple logical volumes (a real Mac
  disk commonly has several - Data, Preboot, Recovery, VM) auto-selects the largest one to browse,
  since that's reliably the actual user-data volume in practice; switching to a different volume in
  the same container isn't supported yet. FileVault-encrypted APFS volumes and deleted-file recovery
  are both explicitly out of scope for this pass - see the internal engineering log for why.
  **Not yet tested against a genuine Mac-formatted drive or image** (no such test file could be
  constructed without real Apple hardware/tooling) - every underlying mechanism was independently
  confirmed against the real library, matching how this project already shipped similarly-unverified
  support for a few other formats (Windows Prefetch, SRUM) before real samples became available.

## [1.75.0] - 2026-09-09

### Added
- **Archive/Re-open button for cases.** Previously, marking a case Archived meant opening Reporting
  for that exact case, finding Report Narrative > Case Details, changing the Status dropdown, and
  clicking "Save Report Changes" - real friction just to hide an old case from the default list. The
  Case Manager's own case list now has a one-click Archive button on every row (and a matching
  Re-open button once a case is archived), writing directly to that case's own status with no need
  to load the full report first. Nothing is ever deleted - an archived case is only hidden from the
  default "Active" filter, and switching the filter to "Archived" finds it again any time.

## [1.74.0] - 2026-09-09

### Added
- **Case-wide analysis-coverage dashboard.** A new "Coverage" tab in Reporting answers "what's been
  run against each evidence item, what hasn't" for the whole case at a glance - previously the only
  way to check was File Explorer's own right-click "already run" checkmark, one file at a time. For
  every completed evidence item, it shows a hash-verification status badge, which Auto Analyze steps
  have actually completed successfully (green), and which haven't been tried yet (gray "Not yet run")
  - plus a tag count. Purely read-only against real, already-recorded data (no new tool runs), and
  built from the exact audit record Auto Analyze already writes on every completed run, so it can
  never drift out of sync with what actually happened. The last of the 6-item backlog from this
  project's own recent DFIR-tool comparison research (Belkasoft's Dashboard+Tasks-window pair was the
  strongest real precedent found across every competitor tool researched).

## [1.73.0] - 2026-09-08

### Added
- **Severity / priority field on tags.** Every tag (Bookmark, Notable Item, or a custom tag) can now
  carry a severity - None, Low, Medium, High, or Critical - set once on the tag itself rather than
  re-picked every time it's applied to a file. A colored badge shows the severity everywhere a tag
  already appears: Settings > Case & Reporting > Manage Tags, File Explorer's "Tag..." action (both
  the existing-tag list and the quick "+ Create New Tag" form), the File Views tree (a `[HIGH]`/
  `[CRITICAL]` prefix on high-severity tag categories, next to the existing notable star), and
  Reporting's Files & Artifacts exhibit list. Existing tags on every case (including ones created
  before this update) automatically migrate to "None" with zero data loss - confirmed live against a
  real, previously-populated case index. A genuine differentiator over comparable commercial DFIR
  tools, which were confirmed via research to lack a real structured severity field on evidence tags
  (only simple color labels).

## [1.72.0] - 2026-09-08

### Added
- **Date-range filter for Location Activity.** Pattern of Life's "Location Activity" map/table can
  now be narrowed to a specific window - a single day, a few days, a week, a month, or any custom
  range - using new From/To date fields, exactly like the existing Communication Activity Pattern
  chart's own filter. This recomputes which locations count as "frequent" for just that window (no
  re-fetch needed), so you can answer "where was this device active during this specific day or
  range" instead of only ever seeing the case's full history at once. A KML-sourced point has no
  timestamp and can only ever appear under the default "All Time" view - narrowing to a specific
  range only shows timestamped points, and the summary line says so.

### Fixed
- **The travel-path line was effectively invisible.** "Show travel path (time-ordered)" drew a real
  line, but at the same pale blue as the individual location markers and a low opacity, it was
  routinely lost against a busy map (real roads, water, highway shields in similar colors). The line
  is now a bright, saturated magenta at a heavier weight, with a green "path start" marker and a
  matching magenta "path end" marker so the direction of travel is clear at a glance, not just
  implied by a barely-visible line.

---

## [1.71.0] - 2026-09-08

### Added
- **Manual contact merge, with a required justification note.** The Relationship Graph and Contact
  Correlation table already flagged two entries sharing an exact name as "possible duplicates" -
  now that flag can actually be acted on. A warning icon next to a flagged contact's name opens a
  "Manage Identity" dialog listing every possible duplicate; merging one into another requires typing
  a short note explaining why (an examiner decision, never automatic just because two names match -
  a phone-only entry and an email-only entry sharing a common name are never silently assumed to be
  the same person). The merged record shows who merged it, when, and the note itself, and can be
  undone at any time from the same dialog. This mirrors Autopsy's own "Personas" approach to the same
  problem.
- **Jump from a Relationship Graph contact straight to their Evidence Timeline.** Clicking a contact
  node in the graph now opens a small menu with "View in Table" (jumps to the same person's row in
  Table View) and "View in Evidence Timeline" (switches tabs and filters the timeline down to just
  that person's activity) - the graph, the table, and the timeline were three separate views before;
  now any of them leads directly to the others for the same person.
- **Whole-image YARA rule sweep.** YARA scanning previously only worked one file at a time. A new
  "YARA Rule Sweep" action (File Explorer's image toolbar, right next to Hash Manifest) scans every
  file in an acquired image against your configured rule sets in one pass, records each match in the
  case's analysis history, and writes a plain-text report - closing the same gap Hash Manifest already
  closed for hashing.
- **Auto Analyze now includes malware/keyword screening by default.** Running "Auto Analyze" on a
  Windows or Linux disk image now automatically runs a whole-image YARA sweep (using every rule set
  you've configured) and a structured-data keyword scan (emails, URLs, IPs, card numbers, phone
  numbers) as part of its default step sequence - previously, Auto Analyze covered artifacts and
  hashing, but an examiner had to remember to separately run YARA/keyword screening if they wanted it.

### Changed
- **Relationship Graph reorganized and polished.** The search box, minimum-communications slider, and
  legend moved into a dedicated left-hand sidebar (previously stacked above/below the graph itself),
  freeing up more room for the graph. The legend now lists each tier as a proper row with a colored
  marker instead of wrapping inline text. Fixed the "This Device" star's own label rendering in dark,
  illegible text against the dark background - it's now light and outlined for contrast against any
  node color. Stress-tested against a 25-contact case to confirm the layout, colors, and labels all
  stay legible at a realistic larger scale, not just a handful of test contacts.

---

## [1.70.0] - 2026-09-08

### Added
- **Unresolved Leads in Contact Correlation.** Previously, a communication (a text, call, email, or
  WhatsApp message) with no matching saved contact only ever showed up as a bare "N unresolved" count
  - the actual number, who it was with, and when, were invisible. A new "Unresolved Leads" section
  lists up to 50 of these directly - counterpart, channel, direction, timestamp, and a content preview
  where available - specifically so an unrecognized number or address that keeps recurring (e.g. a
  burner phone with no saved contact) is something you can actually see and investigate, not just a
  number in a summary line. Each lead also gets its own "Nearby Locations" button, using the same
  time-proximity location cross-linking Contact Correlation's known contacts already have.

### Fixed
- **Nearby Locations/Nearby Contacts no longer lists near-duplicate rows for repeated GPS pings at the
  same spot.** A modern phone can log several location fixes within minutes of each other at the same
  place (e.g. GPS refreshing every few minutes while stationary) - previously, each individual ping
  showed up as its own separate row, cluttering the list and risking crowding out genuinely distinct
  nearby locations under the existing per-row display cap. Pings at the same clustered location are
  now grouped into one row showing how many fixes were recorded there and the time range they span.
- **The Case Overview dashboard no longer briefly shows the previous case's tag/analysis counts when
  switching cases.** Switching to a new case while the dashboard's summary data was still loading could
  momentarily display the old case's numbers before the real ones arrived. The relevant fields now
  reset to a loading state immediately on switch, before the new data is fetched.

## [1.69.0] - 2026-09-09

### Added
- **A 2D hour-of-day x day-of-week heatmap for Communication Activity Pattern.** The existing "By
  Hour of Day" and "By Day of Week" bar charts each show one dimension at a time - a new "Heatmap"
  view shows both together, revealing a pattern neither view alone can (e.g. "active every Tuesday
  night," not just "active at night in general"). Tap a cell for the same drill-down detail the bar
  charts already offer.
- **A communication-volume threshold slider on the Relationship Graph.** "Min. communications" lets
  you declutter the graph down to just the people this device talked to the most, hiding low-volume
  contacts on demand (default: show everyone). Doesn't remove anyone from Table View or anywhere else
  - it only changes what this one graph displays.

## [1.68.0] - 2026-09-09

### Added
- **Pattern of Life: Location Activity and Contact Correlation are now cross-linked.** A new "Nearby
  Locations" button on each Contact Correlation row shows every GPS/location point recorded within 2
  hours of a real communication with that contact - and, the other direction, a new "Nearby Contacts"
  button on each Frequent Location row shows every contact you communicated with within 2 hours of a
  visit there. Both are explicitly disclosed as time-proximity matches only, never a confirmed link -
  useful for spotting a plausible "were they together" moment worth a closer look, not asserted as
  fact.
- **A travel-path line on the Location Activity map.** A new "Show travel path (time-ordered)"
  checkbox draws a line connecting every timestamped location point in chronological order - a rough
  visual sense of where the device moved over time, not a real routed path (it's a straight line
  between fixes, not a road-following route).

## [1.67.0] - 2026-09-08

### Added
- **Contact Correlation, the Relationship Graph, and Device Profile now include ALEAPP/iLEAPP-sourced
  data.** Previously, correlation only ever read directly-parsed Android/iOS contacts, SMS/MMS, call
  logs, and WhatsApp data - it never read anything ALEAPP or iLEAPP itself extracted, which is the tool
  this app runs for a non-rooted Android pull or any iOS extraction (the most common real-world
  acquisition scenarios). Contacts, SMS, MMS, call logs, and WhatsApp messages/contacts/call logs from
  a real ALEAPP/iLEAPP scan now correlate correctly - resolved against each other's real, confirmed
  column names (more than one ALEAPP module can report the same kind of data under a different column
  name; both are now recognized) - and show up on the Relationship Graph and Contact Correlation table
  exactly like directly-parsed data does. Device Profile's Apps & Accounts lists now also merge in
  ALEAPP's own installed-app and configured-account findings (tagged "ALEAPP" so the source is clear).

### Fixed
- **Auto Analyze's Hash Manifest step never actually checked Hash Sets.** The manual "Hash Manifest"
  action in File Explorer already cross-referenced every hash it computed against your configured
  Hash Sets - the same step run automatically as part of Auto Analyze silently never did, always
  reporting zero matches regardless of what was actually configured. Auto Analyze's Hash Manifest step
  now checks every currently-configured SHA-256 hash set automatically, the same as running it manually.
- **Evidence Timeline never showed the message/email preview text it already had.** A recovered
  message/email body was already being computed for each timeline row but never displayed. Each row
  with recoverable content now has a small preview button; the text is also included in CSV exports.

---

## [1.66.0] - 2026-09-08

### Added
- **"Likely Home"/"Likely Work" labels on Pattern of Life's Location Activity map and table.**
  Frequent locations are now automatically checked against a standard pattern-of-life technique:
  the place most-visited overnight is likely Home, the place most-visited during weekday working
  hours is likely Work. Shown only when the signal is clear from real timestamped location data
  (never guessed from a KML point, which has no timestamp, and never asserted when there's a tie
  or too little data) - with the exact reasoning ("8 of 10 timestamped visits (80%) occurred
  between 10pm-6am") always disclosed in a tooltip, not just asserted as fact.
- **The Relationship Graph can now show people who were seen together, not just who talked to the
  device owner.** A group text, a shared calendar invite, or a multi-recipient email thread naming
  two known contacts on the same message now draws a distinct dashed connector directly between
  those two people - a real, disclosed "seen together" signal (never a confirmed relationship
  claim) that a pure hub-and-spoke graph couldn't show before.
- **A search box on the Relationship Graph** to quickly find one contact among many - matching
  names/numbers/emails stay fully visible while everything else dims, without losing the overall
  layout.



### Added
- **A Settings toggle to turn the physical touchscreen's kiosk display on or off, without a reboot.**
  Settings > Service Controls & Diagnostics gained a "Touchscreen Kiosk Mode" switch, next to the
  existing "Reload Touch Kiosk" button. Turning it off closes the on-screen browser immediately -
  freeing the RAM/CPU it was using on the board - while this station's own web UI stays fully
  reachable over the network either way. Turning it back on relaunches the touchscreen automatically
  within a few seconds. Useful for a station that's mostly administered remotely, or whenever the
  local display isn't needed and the extra RAM/CPU headroom is worth having back.
- **Click a bar on the Communication Activity Pattern chart to see exactly what it's made of.**
  Clicking any bar now shows a small popup listing the individual events in that time bucket -
  message/call type, resolved contact name where known, and a short detail line - instead of only
  ever seeing the bar's own total count.
- **A date range filter for the Communication Activity Pattern chart.** For a case spanning months
  or years of activity, the chart can now be narrowed to a specific window (e.g. "just this week" or
  "just last spring") entirely client-side, with no re-fetch - useful once a case has real long-term
  history rather than the short test windows this feature was originally built and shown against.

### Fixed
- **A real bug: the Location Activity map on Pattern of Life could fail with "Map could not be
  rendered."** Reopening or refreshing the map a second time (switching tabs and back, reloading the
  section) hit a real Leaflet limitation - trying to initialize a second map instance on a container
  that still remembered its first one - and threw instead of rendering. Fixed by properly disposing
  of the previous map instance before creating a new one.
- **The Relationship Graph (Contact Correlation's graph view) is visually cleaner and stops jittering
  once it settles.** The force-directed layout used to keep drifting slightly forever; it now freezes
  in place once it's visually stable (nodes can still be dragged by hand). Node/edge styling was also
  tightened up - shadows, outlined labels for readability against busy backgrounds, smoother curved
  edges - for a more professional look overall.



### Added
- **Live Collection USB now collects real browser history, cookies, and bookmarks - not just
  processes/network/DNS/logged-on users.** Chrome, Edge, and Firefox profile files (History/Cookies/
  Bookmarks, or places.sqlite/cookies.sqlite for Firefox) are copied from every user account it can
  reach on the target machine - on Linux/macOS/*BSD via the same trusted collector (UAC) already
  used for the rest of the collection, and on Windows via a new section in the hand-written
  PowerShell collector that walks every real user profile it's permitted to (any account when run
  elevated, just the current one otherwise). Once imported into a case, these are read automatically
  by this app's own already-existing "Parse Browser Artifacts" action in File Explorer - no new
  parsing step to run separately.
- Windows' DNS resolver cache (`Get-DnsClientCache`) was already collected by an earlier release;
  Unix-family targets get their static `/etc/resolv.conf`/`/etc/hosts` configuration as part of the
  same collection, since Unix systems don't typically keep a queryable DNS cache the way Windows
  does.

### Fixed
- **A real bug in this app's own browser-artifact parser could silently miss an entire table's worth
  of already-recovered browsing history** - not just the very latest, not-yet-saved activity, but
  potentially everything, for any Chrome/Edge/Firefox profile collected while the browser was still
  genuinely open (a case folder someone's still actively using, a source drive imaged mid-session, or
  - as of this release - a Live Collection USB pull deliberately run before shutting a live machine
  down). Confirmed and fixed: the parser now correctly recovers this data regardless, while still
  refusing to ever write anything back to the copy it reads from. This also affects Android SMS/MMS/
  contacts/call-log parsing, WhatsApp message/contact parsing, iOS SMS/contacts/call-history parsing,
  and the generic SQLite table viewer in File Explorer - all of which share the same underlying
  reader.

## [1.63.0] - 2026-09-07

### Added
- **Geolocation is now part of Pattern of Life, with a live map you can see immediately.** A new
  "Location Activity" section on the Pattern of Life tab shows every GPS point already available for
  the case - a Google Takeout location-history import, or any KML file already attached to/found in
  the case folder - on an interactive map, with no separate export step needed first. Places visited
  more than once are grouped into "frequent locations" and ranked by visit count, the same idea
  Contact Correlation already applies to people, applied here to place instead.
- **A real preview of message and email content, right in Contact Correlation.** Each contact's row
  now has a "Preview" button showing the actual recovered text of their SMS/email content (where this
  app was able to recover it) - not just a count of how many messages exist. Call log entries
  correctly show no preview, since a call has no text content to show.
- **A disclosed "possible duplicate" warning when two contacts share an exact name but nothing else.**
  If two different contact entries have the identical display name but no shared phone number or
  email linking them, each now shows a warning icon explaining this plainly - it might be the same
  real person using two different, unlinked identities, or it might be two different people who
  happen to share a name. This app never merges them automatically; the icon links straight to the
  other entry so you can look and decide for yourself.
- **Android's own companion-app-extracted contacts can now be correlated too**, matching every other
  contact source this app already understands. Previously this specific source could only ever
  contribute a phone number to Contact Correlation, even when the same contact record also had an
  email address - now both are recognized from the same real per-contact record, closing a real gap
  in how thoroughly this app cross-references identities.
- **The Communication Activity Pattern chart can now optionally include web browsing and/or calendar
  activity.** Two new checkboxes let an examiner fold browser history/downloads/bookmarks/cookies
  and/or parsed calendar events/reminders into the same hour-of-day/day-of-week breakdown alongside
  texts, calls, and app messages - both are already parsed and already on the Evidence Timeline, just
  kept out of this chart's *default* view since neither is a two-way communication the way a text or
  call is.

## [1.62.0] - 2026-09-07

### Added
- **Contact Correlation now understands email addresses, not just phone numbers - so Calendar events
  and Email messages are correlated too, alongside SMS/calls/WhatsApp.** Previously, a contact only
  ever matched by phone number; a person who never texted or called but did show up as a calendar
  attendee or an email correspondent was invisible to this feature entirely. Now, whenever one of
  this app's own already-parsed contact sources records both a phone number and an email address for
  the same real person (e.g. a phone's own address book entry), that person's texts, calls, calendar
  invites, and emails are all merged into ONE entry in the Relationship Graph/Contact Correlation
  table - not shown as two unrelated-looking people. Someone who's only ever emailed (never texted or
  called) still gets their own entry, correctly shown with just an email address and no phone number.
- **The Evidence Timeline now shows, for every row it can, exactly which correlated contact was
  involved - and lets you filter the whole timeline down to just one person.** A new "Contact" column
  and a "Filter by Contact" dropdown (populated from the same Contact Correlation this case has
  already built) mean an examiner can pick a specific person from the list and immediately see every
  text, call, email, and calendar invite involving them, in chronological order, interleaved with
  everything else the timeline already tracks. A new button on each row of the Pattern of Life tab's
  Contact Correlation table jumps straight there, pre-filtered to that exact person. CSV export
  includes the resolved contact name(s) too.

## [1.61.0] - 2026-09-07

### Added
- **A new Relationship Graph on the Pattern of Life tab shows, at a glance, who a phone's owner mostly
  talked to versus who they only contacted once or twice.** Previously, Contact Correlation was a
  plain table of every matched contact - useful, but not something you could read in a few seconds.
  It now has two views: a **Graph View** (the new default) drawing every contact as a node connected
  to a central "This Device" node, with thicker lines and larger, red-colored dots for the small
  handful of contacts who account for the large majority of this device's communication - versus
  smaller, gray dots for someone contacted only once. A plain-language legend states the exact rule
  used ("these N contacts account for ~80% of total communication volume"), and clicking any contact
  jumps straight to its row in the existing **Table View** for full detail. The word "outlier" is
  deliberately never used anywhere in this feature - a low-frequency contact is stated as a fact, not
  framed as suspicious.
- **Contact Correlation now also tracks call direction and total call duration, where the underlying
  data supports it.** The table gained two new columns - "Direction" (how many incoming vs. outgoing
  communications) and "Talk Time" (total call duration, summed across every matched call) - both
  already present in several already-parsed data sources but never previously surfaced. Where the
  underlying comm type has no duration/direction data (SMS, most messaging platforms), these columns
  correctly show "--" rather than a fabricated number; the graph's line-thickness metric can be
  switched between "Frequency" and "Call Duration" whenever real call-duration data exists for the
  case.

## [1.60.0] - 2026-09-06

### Added
- **Drive Management now proactively surfaces a USB port's own known enumeration-failure history,
  before an examiner ever tries plugging anything into it.** Built directly from a real investigation
  on this station's own hardware: one specific physical USB port showed a real, repeated
  enumeration-failure pattern (a device taking an unusually long time to connect, or failing
  outright) across two completely different devices. The rear-port diagram in Settings > Drive
  Management now checks this station's own system log for that exact pattern on each of the 4 ports,
  independent of whether anything is currently connected - a port with a real history shows a small
  warning badge directly on the diagram plus a plain-language summary underneath ("Port 1: N
  enumeration failure(s), most recently at [time]"), so the information is visible the moment the
  page loads rather than only discovered by sitting through a slow, confusing connection attempt. A
  clean port, or a station where nothing has ever gone wrong, shows a simple confirmation instead.
  Reads existing system logs only - no new privilege or configuration needed. Confirmed live end to
  end: real login through the actual station, real historical failure data correctly detected and
  displayed exactly where expected.

## [1.59.0] - 2026-09-06

### Added
- **The write-confirmation protection added in the previous release now covers every acquisition and
  recovery path that writes to network-mounted evidence storage, not just the single main disk-
  imaging path.** Extended to: Android "Pull Accessible Storage," MTP fallback acquisition (for a
  device that can't be reached via adb), Logical Acquisition, the Live Collection USB import step,
  and PhotoRec/extundelete/foremost/scalpel's own recovered/carved file output. Each of these writes
  many files rather than one, so each gets a write-confirmation pass across every file produced
  (with a sensible cap so a legitimately huge recovery can't turn one job into an unbounded check -
  hitting that cap is disclosed, not treated as a failure on its own, since a real, successful large
  recovery routinely produces more files than any reasonable check can individually confirm one by
  one). Android "Bug Report"/"Backup" also gained this same confirmation as an added safeguard,
  layered in front of their existing structural check from the previous release. Confirmed live end
  to end against this station's real evidence storage: a real Logical Acquisition copy, hash, and
  independently-verified sha256 match, all passing cleanly.

## [1.58.0] - 2026-09-06

### Added
- **A real, durable-write confirmation before the app's main acquisition path (dc3dd, dcfldd, plain
  dd, E01, ddrescue, and raw-to-AFF conversion) ever reports "Completed Successfully."** Direct
  continuation of the previous release's finding: a writing tool's own exit code, and even its own
  self-reported hash (computed while streaming, before it closes its output file), don't guarantee
  the resulting bytes have actually, durably landed on network-mounted evidence storage under this
  station's own occasional NFS instability. Before any acquisition is reported complete, the
  destination file's write is now confirmed with a real filesystem `fsync` - forcing the kernel to
  flush and wait for a definitive answer from the storage itself, rather than trusting a tool that
  may have already exited believing everything succeeded. If the storage can't confirm the write,
  the job is now correctly reported as Failed, with a clear explanation, instead of a false success.
  Confirmed live, unprompted, during this same session's own testing: a real acquisition test hit a
  genuine, concurrent storage stall and the resulting file came back short of what was requested -
  correctly caught and reported as a failure rather than silently accepted.

## [1.57.3] - 2026-09-06

### Fixed
- **Android "Bug Report" and "Backup" acquisition modes could report a corrupted file as a genuine
  success.** Found on a real device: `adb bugreport` reported a complete, error-free 29MB transfer,
  but the resulting file on this station's own network-mounted evidence storage was silently
  truncated to exactly 1MB - a transient stall on the destination storage hit the write flush *after*
  `adb` had already exited reporting success, with no error surfaced anywhere in the process. The
  app's own completeness check was just "does the file exist and have some bytes" - a check a
  truncated file trivially passes. Now, before either mode is ever marked "Completed," the resulting
  file is checked for real structural completeness: a bugreport's `.zip` is validated the way any
  zip reader would (a truncated file lacks the trailing directory record every complete zip has,
  confirmed against the real corrupted file from this station); a backup's `.ab` file is fully
  decompressed and checked for its own valid end-of-stream marker when unencrypted, or accepted with
  its header alone verified when password-protected (its payload genuinely can't be checked further
  without the password, which isn't available at acquisition time - disclosed, not silently assumed
  fine). A file that fails this check is now correctly reported as Failed, with a clear message to
  retry, instead of a false "Completed Successfully."
- **A related, more foundational bug found while building the fix above**: the shared `.ab` decoder
  (`decrypt_and_decompress_backup()`, used both by acquisition and by every existing `.ab` analysis/
  parsing feature) never checked whether a compressed payload's decompression actually reached a real
  end-of-stream - confirmed directly that a raw deflate stream cut short by even a single byte still
  "successfully" decompresses and returns without error, silently handing back partial data as if it
  were the complete backup. Fixed at the source, so every existing caller of this function benefits,
  not just the new check above.

## [1.57.2] - 2026-09-06

### Fixed
- **MTP fallback acquisition (v1.57.0) had two real bugs, both found the first time it ran against a
  genuine connected Android phone.** The copy step previously shelled out to a single `sudo cp -a`:
  (1) `-a`'s ownership/mode preservation is meaningless for MTP (the mounted device presents a
  synthesized owner that the destination filesystem won't let root chown to anyway), so it printed a
  "failed to preserve ownership: Operation not permitted" line for every single file copied; (2)
  `cp`'s own aggregate exit code treats any single per-file error - including a real, occasional NFS
  write stall on this kind of evidence storage under sustained load - as total failure, which would
  have misreported a pull that had already captured hundreds of real files as a flat FAILED with
  nothing usable. Rewritten to walk the mounted device and copy each file itself (confirmed live that
  the unprivileged service account can read through the mount directly, closing a previously-open
  question), tracking real per-file success/failure counts the same way Logical Acquisition and Live
  Collection Import already do, instead of trusting one subprocess's exit code. Confirmed live against
  a real Pixel 8a: a run that hit genuine NFS stalls partway through correctly reported 175 files
  captured and 27 failed, with the job honestly marked "Stopped" (not "Failed") - and, as a bonus
  fix, the previous implementation never wrote any report update at all when a pull was manually
  stopped, silently leaving the case record frozen at "in progress" forever; the rewrite always
  records the final tally, even when stopped mid-copy.

## [1.57.1] - 2026-09-05

### Fixed
- **`install.py`'s generated sudoers grant for the MTP fallback feature (v1.57.0) had an unescaped
  comma that broke `visudo` validation outright** (`expected a fully-qualified path name`) - sudoers
  syntax treats a bare comma as a command-list separator, and jmtpfs's own `-o ro,allow_other`
  argument needed that comma backslash-escaped to be treated as a literal character. Never reached
  a live station in a broken state - caught by `visudo -c -f` exactly as designed, before the file
  was ever installed. Confirmed fixed and genuinely live-verified: real F2FS format detection, a
  real kernel mount + bindfs ownership-remap, real content read by the unprivileged service account,
  and read-only enforcement all confirmed working end-to-end against a real F2FS filesystem built on
  the station itself.

## [1.57.0] - 2026-09-05

### Added
- **MTP fallback acquisition for Android devices.** "Pull Accessible Storage" (adb) remains this
  station's default, preferred way to reach a connected Android device's shared storage, but it
  needs USB debugging enabled and on-device authorization - not always available. Mobile Forensics'
  Android controls now offer "MTP Fallback (No ADB Access)" - list connected MTP ("File Transfer"
  USB mode) devices and pull the same shared storage without needing adb at all. This reaches the
  exact same content adb pull already covers, never more - MTP has no shell access, so none of that
  mode's own device-timestamp/app-inventory/accounts/notification enrichment happens here.
- This completes the 3-part Android mobile-forensics gap-closing round (Auto Analyze for mobile
  evidence, F2FS filesystem browsing, and now this) built across v1.55.0-v1.57.0.

### Requires action on the station
- `sudo apt-get install -y jmtpfs`, plus the corresponding sudoers grants - same as the
  `bindfs`/`f2fs-tools` requirement noted in v1.56.0. Re-running `sudo python3 install.py` on a
  station whose sudoers file hasn't been hand-edited picks up all three automatically.

## [1.56.0] - 2026-09-05

### Added
- **F2FS filesystem browsing.** F2FS (common on a rooted Android device's own data partition) has
  never been readable through this app's Sleuth Kit-based Image Browser at all - the underlying
  toolkit simply has no driver for it. Right-clicking an F2FS-formatted image (or a specific
  partition within a larger multi-partition image) now offers "Mount F2FS Partition & Browse..." -
  it mounts the filesystem read-only through the station's own kernel filesystem support, then
  presents it in File Explorer as an ordinary, browsable folder, with every other tool (extract,
  hash, search, tag, attach to case) already working against it with no changes needed. This is
  read-only browse/extract/hash only - unlike ext4/NTFS/FAT, F2FS's own on-disk design doesn't
  support recovering deleted files through a plain mount.

### Requires action on the station
- **This release needs two things this app can't do on its own** - a station updated via git will
  see the new "Mount F2FS Partition & Browse..." menu item, but it will fail with a clear error
  message until both are done:
  1. `sudo apt-get install -y bindfs f2fs-tools` (bindfs is required; f2fs-tools is optional, only
     useful for building/inspecting a test F2FS image).
  2. A new sudoers grant for `bindfs` needs to be added to `/etc/sudoers.d/pi-forensics` -
     re-running `sudo python3 install.py` picks this up automatically on a station whose sudoers
     file hasn't been manually edited since install; a station with hand-edited sudoers needs the
     one new line added by hand (see `install.py`'s own generated content for the exact line).

### Added
- **Auto Analyze now covers Android mobile evidence, not just disk images.** Right-clicking an
  already-acquired Android pull folder, an Android Backup File (`.ab`), or an `adb bugreport` archive
  and choosing "Auto Analyze..." now offers a curated set of analysis steps tailored to what that
  specific item actually is - a pull folder gets Hash Manifest + ALEAPP/iLEAPP + MVT spyware scan by
  default (with an opt-in best-effort WhatsApp decrypt-and-parse and Geolocation Export), a `.ab` file
  gets Extract + Parse + MVT, and a bugreport archive gets its own deep-parse step. Every step runs
  through the same shared background-job/progress system every other tool already uses, and a step
  that genuinely doesn't apply to the selected item (e.g. Hash Manifest against a `.ab` file) is
  clearly reported as "not applicable" rather than silently skipped or falsely marked failed.
- MVT spyware-scan results launched from Auto Analyze are now recorded into the case's analysis index,
  so they show up in Reporting's per-exhibit summary like every other analysis tool's output already
  does - previously an MVT scan's results were only ever visible in the scan's own output folder.

## [1.54.0] - 2026-09-05

### Added
- **A new "Extract All Files" action for Android Backup Files (.ab).** Previously, opening a `.ab`
  file could only pull SMS/MMS records out of it (or run an MVT spyware scan) - every other file the
  backup bundled (installed APKs, shared-storage files, per-app data blobs) was never listed or
  extractable anywhere in the app. This unpacks the entire backup - password-protected or not - into
  a new, browsable folder, so those files can now be reviewed like any other evidence.

### Fixed
- **Several real Android communication/contact records were invisible to the Evidence Timeline,
  Pattern of Life activity chart, and Contact Correlation, purely because of missing category
  mappings** - not missing data. Native MMS messages, and both SMS and MMS pulled from a `.ab`
  backup, now correctly show up as "Communications" instead of the generic default bucket. Contact
  Correlation now also considers companion-app-extracted contacts/SMS/call log and `.ab`-backup
  SMS/MMS, and correctly resolves every real participant of a group MMS separately instead of risking
  a garbled, incorrect match.

---

## [1.53.0] - 2026-09-05

### Added
- **Drive Management is now a single unified card with real SMART telemetry.** The port diagram and
  drive controls no longer sit in two separately-bordered boxes - it's one continuous panel. Selecting
  a drive now shows the same live SMART health data Forensic Acquisition's own telemetry grid shows
  (media type, capacity, health pass/fail, model, serial, temperature, reallocated/pending sectors,
  power-on hours), right in Drive Management, without needing to switch tabs to check drive health.

---

## [1.52.0] - 2026-09-05

### Added
- **Drive Management: a Refresh button, live device info, and click-to-select on the port diagram.**
  A "Refresh" button next to the Drive Management heading re-scans connected drives without reloading
  the whole page - useful right after moving a drive to a different port. A new "Connected Drives"
  panel beneath the port diagram lists every detected drive's model, size, port, and serial number.
  Clicking a highlighted port in the diagram now selects that drive in the dropdown automatically
  (and, if a drive is moved to a different port while the page stays open, an automatic 5-second
  refresh - active only while Drive Management is the visible screen - picks up the change and
  re-highlights the new port with no manual action needed).

---

## [1.51.2] - 2026-09-05

### Fixed
- **Removed emoji from the USB port labels** ("Blue Port"/"Black Port"/"Unknown Port") - they rendered
  as blank boxes on this station's own kiosk font. The badges showing this text already carry their
  own color, so nothing is lost.

### Changed
- **Settings > Drive Management's two panels now visually match** - the port diagram and the drive
  controls (selector, status, buttons) each sit in their own bordered card of equal height, instead of
  the controls floating as loose, individually-bordered rows next to one larger boxed diagram.

---

## [1.51.1] - 2026-09-05

### Changed
- **Settings > Drive Management is more condensed.** The USB port diagram now sits side by side with
  the drive selector, write-blocker status, and buttons instead of stacked above them, cutting the
  card's height roughly in half.

---

## [1.51.0] - 2026-09-05

### Added
- **A real, physical port restriction for write-unlocking a drive.** This station's 2 blue (USB 3.0)
  ports are now permanently evidence-only - neither the manual write-blocker toggle (Settings > Drive
  Management) nor a Live Collection USB build can ever unlock a drive plugged into one of them,
  regardless of what's clicked or confirmed. Only the 2 black (USB 2.0) ports can be write-unlocked.
  This closes a real gap found during live hardware testing: any of the 4 ports could previously be
  unlocked by software, with nothing distinguishing an evidence port from a utility one.
- **A schematic USB port diagram on Settings > Drive Management** (Raspberry Pi 4 stations only - the
  one board this port detection has been verified against), showing all 4 rear ports, labeling which
  one currently holds a connected drive, and highlighting whichever drive is selected above. This is an
  original diagram, not a photograph.
- **The Write Blocker Status badge on Drive Management now reflects a drive's real, current state**
  (it previously always showed "locked" even for a drive deliberately left unlocked to write to).

### Fixed
- **The write-blocker toggle (Settings > Drive Management) is no longer silently undone within
  seconds.** Unlocking a drive through it used to genuinely flip the flag for a moment, then get
  reverted by this app's own routine background polling with no visible cause - the toggle was, in
  practice, non-functional for its actual purpose (unlocking a destination drive to write an image to).

---

## [1.50.3] - 2026-09-05

### Fixed
- **Reduced the underlying case-list scan cost every Reporting header stat shares.** Investigating the
  two fixes above surfaced that this scan was walking directly into recovery-tool bulk-output
  directories (and NAS-internal trash folders) sitting loose in the evidence store - directories that
  can never be a case and never contain one, but were still being fully explored on every single scan.
  These are now skipped outright. This won't eliminate every source of slow-storage latency, but it
  removes a real, unnecessary cost this app itself controlled.

---

## [1.50.2] - 2026-09-05

### Fixed
- **A second real inefficiency in yesterday's throttle fix, found while re-measuring it live.**
  Computing "Tags/Notable Items Flagged" alongside any of the other case-based stats (Total Cases,
  Active Cases, Evidence Items) was still walking the evidence store twice per request - once for
  those stats, once more inside the tags computation itself - needlessly doubling an already-slow
  cost on real network-attached storage. Now shares the one walk every other stat already does.

---

## [1.50.1] - 2026-09-05

### Fixed
- **A real performance issue with the new "Tags/Notable Items Flagged" stat, found and fixed the same
  day it shipped.** Computing it opened a fresh database connection per case, which on the deployed
  station's real network-attached storage measured roughly 15 extra seconds on top of an existing
  ~24-second baseline every other header stat already shares - nearly doubling Reporting's header row
  load time whenever this one stat was enabled. It's now cached for 5 minutes station-wide, matching
  how this app already handles an identical class of slow-storage cost elsewhere. A newly-tagged item
  can take up to 5 minutes to be reflected in the count - an accepted tradeoff for a header stat.

---

## [1.50.0] - 2026-09-05

### Added
- **"Tags/Notable Items Flagged" added to Reporting's customizable header stats** (Settings > Case &
  Reporting > Report Configuration > Reporting Header Stats). A station-wide count of every item
  tagged "Notable Item" (or any other tag an examiner has marked Notable) across every case, summed
  from each case's own tagging history. Off by default, alongside the other selectable stats.

---

## [1.49.0] - 2026-09-04

### Added
- **Companion-app Photos/Video metadata extraction for non-rooted Android devices** (Mobile Forensics
  > Android > Companion-App Extraction (Advanced)). Extends the companion-app extraction mechanism to
  a 5th and 6th data type: photo and video metadata read directly from the device's own MediaStore
  index - filename, size, dimensions, capture/added/modified timestamps, which album/folder, which app
  contributed it (Camera vs. WhatsApp vs. a screenshot tool, etc.), and favorite/trashed/pending flags.
  This reads the OS's own catalog of every photo/video it knows about, not the raw image/video bytes
  themselves (the existing "Pull Accessible Storage" acquisition mode already copies those); GPS/
  location data is deliberately not read this way, since Android's MediaStore redacts it for privacy -
  use the existing exiftool-based Geolocation Export on real pulled files for that instead.

### Changed
- **Companion-app extraction consolidated into one checkbox-driven panel.** The four separate,
  always-open panels (one per data type - SMS, Contacts/Call Log, Calendar, and now Photos/Video) have
  been replaced with a single panel: check the data types you want, pick an SMS access tier if SMS is
  selected, and click one "Start Extraction" button. The companion app is now installed and removed
  exactly once per extraction, regardless of how many data types are selected, and every selected
  type's results land in one combined case report event instead of several separate ones. Nothing
  about what each data type reads, or how the device is restored to its original state afterward,
  changed - only how it's chosen and started.

---

## [1.48.0] - 2026-09-04

### Added
- **Companion-app Calendar extraction for non-rooted Android devices** (Mobile Forensics > Android >
  Companion-App Extraction (Advanced)). Extends the companion-app extraction mechanism to a 4th data
  type: calendar events and their attendees. Installs the same companion app already used for SMS/
  Contacts/Call Log, grants it a single READ_CALENDAR permission, and reads each event's title, time,
  location, organizer, recurrence rule, and every invited attendee's own RSVP status - genuinely
  valuable pattern-of-life evidence (meetings, appointments, who was invited and whether they
  accepted) this app had no other way to capture from a non-rooted device. Like Contacts/Call Log,
  this never disrupts the phone's own Calendar app at any point, and every step is recorded in the
  case report; a "Force Cleanup" action is also available in case a previous extraction was ever
  interrupted before its own automatic cleanup could run.

---

## [1.47.1] - 2026-09-04

### Changed
- **Companion-app SMS extraction now uses this app's own hand-built app, not a separate third-party
  tool.** The SMS collector previously installed a separately-vendored open-source app
  ([adbsms.min](https://github.com/gonodono/adbsms)); it's now folded directly into the same
  companion app already used for Contacts/Call Log extraction, so there's only one app for the
  station to install/manage instead of two. Nothing about how SMS extraction works or what it
  produces has changed - same two access tiers, same disclosed device-modification behavior, same
  case-report record.
- **Both companion-app extraction panels (SMS, Contacts/Call Log) are now tucked into a collapsed
  "Companion-App Extraction (Advanced)" section** on the Android side of Mobile Forensics, instead of
  always sitting open above the standard Pull/Backup/Bugreport modes. These two actions are genuinely
  optional add-ons an examiner can run alongside whichever standard mode is selected, not another
  acquisition mode choice - collapsing them by default keeps the tab less cluttered for the more
  commonly used standard modes, while keeping both one click away.

---

## [1.47.0] - 2026-09-04

### Added
- **Companion-app Contacts/Call Log extraction for non-rooted Android devices** (Mobile Forensics >
  Android). Extends the companion-app extraction mechanism introduced for SMS above to the other two
  data types that are excluded from `adb backup` on every Android device, at the OS level, with no
  way around that short of root. Installs a small companion app (hand-built for this project,
  mirroring the same open-source relay-provider design as the SMS collector, since no suitable
  existing open-source tool was found for Contacts/Call Log specifically) that reads content through
  Android's own normal runtime-permission system, then removes the app and reverses every change
  when finished - just like SMS extraction, every step is recorded in the case report, not just
  logged internally. Genuinely **lower-risk** than SMS extraction: neither `READ_CONTACTS` nor
  `READ_CALL_LOG` requires the phone to reassign a "default app" role, so unlike the SMS full-access
  tier, the device's own Contacts and Phone apps are never disrupted at any point. Choose Contacts
  only, Call Log only, or both. A "Force Cleanup" action is also available in case a previous
  extraction was ever interrupted before its own automatic cleanup could run.

---

## [1.46.0] - 2026-09-04

### Added
- **Companion-app SMS extraction for non-rooted Android devices** (Mobile Forensics > Android). This
  app's `.ab` Android Backup decoder can only ever see SMS from a messaging app that's actually
  included in `adb backup` (many aren't), and Contacts/Call Log are excluded from `adb backup`
  entirely, on every device, at the OS level - no tooling can work around that without root. This
  closes the SMS half of that gap: installs a small, real, open-source (MIT-licensed) relay app,
  [adbsms.min](https://github.com/gonodono/adbsms), which reads SMS through Android's own normal
  runtime-permission system, then removes the app and reverses every change when finished. Two
  tiers: **read-only** (grants the permission only - Android's own real restriction means this sees
  inbox/sent messages only, but never disrupts normal messaging) and **full access** (temporarily
  makes the collector the device's default SMS app to see every folder - draft/outbox/failed/queued
  too - at the real, disclosed cost of the phone's own SMS app going offline until this finishes and
  the original default is restored). This is the one Android acquisition mode that deliberately
  modifies the device rather than only reading from it - every step (install, permission/role
  change, query, cleanup) is recorded in the resulting case report, not just logged internally. A
  "Force Cleanup" action is also available in case a previous extraction was ever interrupted before
  its own automatic cleanup could run.

## [1.45.0] - 2026-09-04

### Added
- **Reporting's "Contacts" tab is now "Pattern of Life"** - a genuine at-a-glance pattern-of-life
  view instead of just contact correlation on its own. Two new sections join the existing contact
  correlation table, both built entirely from data this app already parses (no new format-guessing,
  nothing untested against real data):
  - **Communication Activity Pattern**: a chart of when this device sent/received a text, call, or
    app message, switchable between "by hour of day" and "by day of week" - a classic pattern-of-life
    signal for spotting sleep/waking hours or a regular routine.
  - **Device Profile: Apps & Accounts**: the recently installed/updated apps and configured accounts
    captured automatically during any Android `adb pull` (v1.39.0/v1.44.0), shown together in one
    place instead of only being reachable one at a time through File Views.

### Fixed
- **Four of this app's own generated files could go unclassified in File Explorer's folder tree and
  never get auto-tagged into the case index**: the real-filesystem "Hash Directory Tree" manifest
  (`..._hashdeep_<algo>_manifest.txt`, a different naming convention from the whole-image hash
  manifest, which was already recognized) and the three Android pull manifests added in v1.39.0/
  v1.44.0 (installed-app inventory, configured accounts, notification snapshot) were never added to
  the pattern this app uses to recognize its own output. Found and fixed while grounding the Pattern
  of Life feature above - all four now group correctly under "Case-Generated Artifacts" and tag
  correctly, including retroactively for files already on disk from before this fix.

## [1.44.0] - 2026-09-04

### Added
- **Android configured-accounts and notification-snapshot capture**, both automatic during a plain
  `adb pull` acquisition (no root needed) - a real, direct extension of the existing app-inventory
  capture. Configured accounts (Google, WhatsApp, or any other app-registered account type) are
  captured in full via `adb shell dumpsys account` - real account names/emails, not masked. A
  notification snapshot captures which apps had a notification visible at the moment of the pull,
  its post/update time, and its importance ranking, via `adb shell dumpsys notification` - **real
  notification title/body text is NOT captured**, and never will be: the Android OS itself redacts
  that content by default for this exact command, and this app deliberately never passes the
  `--reveal` flag that would attempt to bypass it. Both are searchable in File Views and appear on
  the Evidence Timeline alongside every other pattern-of-life artifact.

## [1.43.2] - 2026-09-04

### Changed
- **Relicensed back to MIT**, the same day the switch to Apache-2.0 shipped. After a closer look at
  the tradeoffs (Apache-2.0's real edge is its explicit patent grant, which matters more once there
  are outside contributors or a real commercial product - this project's own audience is students,
  hobbyists, and low-budget users today, better served by MIT's two-paragraph simplicity), the
  maintainer chose to switch back. Reversible again later, before this project takes any outside
  contributions - the same reasoning that made both switches straightforward: every commit in this
  repo's history is the maintainer's own original work. Same scope as the [1.43.1] entry below -
  this project's own code only, every third-party tool/library keeps its own separate license.

## [1.43.1] - 2026-09-04

### Changed
- **Relicensed from GPLv3 to the Apache License 2.0.** Verified via this repository's own git history
  before making the change: this codebase started as the maintainer's own original MIT-licensed work
  (the very first commit), and GPLv3 was the maintainer's own later, unilateral choice - not a fork of
  a third party's GPL-licensed project, so no third party's rights are affected. This only changes the
  terms for this project's own original code (`app.py`, `core/`, `routes/`, the frontend, the setup
  scripts) - every third-party tool and library this station installs, imports, or vendors keeps its
  own separate, unchanged license, exactly as documented in `THIRD_PARTY_NOTICES.md`.

## [1.43.0] - 2026-09-04

### Added
- **Richer Android Backup (.ab) SMS/MMS parsing** - the SMS message-type label now covers the full
  real set (Received/Sent/Draft/Outbox/Failed/Queued, not just the two most common), and MMS records
  now also capture attachment metadata (filename and file type per attachment - the actual photo/video
  bytes are never included in an `adb backup`, only this metadata, confirmed against the real Android
  source), the message subject line, and read/archived flags.

### Investigated, not built
- Contacts and Call Log **cannot** be recovered from a `.ab` Android Backup file, confirmed directly
  against the real Android source: the app that owns both (`com.android.providers.contacts`) declares
  itself excluded from `adb backup` entirely, at the operating-system level - the data never enters the
  backup file in the first place, regardless of what tool reads it afterward. The existing rooted
  physical-image parser remains the only real path to that content.

## [1.42.0] - 2026-09-04

### Added
- **Android Backup File (.ab) support** - this app's own Mobile Forensics "Backup" acquisition mode
  (`adb backup`) already produced a real `.ab` file, but nothing ever read it. A rooted phone (needed
  for the existing native SMS/MMS parser) is rare in real casework, so this closes the much more common
  gap:
  - A new built-in decoder parses a real `.ab` file directly - header validation, DEFLATE decompression,
    and (for a password-protected backup) AES-256/PBKDF2 decryption matching Android's own real
    algorithm - and extracts SMS and MMS content straight into the case's searchable Parsed Artifacts
    index and Evidence Timeline. Reachable from File Explorer's right-click menu on any `.ab` file
    (real files, and one found inside an already-acquired disk image).
  - The same action can instead run Amnesty International's MVT (Mobile Verification Toolkit) directly
    against the `.ab` file for a spyware/IOC check - MVT's own `check-backup` command accepts a raw
    `.ab` file (with a password, if needed) without any separate extraction step first, correcting an
    earlier assumption in this app that a pre-decrypted extraction was required.
  - An optional password field covers a backup that was password-protected on-device at backup time.

## [1.41.1] - 2026-09-04

### Fixed

- **File Explorer's Preview pane now pretty-prints `.json` files** instead of showing them as
  whatever single unbroken line they happen to be stored as on disk. Several of this app's own
  JSON output files (including the new Android app inventory manifest from v1.39.0) were never
  indented, since that's a display concern, not a data-correctness one - now fixed at the source
  too, but the real fix is in the Preview pane itself, so any `.json` file (from this app or
  anywhere else) reads correctly regardless of how it was originally saved.

## [1.41.0] - 2026-09-04

### Added

- **Deep-parsing an `adb bugreport` archive no longer produces only a raw JSON file.** Package
  install/delete events, GPS location fixes, crash reports (tombstones), and loaded kernel modules
  are now individually indexed into the same searchable "Parsed Artifacts" list every other artifact
  type in this app already uses - and, wherever the underlying data actually carries a real
  timestamp (installs/deletes, GPS fixes, crashes), they now show up on the Evidence Timeline too.
  The full raw output is still saved alongside this - nothing about the existing JSON export
  changed, this is purely additive. A few sections (battery stats, running processes, network
  sockets, and similar "current state at the moment of the dump" snapshots) are deliberately left as
  before, since making those genuinely searchable would mean guessing at an internal data shape this
  app has never been able to confirm against a real sample bugreport.

## [1.40.0] - 2026-09-04

### Added

- **A rooted physical Android image's SMS/MMS parsing now covers MMS messages, not just SMS.**
  Right-click a rooted physical image (or its already-extracted `mmssms.db`) and every real MMS
  message - text content, photo/video attachment filenames, subject lines, sender/recipient, and
  group-MMS participants - now shows up alongside SMS in the same searchable index and Evidence
  Timeline. Grounded directly against real Android platform source (`Telephony.Mms`/`Mms.Part`/
  `Mms.Addr`) and a real, working MMS-parsing library's own address-type constants, including the
  well-known "MMS timestamps are in seconds, SMS timestamps are in milliseconds" distinction that's
  a common source of mistakes in this exact area.

## [1.39.0] - 2026-09-04

### Added

- **A real `adb pull` acquisition now automatically captures the device's full installed-app
  inventory** - one non-invasive `adb shell dumpsys package packages` query, no root needed, run
  immediately after a successful pull (the same "capture it now, it's gone once the device
  disconnects" reasoning already used for real on-device file timestamps). Package name, version,
  install/update time, and whether it's a system or user-installed app are all captured and parsed
  directly into File Views' searchable index and the Evidence Timeline - genuinely useful
  pattern-of-life context (what apps does this person actually have installed, and when) without
  needing a full ALEAPP run.

### Fixed

- **Two ALEAPP-parsed artifact types - Installed Applications and Usage Stats - could never appear
  on the Evidence Timeline at all**, even when a real ALEAPP run found genuine data for them,
  because this app had never taught itself which column in either module's real output holds a
  timestamp. Fixed by reading the exact real column names directly from this app's own pinned
  ALEAPP source. One of the three real modules that can produce "Installed Applications" data
  (`InstalledappsGass`) genuinely has no timestamp of its own at all - that one honestly stays
  timestamp-less, which is correct, not a remaining gap.

## [1.38.0] - 2026-09-04

### Added

- **Reporting gained a new "Contacts" tab: automatic contact correlation for pattern-of-life
  analysis.** Once you've parsed contacts (Android's own on-device contacts, an iOS backup's
  Contacts, a Google Takeout import, or WhatsApp's `wa.db`) and communications (SMS, call logs,
  WhatsApp messages/calls) for a case, this new tab cross-references them automatically - resolving
  a raw phone number sitting in a text message or call log to a real contact name, regardless of
  whether the two sources formatted that number differently (`+15551234567` vs `(555) 123-4567` vs
  a WhatsApp JID all resolve to the same person). The most-contacted people surface first, and a
  number independently confirmed by more than one contact source (e.g. both the phone's own
  contacts and WhatsApp's contacts naming the same number "Jane Doe") is shown as stronger
  corroboration. This is a read-only report computed fresh from already-parsed data - it never
  changes any evidence record, and correlating nothing costs nothing extra.

## [1.37.0] - 2026-09-04

### Added

- **WhatsApp local backups can now be natively parsed, not just decrypted.** Right-click a folder
  containing a decrypted `msgstore.db` (this app's own WhatsApp-decrypt feature's own output - no
  root or ALEAPP run required) or a rooted physical Android image's extracted `/data/data/
  com.whatsapp/databases/` folder, and choose "Parse WhatsApp Database" to pull out real 1:1 and
  group messages, calls, and (if a `wa.db` file is present) contacts - all searchable in File
  Views and on the Evidence Timeline, exactly like every other artifact this app produces. Grounded
  directly against this app's own already-pinned, actively-maintained ALEAPP source (the same
  schema its existing WhatsApp coverage already trusts), not guessed.

### Fixed

- **A real bug found during this feature's own live verification**: a group chat message's sender
  was never resolving to a real contact name, even with a contacts database available - the query
  was looking up the GROUP's own identity instead of the specific member who sent that message.
  Fixed and covered by a dedicated regression test before release.

---

## [1.36.0] - 2026-09-04

### Added

- **Google Takeout import now covers Gmail, Contacts, and Calendar/Reminders**, alongside the
  existing Search History/YouTube History/Location History/Maps/Photos coverage. All three reuse
  this app's own already-built, high-confidence parsers for these exact open, standard formats -
  Gmail's `.mbox` files (the same parser already used for standalone `.eml`/`.mbox`/`.pst` email),
  and Contacts/Calendar's `.vcf`/`.ics` files (the same RFC 6350/5545 parsers already used for an
  Apple "Data & Privacy" export) - rather than writing new ones. A real, confirmed Takeout behavior
  is handled correctly: selecting specific Gmail labels instead of "All Mail" produces multiple
  separate `.mbox` files, all of which are found and combined.
- The first step of a broader pass to build out real Android pattern-of-life analysis (mobile
  acquisition + File Explorer artifact parsing) - texts, email, apps, messages, contacts, and
  eventually companion/wearable-device data - more of which follows in upcoming releases.

---

## [1.35.0] - 2026-09-03

### Added

- **Bluetooth device pairing history is now parsed from the Windows Registry's SYSTEM hive** -
  which devices have ever been paired with a Windows machine (device name and MAC address), and
  when the machine last saw or connected to each one. Reuses the app's already-built Registry hive
  parser and its existing SYSTEM-hive dispatch, so this automatically applies everywhere that
  parser already runs - whole-image and single-hive scans in File Explorer, and Live Collection
  USB's own live registry pull (v1.34.0, above).
- Grounded against the same real, established forensic tooling used to research every other
  registry artifact this app has added: RegRipper's own maintained Bluetooth plugin (both the
  current and a 2013 revision) and an independent Microsoft support confirmation of the exact
  timestamp math, giving high confidence in both the registry location and the timestamp format.
  Scoped deliberately narrower than a fuller parser could attempt, per real, disclosed limits found
  in those same sources: the device name's exact text encoding isn't authoritatively documented
  anywhere found, so it's decoded best-effort rather than trusted outright, and the timestamp may
  only ever reflect a device's original pairing rather than a later reconnection - both caveats
  visible directly on the record itself, not buried in documentation an examiner would never see.

---

## [1.34.0] - 2026-09-03

### Added

- **Live Collection USB's Windows collector now also pulls a live registry pattern-of-life
  snapshot**, elevated only. Covers what's been done recently and where - RecentDocs, TypedPaths,
  RunMRU, UserAssist (GUI-launched program history), RDP connection history, and Office/Explorer
  search MRU for the collecting account and every other real user profile on the machine, plus the
  machine-wide USB device history, Shimcache, BAM/DAM execution evidence, installed program list,
  Amcache application inventory, and ShellBags folder-browse history. Reuses this app's own
  already-built, already-mature registry hive parser (the same one that's read acquired NTUSER.DAT/
  SYSTEM/SOFTWARE/Amcache.hve/UsrClass.dat files for months) with zero new parsing logic - the
  collector just exports live hive copies (via the registry's own backup API, the same mechanism a
  real offline hive export uses, just against a still-running system) named to exactly match what
  that parser already expects.
- Every real user profile's exported hives now land in their own named subfolder on the collection
  drive, so two different users' identically-named `NTUSER.DAT` files can never collide - the same
  discovery mechanism already used for PowerShell history/Prefetch handles the multi-user layout
  automatically, with zero code changes of its own.

### Disclosed

- The live registry export step needs a genuinely elevated (UAC-elevated) session, not just
  Administrators-group membership - confirmed directly: even an admin account's own hive export
  fails without it, since the underlying mechanism needs a privilege elevation alone doesn't grant.
  The export/parse pipeline itself is fully tested, including a real end-to-end run against genuine
  registry hive files on the deployed station - what hasn't been exercised yet is the collector
  script's own registry step inside an actual elevated session on a real Windows machine, since that
  needs interactive administrator consent this project's own automated testing can't provide. Worth
  a quick real confirmation next time the collector runs elevated on a real target.

---

## [1.33.0] - 2026-09-03

### Added

- **Live Collection USB's Windows collector now also pulls a 30-day excerpt of the Security and
  System Event Logs**, reusing this app's own already-built Event Log parser with zero new parsing
  logic. Covers successful and failed logons, workstation lock/unlock, user account creation,
  process creation, service installation, service start/stop state changes, and audit-log-clearing
  (a classic anti-forensic indicator) - the last two event types require the collector to run
  elevated. Every event keeps its own real, original timestamp on the Evidence Timeline, not the
  time the collection itself ran.

### Fixed

- **A real correctness bug in the Event Log parser itself, found while building the feature above
  and fixed retroactively for every existing use of it (not just the new live-collection path)**:
  a numeric Windows Event ID is only guaranteed unique *within one provider's own event
  definitions* - a different, unrelated Windows component can reuse the same ID for its own,
  completely different kind of event. This was confirmed against a real Windows machine, where a
  WiFi network driver was found reusing Event ID 7036 (normally "a service changed state") for its
  own internal logging. Previously, this app's Event Log parser matched on Event ID alone, meaning
  such a collision could be silently misfiled as a real service state change. The parser now also
  checks the event's actual source (its "Provider" name) before accepting it, and this check has
  been applied to every event type this app has ever recognized, not only the ones added in this
  release. If you've previously parsed a `.evtx` file for service state changes (Event ID 7036)
  and want to double-check the results, re-run "Parse Event Logs" from File Explorer's right-click
  menu against that same file.

---

## [1.32.0] - 2026-09-03

### Added

- **Live Collection USB's Windows collector now pulls three more artifact types, all reusing this
  app's own already-built parsers with zero new parsing logic**:
  - **Scheduled tasks now show real run history** - when each task actually last ran, its result
    code, and its next scheduled run, not just its current state. A task that's never actually run
    is honestly shown as such rather than a misleading date.
  - **PowerShell console history** is now copied and parsed automatically - every command typed at
    a PowerShell prompt on the target, for the account running the collector and (when run as
    administrator) every other real user profile on the machine.
  - **Prefetch execution evidence** is now copied and parsed automatically when the collector runs
    elevated - real run counts and last-execution times for what's actually been launched on that
    machine, closing a real gap between what an already-acquired disk image can show and what a
    live collection could.

## [1.31.0] - 2026-09-03

### Added

- **Live Collection USB's Windows results now show real historical timestamps, not just
  "when the collector ran."** Running processes and network connections were previously stamped
  with a single collection-time timestamp for every item, which meant they all landed at one
  instant on the Evidence Timeline no matter when they actually started. Process launch time and
  network connection establishment time are now captured and used directly, so each one appears at
  its own real moment - genuinely useful for reconstructing what happened and when, not just what
  was running at the moment the drive was plugged in.
- **Five categories of data the collector was already gathering, but never showing you, are now
  parsed and searchable**: system info (hostname, OS version, machine model), a dedicated System
  Boot Time record (a real historical event, distinct from collection time), ARP cache entries,
  DNS cache entries, installed hotfixes/patches (with their real install date), and loaded drivers.
  None of this needed a new collection step - it was already being written to the drive, just never
  read back in.

### Fixed

- A handful of collected fields (installed hotfixes' names, ARP/DNS cache entries) previously kept
  Windows' own internal capitalized field names in the raw output rather than matching every other
  category's plain style - cosmetic only, but now consistent.

## [1.30.3] - 2026-09-03

### Fixed

- **A malformed value from the Live Collection USB Windows collector could hang File Explorer.**
  Verifying real collected data end-to-end (a follow-up to the real-hardware Live Collection USB
  testing in 1.30.2) found one autorun entry whose recorded "value" was a deeply-nested Windows
  object rather than plain text - a leftover from before this same session's collector-script fix.
  Turning that into text with no size limit produced a single field several megabytes in size, which
  was large enough to hang both the app's own API and the File Explorer page trying to display it.
  Every place that builds this kind of summary text (processes, network connections, services,
  scheduled tasks, and autorun entries) now caps how much it will ever try to display, and shows a
  short, clear placeholder instead of an unexpected object - the real data for that one entry is
  gone (it was never real forensic content to begin with, just a leaked internal detail), but every
  category now loads normally.

## [1.30.2] - 2026-09-03

### Fixed

- **Live Collection USB's "Build" step now reliably completes on real physical USB drives.**
  Testing against a real drive for the first time surfaced four real bugs, all now fixed:
  - The wipe/format step could fail partway through with a "write failed" error, because this
    station's write-protection rules re-lock a freshly-created partition the instant it's created,
    independently of the whole-disk unlock already in place - the partition itself needed its own
    explicit unlock before formatting.
  - A slow real USB drive can need longer than 30 seconds to finish flushing its write cache during
    unmount - previously this could time out and fail the whole build even though every file had
    already copied successfully; it's now given more time, an explicit `sync` first, and no longer
    treated as fatal (a slow-but-uncertain unmount now shows as a caveat, not a false failure).
  - Two other setup steps (re-reading the partition table, waiting for the system to catch up) had
    the same "too tight a timeout for real hardware" problem - both fixed the same way.
  - A logging bug after a fully successful build could crash and get wrongly reported as "Failed"
    even though the drive was built completely correctly - fixed.
- **The Windows collector script's Autorun/Startup Items artifact could balloon to over 13MB** of
  mostly irrelevant PowerShell internal data, due to a registry-reading bug that let one internal
  PowerShell property leak through where it shouldn't have. Fixed - a future build's collector
  script will produce a normal-sized, clean list of actual startup entries instead.

---

## [1.30.1] - 2026-09-03

### Fixed

- **File Recovery's extundelete tool now tells you what actually went wrong** when it fails,
  instead of the same generic "exited with code N" message for every failure. Confirmed live
  against a real ext4 test image: this station's extundelete build (the only version Debian
  packages, unmaintained since around 2013) can crash outright on a filesystem using ext4 features
  that are enabled by default on most modern Linux installs (`metadata_csum`/`64bit`), rather than
  exiting cleanly. When that happens, the job log and the Tool Reference help text now say so
  directly and point you at PhotoRec as a working alternative (it recovers by file-signature
  carving, not by reading filesystem metadata, so it isn't affected by this).

---

## [1.30.0] - 2026-09-03

### Added

- **Reporting's header row now has a customizable set of stat cards**, instead of always showing
  just Total Cases. Settings > Case & Reporting > Report Configuration gained a "Reporting Header
  Stats" picker with 4 options: Total Cases (the existing status-breakdown chart, still on by
  default), Active Cases (cases not yet Closed/Archived), Evidence Items (total acquisition events
  across every case), and Reports Exported (a new counter - report PDF/HTML exports are now logged
  to the Audit Trail, so this only counts exports made from this point forward). Every existing
  station keeps showing exactly Total Cases until you opt into more, so nothing changes unless you
  go pick something.

---

## [1.29.0] - 2026-09-03

Continuing the usability pass from v1.28.0 - this time File Explorer's own toolbar/menu density,
plus a search box for Settings, both flagged as bigger structural items during the same review.

### Added

- **Settings now has a search box** at the top of the tab. Type a term (e.g. "password", "reboot",
  "YARA") and it filters live across all 5 categories - clicking a result switches to the right
  category, expands the matching section, scrolls it into view, and briefly highlights it. Covers
  every top-level Security/Case & Reporting/Network section plus Drive Management and Diagnostics'
  own Service/Updates/Diagnostics/Power groups - roughly 20 distinct settings that previously
  required browsing 5 categories by hand to find.
- File Explorer's image-mode toolbar (previously ~17 icon-only buttons in one row) is now just
  Search, Timeline, a "More Analysis" dropdown, and Exit Image - everything else (Geolocation,
  Hash Manifest, Triage Scan, Recover Deleted, and every artifact parser) moved into the dropdown,
  grouped and labeled with real text instead of icon-only.
- File Explorer's right-click "Artifact Parsers" section (33 items, the single largest menu section
  in the app) is now 4 smaller sections - Windows Artifacts, Linux & macOS Artifacts, Mobile &
  Cloud Imports, and Cross-Platform Artifacts - so a right-click shows a shorter list of headers
  instead of one long scrolling list. Every button kept its exact action - this is purely about
  finding things faster, not new capability.

---

## [1.28.0] - 2026-09-03

A usability pass on Reporting/Case Management (the area most requested for review), plus a couple of
smaller, related fixes elsewhere. Prompted by a full usability review across every tab, with the
deepest look specifically at cases and reporting.

### Added

- **Reporting now shows an "Unsaved changes" indicator** whenever the Report Narrative, Case Status,
  Case Details, or the Files & Artifacts exhibit checklist/captions/reference URLs have edits that
  haven't been saved yet - these only persist via the explicit "Save Report Changes" button, unlike
  Case Notes, the Physical Custody Log, tags, and "Attach to Case," which all save immediately. The
  station now also warns before closing the tab or switching to a different case while there are
  unsaved changes, instead of silently discarding them.
- Home gained a "New here?" banner linking straight to the Guided Workflow checklist under Help,
  instead of leaving it undiscovered as one of nine items in Help's own nav.
- The Case Manager's case list now highlights whichever case is currently active with a "Current"
  badge, and shows the examiner's name instead of a raw filesystem path on every row (still available
  as a tooltip).
- Reporting's Export pane now shows the Export button immediately, with a note that the defaults
  already produce a complete report - the section/evidence-item/file checklists are still there, just
  collapsed by default behind a "Customize contents" toggle instead of always taking up the whole pane.
- The Indicators of Compromise and Recommendations / Next Steps fields in Report Narrative now say
  plainly which report templates actually include them by default (DFIR only, and DFIR/Police
  respectively) - previously easy to fill in and then find missing from a Standard export.
- Custom Case Fields shows a clear "not configured yet" message when a station has none defined,
  instead of an empty gap that looked like a rendering error.
- The Exhibits list now notes that exhibit numbers can shift if a file is added or removed, and the
  Case Notes / Report Narrative tabs each link directly to the other, since they're easy to mix up on
  a first pass (a running work journal vs. a polished closing narrative).

### Changed

- Live Collection USB moved down in the sidebar, below Mobile Forensics and File Recovery - its old
  position implied it was an early, required step for every examiner, when it's really an occasional,
  more advanced workflow.
- Reporting's "Custody Log" tab is now labeled "Physical Custody Log," matching the fuller name it
  already used elsewhere in the app, to reduce confusion with Settings' separate "Audit Log."

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
