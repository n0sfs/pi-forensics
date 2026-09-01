"""macOS LaunchAgents/LaunchDaemons persistence artifacts -
~/Library/LaunchAgents/*.plist (per-user), /Library/LaunchAgents/*.plist
and /Library/LaunchDaemons/*.plist (system-wide, admin-installed), and
/System/Library/LaunchDaemons/*.plist (Apple's own built-in ones) -
macOS's closest rough equivalent to Windows Registry Run keys, and a
real, current, dominant malware-persistence technique.

Grounded via real research (2026-09-01) before any code was written:

- **Real, confirmed field semantics from Apple's own launchd.plist(5) man
  page**: `Label` (a unique job identifier), `Program`/`ProgramArguments`
  (the actual executable + arguments actually launched), `RunAtLoad`,
  `KeepAlive`, `StartInterval`/`StartCalendarInterval` (scheduling info),
  `WatchPaths`/`QueueDirectories` (trigger-based launch conditions - a job
  fires when a watched path changes, a technique real malware has used to
  re-launch itself).
- **This is a real, current, dominant technique - cross-validated against
  multiple independent credible sources**: SentinelOne's "How Malware
  Persists on macOS," and Patrick Wardle/Objective-See's own compiled
  research (in 2021, EVERY newly-discovered Mac malware variant attempted
  launch-item persistence; 80% in 2020).
- **Apple's own `/System/Library/LaunchDaemons` items are deliberately
  NOT filtered out**, correcting an initial assumption this module was
  first drafted against: real DFIR practice doesn't bulk-exclude them as
  noise (confirmed via research) - System Integrity Protection (SIP,
  OS X 10.11+) means real malware genuinely cannot write there, but
  practitioners still collect them and diff against a known-good baseline
  or sort by modification time, rather than skip them outright. Every
  found item is returned, tagged with `is_system_item` in `extra` so an
  examiner can filter/sort, never silently dropped.
- **plist format (XML vs. Apple's own binary plist encoding) needs no
  special handling** - stdlib `plistlib.load()` auto-detects and parses
  either transparently, already proven elsewhere in this app (Safari's
  own Bookmarks.plist/Downloads.plist, core/browser_artifacts.py).

**Disclosed, not silently assumed**: this module's own field-extraction
logic is verified against real, hand-built plist fixtures (both XML and
binary-encoded), but the underlying question of whether this app's
image-browsing pipeline (pytsk3/The Sleuth Kit) can actually open a real
macOS disk image at all was separately researched the same session and
found to be a genuine, real gap for APFS specifically (the only
filesystem virtually every Mac sold since ~2017-2018 actually uses) -
pytsk3 itself has never received the "pool API" support APFS containers
need (confirmed via a real 2020 upstream GitHub issue where an attempt to
force it segfaulted), and even mac_apt (a credible, actively-used real
macOS forensic tool) deliberately avoids pytsk3 for APFS content parsing,
using its own separate hand-rolled parser instead. HFS+ (mature TSK
support since 2010) would work today via this app's existing pipeline,
covering pre-APFS Intel Macs and some backup/Time Machine volumes - but
this module works completely independently of that question too: it
scans a real, already-extracted evidence FOLDER (a Target Disk Mode copy,
a logical extraction, or any other means an examiner already has real
files on disk) exactly the same way every other real-fs parser in this
app already does, with zero dependency on in-image browsing working at
all. Full APFS support (a wholly separate dependency, e.g. libfsapfs) is
a materially larger, separate project, not attempted here.
"""
import os
import plistlib

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

LAUNCHD_PLIST_EXTENSION = '.plist'
LAUNCHD_PARENT_DIR_NAMES = {'launchagents', 'launchdaemons'}
LAUNCHD_SCAN_MAX_CANDIDATES = 500  # a real macOS system can easily have 100+ LaunchDaemons alone
LAUNCHD_SCAN_MAX_WALKED = 20_000
LAUNCHD_MAX_PROGRAM_ARGUMENTS_SHOWN = 20


def is_launchd_plist_candidate(name, containing_dir):
    """containing_dir is the directory the file itself sits in - real-fs
    callers pass os.walk()'s own dirpath directly; in-image callers derive
    it from the full in-image path, mirroring core/linux_artifacts.py's
    is_passwd_candidate(name, containing_dir) precedent for the exact same
    reason (one definition of 'what counts as a candidate', not two that
    could drift apart)."""
    if not name.lower().endswith(LAUNCHD_PLIST_EXTENSION):
        return False
    parent_name = os.path.basename((containing_dir or '').rstrip('/\\'))
    return parent_name.lower() in LAUNCHD_PARENT_DIR_NAMES


def find_launchd_plist_files(root_dir):
    """Recursively finds real LaunchAgents/LaunchDaemons .plist files
    (matched by extension + immediate parent directory name) anywhere
    under root_dir. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > LAUNCHD_SCAN_MAX_WALKED:
                return found, True
            if is_launchd_plist_candidate(fname, root):
                found.append(os.path.join(root, fname))
                if len(found) >= LAUNCHD_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _is_system_item(path):
    """Whether this plist sits somewhere under a '/System/' path
    component - Apple's own built-in items (SIP-protected, real malware
    can't write there) vs. an admin/user-installed one. Never used to
    filter results (see this module's own docstring) - only to tag them
    for the examiner's own sorting/filtering."""
    parts = path.replace('\\', '/').split('/')
    return any(p.lower() == 'system' for p in parts)


def _resolve_program_command(plist_data):
    program = plist_data.get('Program')
    args = plist_data.get('ProgramArguments')
    if isinstance(args, list) and args:
        shown = args[:LAUNCHD_MAX_PROGRAM_ARGUMENTS_SHOWN]
        cmd = ' '.join(str(a) for a in shown)
        if len(args) > LAUNCHD_MAX_PROGRAM_ARGUMENTS_SHOWN:
            cmd += ' ...'
        return cmd
    if program:
        return str(program)
    return None


def parse_launchd_plist_file(path, filename=None):
    """Parses one real LaunchAgents/LaunchDaemons .plist into a single
    record (a launchd job description is one file, one job - unlike the
    Registry/EVTX modules' one-file-many-records shape). Returns [] on
    any failure to parse (not a real plist, corrupted, genuinely empty) -
    the same best-effort tolerance every other parser in this app already
    applies, never raises out to the caller. Timestamp is the plist
    file's own mtime (a real, if imprecise, proxy for "when was this
    persistence mechanism installed/modified" - the same convention this
    app's own core/registry_utils.py already established for Amcache/
    Uninstall keys with no dedicated timestamp value of their own)."""
    display_name = filename or os.path.basename(path)
    try:
        with open(path, 'rb') as f:
            data = plistlib.load(f)
    except (plistlib.InvalidFileException, OSError, ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []

    label = data.get('Label')
    title = str(label) if label else display_name.rsplit('.', 1)[0]
    command = _resolve_program_command(data)
    value = command if command else "(no Program/ProgramArguments found)"

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None

    return [{
        "artifact_type": "macos_launchd_item", "title": title, "url": "",
        "value": value, "timestamp": mtime,
        "extra": {
            "label": label,
            "program": data.get('Program'),
            "program_arguments": data.get('ProgramArguments'),
            "run_at_load": data.get('RunAtLoad'),
            "keep_alive": data.get('KeepAlive'),
            "start_interval": data.get('StartInterval'),
            "start_calendar_interval": data.get('StartCalendarInterval'),
            "watch_paths": data.get('WatchPaths'),
            "queue_directories": data.get('QueueDirectories'),
            "is_system_item": _is_system_item(path),
            "source_file": display_name,
        },
    }]
