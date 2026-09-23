"""Path-safety, chain-of-custody logging, and file-classification helpers
shared across every routes/*.py module that touches the filesystem.

Part of the app.py -> core/ + routes/ split - pure code motion, no
behavior change. See the dated CLAUDE.md entry for this refactor.
"""
import os
import re
import time
import json
import threading
from flask import request, g

from core.config import EVIDENCE_ROOT, COC_LOG_FILE
from core.auth import _effective_client_ip

coc_log_lock = threading.Lock()

# --- Block Device Path Validation ---
# Shared by routes/recovery.py, routes/acquisition.py (still inline in
# app.py pending its own extraction), and routes/settings.py's drive
# management - a genuinely cross-module helper, not recovery- or
# acquisition-specific despite living next to the acquisition-flavored
# BitLocker helpers in the original app.py.
_DEVICE_RE = re.compile(r'^/dev/(sd[a-z]|nvme\d+n\d+|mmcblk\d+)$')
_PARTITION_RE = re.compile(r'^/dev/(sd[a-z]\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$')

_SYSTEM_MOUNTPOINTS = ('/', '/boot', '/boot/firmware')


def system_disk_names():
    """Kernel names of the whole disk(s) holding this station's own running
    system (root, /boot, /boot/firmware) - e.g. {'mmcblk0'} on a Pi booted
    from SD. Resolved from the mounted filesystems' device numbers via
    /sys/dev/block, so it is right however the root is named in /proc/mounts
    (/dev/root, PARTUUID=...). Empty set where /sys is absent (a dev machine)."""
    names = set()
    for mp in _SYSTEM_MOUNTPOINTS:
        name = disk_name_for_path(mp)
        if name:
            names.add(name)
    return names


def disk_name_for_path(path):
    """Kernel name of the whole disk a path's filesystem lives on (e.g. 'sdb'
    for a file on /dev/sdb1), or None for anything not backed by a local
    block device (NFS/SMB/sshfs, tmpfs, a missing path, a dev machine)."""
    # A destination folder may not exist yet - its nearest existing ancestor
    # is where it will be created.
    while path and not os.path.exists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    try:
        dev = os.stat(path).st_dev
        sys_path = os.path.realpath(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}")
    except (OSError, AttributeError):
        return None
    if not os.path.isdir(sys_path):
        return None
    # A partition's sysfs dir sits inside its parent disk's dir.
    if os.path.exists(os.path.join(sys_path, 'partition')):
        sys_path = os.path.dirname(sys_path)
    return os.path.basename(sys_path)


def destination_is_on_source_device(dest_path, source_device):
    """True when an image of `source_device` would be written onto that same
    device (2026-09-23 review): e.g. a black-port drive, write-unlocked and
    mounted under /mnt, picked as both source and destination - dc3dd would
    write the image into the filesystem it is reading, corrupting the
    evidence and growing without end."""
    name = disk_name_for_path(dest_path)
    return bool(name) and name == os.path.basename(source_device or '')


def is_system_disk(path_str):
    """True if path_str is the station's own system disk or one of its
    partitions (2026-09-23). Found live: /api/start_imaging and
    /api/start_ddrescue accepted /dev/mmcblk0 - the Pi's own boot SD card -
    because it matches the whole-disk whitelist. Imaging it only reads, but
    a Live Collection USB build WRITES to its target device, and nothing on
    this station ever has a legitimate reason to target its own system disk."""
    if not path_str:
        return False
    base = os.path.basename(path_str)
    for disk in system_disk_names():
        if base == disk or (base.startswith(disk) and _PARTITION_RE.match(path_str)):
            return True
    return False


def is_valid_block_device(path_str):
    """Whitelist check for whole-disk device paths (no partitions, no shell
    metacharacters) - never the station's own system disk."""
    return bool(path_str) and bool(_DEVICE_RE.match(path_str)) and not is_system_disk(path_str)

def is_valid_block_device_or_partition(path_str):
    """Whole-disk OR one-partition device path - originally BitLocker-unlock-
    specific (BitLocker most commonly encrypts a single partition, but some
    BitLocker-To-Go USB media format the whole device with no partition
    table at all, so both forms were accepted), generalized here now that
    Live Device Preview needs the exact same "whole disk or partition"
    check. Moved out of routes/acquisition.py rather than kept as a second,
    independent copy of the same regex - see is_valid_bitlocker_source()
    there, now a thin alias onto this function."""
    return (bool(path_str) and (bool(_DEVICE_RE.match(path_str)) or bool(_PARTITION_RE.match(path_str)))
            and not is_system_disk(path_str))

# --- USB physical port classification (Raspberry Pi 4B hardware, 2026-09-05) ---
# Real finding: this station's write-blocker toggle and the Live Collection
# USB build both need to know whether a whole-disk device is physically in
# one of the station's 2 blue (USB 3.0) ports or one of the 2 black
# (USB 2.0) ports - the design decided on is that the 2 blue ports stay
# evidence-only, permanently write-blocked with NO software override at all
# (not even the toggle), while the 2 black ports are the only ones this
# app's own code is ever allowed to write-unlock (for a Live Collection USB
# build's destination drive, or a manual "unlock this to write an image
# out to it" use of the toggle). This does NOT change what the udev write-
# block rule does on connect - every port still forces a freshly-connected
# drive read-only immediately, on all 4 ports, unconditionally. This only
# gates whether this app's own software is *permitted* to flip it back.
#
# The tricky part, confirmed empirically (not assumed from generic Pi
# documentation): the Pi 4B's 4 rear USB ports all share ONE physical xHCI
# controller chip (VL805), which Linux exposes as two SEPARATE logical
# buses - a USB-2.0-compatible bus and a SuperSpeed bus - depending on what
# speed the plugged-in device actually negotiates, not which physical port
# it's in. A cheap/slow drive in a blue port still shows up on the 2.0-
# compat bus, identically to a drive in a black port - so checking the bus
# number alone is NOT sufficient to tell blue from black.
#
# What IS reliable: the SuperSpeed bus's own root hub is, by this board's
# fixed wiring, only ever reachable from the 2 blue ports at all (the
# black ports have no SuperSpeed wiring whatsoever) - so anything on that
# bus is unconditionally blue. And the USB-2.0-compat bus's own internal
# 4-port hub has a genuinely stable per-physical-port sub-port index,
# confirmed live by moving one real drive through all 4 ports in turn and
# reading back its sysfs path each time:
#   top blue    -> /usb1/1-1/1-1.1/...
#   bottom blue -> /usb1/1-1/1-1.2/...
#   top black   -> /usb1/1-1/1-1.3/...
#   bottom black -> /usb1/1-1/1-1.4/...
# i.e. sub-ports 1-2 are the blue pair, 3-4 are the black pair. This is a
# fixed hardware fact for this board model, not something that changes per
# boot or per device - but IS specific to the Pi 4B; a different Pi model
# would need its own empirical re-verification before trusting this.
USB_BLACK_SUBPORTS = {'3', '4'}
# Requires the SAME sub-port digit to reappear immediately afterward
# followed by a colon (the real "N:1.0" interface-descriptor segment a
# device plugged directly into that port always has, e.g.
# ".../1-1.3/1-1.3:1.0/..."). A device behind an intermediate hub adds an
# extra numbered segment instead (".../1-1.3/1-1.3.1/1-1.3.1:1.0/..."),
# which fails this exact reappear-then-colon check on purpose - a plain
# "digit followed by / or :" check would have matched that shape too
# (a real mistake caught by this file's own test suite before it shipped),
# since both shapes have a "/" right after the first "1-1.N".
_USB1_SUBPORT_RE = re.compile(r'/usb1/1-1/1-1\.([1-4])/1-1\.\1:')

def describe_usb_port(device_path):
    """Richer companion to classify_usb_port() (below, now a thin wrapper
    over this) - for the Drive Management port diagram, which wants to
    know not just the color but the SPECIFIC one of the 4 physical ports,
    so it can highlight the right slot rather than just the right color.

    Returns None for an invalid device path (same as classify_usb_port());
    otherwise a dict: {'color': 'blue'|'black'|'unknown',
    'port_index': '1'|'2'|'3'|'4'|None}.

    port_index is only ever populated via bus1's own sub-port number - the
    one this file's own live testing (2026-09-05) actually confirmed for
    all 4 physical ports. A device that happens to negotiate genuine
    SuperSpeed shows up on bus2 instead (see classify_usb_port()'s own
    docstring for why bus2 is unconditionally 'blue' regardless), but
    which of bus2's own root ports corresponds to which specific physical
    connector was never itself confirmed - no genuine SuperSpeed-capable
    drive was available during that verification pass - so port_index
    stays None in that case even though color is still confidently
    'blue'. Never guess a specific slot from unconfirmed data."""
    if not is_valid_block_device(device_path):
        return None
    try:
        real_path = os.path.realpath(f"/sys/class/block/{os.path.basename(device_path)}")
    except Exception:
        return {"color": "unknown", "port_index": None}
    if not real_path or real_path == f"/sys/class/block/{os.path.basename(device_path)}":
        return {"color": "unknown", "port_index": None}  # no such device
    if "/usb2/" in real_path:
        return {"color": "blue", "port_index": None}
    m = _USB1_SUBPORT_RE.search(real_path)
    if not m:
        return {"color": "unknown", "port_index": None}
    digit = m.group(1)
    color = "black" if digit in USB_BLACK_SUBPORTS else "blue"
    return {"color": color, "port_index": digit}

def classify_usb_port(device_path):
    """'blue' | 'black' | 'unknown' for a whole-disk device path, per the
    empirically-verified Pi 4B port mapping above. Fails closed: anything
    that can't be confidently classified - a different Pi model, a device
    behind an intermediate hub (an extra path segment breaks the anchored
    regex on purpose), an unreadable sysfs symlink - returns 'unknown', and
    every real caller of this function treats 'unknown' exactly like
    'blue' (refuse to write-unlock), never like 'black' (permit it)."""
    info = describe_usb_port(device_path)
    return info["color"] if info is not None else None

def log_chain_of_custody(action, details=None, source_ip=None, user=None):
    # source_ip/user let a caller running outside the original Flask request
    # context (e.g. a background daemon thread, like network config's
    # delayed auto-revert) supply values captured earlier - request/g are
    # request-context-bound proxies and raise RuntimeError if touched from a
    # thread that never received the HTTP request itself. Every existing
    # call site is unaffected (both default to None, falling back to the
    # live request context exactly as before).
    #
    # The fallback here must go through _effective_client_ip(), not a raw
    # request.headers.get('X-Real-IP', request.remote_addr) read - that
    # unconditional-trust pattern is exactly the critical, already-fixed
    # kiosk-bypass/lockout-evasion vulnerability described in core/auth.py's
    # _effective_client_ip() docstring (X-Real-IP is only trustworthy once
    # remote_addr is confirmed loopback), and this logging helper had never
    # been updated to use the fixed helper - every unattributed chain-of-
    # custody entry station-wide was still recording a spoofable IP on any
    # station where the optional TLS/nginx setup was skipped.
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details or {},
        "source_ip": source_ip if source_ip is not None else (_effective_client_ip() if request else None),
        "user": user if user is not None else getattr(g, 'forensic_user', None),
    }
    with coc_log_lock:
        try:
            os.makedirs(os.path.dirname(COC_LOG_FILE), exist_ok=True)
            with open(COC_LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Error writing chain-of-custody log: {e}")

def safe_path(path_str):
    """
    Resolve a user-supplied path and confirm it stays within EVIDENCE_ROOT.

    Prevents path traversal (../..), absolute-path escapes, and symlink
    tricks in every endpoint that takes a path from the client (file
    browser, copy/delete, report load/save, hash verification, PDF export,
    dd/ddrescue acquisition source & destination).
    Returns the resolved absolute path, or None if it escapes the sandbox.
    """
    if not path_str:
        return None
    resolved = os.path.realpath(path_str)
    if resolved == EVIDENCE_ROOT or resolved.startswith(EVIDENCE_ROOT + os.sep):
        return resolved
    return None

_CASE_SLUG_INVALID_RE = re.compile(r'[^A-Za-z0-9_-]+')

def sanitize_case_slug(raw):
    """
    Turn an examiner-typed case number into a filesystem-safe folder name.
    Whitelist-based (like _DEVICE_RE elsewhere) rather than blacklisting bad
    characters, so this can never be tricked into producing '..' or an
    absolute-path-looking result. Returns None if nothing usable is left.
    """
    if not raw:
        return None
    slug = _CASE_SLUG_INVALID_RE.sub('_', raw.strip())
    slug = re.sub(r'_+', '_', slug).strip('_')
    return slug[:80] or None

def case_consolidated_path(dest_path):
    """Returns the case's consolidated-file path if `dest_path` IS a case
    folder root (checked directly, no ancestor walk - matches how the
    frontend sends `destination` as the case folder itself verbatim once a
    case is active), else None.

    Runs `dest_path` through safe_path() itself - this function is used
    throughout the app (core/jobs.py, core/case_index_db.py,
    routes/reporting.py, routes/image_browser.py, routes/file_explorer.py)
    as *the* gate for "is this a legitimate case folder," including several
    call sites that pass a raw, client-supplied `case_folder` straight here
    with no sandboxing of their own - found during the 2026-08-22 security
    audit to be trusting only os.path.isdir() + a marker-file-name match,
    neither of which implies the path is anywhere near EVIDENCE_ROOT. A
    downstream function (case_index_db_path()) happened to safe_path() its
    own derived path anyway, which is what kept this from being directly
    exploitable - but that was two functions incidentally agreeing, not a
    designed guarantee, and it left a directory-listing side channel open
    in at least one caller before that downstream check ever ran. Every
    real case folder already lives under EVIDENCE_ROOT by construction
    (create_case()), so this can never reject a legitimate one."""
    resolved = safe_path(dest_path)
    if not resolved or not os.path.isdir(resolved):
        return None
    slug = os.path.basename(resolved.rstrip(os.sep))
    case_file = os.path.join(resolved, f"{slug}_case.json")
    return case_file if os.path.isfile(case_file) else None

# --- Per-case analysis index (SQLite) extension/category classification ---
# A single small, queryable index living inside the case folder - what makes
# Autopsy-style "File Views" (By Extension counts, Deleted Files, Keyword
# Hits broken out per category) possible without re-walking every indexed
# image on every File Explorer load. Path derivation for the DB itself lives
# in core/case_index_db.py; this module only owns the extension/category
# classification used both there and by report attachment embedding.
EXTENSION_CATEGORY_MAP = {
    'jpg': 'images', 'jpeg': 'images', 'png': 'images', 'gif': 'images', 'bmp': 'images',
    'webp': 'images', 'tif': 'images', 'tiff': 'images', 'heic': 'images', 'heif': 'images',
    'mp4': 'videos', 'mov': 'videos', 'avi': 'videos', 'mkv': 'videos', 'wmv': 'videos',
    'flv': 'videos', 'm4v': 'videos', '3gp': 'videos',
    'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'm4a': 'audio', 'aac': 'audio', 'ogg': 'audio',
    'zip': 'archives', 'rar': 'archives', '7z': 'archives', 'tar': 'archives', 'gz': 'archives', 'bz2': 'archives',
    'pdf': 'documents', 'doc': 'documents', 'docx': 'documents', 'xls': 'documents', 'xlsx': 'documents',
    'ppt': 'documents', 'pptx': 'documents', 'txt': 'documents', 'rtf': 'documents', 'csv': 'documents',
    'exe': 'executables', 'dll': 'executables', 'bat': 'executables', 'sh': 'executables',
    'bin': 'executables', 'msi': 'executables', 'apk': 'executables',
}
FILE_VIEW_EXTENSION_CATEGORIES = ('images', 'videos', 'audio', 'archives', 'documents', 'executables', 'other')

_CASE_ROLE_BACKUP_SUFFIXES = ('.pre_consolidation_backup', '.pre_restore_backup')
_CASE_ROLE_REPORT_SUFFIXES = (
    '_case.json', '_case.pdf', '_case.html', '_case_index.db',
    # The examiner-decision backup sidecar (2026-09-20) - same role as the
    # index it protects, so it is classified with it rather than showing up
    # as unexplained evidence in the case's own file views.
    '_case_tags.json',
    '_case.json.sha256', '_case.pdf.sha256', '_case.html.sha256',
    '_report.json',  # legacy per-job report (pre-consolidated-schema cases)
)
_CASE_ROLE_ANALYSIS_LOG_RE = re.compile(
    r'(_hash_manifest_\w+\.txt|_hashdeep_\w+_manifest\.txt|_triage_scan_report\.txt|_vol3_\w+\.json'
    r'|_device_timestamps\.json'
    r'|_(aleapp|ileapp)_output|_sqlite_dissect_recovery|_apk_analysis\.json|_bugreport_parsed\.json'
    r'|_ios_crash_reports|_mft_analysis\.json|_usnjrnl_parsed\.json|_thumbcache_extracted'
    r'|_android_backup_extracted'
    # Android pull manifests (routes/mobile.py, 2026-09-04) - installed-app
    # inventory, configured accounts, and the notification-metadata snapshot
    # captured automatically alongside device_timestamps.json above.
    r'|_app_inventory\.json|_accounts\.json|_notifications\.json'
    # Companion-app SMS extraction manifest (routes/mobile.py, 2026-09-04) -
    # the device-modification disclosure + extracted SMS summary.
    r'|_companion_sms_extraction\.json'
    r'|^live_collection_import_\d{8}_\d{6})$')
_CASE_ROLE_BUNDLE_RE = re.compile(r'_case_bundle_\d{8}-\d{6}\.zip$')

# Directory names safe to prune out of ANY recursive walk over the evidence
# store, station-wide - not case-scoped, since these can legitimately sit
# loose at the evidence root too, not just inside one case folder. Never a
# case folder (no case marker ever lives inside one) and can be large
# enough (thousands of tiny carved files, or a NAS's own internal recycle
# bin) that walking into one needlessly is a real, measurable cost,
# especially over slow/network-attached storage - confirmed live
# (2026-09-05): list_case_folders()'s own real-world slowdown on the
# deployed station traced in part to exactly this pattern (loose recovery-
# tool test output sitting directly under the evidence root). Originally
# only routes/reporting.py's own _discover_case_files() had this exact
# recovery-tool-suffix check (as ATTACHMENT_DISCOVERY_SKIP_DIRS, for a
# narrower reason - "thousands of tiny files are impractical to list
# individually as attachments") - consolidated here once list_case_folders()
# needed the identical pruning logic for a different reason (avoiding
# needless NFS round-trips), so the one real pattern isn't duplicated and
# risking drift between two copies.
BULK_TOOL_OUTPUT_SKIP_DIRS = {
    'RECOVERED_FILES',  # extundelete's fixed output dir name
    # Common NAS/filesystem-internal trash folders - never case data,
    # never worth walking into, and can genuinely be large on a real NAS.
    '#recycle', '@Recycle', '@recycle', '.@__thumb',
}
BULK_TOOL_OUTPUT_SKIP_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')
# "..._photorec.1", "..._photorec.9" - a re-run's output sitting next to the
# first. Anchored to the end and digits-only so a real case folder whose name
# genuinely ends in a dotted component is never stripped into a false match.
_NUMERIC_RERUN_SUFFIX_RE = re.compile(r'\.\d+$')

def is_bulk_tool_output_dir(name):
    """True for a directory name matching a known recovery-tool bulk
    carved-file output convention, or a NAS/filesystem-internal trash
    folder - safe to prune from any walk over the evidence store, since
    neither can ever be a real case folder (no case marker) or contain one
    nested inside it.

    A trailing ".<digits>" is stripped before the suffix check (2026-09-16).
    A re-run writes its output alongside the first as "<base>_photorec.1",
    ".2" and so on, and the bare endswith() missed every one of them -
    measured on the deployed station, nine such directories held 4,501 of the
    8,737 file entries the case-list walk was reading on EVERY open of the
    Case Manager, which took 13-23 seconds showing only "Loading...". They
    are the same carved output the un-suffixed name already prunes."""
    if name in BULK_TOOL_OUTPUT_SKIP_DIRS:
        return True
    base = _NUMERIC_RERUN_SUFFIX_RE.sub('', name)
    return base.endswith(BULK_TOOL_OUTPUT_SKIP_SUFFIXES)

def classify_case_role(name):
    """Best-effort classification of a filename (or, for the folder-shaped
    kinds below, a directory name) as one of this app's own generated
    case-artifact kinds - 'report' (the case JSON/PDF/HTML export
    and their .sha256 sidecars, the per-case SQLite index, a legacy per-job
    report), 'analysis_log' (a hash-manifest report, a triage-scan report,
    a Volatility3 memory-forensics plugin result, an android_pull's
    captured-on-device-timestamps manifest, an ALEAPP/iLEAPP mobile-artifact-parser output
    folder, a Thumbcache thumbnail-extraction output folder, an Android Backup
    File (.ab) full-extraction output folder, or a Live
    Collection USB import folder - the same "derived/analysis output
    living in its own folder" shape ALEAPP/iLEAPP already established),
    'geolocation' (a
    .kml), 'backup' (a pre-consolidation/pre-restore snapshot), 'case_bundle'
    (a Case Bundle Export zip - matched by its own timestamped naming
    pattern, NOT the plain .zip extension, which classify_extension()
    already treats as a generic 'archives' file an examiner might have
    added themselves), or None for anything that isn't a recognized
    artifact kind (real evidence, an examiner-added note, etc.).
    Deliberately narrow and pattern-matched against this app's own actual
    naming conventions, not a general file-type classifier - see
    classify_extension() above for that. Used to visually group these
    files in File Explorer's folder tree (case_role dividers, separate
    from actual case data) and to auto-tag them into the per-case analysis
    index at the moment each is generated.
    """
    lower = name.lower()
    if _CASE_ROLE_BUNDLE_RE.search(name):
        return 'case_bundle'
    if lower.endswith(_CASE_ROLE_BACKUP_SUFFIXES):
        return 'backup'
    if name == 'case_info.json' or lower.endswith(tuple(s.lower() for s in _CASE_ROLE_REPORT_SUFFIXES)):
        return 'report'
    if _CASE_ROLE_ANALYSIS_LOG_RE.search(name) or lower.endswith('.log'):
        return 'analysis_log'
    if lower.endswith('.kml'):
        return 'geolocation'
    return None

# --- Where an acquisition event actually wrote its output ------------------
#
# An event's acquisition_parameters record their output under one of THREE
# different key names, depending on which tool wrote it:
#
#   output_image_path      - a raw disk image (dc3dd/dcfldd/dd/E01/AFF/
#                            ddrescue, image_conversion)
#   output_destination     - mobile pulls, bugreports, companion-app
#                            extraction, recovery tools
#   output_container_path  - Logical Acquisition, Live Collection import
#
# Every case-wide reader has to resolve that, and before 2026-09-16 three of
# them did it independently and each got a DIFFERENT subset right:
# _collect_case_timeline() handled all three, compute_case_analysis_coverage()
# handled two (silently dropping every logical acquisition and Live Collection
# import), and Verify All Evidence handled one (silently skipping those AND
# every mobile acquisition - measured on the deployed station as 10 of 13
# completed acquisitions in one case, and 3 of 3 in another, reported to the
# examiner as "not verifiable by this tool"). These two helpers are the one
# shared answer, so a fourth reader can't invent a fourth subset. This is
# exactly the "two independent copies" trap CLAUDE.md documents, with three.
def acquisition_output_location(params):
    """Returns (path, kind) for where an acquisition event wrote its output -
    kind is 'image' for a single acquired image file, 'directory' for anything
    written into a destination/container folder, and (None, None) when the
    event records no output location at all (e.g. a companion-app extraction).

    Image wins over destination when both are recorded: a raw acquisition sets
    output_destination to the PARENT folder as well, and it's the image itself
    that is the evidence. Callers still confirm the path exists and is the
    shape they expect - this resolves the recorded value, it does not stat it.
    """
    params = params or {}
    image_path = params.get('output_image_path')
    if image_path:
        return image_path, 'image'
    dest = params.get('output_destination') or params.get('output_container_path')
    if dest:
        return dest, 'directory'
    return None, None

# A case an examiner has marked finished. New evidence landing in one is
# almost always a mis-set destination rather than an intention: measured live
# (2026-09-16) on this app's own station, a case could be Archived and still
# be the ACTIVE case afterwards, with no badge anywhere, its folder pre-filled
# as the destination on every tab - and a triage scan ran to completion and
# wrote a second acquisition event into it with no warning at any point.
# Nothing anywhere read case_status except the Active-Cases count tile.
CASE_STATUSES_CLOSED_TO_NEW_WORK = ('Closed', 'Archived')

def case_status_blocking_new_work(dest_path, _read_json=None):
    """Returns the case's status string when `dest_path` is (or is inside) a
    case folder whose status is one of CASE_STATUSES_CLOSED_TO_NEW_WORK, else
    None. None is also the answer for a destination that isn't in a case at
    all - a job run with no active case is a supported workflow, not something
    to block.

    Walks up from dest_path so a destination pointed at a SUBFOLDER of a
    finished case is caught too, bounded by EVIDENCE_ROOT so it can never
    climb past the evidence store. Any read/parse failure returns None: this
    is a guard against a mistake, and an unreadable case file must not become
    a second way to be unable to work (core/jobs.py's own CaseFileUnreadable
    handling is the place that surfaces that, deliberately).

    Verification, case notes, report and bundle exports are all legitimate
    work ON a finished case and deliberately do NOT consult this - it gates
    starting a new acquisition/recovery/extraction, nothing else.
    """
    reader = _read_json or _read_case_status_json
    try:
        current = os.path.abspath(dest_path or '')
        root = os.path.abspath(EVIDENCE_ROOT)
    except (TypeError, ValueError):
        return None
    if not current or not path_is_within(current, root):
        return None
    while True:
        marker = case_consolidated_path(current)
        if marker:
            status = reader(marker)
            return status if status in CASE_STATUSES_CLOSED_TO_NEW_WORK else None
        if current == root:
            return None
        parent = os.path.dirname(current)
        if parent == current:  # filesystem root, belt-and-braces against a loop
            return None
        current = parent

def _read_case_status_json(marker_path):
    try:
        with open(marker_path, 'r') as f:
            return (json.load(f) or {}).get('case_status')
    except (OSError, ValueError):
        return None

def path_is_within(candidate, root):
    """True when `candidate` IS `root` or sits underneath it. The trailing
    separator matters: without it, a sibling that merely shares a name prefix
    ("/mnt/CASE-12" against root "/mnt/CASE-1") would read as being inside.
    Lives here because two unrelated readers need it - Analysis Coverage, to
    credit a parse aimed at a subfolder of an evidence item to that item, and
    the case timeline, to refuse to walk a destination that contains the case
    folder itself."""
    if not candidate or not root:
        return False
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip(os.sep) + os.sep)

def acquisition_verification_target(params):
    """Returns (path, scope) for the single file whose hash an acquisition
    recorded in computed_verification_hashes, so it can be re-hashed and
    compared - or (None, None) when the event anchored its hash to nothing
    re-checkable.

    scope says WHAT a match actually proves, because that differs by tool and
    an examiner must not be told more than was checked:

      'image'    - the acquired image file itself; a match covers the evidence.
      'manifest' - Logical Acquisition and Live Collection import both hash
                   their own manifest.json (see execution_worker_logical's
                   "Container-level hash" comment), which records every copied
                   file's own hash. A match proves the RECORD is intact; it
                   does not re-read the copied files themselves.
      'file'     - a destination that is itself a single file rather than a
                   folder (an android_bugreport .zip, a companion-extraction
                   .json).

    A destination that names a folder yields (None, None): there is no one
    file to re-hash, and inventing one (hashing a directory walk) would not
    match whatever was recorded at acquisition time anyway.
    """
    params = params or {}
    image_path = params.get('output_image_path')
    if image_path:
        return image_path, 'image'
    manifest_path = params.get('manifest_path')
    if manifest_path:
        return manifest_path, 'manifest'
    dest = params.get('output_destination') or params.get('output_container_path')
    if dest and os.path.isfile(dest):
        return dest, 'file'
    return None, None


def classify_extension(name):
    """Returns (category, extension) for a filename - extension is the bare,
    lowercased suffix with no leading dot ('' if none); category is one of
    FILE_VIEW_EXTENSION_CATEGORIES, defaulting to 'other' for anything not in
    EXTENSION_CATEGORY_MAP. Deliberately not exhaustive - documented as a
    reasonable, extensible starting set, not a claim of complete coverage."""
    ext = os.path.splitext(name)[1].lstrip('.').lower()
    return EXTENSION_CATEGORY_MAP.get(ext, 'other'), ext


def format_epoch(ts):
    """Formats a Unix timestamp as "%Y-%m-%d %H:%M:%S", or None for a falsy/
    missing/unrepresentable one - never guesses. Moved here from routes/
    file_explorer.py (2026-08-29) once routes/reporting.py's own folder-
    based timeline collection needed the exact same formatting a second
    routes/*.py module can't import from another; this is the shared home.

    time.localtime(None) silently defaults to the CURRENT time rather than
    raising - a falsy/missing timestamp must be rejected explicitly here,
    not left to the caller to remember to guard against, or a genuinely-
    unknown timestamp would render as "right now" instead of "Unknown"."""
    if not ts:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OSError, OverflowError, ValueError):
        return None


def closed_case_refusal(*paths):
    """First Closed/Archived status found for any of `paths` (an output folder,
    a case folder...), else None - one call for routes that take both a
    destination and a separate case_folder (2026-09-23). Same semantics as
    case_status_blocking_new_work(), which it simply applies to each path."""
    for path in paths:
        status = case_status_blocking_new_work(path) if path else None
        if status:
            return status
    return None
