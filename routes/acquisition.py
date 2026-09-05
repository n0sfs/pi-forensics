"""Acquisition: BitLocker unlock/mount machinery, the generic dc3dd/
dcfldd/plain-dd/E01/AFF acquisition workers, ddrescue, and the single
shared job's drives/smart_check/toggle_write_block/stop/progress routes.

Largest of the "early group" blueprints - done once the worker+job-state
pattern (mobile, recovery) has already been proven twice on smaller
files. Not fully contiguous in the original app.py: /api/drives and
/api/smart_check sit right before a large, unrelated Settings-owned
network-mounting block, and /api/toggle_write_block/the bitlocker
cluster/start_imaging/start_ddrescue/stop_imaging/progress resume after
it - all pulled together here since they're one functional area
regardless of where they physically sat in the original file.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import re
import glob
import json
import time
import uuid
import shutil
import hashlib
import tempfile
import subprocess
import threading
import signal

from flask import Blueprint, jsonify, request, g

from core.auth import requires_auth, requires_permission
from core.paths import (
    safe_path, log_chain_of_custody, is_valid_block_device,
    is_valid_block_device_or_partition, _DEVICE_RE, classify_usb_port,
    describe_usb_port,
)
from core.config import (
    EVIDENCE_ROOT, INSTALL_DIR, ALLOWED_HASH_ALGOS, load_hash_list_sets, get_hash_lists,
    detect_pi_model, usb_port_diagram_supported,
)
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job,
    get_active_proc, clear_active_proc,
    get_upstream_proc, clear_upstream_proc,
    _stream_subprocess, reclaim_ownership,
    build_report_target, write_initial_report, _write_report,
    _SERVICE_ACCOUNT_NAME,
    begin_suppress_active_false, end_suppress_active_false,
)
from core.decrypted_sources import register_decrypted_source, unregister_decrypted_source
from core.tsk_utils import classify_image_profile
from core.live_collection_utils import (
    PIF_COLLECT_LABEL, UAC_DEFAULT_PROFILE,
    check_existing_collection_volume, wipe_and_format_device,
    mount_collection_partition, unmount_collection_partition,
    discover_collection_runs, unmount_all_partitions, run_timestamp_to_epoch,
)
from core.case_index_db import _auto_tag_case_artifact, _record_parsed_artifacts
from core.live_collection_results_utils import (
    parse_windows_collector_run, parse_unix_collector_run, build_hash_list_match_records,
)
# Guided Workflow automation Tier 2 (2026-08-27) - the one deliberate,
# documented exception to this project's own established "every routes/*.py
# Blueprint only ever imports from core/, never from another routes/*.py
# file" convention (see routes/auto_analyze.py's own module docstring for
# why that convention exists and was upheld once already). Moving Auto
# Analyze's actual step-sequence orchestrator into core/ was considered and
# rejected: it - and the 8 step functions it dispatches through - are
# deeply Blueprint-local, calling many private routes/image_browser.py
# helpers (_tsk_extract_to_temp, _run_hash_manifest_body,
# parse_registry_hive_file, etc.) that aren't in core/ and would need a
# large, disproportionately risky refactor to move for this one caller.
# One-directional, not circular: routes/image_browser.py has no import of
# routes/acquisition.py (confirmed via a full-repo grep before adding this),
# and app.py already imports routes.acquisition before routes.image_browser,
# so Python resolves this import-order dependency the moment it's first
# needed with no cycle.
from routes.image_browser import (
    execution_worker_auto_analyze_image,
    AUTO_ANALYZE_WINDOWS_DEFAULT_STEPS, AUTO_ANALYZE_LINUX_DEFAULT_STEPS,
)

acquisition_bp = Blueprint('acquisition', __name__)


# --- Live Collection USB: the app's first-ever deliberate write to a raw
# block device it doesn't already treat as evidence (every other USB
# device is forced read-only the instant it's plugged in - a udev rule,
# plus list_drives() below re-forcing --setro on every device it
# enumerates). This dict/lock is what lets exactly one device, for
# exactly the duration of the "Build Live Collection USB" job, be
# temporarily exempted from that auto-relock.
#
# A naive "check a dict, then call blockdev" on both sides still races: a
# list_drives() call already past its dict-check could land its --setro
# call *after* the build job has already flipped to --setrw, corrupting
# an in-progress write. The fix is that BOTH sides do their entire
# decision-plus-syscall under this ONE lock - list_drives()'s per-device
# step becomes "with device_write_lock: if device in
# active_write_unlocked_devices: skip; else: blockdev --setro"; the build
# job's unlock step becomes "with device_write_lock:
# active_write_unlocked_devices[device] = {...}; blockdev --setrw".
# Whichever side gets the lock first fully finishes before the other side
# even reads the registry, closing the window a plain dict-check leaves
# open. Mirrors the exact shape of Live Device Preview's
# device_previews_lock/active_device_previews (routes/image_browser.py) -
# a different lock, deliberately, not job_lock (which update_job()'s own
# frequent progress writes would contend for no reason).
device_write_lock = threading.Lock()
active_write_unlocked_devices = {}  # device_path -> {unlocked_at}


def _relock_device_for_list_drives(device_path):
    """Called by list_drives() for each enumerated USB disk - the race-
    safe replacement for its old unconditional `blockdev --setro`. Skips
    the relock entirely (under the same lock a build job's own unlock
    step uses) if this exact device is currently, legitimately unlocked
    by this app's own Live Collection USB build job."""
    with device_write_lock:
        if device_path in active_write_unlocked_devices:
            return
        try:
            subprocess.run(["sudo", "/usr/sbin/blockdev", "--setro", device_path], capture_output=True)
        except Exception:
            pass


def _unlock_device_for_write(device_path):
    """The one function that ever flips a whole-disk device writable -
    shared by the Live Collection USB build job and the manual Drive
    Management toggle (toggle_write_block(), below), so the black-port-
    only rule and the exemption-registry update can never drift between
    the two call sites.

    Real, live-verified design decision (2026-09-05): the station's 2 blue
    (USB 3.0) ports stay evidence-only and permanently write-blocked, with
    NO software path to unlock them at all - not the toggle, not a Live
    Collection build, regardless of confirmation dialogs or who asks. Only
    the 2 black (USB 2.0) ports, reserved for utility media, are ever
    eligible - see classify_usb_port()'s own docstring in core/paths.py for
    exactly how that's determined and why it fails closed. This does NOT
    touch the udev write-block rule itself - every port still forces a
    freshly-connected drive read-only unconditionally; this only gates
    whether this app's own code is ever permitted to reverse that.

    Registers the exemption and flips the device writable, both under
    device_write_lock, so a concurrent list_drives() call can never land
    its own --setro in between (the same race-avoidance this dict/lock
    already existed for). Returns (success: bool, error: str | None) -
    a caller must check this and abort before doing anything destructive
    if it's False, rather than assuming the unlock always succeeds the way
    this function used to (fire-and-forget, pre-2026-09-05)."""
    port_class = classify_usb_port(device_path)
    if port_class != "black":
        return False, (
            f"Write-unlocking is only permitted for a drive in one of this station's 2 standard "
            f"(black) USB ports - reserved for utility media like a Live Collection USB build, never "
            f"for evidence. {device_path} is not confirmed to be in one of those ports (detected: "
            f"{port_class or 'unrecognized'}). The 2 USB 3.0 (blue) ports always stay write-blocked "
            f"and this app has no way to unlock them, regardless of what's clicked or confirmed."
        )
    with device_write_lock:
        active_write_unlocked_devices[device_path] = {"unlocked_at": time.time()}
        res = subprocess.run(["sudo", "/usr/sbin/blockdev", "--setrw", device_path], capture_output=True, text=True)
    if res.returncode != 0:
        with device_write_lock:
            active_write_unlocked_devices.pop(device_path, None)
        return False, res.stderr.strip() or "blockdev --setrw failed"
    return True, None


def _relock_device_after_write(device_path):
    """Always-safe teardown - re-locks the device and clears the
    exemption. Called from the build job's own `finally:` block on every
    exit path (success/Stop/exception), so the app's default-safe posture
    is restored regardless of how the job ended.

    Also explicitly relocks device_path + "1" (the partition) - found live
    (2026-09-03) that a completed build otherwise left the partition itself
    writable indefinitely: this app's write-block udev rules independently
    lock the whole disk and each partition on their OWN "add" uevent, so
    core.live_collection_utils.wipe_and_format_device() has to explicitly
    unlock the freshly-created partition before mkfs.exfat can write to it
    (see that function's own comment for the full story) - but nothing
    naturally re-locks that same partition afterward, since it doesn't get
    a second "add" event just from being mounted/copied to. Relocking it
    here too, alongside the whole disk, closes that gap."""
    with device_write_lock:
        active_write_unlocked_devices.pop(device_path, None)
        subprocess.run(["sudo", "/usr/sbin/blockdev", "--setro", device_path], capture_output=True)
        subprocess.run(["sudo", "/usr/sbin/blockdev", "--setro", device_path + "1"], capture_output=True)


def _live_collection_startup_reconciliation():
    """One-shot check at process start. Unlike every other 'leaked state'
    reconciliation precedent in this app (LUKS's loop-device check, Live
    Device Preview's orphan-ACL check - both deliberately log-only, never
    auto-act, since a legitimate unrelated cause could theoretically
    exist for either), this one auto-remediates: at a fresh process
    start, active_write_unlocked_devices is always empty, so any
    /dev/sd[a-z] that isn't currently read-only is something that, by
    this app's own design, should never legitimately happen - relocking
    it is always safe (never destroys data) and closes a real forensic-
    integrity gap (an unexpectedly-writable USB left in the chassis after
    a crash) rather than just disclosing it. Still logs a chain-of-
    custody entry recording that it happened, so there's a record even
    though it self-healed. The systemd unit's Restart=always/RestartSec=3
    means this runs within seconds of any crash."""
    try:
        candidates = sorted(set(glob.glob('/dev/sd[a-z]')))
    except Exception:
        return
    for device_path in candidates:
        if not is_valid_block_device(device_path):
            continue
        try:
            chk = subprocess.run(["sudo", "/usr/sbin/blockdev", "--getro", device_path],
                                  capture_output=True, text=True, timeout=10)
        except Exception:
            continue
        if chk.returncode != 0:
            continue
        if chk.stdout.strip() == '1':
            continue  # already read-only, nothing to reconcile
        subprocess.run(["sudo", "/usr/sbin/blockdev", "--setro", device_path], capture_output=True)
        log_chain_of_custody(
            "live_collection_device_auto_relocked_at_startup",
            {"device": device_path,
             "note": "Found writable at process startup, not explained by this process's own state "
                     "(active_write_unlocked_devices is always empty at a fresh start) - likely left "
                     "unlocked by a prior crash mid-build. Automatically re-locked."},
            source_ip=None, user="system-startup",
        )

threading.Thread(target=_live_collection_startup_reconciliation, daemon=True).start()


# Thin alias - the actual "whole disk or partition" check now lives in
# core/paths.py as is_valid_block_device_or_partition(), shared with Live
# Device Preview (routes/image_browser.py), which needs the identical
# check. Kept as a distinctly-named alias here (rather than replacing every
# call site below with the core.paths name directly) so this function's own
# name still documents *why* BitLocker unlock accepts a partition path, not
# just what the check does.
is_valid_bitlocker_source = is_valid_block_device_or_partition

# --- BitLocker: unlock an encrypted source via dislocker, so it can be
# imaged decrypted instead of as raw encrypted bytes. A dislocker mount
# exposes the decrypted volume as a single virtual file ("dislocker-file")
# inside a FUSE mountpoint - once mounted, that file is used as the
# acquisition `source` exactly like a real block device would be (dc3dd/
# dcfldd/ewfacquire/plain dd all just read from whatever path they're given,
# real device or regular file). Recording the recovery key itself as case
# documentation (separate from this unlock mechanism) is handled by
# start_imaging()/start_ddrescue()'s own bitlocker_key field - see the
# comment there for why that's stored in plaintext rather than encrypted at
# rest, unlike network-mount credentials.
DISLOCKER_MOUNT_ROOT = os.path.join(INSTALL_DIR, ".bitlocker_mounts")
bitlocker_lock = threading.Lock()
active_bitlocker_mounts = {}  # mount_id -> {mount_dir, device, source_path, unlocked_at}

def _list_device_partitions(device):
    """Real partitions of a whole-disk device via lsblk - JSON output, not
    parsed text, so a device/label containing unusual characters can't
    confuse column-based parsing."""
    if not is_valid_block_device(device):
        return []
    try:
        res = subprocess.run(
            ['lsblk', '-J', '-o', 'NAME,SIZE,FSTYPE,TYPE', device],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode != 0:
            return []
        data = json.loads(res.stdout)
        partitions = []
        for dev in data.get('blockdevices', []):
            for child in dev.get('children', []):
                if child.get('type') == 'part':
                    partitions.append({
                        "path": f"/dev/{child['name']}",
                        "size": child.get('size'),
                        "fstype": child.get('fstype'),
                    })
        return partitions
    except Exception:
        return []

def _detect_bitlocker(partition):
    """Best-effort BitLocker signature check via blkid - not authoritative
    (a wrong/no answer here doesn't block trying to unlock anyway), just a
    helpful hint in the UI before the examiner types in a recovery key."""
    if not is_valid_bitlocker_source(partition):
        return None
    try:
        res = subprocess.run(
            ['sudo', '/sbin/blkid', '-o', 'value', '-s', 'TYPE', partition],
            capture_output=True, text=True, timeout=10
        )
        fstype = res.stdout.strip()
        return {"fstype": fstype, "is_bitlocker": fstype.lower() == 'bitlocker'}
    except Exception:
        return {"fstype": None, "is_bitlocker": False}

def _detect_bitlocker_image(image_path, offset=0):
    """Best-effort BitLocker signature check for an already-acquired evidence
    image (or a specific partition's byte offset within it) - a direct
    read of the on-disk BitLocker boot-sector signature ("-FVE-FS-",
    replacing NTFS's normal "NTFS    " signature at the same location, byte
    3 of the boot sector) rather than shelling out to blkid. No sudo
    needed: unlike a live device, an evidence image file is already owned
    by this app's own unprivileged service account (reclaim_ownership()
    already handed it back after acquisition), so a plain read is enough."""
    validated = safe_path(image_path)
    if not validated or not os.path.isfile(validated):
        return None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return None
    try:
        with open(validated, 'rb') as f:
            f.seek(offset + 3)
            sig = f.read(8)
        return {"is_bitlocker": sig == b'-FVE-FS-'}
    except OSError:
        return {"is_bitlocker": False}

def _dislocker_unlock(source_path, recovery_key, offset=None):
    """Mounts a BitLocker-encrypted volume via dislocker, given a 48-digit
    recovery key (dashes optional - dislocker accepts either form).
    Two modes, selected by whether `offset` is given:
      - offset=None: `source_path` is a live device/partition path (the
        pre-acquisition "unlock before imaging" flow) - validated via
        is_valid_bitlocker_source().
      - offset=<int>: `source_path` is an already-acquired evidence image
        file, and the encrypted volume starts at the given byte offset
        within it (dislocker's own -O/--offset flag - needed for a
        multi-partition raw disk image, e.g. EFI + Recovery + an
        encrypted C: partition all in one .dd file). Validated via
        safe_path() like every other image-accepting route in this app,
        not is_valid_bitlocker_source() (which only recognizes /dev/*
        paths).
    Returns (success, mount_id_or_None, source_path_or_None,
    error_or_None). The mountpoint is entirely server-controlled (a fresh
    directory under DISLOCKER_MOUNT_ROOT, never a client-supplied path) -
    this is what lets _resolve_acquisition_source() below safely trust a
    `source` path later: only a path this function itself just created and
    registered can ever match an active_bitlocker_mounts entry."""
    if offset is None:
        if not is_valid_bitlocker_source(source_path):
            return False, None, None, "Invalid or unrecognized device/partition path."
    else:
        validated = safe_path(source_path)
        if not validated or not os.path.isfile(validated):
            return False, None, None, "Image file not found or outside the permitted evidence directory."
        source_path = validated
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            return False, None, None, "Invalid partition offset."

    recovery_key = (recovery_key or '').strip()
    if not recovery_key:
        return False, None, None, "Recovery key/password is required."

    original_source = source_path  # captured before the local `source_path` name gets reused below for the *decrypted* file's path

    os.makedirs(DISLOCKER_MOUNT_ROOT, exist_ok=True)
    mount_id = uuid.uuid4().hex
    mount_dir = os.path.join(DISLOCKER_MOUNT_ROOT, mount_id)
    os.makedirs(mount_dir, exist_ok=False)

    cmd = ["sudo", "/usr/bin/dislocker", "-V", original_source]
    if offset:
        cmd += ["-O", str(offset)]
    # -o allow_other (passed after -- as a FUSE-native option, per
    # dislocker's own --help: "-- end of program options, beginning of
    # FUSE's ones") is required so the resulting decrypted-file mount is
    # readable by this app's own unprivileged worker process, not just by
    # root (the mounting UID via sudo) - FUSE restricts a mount to the
    # mounting UID by default. This mirrors the exact same requirement and
    # fix already applied to this app's own sshfs network-mount feature
    # (routes/settings.py's SFTP mount, which passes allow_other with an
    # identical rationale comment) - user_allow_other is already enabled
    # system-wide in /etc/fuse.conf by install.py's SFTP-mounting setup, so
    # dislocker only needed this one flag added to actually benefit from it.
    # Without this, a successfully-unlocked volume would still fail the
    # moment anything tried to open() the decrypted file to browse it.
    cmd += [f"-p{recovery_key}", "--", "-o", "allow_other", mount_dir]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        return False, None, None, "dislocker timed out - the device may be unresponsive."
    except FileNotFoundError:
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        return False, None, None, "dislocker is not installed on this station. Run 'sudo apt-get install dislocker' first."

    decrypted_path = os.path.join(mount_dir, "dislocker-file")
    if res.returncode != 0 or not os.path.exists(decrypted_path):
        # dislocker's own FUSE mount can be left half-attached on failure -
        # try to clean it up either way before reporting the error. Plain
        # umount (not fusermount/fusermount3) works fine here since this
        # always runs as root via sudo already - the fusermount helper's
        # whole purpose is letting an *unprivileged* user unmount their own
        # FUSE mount, which doesn't apply here, and this also sidesteps
        # needing to guess whether this station's fuse3 package names the
        # binary fusermount or fusermount3.
        try:
            subprocess.run(["sudo", "/bin/umount", mount_dir], capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        err = (res.stderr or res.stdout or "Unknown dislocker error.").strip()
        return False, None, None, f"Unlock failed - check the recovery key/password: {err[:300]}"

    with bitlocker_lock:
        active_bitlocker_mounts[mount_id] = {
            "mount_dir": mount_dir,
            "device": original_source,
            "source_path": decrypted_path,
            "unlocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    register_decrypted_source(decrypted_path, "bitlocker")
    return True, mount_id, decrypted_path, None

def _dislocker_lock(mount_id):
    """Unmounts and cleans up a dislocker mount. Safe to call more than
    once for the same id - a second call just finds nothing left to do."""
    if not mount_id:
        return True, None
    with bitlocker_lock:
        info = active_bitlocker_mounts.pop(mount_id, None)
    if not info:
        return True, None
    unregister_decrypted_source(info["source_path"])
    mount_dir = info["mount_dir"]
    try:
        # See the matching comment in _dislocker_unlock() above - plain
        # umount (already sudoers-granted, no new grant needed) instead of
        # fusermount/fusermount3, since this always runs as root.
        subprocess.run(["sudo", "/bin/umount", mount_dir], capture_output=True, timeout=15)
    except Exception as e:
        return False, f"Failed to unmount: {e}"
    try:
        os.rmdir(mount_dir)
    except OSError:
        pass
    return True, None

def _resolve_acquisition_source(source):
    """Returns (actual_source_path, source_kind, mount_meta).

    source_kind is one of 'real_device' (an actual whitelisted /dev/sdX-
    style device), 'decrypted_file' (a BitLocker dislocker-file - a regular
    file, needs os.path.getsize() not blockdev), or 'decrypted_block_device'
    (a LUKS or VeraCrypt dm-mapper device - block-device-shaped, needs
    blockdev like a real device, but not SMART-queryable since it's
    virtual; VeraCrypt reuses this exact same kind rather than a new one,
    confirmed live that cryptsetup's own `open --type tcrypt` produces the
    identical /dev/mapper/<name> shape LUKS's `luksOpen` already does).
    mount_meta is None for 'real_device', else {"kind":
    "bitlocker"|"luks"|"veracrypt", "mount_id": ..., "device": <original
    encrypted source>}.

    If `source` exactly matches a currently-registered dislocker mount's own
    decrypted virtual file path, or a currently-registered LUKS/VeraCrypt
    mapper device's own path, it's trusted as a valid acquisition source
    without needing to pass is_valid_block_device() - only a path this
    app's own _dislocker_unlock()/_luks_unlock()/_veracrypt_unlock() just
    created can ever match, since mountpoints/mapper names live under
    server-controlled roots and are never client-supplied.

    Deliberately reads active_bitlocker_mounts/active_luks_mounts directly
    (not the shared core/decrypted_sources.py registry, which exists only
    for routes/image_browser.py's simpler yes/no browsability check) - this
    function needs the richer per-mount metadata (device, mount_id) those
    two dicts already hold, and routing through the shared registry would
    just mean a second lookup for no benefit."""
    with bitlocker_lock:
        for mount_id, info in active_bitlocker_mounts.items():
            if info["source_path"] == source:
                return source, "decrypted_file", {"kind": "bitlocker", "mount_id": mount_id, "device": info["device"]}
    with luks_lock:
        for mapper_name, info in active_luks_mounts.items():
            if info["mapper_path"] == source:
                return source, "decrypted_block_device", {"kind": "luks", "mount_id": mapper_name, "device": info["device"]}
    with veracrypt_lock:
        for mapper_name, info in active_veracrypt_mounts.items():
            if info["mapper_path"] == source:
                return source, "decrypted_block_device", {"kind": "veracrypt", "mount_id": mapper_name, "device": info["device"]}
    return source, "real_device", None

# --- LUKS: unlock an encrypted source via cryptsetup, so it can be imaged/
# browsed decrypted instead of as raw encrypted bytes. Mirrors the BitLocker
# dislocker machinery above structurally, but the actual mechanism differs
# in two real ways confirmed by live testing against the real installed
# cryptsetup on the deployed station (not assumed from documentation):
#   - The decrypted volume is exposed as a real device-mapper block device
#     (/dev/mapper/<name>), not a FUSE-mounted regular file - so it needs a
#     defensive ACL grant (like Live Device Preview's own mechanism) rather
#     than a FUSE allow_other flag, and it's block-device-shaped for
#     total_bytes/iflag=direct purposes even though it's not itself a
#     whitelisted /dev/sdX path.
#   - cryptsetup has NO equivalent of dislocker's -O/--offset flag for LUKS
#     (confirmed live: "Option --offset with open action is only supported
#     for plain and loopaes devices") - unlocking a LUKS volume embedded at
#     a nonzero byte offset within a larger already-acquired image requires
#     first creating a loop device at that offset (losetup -o <offset>
#     --show -f <file>) and opening THAT, tracked here so lock-time cleanup
#     knows to losetup -d it after luksClose.
LUKS_MAPPER_PREFIX = "pif_luks_"
luks_lock = threading.Lock()
active_luks_mounts = {}  # mapper_name -> {mapper_path, device, loop_device (None if no offset), unlocked_at}

def _detect_luks(partition):
    """Best-effort LUKS signature check via blkid - mirrors _detect_bitlocker
    exactly, not authoritative (a wrong/no answer here doesn't block trying
    to unlock anyway)."""
    if not is_valid_bitlocker_source(partition):
        return None
    try:
        res = subprocess.run(
            ['sudo', '/sbin/blkid', '-o', 'value', '-s', 'TYPE', partition],
            capture_output=True, text=True, timeout=10
        )
        fstype = res.stdout.strip()
        return {"fstype": fstype, "is_luks": fstype.lower() == 'crypto_luks'}
    except Exception:
        return {"fstype": None, "is_luks": False}

def _detect_luks_image(image_path, offset=0):
    """Best-effort LUKS signature check for an already-acquired evidence
    image (or a specific partition's byte offset within it) - a direct read
    of the 6-byte LUKS magic ("LUKS\\xba\\xbe", identical for LUKS1 and
    LUKS2 - confirmed live against a real luksFormat'd volume via `od`) at
    the given offset. No sudo needed, mirrors _detect_bitlocker_image
    exactly: an evidence image file is already owned by this app's own
    unprivileged service account, so a plain read is enough."""
    validated = safe_path(image_path)
    if not validated or not os.path.isfile(validated):
        return None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return None
    try:
        with open(validated, 'rb') as f:
            f.seek(offset)
            sig = f.read(6)
        return {"is_luks": sig == b'LUKS\xba\xbe'}
    except OSError:
        return {"is_luks": False}

def _luks_unlock(source_path, passphrase, offset=None):
    """Mounts a LUKS-encrypted volume via cryptsetup. Two modes, selected by
    whether `offset` is given - mirrors _dislocker_unlock's own two modes:
      - offset=None: `source_path` is a live device/partition path -
        validated via is_valid_bitlocker_source() (whole disk or partition).
        luksOpen runs directly against it, no loop device.
      - offset=<int>: `source_path` is an already-acquired evidence image
        file - validated via safe_path() like every other image-accepting
        route. If offset == 0, luksOpen runs directly against the file
        (cryptsetup can open a LUKS container living at the start of a
        regular file with no loop device, confirmed live). If offset > 0, a
        loop device is created first (losetup -o <offset> --show -f) and
        luksOpen runs against that instead (offset 0 relative to the loop
        device) - confirmed live end-to-end, since cryptsetup itself cannot
        open a LUKS container embedded partway through a larger file/device.

    Returns (success, mapper_name_or_None, mapper_path_or_None,
    error_or_None) - same shape as _dislocker_unlock. The mapper name is
    entirely server-controlled (LUKS_MAPPER_PREFIX + a fresh uuid4, never
    client-supplied) - this is what lets _resolve_acquisition_source() and
    the shared decrypted-sources registry safely trust a path later."""
    loop_device = None
    if offset is None:
        if not is_valid_bitlocker_source(source_path):
            return False, None, None, "Invalid or unrecognized device/partition path."
        target = source_path
        original_source = source_path
    else:
        validated = safe_path(source_path)
        if not validated or not os.path.isfile(validated):
            return False, None, None, "Image file not found or outside the permitted evidence directory."
        original_source = validated
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            return False, None, None, "Invalid partition offset."
        if offset > 0:
            try:
                res = subprocess.run(
                    ["sudo", "/sbin/losetup", "-o", str(offset), "--show", "-f", validated],
                    capture_output=True, text=True, timeout=30,
                )
            except subprocess.TimeoutExpired:
                return False, None, None, "losetup timed out."
            except FileNotFoundError:
                return False, None, None, "losetup is not available on this station."
            if res.returncode != 0 or not res.stdout.strip():
                err = (res.stderr or res.stdout or "Unknown losetup error.").strip()
                return False, None, None, f"Could not create a loop device at this offset: {err[:300]}"
            loop_device = res.stdout.strip()
            target = loop_device
        else:
            target = validated

    passphrase = (passphrase or '').strip()
    if not passphrase:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "Passphrase is required."

    mapper_name = f"{LUKS_MAPPER_PREFIX}{uuid.uuid4().hex}"
    cmd = ["sudo", "/usr/sbin/cryptsetup", "luksOpen", target, mapper_name, "-d", "-"]
    try:
        res = subprocess.run(cmd, input=passphrase, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "cryptsetup timed out - the device may be unresponsive."
    except FileNotFoundError:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "cryptsetup is not installed on this station. Run 'sudo apt-get install cryptsetup-bin' first."

    mapper_path = f"/dev/mapper/{mapper_name}"
    if res.returncode != 0 or not os.path.exists(mapper_path):
        # Confirmed live: a failed luksOpen leaves no dangling /dev/mapper/*
        # entry to clean up (unlike a failed dislocker FUSE mount) - but a
        # loop device that WAS already created is a separate resource with
        # its own lifecycle and must still be explicitly detached here.
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        err = (res.stderr or res.stdout or "Unknown cryptsetup error.").strip()
        return False, None, None, f"Unlock failed - check the passphrase: {err[:300]}"

    # Defensive ACL grant so the unprivileged worker process can read the
    # decrypted mapper device - real, portable defense-in-depth even though
    # this station's own service account already has read access to any
    # /dev/mapper/* device via its (pre-existing, disclosed) disk-group
    # membership; a different install won't have that redundancy. Mirrors
    # Live Device Preview's own _grant_device_preview_acl() exactly.
    subprocess.run(
        ["sudo", "/usr/bin/setfacl", "-m", f"u:{_SERVICE_ACCOUNT_NAME}:r", mapper_path],
        capture_output=True, timeout=15,
    )

    with luks_lock:
        active_luks_mounts[mapper_name] = {
            "mapper_path": mapper_path,
            "device": original_source,
            "loop_device": loop_device,
            "unlocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    register_decrypted_source(mapper_path, "luks")
    return True, mapper_name, mapper_path, None

def _luks_lock(mapper_name):
    """Unmounts and cleans up a LUKS mapping. Safe to call more than once
    for the same id - a second call just finds nothing left to do. Order
    matters: revoke the ACL, luksClose (must happen while the loop device,
    if any, is still attached), THEN losetup -d the loop device."""
    if not mapper_name:
        return True, None
    with luks_lock:
        info = active_luks_mounts.pop(mapper_name, None)
    if not info:
        return True, None
    unregister_decrypted_source(info["mapper_path"])
    subprocess.run(
        ["sudo", "/usr/bin/setfacl", "-x", f"u:{_SERVICE_ACCOUNT_NAME}", info["mapper_path"]],
        capture_output=True, timeout=15,
    )
    try:
        subprocess.run(["sudo", "/usr/sbin/cryptsetup", "luksClose", mapper_name], capture_output=True, timeout=15)
    except Exception as e:
        return False, f"Failed to close LUKS mapping: {e}"
    if info.get("loop_device"):
        try:
            subprocess.run(["sudo", "/sbin/losetup", "-d", info["loop_device"]], capture_output=True, timeout=10)
        except Exception:
            pass  # best-effort, matching _dislocker_lock's own best-effort cleanup pattern
    return True, None

VERACRYPT_MAPPER_PREFIX = "pif_veracrypt_"
veracrypt_lock = threading.Lock()
active_veracrypt_mounts = {}  # mapper_name -> {mapper_path, device, loop_device (None if no offset), unlocked_at}

def _detect_veracrypt(partition):
    """Unlike _detect_bitlocker/_detect_luks, there is NO best-effort
    signature check possible here at all - a VeraCrypt volume's whole
    first sector is deliberately designed to look like random noise (no
    fixed magic bytes), by design, so it can't be distinguished from
    unallocated space without a password. Always returns is_veracrypt:
    None (not True/False) - the frontend shows this as "cannot be
    auto-detected, try Unlock directly" rather than presenting a
    definitive-looking but meaningless answer. The honest, disclosure-over-
    silent-promise application of the same pattern _detect_bitlocker/
    _detect_luks already use for their own "best-effort, not authoritative"
    framing, taken to its logical limit here since there's genuinely
    nothing byte-level to check."""
    if not is_valid_bitlocker_source(partition):
        return None
    return {"is_veracrypt": None, "note": "VeraCrypt volumes have no fixed signature - use Unlock directly; a wrong password/format is reported clearly."}

def _detect_veracrypt_image(image_path, offset=0):
    """Same honest non-answer as _detect_veracrypt() above, for an
    already-acquired evidence image."""
    validated = safe_path(image_path)
    if not validated or not os.path.isfile(validated):
        return None
    return {"is_veracrypt": None, "note": "VeraCrypt volumes have no fixed signature - use Unlock directly; a wrong password/format is reported clearly."}

def _veracrypt_unlock(source_path, password, offset=None, pim=None):
    """Mounts a VeraCrypt-encrypted volume via cryptsetup's own built-in
    tcrypt/VeraCrypt support (`cryptsetup open --type tcrypt --veracrypt`) -
    confirmed live against a real VeraCrypt-format test container (created
    with tcplay's SHA256-VC PBKDF variant, the genuine VeraCrypt-compatible
    KDF, not legacy TrueCrypt) that cryptsetup 2.7.5 (this station's real
    installed version) supports this natively - no new binary/package
    dependency needed at all, unlike the original plan's assumption of
    needing the real `veracrypt` CLI (confirmed NOT in Debian's mainline
    ARM64 repo) or `tcplay` (used only for this live test, never shipped -
    see the dated CLAUDE.md entry for the full verification trail).

    Mirrors _luks_unlock()'s exact two-mode shape (offset=None: live
    device/partition; offset=<int>: an evidence image file, with the same
    losetup-loop-device pre-step for offset>0 - deliberately reused rather
    than trusting cryptsetup's own generic -o/--offset flag to work
    correctly for --type tcrypt against a plain file, which was not itself
    live-verified; the loop-device path IS already proven, for LUKS, so
    reusing it here carries zero incremental risk). Mount output shape
    confirmed identical to LUKS too (a /dev/mapper/<name> block device,
    per cryptsetup's own --help: "<name> is the device to create under
    /dev/mapper" - not type-specific), so _resolve_acquisition_source()
    reuses the exact same "decrypted_block_device" source_kind LUKS
    already uses, no new kind needed.

    password is piped via stdin (-d -), never argv - same proven approach
    already used for LUKS, not the weaker "password possibly visible in
    /proc/<pid>/cmdline" alternative the original plan flagged as a real
    concern for a bare veracrypt-CLI-based design. pim (VeraCrypt's
    Personal Iteration Multiplier) defaults to 0 (cryptsetup's/VeraCrypt's
    own "use the default max-iteration behavior" value) when not given -
    --veracrypt-pim is ALWAYS included in the command with a real integer,
    never conditionally omitted, so the resulting argv shape is uniform and
    the sudoers grant can be one single, fully-anchored pattern rather than
    two variants."""
    loop_device = None
    if offset is None:
        if not is_valid_bitlocker_source(source_path):
            return False, None, None, "Invalid or unrecognized device/partition path."
        target = source_path
        original_source = source_path
    else:
        validated = safe_path(source_path)
        if not validated or not os.path.isfile(validated):
            return False, None, None, "Image file not found or outside the permitted evidence directory."
        original_source = validated
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            return False, None, None, "Invalid partition offset."
        if offset > 0:
            try:
                res = subprocess.run(
                    ["sudo", "/sbin/losetup", "-o", str(offset), "--show", "-f", validated],
                    capture_output=True, text=True, timeout=30,
                )
            except subprocess.TimeoutExpired:
                return False, None, None, "losetup timed out."
            except FileNotFoundError:
                return False, None, None, "losetup is not available on this station."
            if res.returncode != 0 or not res.stdout.strip():
                err = (res.stderr or res.stdout or "Unknown losetup error.").strip()
                return False, None, None, f"Could not create a loop device at this offset: {err[:300]}"
            loop_device = res.stdout.strip()
            target = loop_device
        else:
            target = validated

    password = (password or '').strip()
    if not password:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "Password is required."

    try:
        pim_value = int(pim) if pim else 0
    except (TypeError, ValueError):
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "Invalid PIM value."
    if pim_value < 0:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "Invalid PIM value."

    mapper_name = f"{VERACRYPT_MAPPER_PREFIX}{uuid.uuid4().hex}"
    # --veracrypt-pim is ALWAYS present (0 = "use VeraCrypt's own default
    # max-iteration behavior", a real, valid value - not merely "unset"),
    # never conditionally appended - this keeps the command's argv shape
    # fixed/uniform so the sudoers grant below can be one single, fully
    # left-and-right-anchored pattern instead of two variants (with/without
    # a PIM segment), matching this file's own "anchor every wildcard on
    # both sides" discipline for cryptsetup grants.
    cmd = ["sudo", "/usr/sbin/cryptsetup", "open", "--type", "tcrypt", "--veracrypt",
           "--veracrypt-pim", str(pim_value), "-r", "-q", target, mapper_name, "-d", "-"]
    try:
        res = subprocess.run(cmd, input=password, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "cryptsetup timed out - the device may be unresponsive."
    except FileNotFoundError:
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        return False, None, None, "cryptsetup is not installed on this station."

    mapper_path = f"/dev/mapper/{mapper_name}"
    if res.returncode != 0 or not os.path.exists(mapper_path):
        if loop_device:
            subprocess.run(["sudo", "/sbin/losetup", "-d", loop_device], capture_output=True, timeout=10)
        err = (res.stderr or res.stdout or "Unknown cryptsetup error.").strip()
        return False, None, None, f"Unlock failed - check the password/PIM/keyfile: {err[:300]}"

    subprocess.run(
        ["sudo", "/usr/bin/setfacl", "-m", f"u:{_SERVICE_ACCOUNT_NAME}:r", mapper_path],
        capture_output=True, timeout=15,
    )

    with veracrypt_lock:
        active_veracrypt_mounts[mapper_name] = {
            "mapper_path": mapper_path,
            "device": original_source,
            "loop_device": loop_device,
            "unlocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    register_decrypted_source(mapper_path, "veracrypt")
    return True, mapper_name, mapper_path, None

def _veracrypt_lock(mapper_name):
    """Mirrors _luks_lock() exactly - safe to call more than once, same
    revoke-ACL / cryptsetup-close / detach-loop-device-last order."""
    if not mapper_name:
        return True, None
    with veracrypt_lock:
        info = active_veracrypt_mounts.pop(mapper_name, None)
    if not info:
        return True, None
    unregister_decrypted_source(info["mapper_path"])
    subprocess.run(
        ["sudo", "/usr/bin/setfacl", "-x", f"u:{_SERVICE_ACCOUNT_NAME}", info["mapper_path"]],
        capture_output=True, timeout=15,
    )
    try:
        subprocess.run(["sudo", "/usr/sbin/cryptsetup", "close", mapper_name], capture_output=True, timeout=15)
    except Exception as e:
        return False, f"Failed to close VeraCrypt mapping: {e}"
    if info.get("loop_device"):
        try:
            subprocess.run(["sudo", "/sbin/losetup", "-d", info["loop_device"]], capture_output=True, timeout=10)
        except Exception:
            pass
    return True, None

# Shared dispatch for anything that needs to act generically across all 3
# decrypted-source kinds (BitLocker/LUKS/VeraCrypt) - added once VeraCrypt
# made the previous 2-way if/else's implicit "else means luks" fragile (a
# genuine 3rd kind exposes exactly the assumption that shape was quietly
# relying on). Used by start_imaging()'s post-job mount cleanup and its
# label/logging call sites below, rather than a growing pile of ternaries.
DECRYPTED_SOURCE_KIND_LABELS = {"bitlocker": "BitLocker", "luks": "LUKS", "veracrypt": "VeraCrypt"}
DECRYPTED_SOURCE_LOCK_FN = {"bitlocker": _dislocker_lock, "luks": _luks_lock, "veracrypt": _veracrypt_lock}

def _luks_startup_loop_device_reconciliation():
    """One-shot check at process start (not a recurring sweep - unlike Live
    Device Preview's idle-timeout problem, a leaked loop device only ever
    happens via a process crash/restart, which this only needs to check for
    once per process lifetime). active_luks_mounts is always empty at a
    fresh start, so any loop device already backed by a file under
    EVIDENCE_ROOT at this point cannot be explained by this process's own
    state - logs a disclosure, never auto-detaches (a legitimate unrelated
    loop mount could theoretically exist), matching this project's own
    "disclose, don't silently act" posture used elsewhere for similar
    ambiguous-ownership findings."""
    try:
        res = subprocess.run(["sudo", "/sbin/losetup", "-a"], capture_output=True, text=True, timeout=10)
    except Exception:
        return
    if res.returncode != 0:
        return
    for line in res.stdout.splitlines():
        # Format: "/dev/loop1: [0031]:1970616 (/path/to/backing/file)[, offset ...]"
        m = re.match(r'^(/dev/loop\d+):.*\(([^)]+)\)', line.strip())
        if not m:
            continue
        loop_dev, backing_file = m.group(1), m.group(2)
        if backing_file.startswith(EVIDENCE_ROOT + os.sep) or backing_file == EVIDENCE_ROOT:
            log_chain_of_custody(
                "luks_loop_device_orphan_detected",
                {"loop_device": loop_dev, "backing_file": backing_file,
                 "note": "Found attached at process startup, not explained by this process's own state - likely leaked by a prior crash/restart. Not auto-detached."},
                source_ip=None, user="system-startup",
            )

threading.Thread(target=_luks_startup_loop_device_reconciliation, daemon=True).start()

# --- Hash & Recovery Output Parsers ---
def parse_dc3dd_hashes(log_path):
    hashes = {}
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                content = f.read()
                matches = re.findall(r'([a-fA-F0-9]{32,64})\s*\(\s*(\b(?:md5|sha1|sha256)\b)\s*\)', content, re.IGNORECASE)
                for val, algo in matches:
                    hashes[algo.lower()] = val
                    
                if not hashes:
                    fallback_matches = re.findall(r'(\b(?:md5|sha1|sha256)\b)[^\n:]*:\s*([a-fA-F0-9]{32,64})', content, re.IGNORECASE)
                    for algo, val in fallback_matches:
                        hashes[algo.lower()] = val
        except Exception as e:
            print(f"Error parsing dc3dd log: {e}")
    return hashes

def parse_ewf_hashes(console_log_text):
    # Real ewfacquire output (confirmed live against the installed
    # 20140816 build): "MD5 hash calculated over data:\t<hex>" /
    # "SHA256 hash calculated over data:\t<hex>" - a genuine, previously-
    # shipped bug lived here: the old pattern required "hash" to be
    # immediately followed by an optional colon, with no allowance for the
    # " calculated over data" (or, during a verify pass, "stored in file")
    # text actually sitting in between, so it matched *nothing* against
    # real output and every E01 acquisition silently ended up with an empty
    # computed_verification_hashes dict. Fixed to match "<ALGO> hash", any
    # non-colon text, then the colon and hex value - confirmed against both
    # the real "calculated over data" wording and the "stored in file"
    # wording ewfacquire/ewfverify use during a verification pass.
    hashes = {}
    try:
        matches = re.findall(r'(\b(?:MD5|SHA1|SHA256)\b)\s+hash[^:\n]*:\s*([a-fA-F0-9]{32,64})', console_log_text, re.IGNORECASE)
        for algo, val in matches:
            hashes[algo.lower()] = val
    except Exception as e:
        print(f"Error parsing ewf hashes: {e}")
    return hashes

def parse_dc3dd_line(line):
    m = re.search(r'(\d+)\s+bytes.*copied.*,\s*([\d\.]+)\s*(MB|MiB|KB|GB|M|K)/s', line, re.IGNORECASE)
    if m:
        bytes_copied = int(m.group(1))
        speed_val = float(m.group(2))
        unit = m.group(3).upper()
        
        if unit in ['KB', 'K']:
            speed_val /= 1024.0
        elif unit in ['GB', 'G']:
            speed_val *= 1024.0
            
        return bytes_copied, speed_val
    return None, None

def parse_ewf_line(line):
    m_pct = re.search(r'(\d+)%\s*(?:acquired|done|completed|verified)?', line, re.IGNORECASE)
    m_spd = re.search(r'([\d\.]+)\s*(?:MiB|MB|KiB|KB)/s', line, re.IGNORECASE)
    pct = float(m_pct.group(1)) if m_pct else None
    spd = float(m_spd.group(1)) if m_spd else None
    return pct, spd

def parse_ddrescue_line(line):
    rescued_bytes = None
    pct = None
    spd = None
    
    m_rescued = re.search(r'rescued:\s*([\d\.]+)\s*([KMGT]?B)', line, re.IGNORECASE)
    m_spd = re.search(r'current_rate:\s*([\d\.]+)\s*([KMGT]?B/s)', line, re.IGNORECASE)
    m_pct = re.search(r'pct_rescued:\s*([\d\.]+)\%', line, re.IGNORECASE)

    def to_bytes(val, unit):
        u = unit.upper()
        v = float(val)
        if 'K' in u: return int(v * 1024)
        if 'M' in u: return int(v * 1024**2)
        if 'G' in u: return int(v * 1024**3)
        if 'T' in u: return int(v * 1024**4)
        return int(v)

    if m_rescued:
        rescued_bytes = to_bytes(m_rescued.group(1), m_rescued.group(2))
    if m_pct:
        pct = float(m_pct.group(1))
    if m_spd:
        spd = to_bytes(m_spd.group(1), m_spd.group(2)) / (1024**2)

    return rescued_bytes, pct, spd

HASH_HEX_LEN = {'md5': 32, 'sha1': 40, 'sha256': 64}

def read_hash_log_file(path, algo):
    """
    Extract a hex hash of the expected length for `algo` from a dcfldd-style
    hash log file (dcfldd writes one file per algorithm via <algo>log=).
    """
    expected_len = HASH_HEX_LEN.get(algo)
    if not expected_len or not path or not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            content = f.read()
        m = re.search(r'\b([a-fA-F0-9]{%d})\b' % expected_len, content)
        return m.group(1).lower() if m else None
    except Exception as e:
        print(f"Error reading hash log {path}: {e}")
        return None

def compute_file_hashes(file_path, algos, chunk_size=8 * 1024 * 1024):
    """
    Stream-hash a file for one or more algorithms. Used for plain GNU `dd`,
    which - unlike dc3dd/dcfldd/ewfacquire - has no built-in hashing at all.
    """
    hashers = {a: hashlib.new(a) for a in algos if a in ALLOWED_HASH_ALGOS}
    if not hashers or not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
        return {a: h.hexdigest() for a, h in hashers.items()}
    except Exception as e:
        print(f"Error computing hashes for {file_path}: {e}")
        return {}

def parse_affconvert_line(line):
    """affconvert prints progress as 'Converting page N of M'."""
    m = re.search(r'[Cc]onverting page (\d+) of (\d+)', line)
    if m:
        current, total_pages = int(m.group(1)), int(m.group(2))
        if total_pages > 0:
            return round((current / total_pages) * 100, 1)
    return None

def parse_ddrescue_mapfile(map_path):
    summary = {
        "rescued_bytes": 0,
        "non_tried_bytes": 0,
        "bad_sector_bytes": 0,
        "bad_blocks_count": 0
    }
    if os.path.exists(map_path):
        try:
            with open(map_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            size = int(parts[1], 16)
                            status = parts[2]
                            
                            if status == '+':
                                summary["rescued_bytes"] += size
                            elif status in ['?', '*', '/']:
                                summary["non_tried_bytes"] += size
                            elif status == '-':
                                summary["bad_sector_bytes"] += size
                                summary["bad_blocks_count"] += 1
                        except ValueError:
                            pass
        except Exception as e:
            print(f"Error reading mapfile: {e}")
    return summary

def execution_worker(cmd, fmt, total_bytes, out_file, report_file_path, report_data, hashes=None):
    log_history = []
    hashes = hashes or []
    
    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    append_log(f"[*] Starting execution using [{fmt.upper()}] engine...")
    append_log(f"[*] Command: {' '.join(cmd)}")

    start_time = time.time()
    update_job(status="Processing Media...")

    try:
        def on_line(clean_line):
            append_log(clean_line)

            if fmt in ['raw', 'dd', 'dcfldd', 'plain_dd']:
                bytes_copied, speed = parse_dc3dd_line(clean_line)
                updates = {}
                if bytes_copied is not None:
                    updates["transferred_bytes"] = bytes_copied
                    if total_bytes > 0:
                        updates["progress_percent"] = round((bytes_copied / total_bytes) * 100, 1)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            elif fmt == 'e01':
                pct, speed = parse_ewf_line(clean_line)
                updates = {}
                if "verify" in clean_line.lower() or "verifying" in clean_line.lower():
                    updates["status"] = "Verifying Image Integrity..."

                if pct is not None:
                    updates["progress_percent"] = pct
                    if total_bytes > 0:
                        updates["transferred_bytes"] = int((pct / 100.0) * total_bytes)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            elif fmt == 'ddrescue':
                rescued_bytes, pct, speed = parse_ddrescue_line(clean_line)
                updates = {}
                if rescued_bytes is not None:
                    updates["transferred_bytes"] = rescued_bytes
                if pct is not None:
                    updates["progress_percent"] = pct
                elif rescued_bytes is not None and total_bytes > 0:
                    updates["progress_percent"] = round((rescued_bytes / total_bytes) * 100, 1)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

        proc = _stream_subprocess(cmd, on_line)

        time.sleep(1.0)
        computed_hashes = {}
        if fmt == 'e01':
            computed_hashes = parse_ewf_hashes(snapshot_job()["log"])
        elif fmt in ['raw', 'dd']:
            dc3dd_log = out_file.replace('.dd', '_dc3dd.log')
            computed_hashes = parse_dc3dd_hashes(dc3dd_log)
        elif fmt == 'dcfldd':
            for h in hashes:
                val = read_hash_log_file(out_file.replace('.dd', f'_{h}.log'), h)
                if val:
                    computed_hashes[h] = val
        elif fmt == 'plain_dd':
            reclaim_ownership(out_file)  # written by sudo'd dd - must reclaim before we can read it below
            append_log("[*] Computing hash(es) of output file (plain dd has no built-in hashing)...")
            computed_hashes = compute_file_hashes(out_file, hashes)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["computed_verification_hashes"] = computed_hashes

        # dc3dd's own process exit code is not reliable on its own - it can
        # exit 0/2 (treated as success below) while still self-reporting a
        # failure (e.g. an unrecovered read error partway through) via a
        # "dc3dd failed at <timestamp>" line in its own output, distinct
        # from "dc3dd completed at <timestamp>" on genuine success. Since
        # that line is already being streamed into log_history live, check
        # it directly rather than trusting returncode alone for this format.
        dc3dd_self_reported_failure = (
            fmt in ['raw', 'dd'] and 'dc3dd failed at' in "\n".join(log_history)
        )

        if proc.returncode in [0, 2] and not dc3dd_self_reported_failure:
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] Recovery/acquisition completed successfully.")
            report_data["acquisition_status"] = "COMPLETED"

        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            if dc3dd_self_reported_failure:
                append_log("[-] dc3dd reported its own failure (see 'dc3dd failed at ...' above) despite exiting with a code normally treated as success - treating this run as failed.")
            else:
                append_log(f"[-] Process exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # Every format this worker handles (dc3dd/dcfldd/dd/ewfacquire/
        # ddrescue) now runs via sudo to read the raw device - their output
        # lands owned by root. Reclaim regardless of success/failure/stop,
        # so even a partial/failed run's output can still be inspected or
        # deleted afterward by this unprivileged service account.
        reclaim_ownership(os.path.dirname(out_file))
        update_job(active=False)
        clear_active_proc()

def execution_worker_chained_auto_analyze(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes, case_folder, source_ip, user):
    """Guided Workflow automation Tier 2 (2026-08-27) - wraps execution_worker()
    with an opt-in hand-off into Auto Analyze's own step sequence once
    acquisition genuinely COMPLETEs. Only ever spawned by start_imaging()
    when the examiner explicitly checked "Automatically run Auto Analyze
    when this finishes" for this one run - never a silent/default trigger
    (see the dated CLAUDE.md entry for the full design reasoning, including
    why this extends Auto Analyze's own existing single-job-claim-holding
    mechanism one level up rather than a new generic "job A triggers job B"
    system).

    core/jobs.py's _suppress_active_false is a plain bool, not a counter -
    the hand-off below only composes correctly because
    execution_worker_auto_analyze_image() is always the LAST stage when it
    runs: its own internal end_suppress_active_false()+update_job(active=False)
    correctly finishes the whole combined job exactly once, at the true end.
    The `finally` below is this function's OWN safety net for every other
    exit path (acquisition failed/stopped, or the evidence type couldn't be
    determined) - without it, an early return here would leave
    current_job["active"]=True forever, a station-wide lockup until a
    service restart.
    """
    chained_into_analyze = False
    begin_suppress_active_false()
    try:
        execution_worker(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes)
        if report_data.get("acquisition_status") != "COMPLETED":
            return  # failed, or stopped mid-run - nothing valid to analyze

        profile_result = classify_image_profile(out_file)
        profile = profile_result.get("profile")
        steps = {
            "windows": AUTO_ANALYZE_WINDOWS_DEFAULT_STEPS,
            "linux": AUTO_ANALYZE_LINUX_DEFAULT_STEPS,
        }.get(profile)

        if not steps:
            # A real, disclosed outcome, not a silent no-op - "mixed"/
            # "unknown" images (or a filesystem classify_image_profile()
            # couldn't open) are never guessed at, matching Auto Analyze's
            # own detect route's identical honesty principle.
            log_chain_of_custody("chained_auto_analyze_skipped", {
                "image_path": out_file,
                "reason": f"Could not determine evidence type (detected: {profile}) - automatic analysis was not started.",
            }, source_ip=source_ip, user=user)
            update_job(status=f"Acquisition completed - automatic analysis skipped (could not determine evidence type: {profile}).")
            return

        execution_worker_auto_analyze_image(out_file, case_folder, steps, source_ip=source_ip, user=user)
        chained_into_analyze = True
    finally:
        if not chained_into_analyze:
            end_suppress_active_false()
            update_job(active=False)

def execution_worker_aff(source, dest_path, base_name, hashes, keep_raw, report_file_path, report_data, total_bytes):
    """
    Two-phase AFF acquisition: (1) raw acquisition via dc3dd, with on-the-fly
    hashing - these hashes are the forensic record of what was actually read
    off the device; (2) convert the raw image to .aff via affconvert, which
    repackages the same bytes (compression/segmentation only), so the phase-1
    hashes remain the authoritative acquisition hashes. Real device-to-AFF
    tools (e.g. the old `aimage`) are no longer part of the packaged
    afflib-tools, which only ships file-to-file converters - hence two phases.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    raw_file = os.path.join(dest_path, f"{base_name}.raw")
    dc3dd_log_file = os.path.join(dest_path, f"{base_name}_dc3dd.log")
    aff_file = os.path.join(dest_path, f"{base_name}.aff")

    try:
        # --- Phase 1: raw acquisition (dc3dd) ---
        update_job(format="aff", status="Phase 1/2: Raw Acquisition...",
                   progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=total_bytes)
        append_log(f"[*] Phase 1/2: Acquiring raw image to {raw_file}")

        cmd1 = ["sudo", "/usr/bin/dc3dd", f"if={source}", f"of={raw_file}", f"log={dc3dd_log_file}"]
        for h in hashes:
            cmd1.append(f"hash={h}")
        append_log(f"[*] Command: {' '.join(cmd1)}")

        def on_line_phase1(clean_line):
            append_log(clean_line)
            bytes_copied, speed = parse_dc3dd_line(clean_line)
            updates = {}
            if bytes_copied is not None:
                updates["transferred_bytes"] = bytes_copied
                if total_bytes > 0:
                    # Phase 1 is the first half of overall progress.
                    updates["progress_percent"] = round((bytes_copied / total_bytes) * 50.0, 1)
            if speed is not None:
                updates["speed_mbps"] = speed
            if updates:
                update_job(**updates)

        proc1 = _stream_subprocess(cmd1, on_line_phase1)
        time.sleep(1.0)

        if proc1.returncode not in [0, 2]:
            reclaim_ownership(dest_path)  # hand back whatever partial output exists, even on failure
            if snapshot_job()["status"] != "Stopped":
                update_job(status="Failed")
                append_log(f"[-] Phase 1 (raw acquisition) failed with exit code {proc1.returncode}")
                report_data["acquisition_status"] = "FAILED"
                report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
                _write_report(report_file_path, report_data, append_log)
            return

        if snapshot_job()["status"] == "Stopped":
            reclaim_ownership(dest_path)  # hand back whatever phase 1 did produce, even though we're stopping
            return  # user aborted right after phase 1 finished

        # Phase 1 ran via sudo (root, for raw device access) - reclaim
        # before reading the log file directly in Python below, and before
        # phase 2 (affconvert, unprivileged) needs to read the raw file
        # phase 1 just wrote.
        reclaim_ownership(dest_path)

        raw_hashes = parse_dc3dd_hashes(dc3dd_log_file)
        append_log(f"[+] Phase 1 complete. Raw acquisition hashes: {raw_hashes}")
        report_data["computed_verification_hashes"] = raw_hashes

        # --- Phase 2: convert raw -> AFF ---
        update_job(status="Phase 2/2: Converting to AFF...", progress_percent=50.0)
        append_log(f"[*] Phase 2/2: Converting {raw_file} -> {aff_file}")

        cmd2 = ["affconvert", "-o", aff_file, raw_file]
        append_log(f"[*] Command: {' '.join(cmd2)}")

        def on_line_phase2(clean_line):
            append_log(clean_line)
            pct = parse_affconvert_line(clean_line)
            if pct is not None:
                update_job(progress_percent=round(50.0 + pct / 2.0, 1))

        proc2 = _stream_subprocess(cmd2, on_line_phase2)
        time.sleep(0.5)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if proc2.returncode == 0 and os.path.exists(aff_file):
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] AFF conversion completed successfully.")
            report_data["acquisition_status"] = "COMPLETED"

            if keep_raw:
                append_log(f"[*] Intermediate raw image retained per examiner selection: {raw_file}")
                report_data["acquisition_parameters"]["raw_image_retained"] = True
            else:
                try:
                    os.remove(raw_file)
                    append_log(f"[*] Intermediate raw image deleted per examiner selection: {raw_file}")
                    report_data["acquisition_parameters"]["raw_image_retained"] = False
                except Exception as e:
                    append_log(f"[-] Warning: Could not delete intermediate raw image: {e}")
                    report_data["acquisition_parameters"]["raw_image_retained"] = True

        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] Phase 2 (AFF conversion) failed with exit code {proc2.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()

# --- Standalone image-format conversion (raw <-> E01), for an image already
# sitting in a case folder - independent of a fresh device acquisition, no
# live source, no job-slot dependency beyond the same single-job-station-
# wide constraint every other worker already shares. Confirmed live against
# the real installed ewfacquire/ewfexport (20140816) before writing this:
# ewfacquire's own help text documents it works against "a file or device"
# interchangeably (no special-casing needed versus the existing device-
# acquisition E01 branch above); ewfexport needs -S/-o passed explicitly
# (and -u for defense in depth) or it hangs on an interactive prompt with a
# closed/piped stdin - confirmed live, not assumed.
IMAGE_CONVERSION_FORMATS = {'e01', 'raw'}

def _ewf_media_size_bytes(e01_path):
    """Best-effort: parses ewfinfo -m's 'Media size: X MiB (N bytes)' line,
    used only for the E01->raw direction's progress-percent transferred-
    bytes estimate. Returns 0 (the same 'unknown, skip the estimate'
    sentinel every update_job() call site below already treats safely) on
    any failure - this is a display nicety, never load-bearing for the
    conversion or its hash verification."""
    try:
        res = subprocess.run(["ewfinfo", "-m", e01_path], capture_output=True, text=True, timeout=15)
        m = re.search(r'Media size:.*?\((\d+)\s*bytes\)', res.stdout or '')
        return int(m.group(1)) if m else 0
    except Exception:
        return 0

def execution_worker_image_conversion(source_image_path, target_format, requested_hashes, report_file_path, report_data):
    """Converts an already-acquired image between raw (.dd) and E01, for an
    image already sitting in a case folder.

    Unlike execution_worker_aff's raw->AFF phase-2 (a lossless repackage
    that deliberately skips re-verification per its own docstring), raw<->E01
    involves genuine reformatting, so this always independently recomputes
    and compares hashes rather than trusting either tool's self-report
    alone - but the two directions compare genuinely different things, and
    conflating them would be a real correctness bug: an E01 file's own bytes
    are a compressed/structured container, never byte-identical to the raw
    media, so 'hash the .E01 file and compare to the raw source's hash'
    would never match by design and isn't attempted. What's actually
    compared:
      - raw -> E01: the independently-computed hash of the raw *source*
        bytes (computed before conversion starts) against ewfacquire's own
        self-reported hash of the media content it read (parse_ewf_hashes()
        on its live output) - the same authoritative-hash convention this
        app's existing E01 acquisition path already uses, just with the
        comparison run explicitly instead of implicitly trusted.
      - E01 -> raw: the independently-computed hash of the real raw *output*
        file that now exists on disk (computed after conversion) against
        ewfexport's own self-reported hash (confirmed live: always MD5 only,
        regardless of what -d is asked for, since the tool's own help text
        documents -d as "not used for raw and files format"). ewfinfo's
        readback of the *original* E01's stored hash was confirmed live to
        be unreliable for non-MD5 algorithms (a real, observed inconsistency
        across two otherwise-identical test acquisitions, not a hypothetical
        concern), so it's never used to gate hash_verified - only MD5, which
        both tools reliably agree on in every direction, does that.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    base, _ext = os.path.splitext(source_image_path)

    try:
        if target_format == 'e01':
            source_size = os.path.getsize(source_image_path) if os.path.exists(source_image_path) else 0
            update_job(format='image_conversion', status="Computing source hash(es)...",
                       progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=source_size)
            append_log(f"[*] Independently hashing source before conversion: {source_image_path}")
            source_hashes = compute_file_hashes(source_image_path, requested_hashes)
            report_data["acquisition_parameters"]["source_hashes"] = source_hashes

            output_path = f"{base}.E01"
            params = report_data["acquisition_parameters"]
            cmd = [
                "sudo", "/usr/bin/ewfacquire", "-u",
                "-t", base,
                "-C", params.get("case_number") or "UNASSIGNED",
                "-E", params.get("evidence_id") or "ITEM-01",
                "-e", params.get("examiner") or "UNSPECIFIED",
                "-N", "Converted from an already-acquired raw image",
                "-f", "encase6",
            ]
            for h in requested_hashes:
                if h != 'md5':
                    cmd += ["-d", h]
            cmd += ["-c", "fast", "-S", "2000M", source_image_path]
            append_log(f"[*] Command: {' '.join(cmd)}")
            update_job(status="Converting to E01...")

            def on_line(clean_line):
                append_log(clean_line)
                pct, speed = parse_ewf_line(clean_line)
                updates = {}
                if pct is not None:
                    updates["progress_percent"] = pct
                    if source_size > 0:
                        updates["transferred_bytes"] = int((pct / 100.0) * source_size)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            proc = _stream_subprocess(cmd, on_line)
            time.sleep(1.0)
            tool_hashes = parse_ewf_hashes(snapshot_job()["log"])
            report_data["computed_verification_hashes"] = tool_hashes
            hash_verified = bool(tool_hashes) and all(
                source_hashes.get(a) == tool_hashes.get(a) for a in requested_hashes if a in tool_hashes
            )
            conversion_ok = proc.returncode in (0, 2) and os.path.exists(output_path)

        elif target_format == 'raw':
            source_total = _ewf_media_size_bytes(source_image_path)
            update_job(format='image_conversion', status="Converting to raw (.dd)...",
                       progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=source_total)

            output_path = f"{base}.dd"
            cmd = ["sudo", "/usr/bin/ewfexport", "-u", "-f", "raw", "-S", "0", "-o", "0",
                   "-t", base, source_image_path]
            append_log(f"[*] Command: {' '.join(cmd)}")

            def on_line(clean_line):
                append_log(clean_line)
                pct, speed = parse_ewf_line(clean_line)
                updates = {}
                if pct is not None:
                    updates["progress_percent"] = pct
                    if source_total > 0:
                        updates["transferred_bytes"] = int((pct / 100.0) * source_total)
                if speed is not None:
                    updates["speed_mbps"] = speed
                if updates:
                    update_job(**updates)

            proc = _stream_subprocess(cmd, on_line)
            time.sleep(1.0)

            # ewfexport always writes <base>.raw (+ a <base>.raw.info
            # sidecar) regardless of what -t is given - rename to this app's
            # own established raw-output convention (.dd, matching every
            # other raw-producing acquisition route) once export succeeds.
            exported_raw = f"{base}.raw"
            conversion_ok = proc.returncode == 0 and os.path.exists(exported_raw)
            if conversion_ok:
                reclaim_ownership(exported_raw)
                os.rename(exported_raw, output_path)
                info_sidecar = f"{exported_raw}.info"
                if os.path.exists(info_sidecar):
                    os.rename(info_sidecar, f"{output_path}.info")

            tool_hashes = parse_ewf_hashes(snapshot_job()["log"])  # ewfexport only ever reports MD5, confirmed live
            report_data["acquisition_parameters"]["tool_reported_hashes"] = tool_hashes

            output_hashes = {}
            if conversion_ok:
                reclaim_ownership(output_path)
                append_log("[*] Independently hashing output after conversion for verification...")
                output_hashes = compute_file_hashes(output_path, requested_hashes)
            report_data["computed_verification_hashes"] = output_hashes
            hash_verified = bool(tool_hashes.get('md5')) and output_hashes.get('md5') == tool_hashes.get('md5')

        else:
            raise ValueError(f"Unsupported target format: {target_format}")

        report_data["acquisition_parameters"]["output_image_path"] = output_path
        report_data["acquisition_parameters"]["hash_verified"] = hash_verified
        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if conversion_ok:
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log(f"[+] Conversion completed successfully. Hash verified: {hash_verified}")
            report_data["acquisition_status"] = "COMPLETED"
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] Conversion failed with exit code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # Both directions run their real conversion tool via sudo, so any
        # output written before an exception/failure needs the same
        # reclaim-in-finally treatment execution_worker()/execution_worker_aff()
        # already give every other sudo'd acquisition tool's output.
        reclaim_ownership(os.path.dirname(source_image_path))
        update_job(active=False)
        clear_active_proc()

@acquisition_bp.route('/api/start_image_conversion', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_image_conversion():
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_image_path = safe_path(req.get('source_image_path'))
    target_format = (req.get('target_format') or '').lower()
    hashes = [h.lower() for h in req.get('hashes', ['sha256'])]
    metadata = req.get('metadata', {})

    if not source_image_path or not os.path.isfile(source_image_path):
        update_job(active=False)
        return jsonify({"success": False, "error": "Source image file not found or outside the permitted evidence directory."}), 400

    if target_format not in IMAGE_CONVERSION_FORMATS:
        update_job(active=False)
        return jsonify({"success": False, "error": f"Unsupported target format '{target_format}'. Use one of {sorted(IMAGE_CONVERSION_FORMATS)}."}), 400

    invalid_hashes = set(hashes) - ALLOWED_HASH_ALGOS
    if invalid_hashes:
        update_job(active=False)
        return jsonify({"success": False, "error": f"Unsupported hash algorithm(s): {sorted(invalid_hashes)}. Use any of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    ext = os.path.splitext(source_image_path)[1].lower()
    RAW_IMAGE_EXTENSIONS = {'.dd', '.raw', '.001', '.img'}
    if target_format == 'e01' and ext not in RAW_IMAGE_EXTENSIONS:
        update_job(active=False)
        return jsonify({"success": False, "error": f"raw -> E01 conversion requires a recognized raw image source ({', '.join(sorted(RAW_IMAGE_EXTENSIONS))})."}), 400
    if target_format == 'raw' and ext != '.e01':
        update_job(active=False)
        return jsonify({"success": False, "error": "E01 -> raw conversion requires an .E01 source file."}), 400

    # Hard-stop on any pre-existing collision rather than silently
    # overwriting - real, live-caught bug: ewfexport always writes its raw
    # output to exactly {base}.raw (regardless of -t's own basename intent),
    # and if the E01 being converted sits right next to the very .raw file
    # it was originally acquired FROM (the same base name, the single most
    # likely real-world case for this feature), that original file would be
    # silently clobbered before ever getting renamed to .dd. Checked for
    # both directions' actual output path, not just the raw side, since
    # ewfacquire's own overwrite behavior for a pre-existing .E01 was never
    # independently verified either - refusing outright is the safe default
    # regardless of what either tool would have done on its own.
    source_base, _source_ext = os.path.splitext(source_image_path)
    final_output_path = f"{source_base}.E01" if target_format == 'e01' else f"{source_base}.dd"
    ewfexport_intermediate_path = f"{source_base}.raw"
    collision_path = ewfexport_intermediate_path if (target_format == 'raw' and os.path.exists(ewfexport_intermediate_path)) \
        else (final_output_path if os.path.exists(final_output_path) else None)
    if collision_path:
        update_job(active=False)
        return jsonify({"success": False, "error": f"A file already exists at {collision_path} - rename or remove it first rather than risk it being overwritten by the conversion."}), 409

    base_name = os.path.splitext(os.path.basename(source_image_path))[0]
    dest_dir = os.path.dirname(source_image_path)

    report_data = {
        "tool": "image_conversion",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "source_image_path": source_image_path,
            "target_format": target_format,
            "requested_hashes": hashes,
            "case_number": metadata.get("case_number"),
            "evidence_id": metadata.get("evidence_id"),
            "examiner": metadata.get("examiner"),
        },
        "attachments": {
            "files": [],
            "reference_urls": []
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    report_target = build_report_target(dest_dir, dest_dir, f"{base_name}_converted")
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_image_conversion,
        args=(source_image_path, target_format, hashes, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("image_conversion_started", {"source": source_image_path, "target_format": target_format})
    return jsonify({"success": True})

# --- Logical / "Custom Content" Acquisition: package selected whole folders
# from an already-mounted evidence source (a write-blocked drive, or a
# network share - both already land under EVIDENCE_ROOT per this app's own
# mount conventions, so safe_path() already covers both with no boundary
# change needed) into one hash-verified evidence container + manifest,
# without imaging the whole device. FTK Imager's AD1/Custom Content Image
# equivalent - net new, nothing like it existed anywhere in this app before.
LOGICAL_ACQ_SKIP_DIRS = {'RECOVERED_FILES'}  # extundelete's fixed output dir name, matches _discover_case_files()'s own skip-list
LOGICAL_ACQ_MAX_FILES = 20000
LOGICAL_ACQ_MAX_TOTAL_BYTES = 20 * 1024**3  # 20 GB - generous vs the in-image tools' own caps, since this is a deliberate, examiner-curated multi-folder selection expected to legitimately be sizable sometimes

def _is_logical_acq_bulk_carve_dir(dirname):
    return dirname in LOGICAL_ACQ_SKIP_DIRS or dirname.endswith(('_photorec', '_foremost', '_scalpel', '_triagescan'))

def _enumerate_logical_acq_files(selected_folders):
    """Walks every selected folder (skipping this app's own bulk-carve-
    output directories, same convention as _discover_case_files() in
    routes/reporting.py), returning (files, total_bytes, truncated) where
    files is a list of (folder_root, abs_path, relative_path_within_folder).
    Stops enumerating - not copying, this is a dry pass - the instant either
    cap would be exceeded, so a genuinely oversized selection gets a clear
    truncation note rather than a silent partial result."""
    files = []
    total_bytes = 0
    truncated = False
    for folder in selected_folders:
        for root, dirs, filenames in os.walk(folder):
            dirs[:] = [d for d in dirs if not _is_logical_acq_bulk_carve_dir(d)]
            for fname in filenames:
                abs_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(abs_path)
                except OSError:
                    continue
                if len(files) >= LOGICAL_ACQ_MAX_FILES or total_bytes + size > LOGICAL_ACQ_MAX_TOTAL_BYTES:
                    truncated = True
                    return files, total_bytes, truncated
                rel_path = os.path.relpath(abs_path, folder)
                files.append((folder, abs_path, rel_path))
                total_bytes += size
    return files, total_bytes, truncated

def _unique_folder_label(basename, used_labels):
    label = basename or 'folder'
    n = 2
    while label in used_labels:
        label = f"{basename}_{n}"
        n += 1
    used_labels.add(label)
    return label

def execution_worker_logical_acquisition(selected_folders, output_root, requested_hashes, make_zip, report_file_path, report_data):
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    manifest_entries = []
    files_copied = 0
    files_errored = 0

    try:
        update_job(format='logical_acquisition', status="Enumerating selected folders...",
                   progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=0)
        append_log(f"[*] Enumerating {len(selected_folders)} selected folder(s)...")
        files, total_bytes, truncated = _enumerate_logical_acq_files(selected_folders)
        if truncated:
            append_log(f"[-] Selection exceeds the {LOGICAL_ACQ_MAX_FILES}-file / {LOGICAL_ACQ_MAX_TOTAL_BYTES // (1024**3)}GB cap - stopped enumerating early, only what was found before the cap will be included.")
        append_log(f"[*] Found {len(files)} file(s), {total_bytes} bytes total. Beginning copy...")
        update_job(status="Copying files...", total_bytes=total_bytes)

        os.makedirs(output_root, exist_ok=True)
        used_labels = set()
        folder_labels = {folder: _unique_folder_label(os.path.basename(folder.rstrip('/')) or 'folder', used_labels) for folder in selected_folders}

        transferred_bytes = 0
        for i, (folder, abs_path, rel_path) in enumerate(files):
            if snapshot_job()["status"] == "Stopped":
                append_log("[-] Stopped by examiner.")
                break
            dest_path = os.path.join(output_root, folder_labels[folder], rel_path)
            try:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy2(abs_path, dest_path)
                file_hashes = compute_file_hashes(dest_path, requested_hashes)
                size = os.path.getsize(dest_path)
                manifest_entries.append({
                    "original_path": abs_path,
                    "relative_output_path": os.path.join(folder_labels[folder], rel_path),
                    "size_bytes": size,
                    "hashes": file_hashes,
                })
                files_copied += 1
                transferred_bytes += size
            except Exception as e:
                files_errored += 1
                append_log(f"[-] Failed to copy {abs_path}: {e}")
                continue

            if i % 25 == 0 or i == len(files) - 1:
                pct = round(((i + 1) / len(files)) * 100, 1) if files else 100.0
                update_job(progress_percent=pct, transferred_bytes=transferred_bytes)

        # Manifest written regardless of a mid-run Stop, so whatever was
        # actually copied before stopping is still accounted for - matches
        # this app's own "hard error/honest partial result over silent data
        # loss" posture elsewhere (e.g. Hash Manifest's own truncation note).
        manifest_json_path = os.path.join(output_root, "manifest.json")
        manifest_txt_path = os.path.join(output_root, "manifest.txt")
        manifest_data = {
            "case_metadata": report_data.get("case_metadata", {}),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "selected_folders": selected_folders,
            "requested_hashes": requested_hashes,
            "truncated": truncated,
            "files_copied": files_copied,
            "files_errored": files_errored,
            "total_bytes": transferred_bytes,
            "entries": manifest_entries,
        }
        with open(manifest_json_path, 'w') as f:
            json.dump(manifest_data, f, indent=2)
        with open(manifest_txt_path, 'w') as f:
            f.write(f"Logical Acquisition Manifest - generated {manifest_data['generated_at']}\n")
            f.write(f"Selected folders: {', '.join(selected_folders)}\n")
            f.write(f"Files copied: {files_copied} ({transferred_bytes} bytes){' - TRUNCATED, see below' if truncated else ''}\n")
            if files_errored:
                f.write(f"Files that failed to copy: {files_errored} (see the job log)\n")
            f.write("\n")
            for entry in manifest_entries:
                hash_str = ", ".join(f"{a}={h}" for a, h in entry["hashes"].items())
                f.write(f"{entry['relative_output_path']}\t{entry['size_bytes']} bytes\t{hash_str}\n")
        append_log(f"[*] Wrote manifest.json and manifest.txt ({files_copied} file(s) recorded).")

        zip_path = None
        if make_zip:
            append_log("[*] Building .zip archive...")
            update_job(status="Building .zip archive...")
            zip_base = output_root.rstrip('/')
            zip_path = shutil.make_archive(zip_base, 'zip', root_dir=output_root)
            append_log(f"[*] Wrote {zip_path}")

        # Container-level hash for Evidence Inventory's existing one-hash-
        # per-event display - hash of the manifest.json itself (a
        # deterministic, single reference point), while every individual
        # file's own hash still lives inside the manifest for deeper
        # verification. Matches _pick_display_hash()'s documented
        # "one hash per item" assumption with zero schema change needed.
        container_hashes = compute_file_hashes(manifest_json_path, requested_hashes)

        report_data["acquisition_parameters"]["output_container_path"] = output_root
        report_data["acquisition_parameters"]["manifest_path"] = manifest_json_path
        report_data["acquisition_parameters"]["zip_path"] = zip_path
        report_data["acquisition_parameters"]["file_count"] = files_copied
        report_data["acquisition_parameters"]["total_bytes"] = transferred_bytes
        report_data["acquisition_parameters"]["truncated"] = truncated
        report_data["computed_verification_hashes"] = container_hashes
        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

        if snapshot_job()["status"] == "Stopped":
            report_data["acquisition_status"] = "STOPPED"
            append_log(f"[+] Stopped - {files_copied} file(s) were copied and included in the manifest before stopping.")
        elif files_errored and not files_copied:
            update_job(status="Failed")
            report_data["acquisition_status"] = "FAILED"
            append_log("[-] Every file failed to copy - nothing was captured.")
        else:
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            report_data["acquisition_status"] = "COMPLETED"
            append_log(f"[+] Logical acquisition completed successfully. {files_copied} file(s) captured, {files_errored} error(s).")

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # No sudo'd tool runs anywhere in this worker (safe_path()-validated
        # real filesystem paths, plain unprivileged file copies), so unlike
        # every other worker there's no root-owned output to reclaim here -
        # everything this worker writes is already owned by the service
        # account from the moment it's created.
        update_job(active=False)
        clear_active_proc()

@acquisition_bp.route('/api/start_logical_acquisition', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_logical_acquisition():
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    selected_folders_raw = req.get('selected_folders') or []
    dest_path = safe_path((req.get('destination') or EVIDENCE_ROOT).strip())
    hashes = [h.lower() for h in req.get('hashes', ['sha256'])]
    make_zip = bool(req.get('make_zip', False))
    metadata = req.get('metadata', {})

    if not selected_folders_raw:
        update_job(active=False)
        return jsonify({"success": False, "error": "Select at least one folder first."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"success": False, "error": "Destination path is outside the permitted evidence directory."}), 400

    selected_folders = []
    for raw in selected_folders_raw:
        validated = safe_path(raw)
        if not validated or not os.path.isdir(validated):
            update_job(active=False)
            return jsonify({"success": False, "error": f"'{raw}' is not a folder inside the permitted evidence directory."}), 400
        selected_folders.append(validated)

    invalid_hashes = set(hashes) - ALLOWED_HASH_ALGOS
    if invalid_hashes:
        update_job(active=False)
        return jsonify({"success": False, "error": f"Unsupported hash algorithm(s): {sorted(invalid_hashes)}. Use any of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    case_num = metadata.get('case_number') or 'UNASSIGNED'
    evidence_id = metadata.get('evidence_id') or 'ITEM-01'
    base_name = f"{case_num}_{evidence_id}"
    output_root = os.path.join(dest_path, f"{base_name}_logical")

    if os.path.exists(output_root):
        update_job(active=False)
        return jsonify({"success": False, "error": f"{output_root} already exists - rename/remove it, or change the Evidence ID, before starting."}), 409

    report_data = {
        "tool": "logical_acquisition",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "selected_folders": selected_folders,
            "requested_hashes": hashes,
            "make_zip": make_zip,
        },
        "attachments": {
            "files": [],
            "reference_urls": []
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_logical_acquisition,
        args=(selected_folders, output_root, hashes, make_zip, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("logical_acquisition_started", {"selected_folders": selected_folders, "destination": output_root})
    return jsonify({"success": True})


# --- Live Collection USB (Phase A: build) ---
# Prepares a confirmed-blank USB drive with live-forensics collector
# tooling (UAC for Unix-like targets, a hand-written PowerShell script
# for Windows) so an examiner can plug it into a separate, live target
# machine to gather volatile artifacts, then bring it back to import the
# results into a case (Phase B, below). See core/live_collection_utils.py
# for the wipe/partition/format/mount mechanics and the device_write_lock
# block above this file's BitLocker section for the race-avoidance
# mechanism that exempts the target device from list_drives()'s normal
# auto-relock for exactly this job's duration.
LIVE_COLLECTION_BUILD_MOUNTPOINT = os.path.join(INSTALL_DIR, ".live_collection_mounts", "build")
LIVE_COLLECTION_SCAN_MOUNTPOINT = os.path.join(INSTALL_DIR, ".live_collection_mounts", "scan")
LIVE_COLLECTION_IMPORT_MOUNTPOINT = os.path.join(INSTALL_DIR, ".live_collection_mounts", "import")
LIVE_COLLECTION_ASSETS_DIR = os.path.join(INSTALL_DIR, "live_collection_assets")
LIVE_COLLECTION_UAC_DIR = os.path.join(INSTALL_DIR, "live_collection", "uac")
# Optional memory-acquisition tools (AVML for Unix targets, WinPmem for
# Windows) vendored by install.py's own single-file-release-asset download
# step - see that step's own comment for exactly why/how. Same "local
# constant, not centralized in core/config.py" precedent as
# LIVE_COLLECTION_UAC_DIR just above (both are consumed by exactly this one
# build worker, in exactly this one file).
LIVE_COLLECTION_MEMORY_DIR = os.path.join(INSTALL_DIR, "live_collection", "memory")


def execution_worker_build_collection_usb(device, device_info, source_ip=None, user=None):
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    try:
        update_job(format='live_collection_build', status="Checking device...",
                   progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

        fast_path = check_existing_collection_volume(device)
        partition = f"{device}1"

        unlocked, unlock_error = _unlock_device_for_write(device)
        if not unlocked:
            update_job(status="Failed")
            append_log(f"[-] {unlock_error}")
            return
        try:
            append_log(f"[*] Unmounting any existing partitions on {device}...")
            unmount_all_partitions(device)

            if fast_path["already_prepared"]:
                append_log(f"[*] {fast_path['reason']} Skipping wipe/format - reusing the existing volume.")
                update_job(status="Reusing already-prepared collection volume...", progress_percent=20.0)
            else:
                append_log(f"[*] Not already a prepared collection volume ({fast_path['reason']}) - performing a full wipe and format.")
                update_job(status="Wiping and formatting drive...", progress_percent=10.0)
                if snapshot_job()["status"] == "Stopped":
                    append_log("[-] Stopped by examiner before any destructive step ran - device was never wiped.")
                    return
                fmt_result = wipe_and_format_device(device, append_log)
                if not fmt_result["success"]:
                    update_job(status="Failed")
                    append_log(f"[-] {fmt_result['error']}")
                    return
                update_job(progress_percent=40.0)

            if snapshot_job()["status"] == "Stopped":
                append_log("[-] Stopped by examiner.")
                return

            update_job(status="Mounting and copying collector tooling...", progress_percent=50.0)
            uid, gid = os.getuid(), os.getgid()
            mount_result = mount_collection_partition(partition, LIVE_COLLECTION_BUILD_MOUNTPOINT, uid, gid, read_only=False)
            if not mount_result["success"]:
                update_job(status="Failed")
                append_log(f"[-] Could not mount {partition}: {mount_result['error']}")
                return

            try:
                mnt = LIVE_COLLECTION_BUILD_MOUNTPOINT
                os.makedirs(os.path.join(mnt, "uac", "output"), exist_ok=True)
                os.makedirs(os.path.join(mnt, "windows", "results"), exist_ok=True)

                if os.path.isdir(LIVE_COLLECTION_UAC_DIR):
                    uac_dest = os.path.join(mnt, "uac")
                    for name in os.listdir(LIVE_COLLECTION_UAC_DIR):
                        # install.py's vendoring step is a full `git clone`,
                        # not a source-only export - .git/.github are pure
                        # dev/CI metadata with zero runtime value on a
                        # collection drive (confirmed live: .git alone is
                        # 8.4MB, ~28% of the whole UAC payload) and were
                        # being copied onto every built USB for nothing.
                        if name in ('.git', '.github'):
                            continue
                        src = os.path.join(LIVE_COLLECTION_UAC_DIR, name)
                        dst = os.path.join(uac_dest, name)
                        if os.path.isdir(src):
                            shutil.copytree(src, dst, dirs_exist_ok=True)
                        else:
                            shutil.copy2(src, dst)
                    append_log("[*] Copied UAC (Unix/Linux/macOS collector).")
                else:
                    append_log("[!] UAC was not found on this station (install.py's vendoring step "
                               "may not have run, or ran without internet access) - only the Windows "
                               "collector will be on this drive.")

                for asset_name, dest_rel in (
                    ("run_collector.sh", os.path.join("uac", "run_collector.sh")),
                    ("windows_collector.ps1", os.path.join("windows", "windows_collector.ps1")),
                    ("launch_collector.cmd", os.path.join("windows", "launch_collector.cmd")),
                    ("README.txt", "README.txt"),
                ):
                    src = os.path.join(LIVE_COLLECTION_ASSETS_DIR, asset_name)
                    if os.path.isfile(src):
                        dst = os.path.join(mnt, dest_rel)
                        shutil.copy2(src, dst)
                        if asset_name.endswith((".sh",)):
                            os.chmod(dst, 0o755)
                append_log("[*] Copied Windows collector, launcher, and README.")

                # Optional memory-acquisition tools - same "if missing, log
                # and continue, never fail the whole build" tolerance as
                # every other asset copy above (install.py's own vendoring
                # step is itself non-fatal-on-failure, so this is a real,
                # expected state on a station that installed offline).
                if os.path.isdir(LIVE_COLLECTION_MEMORY_DIR) and os.listdir(LIVE_COLLECTION_MEMORY_DIR):
                    memory_files = os.listdir(LIVE_COLLECTION_MEMORY_DIR)
                    uac_memory_dest = os.path.join(mnt, "uac", "memory")
                    windows_memory_dest = os.path.join(mnt, "windows", "memory")
                    os.makedirs(uac_memory_dest, exist_ok=True)
                    os.makedirs(windows_memory_dest, exist_ok=True)
                    copied_any = False
                    for name in memory_files:
                        src = os.path.join(LIVE_COLLECTION_MEMORY_DIR, name)
                        if name.startswith("avml"):
                            dst = os.path.join(uac_memory_dest, name)
                            shutil.copy2(src, dst)
                            os.chmod(dst, 0o755)
                            copied_any = True
                        elif name == "winpmem.exe":
                            shutil.copy2(src, os.path.join(windows_memory_dest, name))
                            copied_any = True
                    if copied_any:
                        append_log("[*] Copied optional memory-acquisition tools (AVML/WinPmem).")
                else:
                    append_log("[!] Memory-acquisition tools were not found on this station "
                               "(install.py's vendoring step may not have run, or ran without "
                               "internet access) - the memory-capture prompt on this drive will "
                               "have nothing to run.")

                update_job(status="Finalizing (unmounting)...", progress_percent=90.0)
            finally:
                unmount_result = unmount_collection_partition(LIVE_COLLECTION_BUILD_MOUNTPOINT)

            if unmount_result.get("warning"):
                # The asset copy already fully succeeded by this point - a
                # slow/uncertain unmount on its own isn't reason enough to
                # report the whole build as failed (see unmount_collection_
                # partition()'s own docstring for why this can happen on
                # real physical media), but it IS worth a clear, visible
                # caveat rather than silently claiming full success.
                append_log(f"[!] {unmount_result['warning']} The drive's tooling was fully copied, but "
                           f"double-check it mounts cleanly on the target machine before relying on it.")
            update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
            append_log("[+] Live Collection USB build completed successfully.")
            log_chain_of_custody("live_collection_usb_built", {
                "device": device, "model": device_info.get("model"),
                "serial": device_info.get("serial"), "size": device_info.get("size"),
                "reused_existing_volume": fast_path["already_prepared"],
            }, source_ip=source_ip, user=user)
        finally:
            _relock_device_after_write(device)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        update_job(active=False)


@acquisition_bp.route('/api/live_collection/start_build', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_build_collection_usb():
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    device = (req.get('device') or '').strip()
    device_info = req.get('device_info') or {}

    if not is_valid_block_device(device):
        update_job(active=False)
        return jsonify({"success": False, "error": f"'{device}' is not a recognized whole-disk device."}), 400

    # Fail fast, before ever spawning the worker thread - see
    # _unlock_device_for_write()'s own docstring for why blue-port devices
    # are permanently ineligible. This is a UX improvement (an instant,
    # clear error instead of watching "Checking device..." fail moments
    # later) - _unlock_device_for_write() itself still enforces this too,
    # as the real, authoritative gate.
    port_class = classify_usb_port(device)
    if port_class != "black":
        update_job(active=False)
        return jsonify({"success": False, "error": (
            f"Live Collection USB can only be built onto a drive in one of this station's 2 standard "
            f"(black) USB ports - the 2 USB 3.0 (blue) ports are reserved for evidence and always stay "
            f"write-blocked. {device} is not confirmed to be in one of those ports (detected: "
            f"{port_class or 'unrecognized'}). Move the drive to a black port and try again."
        )}), 400

    # Real bug found live (2026-09-03): the worker's own completion
    # log_chain_of_custody() call runs from inside this background thread,
    # which has no active Flask request/app context - calling it with no
    # explicit source_ip/user (its default fallback reads request/g)
    # raised "Working outside of application context" AFTER a genuinely
    # successful build, and the outer exception handler then overwrote the
    # already-correct "Completed Successfully" status back to "Failed" -
    # reporting a real success as a failure. Capture both here, in the real
    # request thread, and thread them through explicitly - the same
    # established pattern already used elsewhere in this file (see e.g.
    # the decrypted-source cleanup thread above).
    requester_ip = request.remote_addr
    requester_user = getattr(g, 'forensic_user', None)
    thread = threading.Thread(
        target=execution_worker_build_collection_usb,
        args=(device, device_info, requester_ip, requester_user),
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("live_collection_usb_build_started", {"device": device, "device_info": device_info})
    return jsonify({"success": True})


# --- Live Collection USB (Phase B: import results) ---
@acquisition_bp.route('/api/live_collection/scan', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def scan_live_collection_results():
    """Synchronous, read-only - mounts the device's partition read-only,
    discovers real result run folders, unmounts, and returns the list for
    the examiner to review before choosing what to import. No job-slot
    claim needed (quick, read-only, doesn't touch current_job) - the same
    pattern this app's BitLocker/LUKS/VeraCrypt "detect" routes already
    use for a quick look before the real (job-driven) action."""
    req = request.get_json() or {}
    device = (req.get('device') or '').strip()
    if not is_valid_block_device(device):
        return jsonify({"success": False, "error": f"'{device}' is not a recognized whole-disk device."}), 400

    partition = f"{device}1"
    if not os.path.exists(partition):
        return jsonify({"success": False, "error": f"No partition found on {device}. Has a Live Collection USB been built and used on this drive?"}), 400

    uid, gid = os.getuid(), os.getgid()
    mount_result = mount_collection_partition(partition, LIVE_COLLECTION_SCAN_MOUNTPOINT, uid, gid, read_only=True)
    if not mount_result["success"]:
        return jsonify({"success": False, "error": f"Could not mount {partition}: {mount_result['error']}"}), 500

    try:
        runs = discover_collection_runs(LIVE_COLLECTION_SCAN_MOUNTPOINT)
    finally:
        unmount_collection_partition(LIVE_COLLECTION_SCAN_MOUNTPOINT)

    return jsonify({"success": True, "runs": runs})


def execution_worker_import_live_collection(device, selected_relative_paths, case_folder, requested_hashes, report_file_path, report_data):
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    manifest_entries = []
    files_copied = 0
    files_errored = 0
    partition = f"{device}1"

    try:
        update_job(format='live_collection_import', status="Mounting collection USB (read-only)...",
                   progress_percent=0.0, speed_mbps=0.0, transferred_bytes=0, total_bytes=0)
        uid, gid = os.getuid(), os.getgid()
        mount_result = mount_collection_partition(partition, LIVE_COLLECTION_IMPORT_MOUNTPOINT, uid, gid, read_only=True)
        if not mount_result["success"]:
            update_job(status="Failed")
            append_log(f"[-] Could not mount {partition}: {mount_result['error']}")
            report_data["acquisition_status"] = "FAILED"
            _write_report(report_file_path, report_data, append_log)
            return

        try:
            append_log("[*] Re-discovering result runs on the mounted drive (server-authoritative, not trusting client-supplied metadata)...")
            all_runs = discover_collection_runs(LIVE_COLLECTION_IMPORT_MOUNTPOINT)
            runs_to_import = [r for r in all_runs if r["relative_path"] in selected_relative_paths]
            if not runs_to_import:
                update_job(status="Failed")
                append_log("[-] None of the selected result run(s) were found on this drive anymore.")
                report_data["acquisition_status"] = "FAILED"
                _write_report(report_file_path, report_data, append_log)
                return

            output_root = os.path.join(case_folder, f"live_collection_import_{time.strftime('%Y%m%d_%H%M%S')}")
            # Never write back onto the USB itself, or into any path nested
            # under its own mountpoint - the case folder is always a real,
            # safe_path()-validated path elsewhere on this station, but this
            # is cheap, direct insurance against that ever regressing.
            real_dest = os.path.realpath(output_root)
            real_source = os.path.realpath(LIVE_COLLECTION_IMPORT_MOUNTPOINT)
            if real_dest == real_source or real_dest.startswith(real_source + os.sep):
                update_job(status="Failed")
                append_log("[-] Refusing to write the import destination onto the source USB itself.")
                report_data["acquisition_status"] = "FAILED"
                _write_report(report_file_path, report_data, append_log)
                return
            os.makedirs(output_root, exist_ok=True)

            all_files = []
            for run in runs_to_import:
                run_src = os.path.join(LIVE_COLLECTION_IMPORT_MOUNTPOINT, run["relative_path"])
                run_label = f"{run['platform']}_{run['run_name']}"
                for root, _dirs, files in os.walk(run_src):
                    for name in files:
                        abs_path = os.path.join(root, name)
                        rel_path = os.path.join(run_label, os.path.relpath(abs_path, run_src))
                        all_files.append((abs_path, rel_path))

            total_files = len(all_files)
            append_log(f"[*] Importing {total_files} file(s) from {len(runs_to_import)} result run(s)...")
            update_job(status="Copying files...", total_bytes=sum(os.path.getsize(p) for p, _ in all_files if os.path.exists(p)))

            transferred_bytes = 0
            for i, (abs_path, rel_path) in enumerate(all_files):
                if snapshot_job()["status"] == "Stopped":
                    append_log("[-] Stopped by examiner.")
                    break
                dest_path = os.path.join(output_root, rel_path)
                try:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy2(abs_path, dest_path)
                    file_hashes = compute_file_hashes(dest_path, requested_hashes)
                    size = os.path.getsize(dest_path)
                    manifest_entries.append({
                        "original_relative_path": rel_path,
                        "size_bytes": size,
                        "hashes": file_hashes,
                    })
                    files_copied += 1
                    transferred_bytes += size
                except Exception as e:
                    files_errored += 1
                    append_log(f"[-] Failed to copy {rel_path}: {e}")
                    continue
                if i % 25 == 0 or i == total_files - 1:
                    pct = round(((i + 1) / total_files) * 100, 1) if total_files else 100.0
                    update_job(progress_percent=pct, transferred_bytes=transferred_bytes)

            manifest_json_path = os.path.join(output_root, "manifest.json")
            manifest_txt_path = os.path.join(output_root, "manifest.txt")
            manifest_data = {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_device": device,
                "imported_runs": [r["relative_path"] for r in runs_to_import],
                "files_copied": files_copied,
                "files_errored": files_errored,
                "total_bytes": transferred_bytes,
                "entries": manifest_entries,
            }
            with open(manifest_json_path, 'w') as f:
                json.dump(manifest_data, f, indent=2)
            with open(manifest_txt_path, 'w') as f:
                f.write(f"Live Collection Import Manifest - generated {manifest_data['generated_at']}\n")
                f.write(f"Imported run(s): {', '.join(manifest_data['imported_runs'])}\n")
                f.write(f"Files copied: {files_copied} ({transferred_bytes} bytes)\n")
                if files_errored:
                    f.write(f"Files that failed to copy: {files_errored} (see the job log)\n")
                f.write("\n")
                for entry in manifest_entries:
                    hash_str = ", ".join(f"{a}={h}" for a, h in entry["hashes"].items())
                    f.write(f"{entry['original_relative_path']}\t{entry['size_bytes']} bytes\t{hash_str}\n")
            append_log(f"[*] Wrote manifest.json and manifest.txt ({files_copied} file(s) recorded).")

            # Parses every already-copied run's own result files into this
            # app's standard artifact-record shape (see core/live_
            # collection_results_utils.py's own docstring for the split
            # between the fully-scoped Windows-JSON side and the
            # deliberately narrow Unix/UAC side) - a cheap additional pass
            # over data already in hand from the copy loop above, not a
            # second scan. Reads from output_root (the already-copied
            # DESTINATION), never the source USB - matches this worker's
            # own "never re-read from the source drive" discipline
            # everywhere else. Persisted via the exact same _record_
            # parsed_artifacts() every other artifact parser in this app
            # already uses - File Views' "Parsed Artifacts" category, the
            # Reporting Web Artifacts gallery, and the Evidence Timeline all
            # pick these up automatically once live_collection_* is in both
            # PARSED_ARTIFACT_TYPE_LABELS (routes/case_index.py) and its
            # required JS-side mirror (static/js/main.js) - zero further
            # wiring needed here.
            all_parsed_records = []
            all_process_records = []
            for run in runs_to_import:
                run_label = f"{run['platform']}_{run['run_name']}"
                run_dest = os.path.join(output_root, run_label)
                run_ts = run_timestamp_to_epoch(run.get('timestamp') or '') or time.time()
                try:
                    if run['platform'] == 'windows':
                        run_records = parse_windows_collector_run(run_dest, run_ts)
                    else:
                        run_records = parse_unix_collector_run(run_dest, run_ts)
                except Exception as e:
                    append_log(f"[-] Could not parse results for {run_label}: {e}")
                    run_records = []
                all_parsed_records.extend(run_records)
                all_process_records.extend([r for r in run_records if r['artifact_type'] == 'live_collection_process'])

            hash_list_match_count = 0
            if all_process_records:
                # Same "check every configured list automatically, no
                # examiner selection needed" precedent already established
                # by routes/file_explorer.py's own browser-artifact URL-list
                # check (confirmed before writing this) - never a new UI/
                # request parameter for which lists to check.
                try:
                    hash_sets = load_hash_list_sets([hl['id'] for hl in get_hash_lists()])
                    match_records = build_hash_list_match_records(all_process_records, hash_sets, run_timestamp=time.time())
                    all_parsed_records.extend(match_records)
                    hash_list_match_count = len(match_records)
                    if hash_list_match_count:
                        append_log(f"[!] {hash_list_match_count} process executable(s) matched a configured hash list.")
                except Exception as e:
                    append_log(f"[-] Hash-list cross-reference failed (non-fatal): {e}")

            if all_parsed_records:
                try:
                    persisted = _record_parsed_artifacts(case_folder, {"source_type": "real_fs", "path": output_root}, all_parsed_records)
                    append_log(f"[*] Parsed {persisted} artifact record(s) into the case index.")
                except Exception as e:
                    append_log(f"[-] Could not persist parsed artifact records (non-fatal): {e}")

            # A one-page summary at a glance, alongside the existing
            # manifest.json/manifest.txt - built from data this worker
            # already has in hand (the manifest entries + the parse pass
            # just above), no extra file re-reads.
            try:
                by_type_counts = {}
                for r in all_parsed_records:
                    by_type_counts[r['artifact_type']] = by_type_counts.get(r['artifact_type'], 0) + 1
                memory_entry = next((e for e in manifest_entries if os.path.basename(e['original_relative_path']) in ('memory.lime', 'memory.raw')), None)
                summary_data = {
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "imported_runs": manifest_data["imported_runs"],
                    "process_count": by_type_counts.get('live_collection_process', 0),
                    "network_connection_count": by_type_counts.get('live_collection_network_connection', 0),
                    "service_count": by_type_counts.get('live_collection_service', 0),
                    "scheduled_task_count": by_type_counts.get('live_collection_scheduled_task', 0),
                    "autorun_count": by_type_counts.get('live_collection_autorun', 0),
                    "hash_list_match_count": hash_list_match_count,
                    "memory_image_captured": memory_entry is not None,
                    "memory_image_size_bytes": memory_entry['size_bytes'] if memory_entry else None,
                }
                with open(os.path.join(output_root, "summary.json"), 'w') as f:
                    json.dump(summary_data, f, indent=2)
                with open(os.path.join(output_root, "SUMMARY.txt"), 'w') as f:
                    f.write(f"Live Collection Import Summary - generated {summary_data['generated_at']}\n")
                    f.write(f"Imported run(s): {', '.join(summary_data['imported_runs'])}\n\n")
                    f.write(f"Processes: {summary_data['process_count']}\n")
                    f.write(f"Network connections: {summary_data['network_connection_count']}\n")
                    f.write(f"Services: {summary_data['service_count']}\n")
                    f.write(f"Scheduled tasks: {summary_data['scheduled_task_count']}\n")
                    f.write(f"Autorun/startup entries: {summary_data['autorun_count']}\n")
                    f.write(f"Hash-list matches: {summary_data['hash_list_match_count']}\n")
                    if summary_data['memory_image_captured']:
                        mb = round(summary_data['memory_image_size_bytes'] / (1024 * 1024))
                        f.write(f"Memory image: captured ({mb} MB)\n")
                    else:
                        f.write("Memory image: not captured\n")
                append_log("[*] Wrote summary.json and SUMMARY.txt.")
            except Exception as e:
                append_log(f"[-] Could not write summary (non-fatal): {e}")

            # Tags the whole import folder (not just manifest.json) into the
            # per-case index as an 'analysis_log'-role artifact - matches
            # classify_case_role()'s live_collection_import_<timestamp>
            # directory pattern (core/paths.py), so it groups alongside this
            # app's other derived-analysis-output folders (ALEAPP/iLEAPP)
            # rather than sitting unclassified. Best-effort, matching every
            # other _auto_tag_case_artifact() call site in this app.
            _auto_tag_case_artifact(case_folder, output_root)

            container_hashes = compute_file_hashes(manifest_json_path, requested_hashes)
            report_data["acquisition_parameters"]["output_container_path"] = output_root
            report_data["acquisition_parameters"]["manifest_path"] = manifest_json_path
            report_data["acquisition_parameters"]["source_device"] = device
            report_data["acquisition_parameters"]["imported_runs"] = manifest_data["imported_runs"]
            report_data["acquisition_parameters"]["file_count"] = files_copied
            report_data["acquisition_parameters"]["total_bytes"] = transferred_bytes
            report_data["computed_verification_hashes"] = container_hashes
            report_data["execution_time_seconds"] = round(time.time() - start_time, 2)

            if snapshot_job()["status"] == "Stopped":
                report_data["acquisition_status"] = "STOPPED"
                append_log(f"[+] Stopped - {files_copied} file(s) were imported and included in the manifest before stopping.")
            elif files_errored and not files_copied:
                update_job(status="Failed")
                report_data["acquisition_status"] = "FAILED"
                append_log("[-] Every file failed to import - nothing was captured.")
            else:
                update_job(status="Completed Successfully", progress_percent=100.0, speed_mbps=0.0)
                report_data["acquisition_status"] = "COMPLETED"
                append_log(f"[+] Live collection import completed successfully. {files_copied} file(s) captured, {files_errored} error(s).")

            _write_report(report_file_path, report_data, append_log)
        finally:
            unmount_collection_partition(LIVE_COLLECTION_IMPORT_MOUNTPOINT)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")
    finally:
        update_job(active=False)


@acquisition_bp.route('/api/live_collection/start_import', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_import_live_collection():
    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    device = (req.get('device') or '').strip()
    selected_relative_paths = req.get('selected_relative_paths') or []
    dest_path = safe_path((req.get('destination') or EVIDENCE_ROOT).strip())
    hashes = [h.lower() for h in req.get('hashes', ['sha256'])]
    metadata = req.get('metadata', {})

    if not is_valid_block_device(device):
        update_job(active=False)
        return jsonify({"success": False, "error": f"'{device}' is not a recognized whole-disk device."}), 400
    if not selected_relative_paths:
        update_job(active=False)
        return jsonify({"success": False, "error": "Select at least one result run to import first."}), 400
    if not dest_path:
        update_job(active=False)
        return jsonify({"success": False, "error": "Destination path is outside the permitted evidence directory."}), 400
    invalid_hashes = set(hashes) - ALLOWED_HASH_ALGOS
    if invalid_hashes:
        update_job(active=False)
        return jsonify({"success": False, "error": f"Unsupported hash algorithm(s): {sorted(invalid_hashes)}. Use any of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    case_num = metadata.get('case_number') or 'UNASSIGNED'
    evidence_id = metadata.get('evidence_id') or 'LIVECOLLECT-01'
    base_name = f"{case_num}_{evidence_id}"

    report_data = {
        "tool": "live_collection_import",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "source_device": device,
            "requested_hashes": hashes,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_import_live_collection,
        args=(device, selected_relative_paths, dest_path, hashes, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("live_collection_import_started", {"device": device, "selected_relative_paths": selected_relative_paths, "destination": dest_path})
    return jsonify({"success": True})


@acquisition_bp.route('/api/drives', methods=['GET'])
@requires_auth
def list_drives():
    drives = []
    try:
        res = subprocess.run(
            ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,MODEL,TRAN,TYPE,SERIAL,RO'],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            data = json.loads(res.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') == 'disk' and not dev['name'].startswith('loop'):
                    bytes_size = int(dev.get('size', 0))
                    gb_size = round(bytes_size / (1024**3), 1)
                    dev_path = f"/dev/{dev['name']}"

                    # Force read-only lock upon discovery - race-safe
                    # against a concurrent Live Collection USB build job
                    # (or, since 2026-09-05, a manually toggled-unlocked
                    # drive) via _relock_device_for_list_drives() (skips
                    # this exact device, under device_write_lock, while
                    # it's legitimately unlocked and tracked in
                    # active_write_unlocked_devices).
                    _relock_device_for_list_drives(dev_path)

                    # read_only now reflects real, current state (a plain
                    # dict-membership read is fine here - this is a display
                    # field, not a security decision; the actual gate is
                    # _unlock_device_for_write()'s own port check, done
                    # under device_write_lock, not this) - previously
                    # hardcoded True unconditionally, which would have
                    # misreported a drive as locked while it was still
                    # legitimately, deliberately unlocked via the toggle.
                    # port_class ('blue'/'black'/'unknown') lets the
                    # frontend show which of the 2 evidence-only vs 2
                    # utility ports a drive is actually in - see
                    # classify_usb_port()'s own docstring in core/paths.py.
                    port_info = describe_usb_port(dev_path) or {"color": None, "port_index": None}
                    drives.append({
                        "name": dev['name'],
                        "device": dev_path,
                        "model": dev.get('model') or 'Generic Disk',
                        "size": f"{gb_size} GB",
                        "bytes": bytes_size,
                        "transport": dev.get('tran') or 'usb',
                        "serial": dev.get('serial') or 'N/A',
                        "read_only": dev_path not in active_write_unlocked_devices,
                        "port_class": port_info["color"],
                        # 1-4, or None if only the color (not the specific
                        # physical port) could be confirmed - see
                        # describe_usb_port()'s own docstring. Used by the
                        # Drive Management port diagram to highlight the
                        # exact slot a drive is in, not just its color.
                        "port_index": port_info["port_index"],
                    })
    except Exception as e:
        print(f"Error executing lsblk: {e}")

    return jsonify(drives)


@acquisition_bp.route('/api/system/pi_hardware_info', methods=['GET'])
@requires_auth
def pi_hardware_info():
    """The station's own detected board model, and whether this app's USB
    port diagram/classification is confirmed to apply to it - see
    core/config.py's detect_pi_model()/usb_port_diagram_supported() for why
    this is a real, empirically-scoped check (Pi 4B only), not assumed for
    any board. A separate, tiny route rather than folded into /api/drives -
    this is a station-wide fact, not a per-drive one, and keeping it apart
    avoids changing /api/drives' own existing response shape."""
    return jsonify({
        "pi_model": detect_pi_model(),
        "usb_port_diagram_supported": usb_port_diagram_supported(),
    })

@acquisition_bp.route('/api/smart_check', methods=['POST'])
@requires_auth
def smart_check():
    req = request.get_json() or {}
    drive = req.get('drive', '')
    
    if not drive or not drive.startswith('/dev/'):
        return jsonify({"success": False, "error": "Invalid drive selection"})

    try:
        total_bytes = 0
        try:
            res_sz = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', drive], capture_output=True, text=True)
            if res_sz.returncode == 0:
                total_bytes = int(res_sz.stdout.strip())
        except Exception:
            pass

        capacity_str = f"{round(total_bytes / (1024**3), 2)} GB" if total_bytes > 0 else "N/A"

        res = subprocess.run(['sudo', 'smartctl', '-a', '-j', drive], capture_output=True, text=True)
        data = json.loads(res.stdout) if res.stdout else {}
        
        healthy = data.get('smart_status', {}).get('passed', True)
        family = data.get('model_family') or data.get('family_name')
        model = data.get('model_name') or data.get('device', {}).get('name')
        
        if family and model and family.lower() not in model.lower():
            vendor_model_str = f"{family} ({model})"
        elif family:
            vendor_model_str = family
        else:
            vendor_model_str = model or "Generic Media"

        serial = data.get('serial_number', 'N/A')
        temp = data.get('temperature', {}).get('current')
        
        dev_type = data.get('device', {}).get('type', '')
        protocol = data.get('device', {}).get('protocol', '')
        media_type = f"{protocol.upper()} / {dev_type.upper()} Storage" if protocol else "USB / ATA Storage"

        reallocated = 0
        pending = 0
        power_on = None
        
        for attr in data.get('ata_smart_attributes', {}).get('table', []):
            attr_id = attr.get('id')
            if attr_id == 5:
                reallocated = attr.get('raw', {}).get('value', 0)
            elif attr_id == 197:
                pending = attr.get('raw', {}).get('value', 0)
            elif attr_id == 9:
                power_on = attr.get('raw', {}).get('value')

        return jsonify({
            "success": True,
            "healthy": healthy,
            "vendor_model": vendor_model_str,
            "media_type": media_type,
            "capacity": capacity_str,
            "serial": serial,
            "temperature": temp,
            "reallocated_sectors": reallocated,
            "pending_sectors": pending,
            "power_on_hours": power_on
        })

    except Exception:
        return jsonify({
            "success": True,
            "healthy": True,
            "vendor_model": "Generic Media Device",
            "media_type": "USB / Storage Media",
            "capacity": "N/A",
            "serial": "N/A",
            "temperature": None,
            "reallocated_sectors": 0,
            "pending_sectors": 0,
            "power_on_hours": None
        })

@acquisition_bp.route('/api/toggle_write_block', methods=['POST'])
@requires_auth
@requires_permission('settings')
def toggle_write_block():
    req = request.get_json() or {}
    enable = req.get('enable', True)
    drive = req.get('drive', '/dev/sda')

    # Strict whitelist instead of startswith('/dev/'), which previously let
    # values like "/dev/sda; rm -rf /" through into a shell=True call below.
    if not is_valid_block_device(drive):
        return jsonify({"success": False, "error": f"'{drive}' is not a recognized whole-disk device."}), 400

    try:
        if not enable:
            # Real bug found live (2026-09-05): this route used to call
            # blockdev --setrw directly with no exemption-registry update
            # at all - the flag genuinely flipped for a moment, but
            # list_drives()'s own periodic re-lock (every /api/drives poll,
            # which the frontend does routinely) had no record of this
            # unlock being legitimate and silently reverted it within
            # seconds. Unlocking now goes through the same
            # _unlock_device_for_write() the Live Collection USB build
            # uses, which both registers the exemption AND enforces the
            # black-port-only rule - see that function's own docstring.
            # Unmount first (unchanged) so an unlock never races a
            # still-mounted filesystem.
            for part in sorted(glob.glob(f"{drive}*")):
                subprocess.run(['sudo', 'udevil', 'unmount', '-b', part], capture_output=True)
                subprocess.run(['sudo', 'umount', part], capture_output=True)

            unlocked, unlock_error = _unlock_device_for_write(drive)
            if not unlocked:
                return jsonify({"success": False, "error": unlock_error}), 400
        else:
            # Re-locking is always safe on any port - clear the exemption
            # (if any) under the same lock the relock/unlock paths already
            # use, then actually flip the flag.
            with device_write_lock:
                active_write_unlocked_devices.pop(drive, None)
                res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--setro', drive], capture_output=True, text=True)
            if res.returncode != 0:
                return jsonify({"success": False, "error": res.stderr.strip() or "blockdev execution failed"}), 500

        chk = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getro', drive], capture_output=True, text=True)
        is_ro = (chk.returncode == 0 and chk.stdout.strip() == '1')

        return jsonify({"success": True, "write_blocker_active": is_ro, "device": drive})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@acquisition_bp.route('/api/bitlocker/partitions', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_partitions():
    req = request.get_json() or {}
    device = req.get('device', '')
    if not is_valid_block_device(device):
        return jsonify({"success": False, "error": "Not a recognized whole-disk device."}), 400
    return jsonify({"success": True, "partitions": _list_device_partitions(device)})

@acquisition_bp.route('/api/bitlocker/detect', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_detect():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    result = _detect_bitlocker(partition)
    if result is None:
        return jsonify({"success": False, "error": "Invalid or unrecognized device/partition path."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/bitlocker/unlock', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_unlock():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    recovery_key = req.get('recovery_key', '')
    success, mount_id, source_path, error = _dislocker_unlock(partition, recovery_key)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("bitlocker_unlock", {"device": partition, "mount_id": mount_id})
    return jsonify({"success": True, "mount_id": mount_id, "source_path": source_path})

@acquisition_bp.route('/api/bitlocker/detect_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def bitlocker_detect_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    result = _detect_bitlocker_image(image_path, offset)
    if result is None:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/bitlocker/unlock_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def bitlocker_unlock_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    recovery_key = req.get('recovery_key', '')
    success, mount_id, source_path, error = _dislocker_unlock(image_path, recovery_key, offset=offset)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("bitlocker_unlock_image", {"image_path": image_path, "offset": offset, "mount_id": mount_id})
    return jsonify({"success": True, "mount_id": mount_id, "source_path": source_path})

@acquisition_bp.route('/api/bitlocker/lock', methods=['POST'])
@requires_auth
@requires_permission('acquisition', 'file_explorer')
def bitlocker_lock_route():
    req = request.get_json() or {}
    mount_id = req.get('mount_id', '')
    success, error = _dislocker_lock(mount_id)
    if not success:
        return jsonify({"success": False, "error": error}), 500
    log_chain_of_custody("bitlocker_lock", {"mount_id": mount_id})
    return jsonify({"success": True})

@acquisition_bp.route('/api/bitlocker/status', methods=['GET'])
@requires_auth
@requires_permission('acquisition')
def bitlocker_status():
    with bitlocker_lock:
        mounts = [{"mount_id": mid, **{k: v for k, v in info.items() if k != 'mount_dir'}}
                  for mid, info in active_bitlocker_mounts.items()]
    return jsonify({"success": True, "mounts": mounts})

@acquisition_bp.route('/api/luks/partitions', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def luks_partitions():
    req = request.get_json() or {}
    device = req.get('device', '')
    if not is_valid_block_device(device):
        return jsonify({"success": False, "error": "Not a recognized whole-disk device."}), 400
    return jsonify({"success": True, "partitions": _list_device_partitions(device)})

@acquisition_bp.route('/api/luks/detect', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def luks_detect():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    result = _detect_luks(partition)
    if result is None:
        return jsonify({"success": False, "error": "Invalid or unrecognized device/partition path."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/luks/unlock', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def luks_unlock():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    passphrase = req.get('passphrase', '')
    success, mapper_name, source_path, error = _luks_unlock(partition, passphrase)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("luks_unlock", {"device": partition, "mount_id": mapper_name})
    return jsonify({"success": True, "mount_id": mapper_name, "source_path": source_path})

@acquisition_bp.route('/api/luks/detect_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def luks_detect_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    result = _detect_luks_image(image_path, offset)
    if result is None:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/luks/unlock_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def luks_unlock_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    passphrase = req.get('passphrase', '')
    success, mapper_name, source_path, error = _luks_unlock(image_path, passphrase, offset=offset)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("luks_unlock_image", {"image_path": image_path, "offset": offset, "mount_id": mapper_name})
    return jsonify({"success": True, "mount_id": mapper_name, "source_path": source_path})

@acquisition_bp.route('/api/luks/lock', methods=['POST'])
@requires_auth
@requires_permission('acquisition', 'file_explorer')
def luks_lock_route():
    req = request.get_json() or {}
    mount_id = req.get('mount_id', '')
    success, error = _luks_lock(mount_id)
    if not success:
        return jsonify({"success": False, "error": error}), 500
    log_chain_of_custody("luks_lock", {"mount_id": mount_id})
    return jsonify({"success": True})

@acquisition_bp.route('/api/luks/status', methods=['GET'])
@requires_auth
@requires_permission('acquisition')
def luks_status():
    with luks_lock:
        mounts = [{"mount_id": mid, **info} for mid, info in active_luks_mounts.items()]
    return jsonify({"success": True, "mounts": mounts})

# --- VeraCrypt: mirrors the LUKS route set exactly, 1:1 - same decorators,
# same request/response shapes, same permission gating per route type. ---

@acquisition_bp.route('/api/veracrypt/partitions', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def veracrypt_partitions():
    req = request.get_json() or {}
    device = req.get('device', '')
    if not is_valid_block_device(device):
        return jsonify({"success": False, "error": "Not a recognized whole-disk device."}), 400
    return jsonify({"success": True, "partitions": _list_device_partitions(device)})

@acquisition_bp.route('/api/veracrypt/detect', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def veracrypt_detect():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    result = _detect_veracrypt(partition)
    if result is None:
        return jsonify({"success": False, "error": "Invalid or unrecognized device/partition path."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/veracrypt/unlock', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def veracrypt_unlock():
    req = request.get_json() or {}
    partition = req.get('partition', '')
    password = req.get('password', '')
    pim = req.get('pim')
    success, mapper_name, source_path, error = _veracrypt_unlock(partition, password, pim=pim)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("veracrypt_unlock", {"device": partition, "mount_id": mapper_name})
    return jsonify({"success": True, "mount_id": mapper_name, "source_path": source_path})

@acquisition_bp.route('/api/veracrypt/detect_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def veracrypt_detect_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    result = _detect_veracrypt_image(image_path, offset)
    if result is None:
        return jsonify({"success": False, "error": "Image file not found or outside the permitted evidence directory."}), 400
    return jsonify({"success": True, **result})

@acquisition_bp.route('/api/veracrypt/unlock_image', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def veracrypt_unlock_image():
    req = request.get_json() or {}
    image_path = req.get('image_path', '')
    offset = req.get('offset', 0)
    password = req.get('password', '')
    pim = req.get('pim')
    success, mapper_name, source_path, error = _veracrypt_unlock(image_path, password, offset=offset, pim=pim)
    if not success:
        return jsonify({"success": False, "error": error}), 400
    log_chain_of_custody("veracrypt_unlock_image", {"image_path": image_path, "offset": offset, "mount_id": mapper_name})
    return jsonify({"success": True, "mount_id": mapper_name, "source_path": source_path})

@acquisition_bp.route('/api/veracrypt/lock', methods=['POST'])
@requires_auth
@requires_permission('acquisition', 'file_explorer')
def veracrypt_lock_route():
    req = request.get_json() or {}
    mount_id = req.get('mount_id', '')
    success, error = _veracrypt_lock(mount_id)
    if not success:
        return jsonify({"success": False, "error": error}), 500
    log_chain_of_custody("veracrypt_lock", {"mount_id": mount_id})
    return jsonify({"success": True})

@acquisition_bp.route('/api/veracrypt/status', methods=['GET'])
@requires_auth
@requires_permission('acquisition')
def veracrypt_status():
    with veracrypt_lock:
        mounts = [{"mount_id": mid, **info} for mid, info in active_veracrypt_mounts.items()]
    return jsonify({"success": True, "mounts": mounts})

@acquisition_bp.route('/api/start_imaging', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_imaging():
    # Atomically check-and-reserve the job slot so two concurrent requests
    # can't both pass the check and start simultaneous acquisitions.
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    fmt = req.get('format', 'dd')
    hashes = [h.lower() for h in req.get('hashes', ['sha256'])]
    metadata = req.get('metadata', {})
    keep_raw = bool(req.get('keep_raw', True))  # only relevant when fmt == 'aff'
    # Documentation only, never used to decrypt anything - imaging still
    # captures the source exactly as found (encrypted or not). Recorded in
    # plaintext in the case report (like every other case_metadata field),
    # deliberately NOT Fernet-encrypted at rest the way network-mount
    # credentials are - this key's whole value is traveling with the
    # exported PDF/HTML report as documentation for whoever needs to
    # decrypt the image later, so encrypting it with a station-local key
    # would make it useless the moment the report leaves this station.
    bitlocker_key = (req.get('bitlocker_key') or '').strip()
    # Same rationale/plaintext-at-rest tradeoff as bitlocker_key above -
    # documentation only, never used to decrypt anything.
    luks_passphrase_doc = (req.get('luks_passphrase') or '').strip()
    veracrypt_password_doc = (req.get('veracrypt_password') or '').strip()

    compression = req.get('compression', 'fast')
    split_size = req.get('split_size', '2000M')

    # Guided Workflow automation Tier 2 (2026-08-27) - opt-in, examiner-
    # confirmed-once-up-front chain into Auto Analyze on a genuine COMPLETED
    # acquisition. Never applies to AFF (which runs execution_worker_aff(),
    # not the shared execution_worker() the chain hooks into) - the frontend
    # already hides/skips sending this for AFF, checked again here
    # defensively. A case_folder is required (Auto Analyze's own step
    # functions need one to index results against) - chaining is simply
    # skipped, not an error, if the examiner checked the box with no active
    # case (the frontend already warns about this before ever sending the
    # request, so reaching here with the flag set and no case_folder would
    # only happen via a direct API call bypassing the UI).
    chain_auto_analyze = bool(req.get('chain_auto_analyze', False)) and fmt != 'aff'
    chain_case_folder = safe_path(req.get('case_folder')) if chain_auto_analyze else None
    if chain_auto_analyze and not chain_case_folder:
        chain_auto_analyze = False

    VALID_FORMATS = {'dd', 'raw', 'dcfldd', 'plain_dd', 'e01', 'aff'}
    if fmt not in VALID_FORMATS:
        update_job(active=False)
        return jsonify({"error": f"Unrecognized format '{fmt}'. Use one of {sorted(VALID_FORMATS)}."}), 400

    # A `source` matching a currently-registered dislocker mount (see
    # /api/bitlocker/unlock) or LUKS mapper (see /api/luks/unlock) is a
    # decrypted virtual source, not a real block device - trusted because
    # only this app's own _dislocker_unlock()/_luks_unlock() can ever create
    # a path that matches (mountpoints/mapper names live under
    # server-controlled roots, never client-supplied).
    source, source_kind, mount_meta = _resolve_acquisition_source(source)
    if source_kind == 'real_device':
        if not is_valid_block_device(source) or not os.path.exists(source):
            update_job(active=False)
            return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400
    elif not os.path.exists(source):
        update_job(active=False)
        kind_label = DECRYPTED_SOURCE_KIND_LABELS.get(mount_meta["kind"], mount_meta["kind"])
        return jsonify({"error": f"The unlocked {kind_label} volume is no longer available - it may have been locked/unmounted."}), 400

    invalid_hashes = set(hashes) - ALLOWED_HASH_ALGOS
    if invalid_hashes:
        update_job(active=False)
        return jsonify({"error": f"Unsupported hash algorithm(s): {sorted(invalid_hashes)}. Use any of {sorted(ALLOWED_HASH_ALGOS)}."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    if not os.path.exists(dest_path):
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    total_bytes = 0
    if source_kind in ('real_device', 'decrypted_block_device'):
        # A LUKS mapper device is block-device-shaped (dm-crypt), so
        # blockdev works on it exactly like a real device - confirmed live.
        try:
            res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
            if res.returncode == 0:
                total_bytes = int(res.stdout.strip())
        except Exception:
            pass
    else:
        # A dislocker-file is a regular file, not a block device - a plain
        # stat gives its real decrypted size directly, no blockdev needed.
        try:
            total_bytes = os.path.getsize(source)
        except OSError:
            pass

    dest_disk_usage = shutil.disk_usage(dest_path)
    if total_bytes > 0 and dest_disk_usage.free < total_bytes:
        free_gb = round(dest_disk_usage.free / (1024**3), 2)
        required_gb = round(total_bytes / (1024**3), 2)
        update_job(active=False)
        return jsonify({"error": f"Pre-flight storage check failed: Destination has only {free_gb} GB free, but source requires {required_gb} GB."}), 400

    # SMART telemetry only exists for a real physical device - neither a
    # decrypted dislocker-file nor a LUKS mapper device has any of its own
    # (both are virtual, backed by the already-encrypted source), so this is
    # skipped entirely rather than querying smartctl against a path it was
    # never meant to see.
    smart_data = {}
    if source_kind == 'real_device':
        try:
            res_smart = subprocess.run(['sudo', 'smartctl', '-a', '-j', source], capture_output=True, text=True)
            if res_smart.stdout:
                smart_data = json.loads(res_smart.stdout)
        except Exception:
            pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    vendor_model = f"{family} ({model})" if (family and family.lower() not in model.lower()) else model
    if mount_meta:
        vendor_model = {
            "luks": "LUKS-Decrypted Volume (via cryptsetup)",
            "veracrypt": "VeraCrypt-Decrypted Volume (via cryptsetup)",
            "bitlocker": "BitLocker-Decrypted Volume (via dislocker)",
        }.get(mount_meta["kind"], "Decrypted Volume")

    serial = smart_data.get('serial_number', 'N/A')
    healthy = smart_data.get('smart_status', {}).get('passed', True)
    temp = smart_data.get('temperature', {}).get('current')
    power_hours = smart_data.get('power_on_time', {}).get('hours')
    
    reallocated = 0
    pending = 0
    for attr in smart_data.get('ata_smart_attributes', {}).get('table', []):
        attr_id = attr.get('id')
        if attr_id == 5:
            reallocated = attr.get('raw', {}).get('value', 0)
        elif attr_id == 197:
            pending = attr.get('raw', {}).get('value', 0)

    drive_telemetry = {
        # Displays the real encrypted device/partition path for a BitLocker
        # or LUKS acquisition, not the internal dislocker mountpoint/LUKS
        # mapper name - that's implementation detail, the original device is
        # what belongs in the case record.
        "device_path": mount_meta["device"] if mount_meta else source,
        "vendor_model": vendor_model,
        "serial_number": serial,
        "capacity_bytes": total_bytes,
        "capacity_gb": round(total_bytes / (1024**3), 2),
        "smart_healthy": healthy,
        "temperature_celsius": temp,
        "power_on_hours": power_hours,
        "reallocated_sectors": reallocated,
        "pending_sectors": pending
    }

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    examiner = metadata.get('examiner', 'UNSPECIFIED')
    notes = metadata.get('notes', 'None')
    base_name = f"{case_num}_{evidence_id}"

    if fmt == 'e01':
        ewf_hash_type = "sha256" if "sha256" in hashes else ("sha1" if "sha1" in hashes else "md5")
        out_file = f"{dest_path}/{base_name}.E01"
        cmd = [
            "sudo", "/usr/bin/ewfacquire", "-u",
            "-t", f"{dest_path}/{base_name}",
            "-C", case_num,
            "-E", evidence_id,
            "-e", examiner,
            "-N", notes,
            "-f", "encase6",
            "-d", ewf_hash_type,
            "-c", compression,
            "-S", split_size,
            source
        ]

    elif fmt == 'dcfldd':
        out_file = f"{dest_path}/{base_name}.dd"
        cmd = [
            "sudo", "/usr/bin/dcfldd",
            f"if={source}",
            f"of={out_file}",
            "conv=noerror,sync",
        ]
        if hashes:
            cmd.append(f"hash={','.join(hashes)}")
            for h in hashes:
                cmd.append(f"{h}log={out_file.replace('.dd', f'_{h}.log')}")

    elif fmt == 'plain_dd':
        out_file = f"{dest_path}/{base_name}.dd"
        # Unlike dc3dd, GNU dd genuinely supports iflag=direct - this
        # bypasses the page cache on the *read* side, which is the actual
        # forensic concern (avoiding cache pollution/buffer dirtying from
        # reading the source device). oflag=direct is deliberately omitted:
        # it requires block-aligned writes and can fail outright on some
        # destination filesystems (e.g. mounted network shares), which
        # would break the acquisition entirely for a benefit that mostly
        # matters on the read side anyway.
        cmd = [
            "sudo", "/usr/bin/dd",
            f"if={source}",
            f"of={out_file}",
            "bs=4M",
            "conv=noerror,sync",
            "status=progress",
        ]
        # iflag=direct bypasses the page cache on the read side - meaningful
        # for a real physical device, but O_DIRECT is frequently unsupported
        # (or outright rejected) by FUSE-backed regular files, which a
        # dislocker-unlocked BitLocker source is. A LUKS mapper device
        # (dm-crypt) IS a real block device and supports O_DIRECT fine, so
        # it gets iflag=direct too, unlike the FUSE case.
        if source_kind in ('real_device', 'decrypted_block_device'):
            cmd.append("iflag=direct")
        # dd itself has no built-in hashing; computed_hashes is filled in
        # after completion by streaming the output file through hashlib.

    elif fmt == 'aff':
        # Two-phase (raw acquisition -> AFF conversion); see
        # execution_worker_aff for why, and cmd/out_file here are only used
        # for the report's "requested command" field, not actually launched
        # via the generic execution_worker thread below.
        out_file = f"{dest_path}/{base_name}.aff"
        dc3dd_cmd_preview = ["sudo", "/usr/bin/dc3dd", f"if={source}", f"of={dest_path}/{base_name}.raw"] + [f"hash={h}" for h in hashes]
        affconvert_cmd_preview = ["affconvert", "-o", out_file, f"{dest_path}/{base_name}.raw"]
        cmd = dc3dd_cmd_preview + ["&&"] + affconvert_cmd_preview

    else:  # 'dd' / 'raw' -> dc3dd (original default engine)
        out_file = f"{dest_path}/{base_name}.dd"
        dc3dd_log_file = f"{dest_path}/{base_name}_dc3dd.log"
        # NOTE: dc3dd is a fork of the old-style `dd`, not GNU coreutils dd -
        # it does not support iflag=/oflag= at all (confirmed against its
        # own --help: only if=, of=, hash=, log=, ssz=, bufsz=, etc. are
        # recognized). The previous iflag=direct/oflag=direct here were
        # silently doing nothing. dc3dd has no O_DIRECT equivalent; the
        # closest actual performance/memory knob it exposes is bufsz=,
        # which sets the internal read buffer size. Use format=plain_dd
        # instead if genuine O_DIRECT behavior matters for your hardware.
        cmd = [
            "sudo", "/usr/bin/dc3dd",
            f"if={source}",
            f"of={out_file}",
            f"log={dc3dd_log_file}",
        ]
        for h in hashes:
            cmd.append(f"hash={h}")

    update_job(
        format=fmt,
        progress_percent=0.0,
        speed_mbps=0.0,
        transferred_bytes=0,
        total_bytes=total_bytes,
        status="Initializing...",
        log=f"[*] Initializing {fmt.upper()} acquisition ({', '.join(hashes).upper()}) for {source} -> {dest_path}..."
    )

    report_data = {
        "tool": fmt,
        "case_metadata": metadata,
        "source_drive_telemetry": drive_telemetry,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": fmt,
            "output_image_path": out_file,
            "compression": compression if fmt == 'e01' else 'N/A',
            "split_size": split_size if fmt == 'e01' else 'N/A',
            "requested_hashes": hashes,
            "execution_command": " ".join(cmd),
            **({"raw_image_retained": None} if fmt == 'aff' else {}),
            **({"bitlocker_key": bitlocker_key} if bitlocker_key else {}),
            **({"bitlocker_decrypted": True} if mount_meta and mount_meta["kind"] == "bitlocker" else {}),
            **({"luks_passphrase": luks_passphrase_doc} if luks_passphrase_doc else {}),
            **({"luks_decrypted": True} if mount_meta and mount_meta["kind"] == "luks" else {}),
            **({"veracrypt_password": veracrypt_password_doc} if veracrypt_password_doc else {}),
            **({"veracrypt_decrypted": True} if mount_meta and mount_meta["kind"] == "veracrypt" else {}),
        },
        "attachments": {
            "files": [],
            "reference_urls": []
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computed_verification_hashes": {}
    }

    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    if fmt == 'aff':
        thread = threading.Thread(
            target=execution_worker_aff,
            args=(source, dest_path, base_name, hashes, keep_raw, report_target, report_data, total_bytes)
        )
    elif chain_auto_analyze:
        # Captured here (in the real request thread, before spawning) rather
        # than read from request/g inside the worker - the same
        # capture-before-spawn discipline every other background-thread
        # log_chain_of_custody() call in this app already needs, since
        # request/g are request-context-bound proxies that raise off-thread.
        chain_requester_ip = request.headers.get('X-Real-IP', request.remote_addr)
        chain_requester_user = getattr(g, 'forensic_user', None)
        thread = threading.Thread(
            target=execution_worker_chained_auto_analyze,
            args=(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes,
                  chain_case_folder, chain_requester_ip, chain_requester_user)
        )
    else:
        thread = threading.Thread(
            target=execution_worker,
            args=(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes)
        )
    thread.daemon = True
    thread.start()

    # A dislocker/LUKS mount must stay live for the whole acquisition (dc3dd/
    # dcfldd/etc. read from it throughout the job), then gets torn down as
    # soon as it's no longer needed - a decrypted mount is sensitive and
    # shouldn't linger any longer than the job that actually needed it.
    # This runs in its own thread (not execution_worker's own finally
    # block) specifically to avoid threading a new parameter through that
    # already-large, multi-caller function; thread.join() here blocks only
    # this cleanup thread, not the request that already returned above.
    if mount_meta:
        requester_ip = request.remote_addr
        requester_user = getattr(g, 'forensic_user', None)
        lock_fn = DECRYPTED_SOURCE_LOCK_FN[mount_meta["kind"]]
        log_action = f"{mount_meta['kind']}_lock"

        def _cleanup_decrypted_mount_after_job(worker_thread, fn, mid, action, src_ip, user):
            worker_thread.join()
            fn(mid)
            log_chain_of_custody(action, {"mount_id": mid, "reason": "acquisition_complete"},
                                 source_ip=src_ip, user=user)

        cleanup_thread = threading.Thread(
            target=_cleanup_decrypted_mount_after_job,
            args=(thread, lock_fn, mount_meta["mount_id"], log_action, requester_ip, requester_user)
        )
        cleanup_thread.daemon = True
        cleanup_thread.start()

    log_chain_of_custody("acquisition_start", {"format": fmt, "source": source, "destination": dest_path,
                                                **({"bitlocker_decrypted": True} if mount_meta and mount_meta["kind"] == "bitlocker" else {}),
                                                **({"luks_decrypted": True} if mount_meta and mount_meta["kind"] == "luks" else {}),
                                                **({"veracrypt_decrypted": True} if mount_meta and mount_meta["kind"] == "veracrypt" else {}),
                                                **({"chain_auto_analyze": True} if chain_auto_analyze else {})})
    return jsonify({"success": True, "message": "Acquisition started."})

@acquisition_bp.route('/api/ddrescue/inspect_map', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def inspect_ddrescue_map():
    req = request.get_json() or {}
    map_path = safe_path(req.get('map_path', ''))
    if not map_path or not os.path.exists(map_path):
        return jsonify({"success": False, "error": "Mapfile not found or outside the permitted evidence directory."}), 404

    summary = parse_ddrescue_mapfile(map_path)
    return jsonify({
        "success": True,
        "map_path": map_path,
        "rescued_gb": round(summary["rescued_bytes"] / (1024**3), 3),
        "non_tried_mb": round(summary["non_tried_bytes"] / (1024**2), 2),
        "bad_sector_kb": round(summary["bad_sector_bytes"] / 1024, 2),
        "bad_blocks_count": summary["bad_blocks_count"]
    })


@acquisition_bp.route('/api/start_ddrescue', methods=['POST'])
@requires_auth
@requires_permission('acquisition')
def start_ddrescue():
    # Atomically check-and-reserve the job slot, same as start_imaging.
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source = req.get('source')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    strategy = req.get('strategy', 'stage1_fast')
    retry_passes = str(req.get('retry_passes', '3'))
    direct_mode = req.get('direct_mode', True)
    input_pos = req.get('input_position', '')
    max_size = req.get('max_size', '')
    metadata = req.get('metadata', {})
    # Documentation only here (see start_imaging()'s own comment on why
    # plaintext) - ddrescue itself deliberately does NOT support acquiring
    # from an unlocked dislocker mount the way start_imaging()'s other
    # formats do. ddrescue exists specifically for physically failing
    # drives - direct-I/O sector-level retry/skip logic against a raw
    # block device - which doesn't apply to an already-decrypted FUSE
    # virtual file sitting on top of a drive that (by definition, since it
    # unlocked successfully) is already being read fine. `-d`/--idirect
    # would likely just fail outright against a non-block-device source.
    # If a genuinely failing BitLocker-encrypted drive ever needs
    # sector-level recovery, that has to happen at the raw encrypted layer
    # (ddrescue the raw partition first, decrypt the resulting image
    # afterward with dislocker) - a different workflow than this route.
    bitlocker_key = (req.get('bitlocker_key') or '').strip()
    luks_passphrase_doc = (req.get('luks_passphrase') or '').strip()
    veracrypt_password_doc = (req.get('veracrypt_password') or '').strip()

    # This runs ddrescue via a passwordless sudo rule (see install.py), so
    # source/destination MUST be tightly validated - otherwise any caller
    # could point ddrescue at an arbitrary file (e.g. /etc/shadow) and have
    # it copied out as root.
    if not is_valid_block_device(source) or not os.path.exists(source):
        update_job(active=False)
        return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    if strategy not in ('stage1_fast', 'stage2_trim', 'stage3_intensive', 'reverse'):
        update_job(active=False)
        return jsonify({"error": f"Unrecognized strategy '{strategy}'."}), 400

    if not retry_passes.isdigit():
        update_job(active=False)
        return jsonify({"error": "retry_passes must be a positive integer."}), 400

    if not os.path.exists(dest_path):
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            update_job(active=False)
            return jsonify({"error": f"Destination path {dest_path} is inaccessible: {str(e)}"}), 400

    case_num = metadata.get('case_number', 'RECOVERY')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_ddrescue"
    
    out_file = os.path.join(dest_path, f"{base_name}.dd")
    map_file = os.path.join(dest_path, f"{base_name}.map")

    cmd = ["sudo", "/usr/bin/ddrescue", "--force"]

    if strategy == 'stage1_fast':
        cmd.extend(["--no-scrape", "--no-trim"])
    elif strategy == 'stage2_trim':
        cmd.append("--no-scrape")
    elif strategy == 'stage3_intensive':
        cmd.append(f"--retry-passes={retry_passes}")
    elif strategy == 'reverse':
        cmd.extend(["--reverse", f"--retry-passes={retry_passes}"])

    if direct_mode:
        cmd.append("-d")

    # input_pos/max_size are ddrescue byte-offset/size arguments (e.g. "512MiB").
    # Restrict to digits + a small unit-suffix alphabet so a stray value can't
    # smuggle an extra flag through as a single argv token.
    _SIZE_RE = re.compile(r'^\d+[KMGTP]?i?B?$', re.IGNORECASE)
    if input_pos:
        if not _SIZE_RE.match(input_pos):
            update_job(active=False)
            return jsonify({"error": f"Invalid input_position '{input_pos}'."}), 400
        cmd.append(f"--input-position={input_pos}")
    if max_size:
        if not _SIZE_RE.match(max_size):
            update_job(active=False)
            return jsonify({"error": f"Invalid max_size '{max_size}'."}), 400
        cmd.append(f"--max-size={max_size}")

    cmd.extend([source, out_file, map_file])

    total_bytes = 0
    try:
        res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
        if res.returncode == 0:
            total_bytes = int(res.stdout.strip())
    except Exception:
        pass

    update_job(
        format="ddrescue",
        progress_percent=0.0,
        speed_mbps=0.0,
        transferred_bytes=0,
        total_bytes=total_bytes,
        status=f"ddrescue [{strategy.upper()}]...",
        log=f"[*] Initializing ddrescue ({strategy}) pass for {source} -> {out_file}\n[*] Mapfile: {map_file}..."
    )

    report_data = {
        "tool": "ddrescue",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "output_destination": dest_path,
            "output_format": "ddrescue_raw",
            "output_image_path": out_file,
            "mapfile": map_file,
            "strategy": strategy,
            "retry_passes": retry_passes,
            "direct_mode": direct_mode,
            "execution_command": " ".join(cmd),
            **({"bitlocker_key": bitlocker_key} if bitlocker_key else {}),
            **({"luks_passphrase": luks_passphrase_doc} if luks_passphrase_doc else {}),
            **({"veracrypt_password": veracrypt_password_doc} if veracrypt_password_doc else {}),
        },
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    report_target = build_report_target(dest_path, dest_path, base_name)

    thread = threading.Thread(
        target=execution_worker,
        args=(cmd, "ddrescue", total_bytes, out_file, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("ddrescue_start", {"strategy": strategy, "source": source, "destination": dest_path})
    return jsonify({"success": True, "message": f"ddrescue ({strategy}) started."})

@acquisition_bp.route('/api/stop_imaging', methods=['POST'])
@requires_auth
def stop_imaging():
    if current_job["active"]:
        try:
            proc = get_active_proc()
            if proc and proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception as e:
            print(f"Error killing process group: {e}")

        # 2026-08-30, physical/raw Android acquisition: a second tracked
        # process (the upstream `adb exec-out su -c dd` read, piped into
        # the dc3dd/dcfldd process killed just above via active_proc) -
        # see core/jobs.py's _stream_piped_subprocess(). adb never runs
        # under sudo on this host (`su` happens ON the device, not here),
        # so a plain, non-sudo killpg on a process this same service
        # account spawned is already permitted - no new sudoers grant.
        # Deliberately NOT added to the sudo-pkill-by-name list below:
        # those tools all need sudo because THEY run via sudo, and a bare
        # `pkill adb` would also kill an unrelated, concurrent adb call
        # elsewhere in the app (e.g. a device-list refresh) - the
        # tracked-PID killpg here is the correct, surgical mechanism.
        try:
            up = get_upstream_proc()
            if up and up.poll() is None:
                os.killpg(os.getpgid(up.pid), signal.SIGKILL)
        except Exception as e:
            print(f"Error killing upstream process group: {e}")
        finally:
            clear_upstream_proc()

        # These now run via sudo (root) to get raw device access, so killing
        # them also needs sudo - an unprivileged kill/pkill can't signal a
        # root-owned process. The existing /usr/bin/pkill sudoers grant is
        # already unrestricted, so no new sudoers entry is needed here.
        # "dd" gets matched via -f with a distinguishing substring rather
        # than a bare name match - "dd" is too generic a process name to
        # pkill by bare name without risking killing an unrelated process
        # elsewhere on the system.
        for tool in ["dc3dd", "dcfldd", "ewfacquire", "ddrescue", "photorec", "extundelete", "foremost", "scalpel"]:
            try:
                subprocess.run(["sudo", "pkill", "-9", tool], capture_output=True)
            except Exception:
                pass
        try:
            subprocess.run(["sudo", "pkill", "-9", "-f", "dd if="], capture_output=True)
        except Exception:
            pass

        # Routed through update_job() (not a direct current_job[...] = ...
        # write, which this used to be) specifically so Auto Analyze's
        # begin_suppress_active_false()/end_suppress_active_false()
        # mechanism (core/jobs.py) actually applies here. Caught live,
        # not by design review: with the old direct-write version, Stop
        # released the shared job slot (active=False) IMMEDIATELY even
        # while an Auto Analyze step's own background thread was still
        # mid-flight (e.g. still walking a multi-GB image for Hash
        # Manifest) - confirmed via a real `ps`/`top` check showing the
        # orphaned worker thread still consuming real CPU/IO seconds
        # after the job already read back as inactive, which would have
        # let a second, unrelated job start and run concurrently with it,
        # defeating the entire point of Auto Analyze's "one continuously-
        # held job-slot claim" design. status="Stopped" still needs to
        # land immediately (every worker's own between-step/between-
        # iteration check reads it), so only `active` goes through the
        # suppressible path - update_job() applies both together, and the
        # suppress flag (when set) simply drops `active` from that one
        # call while `status`/`log` still update normally.
        current_log = snapshot_job()["log"]
        update_job(status="Stopped", active=False, log=current_log + "\n[!] Acquisition manually terminated by user.")
        return jsonify({"success": True, "message": "Acquisition stopped."})
        
    return jsonify({"error": "No active job running."}), 400

@acquisition_bp.route('/api/progress', methods=['GET'])
@requires_auth
def get_progress():
    job = snapshot_job()
    return jsonify({
        "active": job["active"],
        "format": job["format"],
        "progress_percent": job["progress_percent"],
        "speed_mbps": job["speed_mbps"],
        "transferred_bytes": job["transferred_bytes"],
        "total_bytes": job["total_bytes"],
        "status": job["status"],
        "log": job["log"]
    })

