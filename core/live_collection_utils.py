"""USB-deployable live-forensics collector - the app's first-ever deliberate
write to a raw block device it doesn't already treat as evidence. Every
other operation in this app treats a connected USB drive as sacrosanct,
read-only evidence (a udev rule forces `blockdev --setro` on every plug
event, and `routes/acquisition.py`'s own `list_drives()` re-forces it on
every poll). This module is the one place that's allowed to write to a
*confirmed-blank, non-evidence* USB drive - preparing it with live-
collection tooling (UAC for Unix-like targets, a hand-written PowerShell
script for Windows targets) so an examiner can plug it into a different,
running, live machine to collect volatile artifacts, then bring it back
to import the results into a case.

Pure, Flask-independent helper functions - the job-orchestration/locking/
report-writing glue lives in routes/acquisition.py, which is also where
the `device_write_lock`/`active_write_unlocked_devices` race-avoidance
mechanism (see that file's own comment block) lives, since it has to be
checked by list_drives() in the same file.

Wipe/partition/format sequence and every command choice below were spiked
against a real losetup-backed loop device on the deployed station before
any of this was wired into the app - not assumed from documentation:
- `sfdisk`, not `parted` - already shipped with util-linux (an existing
  dependency), avoiding a wholly new apt package for zero functional gain.
- An explicit `blockdev --rereadpt` + `udevadm settle` between writing the
  partition table and running `mkfs.exfat` - confirmed live to be
  necessary; `mkfs` can otherwise race the kernel/udev not having created
  the partition device node yet.
- exFAT (MBR partition type 0x07, matching real-world convention for an
  NTFS/exFAT-family filesystem, not FAT32's 0x0c) over FAT32 (4GB single-
  file cap - can truncate a real collection archive) or NTFS (no native
  macOS *write* support) - the best available cross-platform read-write
  filesystem for a Pi -> unknown-live-target -> Pi round trip.
- Ownership solved via `mount -o uid=...,gid=...` (the exact technique
  already used for this app's SFTP/CIFS network mounts, routes/
  settings.py), not a `chown -R` pass after mounting root-owned - the
  unprivileged service account writes/reads directly with no extra sudo
  round trip either direction.
"""
import os
import re
import glob
import json
import subprocess
import time

PIF_COLLECT_LABEL = "PIF_COLLECT"
UAC_DEFAULT_PROFILE = "ir_triage"

WIPEFS_BIN = "/sbin/wipefs"
SFDISK_BIN = "/sbin/sfdisk"
MKFS_EXFAT_BIN = "/sbin/mkfs.exfat"
BLOCKDEV_BIN = "/sbin/blockdev"

_WIPE_FORMAT_TIMEOUT_SECONDS = 120
_MOUNT_TIMEOUT_SECONDS = 30
_SYNC_TIMEOUT_SECONDS = 60
_UNMOUNT_TIMEOUT_SECONDS = 90
_SETTLE_TIMEOUT_SECONDS = 60


def unmount_all_partitions(device):
    """Best-effort unmount of every partition of `device` - the exact
    loop already used by toggle_write_block() (routes/acquisition.py),
    reused here rather than duplicated a second time, since both live in
    the same blueprint. Never raises; a partition that was never mounted
    is a harmless no-op for both commands."""
    for part in sorted(glob.glob(f"{device}*")):
        subprocess.run(["sudo", "udevil", "unmount", "-b", part], capture_output=True)
        subprocess.run(["sudo", "umount", part], capture_output=True)


def check_existing_collection_volume(device):
    """Fast-path check (design decision 3 of the feature plan): before
    ever touching wipefs/sfdisk/mkfs, see whether `device` already has
    exactly one partition, already exFAT, already labeled PIF_COLLECT -
    if so, the caller can skip straight to mount+copy instead of a full
    wipe. Uses `blkid` (already used elsewhere in this app, no new
    dependency) against the device's own first partition. Returns
    {"already_prepared": bool, "reason": str} - never raises; any blkid
    failure or ambiguous state is treated as "not already prepared" (the
    safe default - falls through to a full wipe)."""
    partition = f"{device}1"
    if not os.path.exists(partition):
        return {"already_prepared": False, "reason": "No existing partition found."}
    try:
        res = subprocess.run(
            ["sudo", "blkid", "-o", "export", partition],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        return {"already_prepared": False, "reason": f"blkid failed: {e}"}
    if res.returncode != 0:
        return {"already_prepared": False, "reason": "blkid could not read this partition."}
    fields = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
    fs_type = fields.get("TYPE", "")
    label = fields.get("LABEL", "")
    # Also confirm this is the ONLY partition on the device - a multi-
    # partition drive (even if partition 1 happens to be a correctly-
    # labeled exFAT volume) is not "already prepared" in the shape this
    # feature always creates, and should still go through a full wipe
    # rather than risk leaving unrelated partitions behind.
    other_partitions = [p for p in glob.glob(f"{device}*") if p not in (device, partition)]
    if fs_type == "exfat" and label == PIF_COLLECT_LABEL and not other_partitions:
        return {"already_prepared": True, "reason": f"Already a single exFAT partition labeled {PIF_COLLECT_LABEL}."}
    return {"already_prepared": False, "reason": f"Partition is {fs_type or 'unformatted'}"
                                                  f"{f', labeled {label!r}' if label else ''} - not a recognized collection volume."}


def wipe_and_format_device(device, append_log=None):
    """Wipes `device` entirely and formats it exFAT with the fixed
    PIF_COLLECT label - the one genuinely destructive step in this whole
    feature. Caller is responsible for confirming (a) the device is
    validated via is_valid_block_device() before this is ever called, and
    (b) the examiner has already confirmed via the UI's strengthened
    type-to-confirm gate. Returns {"success": bool, "error": str|None,
    "partition_device": str|None}. append_log(msg), if given, is called
    with a one-line progress message before each step (matches this app's
    established job-log-append pattern)."""
    def log(msg):
        if append_log:
            append_log(msg)

    partition = f"{device}1"

    log(f"[*] Wiping any existing filesystem/partition signatures on {device}...")
    res = subprocess.run(["sudo", WIPEFS_BIN, "-a", device], capture_output=True, text=True, timeout=_WIPE_FORMAT_TIMEOUT_SECONDS)
    if res.returncode != 0:
        return {"success": False, "error": f"wipefs failed: {res.stderr.strip() or res.stdout.strip()}", "partition_device": None}

    log(f"[*] Writing a fresh MBR partition table to {device} (one partition, exFAT/NTFS type 0x07)...")
    sfdisk_script = "label: dos\nstart=2048, type=7\n"
    res = subprocess.run(
        ["sudo", SFDISK_BIN, device], input=sfdisk_script,
        capture_output=True, text=True, timeout=_WIPE_FORMAT_TIMEOUT_SECONDS,
    )
    if res.returncode != 0:
        return {"success": False, "error": f"sfdisk failed: {res.stderr.strip() or res.stdout.strip()}", "partition_device": None}

    # Confirmed live via the Phase 0 loopback spike: mkfs can otherwise
    # race the kernel/udev not having created the partition device node
    # yet if this pair is skipped.
    #
    # A second real bug found live (2026-09-03), against the same physical
    # USB drive that surfaced the partition-lock and unmount bugs above:
    # `udevadm settle` genuinely completes in ~1s on this station when
    # tested standalone against an idle system, but reliably timed out at
    # 15s twice in a row during this exact sequence - re-reading a real
    # partition table off real USB flash (not the fast loopback devices
    # this module's original design/spike testing used) plus running every
    # write-block udev rule's RUN+= action for both the whole disk and the
    # freshly-created partition genuinely takes longer than 15s on real
    # hardware, especially after several back-to-back wipe/reformat cycles.
    # Neither call is treated as fatal any more, both got a materially
    # longer timeout, and - critically - this is still safe even if a call
    # times out anyway: the very next real safety check
    # ("if not os.path.exists(partition)") independently confirms the
    # partition genuinely appeared before mkfs.exfat is ever allowed to
    # run, regardless of whether rereadpt/settle themselves finished
    # cleanly within their own timeout window.
    try:
        subprocess.run(["sudo", BLOCKDEV_BIN, "--rereadpt", device], capture_output=True, timeout=_SETTLE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        subprocess.run(["udevadm", "settle"], capture_output=True, timeout=_SETTLE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        pass

    if not os.path.exists(partition):
        return {"success": False, "error": f"Partition table was written but {partition} never appeared - aborting before formatting.", "partition_device": None}

    # Real bug found live (2026-09-03): this station's write-block udev
    # rules are two INDEPENDENT rules, not one - "KERNEL==sd[a-z]" (whole
    # disk) and a separate "KERNEL==sd[a-z][0-9]*" (partitions), each firing
    # blockdev --setro on its OWN device node's own "add" uevent.
    # _unlock_device_for_write() (routes/acquisition.py) only ever unlocks
    # the whole-disk device, before sfdisk runs - but sfdisk writing the
    # partition table makes the kernel create `partition` as a genuinely
    # NEW device node, which fires its own independent "add" uevent the
    # partition-specific rule catches and re-locks read-only, regardless of
    # the whole-disk unlock already in place. mkfs.exfat then fails with
    # "write failed(errno : 1)" (EPERM) - confirmed exactly this via a real
    # failed Build against a real USB drive, then confirmed both /dev/sda
    # and /dev/sda1 independently show ro=1 after the failure. The
    # partition device needs its own explicit unlock too, not just the
    # whole disk - this fires once, right after the partition's own "add"
    # event already happened (rereadpt+settle above), so there's no race
    # with the udev rule re-locking it a second time afterward.
    subprocess.run(["sudo", BLOCKDEV_BIN, "--setrw", partition], capture_output=True, timeout=15)

    log(f"[*] Formatting {partition} exFAT, volume label {PIF_COLLECT_LABEL}...")
    res = subprocess.run(
        ["sudo", MKFS_EXFAT_BIN, "-n", PIF_COLLECT_LABEL, partition],
        capture_output=True, text=True, timeout=_WIPE_FORMAT_TIMEOUT_SECONDS,
    )
    if res.returncode != 0:
        return {"success": False, "error": f"mkfs.exfat failed: {res.stderr.strip() or res.stdout.strip()}", "partition_device": None}

    return {"success": True, "error": None, "partition_device": partition}


def mount_collection_partition(partition_device, mountpoint, uid, gid, read_only=False):
    """Mounts `partition_device` (an exFAT partition) at `mountpoint` with
    uid=/gid= mount options so the unprivileged service account can
    write (Phase A: building the USB) or read (Phase B: importing
    results) without any chown pass. `mount` itself is already an
    unqualified sudoers grant in this app (no new grant needed for this
    step). Returns {"success": bool, "error": str|None}."""
    os.makedirs(mountpoint, exist_ok=True)
    opts = f"uid={uid},gid={gid}"
    if read_only:
        opts += ",ro"
    try:
        res = subprocess.run(
            ["sudo", "mount", "-t", "exfat", "-o", opts, partition_device, mountpoint],
            capture_output=True, text=True, timeout=_MOUNT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Mount timed out."}
    if res.returncode != 0:
        return {"success": False, "error": res.stderr.strip() or res.stdout.strip() or "mount failed."}
    return {"success": True, "error": None}


def unmount_collection_partition(mountpoint):
    """Best-effort unmount + directory cleanup.

    Real bug found live (2026-09-03), against a real physical USB drive
    after a real ~49MB asset copy: `umount` can genuinely take longer than
    a plain mount ever would, since it has to flush the kernel's write-back
    cache to the physical device first - a real, slow USB flash drive can
    need well over 30s for that, unlike the fast loopback-backed devices
    this module's design/spike testing used, which flush near-instantly.
    Worse, a Python subprocess.run(timeout=...) that kills the `umount`
    process after a timeout doesn't reliably abort the underlying kernel
    unmount if it was blocked in uninterruptible sleep on device I/O - the
    unmount can go on to complete on its own moments later (confirmed live:
    the mount table showed nothing mounted well after the reported
    timeout), but the flush getting interrupted mid-flight can leave the
    filesystem's own metadata on the physical device inconsistent (confirmed
    live: the resulting partition failed to remount at all - "bad
    superblock"). This function's own original docstring already promised
    "never raises," but had no try/except around the actual subprocess.run()
    call at all, so a real TimeoutExpired here previously escaped straight
    up into the caller's own exception handling, failing the whole job even
    though the actual valuable work (wipe/format/asset copy) had already
    succeeded.

    Fixed with two changes: an explicit `sync` *before* attempting `umount`,
    so the flush happens on its own timeline (with its own generous
    timeout) rather than hidden inside umount's own blocking wait - by the
    time umount actually runs, there should be little or nothing left to
    flush, making it fast; and a real try/except around the umount call
    itself with a materially longer, dedicated timeout, so this function
    finally, genuinely never raises as documented. Returns {"success": bool,
    "warning": str|None} - "warning" is set (but success can still be True)
    when sync or umount didn't cleanly finish in time, so a caller with
    other, already-confirmed-successful work to report (e.g. the Build
    job's own asset copy) can decide not to hard-fail the whole job over a
    slow bookkeeping step, while still surfacing that something took an
    unusually long time and the drive is worth double-checking."""
    warning = None
    try:
        sync_res = subprocess.run(["sync"], capture_output=True, timeout=_SYNC_TIMEOUT_SECONDS)
        if sync_res.returncode != 0:
            warning = "sync exited non-zero before unmount - the drive may still have pending writes."
    except subprocess.TimeoutExpired:
        warning = f"sync did not finish within {_SYNC_TIMEOUT_SECONDS}s before unmount - the drive may still have pending writes."
    except Exception:
        pass

    try:
        res = subprocess.run(["sudo", "umount", mountpoint], capture_output=True, timeout=_UNMOUNT_TIMEOUT_SECONDS)
        if res.returncode != 0:
            warning = (warning + " " if warning else "") + "umount exited non-zero - the drive may not be fully written."
    except subprocess.TimeoutExpired:
        warning = (warning + " " if warning else "") + f"umount did not finish within {_UNMOUNT_TIMEOUT_SECONDS}s - it may still be running in the background."
    except Exception as e:
        warning = (warning + " " if warning else "") + f"umount raised an unexpected error: {e}"

    try:
        os.rmdir(mountpoint)
    except OSError:
        pass

    return {"success": warning is None, "warning": warning}


# Phase B discovery - both platforms write into a fixed pair of roots
# relative to the volume root (see live_collection_assets/README.txt for
# the full on-disk layout this mirrors): UAC's own run directory lands
# under uac/output/ (forced via --format none/--output-base-name at
# invocation time so it's a plain directory, never a .tar.gz - avoids
# ever needing to extract an archive, and the attack surface a crafted
# tar entry would otherwise be, entirely), and the hand-written
# PowerShell collector's own run directory lands under windows/results/.
_UAC_RUN_DIR_RE = re.compile(r'^uac-(?P<hostname>.+)-(?P<os>[a-z]+)-(?P<timestamp>\d{8}T\d{6}Z?)$')
_WINDOWS_RUN_DIR_RE = re.compile(r'^(?P<hostname>.+)_(?P<timestamp>\d{8}_\d{6})$')
COLLECTION_RUN_ROOTS = {"unix": "uac/output", "windows": "windows/results"}


def run_timestamp_to_epoch(timestamp_str):
    """Converts a run's own directory-name timestamp (either shape above -
    '%Y%m%dT%H%M%S' with an optional trailing Z from UAC, or '%Y%m%d_%H%M%S'
    from windows_collector.ps1's Get-Date) into a Unix epoch float, used to
    stamp every artifact record parsed from that run with a single, honest
    "as of this snapshot" capture time (see core/live_collection_results_
    utils.py's own docstring for why a per-run, not per-record, timestamp).
    Treated as naive local time on this station, not UTC - windows_
    collector.ps1's own Get-Date call is unambiguously local time, and this
    is meant as a rough "when was this collected" reference for the
    Evidence Timeline, not a to-the-second-precise value. Returns None
    (never raises) if the string doesn't match either known shape."""
    cleaned = timestamp_str.rstrip('Z')
    for fmt in ('%Y%m%dT%H%M%S', '%Y%m%d_%H%M%S'):
        try:
            return time.mktime(time.strptime(cleaned, fmt))
        except ValueError:
            continue
    return None


def _dir_stats(path):
    file_count = 0
    total_bytes = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            file_count += 1
            try:
                total_bytes += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return file_count, total_bytes


def discover_collection_runs(mount_path):
    """Scans a mounted collection USB for real result run folders under
    both known roots. Returns a list of {platform, path (relative to
    mount_path), hostname, timestamp, file_count, total_bytes} - never
    raises; a missing root directory (e.g. the USB was only ever used for
    one platform) is simply skipped, not an error."""
    runs = []
    for platform, rel_root in COLLECTION_RUN_ROOTS.items():
        root_path = os.path.join(mount_path, rel_root)
        if not os.path.isdir(root_path):
            continue
        for name in sorted(os.listdir(root_path)):
            full_path = os.path.join(root_path, name)
            if not os.path.isdir(full_path):
                continue
            pattern = _UAC_RUN_DIR_RE if platform == "unix" else _WINDOWS_RUN_DIR_RE
            m = pattern.match(name)
            file_count, total_bytes = _dir_stats(full_path)
            if file_count == 0:
                continue  # an empty run directory (tool started, never finished) isn't a real result
            runs.append({
                "platform": platform,
                "run_name": name,
                "relative_path": os.path.join(rel_root, name),
                "hostname": m.group("hostname") if m else None,
                "timestamp": m.group("timestamp") if m else None,
                "file_count": file_count,
                "total_bytes": total_bytes,
            })
    return runs
