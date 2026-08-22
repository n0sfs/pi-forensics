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
    is_valid_block_device_or_partition, _DEVICE_RE,
)
from core.config import EVIDENCE_ROOT, INSTALL_DIR, ALLOWED_HASH_ALGOS
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job,
    get_active_proc, clear_active_proc,
    _stream_subprocess, reclaim_ownership,
    build_report_target, write_initial_report, _write_report,
)

acquisition_bp = Blueprint('acquisition', __name__)


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
    cmd += [f"-p{recovery_key}", "--", mount_dir]
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
    """Returns (actual_source_path, is_real_block_device, bitlocker_mount_id).
    If `source` exactly matches a currently-registered dislocker mount's own
    decrypted virtual file path, it's trusted as a valid acquisition source
    without needing to pass is_valid_block_device() - only a path this app's
    own _dislocker_unlock() just created can ever match, since mountpoints
    live under DISLOCKER_MOUNT_ROOT and are never client-supplied."""
    with bitlocker_lock:
        for mount_id, info in active_bitlocker_mounts.items():
            if info["source_path"] == source:
                return source, False, mount_id
    return source, True, None

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
    hashes = {}
    try:
        matches = re.findall(r'(\b(?:MD5|SHA1|SHA256)\b)\s*(?:hash|hash stored in file)?:?\s*([a-fA-F0-9]{32,64})', console_log_text, re.IGNORECASE)
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
                    
                    # Force read-only lock upon discovery
                    try:
                        subprocess.run(['sudo', '/usr/sbin/blockdev', '--setro', dev_path], capture_output=True)
                    except Exception:
                        pass

                    drives.append({
                        "name": dev['name'],
                        "device": dev_path,
                        "model": dev.get('model') or 'Generic Disk',
                        "size": f"{gb_size} GB",
                        "bytes": bytes_size,
                        "transport": dev.get('tran') or 'usb',
                        "serial": dev.get('serial') or 'N/A',
                        "read_only": True
                    })
    except Exception as e:
        print(f"Error executing lsblk: {e}")
        
    return jsonify(drives)

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

    action_flag = '--setro' if enable else '--setrw'

    try:
        # Expand partitions in Python (no shell globbing) and unmount each
        # with argv-list subprocess calls, so nothing reaches a shell.
        for part in sorted(glob.glob(f"{drive}*")):
            subprocess.run(['sudo', 'udevil', 'unmount', '-b', part], capture_output=True)
            subprocess.run(['sudo', 'umount', part], capture_output=True)

        res = subprocess.run(['sudo', '/usr/sbin/blockdev', action_flag, drive], capture_output=True, text=True)

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
    
    compression = req.get('compression', 'fast')
    split_size = req.get('split_size', '2000M')

    VALID_FORMATS = {'dd', 'raw', 'dcfldd', 'plain_dd', 'e01', 'aff'}
    if fmt not in VALID_FORMATS:
        update_job(active=False)
        return jsonify({"error": f"Unrecognized format '{fmt}'. Use one of {sorted(VALID_FORMATS)}."}), 400

    # A `source` matching a currently-registered dislocker mount (see
    # /api/bitlocker/unlock) is a decrypted virtual file, not a real block
    # device - trusted because only this app's own _dislocker_unlock() can
    # ever create a path that matches (mountpoints live under the
    # server-controlled DISLOCKER_MOUNT_ROOT, never client-supplied).
    source, source_is_real_device, bitlocker_mount_id = _resolve_acquisition_source(source)
    if source_is_real_device:
        if not is_valid_block_device(source) or not os.path.exists(source):
            update_job(active=False)
            return jsonify({"error": f"Source device {source} not found or not a recognized whole-disk device."}), 400
    elif not os.path.exists(source):
        update_job(active=False)
        return jsonify({"error": "The unlocked BitLocker volume is no longer available - it may have been locked/unmounted."}), 400

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
    if source_is_real_device:
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

    # SMART telemetry only exists for a real physical device - a decrypted
    # dislocker-file has none of its own (it's a virtual file backed by the
    # already-encrypted partition), so this is skipped entirely rather than
    # querying smartctl against a path it was never meant to see.
    smart_data = {}
    if source_is_real_device:
        try:
            res_smart = subprocess.run(['sudo', 'smartctl', '-a', '-j', source], capture_output=True, text=True)
            if res_smart.stdout:
                smart_data = json.loads(res_smart.stdout)
        except Exception:
            pass

    model = smart_data.get('model_name') or smart_data.get('device', {}).get('name') or "Generic Storage Media"
    family = smart_data.get('model_family') or smart_data.get('family_name')
    vendor_model = f"{family} ({model})" if (family and family.lower() not in model.lower()) else model
    if not source_is_real_device:
        vendor_model = "BitLocker-Decrypted Volume (via dislocker)"

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
        # acquisition, not the internal dislocker mountpoint - the mountpoint
        # is implementation detail, the original device is what belongs in
        # the case record.
        "device_path": active_bitlocker_mounts.get(bitlocker_mount_id, {}).get("device", source) if bitlocker_mount_id else source,
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
        # dislocker-unlocked BitLocker source is. Only add it for a real
        # block device.
        if source_is_real_device:
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
            **({"bitlocker_decrypted": True} if bitlocker_mount_id else {}),
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
    else:
        thread = threading.Thread(
            target=execution_worker,
            args=(cmd, fmt, total_bytes, out_file, report_target, report_data, hashes)
        )
    thread.daemon = True
    thread.start()

    # A dislocker mount must stay live for the whole acquisition (dc3dd/
    # dcfldd/etc. read from it throughout the job), then gets torn down as
    # soon as it's no longer needed - a decrypted mount is sensitive and
    # shouldn't linger any longer than the job that actually needed it.
    # This runs in its own thread (not execution_worker's own finally
    # block) specifically to avoid threading a new parameter through that
    # already-large, multi-caller function; thread.join() here blocks only
    # this cleanup thread, not the request that already returned above.
    if bitlocker_mount_id:
        requester_ip = request.remote_addr
        requester_user = getattr(g, 'forensic_user', None)

        def _cleanup_bitlocker_after_job(worker_thread, mid, src_ip, user):
            worker_thread.join()
            _dislocker_lock(mid)
            log_chain_of_custody("bitlocker_lock", {"mount_id": mid, "reason": "acquisition_complete"},
                                 source_ip=src_ip, user=user)

        cleanup_thread = threading.Thread(
            target=_cleanup_bitlocker_after_job, args=(thread, bitlocker_mount_id, requester_ip, requester_user)
        )
        cleanup_thread.daemon = True
        cleanup_thread.start()

    log_chain_of_custody("acquisition_start", {"format": fmt, "source": source, "destination": dest_path,
                                                **({"bitlocker_decrypted": True} if bitlocker_mount_id else {})})
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

        with job_lock:
            current_job["status"] = "Stopped"
            current_job["active"] = False
            current_job["log"] += "\n[!] Acquisition manually terminated by user."
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

