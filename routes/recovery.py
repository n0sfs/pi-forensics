"""File Recovery: PhotoRec, extundelete, foremost, scalpel, the built-in
triage scanner, and TestDisk's read-only partition analysis.

testdisk_analyze() is pulled out of a foreign location in the original
app.py (it physically sat inside the File Explorer/analysis-tools
block, far from the other 5 recovery routes) - the first "pull one
route out of a foreign block" extraction in this refactor, a rehearsal
for two similar clusters reporting.py will need in a later step.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import time
import subprocess
import threading

from flask import Blueprint, jsonify, request

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, is_valid_block_device
from core.config import EVIDENCE_ROOT, SCALPEL_CONF_PATH
from core.jobs import (
    job_lock, current_job, update_job, snapshot_job, poll_directory_size,
    _stream_subprocess, clear_active_proc, reclaim_ownership,
    build_report_target, write_initial_report, _write_report,
)
from core.case_index_db import TRIAGE_PATTERNS, TRIAGE_MAX_MATCHES_PER_CATEGORY

recovery_bp = Blueprint('recovery', __name__)


def execution_worker_photorec(source, dest_dir, report_file_path, report_data):
    """
    PhotoRec file-carving recovery. Only ever reads from `source` and writes
    recovered files to `dest_dir` - never writes back to the source, unlike
    TestDisk's partition-repair mode (which this project deliberately does
    NOT expose, since rewriting a partition table is a write to the
    evidence, conflicting with the write-blocking this whole app is built
    around).

    Scripted-mode syntax is per CGSecurity's own docs (cgsecurity.org/
    testdisk_doc/scripted_run.html): partition_none treats the source as a
    single unpartitioned blob to search (appropriate here since we already
    let the examiner point this at a specific device or a specific image
    file directly, rather than trying to auto-detect partitions).

    No detailed progress percentage is parsed from PhotoRec's output - its
    scripted-mode reporting isn't documented/stable enough to parse safely
    (unlike dc3dd's well-documented format). Progress is bytes recovered so
    far (polled from the destination directory) plus the live log, same
    conservative approach used for the mobile forensics jobs.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="photorec", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = [
            "sudo", "/usr/bin/photorec", "/log", "/d", dest_dir,
            "/cmd", source, "partition_none,options,fileopt,everything,enable,search"
        ]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (PhotoRec)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] PhotoRec recovery completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] photorec exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        # photorec now runs via sudo for raw device access - reclaim
        # regardless of outcome, so recovered files can actually be
        # browsed/deleted/copied afterward by this unprivileged service.
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()


def execution_worker_extundelete(source, dest_dir, report_file_path, report_data):
    """
    extundelete recovers deleted files from ext2/3/4 filesystems by
    parsing the filesystem journal - can recover original filenames/paths
    where a normal carving tool (PhotoRec) can't, but only works on
    ext-family filesystems specifically, unlike PhotoRec's format-agnostic
    signature matching.

    Two things this tool needs that others here don't:
    - It writes to RECOVERED_FILES/ in its *working directory* - there's
      no output-path flag - so it's launched with cwd=dest_dir instead.
    - It can block on an interactive y/n safety confirmation about the
      filesystem's journal state - answered via stdin_yes rather than
      risking an indefinite hang.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="extundelete", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        os.makedirs(dest_dir, exist_ok=True)
        cmd = ["sudo", "/usr/bin/extundelete", source, "--restore-all"]
        append_log(f"[*] Command: {' '.join(cmd)} (run from {dest_dir})")
        update_job(status="Recovering Deleted Files (extundelete)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0, cwd=dest_dir, stdin_yes=True)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] extundelete completed. Recovered data in {dest_dir}/RECOVERED_FILES/")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] extundelete exited with code {proc.returncode} - is the source an ext2/3/4 filesystem?")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()


def execution_worker_foremost(source, dest_dir, report_file_path, report_data):
    """
    foremost - signature-based file carving, an alternative to PhotoRec.
    Older and narrower in supported types than PhotoRec, but sometimes
    faster for the common formats it does support.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="foremost", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = ["sudo", "/usr/bin/foremost", "-t", "all", "-i", source, "-o", dest_dir]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (foremost)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        # foremost refuses to run if the output directory already exists -
        # unlike PhotoRec (-Z) it has no flag to force/wipe it, so this
        # must not be pre-created (matches PhotoRec's route not
        # pre-creating job_dest_dir either).
        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] foremost completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] foremost exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()


def execution_worker_scalpel(source, dest_dir, report_file_path, report_data):
    """
    scalpel - signature-based file carving, another PhotoRec alternative,
    multithreaded so sometimes faster on larger images. Ships with every
    file signature disabled by default in its stock config - this uses a
    curated config file installed alongside this app (SCALPEL_CONF_PATH)
    covering common formats (jpg/png/gif/pdf/zip) rather than depending on
    the stock config, which would silently recover nothing if left as-is.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="scalpel", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=0)

    try:
        cmd = ["sudo", "/usr/bin/scalpel", "-c", SCALPEL_CONF_PATH, "-o", dest_dir, source]
        append_log(f"[*] Command: {' '.join(cmd)}")
        update_job(status="Carving Files (scalpel)...")

        def on_line(clean_line):
            append_log(clean_line)

        def on_poll():
            update_job(transferred_bytes=poll_directory_size(dest_dir))

        # Like foremost, scalpel refuses to run against an existing output
        # directory - must not be pre-created.
        proc = _stream_subprocess(cmd, on_line, on_poll=on_poll, poll_interval=3.0)
        time.sleep(1.0)

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        final_size = poll_directory_size(dest_dir)

        if proc.returncode == 0:
            update_job(status="Completed Successfully", progress_percent=100.0, transferred_bytes=final_size)
            append_log(f"[+] scalpel completed. Recovered data size: {final_size} bytes")
            report_data["acquisition_status"] = "COMPLETED"
            report_data["output_size_bytes"] = final_size
        elif snapshot_job()["status"] != "Stopped":
            update_job(status="Failed")
            append_log(f"[-] scalpel exited with code {proc.returncode}")
            report_data["acquisition_status"] = "FAILED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        reclaim_ownership(dest_dir)
        update_job(active=False)
        clear_active_proc()


def execution_worker_triage_scan(source, dest_dir, report_file_path, report_data, total_bytes):
    """
    Built-in triage scan for structured data (emails, URLs, IP addresses,
    credit-card-like numbers, phone numbers) - reads the source directly
    and regex-matches TRIAGE_PATTERNS against it, writing deduplicated
    results to one text file per category. No external tool dependency at
    all (see TRIAGE_PATTERNS above for why that matters), so this can never
    hit a "package not found" wall on any system this app runs on.
    Read-only against the source.

    Honest tradeoff: this is a straightforward single-threaded Python loop,
    not a highly-optimized C/C++ scanner - noticeably slower than a
    dedicated tool on a very large (multi-TB) image. It's well suited to
    the smaller targets (USB drives, phone backups, individual files) this
    project mostly deals with; for a full scan of a very large drive,
    expect it to take a while.
    """
    log_history = []

    def append_log(msg):
        if msg:
            log_history.append(msg)
            update_job(log="\n".join(log_history[-100:]))

    start_time = time.time()
    update_job(format="triage_scan", status="Initializing...", progress_percent=0.0,
               speed_mbps=0.0, transferred_bytes=0, total_bytes=total_bytes)

    CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB
    OVERLAP = 256  # bytes carried over between chunks so a match spanning a
                   # chunk boundary isn't missed

    results = {name: set() for name in TRIAGE_PATTERNS}
    truncated = {name: False for name in TRIAGE_PATTERNS}

    try:
        os.makedirs(dest_dir, exist_ok=True)
        append_log(f"[*] Scanning {source} for structured data (emails, URLs, IPs, card-like numbers, phone numbers)...")
        update_job(status="Scanning for Structured Data...")

        bytes_read = 0
        tail = b""
        last_update_time = time.time()

        # Raw block devices need root to read directly - pipe through a
        # privileged `dd` and read its stdout instead of opening the device
        # file directly (which would hit the same permission wall dc3dd/
        # ddrescue/etc. would without sudo). An already-acquired image file
        # is owned by this account already, so a direct Python open() is
        # simpler and faster there - no privilege elevation needed.
        read_proc = None
        if is_valid_block_device(source):
            read_proc = subprocess.Popen(
                ["sudo", "/usr/bin/dd", f"if={source}", f"bs={CHUNK_SIZE}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            source_stream = read_proc.stdout
        else:
            source_stream = open(source, 'rb')

        try:
            while True:
                if snapshot_job()["status"] == "Stopped":
                    append_log("[!] Scan stopped by user.")
                    break

                chunk = source_stream.read(CHUNK_SIZE)
                if not chunk:
                    break

                data = tail + chunk
                for name, pattern in TRIAGE_PATTERNS.items():
                    if truncated[name]:
                        continue
                    for m in pattern.finditer(data):
                        val = m.group(0)
                        if len(val) > 4:  # skip trivial/near-empty matches
                            results[name].add(val)
                            if len(results[name]) >= TRIAGE_MAX_MATCHES_PER_CATEGORY:
                                truncated[name] = True
                                append_log(f"[!] {name}: hit the {TRIAGE_MAX_MATCHES_PER_CATEGORY}-match cap, no longer collecting new ones.")
                                break

                tail = data[-OVERLAP:] if len(data) >= OVERLAP else data
                bytes_read += len(chunk)

                # Throttle UI updates rather than pushing on every chunk.
                if time.time() - last_update_time > 0.5:
                    updates = {"transferred_bytes": bytes_read}
                    if total_bytes > 0:
                        updates["progress_percent"] = round((bytes_read / total_bytes) * 100, 1)
                    update_job(**updates)
                    last_update_time = time.time()
        finally:
            try:
                source_stream.close()
            except Exception:
                pass
            if read_proc is not None:
                try:
                    if read_proc.poll() is None:
                        read_proc.terminate()
                        read_proc.wait(timeout=5)
                except Exception:
                    pass  # expected if it's already root-owned via sudo - the sudo pkill below is the real cleanup
                # sudo dd runs as root - an unprivileged terminate()/kill()
                # from this process can't touch it, so also sweep it via
                # the same sudo pkill pattern used to stop other privileged
                # acquisition tools.
                try:
                    subprocess.run(["sudo", "pkill", "-9", "-f", f"dd if={source}"], capture_output=True)
                except Exception:
                    pass

        update_job(transferred_bytes=bytes_read)

        total_hits = 0
        for name, matches in results.items():
            out_path = os.path.join(dest_dir, f"{name}.txt")
            with open(out_path, 'w') as out_f:
                for val in sorted(matches):
                    out_f.write(val.decode('utf-8', errors='replace') + "\n")
            total_hits += len(matches)
            note = " (capped)" if truncated[name] else ""
            append_log(f"[+] {name}: {len(matches)} unique match(es){note} -> {out_path}")

        report_data["execution_time_seconds"] = round(time.time() - start_time, 2)
        report_data["triage_summary"] = {name: len(matches) for name, matches in results.items()}

        if snapshot_job()["status"] == "Stopped":
            report_data["acquisition_status"] = "STOPPED"
        else:
            update_job(status="Completed Successfully", progress_percent=100.0)
            append_log(f"[+] Triage scan completed. {total_hits} total unique matches across all categories.")
            report_data["acquisition_status"] = "COMPLETED"

        _write_report(report_file_path, report_data, append_log)

    except Exception as e:
        update_job(status="Failed")
        append_log(f"[-] Execution Exception: {str(e)}")

    finally:
        update_job(active=False)
        clear_active_proc()


# --- File Carving / Recovery (PhotoRec) ---
@recovery_bp.route('/api/recovery/start_photorec', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_photorec():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    # Source can be either a whole-disk device (recovering directly from a
    # damaged drive) or an already-sandboxed image file (recovering from a
    # .dd/.img acquired earlier, e.g. after a ddrescue pass) - never an
    # arbitrary path outside EVIDENCE_ROOT either way.
    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_photorec"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="photorec", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing PhotoRec recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "photorec",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "photorec (file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_photorec,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("photorec_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "PhotoRec recovery started."})


@recovery_bp.route('/api/recovery/start_extundelete', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_extundelete():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_extundelete"
    job_dest_dir = os.path.join(dest_path, base_name)

    try:
        # Must pre-create (unlike foremost/scalpel below) - extundelete is
        # launched with cwd=job_dest_dir, which requires the directory to
        # already exist.
        os.makedirs(job_dest_dir, exist_ok=True)
    except Exception as e:
        update_job(active=False)
        return jsonify({"error": f"Destination path {job_dest_dir} is inaccessible: {str(e)}"}), 400

    update_job(
        format="extundelete", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing extundelete recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "extundelete",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "extundelete (ext2/3/4 journal-based deleted file recovery)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, job_dest_dir, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_extundelete,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("extundelete_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "extundelete recovery started."})


@recovery_bp.route('/api/recovery/start_foremost', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_foremost():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_foremost"
    job_dest_dir = os.path.join(dest_path, base_name)
    # Deliberately NOT pre-created - foremost refuses to run if its output
    # directory already exists. The report lives in the parent dest_path
    # instead, since job_dest_dir won't exist until foremost itself creates it.

    update_job(
        format="foremost", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing foremost recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "foremost",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "foremost (signature-based file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_foremost,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("foremost_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "foremost recovery started."})


@recovery_bp.route('/api/recovery/start_scalpel', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_scalpel():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_scalpel"
    job_dest_dir = os.path.join(dest_path, base_name)
    # Deliberately NOT pre-created - same reason as foremost above.

    update_job(
        format="scalpel", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=0, status="Initializing...",
        log=f"[*] Initializing scalpel recovery from {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "scalpel",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "scalpel (signature-based file carving)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_scalpel,
        args=(source, job_dest_dir, report_target, report_data)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("scalpel_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "scalpel recovery started."})


@recovery_bp.route('/api/recovery/start_triage_scan', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def start_triage_scan():
    with job_lock:
        if current_job["active"]:
            return jsonify({"error": "An acquisition job is already running."}), 400
        current_job["active"] = True

    req = request.get_json() or {}
    source_raw = req.get('source', '')
    dest_path = safe_path(req.get('destination', EVIDENCE_ROOT).strip())
    metadata = req.get('metadata', {})

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            update_job(active=False)
            return jsonify({"error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    if not dest_path:
        update_job(active=False)
        return jsonify({"error": "Destination path is outside the permitted evidence directory."}), 400

    case_num = metadata.get('case_number', 'UNASSIGNED')
    evidence_id = metadata.get('evidence_id', 'ITEM-01')
    base_name = f"{case_num}_{evidence_id}_triagescan"
    job_dest_dir = os.path.join(dest_path, base_name)

    total_bytes = 0
    try:
        if is_valid_block_device(source):
            res = subprocess.run(['sudo', '/usr/sbin/blockdev', '--getsize64', source], capture_output=True, text=True)
            if res.returncode == 0:
                total_bytes = int(res.stdout.strip())
        else:
            total_bytes = os.path.getsize(source)
    except Exception:
        pass

    update_job(
        format="triage_scan", progress_percent=0.0, speed_mbps=0.0,
        transferred_bytes=0, total_bytes=total_bytes, status="Initializing...",
        log=f"[*] Initializing triage scan of {source} -> {job_dest_dir}..."
    )

    report_data = {
        "tool": "triage_scan",
        "case_metadata": metadata,
        "acquisition_parameters": {
            "method": "built-in triage scan (emails/URLs/IPs/card-like numbers/phone numbers)",
            "source": source,
            "output_destination": job_dest_dir,
        },
        "attachments": {"files": [], "reference_urls": []},
        "acquisition_status": "IN_PROGRESS",
        "timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    report_target = build_report_target(dest_path, dest_path, base_name)
    write_initial_report(report_target, report_data)

    thread = threading.Thread(
        target=execution_worker_triage_scan,
        args=(source, job_dest_dir, report_target, report_data, total_bytes)
    )
    thread.daemon = True
    thread.start()

    log_chain_of_custody("triage_scan_start", {"source": source, "destination": job_dest_dir})
    return jsonify({"success": True, "message": "Triage scan started."})


# --- TestDisk: Read-Only Partition Analysis ---
@recovery_bp.route('/api/recovery/testdisk_analyze', methods=['POST'])
@requires_auth
@requires_permission('recovery')
def testdisk_analyze():
    req = request.get_json() or {}
    source_raw = req.get('source', '')

    if is_valid_block_device(source_raw) and os.path.exists(source_raw):
        source = source_raw
    else:
        source = safe_path(source_raw)
        if not source or not os.path.isfile(source):
            return jsonify({"success": False, "error": f"Source '{source_raw}' is not a recognized device or a valid image file in the permitted evidence directory."}), 400

    try:
        # -l is TestDisk's dedicated read-only partition listing flag - a
        # genuinely separate, simpler command from the /cmd scripting
        # syntax (which supports write-capable actions like rebuildbs).
        # Using -l specifically, rather than /cmd with a hand-picked
        # read-only subset of keywords, means this can never accidentally
        # grow a write action later - the flag itself is incapable of one.
        res = subprocess.run(['sudo', '/usr/bin/testdisk', '-l', source], capture_output=True, text=True, timeout=60)
        output = res.stdout.strip() or res.stderr.strip() or "[no output]"
        log_chain_of_custody("testdisk_analyze", {"source": source})
        return jsonify({"success": True, "source": source, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "testdisk timed out."}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
