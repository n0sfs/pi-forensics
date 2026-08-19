"""Shared single-job state (current_job/active_proc), the generic
subprocess-streaming engine, and the per-case report-write helpers every
execution_worker_* function in routes/acquisition.py, routes/mobile.py,
and routes/recovery.py depends on.

Part of the app.py -> core/ + routes/ split - pure code motion, with one
deliberate, load-bearing fix: `active_proc` used to be a bare module-level
global, reassigned via `global active_proc; active_proc = ...` inside 9
different execution_worker_* functions' `finally` blocks and read directly
by stop_imaging() - all of which now live in different routes/*.py files.
A bare `from core.jobs import active_proc` in another module creates an
independent local name binding at import time; `global active_proc;
active_proc = None` inside a worker living in, say, routes/mobile.py would
then rebind routes.mobile's OWN attribute, never touching the real
core.jobs.active_proc - silently breaking stop_imaging()'s ability to kill
the actual running process. Fixed by never exporting `active_proc` as an
importable name at all - only get_active_proc()/set_active_proc()/
clear_active_proc() accessor functions, mirroring the existing
update_job()/snapshot_job() pattern already used for current_job. Every
caller outside this module goes through those. See the dated CLAUDE.md
entry for this refactor for the full rationale.
"""
import os
import re
import pwd
import time
import json
import uuid
import fcntl
import subprocess
import threading

from core.paths import case_consolidated_path

# Guards access to the shared current_job / active_proc state, which is
# written from the background acquisition thread and read/written from
# request-handling threads.
job_lock = threading.Lock()

def update_job(**kwargs):
    """Atomically update one or more fields of the shared current_job dict."""
    with job_lock:
        current_job.update(kwargs)

def snapshot_job():
    """Return a consistent point-in-time copy of current_job for reading."""
    with job_lock:
        return dict(current_job)

def poll_directory_size(path):
    """Ground-truth bytes-on-disk for a file or directory tree, used as a
    progress proxy for tools that don't report a parseable percentage.
    Shared by mobile and recovery workers (routes/mobile.py,
    routes/recovery.py) - lives here rather than in either routes/*.py
    file so neither has to import it from the other."""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        total = 0
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return total
    except Exception:
        return 0

# Global State for Live Acquisition Job
current_job = {
    "active": False,
    "format": "dd",
    "progress_percent": 0.0,
    "speed_mbps": 0.0,
    "transferred_bytes": 0,
    "total_bytes": 0,
    "status": "IDLE",
    "log": "[System initialized and idle. Ready for disk acquisition job.]"
}

# Never imported directly by other modules - see the accessor functions
# below and the module docstring for why.
active_proc = None

def get_active_proc():
    return active_proc

def set_active_proc(proc):
    global active_proc
    active_proc = proc

def clear_active_proc():
    global active_proc
    active_proc = None

# --- Direct Real-time Asynchronous Execution Engine ---
def _stream_subprocess(cmd, on_line, on_poll=None, poll_interval=2.0, cwd=None, stdin_yes=False):
    """
    Launch cmd, non-blockingly stream stdout+stderr line by line (ANSI-
    stripped) into on_line(clean_line), and return the finished Popen
    object. Sets the module-level active_proc so /api/stop_imaging can
    kill it. Shared by execution_worker (single-phase formats),
    execution_worker_aff (raw acquisition + AFF conversion phases), and
    the mobile workers.

    If on_poll is given, it's called every poll_interval seconds
    regardless of stdout activity - some tools (idevicebackup2, adb
    backup) go long stretches with no output while still working, so
    line-triggered progress alone isn't enough to show the job is alive.

    cwd: run the process in this working directory - needed for tools
    like extundelete that write output relative to their cwd rather than
    accepting an explicit output-path flag.

    stdin_yes: pipe "y\\n" to the process immediately, then close stdin -
    needed for extundelete, which can block on an interactive
    confirmation prompt about filesystem safety warnings. Without an
    explicit pipe here, stdin would be whatever the parent service
    process has (typically /dev/null under systemd), which doesn't
    reliably answer that prompt.
    """
    global active_proc
    active_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin_yes else None,
        text=False,
        bufsize=0,
        cwd=cwd,
        preexec_fn=os.setsid
    )

    if stdin_yes:
        try:
            active_proc.stdin.write(b'y\n')
            active_proc.stdin.close()
        except Exception:
            pass

    fd = active_proc.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    byte_buffer = b""
    last_poll = time.time()

    while True:
        time.sleep(0.1)
        try:
            raw_chunk = os.read(fd, 1024)
            if raw_chunk:
                byte_buffer += raw_chunk

                while b'\r' in byte_buffer or b'\n' in byte_buffer:
                    r_idx = byte_buffer.find(b'\r')
                    n_idx = byte_buffer.find(b'\n')
                    indices = [i for i in (r_idx, n_idx) if i != -1]
                    cut_idx = min(indices)

                    line_bytes = byte_buffer[:cut_idx]
                    byte_buffer = byte_buffer[cut_idx + 1:]

                    line_str = line_bytes.decode('utf-8', errors='ignore')
                    clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line_str).replace('\r', '').strip()
                    if clean_line:
                        on_line(clean_line)

            elif active_proc.poll() is not None:
                break
        except (OSError, IOError):
            pass

        if on_poll and (time.time() - last_poll) >= poll_interval:
            try:
                on_poll()
            except Exception:
                pass
            last_poll = time.time()

    active_proc.wait()
    return active_proc

# --- Consolidated Per-Case Reporting ---
# A "case" started via /api/cases/create now gets exactly one JSON file
# ({slug}_case.json, at the case folder root) that every job run against
# any evidence item in that case appends an "event" to, instead of each of
# the 9 job-starting routes below writing its own separate {base}_report.json.
# No-case-active usage (a destination that isn't a real case folder) keeps
# writing the old flat per-job file, completely unchanged - see
# build_report_target(). Existing cases stay on the old scattered-files
# layout until explicitly migrated (see /api/cases/migrate_preview/_apply);
# there's no silent auto-upgrade, to avoid a case ending up half-migrated.
class CaseEventTarget:
    """Marks a report write as 'append/update one event inside a case's
    consolidated file' rather than 'overwrite a standalone _report.json'."""
    __slots__ = ("case_file", "event_id")
    def __init__(self, case_file, event_id):
        self.case_file = case_file
        self.event_id = event_id

def _read_case_file(case_file):
    try:
        with open(case_file, 'r') as f:
            return json.load(f)
    except Exception:
        return {"schema_version": 1, "events": [], "attachments": {"files": [], "reference_urls": []}}

def _write_case_file(case_file, case_record):
    with open(case_file, 'w') as f:
        json.dump(case_record, f, indent=2)

def _case_upsert_event(case_file, event_id, event_data):
    """Replaces the event matching event_id if present, else appends it -
    this is what makes a job's start-write and later complete-write update
    the SAME array entry instead of appending a duplicate."""
    case_record = _read_case_file(case_file)
    events = case_record.setdefault("events", [])
    events[:] = [e for e in events if e.get("event_id") != event_id]
    payload = dict(event_data)
    payload["event_id"] = event_id
    events.append(payload)
    case_record["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_case_file(case_file, case_record)

def build_report_target(dest_path, legacy_dir, base_name):
    """Returns a CaseEventTarget if `dest_path` is an active case folder,
    else the plain flat-file path this route would have used before this
    change existed (legacy_dir is job_dest_dir for tools that write into
    their own subfolder, dest_path itself for the rest)."""
    case_file = case_consolidated_path(dest_path)
    if case_file:
        return CaseEventTarget(case_file, uuid.uuid4().hex)
    return os.path.join(legacy_dir, f"{base_name}_report.json")

def write_initial_report(report_target, report_data):
    """First write at job start (status IN_PROGRESS) - mirrors what every
    route used to do with a bare open()/json.dump() against its own file."""
    try:
        if isinstance(report_target, CaseEventTarget):
            _case_upsert_event(report_target.case_file, report_target.event_id, report_data)
        else:
            with open(report_target, 'w') as f:
                json.dump(report_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not write report JSON: {e}")

def _write_report(report_target, report_data, append_log):
    """Second write at job completion (status COMPLETED/FAILED/etc) - called
    from inside the worker threads, unchanged at every call site; only the
    type of report_target (flat path vs CaseEventTarget) changed upstream."""
    try:
        if isinstance(report_target, CaseEventTarget):
            _case_upsert_event(report_target.case_file, report_target.event_id, report_data)
            append_log(f"[+] Forensic case report updated: {report_target.case_file} (event {report_target.event_id[:8]})")
        else:
            with open(report_target, 'w') as f:
                json.dump(report_data, f, indent=2)
            append_log(f"[+] Forensic case report updated: {report_target}")
    except Exception as e:
        append_log(f"[-] Warning: Failed updating report JSON: {e}")

_SERVICE_ACCOUNT_NAME = pwd.getpwuid(os.getuid()).pw_name

def reclaim_ownership(path):
    """
    dc3dd/dcfldd/dd/ewfacquire/photorec/ddrescue all run via sudo (root) to
    get raw read access to the source device - their output files land
    owned by root as a side effect. Without handing ownership back, every
    later operation on those files (delete, hash verify, copy, ExifTool,
    etc.) run as this unprivileged service account would fail with
    permission denied. Safe to grant broadly in sudoers: the target
    user:group is fixed at install time, not attacker-controllable, so this
    can only ever hand a file back to the unprivileged account, never
    escalate ownership to root or anyone else.
    """
    if not path or not os.path.exists(path):
        return
    try:
        subprocess.run(['sudo', '/bin/chown', '-R', _SERVICE_ACCOUNT_NAME, path], capture_output=True, timeout=30)
        subprocess.run(['sudo', '/bin/chgrp', '-R', _SERVICE_ACCOUNT_NAME, path], capture_output=True, timeout=30)
    except Exception as e:
        print(f"Warning: could not reclaim ownership of {path}: {e}")
