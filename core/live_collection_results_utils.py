"""Live Collection USB results parsing - turns the raw JSON/text files a
completed collection run produces into this app's standard artifact-record
shape ({artifact_type, title, url, value, timestamp, extra}), so the same
already-generic _record_parsed_artifacts()/parsed_artifacts table and File
Views' "Parsed Artifacts" rendering that already handle Registry/Event Log/
Prefetch/browser artifacts need zero changes to also handle this source.

Two genuinely different parsing problems, kept as two separate halves of
this module (mirroring why core/registry_utils.py and core/linux_
artifacts.py are already separate modules rather than one shared one):

- The Windows side (live_collection_assets/windows_collector.ps1's own
  output) is dispatch-by-known-filename JSON, fully scoped and parsed here
  - the script's exact field shapes were confirmed by direct read before
  this module was written, not guessed.
- The Unix/UAC side is scoped narrowly to just the clipboard supplemental
  file this app's own run_collector.sh writes (see that script's own
  comments) - a real, partial ir_triage run against a live station during
  this feature's own Phase 0 spike (2026-08-31) confirmed UAC's own raw
  output is per-shell-command plain text with highly variable, command-
  derived filenames (e.g. ps_-axo_pid_user_lstart_args.txt), genuinely more
  varied than a quick scope could safely parse - full UAC-side individual-
  record parsing is deliberately deferred to a future pass once real,
  complete sample output exists to design against, not attempted here on
  an under-verified assumption. The folder-level auto-tag (_auto_tag_case_
  artifact(), already wired into the import worker) is always the
  guaranteed fallback for everything not individually parsed here.

No per-record timestamp exists in most of this data (a process list has no
timestamp of its own) - every record from one collection run is stamped
with that run's own capture time instead (parsed once, by the caller, from
the run's own directory name via core/live_collection_utils.py's existing
_UAC_RUN_DIR_RE/_WINDOWS_RUN_DIR_RE). This is honest (it never fabricates
per-record precision that doesn't exist) and still genuinely useful on the
Evidence Timeline as a dense "state as of this snapshot" cluster.
"""
import json
import os
from datetime import datetime, timezone

# --- Windows side ---

# Every filename windows_collector.ps1 (live_collection_assets/) is known to
# write - confirmed against that script's own Write-ArtifactJson -Name calls
# directly, not guessed. _collection_log.json is read first (see below) to
# skip categories the collector itself already logged as failed/skipped,
# rather than attempting to parse a file that may not exist or be empty.
WINDOWS_RESULT_FILENAMES = {
    'system_info.json', 'processes.json', 'process_hashes.json',
    'network_connections.json', 'logged_on_users.json', 'arp_cache.json',
    'dns_cache.json', 'services.json', 'scheduled_tasks.json', 'autoruns.json',
    'installed_hotfixes.json', 'loaded_drivers.json', 'mapped_drives.json',
    'clipboard.json', '_collection_log.json',
}


def find_windows_collector_result_files(run_dir):
    """The run directory is already fully known by the time this is called
    (the caller located it via discover_collection_runs()), so this is a
    flat listdir + filename-allowlist check, not a recursive walk. Returns
    the set of known filenames actually present."""
    try:
        present = set(os.listdir(run_dir))
    except OSError:
        return set()
    return present & WINDOWS_RESULT_FILENAMES


def _load_json(run_dir, filename):
    """Best-effort JSON load - a truncated write, an unexpected top-level
    shape, or a missing file all degrade to None rather than raising, so
    one bad file can never abort the rest of a run's parse."""
    path = os.path.join(run_dir, filename)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _skipped_categories(run_dir):
    """Reads _collection_log.json (if present) and returns the set of
    category names the collector script itself already logged as 'failed'
    or 'skipped' - used to avoid even attempting to parse a file that's
    known to be absent/empty for a documented reason. Never raises; an
    unreadable/missing log just means nothing is pre-filtered, the per-file
    try/except in each _parse_* function still protects against a bad file."""
    log = _load_json(run_dir, '_collection_log.json')
    if not isinstance(log, list):
        return set()
    skipped = set()
    for entry in log:
        if isinstance(entry, dict) and entry.get('status') in ('failed', 'skipped'):
            cat = entry.get('category')
            if cat:
                skipped.add(cat)
    return skipped


def _record(artifact_type, title, url, value, timestamp, extra):
    return {
        'artifact_type': artifact_type, 'title': title or '', 'url': url or '',
        'value': value or '', 'timestamp': timestamp, 'extra': extra or {},
    }


_VALUE_MAX_LEN = 500


def _safe_value_text(value, max_len=_VALUE_MAX_LEN):
    """Every _parse_* function below interpolates a raw JSON field straight
    from the collector's own output into a record's `value` string, always
    assuming it's a plain scalar. Windows PowerShell can hand back something
    else entirely - confirmed live, not hypothetical: a still-not-yet-fixed
    windows_collector.ps1 run (see that script's own PSDrive metadata-leak
    fix, 2026-09-03) produced one autoruns.json entry whose "value" field
    was a deeply-nested PSDriveInfo object rather than a string. Naively
    str()-ing that into an f-string produced a single ~4MB field, which was
    enough to hang both a direct API client and the real File Explorer UI
    trying to render it - not a style nit, a genuine denial-of-service on
    this app's own File Views. A dict/list is never str()-ified whole here
    (avoids paying that cost at all, not just capping it after the fact);
    every other type is stringified and length-capped, matching this
    module's own pre-existing convention (_parse_scheduled_tasks' fallback
    branch already did `json.dumps(t)[:500]`, just not unconditionally)."""
    if value is None:
        return ''
    if isinstance(value, (dict, list)):
        kind = 'object' if isinstance(value, dict) else 'list'
        return (f"[unexpected {kind} value with {len(value)} field(s) - "
                f"collector output may be malformed, not a plain value]")
    text = str(value)
    if len(text) > max_len:
        text = text[:max_len] + f"... [{len(text) - max_len} more character(s) omitted]"
    return text


def _safe_extra(raw, max_len=_VALUE_MAX_LEN):
    """Applies the same _safe_value_text() capping to every top-level value
    of a raw collector-output dict before it's stored as a parsed_artifact's
    `extra` field. `value` alone being capped isn't enough - extra is stored
    in full (not display-truncated) elsewhere in this app, so an uncapped
    nested object surviving here would still bloat the case index even
    after the fix above. Only dict/list values are touched; every plain
    scalar (str/int/float/bool/None) is passed through unchanged so fields
    like `pid` stay real ints in extra, matching existing behavior."""
    if not isinstance(raw, dict):
        return {}
    return {k: (_safe_value_text(v, max_len) if isinstance(v, (dict, list)) else v) for k, v in raw.items()}


def _parse_iso_datetime_epoch(text):
    """windows_collector.ps1 stamps every genuinely historical timestamp
    (process creation_date, TCP connection created, hotfix installed_on,
    system last_boot_time) via PowerShell's `.ToString('o')` - confirmed
    live (2026-09-03) against real PowerShell 5.1/7 output to always
    produce e.g. "2026-09-03T20:13:04.4885418-04:00" (7-digit, i.e.
    100-nanosecond-tick, fractional seconds - .NET's native resolution,
    not milliseconds), and confirmed live that Python 3.13's
    datetime.fromisoformat() parses that exact format correctly
    (silently rounding to microsecond precision, which is more than
    enough here). Every caller of this function is expected to fall back
    to the collection run's own capture timestamp when this returns None
    - some of these fields are legitimately absent for real reasons (a
    process with no CreationDate, e.g. System Idle Process; a hotfix with
    no InstalledOn), not just malformed collector output, so this always
    degrades quietly rather than raising.

    A NAIVE (no timezone offset) datetime is deliberately treated as
    unparseable, not silently converted via `.timestamp()`'s own default
    of assuming the ANALYSIS machine's local timezone - that would make
    the resulting timestamp depend on where the case is being reviewed
    rather than the evidence itself, exactly the class of bug this project
    has already found and fixed twice this same session for a different
    reason (Windows Registry FILETIME values, macOS plist dates, both
    naive-but-actually-UTC). It's moot for real collector output, which
    is always offset-aware via .ToString('o') - this only matters for a
    genuinely malformed/legacy field, where falling back to the run's own
    capture time is the honest, deterministic answer."""
    if not text or not isinstance(text, str):
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


_MIN_PLAUSIBLE_YEAR = 2000
# Computed once, in the forward direction (a real datetime -> its epoch) -
# datetime.fromtimestamp() (the REVERSE direction, epoch -> datetime) is
# genuinely unsafe here: confirmed live that it raises OSError on Windows
# for a negative epoch (a real, well-known cross-platform C-runtime
# limitation, not a Linux-only quirk this app could assume away just
# because production runs on Debian). A plain float comparison against
# this precomputed cutoff avoids the round-trip entirely.
_MIN_PLAUSIBLE_EPOCH = datetime(_MIN_PLAUSIBLE_YEAR, 1, 1, tzinfo=timezone.utc).timestamp()


def _parse_plausible_historical_epoch(text):
    """Like _parse_iso_datetime_epoch() above, but additionally rejects a
    date before _MIN_PLAUSIBLE_YEAR. Get-ScheduledTaskInfo's own
    LastRunTime/NextRunTime properties are well-documented, real Task
    Scheduler/PowerShell behavior (a widely-reported gotcha, not this
    app's own guess): a task that's never run, or has no scheduled next
    run, gets a sentinel "zero date" (commonly rendered around 1899 - the
    OLE Automation Date epoch the underlying COM Task Scheduler API uses
    for "no value") instead of a real $null. A sentinel value still
    PARSES successfully as a perfectly valid ISO datetime (unlike a
    genuinely missing/malformed field, which _parse_iso_datetime_epoch
    already catches) - without this extra guard it would silently become
    a real, wrong Evidence Timeline entry claiming a task last ran in
    1899. Every genuine timestamp anywhere in this app is comfortably
    after this cutoff, so a real value is never rejected by it."""
    epoch = _parse_iso_datetime_epoch(text)
    if epoch is None:
        return None
    if epoch < _MIN_PLAUSIBLE_EPOCH:
        return None
    return epoch


def _parse_system_info(run_dir, ts):
    """system_info.json is the one Windows category that's a single dict,
    not a list (_load_json's own generic caller doesn't assume a shape, so
    this is handled entirely here). Emits up to two records: a general
    "System Info" summary (always, stamped with the run's own capture
    time), and - only when last_boot_time actually parses - a separate
    "System Boot" record stamped with the machine's real, historical
    boot time. That second one is the genuinely pattern-of-life-useful
    piece: a real, discrete event on the Evidence Timeline distinct from
    "when did the examiner run the collector", not just more collection
    metadata (2026-09-03)."""
    info = _load_json(run_dir, 'system_info.json')
    if not isinstance(info, dict):
        return []
    hostname = info.get('hostname') or 'Unknown Host'
    os_caption = _safe_value_text(info.get('os_caption', ''))
    os_build = _safe_value_text(info.get('os_build', ''))
    os_arch = _safe_value_text(info.get('os_architecture', ''))
    summary = f"{os_caption} (build {os_build}, {os_arch})"
    records = [_record('live_collection_system_info', str(hostname), '', summary, ts, _safe_extra(info))]

    boot_ts = _parse_iso_datetime_epoch(info.get('last_boot_time'))
    if boot_ts is not None:
        records.append(_record(
            'live_collection_system_boot', f"System Boot - {hostname}", '', summary, boot_ts,
            {'hostname': hostname, 'os_caption': os_caption, 'last_boot_time': info.get('last_boot_time')},
        ))
    return records


def _parse_processes(run_dir, ts):
    procs = _load_json(run_dir, 'processes.json')
    if not isinstance(procs, list):
        return []
    hashes = _load_json(run_dir, 'process_hashes.json')
    hash_by_path = {}
    if isinstance(hashes, list):
        for h in hashes:
            if isinstance(h, dict) and h.get('executable_path'):
                hash_by_path[h['executable_path']] = h.get('sha256')
    records = []
    for p in procs:
        if not isinstance(p, dict):
            continue
        exe_path = p.get('executable_path')
        sha256 = hash_by_path.get(exe_path) if exe_path else None
        cmdline = _safe_value_text(p.get('command_line') or exe_path or '')
        value = f"PID {p.get('pid')} (parent {p.get('parent_pid')}) - {cmdline}"
        extra = {
            'pid': p.get('pid'), 'parent_pid': p.get('parent_pid'),
            'executable_path': exe_path, 'command_line': cmdline,
            'creation_date': p.get('creation_date'), 'owner': p.get('owner'),
            'sha256': sha256,
        }
        # Real per-process launch time (2026-09-03) - falls back to the
        # collection run's own capture time for the small number of
        # processes that legitimately have no CreationDate (System Idle
        # Process, sometimes System itself), never crashes on it.
        record_ts = _parse_iso_datetime_epoch(p.get('creation_date')) or ts
        records.append(_record('live_collection_process', p.get('name'), '', value, record_ts, extra))
    return records


def _parse_network_connections(run_dir, ts):
    conns = _load_json(run_dir, 'network_connections.json')
    if not isinstance(conns, list):
        return []
    records = []
    for c in conns:
        if not isinstance(c, dict):
            continue
        proto = c.get('protocol', '?')
        # Two real shapes exist depending on which PowerShell path collected
        # this - Get-NetTCPConnection/Get-NetUDPEndpoint use local_address/
        # local_port/remote_address/remote_port; the pre-Win8 netstat
        # fallback uses local/remote (already-formatted "ip:port" strings)
        # instead. Handle both rather than assuming one.
        if 'local_address' in c:
            local = f"{c.get('local_address')}:{c.get('local_port')}"
            remote = f"{c.get('remote_address')}:{c.get('remote_port')}" if c.get('remote_address') else ''
        else:
            local = c.get('local', '')
            remote = c.get('remote') or ''
        title = f"{proto} {local}" + (f" -> {remote}" if remote else '')
        value = _safe_value_text(c.get('state') or '')
        extra = _safe_extra(c)
        # Real "when was this connection established" data for TCP
        # (2026-09-03) - never present for UDP (connectionless, no
        # equivalent PowerShell property) or the legacy netstat fallback
        # shape, both of which correctly fall back to the run's own ts.
        record_ts = _parse_iso_datetime_epoch(c.get('created')) or ts
        records.append(_record('live_collection_network_connection', title, '', value, record_ts, extra))
    return records


def _parse_logged_on_users(run_dir, ts):
    sessions = _load_json(run_dir, 'logged_on_users.json')
    if not isinstance(sessions, list):
        return []
    records = []
    for s in sessions:
        if not isinstance(s, dict):
            continue
        raw = s.get('raw_line', '')
        records.append(_record('live_collection_logged_on_user', 'Logged-On Session', '', raw, ts, {'raw_line': raw}))
    return records


def _parse_arp_cache(run_dir, ts):
    entries = _load_json(run_dir, 'arp_cache.json')
    if not isinstance(entries, list):
        return []
    records = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        # Two real shapes: Get-NetNeighbor's own snake_case object (see
        # windows_collector.ps1's 2026-09-03 normalization) vs. the legacy
        # `arp -a` text fallback (raw_line/source only).
        if 'ip_address' in e:
            title = _safe_value_text(e.get('ip_address', ''))
            mac = _safe_value_text(e.get('mac_address', ''))
            state = _safe_value_text(e.get('state', ''))
            value = f"{mac} ({state})"
        else:
            title = 'ARP Entry'
            value = _safe_value_text(e.get('raw_line', ''))
        records.append(_record('live_collection_arp_entry', title, '', value, ts, _safe_extra(e)))
    return records


def _parse_dns_cache(run_dir, ts):
    entries = _load_json(run_dir, 'dns_cache.json')
    if not isinstance(entries, list):
        return []
    records = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        # Two real shapes: Get-DnsClientCache's own snake_case object (see
        # windows_collector.ps1's 2026-09-03 normalization) vs. the legacy
        # `ipconfig /displaydns` text fallback (raw_line/source only).
        if 'name' in e:
            title = _safe_value_text(e.get('name', ''))
            data = _safe_value_text(e.get('data', ''))
            rtype = _safe_value_text(e.get('type', ''))
            ttl = _safe_value_text(e.get('ttl', ''))
            value = f"{data} (type {rtype}, TTL {ttl})"
        else:
            title = 'DNS Cache Entry'
            value = _safe_value_text(e.get('raw_line', ''))
        records.append(_record('live_collection_dns_cache_entry', title, '', value, ts, _safe_extra(e)))
    return records


def _parse_services(run_dir, ts):
    services = _load_json(run_dir, 'services.json')
    if not isinstance(services, list):
        return []
    records = []
    for s in services:
        if not isinstance(s, dict):
            continue
        title = s.get('display_name') or s.get('name') or ''
        state = _safe_value_text(s.get('state', ''))
        start_mode = _safe_value_text(s.get('start_mode', ''))
        path = _safe_value_text(s.get('path', ''))
        value = f"{state} ({start_mode}) - {path}"
        records.append(_record('live_collection_service', title, '', value, ts, _safe_extra(s)))
    return records


def _parse_scheduled_tasks(run_dir, ts):
    tasks = _load_json(run_dir, 'scheduled_tasks.json')
    if not isinstance(tasks, list):
        return []
    records = []
    for t in tasks:
        if not isinstance(t, dict):
            continue
        # Two real shapes: Get-ScheduledTask's own object (task_name/
        # task_path/state/actions) vs. the schtasks.exe CSV fallback
        # (whatever headers that tool emits - not independently confirmed,
        # so this branch degrades gracefully to whatever keys are present
        # rather than assuming task_name exists).
        title = t.get('task_name') or t.get('TaskName') or next(iter(t.values()), '') or ''
        record_ts = ts
        if 'task_name' in t:
            state = _safe_value_text(t.get('state', ''))
            actions = _safe_value_text(t.get('actions', ''))
            # Real "when did this task last actually run" data
            # (2026-09-03) - only present on the Get-ScheduledTask branch
            # (the schtasks.exe CSV fallback below has no equivalent
            # field). See _parse_plausible_historical_epoch()'s own
            # docstring for why a sentinel "never run" date is rejected
            # rather than trusted as a real historical timestamp.
            last_run = _parse_plausible_historical_epoch(t.get('last_run_time'))
            last_run_display = _safe_value_text(t.get('last_run_time')) if last_run is not None else 'never run'
            value = f"{state} - {actions} (last run: {last_run_display})"
            if last_run is not None:
                record_ts = last_run
        else:
            value = json.dumps(t, default=str)[:500]
        records.append(_record('live_collection_scheduled_task', str(title), '', value, record_ts, _safe_extra(t)))
    return records


def _parse_live_powershell_history(run_dir, ts):
    """Reuses core/powershell_history_utils.py's existing PSReadLine
    parser UNCHANGED against real *_history.txt files the collector
    copied live off the target (see windows_collector.ps1's own
    PowerShell console history collection step, 2026-09-03) - the same
    "collect the real file, reuse the already-built parser" approach as
    Prefetch below. Imported at module level here (unlike Prefetch),
    since that module has zero optional/native dependencies - pure
    stdlib, same as this one.

    Unlike an acquired-file parse (where every record's own timestamp is
    honestly None - PSReadLine's file format has no per-command
    timestamp at all, see that module's own docstring), a LIVE
    collection record is deliberately stamped with the run's own capture
    time instead: "this command history existed on the machine at the
    moment of this collection" is itself a real, useful fact for a live-
    collection context, genuinely distinct from "we don't know when this
    ran" (which stays true either way - this doesn't fabricate per-
    command precision that doesn't exist, it just anchors the whole file
    to when it was captured, matching every other no-natural-timestamp
    category in this module, e.g. services/loaded_drivers)."""
    from core.powershell_history_utils import find_powershell_history_files, parse_powershell_history_file
    paths, _truncated = find_powershell_history_files(run_dir)
    records = []
    for path in paths:
        for r in parse_powershell_history_file(path):
            r['timestamp'] = ts
            records.append(r)
    return records


def _parse_live_prefetch(run_dir, ts):
    """Prefetch (.pf) files the collector could copy live (admin-only -
    see windows_collector.ps1's own privilege-gated collection step,
    2026-09-03). Reuses core/prefetch_utils.py's existing parser
    UNCHANGED - deliberately imported HERE, inside the function, not at
    this module's own top level. core/prefetch_utils.py needs pyscca, a
    native, POSIX-only dependency this app already treats as optional
    build-time-only elsewhere (routes/file_explorer.py/routes/
    image_browser.py both already import it unconditionally, but those
    two are already gated behind core.jobs' own POSIX-only pwd/fcntl
    requirement in every test that touches them). This module is
    otherwise pure stdlib and deliberately stays importable on ANY
    machine, including this project's own Windows dev environment - a
    module-level import here would silently break that property. `ts`
    is unused (each .pf file already carries its own real last-run
    timestamp from parse_prefetch_file() itself) - kept for signature
    consistency with every other _parse_* function in this module."""
    prefetch_dir = os.path.join(run_dir, 'prefetch')
    if not os.path.isdir(prefetch_dir):
        return []
    try:
        from core.prefetch_utils import find_prefetch_files, parse_prefetch_file
    except ImportError:
        return []
    paths, _truncated = find_prefetch_files(prefetch_dir)
    records = []
    for path in paths:
        records.extend(parse_prefetch_file(path))
    return records


def _parse_live_evtx(run_dir, ts):
    """Windows Event Log excerpts (logon/logoff, workstation lock/unlock,
    service state changes, audit-log-cleared) the collector exported live
    as real, filtered .evtx snapshot files - see windows_collector.ps1's
    own Event Log collection step, 2026-09-03. Reuses core/evtx_utils.py's
    existing find_evtx_files()/parse_evtx_file() UNCHANGED, same "collect
    the real format, reuse the already-built parser" approach as Prefetch
    above - including that module's own real per-event timestamps (each
    .evtx record genuinely carries one, unlike PSReadLine's format, which
    has none at all - `ts` is unused here for the identical reason it's
    unused in _parse_live_prefetch). Deliberately imported HERE, not at
    this module's own top level - core/evtx_utils.py needs python-evtx, a
    genuinely optional pip dependency (confirmed not installed on this
    project's own Windows dev environment, matching the same reasoning
    already documented for pyscca/core.prefetch_utils above)."""
    evtx_dir = os.path.join(run_dir, 'evtx')
    if not os.path.isdir(evtx_dir):
        return []
    try:
        from core.evtx_utils import find_evtx_files, parse_evtx_file
    except ImportError:
        return []
    paths, _truncated = find_evtx_files(evtx_dir)
    records = []
    for path in paths:
        records.extend(parse_evtx_file(path))
    return records


def _parse_live_registry(run_dir, ts):
    """Real registry hive exports the collector pulled live from a
    running Windows system - RecentDocs, TypedPaths, RunMRU, UserAssist,
    RDP connections, Office MRU, WordWheelQuery, USB device history,
    Shimcache, BAM/DAM, installed programs, Amcache, and ShellBags - see
    windows_collector.ps1's own registry pattern-of-life collection step
    (2026-09-03, admin-only). Reuses core/registry_utils.py's existing
    find_registry_hive_files()/parse_registry_hive_file() UNCHANGED, same
    "collect the real file, reuse the already-built parser" approach as
    Prefetch/Event Logs above - including that module's own real
    per-value/per-key timestamps (`ts` is unused here for the identical
    reason it's unused in _parse_live_prefetch/_parse_live_evtx).
    Deliberately imported HERE, not at this module's own top level -
    core/registry_utils.py needs python-registry, a genuinely optional
    pip dependency, matching the same reasoning already documented for
    pyscca/python-evtx above.

    The collector may write more than one real user's hives, each into
    its own <username>\\ subfolder (so two different users' identically-
    named NTUSER.DAT files never collide on disk - see the collector
    script's own docstring). find_registry_hive_files() already walks
    the whole run directory recursively by exact basename regardless of
    nesting, so this needs no per-user bookkeeping of its own at all,
    unlike the PSReadLine parser above (which does have to track which
    username each history file came from)."""
    registry_dir = os.path.join(run_dir, 'registry')
    if not os.path.isdir(registry_dir):
        return []
    try:
        from core.registry_utils import find_registry_hive_files, parse_registry_hive_file
    except ImportError:
        return []
    paths, _truncated = find_registry_hive_files(registry_dir)
    records = []
    for path in paths:
        records.extend(parse_registry_hive_file(path, os.path.basename(path)))
    return records


def _parse_autoruns(run_dir, ts):
    autoruns = _load_json(run_dir, 'autoruns.json')
    if not isinstance(autoruns, list):
        return []
    records = []
    for a in autoruns:
        if not isinstance(a, dict):
            continue
        title = a.get('name', '')
        raw_value = _safe_value_text(a.get('value', ''))
        source = _safe_value_text(a.get('source', ''))
        value = f"{raw_value} ({source})"
        records.append(_record('live_collection_autorun', title, '', value, ts, _safe_extra(a)))
    return records


def _parse_installed_hotfixes(run_dir, ts):
    hotfixes = _load_json(run_dir, 'installed_hotfixes.json')
    if not isinstance(hotfixes, list):
        return []
    records = []
    for h in hotfixes:
        if not isinstance(h, dict):
            continue
        title = _safe_value_text(h.get('hotfix_id', ''))
        value = _safe_value_text(h.get('description', ''))
        # Real "when was this patch applied" data - genuinely historical,
        # not collection-time metadata (2026-09-03). installed_on is
        # legitimately null for some real hotfix entries, so this falls
        # back to the run's own capture time rather than guessing.
        record_ts = _parse_iso_datetime_epoch(h.get('installed_on')) or ts
        records.append(_record('live_collection_installed_hotfix', title, '', value, record_ts, _safe_extra(h)))
    return records


def _parse_loaded_drivers(run_dir, ts):
    drivers = _load_json(run_dir, 'loaded_drivers.json')
    if not isinstance(drivers, list):
        return []
    records = []
    for d in drivers:
        if not isinstance(d, dict):
            continue
        title = d.get('display_name') or d.get('name') or ''
        state = _safe_value_text(d.get('state', ''))
        path = _safe_value_text(d.get('path_name', ''))
        value = f"{state} - {path}"
        # No per-driver "loaded at" time is available via Win32_SystemDriver
        # - a real OS limitation, not a collector gap - so every record
        # here is stamped with the run's own capture time.
        records.append(_record('live_collection_loaded_driver', str(title), '', value, ts, _safe_extra(d)))
    return records


def _parse_mapped_drives(run_dir, ts):
    drives = _load_json(run_dir, 'mapped_drives.json')
    if not isinstance(drives, list):
        return []
    records = []
    for d in drives:
        if not isinstance(d, dict):
            continue
        title = d.get('local_path', '')
        remote_path = _safe_value_text(d.get('remote_path', ''))
        status = _safe_value_text(d.get('status', ''))
        value = f"{remote_path} ({status})"
        records.append(_record('live_collection_mapped_drive', title, '', value, ts, _safe_extra(d)))
    return records


def _parse_windows_clipboard(run_dir, ts):
    data = _load_json(run_dir, 'clipboard.json')
    if not isinstance(data, dict) or not data.get('content'):
        return []
    content = data['content']
    value = content if len(content) <= 500 else content[:500] + '...'
    return [_record('live_collection_clipboard', 'Clipboard Contents', '', value, ts, {'content': content})]


_WINDOWS_PARSERS = (
    ('system_info', _parse_system_info),
    ('processes', _parse_processes), ('network_connections', _parse_network_connections),
    ('logged_on_users', _parse_logged_on_users),
    ('arp_cache', _parse_arp_cache), ('dns_cache', _parse_dns_cache),
    ('services', _parse_services),
    ('scheduled_tasks', _parse_scheduled_tasks), ('autoruns', _parse_autoruns),
    ('installed_hotfixes', _parse_installed_hotfixes), ('loaded_drivers', _parse_loaded_drivers),
    ('powershell_history', _parse_live_powershell_history), ('prefetch', _parse_live_prefetch),
    ('evtx', _parse_live_evtx), ('registry', _parse_live_registry),
    ('mapped_drives', _parse_mapped_drives), ('clipboard', _parse_windows_clipboard),
)


def parse_windows_collector_run(run_dir, run_timestamp):
    """Parses every known category file inside a completed Windows
    collector run directory into the app's standard record shape. Skips
    categories the collector's own _collection_log.json already logged as
    failed/skipped; any category whose file still fails to parse is
    swallowed silently (matches every other artifact parser in this app's
    own outer-try/except tolerance) rather than aborting the whole run.
    run_timestamp is a Unix epoch float applied to every record - see this
    module's own docstring for why a per-run, not per-record, timestamp."""
    skipped = _skipped_categories(run_dir)
    records = []
    for category, parser_fn in _WINDOWS_PARSERS:
        if category in skipped:
            continue
        try:
            records.extend(parser_fn(run_dir, run_timestamp))
        except Exception:
            continue
    return records


# --- Unix side (deliberately narrow - see module docstring) ---

def parse_unix_collector_run(run_dir, run_timestamp):
    """Deliberately scoped to just the clipboard.txt supplemental file
    run_collector.sh writes alongside UAC's own output - see this module's
    own docstring for why UAC's own raw per-command text output isn't
    individually parsed here. clipboard.txt is a single plain-text blob (no
    structured shape to gain from JSON), matching the launcher's own "plain
    shell, read it before running it" simplicity."""
    path = os.path.join(run_dir, 'clipboard.txt')
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return []
    if not content.strip():
        return []
    value = content if len(content) <= 500 else content[:500] + '...'
    return [_record('live_collection_clipboard', 'Clipboard Contents', '', value, run_timestamp, {'content': content})]


# --- Hash-list cross-referencing (shared by both platforms) ---

def build_hash_list_match_records(process_records, hash_sets, run_timestamp):
    """Cross-references every unique process executable hash already
    present in process_records' own extra['sha256'] field (populated by
    _parse_processes()'s join against process_hashes.json - a Unix-side
    process parser, if one is ever added, would need to populate the same
    field for this to apply there too) against every currently-configured
    hash list, mirroring the already-established "check every configured
    list automatically, no examiner selection needed" precedent
    (routes/file_explorer.py's browser-artifact URL-list check). hash_sets
    is the already-loaded {list_id: {name, label, algorithm, hashes}} dict
    from core.config.load_hash_list_sets() - this function stays a pure,
    Flask-independent transform so it's cheaply unit-testable. Returns one
    live_collection_hash_list_match record per (executable, matching list)
    pair - a hash matching two different lists produces two records, same
    as every other hash-set-match feature in this app."""
    seen_paths = set()
    matches = []
    for rec in process_records:
        if rec.get('artifact_type') != 'live_collection_process':
            continue
        extra = rec.get('extra') or {}
        digest = extra.get('sha256')
        exe_path = extra.get('executable_path')
        if not digest or not exe_path or exe_path in seen_paths:
            continue
        seen_paths.add(exe_path)
        digest_lower = digest.lower()
        for list_id, s in hash_sets.items():
            if s.get('algorithm') != 'sha256':
                continue
            if digest_lower in s.get('hashes', set()):
                value = f"Matched hash list: {s.get('label') or s.get('name')}"
                extra_match = {
                    'executable_path': exe_path, 'sha256': digest,
                    'matched_list_id': list_id, 'matched_list_name': s.get('name'),
                    'matched_list_label': s.get('label'),
                }
                matches.append(_record('live_collection_hash_list_match', exe_path, '', value, run_timestamp, extra_match))
    return matches
