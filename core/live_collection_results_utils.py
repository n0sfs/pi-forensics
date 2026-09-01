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
        cmdline = p.get('command_line') or exe_path or ''
        value = f"PID {p.get('pid')} (parent {p.get('parent_pid')}) - {cmdline}"
        extra = {
            'pid': p.get('pid'), 'parent_pid': p.get('parent_pid'),
            'executable_path': exe_path, 'command_line': p.get('command_line'),
            'creation_date': p.get('creation_date'), 'owner': p.get('owner'),
            'sha256': sha256,
        }
        records.append(_record('live_collection_process', p.get('name'), '', value, ts, extra))
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
        value = c.get('state') or ''
        extra = dict(c)
        records.append(_record('live_collection_network_connection', title, '', value, ts, extra))
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


def _parse_services(run_dir, ts):
    services = _load_json(run_dir, 'services.json')
    if not isinstance(services, list):
        return []
    records = []
    for s in services:
        if not isinstance(s, dict):
            continue
        title = s.get('display_name') or s.get('name') or ''
        value = f"{s.get('state', '')} ({s.get('start_mode', '')}) - {s.get('path', '')}"
        records.append(_record('live_collection_service', title, '', value, ts, dict(s)))
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
        value = f"{t.get('state', '')} - {t.get('actions', '')}" if 'task_name' in t else json.dumps(t)[:500]
        records.append(_record('live_collection_scheduled_task', str(title), '', value, ts, dict(t)))
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
        value = f"{a.get('value', '')} ({a.get('source', '')})"
        records.append(_record('live_collection_autorun', title, '', value, ts, dict(a)))
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
        value = f"{d.get('remote_path', '')} ({d.get('status', '')})"
        records.append(_record('live_collection_mapped_drive', title, '', value, ts, dict(d)))
    return records


def _parse_windows_clipboard(run_dir, ts):
    data = _load_json(run_dir, 'clipboard.json')
    if not isinstance(data, dict) or not data.get('content'):
        return []
    content = data['content']
    value = content if len(content) <= 500 else content[:500] + '...'
    return [_record('live_collection_clipboard', 'Clipboard Contents', '', value, ts, {'content': content})]


_WINDOWS_PARSERS = (
    ('processes', _parse_processes), ('network_connections', _parse_network_connections),
    ('logged_on_users', _parse_logged_on_users), ('services', _parse_services),
    ('scheduled_tasks', _parse_scheduled_tasks), ('autoruns', _parse_autoruns),
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
