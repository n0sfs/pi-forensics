"""core/live_collection_results_utils.py - Live Collection USB results
parsing (Phase 2 of the feature). Fixture JSON files are hand-built to
exactly match windows_collector.ps1's own real, confirmed-by-direct-read
output shapes (see that script and this module's own docstrings) - not
opaque blobs, so a reviewer can see exactly what each test asserts against.
No optional pip dependency here (pure stdlib json/os), unlike registry_
utils.py's python-registry requirement - no importorskip guard needed.
"""
import json
import os

import core.live_collection_results_utils as lcru


def _write_json(run_dir, filename, data):
    with open(os.path.join(run_dir, filename), 'w', encoding='utf-8') as f:
        json.dump(data, f)


# --- find_windows_collector_result_files ---

def test_find_windows_collector_result_files_filters_to_known_names(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_json(str(run_dir), "processes.json", [])
    _write_json(str(run_dir), "not_a_real_category.json", [])
    (run_dir / "README.txt").write_text("hello")
    found = lcru.find_windows_collector_result_files(str(run_dir))
    assert found == {"processes.json"}


def test_find_windows_collector_result_files_missing_dir_returns_empty():
    assert lcru.find_windows_collector_result_files("/does/not/exist") == set()


# --- parse_windows_collector_run: the full realistic fixture ---

def _build_full_fixture(run_dir):
    _write_json(run_dir, "_collection_log.json", [
        {"category": "processes", "status": "ok", "detail": "", "timestamp": "2026-08-31T00:00:00Z"},
        {"category": "loaded_drivers", "status": "skipped", "detail": "requires administrator privileges", "timestamp": "x"},
    ])
    _write_json(run_dir, "processes.json", [
        {"pid": 100, "parent_pid": 4, "name": "svchost.exe", "executable_path": "C:\\Windows\\System32\\svchost.exe",
         "command_line": "svchost.exe -k netsvcs", "creation_date": "2026-08-31T10:00:00", "owner": "SYSTEM"},
        {"pid": 200, "parent_pid": 100, "name": "evil.exe", "executable_path": "C:\\Temp\\evil.exe",
         "command_line": "evil.exe --beacon", "creation_date": "2026-08-31T10:05:00", "owner": "user1"},
    ])
    _write_json(run_dir, "process_hashes.json", [
        {"executable_path": "C:\\Windows\\System32\\svchost.exe", "sha256": "aaaa" * 16},
        {"executable_path": "C:\\Temp\\evil.exe", "sha256": "BBBB" * 16},
    ])
    _write_json(run_dir, "network_connections.json", [
        {"protocol": "TCP", "local_address": "10.0.0.5", "local_port": 49152,
         "remote_address": "203.0.113.9", "remote_port": 443, "state": "Established", "owning_pid": 200},
        {"protocol": "TCP", "local": "127.0.0.1:5000", "remote": "0.0.0.0:0", "state": "LISTENING",
         "owning_pid": 999, "source": "netstat (legacy fallback)"},
    ])
    _write_json(run_dir, "logged_on_users.json", [{"raw_line": "user1  console  1  Active  none  8/31/2026 9:00 AM"}])
    _write_json(run_dir, "services.json", [
        {"name": "wuauserv", "display_name": "Windows Update", "state": "Running",
         "start_mode": "Auto", "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "start_name": "LocalSystem"},
    ])
    _write_json(run_dir, "scheduled_tasks.json", [
        {"task_name": "\\Microsoft\\Windows\\UpdateCheck", "task_path": "\\Microsoft\\Windows\\",
         "state": "Ready", "actions": "C:\\update.exe "},
    ])
    _write_json(run_dir, "autoruns.json", [
        {"source": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater", "value": "C:\\Temp\\evil.exe --beacon"},
    ])
    _write_json(run_dir, "mapped_drives.json", [
        {"local_path": "Z:", "remote_path": "\\\\fileserver\\share", "status": "OK"},
    ])
    _write_json(run_dir, "clipboard.json", {"content": "some secret pasted text", "collected_at": "2026-08-31T10:00:00Z"})
    # loaded_drivers.json deliberately absent - matches its own _collection_log.json 'skipped' status


def test_parse_windows_collector_run_full_fixture(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _build_full_fixture(run_dir)

    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1756598400.0)

    by_type = {}
    for r in records:
        by_type.setdefault(r['artifact_type'], []).append(r)

    assert len(by_type['live_collection_process']) == 2
    assert len(by_type['live_collection_network_connection']) == 2
    assert len(by_type['live_collection_logged_on_user']) == 1
    assert len(by_type['live_collection_service']) == 1
    assert len(by_type['live_collection_scheduled_task']) == 1
    assert len(by_type['live_collection_autorun']) == 1
    assert len(by_type['live_collection_mapped_drive']) == 1
    assert len(by_type['live_collection_clipboard']) == 1

    # The process/hash join worked, joined by executable_path, case preserved as stored
    evil = next(r for r in by_type['live_collection_process'] if r['title'] == 'evil.exe')
    assert evil['extra']['sha256'] == 'BBBB' * 16
    assert evil['extra']['pid'] == 200
    assert 'evil.exe --beacon' in evil['value']

    # Every record from this run carries the exact same run_timestamp
    assert all(r['timestamp'] == 1756598400.0 for r in records)

    # Two real network-connection shapes both parsed correctly
    conn_titles = {r['title'] for r in by_type['live_collection_network_connection']}
    assert 'TCP 10.0.0.5:49152 -> 203.0.113.9:443' in conn_titles
    assert 'TCP 127.0.0.1:5000 -> 0.0.0.0:0' in conn_titles


def test_loaded_drivers_skipped_per_collection_log(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _build_full_fixture(run_dir)
    # No loaded_drivers.json file exists at all (matches the real skip case) -
    # confirm this doesn't appear as any artifact_type and doesn't error.
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert not any('driver' in r['artifact_type'] for r in records)


# --- Malformed-input tolerance ---

def test_missing_process_hashes_file_does_not_raise(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "processes.json", [
        {"pid": 1, "parent_pid": 0, "name": "init", "executable_path": "/sbin/init",
         "command_line": "", "creation_date": "", "owner": ""},
    ])
    # process_hashes.json deliberately not written at all
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    procs = [r for r in records if r['artifact_type'] == 'live_collection_process']
    assert len(procs) == 1
    assert procs[0]['extra']['sha256'] is None


def test_empty_process_hashes_array_does_not_raise(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "processes.json", [{"pid": 1, "parent_pid": 0, "name": "x",
                                              "executable_path": "/x", "command_line": "", "creation_date": "", "owner": ""}])
    _write_json(run_dir, "process_hashes.json", [])
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert records[0]['extra']['sha256'] is None


def test_truncated_json_file_is_skipped_not_raised(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    with open(os.path.join(run_dir, "processes.json"), 'w') as f:
        f.write('[{"pid": 1, "name": "trunc')  # deliberately truncated, invalid JSON
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert records == []


def test_unexpected_top_level_shape_is_skipped_not_raised(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "processes.json", {"this": "should have been an array"})
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert records == []


def test_empty_file_is_skipped_not_raised(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    open(os.path.join(run_dir, "processes.json"), 'w').close()
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert records == []


def test_missing_run_directory_returns_empty_not_raise():
    records = lcru.parse_windows_collector_run("/does/not/exist", run_timestamp=1.0)
    assert records == []


def test_clipboard_json_missing_content_key_is_skipped(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "clipboard.json", {"collected_at": "2026-08-31T00:00:00Z"})  # no content
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert records == []


# --- Unix side (clipboard-only) ---

def test_parse_unix_collector_run_reads_clipboard_txt(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    with open(os.path.join(run_dir, "clipboard.txt"), 'w', encoding='utf-8') as f:
        f.write("pasted shell secret")
    records = lcru.parse_unix_collector_run(run_dir, run_timestamp=42.0)
    assert len(records) == 1
    assert records[0]['artifact_type'] == 'live_collection_clipboard'
    assert records[0]['timestamp'] == 42.0
    assert records[0]['extra']['content'] == 'pasted shell secret'


def test_parse_unix_collector_run_no_clipboard_file(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru.parse_unix_collector_run(run_dir, run_timestamp=1.0) == []


def test_parse_unix_collector_run_empty_clipboard_file(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    open(os.path.join(run_dir, "clipboard.txt"), 'w').close()
    assert lcru.parse_unix_collector_run(run_dir, run_timestamp=1.0) == []


def test_clipboard_content_over_500_chars_is_truncated_for_display(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    long_content = "x" * 600
    _write_json(run_dir, "clipboard.json", {"content": long_content, "collected_at": "2026-08-31T00:00:00Z"})
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    assert len(records) == 1
    rec = records[0]
    assert rec['value'].endswith('...')
    assert len(rec['value']) == 503
    assert rec['extra']['content'] == long_content  # full content preserved in extra, only display value truncated


def test_unix_clipboard_content_over_500_chars_is_truncated_for_display(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    long_content = "y" * 600
    with open(os.path.join(run_dir, "clipboard.txt"), 'w', encoding='utf-8') as f:
        f.write(long_content)
    records = lcru.parse_unix_collector_run(run_dir, run_timestamp=1.0)
    assert len(records) == 1
    assert records[0]['value'].endswith('...')
    assert records[0]['extra']['content'] == long_content


# --- Hash-list cross-referencing ---

def _fake_hash_sets():
    return {
        'bad_list_1': {'name': 'Known Malware', 'label': 'known_bad', 'algorithm': 'sha256',
                        'hashes': {('bbbb' * 16)}},  # already lowercased, matching load_hash_list_sets()'s own convention
        'good_list_1': {'name': 'Known Good OS Files', 'label': 'known_good', 'algorithm': 'sha256',
                         'hashes': {('aaaa' * 16)}},
    }


def test_hash_list_cross_reference_finds_a_real_match(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _build_full_fixture(run_dir)
    records = lcru.parse_windows_collector_run(run_dir, run_timestamp=1.0)
    process_records = [r for r in records if r['artifact_type'] == 'live_collection_process']

    matches = lcru.build_hash_list_match_records(process_records, _fake_hash_sets(), run_timestamp=1.0)

    assert len(matches) == 2  # evil.exe matches bad_list_1, svchost.exe matches good_list_1
    matched_paths = {m['extra']['executable_path'] for m in matches}
    assert matched_paths == {"C:\\Temp\\evil.exe", "C:\\Windows\\System32\\svchost.exe"}
    evil_match = next(m for m in matches if m['extra']['executable_path'] == "C:\\Temp\\evil.exe")
    assert evil_match['extra']['matched_list_id'] == 'bad_list_1'
    assert evil_match['artifact_type'] == 'live_collection_hash_list_match'


def test_hash_list_cross_reference_no_match_produces_nothing():
    process_records = [{
        'artifact_type': 'live_collection_process', 'title': 'clean.exe', 'url': '', 'value': '', 'timestamp': 1.0,
        'extra': {'executable_path': 'C:\\clean.exe', 'sha256': 'ffff' * 16},
    }]
    matches = lcru.build_hash_list_match_records(process_records, _fake_hash_sets(), run_timestamp=1.0)
    assert matches == []


def test_hash_list_cross_reference_deduplicates_repeated_executable_path():
    # Two different processes running the same binary shouldn't produce two match records
    process_records = [
        {'artifact_type': 'live_collection_process', 'title': 'a', 'url': '', 'value': '', 'timestamp': 1.0,
         'extra': {'executable_path': 'C:\\evil.exe', 'sha256': 'bbbb' * 16}},
        {'artifact_type': 'live_collection_process', 'title': 'b', 'url': '', 'value': '', 'timestamp': 1.0,
         'extra': {'executable_path': 'C:\\evil.exe', 'sha256': 'bbbb' * 16}},
    ]
    matches = lcru.build_hash_list_match_records(process_records, _fake_hash_sets(), run_timestamp=1.0)
    assert len(matches) == 1


def test_hash_list_cross_reference_no_hash_sets_configured():
    process_records = [{
        'artifact_type': 'live_collection_process', 'title': 'a', 'url': '', 'value': '', 'timestamp': 1.0,
        'extra': {'executable_path': 'C:\\a.exe', 'sha256': 'bbbb' * 16},
    }]
    assert lcru.build_hash_list_match_records(process_records, {}, run_timestamp=1.0) == []


def test_hash_list_cross_reference_ignores_non_process_records():
    non_process = [{'artifact_type': 'live_collection_service', 'title': 'x', 'url': '', 'value': '', 'timestamp': 1.0, 'extra': {}}]
    assert lcru.build_hash_list_match_records(non_process, _fake_hash_sets(), run_timestamp=1.0) == []


def test_hash_list_cross_reference_missing_sha256_is_skipped():
    process_records = [{
        'artifact_type': 'live_collection_process', 'title': 'a', 'url': '', 'value': '', 'timestamp': 1.0,
        'extra': {'executable_path': 'C:\\a.exe', 'sha256': None},
    }]
    assert lcru.build_hash_list_match_records(process_records, _fake_hash_sets(), run_timestamp=1.0) == []


# --- _safe_value_text / _safe_extra: the 2026-09-03 real-world bug fix ---
#
# Found live, not hypothetical: a genuine windows_collector.ps1 run (before
# that script's own PSDrive metadata-leak fix landed) produced one
# autoruns.json entry whose "value" field was a deeply-nested PSDriveInfo
# object instead of a plain string. The old code's bare f-string
# interpolation (`f"{a.get('value', '')} (...)"`) implicitly called str()
# on it with no cap at all, producing a single ~4MB field that hung both a
# direct API client and the real File Explorer UI trying to render it -
# reproduced here with a much smaller (but still non-scalar) stand-in,
# since the point is proving the *shape* of leak is handled, not
# replicating the exact byte count.

def test_safe_value_text_passes_short_scalars_through_unchanged():
    assert lcru._safe_value_text("C:\\Windows\\System32\\evil.exe") == "C:\\Windows\\System32\\evil.exe"
    assert lcru._safe_value_text(42) == "42"
    assert lcru._safe_value_text(None) == ""


def test_safe_value_text_caps_a_long_string():
    text = lcru._safe_value_text("A" * 1000)
    assert len(text) < 1000
    assert text.startswith("A" * 500)
    assert "500 more character(s) omitted" in text


def test_safe_value_text_never_str_ifies_a_nested_object_whole():
    # This is the exact shape of the real leaked PSDriveInfo object -
    # nested dicts/lists, not a plain scalar.
    leaked = {"Credential": {"Password": None, "UserName": None}, "Provider": {"Drives": ["HKLM", "HKCU"]}}
    text = lcru._safe_value_text(leaked)
    assert "Credential" not in text  # never dumped the real nested content
    assert "unexpected object value with 2 field(s)" in text
    assert len(text) < 200  # a short, bounded placeholder, not a multi-KB/MB dump


def test_safe_value_text_handles_a_leaked_list_too():
    text = lcru._safe_value_text(["HKLM", "HKCU"])
    assert "unexpected list value with 2 field(s)" in text


def test_safe_extra_leaves_plain_scalars_untouched():
    raw = {"pid": 100, "name": "svchost.exe", "path": None}
    assert lcru._safe_extra(raw) == raw


def test_safe_extra_replaces_a_nested_value_with_a_bounded_placeholder():
    raw = {"name": "PSDrive", "value": {"Provider": {"Drives": ["HKLM", "HKCU"]}}}
    safe = lcru._safe_extra(raw)
    assert safe["name"] == "PSDrive"
    assert isinstance(safe["value"], str)
    assert "unexpected object value" in safe["value"]
    assert "Drives" not in safe["value"]


def test_safe_extra_non_dict_input_returns_empty_dict():
    assert lcru._safe_extra("not a dict") == {}
    assert lcru._safe_extra(None) == {}


def test_parse_autoruns_survives_a_real_powershell_object_leak(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "autoruns.json", [
        {"source": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater",
         "value": "C:\\Temp\\evil.exe --beacon"},
        # The real leaked shape: PowerShell's Get-ItemProperty synthetic
        # PSDrive property, slipping through as its own spurious "autorun"
        # entry because the collector's old metadata filter regex missed it.
        {"source": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "PSDrive",
         "value": {"Credential": {"Password": None, "UserName": None},
                    "Provider": {"Drives": ["HKLM", "HKCU"], "Name": "Registry"}}},
    ])

    records = lcru._parse_autoruns(run_dir, ts=1756598400.0)

    assert len(records) == 2
    clean = next(r for r in records if r['title'] == 'Updater')
    assert 'evil.exe --beacon' in clean['value']

    leaked = next(r for r in records if r['title'] == 'PSDrive')
    # The record still exists (not silently dropped) but never carries the
    # raw nested object anywhere - not in `value`, not in `extra`.
    assert len(leaked['value']) < 200
    assert 'Credential' not in leaked['value']
    assert 'Drives' not in leaked['value']
    assert isinstance(leaked['extra']['value'], str)
    assert 'Drives' not in leaked['extra']['value']


def test_parse_services_survives_a_nested_state_field(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "services.json", [
        {"name": "wuauserv", "display_name": "Windows Update",
         "state": {"unexpected": "nested object"}, "start_mode": "Auto", "path": "C:\\svchost.exe"},
    ])
    records = lcru._parse_services(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'unexpected object value' in records[0]['value']
    assert len(records[0]['value']) < 300


def test_parse_network_connections_survives_a_nested_state_field(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "network_connections.json", [
        {"protocol": "TCP", "local_address": "10.0.0.5", "local_port": 1234,
         "state": {"unexpected": "nested object"}},
    ])
    records = lcru._parse_network_connections(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'unexpected object value' in records[0]['value']


def test_parse_mapped_drives_survives_a_nested_status_field(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "mapped_drives.json", [
        {"local_path": "Z:", "remote_path": "\\\\fileserver\\share", "status": {"unexpected": "nested"}},
    ])
    records = lcru._parse_mapped_drives(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'unexpected object value' in records[0]['value']


def test_parse_processes_survives_a_nested_command_line_field(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "processes.json", [
        {"pid": 100, "parent_pid": 4, "name": "svchost.exe",
         "executable_path": "C:\\svchost.exe", "command_line": {"unexpected": "nested"}},
    ])
    records = lcru._parse_processes(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'unexpected object value' in records[0]['value']
    assert isinstance(records[0]['extra']['command_line'], str)


def test_parse_scheduled_tasks_survives_a_nested_actions_field(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "scheduled_tasks.json", [
        {"task_name": "\\Microsoft\\Windows\\UpdateCheck", "state": "Ready",
         "actions": {"unexpected": "nested"}},
    ])
    records = lcru._parse_scheduled_tasks(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'unexpected object value' in records[0]['value']
