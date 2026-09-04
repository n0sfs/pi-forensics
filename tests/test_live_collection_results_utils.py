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
import sys
import types

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
    _write_json(run_dir, "system_info.json", {
        "hostname": "DESKTOP-TEST", "os_caption": "Microsoft Windows 11 Pro", "os_version": "10.0.22631",
        "os_build": "22631", "os_architecture": "64-bit", "last_boot_time": "2026-08-30T07:00:00.0000000-04:00",
        "current_time": "2026-08-31T10:00:00.0000000-04:00", "timezone": "Eastern Standard Time",
        "manufacturer": "Dell Inc.", "model": "OptiPlex 7090", "domain": "WORKGROUP", "collected_as_admin": False,
    })
    _write_json(run_dir, "processes.json", [
        # Real windows_collector.ps1 output is always offset-aware via
        # .ToString('o') (see the 2026-09-03 fix) - this fixture matches
        # that exact shape, not a naive/unrealistic one.
        {"pid": 100, "parent_pid": 4, "name": "svchost.exe", "executable_path": "C:\\Windows\\System32\\svchost.exe",
         "command_line": "svchost.exe -k netsvcs", "creation_date": "2026-08-31T10:00:00.0000000-04:00", "owner": "SYSTEM"},
        {"pid": 200, "parent_pid": 100, "name": "evil.exe", "executable_path": "C:\\Temp\\evil.exe",
         "command_line": "evil.exe --beacon", "creation_date": "2026-08-31T10:05:00.0000000-04:00", "owner": "user1"},
    ])
    _write_json(run_dir, "process_hashes.json", [
        {"executable_path": "C:\\Windows\\System32\\svchost.exe", "sha256": "aaaa" * 16},
        {"executable_path": "C:\\Temp\\evil.exe", "sha256": "BBBB" * 16},
    ])
    _write_json(run_dir, "network_connections.json", [
        {"protocol": "TCP", "local_address": "10.0.0.5", "local_port": 49152,
         "remote_address": "203.0.113.9", "remote_port": 443, "state": "Established", "owning_pid": 200,
         "created": "2026-08-31T09:58:00.0000000-04:00"},
        {"protocol": "TCP", "local": "127.0.0.1:5000", "remote": "0.0.0.0:0", "state": "LISTENING",
         "owning_pid": 999, "source": "netstat (legacy fallback)"},
    ])
    _write_json(run_dir, "logged_on_users.json", [{"raw_line": "user1  console  1  Active  none  8/31/2026 9:00 AM"}])
    _write_json(run_dir, "arp_cache.json", [
        {"ip_address": "10.0.0.1", "mac_address": "aa-bb-cc-dd-ee-ff", "state": "Reachable", "interface": "Ethernet"},
    ])
    _write_json(run_dir, "dns_cache.json", [
        {"entry": "example.com", "name": "example.com", "data": "93.184.216.34", "ttl": 300, "type": 1},
    ])
    _write_json(run_dir, "installed_hotfixes.json", [
        {"hotfix_id": "KB5031354", "description": "Security Update", "installed_on": "2026-08-01T00:00:00.0000000-04:00"},
    ])
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

    assert len(by_type['live_collection_system_info']) == 1
    assert len(by_type['live_collection_system_boot']) == 1
    assert len(by_type['live_collection_process']) == 2
    assert len(by_type['live_collection_network_connection']) == 2
    assert len(by_type['live_collection_logged_on_user']) == 1
    assert len(by_type['live_collection_arp_entry']) == 1
    assert len(by_type['live_collection_dns_cache_entry']) == 1
    assert len(by_type['live_collection_service']) == 1
    assert len(by_type['live_collection_scheduled_task']) == 1
    assert len(by_type['live_collection_autorun']) == 1
    assert len(by_type['live_collection_installed_hotfix']) == 1
    assert len(by_type['live_collection_mapped_drive']) == 1
    assert len(by_type['live_collection_clipboard']) == 1

    # The process/hash join worked, joined by executable_path, case preserved as stored
    evil = next(r for r in by_type['live_collection_process'] if r['title'] == 'evil.exe')
    assert evil['extra']['sha256'] == 'BBBB' * 16
    assert evil['extra']['pid'] == 200
    assert 'evil.exe --beacon' in evil['value']

    # Records with a real, offset-aware historical timestamp in the source
    # data now carry THEIR OWN timestamp (2026-09-03), not the run's own
    # capture time - process creation, connection establishment, hotfix
    # install date, and system boot time are all genuinely different
    # instants than 1756598400.0 (the run_timestamp passed in above).
    assert evil['timestamp'] != 1756598400.0
    svchost = next(r for r in by_type['live_collection_process'] if r['title'] == 'svchost.exe')
    assert svchost['timestamp'] != 1756598400.0
    assert svchost['timestamp'] != evil['timestamp']  # each process keeps its OWN creation time
    conn_with_created = next(r for r in by_type['live_collection_network_connection'] if 'Established' in r['value'])
    assert conn_with_created['timestamp'] != 1756598400.0
    assert by_type['live_collection_installed_hotfix'][0]['timestamp'] != 1756598400.0
    assert by_type['live_collection_system_boot'][0]['timestamp'] != 1756598400.0

    # Records with no genuine per-item historical timestamp still fall
    # back to the run's own capture time, exactly as before this feature.
    assert by_type['live_collection_service'][0]['timestamp'] == 1756598400.0
    assert by_type['live_collection_autorun'][0]['timestamp'] == 1756598400.0
    assert by_type['live_collection_system_info'][0]['timestamp'] == 1756598400.0
    netstat_fallback_conn = next(r for r in by_type['live_collection_network_connection'] if 'LISTENING' in r['value'])
    assert netstat_fallback_conn['timestamp'] == 1756598400.0  # legacy shape has no 'created' field at all

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


# --- _parse_iso_datetime_epoch: the 2026-09-03 per-record-timestamp feature ---
#
# windows_collector.ps1 now stamps process creation_date, TCP connection
# created, hotfix installed_on, and system last_boot_time via PowerShell's
# `.ToString('o')` (confirmed live against real PowerShell 5.1/7 output -
# see that script's own comments) so this app can show each record's
# REAL historical timestamp on the Evidence Timeline instead of always
# using the collection run's own capture time.

def test_parse_iso_datetime_epoch_accepts_the_real_powershell_format():
    # Confirmed live: PowerShell's .ToString('o') produces exactly this
    # shape - 7-digit (100ns-tick) fractional seconds, colon-separated offset.
    epoch = lcru._parse_iso_datetime_epoch("2026-09-03T20:13:04.4885418-04:00")
    assert epoch is not None
    assert abs(epoch - 1788480784.488541) < 0.01


def test_parse_iso_datetime_epoch_accepts_a_z_suffix():
    assert lcru._parse_iso_datetime_epoch("2026-09-03T20:13:04.0000000Z") is not None


def test_parse_iso_datetime_epoch_rejects_a_naive_datetime():
    # No offset at all - deliberately NOT accepted, even though it parses
    # fine as a naive datetime, because .timestamp() on a naive datetime
    # would silently assume the ANALYSIS machine's own local timezone -
    # the same class of bug this project already fixed twice this session
    # for a different reason (Registry FILETIME, macOS plist dates).
    assert lcru._parse_iso_datetime_epoch("2026-09-03T20:13:04") is None
    assert lcru._parse_iso_datetime_epoch("2026-09-03T20:13:04.0000000") is None


def test_parse_iso_datetime_epoch_rejects_garbage():
    assert lcru._parse_iso_datetime_epoch("not a date") is None
    assert lcru._parse_iso_datetime_epoch("") is None
    assert lcru._parse_iso_datetime_epoch(None) is None
    assert lcru._parse_iso_datetime_epoch(12345) is None  # non-string input


def test_parse_processes_falls_back_to_run_ts_when_creation_date_is_missing(tmp_path):
    # A real, common case, not hypothetical - System Idle Process (PID 0)
    # genuinely has no CreationDate in WMI.
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "processes.json", [
        {"pid": 0, "parent_pid": 0, "name": "System Idle Process", "executable_path": None,
         "command_line": None, "creation_date": None, "owner": None},
    ])
    records = lcru._parse_processes(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] == 1756598400.0


def test_parse_network_connections_falls_back_to_run_ts_when_created_is_missing(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "network_connections.json", [
        {"protocol": "UDP", "local_address": "0.0.0.0", "local_port": 5353, "owning_pid": 500},
    ])
    records = lcru._parse_network_connections(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] == 1756598400.0


# --- _parse_system_info ---

def test_parse_system_info_emits_a_summary_and_a_boot_record(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    # Boot time is deliberately earlier than the run's own ts (below) - both
    # computed for real via _parse_iso_datetime_epoch itself, not hand-typed
    # epoch guesses, so this test can't drift from real datetime math again.
    boot_iso = "2026-08-30T07:00:00.0000000-04:00"
    run_ts = lcru._parse_iso_datetime_epoch("2026-08-31T10:00:00.0000000-04:00")
    _write_json(run_dir, "system_info.json", {
        "hostname": "DESKTOP-TEST", "os_caption": "Microsoft Windows 11 Pro", "os_build": "22631",
        "os_architecture": "64-bit", "last_boot_time": boot_iso,
        "current_time": "2026-08-31T10:00:00.0000000-04:00", "timezone": "Eastern Standard Time",
    })
    records = lcru._parse_system_info(run_dir, ts=run_ts)
    assert len(records) == 2

    info = next(r for r in records if r['artifact_type'] == 'live_collection_system_info')
    assert info['title'] == 'DESKTOP-TEST'
    assert 'Windows 11 Pro' in info['value']
    assert info['timestamp'] == run_ts  # this one IS collection metadata

    boot = next(r for r in records if r['artifact_type'] == 'live_collection_system_boot')
    assert 'DESKTOP-TEST' in boot['title']
    assert boot['timestamp'] == lcru._parse_iso_datetime_epoch(boot_iso)
    assert boot['timestamp'] < info['timestamp']  # boot genuinely happened before collection


def test_parse_system_info_no_boot_record_when_last_boot_time_missing(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "system_info.json", {"hostname": "DESKTOP-TEST", "os_caption": "Windows 10"})
    records = lcru._parse_system_info(run_dir, ts=1.0)
    assert len(records) == 1
    assert records[0]['artifact_type'] == 'live_collection_system_info'


def test_parse_system_info_non_dict_or_missing_returns_empty(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru._parse_system_info(run_dir, ts=1.0) == []  # file missing entirely
    _write_json(run_dir, "system_info.json", ["not", "a", "dict"])
    assert lcru._parse_system_info(run_dir, ts=1.0) == []


# --- _parse_arp_cache ---

def test_parse_arp_cache_modern_shape(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "arp_cache.json", [
        {"ip_address": "10.0.0.1", "mac_address": "aa-bb-cc-dd-ee-ff", "state": "Reachable", "interface": "Ethernet"},
    ])
    records = lcru._parse_arp_cache(run_dir, ts=1.0)
    assert len(records) == 1
    assert records[0]['title'] == '10.0.0.1'
    assert 'aa-bb-cc-dd-ee-ff' in records[0]['value']
    assert 'Reachable' in records[0]['value']


def test_parse_arp_cache_legacy_shape(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "arp_cache.json", [
        {"raw_line": "  10.0.0.1             aa-bb-cc-dd-ee-ff     dynamic", "source": "arp -a (legacy fallback)"},
    ])
    records = lcru._parse_arp_cache(run_dir, ts=1.0)
    assert len(records) == 1
    assert '10.0.0.1' in records[0]['value']


def test_parse_arp_cache_missing_file_returns_empty(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru._parse_arp_cache(run_dir, ts=1.0) == []


# --- _parse_dns_cache ---

def test_parse_dns_cache_modern_shape(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "dns_cache.json", [
        {"entry": "example.com", "name": "example.com", "data": "93.184.216.34", "ttl": 300, "type": 1},
    ])
    records = lcru._parse_dns_cache(run_dir, ts=1.0)
    assert len(records) == 1
    assert records[0]['title'] == 'example.com'
    assert '93.184.216.34' in records[0]['value']


def test_parse_dns_cache_legacy_shape(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "dns_cache.json", [
        {"raw_line": "example.com. -------- A -------- 93.184.216.34", "source": "ipconfig /displaydns (legacy fallback)"},
    ])
    records = lcru._parse_dns_cache(run_dir, ts=1.0)
    assert len(records) == 1
    assert 'example.com' in records[0]['value']


# --- _parse_installed_hotfixes ---

def test_parse_installed_hotfixes_with_real_install_date(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "installed_hotfixes.json", [
        {"hotfix_id": "KB5031354", "description": "Security Update", "installed_on": "2026-08-01T00:00:00.0000000-04:00"},
    ])
    records = lcru._parse_installed_hotfixes(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['title'] == 'KB5031354'
    assert records[0]['timestamp'] != 1756598400.0  # a real, distinct historical event


def test_parse_installed_hotfixes_falls_back_when_installed_on_missing(tmp_path):
    # A real, documented quirk of Get-HotFix, not hypothetical - some
    # entries genuinely have no InstalledOn.
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "installed_hotfixes.json", [
        {"hotfix_id": "KB0000000", "description": "Unknown", "installed_on": None},
    ])
    records = lcru._parse_installed_hotfixes(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] == 1756598400.0


# --- _parse_loaded_drivers ---

def test_parse_loaded_drivers(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "loaded_drivers.json", [
        {"name": "acpi", "display_name": "Microsoft ACPI Driver", "state": "Running",
         "path_name": "\\SystemRoot\\System32\\drivers\\acpi.sys"},
    ])
    records = lcru._parse_loaded_drivers(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['title'] == 'Microsoft ACPI Driver'
    assert 'acpi.sys' in records[0]['value']
    assert records[0]['timestamp'] == 1756598400.0  # no per-driver load time exists at the OS level


def test_parse_loaded_drivers_missing_file_returns_empty(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru._parse_loaded_drivers(run_dir, ts=1.0) == []


# --- _parse_plausible_historical_epoch: scheduled-task run history
# (2026-09-03) - real, historical last-run timestamps, but with a real
# sentinel-value risk Get-ScheduledTaskInfo is well-documented to have. ---

def test_parse_plausible_historical_epoch_accepts_a_real_recent_date():
    epoch = lcru._parse_plausible_historical_epoch("2026-09-01T08:00:00.0000000-04:00")
    assert epoch is not None
    assert epoch > 0


def test_parse_plausible_historical_epoch_rejects_the_never_run_sentinel():
    # The real, documented Task Scheduler "no value" sentinel - an
    # implausibly old but perfectly valid-looking ISO date.
    assert lcru._parse_plausible_historical_epoch("1899-12-30T00:00:00.0000000-05:00") is None
    assert lcru._parse_plausible_historical_epoch("1601-01-01T00:00:00.0000000Z") is None


def test_parse_plausible_historical_epoch_still_rejects_garbage_and_naive():
    assert lcru._parse_plausible_historical_epoch(None) is None
    assert lcru._parse_plausible_historical_epoch("not a date") is None
    assert lcru._parse_plausible_historical_epoch("2026-09-01T08:00:00") is None  # naive, no offset


# --- _parse_scheduled_tasks: real run-history wiring ---

def test_parse_scheduled_tasks_uses_real_last_run_time(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "scheduled_tasks.json", [
        {"task_name": "\\Microsoft\\Windows\\UpdateCheck", "task_path": "\\Microsoft\\Windows\\",
         "state": "Ready", "actions": "C:\\update.exe ",
         "last_run_time": "2026-08-30T03:00:00.0000000-04:00",
         "next_run_time": "2026-09-04T03:00:00.0000000-04:00", "last_task_result": 0},
    ])
    records = lcru._parse_scheduled_tasks(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] != 1756598400.0
    assert '2026-08-30T03:00:00.0000000-04:00' in records[0]['value']


def test_parse_scheduled_tasks_never_run_falls_back_to_run_ts(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "scheduled_tasks.json", [
        {"task_name": "\\Custom\\NewTask", "task_path": "\\Custom\\", "state": "Ready",
         "actions": "C:\\new.exe ", "last_run_time": "1899-12-30T00:00:00.0000000-05:00",
         "next_run_time": None, "last_task_result": None},
    ])
    records = lcru._parse_scheduled_tasks(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] == 1756598400.0
    assert 'never run' in records[0]['value']


def test_parse_scheduled_tasks_legacy_shape_unaffected(tmp_path):
    # The schtasks.exe CSV fallback has no last_run_time field at all -
    # confirm this path (no 'task_name' key) is completely untouched.
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    _write_json(run_dir, "scheduled_tasks.json", [
        {"TaskName": "\\Legacy\\OldTask", "Status": "Ready"},
    ])
    records = lcru._parse_scheduled_tasks(run_dir, ts=1756598400.0)
    assert len(records) == 1
    assert records[0]['timestamp'] == 1756598400.0


# --- _parse_live_powershell_history: real PSReadLine files copied live ---

def test_parse_live_powershell_history_finds_and_parses_real_files(tmp_path):
    run_dir = str(tmp_path / "run")
    # Matches the exact structure windows_collector.ps1 now writes
    # (2026-09-03): <username>/PSReadLine/<HostName>_history.txt.
    psr_dir = os.path.join(run_dir, "PSReadLine", "testuser", "PSReadLine")
    os.makedirs(psr_dir)
    with open(os.path.join(psr_dir, "ConsoleHost_history.txt"), "w", encoding="utf-8") as f:
        f.write("whoami\nGet-Process | Where-Object { $_.Name -eq 'evil' }\n")
    records = lcru._parse_live_powershell_history(run_dir, ts=1756598400.0)
    assert len(records) == 2
    assert all(r['artifact_type'] == 'powershell_console_history' for r in records)
    # Deliberately stamped with the run's own capture time - see this
    # function's own docstring for why that differs from the acquired-
    # file parser's honest timestamp:None default.
    assert all(r['timestamp'] == 1756598400.0 for r in records)
    assert any('whoami' in r['title'] or 'whoami' in r['value'] for r in records)


def test_parse_live_powershell_history_no_files_found(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru._parse_live_powershell_history(run_dir, ts=1.0) == []


# --- _parse_live_prefetch: real .pf files copied live (admin-only) ---

def test_parse_live_prefetch_no_prefetch_dir_returns_empty(tmp_path):
    run_dir = str(tmp_path / "run")
    os.makedirs(run_dir)
    assert lcru._parse_live_prefetch(run_dir, ts=1.0) == []


def test_parse_live_prefetch_gracefully_handles_pyscca_not_installed(tmp_path, monkeypatch):
    # core.prefetch_utils itself does `import pyscca` at module load time -
    # forcing that import to fail is meaningful both here (pyscca genuinely
    # isn't installed on this dev machine) and on a real station missing
    # it, same documented technique as test_apk_utils.py's own androguard
    # test. The prefetch/ subfolder existing but pyscca being unavailable
    # must never crash the whole import worker.
    run_dir = str(tmp_path / "run")
    os.makedirs(os.path.join(run_dir, "prefetch"))
    monkeypatch.setitem(sys.modules, 'core.prefetch_utils', None)
    monkeypatch.setitem(sys.modules, 'pyscca', None)
    assert lcru._parse_live_prefetch(run_dir, ts=1.0) == []


def test_parse_live_prefetch_wiring_with_a_fake_prefetch_utils_module(tmp_path, monkeypatch):
    # Proves the actual wiring logic this session added (find the
    # prefetch/ subfolder, call find_prefetch_files, call
    # parse_prefetch_file per path, extend the results) is correct,
    # independent of whether the real native pyscca library is
    # installed on THIS machine - a fake core.prefetch_utils module is
    # injected into sys.modules so the local `from core.prefetch_utils
    # import ...` statement resolves to it instead of the real one.
    run_dir = str(tmp_path / "run")
    prefetch_dir = os.path.join(run_dir, "prefetch")
    os.makedirs(prefetch_dir)
    fake_pf_path = os.path.join(prefetch_dir, "NOTEPAD.EXE-ABCDEF12.pf")
    open(fake_pf_path, "w").close()  # content doesn't matter - the fake parser below never reads it

    fake_module = types.ModuleType('core.prefetch_utils')
    fake_module.find_prefetch_files = lambda root_dir: ([fake_pf_path], False)
    fake_module.parse_prefetch_file = lambda path: [{
        'artifact_type': 'prefetch_execution', 'title': 'NOTEPAD.EXE', 'url': '',
        'value': 'run count: 3', 'timestamp': 1788000000.0, 'extra': {'run_count': 3},
    }]
    monkeypatch.setitem(sys.modules, 'core.prefetch_utils', fake_module)

    records = lcru._parse_live_prefetch(run_dir, ts=1.0)
    assert len(records) == 1
    assert records[0]['title'] == 'NOTEPAD.EXE'
    assert records[0]['artifact_type'] == 'prefetch_execution'
    assert records[0]['timestamp'] == 1788000000.0  # the .pf file's OWN real last-run time, not ts
