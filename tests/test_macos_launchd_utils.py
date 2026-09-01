"""Tests for core/macos_launchd_utils.py, built against real plist files
(both XML and Apple's own binary encoding, via stdlib plistlib itself -
proving the format-agnostic parsing claim directly, not assumed) matching
the real, confirmed launchd.plist(5) schema - not mocks."""
import plistlib

import core.macos_launchd_utils as mlu


def _write_plist(path, data, binary=False):
    with open(path, 'wb') as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)


def test_parse_launchd_plist_extracts_real_fields_xml(tmp_path):
    launch_dir = tmp_path / "Library" / "LaunchDaemons"
    launch_dir.mkdir(parents=True)
    p = launch_dir / "com.evil.backdoor.plist"
    _write_plist(str(p), {
        "Label": "com.evil.backdoor",
        "Program": "/usr/local/bin/backdoor",
        "RunAtLoad": True,
        "KeepAlive": True,
        "StartInterval": 300,
    })

    records = mlu.parse_launchd_plist_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "macos_launchd_item"
    assert r["title"] == "com.evil.backdoor"
    assert r["value"] == "/usr/local/bin/backdoor"
    assert r["timestamp"] is not None and r["timestamp"] > 0
    assert r["extra"]["run_at_load"] is True
    assert r["extra"]["keep_alive"] is True
    assert r["extra"]["start_interval"] == 300
    assert r["extra"]["is_system_item"] is False


def test_parse_launchd_plist_extracts_real_fields_binary_format(tmp_path):
    # Apple's own binary plist encoding - stdlib plistlib auto-detects it
    # with zero special handling needed, proving the format-agnostic claim
    # directly rather than assuming XML is the only real-world shape.
    launch_dir = tmp_path / "System" / "Library" / "LaunchDaemons"
    launch_dir.mkdir(parents=True)
    p = launch_dir / "com.apple.something.plist"
    _write_plist(str(p), {
        "Label": "com.apple.something",
        "ProgramArguments": ["/usr/libexec/something", "-daemon", "-v"],
        "RunAtLoad": True,
    }, binary=True)

    records = mlu.parse_launchd_plist_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["title"] == "com.apple.something"
    assert r["value"] == "/usr/libexec/something -daemon -v"
    assert r["extra"]["is_system_item"] is True  # sits under /System/


def test_parse_launchd_plist_missing_label_falls_back_to_filename(tmp_path):
    launch_dir = tmp_path / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    p = launch_dir / "no_label_here.plist"
    _write_plist(str(p), {"Program": "/bin/echo"})
    records = mlu.parse_launchd_plist_file(str(p))
    assert records[0]["title"] == "no_label_here"


def test_parse_launchd_plist_missing_program_reports_honestly(tmp_path):
    launch_dir = tmp_path / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    p = launch_dir / "com.example.watcher.plist"
    _write_plist(str(p), {"Label": "com.example.watcher", "WatchPaths": ["/tmp/trigger"]})
    records = mlu.parse_launchd_plist_file(str(p))
    assert records[0]["value"] == "(no Program/ProgramArguments found)"
    assert records[0]["extra"]["watch_paths"] == ["/tmp/trigger"]


def test_parse_launchd_plist_caps_long_program_arguments_list(tmp_path):
    launch_dir = tmp_path / "Library" / "LaunchDaemons"
    launch_dir.mkdir(parents=True)
    p = launch_dir / "com.example.manyargs.plist"
    args = ["/usr/bin/tool"] + [f"--flag{i}" for i in range(30)]
    _write_plist(str(p), {"Label": "com.example.manyargs", "ProgramArguments": args})
    records = mlu.parse_launchd_plist_file(str(p))
    assert records[0]["value"].endswith('...')
    shown = records[0]["value"][:-4].split()
    assert len(shown) == mlu.LAUNCHD_MAX_PROGRAM_ARGUMENTS_SHOWN


def test_parse_launchd_plist_not_a_real_plist_returns_empty(tmp_path):
    p = tmp_path / "fake.plist"
    p.write_bytes(b'this is not a real plist file at all')
    assert mlu.parse_launchd_plist_file(str(p)) == []


def test_parse_launchd_plist_missing_file_returns_empty(tmp_path):
    assert mlu.parse_launchd_plist_file(str(tmp_path / "gone.plist")) == []


def test_find_launchd_plist_files_matches_only_the_right_parent_directories(tmp_path):
    real_agent_dir = tmp_path / "Users" / "victim" / "Library" / "LaunchAgents"
    real_agent_dir.mkdir(parents=True)
    (real_agent_dir / "com.example.agent.plist").write_bytes(b'x')

    real_daemon_dir = tmp_path / "Library" / "LaunchDaemons"
    real_daemon_dir.mkdir(parents=True)
    (real_daemon_dir / "com.example.daemon.plist").write_bytes(b'x')

    unrelated_dir = tmp_path / "Library" / "Preferences"
    unrelated_dir.mkdir(parents=True)
    (unrelated_dir / "com.example.notlaunchd.plist").write_bytes(b'x')

    found, truncated = mlu.find_launchd_plist_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"com.example.agent.plist", "com.example.daemon.plist"}
    assert truncated is False


def test_find_launchd_plist_files_matches_parent_dir_case_insensitively(tmp_path):
    launch_dir = tmp_path / "Library" / "launchdaemons"  # real-world casing can vary if re-cased
    launch_dir.mkdir(parents=True)
    (launch_dir / "com.example.x.plist").write_bytes(b'x')
    found, _truncated = mlu.find_launchd_plist_files(str(tmp_path))
    assert len(found) == 1


def test_is_system_item_detects_system_ancestor():
    assert mlu._is_system_item('/mnt/case/System/Library/LaunchDaemons/x.plist') is True
    assert mlu._is_system_item('/mnt/case/Library/LaunchDaemons/x.plist') is False
    assert mlu._is_system_item('/mnt/case/Users/bob/Library/LaunchAgents/x.plist') is False
