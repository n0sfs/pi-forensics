"""core/bugreport_utils.py::_extract_parsed_artifact_records() - the
2026-09-04 Android pattern-of-life item 6 fix, turning the genuinely
record-shaped sections of a parsed adb bugreport into this app's
standard artifact record shape instead of a dead-end JSON blob.

Deliberately NOT gated behind pytest.importorskip("dumpstate", ...) the
way tests/test_bugreport_utils_dumpstate.py (parse_bugreport() itself)
is - _extract_parsed_artifact_records() only ever accesses its input via
plain attribute access/hasattr(), never an isinstance() check against a
real dumpstate-py class, so a hand-built types.SimpleNamespace stand-in
mirroring the real, live-confirmed field shapes (dataclasses.fields()
introspection against the real installed package on the deployed
station) exercises the exact same code path with no dependency on the
package being installed - runs on every dev machine, not just the Pi.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import core.bugreport_utils as br


def _ds(**fields):
    """A minimal stand-in Dumpstate - every field _extract_parsed_
    artifact_records() reads defaults to None/empty, matching a real
    Dumpstate instance's own per-field-optional shape."""
    base = {"package_install_log": None, "gps_data_log": None,
            "tombstones_log": None, "loaded_modules_log": None, "power_info_log": None}
    base.update(fields)
    return SimpleNamespace(**base)


def test_package_install_event_uses_the_real_datetime_object_directly():
    install = SimpleNamespace(timestamp=datetime(2026, 1, 15, 10, 23, 45, tzinfo=timezone.utc),
                               observer="PackageManager", package_name="com.example.app",
                               version_code=42, result=1)
    records = br._extract_parsed_artifact_records(_ds(package_install_log=[install]))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_bugreport_package_event"
    assert r["title"] == "Installed: com.example.app"
    assert r["extra"]["event"] == "install"
    assert "Version code: 42" in r["value"]
    assert r["timestamp"] == datetime(2026, 1, 15, 10, 23, 45, tzinfo=timezone.utc).timestamp()


def test_package_delete_event_has_no_version_code_field():
    # PackageDeleteInfo genuinely has no version_code field at all
    # (confirmed via dataclasses.fields() against the real class) -
    # hasattr()-based duck typing must correctly distinguish it from an
    # install event without crashing on the missing attribute.
    delete = SimpleNamespace(timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc),
                              observer="PackageManager", package_name="com.example.removed",
                              user="0", caller="system", result=0)
    records = br._extract_parsed_artifact_records(_ds(package_install_log=[delete]))
    assert len(records) == 1
    assert records[0]["title"] == "Deleted: com.example.removed"
    assert records[0]["extra"]["event"] == "delete"
    assert "Version code" not in records[0]["value"]


def test_gps_location_extracts_real_nested_lat_lon_and_timestamp():
    loc = SimpleNamespace(provider=b"gps", latitude=37.7749, longitude=-122.4194, accuracy=5.0,
                           altitude=10.0, altitude_accuracy=2.0, speed=0.0, speed_accuracy=0.5,
                           bearing=0.0, bearing_accuracy=1.0,
                           timestamp=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc))
    source_entry = SimpleNamespace(source="network", listeners=[], last_availability=True,
                                    last_locations=[loc])
    records = br._extract_parsed_artifact_records(_ds(gps_data_log=[source_entry]))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_bugreport_location"
    assert "37.7749" in r["value"] and "-122.4194" in r["value"]
    assert r["extra"]["provider"] == "gps"  # bytes decoded to str
    assert r["timestamp"] == datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def test_gps_multiple_locations_under_one_source_all_captured():
    loc1 = SimpleNamespace(provider=b"gps", latitude=1.0, longitude=1.0, accuracy=1.0,
                            altitude=0.0, altitude_accuracy=0.0, speed=0.0, speed_accuracy=0.0,
                            bearing=0.0, bearing_accuracy=0.0, timestamp=None)
    loc2 = SimpleNamespace(provider=b"gps", latitude=2.0, longitude=2.0, accuracy=1.0,
                            altitude=0.0, altitude_accuracy=0.0, speed=0.0, speed_accuracy=0.0,
                            bearing=0.0, bearing_accuracy=0.0, timestamp=None)
    source_entry = SimpleNamespace(source="gps", listeners=[], last_availability=True,
                                    last_locations=[loc1, loc2])
    records = br._extract_parsed_artifact_records(_ds(gps_data_log=[source_entry]))
    assert len(records) == 2
    assert records[0]["timestamp"] is None  # no timestamp on this fix - honestly None, not fabricated


def test_tombstone_real_confirmed_timestamp_format_parses_correctly():
    # The exact real format confirmed against Android crash-forensics
    # literature and independently confirmed to parse cleanly via
    # datetime.fromisoformat() on this app's own real Python 3.13 venv.
    tomb = SimpleNamespace(timestamp="2025-03-20 11:42:07.312000000+0000", pid=1234, tid=1234,
                            uid=10123, process_name="com.example.crashy", thread_name="main",
                            cmdline="com.example.crashy", build_fingerprint="x", abi="arm64",
                            signal="SIGSEGV", code="SEGV_MAPERR", fault_addr="0x0",
                            abort_message="null pointer dereference", backtrace=[])
    records = br._extract_parsed_artifact_records(_ds(tombstones_log=[tomb]))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_bugreport_crash"
    assert "com.example.crashy" in r["title"]
    assert "SIGSEGV" in r["title"]
    assert r["timestamp"] is not None
    dt = datetime.fromtimestamp(r["timestamp"], tz=timezone.utc)
    assert (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) == (2025, 3, 20, 11, 42, 7)


def test_tombstone_unparseable_timestamp_stays_none_not_a_crash():
    tomb = SimpleNamespace(timestamp="not a real timestamp at all", pid=1, tid=1, uid=0,
                            process_name="x", thread_name="x", cmdline="x", build_fingerprint="x",
                            abi="x", signal="x", code="x", fault_addr="x", abort_message=None,
                            backtrace=[])
    records = br._extract_parsed_artifact_records(_ds(tombstones_log=[tomb]))
    assert records[0]["timestamp"] is None


def test_loaded_kernel_module_has_no_timestamp_but_is_still_indexed():
    mod = SimpleNamespace(name=b"suspicious_rootkit_mod", size=8192, used_by=[b"other_mod"])
    records = br._extract_parsed_artifact_records(_ds(loaded_modules_log=[mod]))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_bugreport_kernel_module"
    assert r["title"] == "suspicious_rootkit_mod"  # bytes decoded to str
    assert r["timestamp"] is None  # honestly no per-module load time in this dump format
    assert r["extra"]["used_by"] == ["other_mod"]


def test_power_event_never_fabricates_a_timestamp_from_the_unconfirmed_raw_text():
    # PowerEvent.timestamp is confirmed (via reading dumpstate-py's own
    # power.py source directly) to be raw, un-parsed first-line dump text
    # - never treated as a real epoch value here, only preserved as raw
    # text for search.
    evt = SimpleNamespace(timestamp=b"some raw first line of unknown format",
                           reason=b"reboot,userrequested", stack_trace=[], log=[], boot_info=None)
    records = br._extract_parsed_artifact_records(_ds(power_info_log=[evt]))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_bugreport_power_event"
    assert r["timestamp"] is None  # never fabricated from the unconfirmed format
    assert r["extra"]["raw_timestamp_text"] == "some raw first line of unknown format"
    assert "reboot,userrequested" in r["title"]


def test_every_field_absent_produces_zero_records_not_an_error():
    assert br._extract_parsed_artifact_records(_ds()) == []


def test_extract_parsed_artifact_records_combines_every_scoped_section():
    ds = _ds(
        package_install_log=[SimpleNamespace(timestamp=None, observer="x", package_name="a",
                                               version_code=1, result=0)],
        tombstones_log=[SimpleNamespace(timestamp="", pid=1, tid=1, uid=0, process_name="b",
                                         thread_name="x", cmdline="x", build_fingerprint="x",
                                         abi="x", signal="x", code="x", fault_addr="x",
                                         abort_message=None, backtrace=[])],
        loaded_modules_log=[SimpleNamespace(name=b"c", size=1, used_by=[])],
    )
    records = br._extract_parsed_artifact_records(ds)
    assert {r["artifact_type"] for r in records} == {
        "android_bugreport_package_event", "android_bugreport_crash", "android_bugreport_kernel_module",
    }
