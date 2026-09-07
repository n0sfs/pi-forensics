"""core/usb_port_health.py's proactive USB port diagnostic (2026-09-06) -
built directly from a real, live investigation on the deployed station:
1,750 consecutive kernel enumeration-failure lines across a 38-minute
retry storm, all on port 1-1.1 (top blue), zero on the other 3 ports -
confirmed twice with two completely different real devices. The user
then asked whether this could be surfaced in Drive Management BEFORE an
examiner tries a port themselves, rather than only discoverable by
sitting through a slow, confusing retry storm.

Mocks subprocess.run with real, confirmed kernel-log line shapes pulled
directly from the deployed station's own journal (journalctl -k), rather
than guessed formats - this project's own established discipline for
every reverse-engineered log/binary format elsewhere in this codebase.
No POSIX-only import in this module (no pwd/fcntl), so - unlike most of
this project's execution_worker tests - this runs on any dev machine,
Windows included.
"""
import subprocess
import types
from unittest import mock

import core.usb_port_health as usb_health


def _fake_completed(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class TestClassifyUsbPortLogLine:
    def test_a_device_descriptor_read_error_is_a_failure(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1.1: device descriptor read/64, error -32") == "failure"

    def test_device_not_responding_to_setup_address_is_a_failure(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1.1: Device not responding to setup address.") == "failure"

    def test_device_not_accepting_address_is_a_failure(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1.1: device not accepting address 3, error -71") == "failure"

    def test_unable_to_enumerate_is_a_failure(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1-port1: unable to enumerate USB device") == "failure"

    def test_attempt_power_cycle_is_its_own_distinct_category(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1-port1: attempt power cycle") == "power_cycle"

    def test_new_usb_device_found_is_a_success(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1.1: New USB device found, idVendor=058f, idProduct=6387, bcdDevice= 1.05") == "success"

    def test_an_unrelated_usb_line_is_not_classified_at_all(self):
        assert usb_health._classify_usb_port_log_line(
            "usb 1-1.1: new full-speed USB device number 60 using xhci_hcd") is None


class TestUsbPortLogLinePortExtraction:
    def test_the_device_level_dotted_shape_extracts_the_right_port(self):
        m = usb_health._USB_PORT_LOG_LINE_RE.search("usb 1-1.3: device descriptor read/64, error -32")
        assert m.group(1) == "3"

    def test_the_hub_port_level_dashed_shape_extracts_the_right_port(self):
        m = usb_health._USB_PORT_LOG_LINE_RE.search("usb 1-1-port2: attempt power cycle")
        assert m.group(1) == "2"

    def test_the_usb_storage_prefixed_shape_extracts_the_right_port(self):
        m = usb_health._USB_PORT_LOG_LINE_RE.search("usb-storage 1-1.4:1.0: USB Mass Storage device detected")
        assert m.group(1) == "4"

    def test_the_scsi_host_prefixed_shape_extracts_the_right_port(self):
        m = usb_health._USB_PORT_LOG_LINE_RE.search("scsi host0: usb-storage 1-1.1:1.0")
        assert m.group(1) == "1"


class TestDiagnoseUsbPortHealth:
    def _real_journal_sample(self):
        # A realistic mix mirroring the actual incident this module was
        # built from - port 1 with real, repeated failures then an
        # eventual real success; port 3 with a single clean success and
        # nothing else; ports 2 and 4 completely untouched.
        return "\n".join([
            "Sep 06 15:45:31 nospi4 kernel: usb 1-1-port1: unable to enumerate USB device",
            "Sep 06 15:45:32 nospi4 kernel: usb 1-1.1: device descriptor read/64, error -32",
            "Sep 06 15:45:33 nospi4 kernel: usb 1-1.1: Device not responding to setup address.",
            "Sep 06 15:45:40 nospi4 kernel: usb 1-1-port1: attempt power cycle",
            "Sep 06 15:46:00 nospi4 kernel: usb 1-1.1: device descriptor read/64, error -32",
            "Sep 06 16:44:50 nospi4 kernel: usb 1-1.1: New USB device found, idVendor=058f, idProduct=6387, bcdDevice= 1.05",
            "Sep 06 16:44:50 nospi4 kernel: usb-storage 1-1.1:1.0: USB Mass Storage device detected",
            "Sep 06 12:00:00 nospi4 kernel: usb 1-1.3: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00",
        ])

    def test_a_realistic_mixed_log_is_aggregated_correctly_per_port(self):
        with mock.patch("core.usb_port_health.subprocess.run",
                         return_value=_fake_completed(stdout=self._real_journal_sample())):
            result = usb_health.diagnose_usb_port_health()

        assert result["available"] is True
        assert result["error"] is None

        port1 = result["ports"]["1"]
        # 4 real failure lines: unable-to-enumerate, device-descriptor-
        # read (x2), Device-not-responding-to-setup-address.
        assert port1["failure_count"] == 4
        assert port1["power_cycle_count"] == 1
        assert port1["success_count"] == 1
        assert port1["last_failure_at"] == "Sep 06 15:46:00"
        assert port1["last_success_at"] == "Sep 06 16:44:50"

        port3 = result["ports"]["3"]
        assert port3["failure_count"] == 0
        assert port3["success_count"] == 1
        assert port3["last_success_at"] == "Sep 06 12:00:00"

        # Never-touched ports must read as genuinely clean zeros, not
        # missing/None - the frontend needs every one of the 4 keys
        # present regardless of whether anything ever happened on it.
        for idx in ("2", "4"):
            p = result["ports"][idx]
            assert p == {"failure_count": 0, "power_cycle_count": 0, "success_count": 0,
                         "last_failure_at": None, "last_success_at": None}

    def test_journalctl_not_installed_is_reported_as_unavailable_not_silently_all_clean(self):
        # The real, important distinction this module exists to preserve:
        # "we don't know" must never collapse into "every port is fine."
        with mock.patch("core.usb_port_health.subprocess.run", side_effect=FileNotFoundError()):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is False
        assert result["error"]
        assert result["ports"]["1"]["failure_count"] == 0  # a real zero-count default, not a false "clean" claim

    def test_a_journalctl_timeout_is_reported_as_unavailable(self):
        with mock.patch("core.usb_port_health.subprocess.run",
                         side_effect=subprocess.TimeoutExpired(cmd="journalctl", timeout=15)):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is False
        assert "timed out" in result["error"]

    def test_a_nonzero_journalctl_exit_code_is_reported_as_unavailable_with_its_own_stderr(self):
        with mock.patch("core.usb_port_health.subprocess.run",
                         return_value=_fake_completed(returncode=1, stderr="Permission denied")):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is False
        assert "Permission denied" in result["error"]

    def test_a_genuinely_clean_journal_with_no_matching_lines_is_a_real_available_clean_result(self):
        # Distinct from the unavailable cases above - journalctl itself
        # worked fine, it just found nothing to report. Every port reads
        # as a genuine, confirmed zero, not an "unknown."
        with mock.patch("core.usb_port_health.subprocess.run", return_value=_fake_completed(stdout="")):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is True
        assert result["error"] is None
        for idx in ("1", "2", "3", "4"):
            assert result["ports"][idx]["failure_count"] == 0

    def test_a_malformed_or_unrelated_line_is_skipped_not_raised(self):
        garbage = "\n".join([
            "not a real journalctl line at all",
            "Sep 06 15:45:31 nospi4 kernel: usb 1-1.1: device descriptor read/64, error -32",
            "",
            "Sep 06 bogus timestamp shape kernel: usb 1-1.2: something unrelated",
        ])
        with mock.patch("core.usb_port_health.subprocess.run", return_value=_fake_completed(stdout=garbage)):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is True
        # Only the one genuinely well-formed, matching line counts.
        assert result["ports"]["1"]["failure_count"] == 1

    def test_bus2_superspeed_lines_are_never_classified_matching_this_apps_own_disclosed_scope(self):
        # describe_usb_port()/classify_usb_port() (core/paths.py) already
        # disclose that bus2 (SuperSpeed) devices are confidently 'blue'
        # by color but were never mapped to a specific physical port_index
        # - this module's own regex is deliberately scoped to bus1 only,
        # for the identical reason, so a bus2-shaped kernel message (if
        # one were ever logged) must never silently get misattributed to
        # one of the bus1 port slots.
        with mock.patch("core.usb_port_health.subprocess.run",
                         return_value=_fake_completed(stdout="Sep 06 15:45:31 nospi4 kernel: usb 2-1: new SuperSpeed USB device number 2 using xhci_hcd")):
            result = usb_health.diagnose_usb_port_health()
        assert result["available"] is True
        for idx in ("1", "2", "3", "4"):
            assert result["ports"][idx]["failure_count"] == 0
            assert result["ports"][idx]["success_count"] == 0
