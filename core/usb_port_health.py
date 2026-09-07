"""Proactive USB port health diagnostics (2026-09-06), built after a real,
live investigation on the deployed station found a physical hardware
fault specific to one exact USB port: 1,750 consecutive kernel
enumeration-failure lines across a 38-minute retry storm, ALL on port
`1-1.1` (top blue), zero on the other 3 ports - confirmed twice, with two
completely different real devices (a phone, then a USB flash drive)
hitting the identical symptom on the identical port. The user then asked
directly whether this could be surfaced in Drive Management BEFORE an
examiner ever tries a port themselves, rather than only discoverable by
sitting through a slow, confusing retry storm - this module is the
diagnostic that makes that possible.

Reads this station's own kernel log via `journalctl -k` - confirmed live,
directly, that this app's own unprivileged service account can already
read it with zero sudo grant needed (it's a member of the `adm` group,
which Debian/Raspbian's own journald ACLs already grant read access to).
No new privilege, no new sudoers entry.

Scope, deliberately narrow and disclosed rather than silently assumed to
cover more: only bus1's own 4 sub-ports (1-1.1 through 1-1.4) are
classified - the exact same scope core/paths.py's own describe_usb_port()/
classify_usb_port() already have, for the identical reason (a genuine
SuperSpeed-negotiating device shows up on bus2 instead, and which of
bus2's own root ports maps to which physical connector was never itself
confirmed against real hardware - see that module's own docstring).
Nothing here is Raspberry-Pi-4-specific in principle, but the underlying
`describe_usb_port()`/`classify_usb_port()` port-color mapping THIS
module's own results get paired with in the UI (Settings > Drive
Management) is - both are already gated behind `usb_port_diagram_
supported()` (core/config.py's `detect_pi_model()`), so this module's
own results are only ever shown on a confirmed Pi 4 station.
"""
import re
import subprocess

# Confirmed directly against this station's real, live journal - both the
# device-level ("usb 1-1.N: ...") and hub-port-level ("usb 1-1-portN: ...",
# emitted before a device number is even assigned) message shapes, plus
# the "usb-storage 1-1.N:..." / "scsi hostN: usb-storage 1-1.N:..." shapes
# a successfully-recognized mass-storage device also produces - all four
# reference the identical bus1 sub-port topology classify_usb_port() already
# maps to a physical connector, just via genuinely different message
# prefixes depending on which USB subsystem layer logged the line.
_USB_PORT_LOG_LINE_RE = re.compile(r'usb(?:-storage)? 1-1(?:\.|-port)([1-4])[:.\s]')

# Confirmed live against this station's real kernel log (2026-09-06) - the
# exact message text a real, repeated enumeration failure produces at each
# of the three real USB subsystem layers involved (hub-level, device-
# descriptor-read, address-assignment).
_USB_PORT_FAILURE_PATTERNS = (
    re.compile(r'unable to enumerate USB device'),
    re.compile(r'device descriptor read/\d+, error -\d+'),
    re.compile(r'[Dd]evice not responding to setup address'),
    re.compile(r'device not accepting address \d+, error -\d+'),
)
_USB_PORT_POWER_CYCLE_RE = re.compile(r'attempt power cycle')
# A real, successful enumeration - confirmed live as the actual line a
# genuine, working USB Mass Storage device connecting produces.
_USB_PORT_SUCCESS_RE = re.compile(r'New USB device found')

# journalctl's own timestamp prefix ("Sep 06 16:44:50 nospi4 kernel: "),
# stripped before classifying the message body, then re-parsed back out
# per matching line so each aggregated stat can report a real "last seen"
# time rather than just a bare count.
_JOURNALCTL_LINE_RE = re.compile(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) \S+ (?:kernel: )?(.*)$')

# How far back to look - a real hardware fault (a marginal solder joint, a
# worn connector) doesn't heal itself on its own, so this doesn't need to
# be "since last reboot" only; bounded regardless so an appliance with a
# very long uptime never has to walk an unbounded journal on every page
# load. journalctl's own -g/--grep does the actual line-filtering
# server-side (confirmed live: ~7,400 matching lines out of a much larger
# real journal in ~0.2s), so this is cheap even at this window size.
USB_PORT_HEALTH_LOOKBACK = "-30 days"


def _classify_usb_port_log_line(message):
    """Returns 'failure', 'power_cycle', 'success', or None (not a
    recognized event) for one already-stripped kernel-log message body."""
    if _USB_PORT_SUCCESS_RE.search(message):
        return "success"
    if _USB_PORT_POWER_CYCLE_RE.search(message):
        return "power_cycle"
    for pattern in _USB_PORT_FAILURE_PATTERNS:
        if pattern.search(message):
            return "failure"
    return None


def diagnose_usb_port_health():
    """Reads this station's own kernel log (journalctl -k) and returns a
    per-sub-port health summary, keyed by port_index ('1'-'4') - the same
    key core/paths.py's describe_usb_port() already returns, so the
    frontend can pair a physical drive's own detected port with this
    diagnostic directly, or show it station-wide with nothing connected
    at all (the whole point - see this module's own docstring).

    Returns:
        {"available": bool, "error": str|None,
         "ports": {"1": {...}, "2": {...}, "3": {...}, "4": {...}}}
    Each port entry: {"failure_count": int, "power_cycle_count": int,
    "success_count": int, "last_failure_at": str|None,
    "last_success_at": str|None}.

    "available": False (with a clear "error" reason, e.g. journalctl not
    present, or a permission error) means this station's own environment
    couldn't be read at all - never silently reported as "every port is
    healthy" in that case, which would be a false, misleading all-clear.
    A station where journalctl genuinely returns zero matching lines
    (nothing has ever gone wrong on any port) is a real, different
    "available": True result with every port's counts at 0 - the
    distinction between "we don't know" and "we checked and it's clean"
    matters here."""
    ports = {str(i): {"failure_count": 0, "power_cycle_count": 0, "success_count": 0,
                       "last_failure_at": None, "last_success_at": None} for i in range(1, 5)}

    try:
        result = subprocess.run(
            ["journalctl", "-k", "--no-pager", "-g", "usb", "--since", USB_PORT_HEALTH_LOOKBACK],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return {"available": False, "error": "journalctl is not available on this station.", "ports": ports}
    except subprocess.TimeoutExpired:
        return {"available": False, "error": "Reading the kernel log timed out.", "ports": ports}
    except Exception as e:
        return {"available": False, "error": f"Could not read the kernel log: {e}", "ports": ports}

    if result.returncode != 0:
        # A real, confirmed cause for this on some systems: journald
        # running with volatile (non-persistent) storage and no current-
        # boot data yet, or the calling account genuinely lacking read
        # access (should never happen for this app's own service account,
        # already confirmed live to have it via the `adm` group, but a
        # different install's own permissions could differ) - disclosed,
        # not silently treated as "every port is clean."
        err = (result.stderr or "").strip() or f"journalctl exited with code {result.returncode}"
        return {"available": False, "error": err, "ports": ports}

    for raw_line in result.stdout.splitlines():
        m = _JOURNALCTL_LINE_RE.match(raw_line)
        if not m:
            continue
        timestamp, message = m.group(1), m.group(2)
        port_m = _USB_PORT_LOG_LINE_RE.search(message)
        if not port_m:
            continue
        port_index = port_m.group(1)
        kind = _classify_usb_port_log_line(message)
        if kind == "failure":
            ports[port_index]["failure_count"] += 1
            ports[port_index]["last_failure_at"] = timestamp
        elif kind == "power_cycle":
            ports[port_index]["power_cycle_count"] += 1
        elif kind == "success":
            ports[port_index]["success_count"] += 1
            ports[port_index]["last_success_at"] = timestamp

    return {"available": True, "error": None, "ports": ports}
