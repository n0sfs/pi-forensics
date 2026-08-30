"""iOS crash-report pull via idevicecrashreport (libimobiledevice). Pulls
a connected device's own `CrashReporter` directory - typically low tens
of files, a few MB, finishing in seconds (same size class as this app's
existing `pair_ios_device()`, not `idevicebackup2 --full`'s multi-GB
job-system-scale acquisition).

CRITICAL, confirmed live against the real installed binary (1.3.0) on
this station before writing this module - the plan's own original
assumption about which flag controls device mutation was wrong. `-e`/
`--extract` does NOT mean "extract and delete from device" - it means
"decode the raw crash report into a separate, readable .crash file", a
purely local, zero-device-impact operation. The flag that actually
controls whether crash reports are removed from the device is `-k`/
`--keep` ("copy but do not remove crash reports from device") - and
its own --help text confirms the *default* behavior (no `-k`) is
destructive: it copies AND deletes. This module always passes `-k`, so
pulling crash reports is non-destructive by default - a live-device
mutation must never be a silent default, matching this app's own
established evidence-handling posture elsewhere (write-blocking,
BitLocker/LUKS never auto-decrypting, etc.). `-e` is also always passed
since it's free, real value (decoded .crash files instead of raw ones)
with zero downside.
"""
import os
import subprocess

IDEVICECRASHREPORT_TIMEOUT_SECONDS = 60


def pull_ios_crash_reports(udid, output_dir):
    """Runs `idevicecrashreport -u <udid> -k -e <output_dir>` - `-k`
    (keep, never remove from device) and `-e` (extract/decode locally,
    zero device impact) are always passed, never optional. Returns
    {"success": bool, "output_dir": str|None, "log": str, "error": str|None,
    "files": list[str]}. Never raises."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["idevicecrashreport", "-u", udid, "-k", "-e", output_dir]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=IDEVICECRASHREPORT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "output_dir": None, "log": "", "error": "Timed out waiting for the device.", "files": []}
    except FileNotFoundError:
        return {"success": False, "output_dir": None, "log": "", "error": "idevicecrashreport is not installed on this station.", "files": []}
    except Exception as e:
        return {"success": False, "output_dir": None, "log": "", "error": str(e), "files": []}

    log = ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip() or "[no output]"

    if res.returncode != 0:
        return {"success": False, "output_dir": None, "log": log,
                "error": log[:1000] or "idevicecrashreport failed with no output.", "files": []}

    files = []
    for root, _dirs, filenames in os.walk(output_dir):
        for name in filenames:
            files.append(os.path.relpath(os.path.join(root, name), output_dir))
    files.sort()

    return {"success": True, "output_dir": output_dir, "log": log, "error": None, "files": files}
