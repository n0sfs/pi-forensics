"""WhatsApp local-backup decryption - two independent pieces: pulling the
device's own `key` file off a rooted Android phone (an acquisition step,
called from routes/mobile.py), and decrypting an already-acquired
`msgstore.db.crypt12/14/15` file against that key (an analysis step,
called from routes/file_explorer.py).

Real CLI shapes below were confirmed live against the installed
wa-crypt-tools 0.1.0 package on this station's real ARM64 venv before
writing this module, not assumed - including a real, genuine upstream bug
found along the way: `wacreatekey`'s own `-o/--output` flag crashes with a
TypeError on this exact installed version (it opens the file via
argparse's FileType('wb') and then re-wraps the already-open handle in
Path(), which is invalid) - irrelevant to this module itself (it never
calls wacreatekey), but worth remembering if a future feature ever needs
to generate a synthetic test key file the way this module's own live
verification did (work around it by omitting -o and using the tool's own
default output filename instead).

`wadecrypt`'s real, confirmed positional argument order is
`[keyfile] [encrypted] [decrypted]` - verified via a real synthetic
key+crypt14 round trip (wacreatekey -> waencrypt -> wadecrypt) that
reproduced the original plaintext byte-for-byte. On success, wadecrypt
writes nothing to stdout and its own log lines (ANSI-colored) go to
stderr with exit code 0; on failure (a malformed/wrong key, confirmed
live against a real wrong-key test) it can raise an outright Python
traceback rather than fail gracefully - this wrapper treats any non-zero
exit as a clean, reported failure, the same "never let a tool's own
crash propagate" discipline already established for SQLite Dissect.
"""
import os
import re
import subprocess

from core.config import MVT_BIN_DIR

WHATSAPP_KEY_PULL_TIMEOUT_SECONDS = 20
WHATSAPP_KEY_MAX_BYTES = 4096  # a real key file is a few hundred bytes at
                               # most across crypt12/14/15 formats - a
                               # larger response is very likely an `su -c`
                               # denial message misrouted to stdout, not a
                               # real key, and is rejected rather than
                               # trusted.
WADECRYPT_TIMEOUT_SECONDS = 300
# wadecrypt is a pip console-script (see requirements.txt), same
# MVT_BIN_DIR resolution as every other pip-installed analysis tool in
# this app - not on PATH under gunicorn/systemd.
WADECRYPT_BIN = os.path.join(MVT_BIN_DIR, "wadecrypt")

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def pull_whatsapp_key_file(serial, dest_path):
    """Pulls a rooted Android device's own WhatsApp `key` file
    (/data/data/com.whatsapp/files/key) via `adb shell su -c cat` and
    writes its raw bytes to dest_path. Returns
    {"success": bool, "path": str|None, "error": str|None}. Requires the
    device to already be rooted (_probe_android_root_status()'s own
    check) - a non-rooted device's `su` invocation fails cleanly, the
    same outcome as any other su-denied command elsewhere in this app."""
    try:
        res = subprocess.run(
            ["adb", "-s", serial, "shell", "su", "-c", "cat /data/data/com.whatsapp/files/key"],
            capture_output=True, text=False, timeout=WHATSAPP_KEY_PULL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "path": None, "error": "Timed out waiting for the device."}
    except Exception as e:
        return {"success": False, "path": None, "error": str(e)}

    if res.returncode != 0:
        stderr_text = (res.stderr or b'').decode('utf-8', errors='replace').strip()
        return {"success": False, "path": None, "error": stderr_text or
                "Could not read the key file - is WhatsApp installed and is this device genuinely rooted?"}

    key_bytes = res.stdout or b''
    if not key_bytes:
        return {"success": False, "path": None, "error": "No key file content returned - "
                "WhatsApp may not be installed, or su access was denied."}
    if len(key_bytes) > WHATSAPP_KEY_MAX_BYTES:
        return {"success": False, "path": None, "error": f"Unexpectedly large response "
                f"({len(key_bytes)} bytes) - this is very likely an su-denial message rather "
                f"than a real key file, so it was not saved."}

    try:
        with open(dest_path, 'wb') as f:
            f.write(key_bytes)
    except OSError as e:
        return {"success": False, "path": None, "error": f"Could not write key file: {e}"}

    return {"success": True, "path": dest_path, "error": None}


def decrypt_whatsapp_backup(crypt_path, key_path, output_db_path):
    """Runs `wadecrypt <key_path> <crypt_path> <output_db_path>` -
    confirmed positional order via a real synthetic round trip on this
    station. Returns {"success": bool, "output_path": str|None,
    "log": str, "error": str|None} - never raises."""
    if not os.path.isfile(WADECRYPT_BIN):
        return {"success": False, "output_path": None, "log": "",
                "error": "wadecrypt is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions."}

    cmd = [WADECRYPT_BIN, key_path, crypt_path, output_db_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=WADECRYPT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "output_path": None, "log": "",
                "error": "wadecrypt timed out (unusually large backup file)."}
    except Exception as e:
        return {"success": False, "output_path": None, "log": "", "error": str(e)}

    log = _ANSI_RE.sub('', ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip())

    if res.returncode != 0:
        # A non-zero exit (including a raw Python traceback from the tool
        # itself on a wrong/malformed key, confirmed live) is always a
        # clean, reported failure here - never surfaced as a crash.
        return {"success": False, "output_path": None, "log": log,
                "error": log[:2000] or "wadecrypt failed with no output."}

    if not os.path.isfile(output_db_path) or os.path.getsize(output_db_path) == 0:
        return {"success": False, "output_path": None, "log": log,
                "error": "wadecrypt reported success but wrote no decrypted output - "
                "the key may not match this backup file."}

    return {"success": True, "output_path": output_db_path, "log": log, "error": None}
