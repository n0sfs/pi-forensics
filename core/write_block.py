"""The kernel read-only flag on a whole-disk device, as the write blocker
reads it (Eric's decision 2026-11-20, 10-09 item 3A).

The Write Blocker badge used to fall back to /dev/sda when no drive was
selected, and reported "On" whenever the query failed or the device was
missing - so a failed check read as protection. Starting an acquisition or a
recovery from a source whose flag was off was also allowed. This module is
the one place that answers "is this source write-blocked?", and it never
answers yes without the kernel saying so."""
import os
import subprocess

from core.paths import is_valid_block_device
from core.priv import priv_argv

GETRO_TIMEOUT_SECONDS = 5


def read_write_block_state(device):
    """True (read-only), False (writable) or None (could not tell: not a
    whole-disk device, missing, query failed or timed out). Never guesses."""
    if not is_valid_block_device(device) or not os.path.exists(device):
        return None
    try:
        res = subprocess.run(priv_argv("blockdev-getro", device, legacy=["sudo", "/usr/sbin/blockdev", "--getro", device]),
                             capture_output=True, text=True, timeout=GETRO_TIMEOUT_SECONDS)
    except Exception:
        return None
    if res.returncode != 0:
        return None
    out = res.stdout.strip()
    if out == '1':
        return True
    if out == '0':
        return False
    return None


def source_write_block_problem(device):
    """Why reading from this source device must be refused, or None. Only
    whole-disk devices are checked; image files and decrypted mounts are not
    block devices this station can write-block."""
    if not is_valid_block_device(device):
        return None
    state = read_write_block_state(device)
    if state is True:
        return None
    if state is False:
        return (f"The write blocker is OFF on {device}, so nothing was started. Turn it back on in "
                f"Settings > Drive Management (or pick the right source drive), then start again.")
    return (f"Could not confirm that {device} is write-blocked (the read-only check failed or the drive "
            f"is gone), so nothing was started. Re-seat the drive, check it shows as PROTECTED in "
            f"Settings > Drive Management, then start again.")
