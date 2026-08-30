"""SIM/UICC card forensics via pysim (osmocom), run in its own isolated
venv (see core/config.py's PYSIM_DIR/PYSIM_VENV_PYTHON) - reads a card
inserted in a connected PC/SC reader.

Genuinely provisional, per this project's own established precedent for
a feature built without matching hardware available to verify against
(the same "structurally complete, functionally disclosed as unverified
until proven live" standard already used for BitLocker/LUKS/rooted-
Android acquisition before real hardware existed for those). Every piece
BELOW this docstring line was independently confirmed live against the
real installed package on this station - the reader-enumeration call
correctly returns an empty list with no error when no reader is attached
(a real, common, non-error PC/SC state), and pySim-shell.py's own
non-interactive invocation shape was confirmed to fail cleanly (a real,
catchable Python exception, not a hang) when no reader is present at the
requested index. What was NOT verified: what a real inserted SIM/UICC
card's own `cardinfo` output actually looks like - v1 deliberately
returns the tool's raw stdout unconditionally as an `output` string
rather than attempting to parse it into structured fields, matching this
app's own established fallback for any tool whose real output shape
hasn't been seen yet (e.g. core/linux_artifacts.py's wtmp handling).

Getting pcscd to actually authorize this station's own unprivileged
service account required a real, load-bearing discovery beyond pysim
itself: modern pcscd (Debian's own packaging) gates access through
polkit's org.debian.pcsc-lite.access_pcsc/access_card actions, whose
*default* policy only authorizes an "active" (real logged-in desktop)
session - `allow_inactive: no`, `allow_any: no` - so a systemd-run
background service account is rejected by design, confirmed directly
from pcscd's own journal log ("NOT authorized for action: access_pcsc").
Fixed via a minimal, exact-match polkit rule (see install.py's own
_write_pcsc_polkit_rule() step) granting exactly those two actions to
exactly this station's service account - not a broad policy loosening,
matching this project's own sudoers-grant philosophy elsewhere.
"""
import json
import os
import subprocess

from core.config import PYSIM_DIR, PYSIM_VENV_PYTHON

PYSIM_READERS_TIMEOUT_SECONDS = 15
PYSIM_READ_TIMEOUT_SECONDS = 30
PYSIM_SHELL_BIN = os.path.join(os.path.dirname(PYSIM_VENV_PYTHON), "pySim-shell.py")

_LIST_READERS_SNIPPET = (
    "from smartcard.System import readers\n"
    "import json\n"
    "print(json.dumps([str(r) for r in readers()]))\n"
)


def list_pcsc_readers():
    """Enumerates connected PC/SC readers via pyscard directly (no need
    to spawn the heavier pySim-shell.py just to list readers). Returns
    {"success": bool, "readers": list[str], "error": str|None}. An empty
    list with success=True is the normal, common "no reader physically
    connected" state, not an error - confirmed live. Never raises."""
    if not os.path.isfile(PYSIM_VENV_PYTHON):
        return {"success": False, "readers": [], "error": "pysim is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions."}

    try:
        res = subprocess.run([PYSIM_VENV_PYTHON, "-c", _LIST_READERS_SNIPPET],
                              capture_output=True, text=True, timeout=PYSIM_READERS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"success": False, "readers": [], "error": "Timed out talking to the PC/SC daemon (pcscd)."}
    except Exception as e:
        return {"success": False, "readers": [], "error": str(e)}

    if res.returncode != 0:
        log = ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip()
        return {"success": False, "readers": [], "error": log[:1000] or "Failed to enumerate PC/SC readers."}

    try:
        reader_list = json.loads(res.stdout.strip())
    except (ValueError, json.JSONDecodeError):
        return {"success": False, "readers": [], "error": "Unexpected output from the reader-enumeration check."}

    return {"success": True, "readers": reader_list, "error": None}


def read_sim_card(reader_index=0):
    """Runs `pySim-shell.py --noprompt -p <reader_index> -e cardinfo` -
    confirmed real, non-interactive invocation shape (verified live
    against the real installed pySim-shell.py --help output before
    writing this). Returns {"success": bool, "output": str, "error": str|None}
    - `output` is the tool's raw stdout, unparsed (see module docstring
    for why). A non-zero exit (including a raw Python traceback from the
    tool itself, confirmed live for the "no reader at this index" case)
    is always a clean, reported failure here - never surfaced as a crash,
    matching this app's already-established handling for SQLite Dissect/
    wadecrypt. Never raises."""
    if not os.path.isfile(PYSIM_SHELL_BIN):
        return {"success": False, "output": "", "error": "pysim is not installed on this station. "
                "Check Settings > Service Controls & Diagnostics > Tool Versions."}

    cmd = [PYSIM_VENV_PYTHON, PYSIM_SHELL_BIN, "--noprompt", "-p", str(reader_index), "-e", "cardinfo"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=PYSIM_READ_TIMEOUT_SECONDS,
                              cwd=PYSIM_DIR)
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": "Timed out reading the card."}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}

    log = ((res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")).strip() or "[no output]"

    if res.returncode != 0:
        return {"success": False, "output": log, "error": log[:2000] or "pySim-shell failed with no output."}

    return {"success": True, "output": log, "error": None}
