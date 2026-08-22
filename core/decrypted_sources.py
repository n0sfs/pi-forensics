"""Minimal, single-purpose registry of currently-active decrypted virtual
sources (BitLocker dislocker mounts, LUKS dm-mapper devices).

Exists for exactly one reason: routes/image_browser.py's
_resolve_browsable_source() needs to know "is this path currently a
legitimate decrypted source" without importing routes/acquisition.py's own
richer per-mechanism bookkeeping (active_bitlocker_mounts/active_luks_mounts)
- consistent with this project's own stated principle (see the app.py ->
core/ + routes/ split) that anything needed by more than one routes/*.py
module belongs in core/, never inside one routes/*.py file that another
imports from.

Deliberately minimal - path -> kind only, nothing else. No device/mount_id
duplicated here: routes/acquisition.py's _resolve_acquisition_source() (used
by start_imaging()/start_ddrescue(), which need the richer metadata) stays
independent, reading its own active_bitlocker_mounts/active_luks_mounts
dicts directly rather than through this registry - keeping this registry to
a single fact (kind, for logging) avoids two-dict-drift risk entirely for
that consumer, and this one only ever needs a yes/no answer.

register_decrypted_source()/unregister_decrypted_source() are called
immediately adjacent to (not as a separate transaction from) the existing
active_bitlocker_mounts/active_luks_mounts writes in
routes/acquisition.py - so the two can only drift across an exact
crash-mid-two-statements window, the same acceptable risk level already
implicit in this codebase's other in-memory-only job/mount state (e.g. a
process restart already loses all active_bitlocker_mounts state, with no
persistence layer - this isn't a new category of risk).
"""
import threading

_lock = threading.Lock()
_active = {}  # path -> kind ("bitlocker" | "luks")


def register_decrypted_source(path, kind):
    with _lock:
        _active[path] = kind


def unregister_decrypted_source(path):
    with _lock:
        _active.pop(path, None)


def get_decrypted_source_kind(path):
    """Returns "bitlocker"/"luks"/None."""
    with _lock:
        return _active.get(path)
