"""NFS mount options (2026-09-20).

`soft` is deliberate and must stay - this appliance cannot hang forever on a
NAS that vanished mid-examination. What changed is how little patience it had
first: timeo is in DECISECONDS, so the original timeo=30,retrans=2 surrendered
after roughly 9 seconds, and a `soft` I/O error landing mid-transaction is a
leading cause of the "database disk image is malformed" state one of this
station's case indexes is actually in.
"""
import pytest

settings = pytest.importorskip(
    "routes.settings", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")


def test_soft_is_retained():
    """Reverting to `hard` would trade a recoverable I/O error for an
    unkillable process on an appliance with a touchscreen and no shell."""
    assert 'soft' in settings.NFS_RELIABILITY_OPTS
    assert 'hard' not in settings.NFS_RELIABILITY_OPTS


def test_timeout_budget_is_at_least_thirty_seconds():
    """timeo is in deciseconds and the total budget is roughly
    timeo * retrans. The old 9s was inside the range of stalls actually
    measured on this station's NAS."""
    opts = dict(part.split('=', 1) for part in settings.NFS_RELIABILITY_OPTS.split(',') if '=' in part)
    timeo, retrans = int(opts['timeo']), int(opts['retrans'])
    assert timeo / 10.0 * retrans >= 30, "too little headroom over observed NAS stalls"


def test_v4_does_not_request_nolock():
    """NFSv4 has integrated locking, so `nolock` there is at best meaningless.
    v3 keeps it deliberately: real NLM locking needs rpc.statd/lockd, and
    turning it on blind could fail or hang the mount."""
    assert 'nolock' not in settings.NFS_RELIABILITY_OPTS
