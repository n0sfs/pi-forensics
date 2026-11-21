"""`adb shell` joins its argv with plain spaces before the phone's shell
parses it, so a multi-word command for `su -c` must reach adb as ONE quoted
string. ["su", "-c", "ls -la /dev/block/by-name/"] arrived as
`su -c ls -la /dev/block/by-name/`: su ran a bare `ls` and the partition
labels were never found (2026-09-23 review leftover, fixed 2026-11-21)."""
import shlex
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.mobile as mobile


def _remote_command(argv):
    """What the phone's shell receives: adb's space-join of everything after `shell`."""
    return " ".join(argv[argv.index("shell") + 1:])


def test_every_su_c_call_reaches_the_phone_as_one_command():
    calls = []

    def fake_run(argv, *a, **k):
        calls.append(argv)
        out = "lrwxrwxrwx 1 root root 21 2026-01-01 00:00 userdata -> /dev/block/sda34\n" if "by-name" in " ".join(argv) else ""
        return mock.Mock(returncode=0, stdout=out, stderr="")

    with mock.patch.object(mobile.subprocess, "run", side_effect=fake_run):
        result = mobile._enumerate_android_physical_targets("SERIAL123")

    su_calls = [c for c in calls if "su" in _remote_command(c).split()[:1] or _remote_command(c).startswith("su ")]
    assert su_calls, calls
    for argv in su_calls:
        words = shlex.split(_remote_command(argv))   # how the phone's sh tokenizes it
        assert words[:2] == ["su", "-c"] and len(words) == 3, argv
    assert any(t["label"] == "userdata" for t in result["targets"]), result
