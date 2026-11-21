"""The udev write-block helper must never set the station's own boot disk
read-only, even when / is mounted as /dev/root (Pi without an initramfs) and
/boot/firmware isn't mounted yet (udev coldplug). Runs the real script from
install.py against a fake /sys and stub mountpoint/blockdev commands."""
import ast
import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _helper_script():
    tree = ast.parse((ROOT / "install.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "UDEV_SETRO_HELPER_SCRIPT" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("UDEV_SETRO_HELPER_SCRIPT not found in install.py")


def _fake_station(tmp_path, root_disk, root_majmin="179:2", boot_mounted=False):
    """root_disk holds / as partition 2 (and /boot/firmware as partition 1)."""
    sysfs = tmp_path / "sys"
    part_sep = "p" if root_disk[-1].isdigit() else ""
    disk_dir = sysfs / "devices" / "platform" / "block" / root_disk
    for n in (1, 2):
        part = disk_dir / f"{root_disk}{part_sep}{n}"
        part.mkdir(parents=True)
        (part / "partition").write_text(str(n))
    links = sysfs / "dev" / "block"
    links.mkdir(parents=True)
    major = root_majmin.split(":")[0]
    os.symlink(disk_dir / f"{root_disk}{part_sep}2", links / root_majmin)
    os.symlink(disk_dir / f"{root_disk}{part_sep}1", links / f"{major}:1")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    mounts = {"/": root_majmin}
    if boot_mounted:
        mounts["/boot/firmware"] = f"{major}:1"
    cases = "".join(f'  "{mp}") echo {mm} ;;\n' for mp, mm in mounts.items())
    (bindir / "mountpoint").write_text(
        f'#!/bin/sh\n[ "$1" = -d ] || exit 1\ncase "$2" in\n{cases}  *) exit 1 ;;\nesac\n')
    (bindir / "blockdev").write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path}/blockdev.log"\n')
    for f in bindir.iterdir():
        f.chmod(0o755)
    script = tmp_path / "pif-udev-setro"
    script.write_text(_helper_script())
    script.chmod(0o755)
    path = f"{bindir}:/usr/bin:/bin"
    return script, sysfs, path


def _run(tmp_path, script, sysfs, path, dev):
    log = tmp_path / "blockdev.log"
    if log.exists():
        log.unlink()
    subprocess.run([str(script), dev], check=True,
                   env={"PIF_TEST_PATH": path, "PIF_TEST_SYSFS": str(sysfs)})
    return log.read_text().strip() if log.exists() else ""


@pytest.mark.parametrize("boot_mounted", [False, True])
@pytest.mark.parametrize("dev", ["mmcblk0", "mmcblk0p1", "mmcblk0p2"])
def test_sd_boot_disk_is_never_set_read_only(tmp_path, dev, boot_mounted):
    script, sysfs, path = _fake_station(tmp_path, "mmcblk0", boot_mounted=boot_mounted)
    assert _run(tmp_path, script, sysfs, path, dev) == ""


@pytest.mark.parametrize("dev", ["mmcblk1", "mmcblk1p1", "sda", "sdb1", "nvme0n1", "nvme0n1p3"])
def test_other_media_are_set_read_only(tmp_path, dev):
    script, sysfs, path = _fake_station(tmp_path, "mmcblk0")
    assert _run(tmp_path, script, sysfs, path, dev) == f"--setro /dev/{dev}"


@pytest.mark.parametrize("dev", ["sda", "sda1", "sda2"])
def test_usb_boot_disk_is_never_set_read_only(tmp_path, dev):
    script, sysfs, path = _fake_station(tmp_path, "sda", root_majmin="8:2")
    assert _run(tmp_path, script, sysfs, path, dev) == ""
    assert _run(tmp_path, script, sysfs, path, "sdb") == "--setro /dev/sdb"


def test_unknown_root_disk_sets_nothing(tmp_path):
    script, sysfs, path = _fake_station(tmp_path, "mmcblk0", root_majmin="179:2")
    os.unlink(sysfs / "dev" / "block" / "179:2")
    assert _run(tmp_path, script, sysfs, path, "mmcblk1") == ""


@pytest.mark.parametrize("dev", ["", "../sda", "sda/x"])
def test_bad_names_are_ignored(tmp_path, dev):
    script, sysfs, path = _fake_station(tmp_path, "mmcblk0")
    assert _run(tmp_path, script, sysfs, path, dev) == ""


def test_every_block_rule_goes_through_the_helper():
    src = (ROOT / "install.py").read_text()
    rules = [l for l in src.splitlines() if 'SUBSYSTEM=="block"' in l and "RUN+=" in l]
    assert len(rules) == 4
    assert all("{udev_setro_helper} %k" in l for l in rules)
