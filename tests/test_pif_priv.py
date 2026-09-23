"""tools/pif_priv/pif_priv.py - the root-owned privileged helper (2026-09-23).

These run everywhere (no root needed): the helper's validation and argv
building are pure, and device nodes / sysfs are mocked. The argv tests pin
the helper to the EXACT command lines the app built before the migration, so
moving a call site onto the helper cannot silently change what a tool does.
"""
import json
import os
import stat
import types
from unittest import mock

import pytest

from tools.pif_priv import pif_priv as pp

posix_paths = pytest.mark.skipif(os.name == "nt", reason="the helper only runs on Linux; path semantics are POSIX")

CFG = {"service_user": "svc", "evidence_root": "/mnt", "install_dir": "/opt/pi-forensics"}


def _blk(mode=stat.S_IFBLK | 0o660):
    return types.SimpleNamespace(st_mode=mode)


@pytest.fixture
def devices(monkeypatch):
    """Pretend /dev/sda, /dev/sdb, /dev/sdb1, /dev/mmcblk0 (system) exist as block nodes."""
    nodes = {"/dev/sda", "/dev/sdb", "/dev/sdb1", "/dev/mmcblk0", "/dev/mmcblk0p2", "/dev/nvme0n1",
             "/dev/mapper/pif_luks_" + "a" * 32}
    real_lstat = os.lstat

    def fake_lstat(p, *a, **kw):
        if p in nodes:
            return _blk()
        if p == "/dev/sdc":
            return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644)  # not a block device
        return real_lstat(p, *a, **kw)

    monkeypatch.setattr(pp.os, "lstat", fake_lstat)
    monkeypatch.setattr(pp, "system_disks", lambda: {"mmcblk0"})
    return nodes


# --- configuration --------------------------------------------------------

def test_config_must_be_root_owned_and_not_writable_by_others(tmp_path):
    p = tmp_path / "priv.conf"
    p.write_text(json.dumps(CFG))
    with pytest.raises(pp.Refused, match="owned by root"):
        pp.load_config(str(p), _stat=lambda _p: types.SimpleNamespace(st_uid=1000, st_mode=0o644))
    with pytest.raises(pp.Refused, match="owned by root"):
        pp.load_config(str(p), _stat=lambda _p: types.SimpleNamespace(st_uid=0, st_mode=0o666))
    cfg = pp.load_config(str(p), _stat=lambda _p: types.SimpleNamespace(st_uid=0, st_mode=0o644))
    assert cfg["service_user"] == "svc"


def test_config_rejects_root_as_evidence_root(tmp_path):
    p = tmp_path / "priv.conf"
    p.write_text(json.dumps(dict(CFG, evidence_root="/")))
    with pytest.raises(pp.Refused):
        pp.load_config(str(p), _stat=lambda _p: types.SimpleNamespace(st_uid=0, st_mode=0o644))


# --- devices --------------------------------------------------------------

@pytest.mark.parametrize("path", ["/dev/sda", "/dev/nvme0n1"])
def test_whole_disks_are_accepted(devices, path):
    assert pp.require_block_device(path) == path


@pytest.mark.parametrize("path", [
    "/dev/mmcblk0",            # the system disk
    "/dev/mmcblk0p2",          # a partition of it
    "/dev/sdc",                # matches the regex but is not a block device
    "/etc/shadow", "/dev/sda; reboot", "-x", "", "/dev/../etc/shadow", "/dev/sda/../sda",
])
def test_everything_else_is_refused(devices, path):
    with pytest.raises(pp.Refused):
        pp.require_block_device(path, allow_partition=True, allow_mapper=True)


def test_partitions_and_mappers_only_when_allowed(devices):
    with pytest.raises(pp.Refused):
        pp.require_block_device("/dev/sdb1")
    assert pp.require_block_device("/dev/sdb1", allow_partition=True) == "/dev/sdb1"
    m = "/dev/mapper/pif_luks_" + "a" * 32
    with pytest.raises(pp.Refused):
        pp.require_block_device(m)
    assert pp.require_block_device(m, allow_mapper=True) == m


@pytest.mark.parametrize("dev,disk", [("/dev/sdb1", "sdb"), ("/dev/nvme0n1p3", "nvme0n1"),
                                      ("/dev/mmcblk1p1", "mmcblk1"), ("/dev/sda", "sda")])
def test_parent_disk(dev, disk):
    assert pp.parent_disk(dev) == disk


def test_usb_port_color_fails_closed(monkeypatch):
    base = "/sys/devices/platform/scb/fd500000.pcie/pci0000:00/0000:00:00.0/0000:01:00.0"
    cases = {
        f"{base}/usb1/1-1/1-1.3/1-1.3:1.0/host0/target0:0:0/0:0:0:0/block/sdb": "black",
        f"{base}/usb1/1-1/1-1.1/1-1.1:1.0/host0/target0:0:0/0:0:0:0/block/sdb": "blue",
        f"{base}/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0/block/sdb": "blue",
        # behind a hub - an extra segment - must NOT be treated as black
        f"{base}/usb1/1-1/1-1.3/1-1.3.1/1-1.3.1:1.0/host0/block/sdb": "unknown",
    }
    for real, expected in cases.items():
        monkeypatch.setattr(pp.os.path, "realpath", lambda p, _r=real: _r)
        assert pp.usb_port_color("/dev/sdb") == expected


def test_setrw_requires_a_black_port(devices, monkeypatch):
    calls = []
    monkeypatch.setattr(pp, "usb_port_color", lambda d: "blue")
    with pytest.raises(pp.Refused, match="black"):
        pp.cmd_blockdev(CFG, "blockdev-setrw", ["/dev/sdb"], _run=calls.append)
    monkeypatch.setattr(pp, "usb_port_color", lambda d: "black")
    pp.cmd_blockdev(CFG, "blockdev-setrw", ["/dev/sdb1"], _run=calls.append)
    assert calls == [["/usr/sbin/blockdev", "--setrw", "/dev/sdb1"]]


def test_blockdev_never_touches_the_system_disk(devices):
    for sub in ("blockdev-setro", "blockdev-setrw", "blockdev-getro", "blockdev-flush"):
        with pytest.raises(pp.Refused, match="system disk"):
            pp.cmd_blockdev(CFG, sub, ["/dev/mmcblk0"], _run=lambda a: 0)


def test_rereadpt_is_sd_only(devices):
    with pytest.raises(pp.Refused):
        pp.cmd_blockdev(CFG, "blockdev-rereadpt", ["/dev/nvme0n1"], _run=lambda a: 0)


# --- paths ----------------------------------------------------------------

@posix_paths
def test_require_under(tmp_path):
    root = str(tmp_path / "mnt")
    os.makedirs(os.path.join(root, "case"))
    assert pp.require_under(os.path.join(root, "case"), root) == os.path.join(root, "case")
    for bad in ("/etc", os.path.join(root, "..", "etc"), root, "", "a\x00b"):
        with pytest.raises(pp.Refused):
            pp.require_under(bad, root)
    assert pp.require_under(root, root, allow_root=True) == root


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_a_symlink_out_of_the_root_is_refused(tmp_path):
    root = tmp_path / "mnt"
    root.mkdir()
    (root / "escape").symlink_to("/etc")
    with pytest.raises(pp.Refused):
        pp.require_under(str(root / "escape" / "sudoers.d"), str(root))


@posix_paths
def test_output_base_rules(tmp_path, monkeypatch):
    root = str(tmp_path)
    os.makedirs(os.path.join(root, "case"))
    monkeypatch.setattr(pp, "disk_name_of", lambda p: "sdz")
    ok = pp.require_new_output_base(os.path.join(root, "case", "CASE_ITEM-01"), root, "/dev/sda")
    assert ok == os.path.join(root, "case", "CASE_ITEM-01")
    for bad in ("../x", "a b", "x/y", "", "x;rm"):
        with pytest.raises(pp.Refused):
            pp.require_new_output_base(os.path.join(root, "case", bad), root, "/dev/sda")
    with pytest.raises(pp.Refused, match="outside"):
        pp.require_new_output_base("/etc/CASE", root, "/dev/sda")
    # the destination on the very disk being imaged
    monkeypatch.setattr(pp, "disk_name_of", lambda p: "sda")
    with pytest.raises(pp.Refused, match="device being imaged"):
        pp.require_new_output_base(os.path.join(root, "case", "CASE"), root, "/dev/sda")


def test_existing_outputs_are_never_overwritten(tmp_path):
    f = tmp_path / "x.dd"
    f.write_bytes(b"evidence")
    with pytest.raises(pp.Refused, match="already exists"):
        pp.require_absent(str(f))


# --- argv: identical to what the app built before the migration ------------

def test_dc3dd_argv_matches_the_apps_own():
    argv, outs = pp.argv_image_dc3dd("/dev/sda", "/mnt/c/B", "dd", ["md5", "sha256"])
    assert argv == ["/usr/bin/dc3dd", "if=/dev/sda", "of=/mnt/c/B.dd", "log=/mnt/c/B_dc3dd.log",
                    "hash=md5", "hash=sha256"]
    assert outs == ["/mnt/c/B.dd", "/mnt/c/B_dc3dd.log"]
    with pytest.raises(pp.Refused):
        pp.argv_image_dc3dd("/dev/sda", "/mnt/c/B", "sh", ["md5"])


def test_dcfldd_argv_matches_the_apps_own():
    argv, _ = pp.argv_image_dcfldd("/dev/sda", "/mnt/c/B", ["md5", "sha1"])
    assert argv == ["/usr/bin/dcfldd", "if=/dev/sda", "of=/mnt/c/B.dd", "conv=noerror,sync",
                    "hash=md5,sha1", "md5log=/mnt/c/B_md5.log", "sha1log=/mnt/c/B_sha1.log"]


def test_dcfldd_without_hashes_matches_the_apps_own():
    argv, outs = pp.argv_image_dcfldd("/dev/sda", "/mnt/c/B", [])
    assert argv == ["/usr/bin/dcfldd", "if=/dev/sda", "of=/mnt/c/B.dd", "conv=noerror,sync"]
    assert outs == ["/mnt/c/B.dd"]


def test_dd_argv_matches_the_apps_own():
    argv, _ = pp.argv_image_dd("/dev/sda", "/mnt/c/B", True)
    assert argv == ["/usr/bin/dd", "if=/dev/sda", "of=/mnt/c/B.dd", "bs=4M", "conv=noerror,sync",
                    "status=progress", "iflag=direct"]


def test_hash_whitelist():
    assert pp.require_hashes(["md5", "sha256"]) == ["md5", "sha256"]
    assert pp.require_hashes([]) == []           # in-line hashing is optional in the app
    for bad in (["crc32"], ["md5", "md5"], ["md5;id"]):
        with pytest.raises(pp.Refused):
            pp.require_hashes(bad)


@posix_paths
def test_image_subcommand_end_to_end_validation(tmp_path, devices, monkeypatch):
    root = str(tmp_path)
    os.makedirs(os.path.join(root, "case"))
    cfg = dict(CFG, evidence_root=root)
    monkeypatch.setattr(pp, "disk_name_of", lambda p: "nfs")
    ran = []
    pp.cmd_image(cfg, "image-dc3dd", ["/dev/sda", os.path.join(root, "case", "B"), "dd", "sha256"],
                 _exec=ran.append)
    assert ran[0][0] == "/usr/bin/dc3dd" and ran[0][1] == "if=/dev/sda"
    with pytest.raises(pp.Refused, match="system disk"):
        pp.cmd_image(cfg, "image-dd", ["/dev/mmcblk0", os.path.join(root, "case", "B2"), "direct"],
                     _exec=ran.append)
    with pytest.raises(pp.Refused, match="outside"):
        pp.cmd_image(cfg, "image-dd", ["/dev/sda", "/etc/sudoers.d/x", "direct"], _exec=ran.append)


# --- kill -----------------------------------------------------------------

def test_kill_pgroup_refuses_the_callers_own_group():
    runs = []
    kw = dict(_run=runs.append, _getpgrp=lambda: 500, _getppid=lambda: 77, _getpgid=lambda pid: 100)
    for pgid in ("100", "500", "1", "0", "-5", "12x"):
        with pytest.raises(pp.Refused):
            pp.cmd_kill(CFG, "kill-pgroup", [pgid], **kw)
    pp.cmd_kill(CFG, "kill-pgroup", ["4242"], **kw)
    assert runs == [["/usr/bin/pkill", "-9", "-g", "4242"]]


def test_kill_tools_matches_exact_names_only():
    runs = []
    pp.cmd_kill(CFG, "kill-tools", [], _run=runs.append)
    assert all(r[:3] == ["/usr/bin/pkill", "-9", "-x"] for r in runs)
    assert {r[3] for r in runs} == set(pp.STOPPABLE_TOOLS)


# --- reclaim --------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="lstat st_dev/symlink semantics are POSIX")
def test_reclaim_stays_inside_the_tree_and_never_follows_symlinks(tmp_path, monkeypatch):
    root = tmp_path / "mnt"
    job = root / "case" / "job"
    (job / "sub").mkdir(parents=True)
    (job / "a.dd").write_bytes(b"x")
    (job / "sub" / "b.log").write_text("y")
    (job / "link").symlink_to("/etc")
    cfg = dict(CFG, evidence_root=str(root))
    monkeypatch.setattr(pp, "_pw", lambda c: types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
    touched = []
    pp.cmd_reclaim(cfg, [str(job)], _lchown=lambda p, u, g: touched.append(p))
    assert str(job / "a.dd") in touched and str(job / "sub" / "b.log") in touched
    assert str(job / "link") in touched            # the link itself (lchown), never its target
    assert not any(t.startswith("/etc") for t in touched)
    with pytest.raises(pp.Refused):
        pp.cmd_reclaim(cfg, [str(root)], _lchown=lambda *a: None)   # never the evidence root
    with pytest.raises(pp.Refused):
        pp.cmd_reclaim(cfg, ["/etc"], _lchown=lambda *a: None)


def test_unknown_subcommand_exits_2(capsys):
    assert pp.main(["chown", "-R", "svc", "/etc"]) == 2
    assert "unknown" in capsys.readouterr().err
