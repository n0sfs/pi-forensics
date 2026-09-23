#!/usr/bin/python3 -I
"""pif-priv - the ONE privileged entry point for pi-forensics.

Installed by install.py as /usr/local/sbin/pif-priv (root:root, 0755), and
granted in sudoers as that exact path. The web app runs unprivileged; every
operation it needs root for goes through a subcommand here, and every
subcommand validates its own arguments. The point (2026-09-23 review): the
old sudoers grants (unpinned dd, dc3dd, mount, cp -a * *, chown -R svc *...)
made code execution as the service account equivalent to root. With this
helper, a compromised app can still only do what these subcommands allow.

Rules this file must keep:
  * Self-contained, standard library only. It must NEVER import from the
    app's own directory - that directory is writable by the service account,
    so importing it as root would itself be a privilege escalation. (That is
    also why `-I` is on the shebang: no PYTHONPATH, no user site, no cwd.)
  * Configuration comes from CONFIG_PATH (root-owned, written by install.py),
    never from argv or the environment.
  * Tools are executed by absolute path, with a clean environment, never via
    a shell. Long-running tools are exec'd (this process becomes the tool),
    so process-group and parent/child relationships the app relies on for
    Stop are exactly what they were when the app ran `sudo <tool>` directly.
  * Validation failures exit 2 with a one-line "pif-priv: ..." on stderr.

Everything above `main()` is pure or near-pure so the test suite can run it
off-device without root (tests/test_pif_priv.py).
"""
import json
import os
import re
import stat
import sys

CONFIG_PATH = "/etc/pi-forensics/priv.conf"

# Whole disks and partitions this app may ever touch. Same shapes as the
# app's own core/paths.py whitelist - duplicated on purpose (see above).
DEV_RE = re.compile(r'^/dev/(sd[a-z]|nvme\d+n\d+|mmcblk\d+)$')
PART_RE = re.compile(r'^/dev/(sd[a-z]\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$')
MAPPER_RE = re.compile(r'^/dev/mapper/pif_(luks|veracrypt)_[0-9a-f]{32}$')
HASHES = ("md5", "sha1", "sha256")
OUT_BASENAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,160}$')
SYSTEM_MOUNTPOINTS = ("/", "/boot", "/boot/firmware")

# The Pi 4B USB port map (core/paths.py, verified live 2026-09-05): a disk on
# bus1 sub-port 3 or 4 is in a black (utility) port; everything else -
# including anything on bus2, behind a hub, or unrecognised - is treated as
# evidence-only. Only a black-port disk may ever be made writable.
USB1_SUBPORT_RE = re.compile(r'/usb1/1-1/1-1\.([1-4])/1-1\.\1:')
USB_BLACK_SUBPORTS = {"3", "4"}

STOPPABLE_TOOLS = ("dc3dd", "dcfldd", "ewfacquire", "ewfexport", "affconvert", "ddrescue",
                   "photorec", "extundelete", "foremost", "scalpel")

CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class Refused(Exception):
    """An argument failed validation. main() turns this into exit 2."""


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

def load_config(path=CONFIG_PATH, _stat=os.stat, _open=open):
    """The service account and roots, from a root-owned file only. A config
    the service account could have edited would let it widen every check
    below, so ownership and mode are verified before it is trusted."""
    try:
        st = _stat(path)
    except OSError as e:
        raise Refused(f"configuration {path} is missing ({e.strerror})")
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise Refused(f"configuration {path} must be owned by root and not group/world-writable")
    with _open(path, "r") as f:
        cfg = json.load(f)
    for key in ("service_user", "evidence_root", "install_dir"):
        if not isinstance(cfg.get(key), str) or not cfg[key]:
            raise Refused(f"configuration is missing {key}")
    for key in ("evidence_root", "install_dir"):
        if not cfg[key].startswith("/") or cfg[key] == "/":
            raise Refused(f"configuration {key} must be an absolute path other than /")
    cfg["evidence_root"] = os.path.realpath(cfg["evidence_root"])
    cfg["install_dir"] = os.path.realpath(cfg["install_dir"])
    return cfg


# --------------------------------------------------------------------------
# validation helpers
# --------------------------------------------------------------------------

def disk_name_of(path):
    """Kernel name of the whole disk behind a path's filesystem, or None."""
    while path and not os.path.exists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    try:
        dev = os.stat(path).st_dev
        sys_path = os.path.realpath(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}")
    except (OSError, AttributeError):
        return None
    if not os.path.isdir(sys_path):
        return None
    if os.path.exists(os.path.join(sys_path, "partition")):
        sys_path = os.path.dirname(sys_path)
    return os.path.basename(sys_path)


def system_disks():
    return {n for n in (disk_name_of(mp) for mp in SYSTEM_MOUNTPOINTS) if n}


def parent_disk(dev):
    """'/dev/sdb1' -> 'sdb', '/dev/nvme0n1p2' -> 'nvme0n1', '/dev/sdb' -> 'sdb'."""
    name = os.path.basename(dev)
    m = re.match(r'^(nvme\d+n\d+|mmcblk\d+)p\d+$', name) or re.match(r'^(sd[a-z])\d+$', name)
    return m.group(1) if m else name


def require_block_device(path, allow_partition=False, allow_mapper=False, _system_disks=None):
    """A real block-device node matching the whitelist, not a symlink, and
    never (part of) the disk this system runs from."""
    ok = bool(DEV_RE.match(path or "")) or (allow_partition and bool(PART_RE.match(path or ""))) \
        or (allow_mapper and bool(MAPPER_RE.match(path or "")))
    if not ok:
        raise Refused(f"{path!r} is not a permitted device")
    try:
        st = os.lstat(path)
    except OSError:
        raise Refused(f"{path} does not exist")
    if not stat.S_ISBLK(st.st_mode):
        raise Refused(f"{path} is not a block device")
    if not MAPPER_RE.match(path):
        disks = system_disks() if _system_disks is None else _system_disks
        if parent_disk(path) in disks:
            raise Refused(f"{path} is this station's own system disk")
    return path


def require_under(path, root, *, allow_root=False):
    """realpath(path) must be `root` itself (only if allow_root) or inside it."""
    if not path or "\x00" in path:
        raise Refused("empty or invalid path")
    real = os.path.realpath(path)
    if real == root and allow_root:
        return real
    if not real.startswith(root.rstrip("/") + "/"):
        raise Refused(f"{path} is outside {root}")
    return real


def require_new_output_base(out_base, root, source_dev=None):
    """OUT_BASE = <existing dir under root>/<safe basename>. Returns the
    resolved base. The directory must not be on the source device (an image
    written into the disk being imaged corrupts the evidence)."""
    parent, base = os.path.split(out_base or "")
    if not OUT_BASENAME_RE.match(base):
        raise Refused(f"output name {base!r} is not permitted")
    real_parent = require_under(parent, root)
    if not os.path.isdir(real_parent) or os.path.islink(parent):
        raise Refused(f"output directory {parent} does not exist")
    if source_dev and not MAPPER_RE.match(source_dev):
        if disk_name_of(real_parent) == parent_disk(source_dev):
            raise Refused("the output directory is on the device being imaged")
    return os.path.join(real_parent, base)


def require_absent(*paths):
    for p in paths:
        if os.path.lexists(p):
            raise Refused(f"{p} already exists - refusing to overwrite")


def require_hashes(hashes):
    if not hashes:
        raise Refused("at least one hash algorithm is required")
    for h in hashes:
        if h not in HASHES:
            raise Refused(f"hash {h!r} is not permitted")
    if len(set(hashes)) != len(hashes):
        raise Refused("duplicate hash algorithm")
    return list(hashes)


def image_source(src, cfg, _system_disks=None):
    """What an imaging tool may read: a whole disk, an unlocked pif_* mapper,
    or a BitLocker dislocker-file under the app's own staging directory."""
    bitlocker_re = re.compile(
        r'^' + re.escape(cfg["install_dir"]) + r'/\.bitlocker_mounts/[0-9a-f]{32}/dislocker-file$')
    if bitlocker_re.match(src or ""):
        if os.path.islink(src) or not os.path.exists(src):
            raise Refused(f"{src} is not an unlocked BitLocker volume")
        return src
    return require_block_device(src, allow_mapper=True, _system_disks=_system_disks)


def usb_port_color(dev):
    """'black' | 'blue' | 'unknown' for a whole disk (fails closed)."""
    name = parent_disk(dev)
    link = f"/sys/class/block/{name}"
    real = os.path.realpath(link)
    if not real or real == link:
        return "unknown"
    if "/usb2/" in real:
        return "blue"
    m = USB1_SUBPORT_RE.search(real)
    if not m:
        return "unknown"
    return "black" if m.group(1) in USB_BLACK_SUBPORTS else "blue"


# --------------------------------------------------------------------------
# argv builders (pure - what each subcommand will exec)
# --------------------------------------------------------------------------

def argv_image_dc3dd(src, out_base, ext, hashes):
    if ext not in ("dd", "raw"):
        raise Refused("extension must be dd or raw")
    return (["/usr/bin/dc3dd", f"if={src}", f"of={out_base}.{ext}", f"log={out_base}_dc3dd.log"]
            + [f"hash={h}" for h in hashes],
            [f"{out_base}.{ext}", f"{out_base}_dc3dd.log"])


def argv_image_dcfldd(src, out_base, hashes):
    argv = ["/usr/bin/dcfldd", f"if={src}", f"of={out_base}.dd", "conv=noerror,sync",
            f"hash={','.join(hashes)}"] + [f"{h}log={out_base}_{h}.log" for h in hashes]
    return argv, [f"{out_base}.dd"] + [f"{out_base}_{h}.log" for h in hashes]


def argv_image_dd(src, out_base, direct):
    argv = ["/usr/bin/dd", f"if={src}", f"of={out_base}.dd", "bs=4M", "conv=noerror,sync",
            "status=progress"]
    if direct:
        argv.append("iflag=direct")
    return argv, [f"{out_base}.dd"]


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------

def _pw(cfg):
    import pwd
    return pwd.getpwnam(cfg["service_user"])


def cmd_reclaim(cfg, args, *, _lchown=None, _walk=None, _lstat=None):
    """Hand a job's output tree back to the service account. Replaces the
    `chown -R svc *` / `chgrp -R svc *` grants, which accepted ANY path
    (chown -R svc /etc is root). Never follows symlinks, never leaves the
    starting filesystem, never touches the evidence root itself."""
    _lchown = _lchown or os.lchown
    _walk = _walk or os.walk
    _lstat = _lstat or os.lstat
    if len(args) != 1:
        raise Refused("usage: reclaim PATH")
    root = require_under(args[0], cfg["evidence_root"])
    pw = _pw(cfg)
    top_dev = _lstat(root).st_dev
    _lchown(root, pw.pw_uid, pw.pw_gid)
    if stat.S_ISDIR(_lstat(root).st_mode):
        for dirpath, dirnames, filenames in _walk(root, followlinks=False):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                try:
                    st = _lstat(p)
                except OSError:
                    continue
                if st.st_dev != top_dev:
                    continue
                _lchown(p, pw.pw_uid, pw.pw_gid)
            dirnames[:] = [d for d in dirnames if _lstat(os.path.join(dirpath, d)).st_dev == top_dev]
    return 0


def cmd_blockdev(cfg, sub, args, *, _run=None, _system_disks=None):
    import subprocess
    run = _run or (lambda argv: subprocess.run(argv, env=CLEAN_ENV).returncode)
    if len(args) != 1:
        raise Refused(f"usage: {sub} DEVICE")
    dev = args[0]
    if sub in ("blockdev-getro", "blockdev-getsize"):
        require_block_device(dev, allow_partition=True, allow_mapper=True, _system_disks=_system_disks)
        flag = "--getro" if sub == "blockdev-getro" else "--getsize64"
    elif sub == "blockdev-setro":
        require_block_device(dev, allow_partition=True, _system_disks=_system_disks)
        flag = "--setro"
    elif sub == "blockdev-setrw":
        require_block_device(dev, allow_partition=True, _system_disks=_system_disks)
        # Re-derived here, not trusted from the app: only a disk in one of
        # the two black utility ports may ever be made writable.
        if usb_port_color(dev) != "black":
            raise Refused(f"{dev} is not in a black (utility) USB port - evidence ports stay read-only")
        flag = "--setrw"
    elif sub == "blockdev-flush":
        require_block_device(dev, _system_disks=_system_disks)
        flag = "--flushbufs"
    elif sub == "blockdev-rereadpt":
        if not re.match(r'^/dev/sd[a-z]$', dev):
            raise Refused("rereadpt is only for /dev/sd[a-z]")
        require_block_device(dev, _system_disks=_system_disks)
        flag = "--rereadpt"
    else:
        raise Refused(f"unknown subcommand {sub}")
    return run(["/usr/sbin/blockdev", flag, dev])


def cmd_smart(cfg, args, *, _exec=None, _system_disks=None):
    if len(args) != 1:
        raise Refused("usage: smart DEVICE")
    require_block_device(args[0], _system_disks=_system_disks)
    return (_exec or _execv)(["/usr/sbin/smartctl", "-a", "-j", args[0]])


def cmd_image(cfg, sub, args, *, _exec=None, _system_disks=None):
    """image-dc3dd SRC OUT_BASE {dd|raw} HASH...
       image-dcfldd SRC OUT_BASE HASH...
       image-dd SRC OUT_BASE {direct|nodirect}"""
    if len(args) < 3:
        raise Refused(f"usage: {sub} SRC OUT_BASE ...")
    src = image_source(args[0], cfg, _system_disks=_system_disks)
    out_base = require_new_output_base(args[1], cfg["evidence_root"], source_dev=src)
    if sub == "image-dc3dd":
        argv, outputs = argv_image_dc3dd(src, out_base, args[2], require_hashes(args[3:]))
    elif sub == "image-dcfldd":
        argv, outputs = argv_image_dcfldd(src, out_base, require_hashes(args[2:]))
    elif sub == "image-dd":
        if args[2] not in ("direct", "nodirect") or len(args) != 3:
            raise Refused("usage: image-dd SRC OUT_BASE {direct|nodirect}")
        argv, outputs = argv_image_dd(src, out_base, args[2] == "direct")
    else:
        raise Refused(f"unknown subcommand {sub}")
    require_absent(*outputs)
    return (_exec or _execv)(argv)


def cmd_read_device(cfg, args, *, _exec=None, _system_disks=None):
    """Stream a whole disk to stdout (the triage scanner reads it in Python)."""
    if len(args) != 1:
        raise Refused("usage: read-device DEVICE")
    require_block_device(args[0], _system_disks=_system_disks)
    return (_exec or _execv)(["/usr/bin/dd", f"if={args[0]}", "bs=8388608"])


def cmd_kill(cfg, sub, args, *, _run=None, _getpgrp=None, _getppid=None, _getpgid=None):
    import subprocess
    run = _run or (lambda argv: subprocess.run(argv, env=CLEAN_ENV).returncode)
    if sub == "kill-tools":
        if args:
            raise Refused("usage: kill-tools")
        for tool in STOPPABLE_TOOLS:
            run(["/usr/bin/pkill", "-9", "-x", tool])
        return 0
    if sub == "kill-pgroup":
        if len(args) != 1 or not re.fullmatch(r'[1-9][0-9]{0,9}', args[0]):
            raise Refused("usage: kill-pgroup PGID")
        pgid = int(args[0])
        _getpgrp = _getpgrp or os.getpgrp
        _getppid = _getppid or os.getppid
        _getpgid = _getpgid or os.getpgid
        # Never the group of whoever invoked us (the app itself), nor init's.
        forbidden = {1, _getpgrp()}
        try:
            forbidden.add(_getpgid(_getppid()))
        except OSError:
            pass
        if pgid in forbidden:
            raise Refused("refusing to kill the caller's own process group")
        return run(["/usr/bin/pkill", "-9", "-g", str(pgid)])
    if sub == "kill-children":
        if len(args) != 1 or not re.fullmatch(r'[1-9][0-9]{0,9}', args[0]):
            raise Refused("usage: kill-children PID")
        return run(["/usr/bin/pkill", "-9", "-P", args[0]])
    raise Refused(f"unknown subcommand {sub}")


def _execv(argv):
    os.execve(argv[0], argv, CLEAN_ENV)


SUBCOMMANDS = {
    "reclaim": lambda cfg, sub, a: cmd_reclaim(cfg, a),
    "blockdev-getro": cmd_blockdev, "blockdev-getsize": cmd_blockdev, "blockdev-setro": cmd_blockdev,
    "blockdev-setrw": cmd_blockdev, "blockdev-flush": cmd_blockdev, "blockdev-rereadpt": cmd_blockdev,
    "smart": lambda cfg, sub, a: cmd_smart(cfg, a),
    "image-dc3dd": cmd_image, "image-dcfldd": cmd_image, "image-dd": cmd_image,
    "read-device": lambda cfg, sub, a: cmd_read_device(cfg, a),
    "kill-tools": cmd_kill, "kill-pgroup": cmd_kill, "kill-children": cmd_kill,
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in SUBCOMMANDS:
        print(f"pif-priv: unknown or missing subcommand; one of: {', '.join(sorted(SUBCOMMANDS))}",
              file=sys.stderr)
        return 2
    try:
        cfg = load_config()
        rc = SUBCOMMANDS[argv[0]](cfg, argv[0], argv[1:])
        return rc if isinstance(rc, int) else 0
    except Refused as e:
        print(f"pif-priv: {argv[0]}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
