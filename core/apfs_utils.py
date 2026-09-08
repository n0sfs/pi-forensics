"""macOS APFS (Apple File System) disk-image browsing - libfsapfs-python
(PyPI: libfsapfs-python, import name pyfsapfs), the libyal-family binding
for this format, matching the same family already used elsewhere in this
app (libscca-python/Prefetch, libpff-python/email, libvshadow-python/VSS,
libesedb-python/SRUM+Windows Search+WebCache+BITS).

Closes a real, previously-disclosed gap: pytsk3 (this app's whole existing
Sleuth Kit layer) has never had a "pool API" extension needed to open a
real APFS container at all - confirmed via a real 2020 upstream issue
(py4n6/pytsk#59: an attempt to force it segfaulted) - meaning this app's
File Explorer "Browse as Image" flow could not open virtually any Mac sold
since ~2017-2018 (every one of them APFS-only). HFS+ (pre-APFS Intel Macs,
some Time Machine/backup volumes) already worked before this module and is
unaffected - pytsk3 has had real HFS+ support since v3.1.0 (2010).

Confirmed live before writing this (not assumed from documentation),
against the real installed 20240429 package on the deployed station:
 - pyfsapfs.volume() raises NotImplementedError when constructed directly
   ("initialize of volume not supported") - a volume can ONLY be obtained
   via container.get_volume(index), confirmed live.
 - pyfsapfs.container().open_file_object(f) only actually calls f.read(size)/
   f.seek(offset, whence)/f.tell()/f.get_size() - confirmed via a minimal
   stub object with exactly those four methods and nothing else, which
   reached a real, specific libfsapfs superblock-parsing error rather than
   an AttributeError about a missing method. This is exactly the interface
   core/vshadow_utils.py's own _OffsetWindowFile already implements (built
   for pyvshadow's own, separately-confirmed, identical four-method
   protocol) - reused directly here rather than a second, near-duplicate
   windowed-file wrapper.
 - pyfsapfs.check_container_signature_file_object(f) is a real, dedicated
   module-level signature check - confirmed live to return False against
   300 bytes of garbage, and True against a synthetic 4096-byte buffer with
   the real NX superblock magic (b'NXSB') placed at byte offset 32 (an
   apfs_container's own obj_phys_t header is 32 bytes - o_checksum:8,
   o_oid:8, o_xid:8, o_type:4, o_subtype:4 - with the container-specific
   magic immediately after; independently constructed and verified live,
   not assumed from a single secondhand source). Raises a real OSError
   (not a silent False) when the underlying file is too short to even read
   the signature block - the module's own detect_apfs_container() below
   catches this and reports "no" rather than letting it propagate.

Volume timestamps (created/modified/accessed/inode-changed) are read via
the raw integer accessors (get_*_time_as_integer()) and converted as
nanoseconds-since-the-Unix-epoch, per Apple's own published "Apple File
System Reference" documentation for the on-disk j_inode_val crtime/mtime/
ctime/atime fields (a stable, public format spec, not a guess) - this is
the app's own newest genuinely distinct timestamp epoch/unit (following
WebKit-microseconds, Firefox-PRTime-microseconds, Windows FILETIME,
Cocoa/Core-Data seconds-or-nanoseconds, Android milliseconds, and .NET
Ticks - each already hand-rolled and independently tested elsewhere in
this codebase, since every one of those turned out to be genuinely
different math from the others). Unlike those other six, this specific
conversion has NOT been independently confirmed against a real pyfsapfs
instance and real APFS-formatted bytes (no such test image exists
anywhere in this project's fixtures, and none could be constructed
without genuine macOS tooling this ARM Linux appliance has no way to run)
- disclosed here, not silently assumed correct, matching this project's
already-established honesty convention for Prefetch/SRUM/RDP-Bitmap-Cache
before real samples existed for any of them.

Multi-volume containers ("Volume Groups" - a real macOS container commonly
holds 4-7 logical volumes: a large Data/System volume plus several small
utility volumes - Preboot, Recovery, VM, xART, etc.) are DELIBERATELY
scoped down in this first pass, the same "narrower but confidently
correct" call already made elsewhere in this app (ShellBags' one-level
breadcrumb, BITS's CONTROL-only scope, Jump Lists' non-hierarchical
CustomDestinations parse): open_apfs_container() always auto-selects the
single LARGEST volume by real reported size and browses only that one -
in practice this is reliably the actual user-data volume (Preboot/
Recovery/VM/xART volumes are always small, fixed-purpose utility
partitions by Apple's own design, dramatically smaller than a real Data
volume in any genuine installed system). Every other volume in the
container is still reported by name/size in the returned summary so an
examiner can SEE they exist, but there is no mechanism yet to switch
browsing to one of them - every existing offset-based route in this app
(routes/image_browser.py, 30+ call sites) hard-casts its offset parameter
via int(), which structurally rules out encoding a volume-selector into
that same value; building real volume-switching support would need a
second, disambiguating parameter threaded through every one of those call
sites, a materially larger, separate piece of work, not attempted here.

FileVault (APFS's own native encryption) has a real, working unlock API
on this library (is_locked()/set_password()/set_recovery_password()/
unlock()) but is explicitly OUT OF SCOPE for this initial pass - it
deserves its own "Encrypted Volume" UI integration (mirroring this app's
existing BitLocker/LUKS/VeraCrypt pattern) with its own dedicated design
and testing time, not a rushed bolt-on here. A locked/encrypted volume
this module can't unlock surfaces as a normal, honest open failure - real
information, not a crash.

Deleted-file recovery is NOT buildable via this library at all -
confirmed by grepping every source file in the real installed package for
delete/orphan/unalloc/recover/free_space concepts and finding none. The
underlying reason genuinely differs from this app's already-published
F2FS finding: APFS is itself copy-on-write (theoretically BETTER
recovery potential than most filesystems in principle), but real-world
SSD TRIM commonly defeats this in practice long before an examiner ever
receives the drive - a real hardware/firmware-level fact, not a library
limitation to work around. Every file_entry this module surfaces reports
deleted=False unconditionally, matching that honest boundary.

classify_image_profile() (core/tsk_utils.py) is DELIBERATELY NOT extended
to recognize APFS as a new "macos" profile bucket in this pass - Auto
Analyze (routes/auto_analyze.py + its own frontend step-selection logic)
has no macOS-specific default step sequence to offer at all yet, and
introducing a profile value the frontend can't render into a step list
would be a real regression (a silently-empty checklist), not a neutral
no-op. File Explorer's own direct "Browse as Image" flow (Search,
Timeline, Hash Manifest, Extract, Metadata, Geolocation Export, etc.) is
completely unaffected by this and works against an APFS image immediately,
since none of those routes read classify_image_profile() at all - only
Auto Analyze's own detect route does.
"""
import stat


APFS_NX_SUPERBLOCK_MAGIC_OFFSET = 32
APFS_NX_SUPERBLOCK_MAGIC = b'NXSB'


def apfs_ns_since_epoch_to_unix(raw_nanoseconds):
    """APFS on-disk timestamps (j_inode_val's crtime/mtime/ctime/atime) are
    a real uint64_t count of nanoseconds since the Unix epoch, per Apple's
    own published Apple File System Reference - a stable, public on-disk
    format spec. Deliberately its own small, named, testable function
    (matching this codebase's own established "never silently reuse a
    different epoch's conversion" discipline) even though the actual math
    here (a plain division) is simpler than any of this app's other seven
    hand-rolled epoch conversions - none of them share this same divisor,
    and mixing one up with another has been a real, live-caught bug more
    than once in this project's history."""
    if raw_nanoseconds is None:
        return None
    return raw_nanoseconds / 1_000_000_000


def detect_apfs_container(image_path, offset_bytes=0):
    """Cheap, read-only check for a real APFS container signature at a
    given BYTE offset within image_path - never raises (a too-short file,
    or one with no readable bytes at that offset, both report False, since
    check_container_signature_file_object() itself raises a real OSError
    for that case rather than returning False directly - confirmed live)."""
    try:
        import pyfsapfs
    except ImportError:
        return False

    # Local import to avoid a hard, always-on dependency between two
    # otherwise-independent modules - core/vshadow_utils.py has no reason
    # to know this module exists, only the reverse.
    from core.vshadow_utils import _OffsetWindowFile

    window = None
    try:
        window = _OffsetWindowFile(image_path, offset_bytes)
        return bool(pyfsapfs.check_container_signature_file_object(window))
    except Exception:
        return False
    finally:
        if window is not None:
            window.close()


def _select_primary_volume(container):
    """Auto-selects the single largest volume in a container by real
    reported size - see the module docstring for why this, not a real
    switching mechanism, is this pass's deliberate scope. Returns
    (selected_volume, selected_index, all_volume_summaries)."""
    count = container.get_number_of_volumes()
    summaries = []
    best_index = None
    best_size = -1
    best_volume = None
    for i in range(count):
        vol = container.get_volume(i)
        size = vol.get_size()
        name = vol.get_name()
        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='replace')
        summaries.append({"index": i, "name": name, "size": size})
        if size > best_size:
            best_size = size
            best_index = i
            best_volume = vol
    return best_volume, best_index, summaries


class ApfsFsAdapter:
    """Implements the narrow subset of pytsk3.FS_Info's own interface that
    every existing downstream caller in this app (routes/image_browser.py's
    30+ call sites, core/tsk_utils.py's own _tsk_list_dir/_tsk_walk/
    _tsk_stream_file, routes/reporting.py's _collect_case_timeline()) has
    ever actually used - confirmed via a direct grep of every real
    .open_meta()/.open_dir()/.info.meta.*/.info.name.*/.read_random()/
    .info.ftype access pattern in the codebase before writing this class,
    not assumed. core/tsk_utils.py's own _tsk_open_fs() dispatches to this
    class instead of a real pytsk3.FS_Info whenever pytsk3 itself can't
    open the image but this module's own signature check confirms it's a
    real APFS container - every downstream caller keeps working completely
    unchanged, since it never sees the difference."""

    def __init__(self, image_path, offset_bytes):
        import pyfsapfs
        from core.vshadow_utils import _OffsetWindowFile

        self._window = _OffsetWindowFile(image_path, offset_bytes)
        self._container = pyfsapfs.container()
        self._container.open_file_object(self._window)
        volume, index, summaries = _select_primary_volume(self._container)
        if volume is None:
            self.close()
            raise OSError("APFS container has no volumes.")
        self._volume = volume
        self.selected_volume_index = index
        self.all_volumes = summaries
        self.info = _FakeFsInfo()

    def close(self):
        try:
            self._container.close()
        except Exception:
            pass
        self._window.close()

    def open_dir(self, inode=None, path=None):
        if inode is not None:
            entry = self._volume.get_file_entry_by_identifier(int(inode))
        elif path is not None:
            entry = self._volume.get_file_entry_by_path(path)
        else:
            entry = self._volume.get_root_directory()
        if entry is None:
            raise OSError(f"APFS: no entry found for inode={inode!r} path={path!r}")
        return ApfsDirAdapter(entry)

    def open_meta(self, inode):
        entry = self._volume.get_file_entry_by_identifier(int(inode))
        if entry is None:
            raise OSError(f"APFS: no entry found for inode={inode!r}")
        return ApfsFileAdapter(entry)


class _FakeFsInfo:
    """A tiny stand-in for pytsk3.FS_Info's own .info attribute - only
    .ftype is ever read by any existing caller (core/tsk_utils.py's
    classify_image_profile(), which this module's docstring already
    explains is deliberately NOT extended to recognize APFS this pass -
    kept here anyway so a future caller reading .info.ftype off an
    ApfsFsAdapter gets a real, correct value instead of an AttributeError)."""
    def __init__(self):
        import pytsk3
        self.ftype = pytsk3.TSK_FS_TYPE_APFS


class _FakeName:
    __slots__ = ('name', 'type', 'flags', 'meta_addr')


class _FakeMeta:
    __slots__ = ('size', 'mtime', 'atime', 'ctime', 'crtime')


class _FakeEntryInfo:
    __slots__ = ('name', 'meta')


def _apfs_entry_to_tsk_shaped(file_entry, is_dir):
    """Builds the same .info.name.*/.info.meta.* shape core/tsk_utils.py's
    own _tsk_entry_dict() already reads off a real pytsk3 entry, from a
    real pyfsapfs.file_entry instead - deleted/is_virtual are always
    False/False (see the module docstring: neither concept exists for
    this library)."""
    import pytsk3

    name = file_entry.get_name()
    if isinstance(name, bytes):
        name_bytes = name
    elif name is None:
        name_bytes = b''
    else:
        name_bytes = name.encode('utf-8', errors='replace')

    fake_name = _FakeName()
    fake_name.name = name_bytes
    fake_name.type = pytsk3.TSK_FS_NAME_TYPE_DIR if is_dir else pytsk3.TSK_FS_NAME_TYPE_REG
    fake_name.flags = 0  # never TSK_FS_NAME_FLAG_UNALLOC - deleted is always False here
    fake_name.meta_addr = file_entry.get_identifier()

    fake_meta = _FakeMeta()
    fake_meta.size = file_entry.get_size()
    fake_meta.mtime = apfs_ns_since_epoch_to_unix(file_entry.get_modification_time_as_integer())
    fake_meta.atime = apfs_ns_since_epoch_to_unix(file_entry.get_access_time_as_integer())
    fake_meta.ctime = apfs_ns_since_epoch_to_unix(file_entry.get_inode_change_time_as_integer())
    fake_meta.crtime = apfs_ns_since_epoch_to_unix(file_entry.get_creation_time_as_integer())

    info = _FakeEntryInfo()
    info.name = fake_name
    info.meta = fake_meta
    return info


class _ApfsEntryAdapter:
    """One directory entry, shaped like a real pytsk3 entry object -
    exactly what core/tsk_utils.py's _tsk_entry_dict() already expects."""
    def __init__(self, file_entry):
        is_dir = stat.S_ISDIR(file_entry.get_file_mode() or 0)
        self.info = _apfs_entry_to_tsk_shaped(file_entry, is_dir)


class ApfsDirAdapter:
    """Iterable of _ApfsEntryAdapter, shaped like what pytsk3's own
    fs.open_dir() returns - what core/tsk_utils.py's _tsk_list_dir()
    already iterates directly."""
    def __init__(self, dir_file_entry):
        self._entry = dir_file_entry

    def __iter__(self):
        count = self._entry.get_number_of_sub_file_entries()
        for i in range(count):
            child = self._entry.get_sub_file_entry(i)
            if child is None:
                continue
            yield _ApfsEntryAdapter(child)


class ApfsFileAdapter:
    """Shaped like what pytsk3's fs.open_meta(inode=N) returns - only
    .info.meta.size and .read_random(offset, length) are ever read by any
    existing caller (core/tsk_utils.py's _tsk_stream_file(), confirmed via
    the same grep this module's own docstring already describes)."""
    def __init__(self, file_entry):
        self._entry = file_entry
        is_dir = stat.S_ISDIR(file_entry.get_file_mode() or 0)
        self.info = _apfs_entry_to_tsk_shaped(file_entry, is_dir)

    def read_random(self, offset, length):
        return self._entry.read_buffer_at_offset(length, offset)
