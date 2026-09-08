"""core/apfs_utils.py - macOS APFS disk-image browsing, the first library
in this app to open a filesystem pytsk3 itself can never open at all (a
real, confirmed upstream limitation - py4n6/pytsk#59).

Disclosed limitation, matching this module's own docstring: no genuine
APFS-formatted volume was available this session to open end-to-end (no
practical way to construct one without real macOS tooling, which this ARM
Linux appliance has no way to run, and libfsapfs itself is read-only -
same situation this project already hit for SRUM/Prefetch before real
samples existed for either). This file verifies:
 - detect_apfs_container() against REAL, byte-exact buffers written to
   disk (the NX superblock magic offset/value were independently
   confirmed live against the real installed pyfsapfs, not guessed - see
   the module's own docstring), a genuine end-to-end check of this one
   real, testable function.
 - Every adapter's field-extraction/shaping logic against stand-in
   objects mirroring pyfsapfs's real, live-confirmed API surface
   (container.get_number_of_volumes()/get_volume(i); a volume's
   get_size()/get_name()/get_root_directory()/get_file_entry_by_
   identifier()/get_file_entry_by_path(); a file_entry's get_name()/
   get_file_mode()/get_size()/get_identifier()/get_*_time_as_integer()/
   get_number_of_sub_file_entries()/get_sub_file_entry(i)/
   read_buffer_at_offset()) - matching tests/test_srum_utils.py's own
   already-established pattern for this exact situation.
 - core/tsk_utils.py's own _tsk_open_fs() 3-way dispatch (pytsk3 succeeds
   / pytsk3 fails but it's real APFS / pytsk3 fails and it isn't APFS
   either, so the ORIGINAL pytsk3 error must be the one that propagates).

Skipped (not failed) if libfsapfs-python isn't installed - a genuinely
optional pip dependency, and if pytsk3 itself isn't installed (this whole
module needs core.tsk_utils, POSIX-only).
"""
import os
import stat as stat_module

import pytest

pytest.importorskip("pyfsapfs", reason="libfsapfs-python not installed")
pytest.importorskip("pytsk3", reason="pytsk3 not installed")

import pytsk3

import core.apfs_utils as apfs_utils
import core.tsk_utils as tsk_utils


# --- apfs_ns_since_epoch_to_unix() ---

def test_ns_to_unix_none_stays_none():
    assert apfs_utils.apfs_ns_since_epoch_to_unix(None) is None


def test_ns_to_unix_zero_is_the_epoch():
    assert apfs_utils.apfs_ns_since_epoch_to_unix(0) == 0.0


def test_ns_to_unix_real_value():
    # 1_700_000_000 seconds since epoch (a real, plausible 2023-11-14
    # instant), expressed as nanoseconds - the exact conversion this
    # function exists to do.
    ns = 1_700_000_000 * 1_000_000_000
    assert apfs_utils.apfs_ns_since_epoch_to_unix(ns) == 1_700_000_000.0


# --- detect_apfs_container() - real bytes on real disk ---

def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_detect_apfs_container_true_for_real_nx_magic(tmp_path):
    block = bytearray(4096)
    block[apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET:apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET + 4] = \
        apfs_utils.APFS_NX_SUPERBLOCK_MAGIC
    path = _write(tmp_path, "real.img", bytes(block))
    assert apfs_utils.detect_apfs_container(path) is True


def test_detect_apfs_container_false_for_garbage(tmp_path):
    path = _write(tmp_path, "garbage.img", b"not-apfs-at-all" * 300)
    assert apfs_utils.detect_apfs_container(path) is False


def test_detect_apfs_container_false_for_too_short_file_not_raises(tmp_path):
    # A too-short read raises a real OSError from libfsapfs itself
    # (confirmed live) - detect_apfs_container() must swallow it and
    # report False, never propagate.
    path = _write(tmp_path, "tiny.img", b"x")
    assert apfs_utils.detect_apfs_container(path) is False


def test_detect_apfs_container_at_a_nonzero_offset(tmp_path):
    # Confirms the offset_bytes parameter is genuinely honored (the magic
    # sits mid-file, not at byte 0) - the same "opened at exactly the
    # right offset within a larger image" guarantee every other in-image
    # tool in this app already depends on.
    block = bytearray(4096)
    block[apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET:apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET + 4] = \
        apfs_utils.APFS_NX_SUPERBLOCK_MAGIC
    data = (b'\x00' * 65536) + bytes(block)
    path = _write(tmp_path, "offset.img", data)
    assert apfs_utils.detect_apfs_container(path, offset_bytes=65536) is True
    assert apfs_utils.detect_apfs_container(path, offset_bytes=0) is False


def test_detect_apfs_container_missing_file_returns_false_not_raises(tmp_path):
    assert apfs_utils.detect_apfs_container(str(tmp_path / "does-not-exist.img")) is False


# --- Stand-in objects mirroring the real, live-confirmed pyfsapfs API ---

class _FakeFileEntry:
    def __init__(self, name, is_dir, size=0, identifier=100,
                 crtime_ns=None, mtime_ns=None, atime_ns=None, ctime_ns=None,
                 children=None, content=b""):
        self._name = name
        self._mode = stat_module.S_IFDIR if is_dir else stat_module.S_IFREG
        self._size = size
        self._identifier = identifier
        self._crtime_ns = crtime_ns
        self._mtime_ns = mtime_ns
        self._atime_ns = atime_ns
        self._ctime_ns = ctime_ns
        self._children = children or []
        self._content = content

    def get_name(self):
        return self._name

    def get_file_mode(self):
        return self._mode

    def get_size(self):
        return self._size

    def get_identifier(self):
        return self._identifier

    def get_creation_time_as_integer(self):
        return self._crtime_ns

    def get_modification_time_as_integer(self):
        return self._mtime_ns

    def get_access_time_as_integer(self):
        return self._atime_ns

    def get_inode_change_time_as_integer(self):
        return self._ctime_ns

    def get_number_of_sub_file_entries(self):
        return len(self._children)

    def get_sub_file_entry(self, index):
        return self._children[index]

    def read_buffer_at_offset(self, size, offset):
        return self._content[offset:offset + size]


class _FakeVolume:
    def __init__(self, name, size, root_entry):
        self._name = name
        self._size = size
        self._root = root_entry
        self._by_id = {}

    def get_name(self):
        return self._name

    def get_size(self):
        return self._size

    def get_root_directory(self):
        return self._root

    def get_file_entry_by_identifier(self, identifier):
        return self._by_id.get(identifier)

    def get_file_entry_by_path(self, path):
        return None

    def register(self, entry):
        self._by_id[entry.get_identifier()] = entry
        return entry


class _FakeContainer:
    def __init__(self, volumes):
        self._volumes = volumes

    def get_number_of_volumes(self):
        return len(self._volumes)

    def get_volume(self, index):
        return self._volumes[index]

    def close(self):
        pass


# --- _select_primary_volume() ---

def test_select_primary_volume_picks_the_largest():
    small = _FakeVolume("Preboot", 500_000_000, _FakeFileEntry("/", True))
    big = _FakeVolume("Macintosh HD - Data", 900_000_000_000, _FakeFileEntry("/", True))
    tiny = _FakeVolume("Recovery", 600_000_000, _FakeFileEntry("/", True))
    container = _FakeContainer([small, big, tiny])

    selected, index, summaries = apfs_utils._select_primary_volume(container)

    assert selected is big
    assert index == 1
    assert len(summaries) == 3
    assert summaries[1]["name"] == "Macintosh HD - Data"
    assert summaries[1]["size"] == 900_000_000_000
    # Every volume is disclosed, even the ones not selected - the module's
    # own documented v1 scope (auto-select one, but report every real one).
    assert {s["name"] for s in summaries} == {"Preboot", "Macintosh HD - Data", "Recovery"}


def test_select_primary_volume_empty_container_returns_none():
    container = _FakeContainer([])
    selected, index, summaries = apfs_utils._select_primary_volume(container)
    assert selected is None
    assert index is None
    assert summaries == []


# --- _apfs_entry_to_tsk_shaped() / adapters ---

def test_entry_shaping_directory():
    entry = _FakeFileEntry("Documents", True, identifier=42,
                            crtime_ns=1_700_000_000_000_000_000)
    info = apfs_utils._apfs_entry_to_tsk_shaped(entry, is_dir=True)
    assert info.name.name == b"Documents"
    assert info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
    assert info.name.flags == 0  # never UNALLOC - deleted is always False for this library
    assert info.name.meta_addr == 42
    assert info.meta.crtime == 1_700_000_000.0


def test_entry_shaping_regular_file_and_timestamps():
    entry = _FakeFileEntry("notes.txt", False, size=1234, identifier=7,
                            mtime_ns=2_000_000_000_000_000_000,
                            atime_ns=2_100_000_000_000_000_000,
                            ctime_ns=2_200_000_000_000_000_000)
    info = apfs_utils._apfs_entry_to_tsk_shaped(entry, is_dir=False)
    assert info.name.type == pytsk3.TSK_FS_NAME_TYPE_REG
    assert info.meta.size == 1234
    assert info.meta.mtime == 2_000_000_000.0
    assert info.meta.atime == 2_100_000_000.0
    assert info.meta.ctime == 2_200_000_000.0
    assert info.meta.crtime is None  # never given one - stays None, not 0 or a fabricated value


def test_entry_adapter_derives_is_dir_from_real_file_mode():
    dir_entry = _FakeFileEntry("d", True)
    file_entry = _FakeFileEntry("f", False)
    assert apfs_utils._ApfsEntryAdapter(dir_entry).info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
    assert apfs_utils._ApfsEntryAdapter(file_entry).info.name.type == pytsk3.TSK_FS_NAME_TYPE_REG


def test_dir_adapter_iterates_real_children_and_skips_none():
    a = _FakeFileEntry("a.txt", False)
    b = _FakeFileEntry("b.txt", False)
    root = _FakeFileEntry("/", True, children=[a, None, b])
    names = [e.info.name.name for e in apfs_utils.ApfsDirAdapter(root)]
    assert names == [b"a.txt", b"b.txt"]  # the None child is silently skipped, not a crash


def test_file_adapter_read_random_delegates_to_read_buffer_at_offset():
    entry = _FakeFileEntry("payload.bin", False, size=11, content=b"hello world")
    adapter = apfs_utils.ApfsFileAdapter(entry)
    assert adapter.info.meta.size == 11
    assert adapter.read_random(0, 5) == b"hello"
    assert adapter.read_random(6, 5) == b"world"


# --- ApfsFsAdapter, exercised without ever touching a real container
# (monkeypatching pyfsapfs.container itself - proves the open_dir/
# open_meta dispatch logic, independent of whether a real APFS container
# can be constructed at all) ---

class _FakePyfsapfsContainer:
    """Stands in for the real pyfsapfs.container() the ApfsFsAdapter
    constructor instantiates internally - lets its open_dir()/open_meta()
    dispatch logic be tested without a real byte-level APFS container."""
    def __init__(self, volume):
        self._volume = volume
        self.opened_with = None

    def open_file_object(self, window):
        self.opened_with = window

    def get_number_of_volumes(self):
        return 1

    def get_volume(self, index):
        return self._volume

    def close(self):
        pass


def _make_adapter_with_fake_container(monkeypatch, tmp_path, volume):
    """Builds a real ApfsFsAdapter against a real (empty) file on disk,
    with pyfsapfs.container itself monkeypatched to hand back a fake
    container wrapping the given fake volume - isolates the adapter's own
    open_dir()/open_meta() logic from the real library entirely."""
    path = _write(tmp_path, "fake_container.img", b"\x00" * 4096)

    class _FakePyfsapfsModule:
        @staticmethod
        def container():
            return _FakePyfsapfsContainer(volume)

    # apfs_utils imports pyfsapfs INSIDE ApfsFsAdapter.__init__ (a local
    # import), so patching a module-level name would do nothing - patching
    # sys.modules is what a local `import pyfsapfs` actually resolves
    # against.
    import sys
    monkeypatch.setitem(sys.modules, "pyfsapfs", _FakePyfsapfsModule)
    return apfs_utils.ApfsFsAdapter(path, 0)


def test_apfs_fs_adapter_open_dir_root(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    volume = _FakeVolume("Data", 1000, root)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        dir_result = adapter.open_dir()  # no inode/path -> root
        assert isinstance(dir_result, apfs_utils.ApfsDirAdapter)
        assert adapter.selected_volume_index == 0
        assert adapter.all_volumes == [{"index": 0, "name": "Data", "size": 1000}]
    finally:
        adapter.close()


def test_apfs_fs_adapter_open_dir_by_inode(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    sub = _FakeFileEntry("Documents", True, identifier=99)
    volume = _FakeVolume("Data", 1000, root)
    volume.register(sub)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        result = adapter.open_dir(inode=99)
        assert isinstance(result, apfs_utils.ApfsDirAdapter)
    finally:
        adapter.close()


def test_apfs_fs_adapter_open_meta_by_inode(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    file_entry = _FakeFileEntry("payload.bin", False, identifier=55, size=3, content=b"abc")
    volume = _FakeVolume("Data", 1000, root)
    volume.register(file_entry)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        result = adapter.open_meta(inode=55)
        assert isinstance(result, apfs_utils.ApfsFileAdapter)
        assert result.info.meta.size == 3
        assert result.read_random(0, 3) == b"abc"
    finally:
        adapter.close()


def test_apfs_fs_adapter_open_dir_unknown_inode_raises_oserror(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    volume = _FakeVolume("Data", 1000, root)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        with pytest.raises(OSError):
            adapter.open_dir(inode=99999)
    finally:
        adapter.close()


def test_apfs_fs_adapter_open_meta_unknown_inode_raises_oserror(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    volume = _FakeVolume("Data", 1000, root)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        with pytest.raises(OSError):
            adapter.open_meta(inode=99999)
    finally:
        adapter.close()


def test_apfs_fs_adapter_info_ftype_is_apfs(monkeypatch, tmp_path):
    root = _FakeFileEntry("/", True, identifier=2)
    volume = _FakeVolume("Data", 1000, root)
    adapter = _make_adapter_with_fake_container(monkeypatch, tmp_path, volume)
    try:
        assert adapter.info.ftype == pytsk3.TSK_FS_TYPE_APFS
    finally:
        adapter.close()


def _make_adapter_zero_volumes(monkeypatch, tmp_path):
    path = _write(tmp_path, "zero_vol.img", b"\x00" * 4096)

    class _ZeroVolContainer:
        def open_file_object(self, window):
            pass

        def get_number_of_volumes(self):
            return 0

        def get_volume(self, index):
            raise AssertionError("should never be called - zero volumes")

        def close(self):
            pass

    class _FakePyfsapfsModule:
        @staticmethod
        def container():
            return _ZeroVolContainer()

    import sys
    monkeypatch.setitem(sys.modules, "pyfsapfs", _FakePyfsapfsModule)
    return apfs_utils.ApfsFsAdapter(path, 0)


def test_apfs_fs_adapter_zero_volumes_raises_oserror(monkeypatch, tmp_path):
    with pytest.raises(OSError, match="no volumes"):
        _make_adapter_zero_volumes(monkeypatch, tmp_path)


# --- core/tsk_utils.py's _tsk_open_fs() 3-way dispatch ---

def test_tsk_open_fs_dispatches_to_apfs_when_pytsk3_fails_but_it_is_real_apfs(monkeypatch, tmp_path):
    block = bytearray(4096)
    block[apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET:apfs_utils.APFS_NX_SUPERBLOCK_MAGIC_OFFSET + 4] = \
        apfs_utils.APFS_NX_SUPERBLOCK_MAGIC
    path = _write(tmp_path, "apfs.img", bytes(block) * 20)  # padded so pytsk3.Img_Info doesn't choke on a too-tiny file

    class _FakeImgInfo:
        def __init__(self, p):
            pass

    def _fs_info_always_fails(img, offset):
        raise IOError("Cannot determine file system type")

    monkeypatch.setattr(tsk_utils.pytsk3, "Img_Info", _FakeImgInfo)
    monkeypatch.setattr(tsk_utils.pytsk3, "FS_Info", _fs_info_always_fails)

    sentinel_adapter = object()

    def _fake_apfs_adapter(image_path, offset_bytes):
        assert image_path == path
        assert offset_bytes == 0
        return sentinel_adapter

    monkeypatch.setattr(apfs_utils, "ApfsFsAdapter", _fake_apfs_adapter)

    result = tsk_utils._tsk_open_fs(path, 0)
    assert result is sentinel_adapter


def test_tsk_open_fs_reraises_original_pytsk3_error_when_not_apfs_either(monkeypatch, tmp_path):
    path = _write(tmp_path, "garbage.img", b"not-apfs-and-not-any-real-filesystem" * 200)

    class _FakeImgInfo:
        def __init__(self, p):
            pass

    original_error = IOError("Cannot determine file system type")

    def _fs_info_always_fails(img, offset):
        raise original_error

    monkeypatch.setattr(tsk_utils.pytsk3, "Img_Info", _FakeImgInfo)
    monkeypatch.setattr(tsk_utils.pytsk3, "FS_Info", _fs_info_always_fails)

    with pytest.raises(IOError) as exc_info:
        tsk_utils._tsk_open_fs(path, 0)
    # The ORIGINAL pytsk3 exception must be what propagates, not a
    # different/generic one from the APFS fallback attempt - existing
    # callers' error handling for a genuinely unsupported filesystem must
    # see exactly the same error as before this fallback ever existed.
    assert exc_info.value is original_error


def test_tsk_open_fs_still_works_normally_when_pytsk3_succeeds(monkeypatch, tmp_path):
    path = _write(tmp_path, "whatever.img", b"\x00" * 4096)

    class _FakeImgInfo:
        def __init__(self, p):
            self.path = p

    sentinel_fs = object()
    calls = []

    def _fs_info_succeeds(img, offset):
        calls.append(offset)
        return sentinel_fs

    monkeypatch.setattr(tsk_utils.pytsk3, "Img_Info", _FakeImgInfo)
    monkeypatch.setattr(tsk_utils.pytsk3, "FS_Info", _fs_info_succeeds)

    result = tsk_utils._tsk_open_fs(path, 63)  # 63 sectors, a real, common partition-1 start offset
    assert result is sentinel_fs
    assert calls == [63 * tsk_utils.TSK_DEFAULT_SECTOR_SIZE]
