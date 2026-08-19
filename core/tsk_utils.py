"""Low-level pytsk3 (Sleuth Kit) helpers shared by routes/image_browser.py
and routes/reporting.py's _collect_case_timeline() (the MACB timeline some
report templates embed) - the only two routes/*.py modules that walk an
acquired disk image's filesystem directly.

Part of the app.py -> core/ + routes/ split - pure code motion, no
behavior change. See the dated CLAUDE.md entry for this refactor.
"""
import pytsk3

# These five constants must travel with the functions below rather than stay
# behind in routes/image_browser.py: TSK_DEFAULT_SECTOR_SIZE and
# TSK_READ_CHUNK_BYTES are referenced inside _tsk_open_fs/_tsk_stream_file's
# bodies, and TSK_MAX_WALK_DIRS/TSK_MAX_WALK_DEPTH are bound as *default
# argument values* on _tsk_walk() - default args are evaluated once, at
# function-definition time, so they must resolve correctly wherever this
# module itself is imported, not wherever a caller happens to live.
# TSK_MAX_TIMELINE_ENTRIES is also used directly by routes/image_browser.py's
# own /api/image/timeline route, independent of _collect_case_timeline().
TSK_DEFAULT_SECTOR_SIZE = 512  # matches the sector size this app's images have always assumed (mmls/fls/dc3dd never handled 4Kn-native source drives specially either - not a new limitation)
TSK_READ_CHUNK_BYTES = 1024 * 1024
TSK_MAX_TIMELINE_ENTRIES = 5000
TSK_MAX_WALK_DIRS = 5000   # safety cap against pathological/looping directory structures
TSK_MAX_WALK_DEPTH = 25

def _tsk_parse_inode(raw):
    """Directory/file navigation uses the base inode address only - NTFS's
    optional '-type-id' attribute-selector suffix (for alternate data
    streams) isn't chased here, same scope the old fls-based version had."""
    return int(str(raw).split('-')[0])

def _tsk_open_fs(image_path, offset_sectors):
    img = pytsk3.Img_Info(image_path)
    return pytsk3.FS_Info(img, offset=int(offset_sectors) * TSK_DEFAULT_SECTOR_SIZE)

def _tsk_entry_dict(entry):
    name = entry.info.name.name.decode('utf-8', errors='replace')
    meta = entry.info.meta
    return {
        "name": name,
        "inode": str(entry.info.name.meta_addr),
        "is_dir": entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR,
        "deleted": bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC),
        # TSK synthesizes its own pseudo-entries for filesystem-metadata regions -
        # $MBR/$FAT1/$FAT2 (TSK_FS_NAME_TYPE_VIRT) and $OrphanFiles (a virtual
        # *directory* of recovered-but-unlinked inodes, TSK_FS_NAME_TYPE_VIRT_DIR).
        # These aren't real evidence files a user created - a hash manifest or
        # similar "here are the files on this evidence" listing that included them
        # unfiltered would misrepresent what's actually on the filesystem.
        "is_virtual": entry.info.name.type in (pytsk3.TSK_FS_NAME_TYPE_VIRT, pytsk3.TSK_FS_NAME_TYPE_VIRT_DIR),
        "size": meta.size if meta else None,
        "mtime": meta.mtime if meta else None,
        "atime": meta.atime if meta else None,
        "ctime": meta.ctime if meta else None,
        "crtime": getattr(meta, 'crtime', None) if meta else None,
    }

def _tsk_list_dir(fs, inode_num):
    tsk_dir = fs.open_dir(inode=inode_num) if inode_num is not None else fs.open_dir(path='/')
    entries = []
    for entry in tsk_dir:
        if not entry.info.name or entry.info.name.name in (b'.', b'..'):
            continue
        try:
            entries.append(_tsk_entry_dict(entry))
        except Exception:
            continue  # one corrupt/unreadable directory entry shouldn't fail the whole listing
    return entries

def _tsk_walk(fs, start_inode_num=None, max_dirs=TSK_MAX_WALK_DIRS, max_depth=TSK_MAX_WALK_DEPTH):
    """Recursively walks a filesystem from start_inode_num (or root),
    yielding (entry_dict, path) for every entry found - shared by search and
    timeline below. Deliberately does not recurse into deleted directories:
    a deleted directory's inode may already have been reallocated to
    something unrelated, and walking it can loop or return garbage on a live
    evidence filesystem. Capped on both directories visited and depth as a
    safety net against reused-inode loops."""
    visited = [0]

    def _walk(inode_num, path, depth):
        if visited[0] >= max_dirs or depth > max_depth:
            return
        try:
            entries = _tsk_list_dir(fs, inode_num)
        except Exception:
            return
        visited[0] += 1
        for d in entries:
            entry_path = f"{path}/{d['name']}"
            yield d, entry_path
            if d['is_dir'] and not d['deleted']:
                yield from _walk(int(d['inode']), entry_path, depth + 1)

    yield from _walk(start_inode_num, '', 0)

def _tsk_stream_file(tsk_file, write_fn, max_bytes=None):
    size = tsk_file.info.meta.size if tsk_file.info.meta else 0
    if max_bytes is not None:
        size = min(size, max_bytes)
    read_offset = 0
    while read_offset < size:
        chunk = tsk_file.read_random(read_offset, min(TSK_READ_CHUNK_BYTES, size - read_offset))
        if not chunk:
            break
        write_fn(chunk)
        read_offset += len(chunk)
    return read_offset

def _tsk_resolve_filesystems(image_path):
    """Returns [{'offset': sectors, 'label': str}, ...] for every ALLOCATED
    partition (or the whole image, if unpartitioned) that opens as a real
    filesystem via pytsk3.

    Deliberately does NOT attempt to open every Volume_Info slot -
    Volume_Info lists unallocated/meta placeholder regions alongside real
    partitions (image_mmls() shows all of them for a human-readable
    listing, which is fine there), and a naive "try opening everything, keep
    what succeeds" approach can pick up a stale filesystem signature left in
    what's now unallocated space on media that was previously partitioned
    differently (repartitioned/re-imaged evidence is not unusual) - that
    would inject timeline entries from a filesystem that isn't actually part
    of the evidence's current layout, a real accuracy problem for a
    forensic report, not just noise. Filtering to TSK_VS_PART_FLAG_ALLOC
    entries only avoids that."""
    try:
        img = pytsk3.Img_Info(image_path)
    except Exception:
        return []

    try:
        vol = pytsk3.Volume_Info(img)
    except IOError:
        # No partition table - normal for a single-filesystem image (phone/
        # media card dd), same case image_mmls() already documents.
        try:
            _tsk_open_fs(image_path, 0)
            return [{"offset": 0, "label": "Whole Image"}]
        except Exception:
            return []

    filesystems = []
    for part in vol:
        if int(part.flags) != pytsk3.TSK_VS_PART_FLAG_ALLOC:
            continue
        try:
            _tsk_open_fs(image_path, part.start)
        except Exception:
            continue
        filesystems.append({"offset": part.start, "label": part.desc.decode('utf-8', errors='replace')})
    return filesystems
