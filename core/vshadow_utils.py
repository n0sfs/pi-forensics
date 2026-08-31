"""Volume Shadow Copy (VSS) enumeration and materialization - libvshadow-
python (PyPI: libvshadow-python, confirmed live-installable on the Pi's
real ARM64/Debian-trixie venv as a genuine prebuilt manylinux2014_aarch64
wheel - zero compile step, unlike most of this session's other new
dependencies). Each shadow copy inside an NTFS volume is effectively a
point-in-time snapshot of that entire volume - closing a real gap this
app previously had zero awareness of.

Confirmed live before writing this module (not assumed from
documentation): pyvshadow.volume().open_file_object(file_object) expects
the file-like object to represent the WHOLE NTFS PARTITION's own bytes,
starting at a real, valid NTFS volume header (it reads and validates that
header itself) - not a bare VSS metadata blob. This is why
_OffsetWindowFile below exists: given a raw multi-partition disk image
and an already-resolved NTFS partition's own byte offset (from the same
_tsk_resolve_filesystems() every other in-image tool in this app already
uses), it presents a windowed file-like view starting at that offset, so
pyvshadow sees exactly the NTFS partition it expects regardless of where
that partition actually starts inside the larger image file.

Design choice, not the only possible one: a shadow copy is MATERIALIZED
(its full byte range copied out to a real file, exactly like a
"Convert Image Format" or "Logical Acquisition" output) rather than
exposed as a live, streamed pytsk3.Img_Info subclass. This is
deliberately the lower-risk integration path - it touches none of this
app's existing core/tsk_utils.py machinery (_tsk_open_fs/_resolve_
browsable_source, which every other in-image tool depends on and which a
mistake here could regress), and once materialized, the shadow copy is
just an ordinary raw NTFS image any of this app's already-verified tools
(Search/Timeline/Hash Manifest/Metadata/etc.) already work against with
zero further changes - reached via the same existing "Browse as Image"
flow. The tradeoff: a shadow copy can be as large as the original volume,
so materializing one is a real, potentially-large write, run as a
background job (matching this app's established shared-job-slot pattern)
rather than a synchronous request.

Known, disclosed limitation: this module's mechanics (the offset-window
file wrapper, pyvshadow's own file-object-open protocol) are verified
live against the real installed library - confirmed to correctly reject
non-NTFS bytes with a clean, specific error rather than crashing - but
the actual shadow-copy enumeration/materialization path has NOT been
exercised against a real NTFS volume with real Volume Shadow Copies,
since no such test image exists in this project's fixtures (VSS can only
be created by Windows itself, which this ARM Linux appliance has no way
to run). Matches this project's own established precedent (mquire,
pysim, BitLocker before real hardware existed) of shipping a
structurally-verified, functionally-disclosed capability rather than
withholding it entirely.
"""
import os

VSHADOW_READ_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB per chunk, matches this app's other large-copy loops


class _OffsetWindowFile:
    """A read-only file-like object presenting bytes [base_offset,
    base_offset + window_size) of an underlying file as if they started at
    position 0 - the exact protocol pyvshadow.volume().open_file_object()
    needs (plain read()/seek()/tell(), confirmed live against the real
    installed library). window_size defaults to "rest of the underlying
    file" when not known in advance."""

    def __init__(self, underlying_path, base_offset, window_size=None):
        self._f = open(underlying_path, 'rb')
        self._base_offset = base_offset
        underlying_size = os.fstat(self._f.fileno()).st_size
        self._window_size = window_size if window_size is not None else max(0, underlying_size - base_offset)
        self._f.seek(base_offset)
        self._pos = 0

    def read(self, size=-1):
        if self._pos >= self._window_size:
            return b''
        remaining = self._window_size - self._pos
        to_read = remaining if size is None or size < 0 else min(size, remaining)
        self._f.seek(self._base_offset + self._pos)
        data = self._f.read(to_read)
        self._pos += len(data)
        return data

    def seek(self, offset, whence=0):
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = self._window_size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        self._pos = max(0, min(new_pos, self._window_size))
        return self._pos

    def tell(self):
        return self._pos

    def get_size(self):
        return self._window_size

    def close(self):
        self._f.close()


def list_shadow_copies(image_path, partition_offset):
    """Opens the NTFS partition at partition_offset within image_path (a
    raw disk image, possibly multi-partition) via pyvshadow and returns a
    list of {index, identifier, creation_time, size} for each real shadow
    copy found. Returns {"success", "error", "stores"} - never raises;
    "not a real NTFS volume" / "no VSS present" both come back as a clean,
    specific error via "error" (confirmed live: pyvshadow reports this as
    a real OSError with a specific libvshadow message, not a silent empty
    result, so that message is surfaced directly rather than papered over)."""
    try:
        import pyvshadow
    except ImportError:
        return {"success": False, "error": "libvshadow-python (pyvshadow) is not installed on this station.", "stores": []}

    window = None
    vol = None
    try:
        window = _OffsetWindowFile(image_path, partition_offset)
        vol = pyvshadow.volume()
        vol.open_file_object(window)
        stores = []
        for i in range(vol.get_number_of_stores()):
            store = vol.get_store(i)
            stores.append({
                "index": i,
                "identifier": str(store.get_identifier()),
                "creation_time": store.get_creation_time().isoformat() if store.get_creation_time() else None,
                "creation_time_epoch": store.get_creation_time_as_integer(),
                "size": store.get_size(),
                "volume_size": store.get_volume_size(),
            })
        return {"success": True, "error": None, "stores": stores}
    except Exception as e:
        return {"success": False, "error": str(e), "stores": []}
    finally:
        if vol:
            try:
                vol.close()
            except Exception:
                pass
        if window:
            window.close()


def materialize_shadow_copy(image_path, partition_offset, store_index, output_path, progress_callback=None, should_stop=None):
    """Copies one shadow copy's full byte range out to a real raw-image
    file at output_path, in VSHADOW_READ_CHUNK_SIZE chunks - the resulting
    file is an ordinary raw NTFS volume image, browsable via this app's
    existing "Browse as Image" flow with zero further code needed.
    progress_callback(bytes_written, total_bytes), if given, is called
    after each chunk (matches this app's established job-progress-
    reporting pattern). should_stop(), if given, is polled between chunks
    to support cooperative cancellation (matches the Stop-button pattern
    every other background job in this app already uses). Returns
    {"success", "error", "bytes_written"}."""
    try:
        import pyvshadow
    except ImportError:
        return {"success": False, "error": "libvshadow-python (pyvshadow) is not installed on this station.", "bytes_written": 0}

    window = None
    vol = None
    out_f = None
    try:
        window = _OffsetWindowFile(image_path, partition_offset)
        vol = pyvshadow.volume()
        vol.open_file_object(window)
        if store_index < 0 or store_index >= vol.get_number_of_stores():
            return {"success": False, "error": f"Shadow copy index {store_index} does not exist in this volume.", "bytes_written": 0}
        store = vol.get_store(store_index)
        total_size = store.get_size()

        out_f = open(output_path, 'wb')
        written = 0
        while written < total_size:
            if should_stop and should_stop():
                return {"success": False, "error": "Stopped by user.", "bytes_written": written}
            chunk_size = min(VSHADOW_READ_CHUNK_SIZE, total_size - written)
            data = store.read(chunk_size)
            if not data:
                break
            out_f.write(data)
            written += len(data)
            if progress_callback:
                progress_callback(written, total_size)
        return {"success": True, "error": None, "bytes_written": written}
    except Exception as e:
        return {"success": False, "error": str(e), "bytes_written": 0}
    finally:
        if out_f:
            out_f.close()
        if vol:
            try:
                vol.close()
            except Exception:
                pass
        if window:
            window.close()
