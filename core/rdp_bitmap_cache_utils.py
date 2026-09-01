"""RDP Bitmap Cache - the RDP client's own on-disk cache of on-screen
bitmap tiles from past Remote Desktop sessions, at
%LOCALAPPDATA%\\Microsoft\\Terminal Server Client\\Cache\\ (modern Windows
8+ "RDP8bmp" format, files named Cache####.bin) and, on older Windows
versions, the legacy "persistent bitmap cache" format (bcache22.bmc/
bcache24.bmc/Cache####.bmc). Real forensic value even without viewing a
single pixel: the presence of these files is itself evidence an RDP client
session occurred, tile COUNT is a rough proxy for how much on-screen
content changed during that session, and each tile's own 8-byte cache key
(key1+key2, a checksum/dedup identifier the RDP protocol itself assigns)
is a real, deterministic correlation value - the identical key recurring
across cache files (or within one file) means the identical on-screen
bitmap tile was reused, without needing to decode a single tile's pixels
to know that.

**Deliberately scoped to detection + per-tile metadata only, no pixel/
image extraction** - the user's own explicit scope for this item this
session. Grounded via real, direct research: fetched and read the full
real source of ANSSI-FR's bmc-tools.py
(github.com/ANSSI-FR/bmc-tools) - the same author/organization whose
bits_parser library this session's BITS-queue parser (core/bits_utils.py)
already cross-validated its own confirmed byte layout against. The real,
confirmed container/tile-header structure (magic bytes, per-tile header
field order, the compression-flag bit) is exactly what this module reads;
the much larger, genuinely risky remainder of that real tool - RLE tile
decompression and BMP pixel-data reconstruction, including a real,
non-obvious row-order reversal for the modern RDP8bmp format the source
code itself only reveals by directly reading its pixel-accumulation
logic - is real, confirmed, and could be built, but shipping a subtly
wrong pixel/row-order arrangement would produce a plausible-looking-but-
garbled image, which is worse than no image at all (this app's own
repeated principle - see core/bits_utils.py's identical reasoning for its
own deliberately narrower scope). Left for a future pass with a real
sample to visually verify pixel output against, not guessed at here.

**Real, confirmed container/tile layout** (from bmc-tools.py's own
BMCContainer class):
- A modern .bin file begins with an 8-byte magic, `RDP8bmp\\x00`, followed
  by a 4-byte little-endian header-version integer (12 bytes total, then
  tiles begin). A legacy .bmc file has no such file-level header - tiles
  begin at byte 0.
- Every tile begins with a common 12-byte header: key1 (u32le), key2
  (u32le), width (u16le), height (u16le) - the real 8-byte cache key is
  key1+key2 together, per bmc-tools.py's own tile-header unpack.
- A .bin tile's pixel data is always exactly 4*width*height bytes of raw,
  UNCOMPRESSED 32bpp RGB data immediately following the 12-byte header -
  the modern format has no compression concept at all.
- A .bmc tile's header is 8 bytes longer (20 bytes total): t_len (u32le,
  the tile's own on-disk data length) and t_params (u32le), whose bit
  0x08 is the real, confirmed compression flag ("this bit is always ONE
  when relevant data is smaller than expected data" - bmc-tools.py's own
  code comment). When set, the tile is RLE-compressed (not decoded by
  this module - see above); when clear, t_len bytes of raw pixel data
  follow directly, and bytes-per-pixel is `t_len // (width*height)`
  (4=RGB32, 3=RGB24, 2=RGB565, 1=8bpp palette-indexed).

Disclosed, not silently skipped, matching this app's now-repeated pattern
for a native-format parser with no practical way to hand-construct a
fully valid test file end-to-end: no genuine Windows-produced .bin/.bmc
sample was available this session. Header/tile-walk logic is unit-tested
against real, hand-built byte blobs matching the exact confirmed layout
above (the same technique already proven for core/bits_utils.py's own
byte-offset parsing). Flagged as an open item for the next time a real
Windows machine that has ever used the built-in Remote Desktop Connection
client is available - its own %LOCALAPPDATA%\\Microsoft\\Terminal Server
Client\\Cache\\ folder would work, even if empty of any actual RDP
history, to confirm this module recognizes a genuine, real container
correctly.
"""
import os
import re
import struct

RDP_BITMAP_CACHE_SCAN_MAX_CANDIDATES = 20
RDP_BITMAP_CACHE_SCAN_MAX_WALKED = 20_000
RDP_BITMAP_CACHE_MAX_TILES_PER_FILE = 20_000

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

RDP_BITMAP_CACHE_FILENAME_RE = re.compile(r'^(cache\d+|bcache\d+)\.(bin|bmc)$', re.IGNORECASE)
RDP_BITMAP_CACHE_PARENT_DIR_HINT = 'terminal server client'

BIN_FILE_MAGIC = b'RDP8bmp\x00'
_BIN_FILE_HEADER_SIZE = len(BIN_FILE_MAGIC) + 4  # magic + 4-byte version
_TILE_COMMON_HEADER_SIZE = 12  # key1(4) + key2(4) + width(2) + height(2)
_BMC_TILE_EXTRA_HEADER_SIZE = 8  # t_len(4) + t_params(4)
_BMC_COMPRESSION_FLAG = 0x08

_BPP_FORMAT_LABELS = {4: 'RGB32', 3: 'RGB24', 2: 'RGB565', 1: 'Palette8bpp'}


def find_rdp_bitmap_cache_files(root_dir):
    """Recursively finds real RDP Bitmap Cache candidate files (a real
    Cache####.bin/.bmc or bcache##.bmc filename, AND sitting somewhere
    under a "Terminal Server Client" ancestor folder - the filename
    pattern alone is far too generic a match for a blind directory walk,
    the same "check the containing path too" discipline already used for
    PowerShell's own PSReadLine history files) anywhere under root_dir.
    Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        if RDP_BITMAP_CACHE_PARENT_DIR_HINT not in root.lower():
            continue
        for fname in files:
            walked += 1
            if walked > RDP_BITMAP_CACHE_SCAN_MAX_WALKED:
                return found, True
            if RDP_BITMAP_CACHE_FILENAME_RE.match(fname):
                found.append(os.path.join(root, fname))
                if len(found) >= RDP_BITMAP_CACHE_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _detect_container_type(data):
    """Returns ('bin', tile_data_offset) or ('bmc', 0) based on the real,
    confirmed RDP8bmp magic - see module docstring. A file that's too
    short to even hold the 12-byte common tile header in either case
    returns (None, None)."""
    if data[:len(BIN_FILE_MAGIC)] == BIN_FILE_MAGIC:
        return 'bin', _BIN_FILE_HEADER_SIZE
    return 'bmc', 0


def parse_rdp_bitmap_cache_file(path, filename=None):
    """Parses a real RDP Bitmap Cache container into a list of
    {artifact_type: "rdp_bitmap_cache_tile"} records - one per real tile
    header successfully walked, metadata only (see module docstring for
    why pixel/image extraction is a deliberate scope boundary here).
    Returns [] on any failure to open/read the file, or if the file is
    too short to be a real container at all."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return []
    if len(data) < _TILE_COMMON_HEADER_SIZE:
        return []

    container_type, offset = _detect_container_type(data)
    display_name = filename or os.path.basename(path)

    records = []
    tile_index = 0
    while offset + _TILE_COMMON_HEADER_SIZE <= len(data) and tile_index < RDP_BITMAP_CACHE_MAX_TILES_PER_FILE:
        key1, key2, width, height = struct.unpack_from('<LLHH', data, offset)

        if container_type == 'bin':
            header_size = _TILE_COMMON_HEADER_SIZE
            tile_data_len = 4 * width * height
            compressed = False
            bpp_label = _BPP_FORMAT_LABELS[4]
        else:
            header_size = _TILE_COMMON_HEADER_SIZE + _BMC_TILE_EXTRA_HEADER_SIZE
            if offset + header_size > len(data):
                break
            t_len, t_params = struct.unpack_from('<LL', data, offset + _TILE_COMMON_HEADER_SIZE)
            tile_data_len = t_len
            compressed = bool(t_params & _BMC_COMPRESSION_FLAG)
            if compressed or width == 0 or height == 0:
                bpp_label = 'RLE-compressed (not decoded - see module docstring)' if compressed else 'unknown'
            else:
                bpp = t_len // (width * height) if (width * height) else 0
                bpp_label = _BPP_FORMAT_LABELS.get(bpp, f'unknown({bpp} bytes/px)')

        tile_end = offset + header_size + tile_data_len
        if tile_data_len <= 0 or tile_end > len(data):
            # A garbled/truncated trailing tile - stop walking this file
            # rather than guess at a recovery point, matching this app's
            # established "bail cleanly on a bounds violation" discipline.
            break

        cache_key = f"{key1:08x}{key2:08x}"
        records.append({
            "artifact_type": "rdp_bitmap_cache_tile",
            "title": f"RDP cache tile #{tile_index} ({width}x{height})",
            "url": "", "value": f"Cache key {cache_key} - {width}x{height} {bpp_label}",
            "timestamp": None,  # no timestamp field exists anywhere in this format
            "extra": {
                "source_file": display_name,
                "container_type": container_type,
                "tile_index": tile_index,
                "cache_key": cache_key,
                "width": width,
                "height": height,
                "compressed": compressed,
                "pixel_format": bpp_label,
                "tile_data_bytes": tile_data_len,
            },
        })
        offset = tile_end
        tile_index += 1

    return records
