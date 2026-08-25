"""Windows Prefetch (.pf) parsing - one of the "more artifact types" flagged
as deferred (alongside Amcache/Recycle Bin, both shipped alongside this
module) when Part C's Registry/Event Log/LNK parsing landed. Prefetch is
execution evidence: Windows creates one .pf file per executable the first
few times it's actually run, recording the executable's own name, a run
count, and (on Windows 8+) up to 8 of its most recent run timestamps.

Uses libscca-python (import name `pyscca`) - confirmed live-installable on
this app's real deployed ARM64/Debian-trixie venv as a prebuilt manylinux
wheel (no source compile) before committing to it, matching this project's
own established, twice-burned "verify before adding a native dependency"
discipline. Mirrors core/registry_utils.py's/core/evtx_utils.py's exact
{artifact_type, title, url, value, timestamp, extra} record shape so the
shared, already-generic _record_parsed_artifacts()/parsed_artifacts table
and File Views' "Parsed Artifacts" rendering need zero changes for this new
source.

pyscca's get_last_run_time_as_integer(index) hands back a raw 64-bit
FILETIME integer, not a native datetime (confirmed live via pyscca's own
help() text on the real installed package, not assumed) - unlike
python-registry/python-evtx, which both already return tz-aware datetimes
internally. This is the real, concrete case core/registry_utils.py's
filetime_to_unix() helper (added alongside this module) exists for -
reused here rather than a second FILETIME-math implementation.

Disclosed, not silently skipped: this module's field-extraction logic was
verified against pyscca's real, live-confirmed API surface (file()/open()/
executable_filename/run_count/get_last_run_time_as_integer()/
get_number_of_filenames()/get_filename()), but - unlike the Registry/EVTX/
LNK modules, each verified against a real hand-built or legitimate public
fixture - no genuine, valid SCCA-format .pf file was available to parse
end-to-end this session (the on-disk format is compressed/checksummed in a
way that isn't practical to hand-construct correctly, and no legitimate
public sample was sourced). The parsing logic itself is unit-tested against
a stand-in object matching pyscca's real, confirmed API shape - this proves
the field extraction/record shaping is correct, but the full "read real
bytes off disk" path has not been exercised against a real .pf file. Flagged
as an open item for the next time a genuine Prefetch sample is available.
"""
import os

import pyscca

from core.registry_utils import filetime_to_unix

PREFETCH_EXTENSION = '.pf'

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

PREFETCH_SCAN_MAX_CANDIDATES = 500  # a real Prefetch folder commonly holds 128+ files
PREFETCH_SCAN_MAX_WALKED = 20_000
PREFETCH_MAX_REFERENCED_FILES = 20  # a .pf can reference hundreds of DLLs - keep the summary readable


def find_prefetch_files(root_dir):
    """Recursively finds real .pf files anywhere under root_dir (matched by
    extension, mirroring core/evtx_utils.py's find_evtx_files() - Prefetch
    files live in a fixed C:\\Windows\\Prefetch location on a real system,
    but this app only ever sees an already-extracted/copied evidence
    folder, so there's no real path convention left to anchor a directory-
    name check against). Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > PREFETCH_SCAN_MAX_WALKED:
                return found, True
            if fname.lower().endswith(PREFETCH_EXTENSION):
                found.append(os.path.join(root, fname))
                if len(found) >= PREFETCH_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def parse_prefetch_file(path):
    """Parses one .pf file into a single record (a Prefetch file describes
    one executable, unlike the Registry/EVTX modules' one-file-many-records
    shape) - executable name, run count, most recent run time, and a capped
    list of files referenced during execution (DLLs, config files, etc.,
    genuinely useful for spotting what a piece of malware actually touched)."""
    f = pyscca.file()
    try:
        f.open(path)
        try:
            exe_name = f.executable_filename or os.path.basename(path)
            run_count = f.get_run_count()
            raw_last_run = f.get_last_run_time_as_integer(0)
            last_run_ts = filetime_to_unix(raw_last_run)
            referenced = []
            for i in range(min(f.get_number_of_filenames(), PREFETCH_MAX_REFERENCED_FILES)):
                try:
                    referenced.append(f.get_filename(i))
                except Exception:
                    continue
            return [{
                "artifact_type": "prefetch_execution", "title": exe_name, "url": "",
                "value": f"run count: {run_count}", "timestamp": last_run_ts,
                "extra": {
                    "run_count": run_count,
                    "referenced_files": referenced,
                    "prefetch_hash": f.get_prefetch_hash(),
                },
            }]
        finally:
            f.close()
    except Exception as e:
        print(f"Warning: could not parse prefetch file {path}: {e}")
        return []
