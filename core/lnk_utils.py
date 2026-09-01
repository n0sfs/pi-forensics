"""Windows .lnk shortcut file parsing - a single-file artifact (not a
container to walk, unlike Registry hives/.evtx logs), reached via a
single selected-file "Analyze" action rather than a whole-directory scan.
Returns one record shaped like everything else in this app's parsed-
artifact family ({artifact_type, title, url, value, timestamp, extra}),
so it slots into the same _record_parsed_artifacts()/parsed_artifacts
table with zero storage-layer changes.

Verified end-to-end (2026-08-25) against a hand-built, MS-SHLLINK-spec-
valid .lnk file (target notepad.exe, real arguments/working-dir/icon-
location fields set) - confirmed get_json()'s exact field names/shapes,
including that LnkParse3 already hands back native Python datetime
objects for creation/accessed/modified time (no FILETIME conversion
needed here either, matching core/registry_utils.py's and
core/evtx_utils.py's own equivalent findings).

parse_lnk_from_filelike() (2026-09-01) is the core extraction logic
factored out from parse_lnk_file() so core/jumplist_utils.py can reuse
the exact same field-mapping for an embedded shortcut that never has a
file of its own on disk - an AutomaticDestinations numbered OLE2 stream
(already a real file-like object via olefile's openstream()) or a
CustomDestinations shortcut sliced out of a concatenated blob (wrapped in
io.BytesIO) - without a second, drifting copy of this logic."""
import io

from LnkParse3 import lnk_file


def parse_lnk_from_filelike(fh, name_hint=None, artifact_type="lnk_shortcut", extra_fields=None):
    """Core LNK-record extraction, given an already-open file-like object
    positioned at the start of one complete .lnk binary blob. Returns a
    single-element list (or [] on any parse failure) - same shape/
    tolerance every parser in this family already uses.

    artifact_type/extra_fields let a caller embedding this inside a larger
    container (Jump Lists) tag the resulting record with its own
    artifact_type and merge in container-specific enrichment (e.g. a
    DestList entry's own correlated pin-status/hostname/entry-number) -
    the LNK-field extraction itself never changes, only how the record is
    labeled/enriched around it."""
    try:
        parsed = lnk_file(fhandle=fh)
        data = parsed.get_json()
    except Exception as e:
        print(f"Warning: could not parse LNK data ({name_hint or 'unnamed'}): {e}")
        return []

    header = data.get('header', {}) or {}
    link_info = data.get('link_info', {}) or {}
    string_data = data.get('data', {}) or {}

    target = link_info.get('local_base_path') or link_info.get('common_path_suffix') or ''
    description = string_data.get('description') or ''
    # Windows-style backslash path, never a POSIX one - split manually
    # rather than os.path.basename(), which wouldn't recognize '\' as a
    # separator on this app's own Linux deployment.
    title = (target.split('\\')[-1] if target else (description or name_hint or 'shortcut.lnk'))

    modified_dt = header.get('modified_time')
    try:
        timestamp = modified_dt.timestamp() if modified_dt else None
    except Exception:
        timestamp = None

    extra = {
        "description": description,
        "arguments": string_data.get('command_line_arguments', ''),
        "working_directory": string_data.get('working_directory', ''),
        "icon_location": string_data.get('icon_location', ''),
        "relative_path": string_data.get('relative_path', ''),
        "created_time": str(header.get('creation_time', '')),
        "accessed_time": str(header.get('accessed_time', '')),
    }
    if extra_fields:
        extra.update(extra_fields)

    return [{
        "artifact_type": artifact_type,
        "title": title,
        "url": "",
        "value": target,
        "timestamp": timestamp,
        "extra": extra,
    }]


def parse_lnk_file(path, name_hint=None):
    """Parses one real .lnk file on disk and returns a single-element list
    (matching the list-of-records shape every other parser in this family
    returns) or [] on any parse failure - opens the file, delegates the
    actual field extraction to parse_lnk_from_filelike()."""
    try:
        with open(path, 'rb') as f:
            return parse_lnk_from_filelike(f, name_hint=name_hint)
    except OSError as e:
        print(f"Warning: could not read LNK file {path}: {e}")
        return []
