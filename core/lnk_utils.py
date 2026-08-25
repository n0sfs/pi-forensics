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
"""
from LnkParse3 import lnk_file


def parse_lnk_file(path, name_hint=None):
    """Parses one .lnk file and returns a single-element list (matching
    the list-of-records shape every other parser in this family returns,
    for a uniform caller contract) or [] on any parse failure - same
    best-effort tolerance every other artifact parser in this app applies."""
    try:
        with open(path, 'rb') as f:
            parsed = lnk_file(fhandle=f)
            data = parsed.get_json()
    except Exception as e:
        print(f"Warning: could not parse LNK file {path}: {e}")
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

    value_parts = []
    if string_data.get('command_line_arguments'):
        value_parts.append(f"args={string_data['command_line_arguments']}")
    if string_data.get('working_directory'):
        value_parts.append(f"cwd={string_data['working_directory']}")
    if string_data.get('icon_location'):
        value_parts.append(f"icon={string_data['icon_location']}")

    return [{
        "artifact_type": "lnk_shortcut",
        "title": title,
        "url": "",
        "value": target,
        "timestamp": timestamp,
        "extra": {
            "description": description,
            "arguments": string_data.get('command_line_arguments', ''),
            "working_directory": string_data.get('working_directory', ''),
            "icon_location": string_data.get('icon_location', ''),
            "relative_path": string_data.get('relative_path', ''),
            "created_time": str(header.get('creation_time', '')),
            "accessed_time": str(header.get('accessed_time', '')),
        },
    }]
