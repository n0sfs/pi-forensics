"""PowerShell console command history (PSReadLine) -
%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\<HostName>_history.txt
- a plain-text, one-command-per-entry record of every command typed at a
PowerShell prompt, written by the PSReadLine module that's been the
default interactive-history mechanism since PowerShell 5.0/Windows 10
(2015+). Genuinely comparable in forensic value to this app's existing
Linux shell-history parser (core/linux_artifacts.py's
parse_linux_shell_history_file()), just for the Windows side.

Grounded via real research (2026-09-01) before any code was written:

- **The filename is NOT fixed** - it's driven by `$Host.Name` at write
  time, confirmed directly from PSReadLine's own real source
  (History.cs, PowerShell/PSReadLine on GitHub). The default interactive
  console (`powershell.exe`/`pwsh.exe`) produces `ConsoleHost_history.txt`
  - the dominant, populated case; VS Code's integrated terminal produces
  `Visual Studio Code Host_history.txt` if PSReadLine loads there.
  Windows PowerShell ISE does NOT use PSReadLine at all, so its own
  `Windows PowerShell ISE Host_history.txt` in the same folder is
  typically 0 bytes - not special-cased here, an empty file simply
  produces zero records on its own, no extra logic needed.
- **No timestamps are ever persisted to disk** - confirmed directly from
  PSReadLine's own source: `HistoryItem` tracks `StartTime`/
  `ApproximateElapsedTime` only in memory, never writes either to the
  history file. Every record from this module therefore has
  `timestamp: None`, the same honest null-timestamp treatment already
  established for Thumbcache (a format with the identical real absence,
  not a parsing gap on this app's own part).
- **Multi-line commands are joined via a real, confirmed backtick+
  newline continuation scheme** - PSReadLine's own write path does
  `item.CommandLine.Replace("\\n", "`\\n")` before appending to the file;
  on read, any physical line ending in a backtick is a continuation of
  the same logical command. Independently corroborated by a real, filed
  PSReadLine GitHub issue (#2244, "Command lines that end with a backtick
  cause history recall issues") describing exactly this mechanism
  breaking on a legitimately backtick-terminated single-line command -
  strong secondary confirmation this is real, load-bearing behavior, not
  a guess. This module's own reassembly logic strips the trailing
  backtick and rejoins with a real newline, mirroring PSReadLine's own
  write-side transform in reverse.

A distinct, separately-worth-building artifact this module deliberately
does NOT cover: PowerShell Script Block Logging (Microsoft-Windows-
PowerShell/Operational Event Log, Event ID 4104) - carries real
timestamps and full captured script text, but rides this app's existing
.evtx curated-allowlist pipeline (core/evtx_utils.py) rather than this
one, and extending that allowlist is a separate, smaller follow-up if
ever wanted, not part of this artifact.
"""
import os

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

POWERSHELL_HISTORY_PARENT_DIR_NAME = 'PSReadLine'
POWERSHELL_HISTORY_FILENAME_SUFFIX = '_history.txt'
POWERSHELL_HISTORY_SCAN_MAX_CANDIDATES = 20
POWERSHELL_HISTORY_SCAN_MAX_WALKED = 20_000
POWERSHELL_HISTORY_MAX_COMMANDS = 5_000
POWERSHELL_HISTORY_TITLE_MAX_LEN = 100


def find_powershell_history_files(root_dir):
    """Recursively finds real PSReadLine *_history.txt files - matched by
    BOTH the filename suffix AND the immediate parent directory being
    named 'PSReadLine' (case-insensitive), avoiding a false-positive
    match on some unrelated '*_history.txt' file elsewhere in the
    evidence tree that happens to share the naming convention. Returns
    (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        parent_name = os.path.basename(root)
        if parent_name.lower() != POWERSHELL_HISTORY_PARENT_DIR_NAME.lower():
            continue
        for fname in files:
            walked += 1
            if walked > POWERSHELL_HISTORY_SCAN_MAX_WALKED:
                return found, True
            if fname.lower().endswith(POWERSHELL_HISTORY_FILENAME_SUFFIX.lower()):
                found.append(os.path.join(root, fname))
                if len(found) >= POWERSHELL_HISTORY_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _host_name_from_filename(filename):
    """'ConsoleHost_history.txt' -> 'ConsoleHost'."""
    if filename.lower().endswith(POWERSHELL_HISTORY_FILENAME_SUFFIX.lower()):
        return filename[:-len(POWERSHELL_HISTORY_FILENAME_SUFFIX)]
    return filename


def _join_continuation_lines(raw_text):
    """Reassembles PSReadLine's backtick+newline multi-line continuation
    scheme back into real, individual command strings - see this
    module's own docstring for the confirmed real mechanism. Returns a
    list of complete command strings, in original order, blank lines
    dropped."""
    commands = []
    pending = None
    for line in raw_text.splitlines():
        if pending is not None:
            line = pending + '\n' + line
            pending = None
        if line.endswith('`'):
            pending = line[:-1]
            continue
        stripped = line.strip()
        if stripped:
            commands.append(line)
    if pending is not None and pending.strip():
        # A file that ends mid-continuation (a truncated/corrupted write) -
        # still surface the partial command rather than silently dropping it.
        commands.append(pending)
    return commands


def parse_powershell_history_file(path, filename=None):
    """Parses a real PSReadLine *_history.txt file into a list of
    {artifact_type: "powershell_console_history"} records, one per
    reassembled command - timestamp always None (see this module's own
    docstring for why that's a real, confirmed absence, not a gap).
    Returns [] on any read failure (missing file, permission error,
    genuinely undecodable bytes), the same best-effort tolerance every
    other parser in this app already applies."""
    name = filename or os.path.basename(path)
    host_name = _host_name_from_filename(name)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            raw_text = f.read()
    except OSError:
        return []

    commands = _join_continuation_lines(raw_text)
    records = []
    for cmd in commands[:POWERSHELL_HISTORY_MAX_COMMANDS]:
        first_line = cmd.splitlines()[0] if cmd else cmd
        title = first_line[:POWERSHELL_HISTORY_TITLE_MAX_LEN]
        if len(first_line) > POWERSHELL_HISTORY_TITLE_MAX_LEN or '\n' in cmd:
            title += '...'
        records.append({
            "artifact_type": "powershell_console_history", "title": title, "url": "",
            "value": cmd, "timestamp": None,
            "extra": {"host_name": host_name, "is_multiline": '\n' in cmd},
        })
    return records
