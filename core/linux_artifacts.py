"""Linux forensic artifact parsing - shell history, /etc/passwd, cron jobs,
auth logs, and (Experimental) wtmp/btmp login records. Mirrors the existing
5 artifact-parser modules (core/browser_artifacts.py, core/registry_utils.py,
core/evtx_utils.py, core/prefetch_utils.py, core/recyclebin_utils.py) exactly
in shape - same {artifact_type, title, url, value, timestamp, extra} record
dict, so the shared, already-generic _record_parsed_artifacts()/
parsed_artifacts table and File Views' "Parsed Artifacts" rendering need
zero changes to support this new source.

This app had NO Linux-specific artifact parsing before this module - Sleuth
Kit (pytsk3) already reads ext2/3/4/xfs filesystems fine for browsing, but
nothing extracted artifact *content* the way the Windows modules already do.

Checked directly before writing this, not assumed: Sleuth Kit's own tool
suite (mmls/fls/icat/istat) is filesystem/volume-*structure* only, with no
concept of file content semantics - no Linux-artifact reuse available there.
For wtmp/utmp specifically, the one plausible PyPI candidate (`utmp`
21.10.0, pure Python) was installed and its real struct format inspected
directly: `struct.Struct('hi32s4s32s256shhiii4i20s')` computes to 384 bytes
- the old 32-bit-compat layout (4-byte session/sec/usec fields), which does
NOT match the real, live-verified 400-byte layout this app's own deployed
Pi (aarch64/glibc 2.41) actually produces (8-byte ut_session, 8-byte
tv_sec + 8-byte tv_usec - a genuine 64-bit LP64 build). That package would
silently misparse wtmp files from any modern 64-bit Linux system, which is
most real-world evidence - using it would have been worse than hand-rolling
this, not a safer shortcut, so it was not used.
"""
import os
import re
import struct
import time

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

LINUX_SHELL_HISTORY_FILENAMES = {'.bash_history', '.zsh_history', '.python_history'}
LINUX_SHELL_HISTORY_MAX_CANDIDATES = 100
LINUX_SHELL_HISTORY_MAX_WALKED = 20_000
LINUX_SHELL_HISTORY_MAX_LINES_PER_FILE = 20_000

LINUX_PASSWD_MAX_CANDIDATES = 20
LINUX_PASSWD_MAX_WALKED = 20_000

LINUX_CRON_MAX_CANDIDATES = 100
LINUX_CRON_MAX_WALKED = 20_000

LINUX_AUTH_LOG_MAX_CANDIDATES = 20
LINUX_AUTH_LOG_MAX_WALKED = 20_000
LINUX_AUTH_LOG_MAX_LINES_PER_FILE = 100_000
LINUX_AUTH_LOG_MAX_MATCHES_PER_FILE = 5_000

LINUX_WTMP_MAX_CANDIDATES = 10
LINUX_WTMP_MAX_WALKED = 20_000
LINUX_WTMP_MAX_RECORDS_PER_FILE = 50_000


def _walk_matching(root_dir, matcher, max_candidates, max_walked):
    """Shared os.walk-with-skip-list driver every find_* function below
    uses - matcher(dirpath, filename) -> bool decides what counts as a
    candidate. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > max_walked:
                return found, True
            if matcher(root, fname):
                found.append(os.path.join(root, fname))
                if len(found) >= max_candidates:
                    return found, True
    return found, False


def _mtime_epoch(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


# --- Shell history ---

_HISTTIMEFORMAT_MARKER_RE = re.compile(r'^#(\d{9,10})$')


def is_shell_history_candidate(name, path=None):
    return name in LINUX_SHELL_HISTORY_FILENAMES


def find_linux_shell_history_files(root_dir):
    return _walk_matching(root_dir, lambda dirpath, fname: is_shell_history_candidate(fname),
                           LINUX_SHELL_HISTORY_MAX_CANDIDATES, LINUX_SHELL_HISTORY_MAX_WALKED)


def parse_linux_shell_history_file(path, filename=None):
    """.bash_history/.zsh_history/.python_history - one command per line.
    No reliable timestamp unless HISTTIMEFORMAT was set (bash then prefixes
    each command with a '#<epoch>' marker line) - handled, but never
    guessed when absent.

    filename defaults to path's own basename (correct for a real-fs call,
    where path already IS the real file) - the in-image route passes the
    real in-image entry name explicitly, since path there is a meaningless
    temp-extracted filename, mirroring core/registry_utils.py's
    parse_registry_hive_file(path, filename) precedent for the exact same
    reason."""
    display_name = filename or os.path.basename(path)
    records = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            pending_ts = None
            for i, line in enumerate(f):
                if i >= LINUX_SHELL_HISTORY_MAX_LINES_PER_FILE:
                    break
                line = line.rstrip('\n')
                m = _HISTTIMEFORMAT_MARKER_RE.match(line.strip())
                if m:
                    pending_ts = float(m.group(1))
                    continue
                cmd = line.strip()
                if not cmd:
                    continue
                records.append({
                    "artifact_type": "linux_shell_history", "title": cmd, "url": "",
                    "value": cmd, "timestamp": pending_ts,
                    "extra": {"shell_history_file": display_name},
                })
                pending_ts = None
    except Exception as e:
        print(f"Warning: could not parse shell history {path}: {e}")
        return []
    return records


# --- /etc/passwd ---

def is_passwd_candidate(name, containing_dir):
    """containing_dir is the directory the file itself sits in - real-fs
    callers pass os.walk()'s own dirpath directly; in-image callers derive
    it from the full in-image path (see routes/image_browser.py's
    in-image counterpart) - both shapes land here identically so there is
    exactly one definition of 'what counts as a passwd file', not two
    that could drift apart."""
    if name.lower() != 'passwd':
        return False
    return os.path.basename((containing_dir or '').rstrip('/\\')).lower() == 'etc'


def find_linux_passwd_files(root_dir):
    return _walk_matching(root_dir, lambda dirpath, fname: is_passwd_candidate(fname, dirpath),
                           LINUX_PASSWD_MAX_CANDIDATES, LINUX_PASSWD_MAX_WALKED)


def parse_linux_passwd_file(path, filename=None):
    """/etc/passwd - colon-delimited username:x:uid:gid:gecos:home:shell.
    No per-record timestamp exists in this format at all - the file's own
    mtime is used as an honest 'state as of' proxy, same convention this
    app's core/registry_utils.py already established for Amcache/Uninstall
    keys when no dedicated timestamp value exists. filename is accepted
    (unused - the passwd record shape has no filename field to fill) only
    to keep all 5 parse_linux_*_file() signatures uniform, so the shared
    dispatchers below can call every one of them the same way."""
    records = []
    mtime = _mtime_epoch(path)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                fields = line.split(':')
                if len(fields) < 7:
                    continue
                username, _pw, uid, gid, gecos, home, shell = fields[:7]
                records.append({
                    "artifact_type": "linux_passwd_account", "title": username, "url": "",
                    "value": f"uid={uid} gid={gid} home={home} shell={shell}",
                    "timestamp": mtime,
                    "extra": {"uid": uid, "gid": gid, "gecos": gecos, "home": home, "shell": shell,
                              "timestamp_is_file_mtime": True},
                })
    except Exception as e:
        print(f"Warning: could not parse passwd file {path}: {e}")
        return []
    return records


# --- Cron jobs ---

_CRON_ENV_ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*=')


def is_cron_candidate(name, containing_dir):
    parts = (containing_dir or '').replace('\\', '/').lower().split('/')
    if 'cron.d' in parts:
        return True
    if 'spool' in parts and 'cron' in parts:
        return True
    return name == 'crontab'


def find_linux_cron_files(root_dir):
    return _walk_matching(root_dir, lambda dirpath, fname: is_cron_candidate(fname, dirpath),
                           LINUX_CRON_MAX_CANDIDATES, LINUX_CRON_MAX_WALKED)


def parse_linux_cron_file(path, filename=None):
    """/etc/crontab, /etc/cron.d/*, /var/spool/cron/**  - plain cron
    syntax lines. Skips comments, blank lines, and shell-style env-var
    assignment lines (e.g. PATH=/usr/bin) that aren't real scheduled jobs.
    filename - see parse_linux_shell_history_file()'s own docstring."""
    display_name = filename or os.path.basename(path)
    records = []
    mtime = _mtime_epoch(path)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if _CRON_ENV_ASSIGNMENT_RE.match(line):
                    continue
                records.append({
                    "artifact_type": "linux_cron_job", "title": line, "url": "",
                    "value": line, "timestamp": mtime,
                    "extra": {"cron_file": display_name, "timestamp_is_file_mtime": True},
                })
    except Exception as e:
        print(f"Warning: could not parse cron file {path}: {e}")
        return []
    return records


# --- auth.log / secure ---

_AUTH_LOG_FILENAME_RE = re.compile(r'^(auth\.log|secure)(\.\d+)?$', re.IGNORECASE)
_AUTH_LOG_COMPRESSED_RE = re.compile(r'^(auth\.log|secure)(\.\d+)?\.gz$', re.IGNORECASE)

_SYSLOG_LINE_RE = re.compile(
    r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<msg>.*)$'
)
_MONTH_NUM = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}

# Curated allowlist, matching this app's established EVTX-Event-ID-style
# curation - (event_kind, compiled regex against the syslog message body).
_AUTH_LOG_PATTERNS = [
    ("ssh_login_success", re.compile(r'sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)')),
    ("ssh_login_failure", re.compile(r'sshd\[\d+\]:\s+Failed (\S+) for (?:invalid user )?(\S+) from (\S+)')),
    ("sudo_command", re.compile(r'sudo:\s*(\S+)\s*:.*COMMAND=(.*)')),
    # Two real, distinct message formats seen in the wild: classic PAM
    # ("session opened for user admin(uid=1000) by (uid=0)") and newer
    # systemd-logind ("New session 5 opened for user admin.", which
    # inserts a session number between "session" and "opened" - a real
    # bug caught by this module's own test suite before shipping, not
    # found live) - \w+ (not \S+) for the username capture so it stops at
    # the first non-word character rather than swallowing trailing
    # punctuation/parenthesized uid info from either format.
    ("session_opened", re.compile(r'[Ss]ession(?: \d+)? opened for user (\w+)')),
    ("session_closed", re.compile(r'[Ss]ession closed for user (\w+)')),
]


def is_auth_log_candidate(name, containing_dir):
    if os.path.basename((containing_dir or '').rstrip('/\\')).lower() != 'log':
        return False
    return bool(_AUTH_LOG_FILENAME_RE.match(name)) or bool(_AUTH_LOG_COMPRESSED_RE.match(name))


def find_linux_auth_log_files(root_dir):
    return _walk_matching(root_dir, lambda dirpath, fname: is_auth_log_candidate(fname, dirpath),
                           LINUX_AUTH_LOG_MAX_CANDIDATES, LINUX_AUTH_LOG_MAX_WALKED)


def _infer_syslog_year(month_num, mtime_epoch):
    """Classic syslog lines carry no year. The log file's own mtime is a
    reasonable upper bound for its latest line - if a line's month is
    AFTER the mtime's month, that line must be from the previous year
    (the file spans a Dec->Jan rotation boundary). A per-line inference,
    not a single file-wide year, so a file spanning the boundary itself
    is still handled correctly line by line."""
    if mtime_epoch is None:
        return None
    mtime_struct = time.localtime(mtime_epoch)
    year = mtime_struct.tm_year
    if month_num > mtime_struct.tm_mon:
        year -= 1
    return year


def parse_linux_auth_log_file(path, filename=None):
    """auth.log/secure - curated regex allowlist for SSH login success/
    failure, sudo command execution, and PAM session open/close.
    Compressed (.gz) rotated logs are explicitly skipped (this module does
    no decompression anywhere) and reported as skipped, not silently
    dropped - see find_linux_auth_log_files()'s caller for the count.
    filename - see parse_linux_shell_history_file()'s own docstring."""
    display_name = filename or os.path.basename(path)
    if _AUTH_LOG_COMPRESSED_RE.match(display_name):
        return []
    records = []
    mtime = _mtime_epoch(path)
    matches_this_file = 0
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= LINUX_AUTH_LOG_MAX_LINES_PER_FILE or matches_this_file >= LINUX_AUTH_LOG_MAX_MATCHES_PER_FILE:
                    break
                line = line.rstrip('\n')
                m = _SYSLOG_LINE_RE.match(line)
                if not m:
                    continue
                month_num = _MONTH_NUM.get(m.group('mon'))
                if month_num is None:
                    continue
                year = _infer_syslog_year(month_num, mtime)
                ts = None
                if year is not None:
                    try:
                        ts = time.mktime((year, month_num, int(m.group('day')),
                                           int(m.group('hh')), int(m.group('mm')), int(m.group('ss')),
                                           0, 0, -1))
                    except (ValueError, OverflowError):
                        ts = None
                msg = m.group('msg')
                for event_kind, pattern in _AUTH_LOG_PATTERNS:
                    pm = pattern.search(msg)
                    if not pm:
                        continue
                    records.append({
                        "artifact_type": "linux_auth_log", "title": event_kind.replace('_', ' ').title(),
                        "url": "", "value": msg[:300], "timestamp": ts,
                        "extra": {"event_kind": event_kind, "host": m.group('host'),
                                  "year_inferred": True, "log_file": display_name},
                    })
                    matches_this_file += 1
                    break
    except Exception as e:
        print(f"Warning: could not parse auth log {path}: {e}")
        return []
    return records


# --- wtmp/btmp login records (Experimental) ---
# Verified live (2026-08-25) against the real deployed Pi's own installed
# glibc (aarch64, glibc 2.41) by compiling a small C program against its
# real /usr/include/utmp.h and printing sizeof(struct utmp) plus every
# field offset - NOT assumed from generic DFIR references, which commonly
# cite a 32-bit-compat 382/384-byte layout that does not match this (or
# most modern 64-bit) system. This is a raw C struct memory layout, not an
# OS-defined wire format like every other binary artifact this app parses
# (Windows Recycle Bin/Prefetch/Registry are all stable across the
# versions this app targets) - it genuinely varies by architecture/glibc
# build/compile flags. A wtmp file from evidence of unknown provenance
# could silently produce plausible-but-wrong output under this exact
# layout if it doesn't actually match - the self-check gate below exists
# specifically to catch that and refuse to guess, rather than emit
# confidently-wrong data into a forensic report.
UTMP_RECORD_STRUCT = struct.Struct('<h2xi32s4s32s256shhqqq4i24x')
assert UTMP_RECORD_STRUCT.size == 400, f"unexpected utmp record size {UTMP_RECORD_STRUCT.size}, expected 400"

UTMP_TYPE_USER_PROCESS = 7  # the only type that represents a real login event
_UTMP_VALID_TYPE_RANGE = range(0, 10)
_UTMP_VALID_SEC_MIN = 631152000    # 1990-01-01
_UTMP_VALID_SEC_MAX = 4102444800   # 2100-01-01


def is_wtmp_candidate(name, containing_dir):
    if name.lower() not in ('wtmp', 'btmp'):
        return False
    return os.path.basename((containing_dir or '').rstrip('/\\')).lower() == 'log'


def find_linux_wtmp_files(root_dir):
    return _walk_matching(root_dir, lambda dirpath, fname: is_wtmp_candidate(fname, dirpath),
                           LINUX_WTMP_MAX_CANDIDATES, LINUX_WTMP_MAX_WALKED)


def _wtmp_layout_plausible(records_raw):
    """Samples up to 5 decoded raw tuples and requires ALL of them to look
    like a real utmp record (a strict pass/fail gate, not a statistical
    guess) before trusting the file's layout at all."""
    if not records_raw:
        return True  # an empty/tiny file has nothing to contradict the layout
    sample = records_raw[:5]
    for ut_type, _pid, _line, _id, _user, _host, _e0, _e1, _session, sec, _usec, *_addr in sample:
        if ut_type not in _UTMP_VALID_TYPE_RANGE:
            return False
        if sec != 0 and not (_UTMP_VALID_SEC_MIN <= sec <= _UTMP_VALID_SEC_MAX):
            return False
    return True


def parse_linux_wtmp_file(path, filename=None):
    """wtmp/btmp - fixed-size 400-byte records (this exact system's real,
    live-verified layout - see the module-level comment above). Only
    ut_type == USER_PROCESS (7, a real login) records are emitted as
    forensic events; boot/runlevel/init housekeeping record types are
    walked (for the layout self-check) but not surfaced individually,
    matching this app's 'curated, not exhaustive' output philosophy.
    filename - see parse_linux_shell_history_file()'s own docstring."""
    display_name = filename or os.path.basename(path)
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Warning: could not read wtmp file {path}: {e}")
        return []

    if len(data) % UTMP_RECORD_STRUCT.size != 0 or len(data) == 0:
        return [{
            "artifact_type": "linux_wtmp_login", "title": "Layout mismatch - not parsed", "url": "",
            "value": "", "timestamp": None,
            "extra": {"layout_check_failed": True, "reason": "file size is not a multiple of 400 bytes",
                      "wtmp_file": display_name},
        }]

    n_records = len(data) // UTMP_RECORD_STRUCT.size
    n_records = min(n_records, LINUX_WTMP_MAX_RECORDS_PER_FILE)
    raw_records = [UTMP_RECORD_STRUCT.unpack_from(data, i * UTMP_RECORD_STRUCT.size) for i in range(n_records)]

    if not _wtmp_layout_plausible(raw_records):
        return [{
            "artifact_type": "linux_wtmp_login", "title": "Layout mismatch - not parsed", "url": "",
            "value": "", "timestamp": None,
            "extra": {"layout_check_failed": True,
                      "reason": "decoded fields did not look like real utmp records under this app's verified 400-byte layout",
                      "wtmp_file": display_name},
        }]

    records = []
    for raw in raw_records:
        ut_type, _pid, ut_line, _id, ut_user, ut_host, _e0, _e1, _session, sec, _usec, *_addr = raw
        if ut_type != UTMP_TYPE_USER_PROCESS:
            continue
        user = ut_user.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()
        line = ut_line.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()
        host = ut_host.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()
        if not user:
            continue
        records.append({
            "artifact_type": "linux_wtmp_login", "title": f"Login: {user}", "url": "",
            "value": f"{line}{' from ' + host if host else ''}",
            "timestamp": float(sec) if sec else None,
            "extra": {"tty": line, "host": host, "wtmp_file": display_name},
        })
    return records


# Shared dispatcher for the in-image route (routes/image_browser.py) -
# (is_candidate(name, containing_dir) -> bool, parse_fn(path) -> records)
# per artifact key. The real-fs route (routes/file_explorer.py) has its
# own equivalent (find_fn, parse_fn) dispatcher since its discovery
# already walks a real directory tree directly - this one exists because
# the in-image route instead drives _image_scan_candidate_files() with a
# single (name, in_image_path) matcher callback per type.
LINUX_ARTIFACT_IMAGE_MATCHERS = {
    "shell_history": (lambda name, path: is_shell_history_candidate(name), parse_linux_shell_history_file),
    "passwd_account": (lambda name, path: is_passwd_candidate(name, path.rsplit('/', 1)[0] if '/' in path else ''), parse_linux_passwd_file),
    "cron_job": (lambda name, path: is_cron_candidate(name, path.rsplit('/', 1)[0] if '/' in path else ''), parse_linux_cron_file),
    "auth_log": (lambda name, path: is_auth_log_candidate(name, path.rsplit('/', 1)[0] if '/' in path else ''), parse_linux_auth_log_file),
    "wtmp_login": (lambda name, path: is_wtmp_candidate(name, path.rsplit('/', 1)[0] if '/' in path else ''), parse_linux_wtmp_file),
}
LINUX_ARTIFACT_DEFAULT_TYPES = ["shell_history", "passwd_account", "cron_job", "auth_log"]
