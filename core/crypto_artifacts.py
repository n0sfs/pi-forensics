"""Cryptocurrency wallet-FILE detection - a filename/path classifier, not a
content parser. Mirrors core/linux_artifacts.py's exact shape (same
_walk_matching()-style driver, same {artifact_type, title, url, value,
timestamp, extra} record dict, same try/except-never-raises convention) so
the shared, already-generic _record_parsed_artifacts()/parsed_artifacts
table and File Views' "Parsed Artifacts" rendering need zero changes to
support this new source.

A new module rather than folded into core/linux_artifacts.py - wallet files
are OS-agnostic (wallet.dat/Electrum/geth keystores all appear on Windows,
macOS, and Linux alike), matching this project's own "one module per
artifact domain, not per OS" convention.

Deliberately detection-only for v1: wallet.dat is a Berkeley DB container,
geth keystore files are AES-encrypted JSON, Electrum wallets are their own
encrypted format - none of these are meaningfully "parsed" into structured
fields the way a plaintext/SQLite artifact is. Each found file becomes one
record naming what it looks like and where it is; decrypting/parsing wallet
internals is explicitly out of scope here, the same honest-scoping already
applied to wtmp/utmp in core/linux_artifacts.py (self-aware about what it
can't do, rather than silently guessing).

The companion byte-regex categories (Bitcoin/Ethereum address patterns) are
NOT here - those live in core/case_index_db.py's TRIAGE_PATTERNS, since
every Triage Scan worker already iterates that dict generically by name and
needed zero other code changes to pick up two new categories.
"""
import os

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

CRYPTO_WALLET_MAX_CANDIDATES = 100
CRYPTO_WALLET_MAX_WALKED = 20_000

# Curated, not exhaustive - matches this project's existing curation
# philosophy (Volatility3's plugin list, the Registry-hive key list,
# scalpel.conf's signature set). Each entry: (exact_basename_or_None,
# required_parent_dir_or_None, path_substring_or_None, wallet_type_label).
_CURATED_WALLET_FILENAMES = {
    'wallet.dat': 'Bitcoin Core (or a Core-derived altcoin wallet)',
    'wallet.json': 'Generic JSON wallet export',
    'default_wallet': 'Electrum',
}


def is_crypto_wallet_candidate(fname, containing_dir):
    """Shared classifier both the real-fs os.walk driver below and
    routes/image_browser.py's in-image matcher call - containing_dir is
    either os.walk()'s own dirpath (real-fs) or the in-image parent
    directory derived from a full pytsk3 path (image mode); both land here
    identically so there is exactly one definition of "what counts as a
    wallet file", matching core/linux_artifacts.py's is_passwd_candidate()
    precedent for the same reason."""
    if fname in _CURATED_WALLET_FILENAMES:
        return True
    parent = os.path.basename((containing_dir or '').rstrip('/\\'))
    # geth/Ethereum keystore: UTC--<timestamp>--<address> under a folder
    # literally named "keystore".
    if parent.lower() == 'keystore' and fname.startswith('UTC--'):
        return True
    # Electrum: any file sitting directly under a "wallets" folder whose
    # own path also has a real ".electrum"/"electrum" path SEGMENT above it
    # (an exact segment match, like recyclebin_utils.py's own
    # _has_recyclebin_ancestor() precedent - not a bare substring-anywhere
    # check, which would false-positive on any unrelated path that merely
    # contains "electrum" somewhere, e.g. a folder named "MyElectrumBackups"
    # or - caught live while writing this module's own test suite - a
    # pytest temp-dir name derived from a test function's own name).
    # Electrum wallet filenames are examiner/user-chosen, so this is
    # best-effort path-shape matching, not a fixed name.
    if parent.lower() == 'wallets':
        segments = containing_dir.replace('\\', '/').split('/')
        if any(seg.lower() in ('.electrum', 'electrum') for seg in segments):
            return True
    return False


def _classify_wallet_type(path, fname):
    if fname in _CURATED_WALLET_FILENAMES:
        return _CURATED_WALLET_FILENAMES[fname]
    parent = os.path.basename(os.path.dirname(path).rstrip('/\\'))
    if parent.lower() == 'keystore' and fname.startswith('UTC--'):
        return 'Ethereum keystore (geth/Web3-derived)'
    if parent.lower() == 'wallets':
        return 'Electrum'
    return 'Unrecognized wallet-shaped file'


def find_crypto_wallet_files(root_dir):
    """Real-fs discovery - same os.walk-with-skip-list driver every other
    find_* function in this codebase uses. Returns (paths, truncated)."""
    found = []
    walked = 0
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > CRYPTO_WALLET_MAX_WALKED:
                return found, True
            if is_crypto_wallet_candidate(fname, root):
                found.append(os.path.join(root, fname))
                if len(found) >= CRYPTO_WALLET_MAX_CANDIDATES:
                    return found, True
    return found, False


def parse_crypto_wallet_file(path, filename=None):
    """One record per found file - detection-only, see module docstring for
    why internal wallet-format parsing is out of scope. filename defaults to
    path's own basename (real-fs call); the in-image route passes the real
    in-image entry name explicitly, matching every other parser module's
    parse_*_file(path, filename) convention."""
    display_name = filename or os.path.basename(path)
    try:
        size = os.path.getsize(path)
        mtime = os.path.getmtime(path)
    except OSError as e:
        print(f"Warning: could not stat crypto wallet candidate {path}: {e}")
        return []
    wallet_type = _classify_wallet_type(path, display_name)
    return [{
        "artifact_type": "crypto_wallet_file", "title": display_name, "url": "",
        "value": wallet_type, "timestamp": mtime,
        "extra": {"wallet_type": wallet_type, "file_size": size,
                  "note": "Detection only - internal wallet contents were not decrypted/parsed."},
    }]
