"""Fuzzy hashing (TLSH - PyPI: py-tlsh, confirmed live-compilable on the
Pi's real ARM64 venv) - closes a real gap in this app's existing hash-set
matching (routes/file_explorer.py's check_hash_lists()), which is
exact-match only: a single byte changed in a known-bad file (a recompiled
malware variant, a lightly-edited document) is invisible to it. TLSH
produces a locality-sensitive digest where two files' digests can be
compared for SIMILARITY, not just equality - tlsh.diff() returns a
distance score (0 = identical, larger = less similar; TLSH's own
documented convention treats a distance under roughly 100 as
"meaningfully similar," used here as this module's default threshold,
adjustable per comparison).

Scoped deliberately as a standalone compute-and-compare capability, not a
deeper integration into the existing exact-match Hash Sets subsystem
(core/config.py's load_hash_list_sets(), Settings > Case & Reporting) -
that subsystem's storage format and management UI are built around exact
digests with a single "algorithm" per list; threading a genuinely
different match semantic (distance-under-threshold, not membership)
through it is real additional scope this pass didn't cover, disclosed
here rather than silently half-integrated.

TLSH's own real constraint, not a limitation of this wrapper: it refuses
to hash data with too little "entropy variety" (very small or very
uniform/repetitive files) - tlsh.hash() returns 'TNULL' in that case,
handled here as a clean "cannot compute" result, not an error.
"""

FUZZY_HASH_MIN_FILE_BYTES = 256  # TLSH's own practical minimum for a meaningful digest
FUZZY_HASH_DEFAULT_SIMILARITY_THRESHOLD = 100


def compute_tlsh_hash(path):
    """Computes a file's TLSH digest. Returns
    {"success", "error", "hash"} - "hash" is None (not an error) for a
    file too small/too uniform for TLSH to produce a meaningful digest
    from (TLSH's own real 'TNULL' sentinel), or if tlsh itself isn't
    installed."""
    try:
        import tlsh
    except ImportError:
        return {"success": False, "error": "The tlsh (fuzzy hashing) library is not installed on this station.", "hash": None}

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        return {"success": False, "error": f"Could not read file: {e}", "hash": None}

    if len(data) < FUZZY_HASH_MIN_FILE_BYTES:
        return {"success": True, "error": None, "hash": None,
                "note": f"File is smaller than {FUZZY_HASH_MIN_FILE_BYTES} bytes - too small for a meaningful TLSH digest."}

    digest = tlsh.hash(data)
    if not digest or digest == 'TNULL':
        return {"success": True, "error": None, "hash": None,
                "note": "TLSH could not compute a digest for this file (too uniform/low-entropy content, e.g. an empty or all-zero-byte file)."}
    return {"success": True, "error": None, "hash": digest, "note": None}


def compare_tlsh_hashes(hash_a, hash_b):
    """Compares two already-computed TLSH digests. Returns
    {"success", "error", "distance", "similar"} - "similar" uses
    FUZZY_HASH_DEFAULT_SIMILARITY_THRESHOLD, a real but disclosed
    approximation (TLSH's own guidance is that a genuinely meaningful
    threshold varies by file type/size - this is a reasonable general
    default, not a precisely-calibrated cutoff for every use case)."""
    try:
        import tlsh
    except ImportError:
        return {"success": False, "error": "The tlsh (fuzzy hashing) library is not installed on this station.", "distance": None, "similar": False}

    if not hash_a or not hash_b:
        return {"success": False, "error": "Both TLSH hashes are required.", "distance": None, "similar": False}
    try:
        distance = tlsh.diff(hash_a, hash_b)
    except Exception as e:
        return {"success": False, "error": f"Could not compare hashes (invalid TLSH format?): {e}", "distance": None, "similar": False}
    return {
        "success": True, "error": None, "distance": distance,
        "similar": distance <= FUZZY_HASH_DEFAULT_SIMILARITY_THRESHOLD,
    }
