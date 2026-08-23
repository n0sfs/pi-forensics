"""core/case_index_db.py's ReDoS defense - check_regex_pattern_for_redos()
and its integration into build_scan_patterns() - a real finding from the
2026-08-22 security audit: an examiner-defined regex keyword-list pattern
compiled fine but was never checked for catastrophic backtracking, and ran
directly against raw, attacker-influenced evidence bytes with no timeout,
able to hang this app's single shared job slot indefinitely.

check_regex_pattern_for_redos() runs each probe in a genuinely separate OS
process (multiprocessing.Process + terminate()/kill() on timeout) - an
earlier version of this fix used a background thread instead, which turned
out to be actively unsafe: CPython's re engine doesn't release the GIL
during backtracking, so an "abandoned" thread can starve the whole process,
not just leak quietly. That was caught empirically (a 28-byte adversarial
string hung an entire test session), not just reasoned about - see the
dated comment in core/case_index_db.py for the full account.

Deliberately imports only core.case_index_db (no core.jobs), so this runs
on a non-POSIX dev machine too, unlike the routes/settings.py-level save-
time-rejection test (tests/test_keyword_list_redos_validation.py).
"""
import re

import core.case_index_db as case_index_db

# The textbook catastrophic-backtracking pattern: nested quantifier
# (a+)+ against a run of the "expected" character followed by one that
# breaks the match forces exhaustive exponential backtracking.
_EVIL_PATTERN = re.compile(rb"(a+)+$")


def test_check_regex_pattern_for_redos_flags_a_known_catastrophic_pattern():
    error = case_index_db.check_regex_pattern_for_redos(_EVIL_PATTERN)
    assert error is not None
    assert "backtracking" in error.lower() or "slow" in error.lower()


def test_check_regex_pattern_for_redos_does_not_flag_an_ordinary_safe_pattern():
    # No false positives - a normal, real-world-shaped pattern (matches
    # this app's own built-in email category) must pass cleanly.
    safe = re.compile(rb"[\w.+-]+@[\w-]+\.[\w.-]+", re.IGNORECASE)
    assert case_index_db.check_regex_pattern_for_redos(safe) is None


def test_check_regex_pattern_for_redos_does_not_flag_a_simple_alternation():
    safe = re.compile(rb"(?:foo)|(?:bar)|(?:baz)", re.IGNORECASE)
    assert case_index_db.check_regex_pattern_for_redos(safe) is None


def _save_keyword_list(list_id, terms, is_regex):
    import core.config as config
    cfg = config.load_runtime_config()
    cfg.setdefault("keyword_lists", []).append({
        "id": list_id, "name": list_id, "terms": terms, "is_regex": is_regex,
    })
    config.save_runtime_config(cfg)


def test_build_scan_patterns_silently_drops_a_catastrophic_custom_pattern(runtime_config_file):
    # This is what closes the gap for a keyword list saved BEFORE this fix
    # existed (no separate "already validated" flag to trust) - the check
    # runs here, once per scan job, not just at save time.
    _save_keyword_list("evil", [r"(a+)+$"], is_regex=True)
    patterns = case_index_db.build_scan_patterns(["evil"])
    assert "kw_evil" not in patterns
    # The 5 built-ins are always present regardless.
    assert set(case_index_db.TRIAGE_PATTERNS) <= set(patterns)


def test_build_scan_patterns_keeps_a_safe_custom_regex_pattern(runtime_config_file):
    _save_keyword_list("safe_re", [r"foo\d+bar"], is_regex=True)
    patterns = case_index_db.build_scan_patterns(["safe_re"])
    assert "kw_safe_re" in patterns
    assert patterns["kw_safe_re"].search(b"prefix foo123bar suffix")


def test_build_scan_patterns_never_redos_checks_a_plain_term_list(runtime_config_file):
    # Plain (non-regex) terms are always re.escape()'d - no backtracking
    # risk regardless of content - so a term that LOOKS like a dangerous
    # pattern, but is_regex=False, must still be included literally.
    _save_keyword_list("literal", ["(a+)+$"], is_regex=False)
    patterns = case_index_db.build_scan_patterns(["literal"])
    assert "kw_literal" in patterns
    assert patterns["kw_literal"].search(b"contains literally (a+)+$ right here")
