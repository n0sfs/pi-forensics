"""core/case_index_db.py's build_scan_patterns()/resolve_scan_category_
label() - the mechanism that lets every triage-scan worker
(execution_worker_triage_scan, quick_triage_scan,
execution_worker_image_triage_scan) gain examiner-selected keyword-list
support by swapping the module-level TRIAGE_PATTERNS constant for this
function's return value locally, with zero other change to any of their
scanning logic. No POSIX dependency here (unlike routes/*.py, which mostly
need core.jobs) - runs on every platform.
"""
import core.case_index_db as case_index_db


def test_no_keyword_list_ids_returns_only_the_five_built_ins():
    patterns = case_index_db.build_scan_patterns(None)
    assert set(patterns.keys()) == set(case_index_db.TRIAGE_PATTERNS.keys())

    patterns_empty = case_index_db.build_scan_patterns([])
    assert set(patterns_empty.keys()) == set(case_index_db.TRIAGE_PATTERNS.keys())


def test_a_plain_term_list_compiles_and_matches_case_insensitively(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "suspects", "name": "Suspects", "terms": ["Alice Smith"], "is_regex": False},
    ])
    patterns = case_index_db.build_scan_patterns(["suspects"])
    assert "kw_suspects" in patterns
    assert patterns["kw_suspects"].search(b"an email mentions alice smith here") is not None
    assert patterns["kw_suspects"].search(b"nothing relevant here") is None


def test_a_plain_term_with_regex_metacharacters_is_escaped_not_interpreted(monkeypatch):
    # A literal term containing regex-special characters (a domain, a price)
    # must match itself literally, not be interpreted as a pattern.
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "iocs", "name": "IOCs", "terms": ["evil.example.com", "$1,234.56"], "is_regex": False},
    ])
    patterns = case_index_db.build_scan_patterns(["iocs"])
    assert patterns["kw_iocs"].search(b"seen contacting evilXexampleXcom today") is None  # '.' must not act as wildcard
    assert patterns["kw_iocs"].search(b"found evil.example.com in the logs") is not None
    assert patterns["kw_iocs"].search(b"paid $1,234.56 total") is not None


def test_a_regex_mode_list_compiles_terms_as_real_patterns(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "domains", "name": "Bad Domains", "terms": [r"evil\.\w+\.com"], "is_regex": True},
    ])
    patterns = case_index_db.build_scan_patterns(["domains"])
    assert patterns["kw_domains"].search(b"connects to evil.malware.com daily") is not None
    assert patterns["kw_domains"].search(b"connects to good.example.com daily") is None


def test_an_unselected_keyword_list_is_never_included(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "a", "name": "A", "terms": ["foo"], "is_regex": False},
        {"id": "b", "name": "B", "terms": ["bar"], "is_regex": False},
    ])
    patterns = case_index_db.build_scan_patterns(["a"])
    assert "kw_a" in patterns
    assert "kw_b" not in patterns


def test_a_list_with_no_usable_terms_is_silently_skipped(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "empty", "name": "Empty", "terms": ["", "   "], "is_regex": False},
    ])
    patterns = case_index_db.build_scan_patterns(["empty"])
    assert "kw_empty" not in patterns
    # Must not raise, and the 5 built-ins still come through untouched.
    assert set(patterns.keys()) == set(case_index_db.TRIAGE_PATTERNS.keys())


def test_a_broken_regex_list_is_silently_skipped_not_fatal(monkeypatch):
    # build_scan_patterns() itself must never crash a long-running scan over
    # a stale/broken saved list - the CRUD route (routes/settings.py) is
    # what rejects an invalid regex at save time; this is defense in depth
    # for a list that somehow got saved broken anyway (hand-edited config,
    # a future bug in that validation).
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "broken", "name": "Broken", "terms": ["foo(bar"], "is_regex": True},
    ])
    patterns = case_index_db.build_scan_patterns(["broken"])
    assert "kw_broken" not in patterns
    assert set(patterns.keys()) == set(case_index_db.TRIAGE_PATTERNS.keys())


def test_resolve_label_for_a_built_in_category():
    assert case_index_db.resolve_scan_category_label("emails") == "Email Addresses"


def test_resolve_label_for_a_keyword_list_category(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [
        {"id": "suspects", "name": "Suspects", "terms": ["alice"], "is_regex": False},
    ])
    assert case_index_db.resolve_scan_category_label("kw_suspects") == "Suspects"


def test_resolve_label_for_a_deleted_keyword_list_is_still_meaningful(monkeypatch):
    monkeypatch.setattr(case_index_db, "get_keyword_lists", lambda: [])
    label = case_index_db.resolve_scan_category_label("kw_no_longer_exists")
    assert "no_longer_exists" in label
    assert "deleted" in label.lower()


def test_resolve_label_for_an_unrecognized_category_falls_back_to_itself():
    assert case_index_db.resolve_scan_category_label("something_else") == "something_else"
