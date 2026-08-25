"""routes/settings.py's _yara_ruleset_from_payload() - the save-time
validation every pasted YARA rule goes through before being written to
runtime_config.json (D3). Skipped (not failed) on a non-POSIX dev machine:
routes/settings.py needs core.jobs, which imports POSIX-only pwd/fcntl.

Deliberately compiles the rule via the real yara.compile() (not a mock or a
regex-shaped plausibility check) - the same compile step the scan routes
themselves run, so a rule accepted here is guaranteed to actually compile at
scan time too. yara-python's real install/compile/match API shape was
confirmed live on the Pi's ARM64 venv before writing this test or the routes
it exercises - see the dated CLAUDE.md entry for D3.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.settings needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.settings as settings

_VALID_RULE = 'rule ValidRule { strings: $a = "pi-forensics-yara-test-marker" condition: $a }'


def test_accepts_a_real_valid_rule():
    record, error = settings._yara_ruleset_from_payload({"name": "Test", "rule_text": _VALID_RULE})
    assert error is None
    assert record["name"] == "Test"
    assert record["rule_text"] == _VALID_RULE
    assert "updated_at" in record


def test_rejects_a_malformed_rule():
    record, error = settings._yara_ruleset_from_payload({"name": "Bad", "rule_text": "rule Bad { this is not valid yara"})
    assert record is None
    assert "did not compile" in error


def test_rejects_missing_name():
    record, error = settings._yara_ruleset_from_payload({"name": "", "rule_text": _VALID_RULE})
    assert record is None
    assert "name is required" in error


def test_rejects_missing_rule_text():
    record, error = settings._yara_ruleset_from_payload({"name": "Test", "rule_text": ""})
    assert record is None
    assert "Rule text is required" in error


def test_rejects_rule_text_over_the_max_length(monkeypatch):
    monkeypatch.setattr(settings, "YARA_RULESET_MAX_RULE_TEXT", 10)
    record, error = settings._yara_ruleset_from_payload({"name": "Test", "rule_text": _VALID_RULE})
    assert record is None
    assert "too long" in error


def test_a_rule_with_no_matching_strings_still_compiles():
    # A syntactically valid, condition-only rule (e.g. "condition: true") is
    # a legitimate YARA rule even with zero strings - must not be rejected.
    record, error = settings._yara_ruleset_from_payload({"name": "AlwaysTrue", "rule_text": "rule AlwaysTrue { condition: true }"})
    assert error is None
    assert record is not None
