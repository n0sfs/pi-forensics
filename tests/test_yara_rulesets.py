"""YARA rule scanning (Part D, D3) - station-wide rulesets. core/config.py's
get_yara_rulesets()/load_yara_ruleset_sources() have no POSIX dependency and
are tested directly here, matching test_hash_lists.py's exact structure;
routes/settings.py's _yara_ruleset_from_payload() validation (which actually
compiles the rule via yara.compile()) needs core.jobs (POSIX pwd/fcntl, via
the settings blueprint's own imports) and is tested separately in
tests/test_yara_rule_validation.py, skipped on a non-POSIX dev machine like
every other routes/*.py test in this suite.
"""
import core.config as config


def test_get_yara_rulesets_returns_empty_list_by_default(runtime_config_file):
    assert config.get_yara_rulesets() == []


def test_load_yara_ruleset_sources_returns_empty_dict_for_no_ids(runtime_config_file):
    assert config.load_yara_ruleset_sources([]) == {}
    assert config.load_yara_ruleset_sources(None) == {}


def test_load_yara_ruleset_sources_loads_real_records(runtime_config_file):
    config.save_runtime_config({
        "yara_rulesets": [{
            "id": "ruleset_a", "name": "Marker Rule",
            "rule_text": 'rule Marker { strings: $a = "pi-forensics-marker" condition: $a }',
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
        }]
    })
    result = config.load_yara_ruleset_sources(["ruleset_a"])
    assert result == {"ruleset_a": {"name": "Marker Rule",
                                     "rule_text": 'rule Marker { strings: $a = "pi-forensics-marker" condition: $a }'}}


def test_load_yara_ruleset_sources_silently_skips_a_missing_id(runtime_config_file):
    config.save_runtime_config({"yara_rulesets": []})
    assert config.load_yara_ruleset_sources(["does_not_exist"]) == {}


def test_load_yara_ruleset_sources_only_returns_the_requested_ids(runtime_config_file):
    config.save_runtime_config({
        "yara_rulesets": [
            {"id": "a", "name": "A", "rule_text": "rule A { condition: true }"},
            {"id": "b", "name": "B", "rule_text": "rule B { condition: true }"},
        ]
    })
    result = config.load_yara_ruleset_sources(["a"])
    assert set(result.keys()) == {"a"}
