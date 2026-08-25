"""Hash-set filtering (Part D, D2) - station-wide known-good/known-bad
hash lists. core/config.py's load_hash_list_sets()/hash_list_file_path()
have no POSIX dependency and are tested directly here; routes/settings.py's
_parse_hash_list_text() validation logic needs core.jobs (POSIX pwd/fcntl,
via the settings blueprint's own imports) and is tested separately, skipped
on a non-POSIX dev machine like every other routes/*.py test in this suite.
"""
import os

import pytest

import core.config as config


def test_hash_list_file_path_lives_under_hash_lists_dir(hash_lists_dir):
    path = config.hash_list_file_path("my_list")
    assert path == os.path.join(str(hash_lists_dir), "my_list.txt")


def test_load_hash_list_sets_returns_empty_dict_for_no_ids(hash_lists_dir, runtime_config_file):
    assert config.load_hash_list_sets([]) == {}
    assert config.load_hash_list_sets(None) == {}


def test_load_hash_list_sets_loads_real_hashes_from_disk(hash_lists_dir, runtime_config_file):
    os.makedirs(str(hash_lists_dir))
    list_id = "known_malware"
    with open(config.hash_list_file_path(list_id), "w") as f:
        f.write("09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8\n")
        f.write("5d41402abc4b2a76b9719d911017c592d81c5cb\n")  # a second, unrelated-length line - real files can have mixed junk

    config.save_runtime_config({
        "hash_lists": [{
            "id": list_id, "name": "Known Malware", "algorithm": "sha256",
            "label": "known_bad", "hash_count": 2,
            "created_at": "2026-01-01 00:00:00", "updated_at": "2026-01-01 00:00:00",
        }]
    })

    result = config.load_hash_list_sets([list_id])
    assert list_id in result
    assert result[list_id]["name"] == "Known Malware"
    assert result[list_id]["label"] == "known_bad"
    assert result[list_id]["algorithm"] == "sha256"
    assert "09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8" in result[list_id]["hashes"]


def test_load_hash_list_sets_is_case_insensitive_on_stored_hashes(hash_lists_dir, runtime_config_file):
    os.makedirs(str(hash_lists_dir))
    list_id = "mixed_case"
    with open(config.hash_list_file_path(list_id), "w") as f:
        f.write("09ABE58E1025B54B8E020CE1560652F77D13F169F6DC596B5F2BB30111DF3C8\n")
    config.save_runtime_config({"hash_lists": [{"id": list_id, "name": "Mixed Case", "algorithm": "sha256",
                                                 "label": "known_bad", "hash_count": 1}]})
    result = config.load_hash_list_sets([list_id])
    assert "09abe58e1025b54b8e020ce1560652f77d13f169f6dc596b5f2bb30111df3c8" in result[list_id]["hashes"]


def test_load_hash_list_sets_silently_skips_a_missing_list_id(hash_lists_dir, runtime_config_file):
    config.save_runtime_config({"hash_lists": []})
    assert config.load_hash_list_sets(["does_not_exist"]) == {}


def test_load_hash_list_sets_silently_skips_metadata_with_no_real_file_on_disk(hash_lists_dir, runtime_config_file):
    # Metadata exists in runtime_config.json but the .txt file was never
    # written (or was deleted out-of-band) - must not raise, matching this
    # function's own documented "best-effort, not fatal" contract.
    config.save_runtime_config({"hash_lists": [{"id": "orphaned", "name": "Orphaned", "algorithm": "sha256",
                                                 "label": "known_bad", "hash_count": 5}]})
    assert config.load_hash_list_sets(["orphaned"]) == {}
