"""Hash-set filtering (Part D, D2) - station-wide known-good/known-bad
hash lists. core/config.py's load_hash_list_sets()/hash_list_file_path()
have no POSIX dependency and are tested directly here; routes/settings.py's
_parse_hash_list_text() validation logic needs core.jobs (POSIX pwd/fcntl,
via the settings blueprint's own imports) and is tested separately, skipped
on a non-POSIX dev machine like every other routes/*.py test in this suite.
"""
import hashlib
import os

import pytest

import core.config as config

# Computed, not hand-typed - avoids the exact class of bug this file's own
# sibling test_hash_list_validation.py caught on its first Pi run (a
# memory-recalled "real" sha256 hash that turned out one character short).
_REAL_SHA256 = hashlib.sha256(b"pi-forensics-test-fixture").hexdigest()


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
        f.write(f"{_REAL_SHA256}\n")
        f.write(f"{hashlib.sha256(b'pi-forensics-test-fixture-2').hexdigest()}\n")

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
    assert _REAL_SHA256 in result[list_id]["hashes"]


def test_load_hash_list_sets_is_case_insensitive_on_stored_hashes(hash_lists_dir, runtime_config_file):
    os.makedirs(str(hash_lists_dir))
    list_id = "mixed_case"
    with open(config.hash_list_file_path(list_id), "w") as f:
        f.write(f"{_REAL_SHA256.upper()}\n")
    config.save_runtime_config({"hash_lists": [{"id": list_id, "name": "Mixed Case", "algorithm": "sha256",
                                                 "label": "known_bad", "hash_count": 1}]})
    result = config.load_hash_list_sets([list_id])
    assert _REAL_SHA256 in result[list_id]["hashes"]


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
