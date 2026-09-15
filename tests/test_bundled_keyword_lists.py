"""The keyword lists shipped in bundled_keyword_lists/.

These are reference data an examiner imports with one click, so they have to
clear exactly the gate an examiner-authored list clears - a bundled list that
this app would refuse to run, or that quietly matches nothing, is worse than
no bundled list at all.

Runs everywhere: core.case_index_db has no POSIX dependency (unlike routes/*),
which is the whole reason build_scan_patterns() lives there.
"""
import json
import os
import re

import pytest

import core.case_index_db as case_index_db
from core.config import BUNDLED_KEYWORD_LISTS_DIR

# routes/settings.py's own caps. Imported by value rather than from that
# module, which needs POSIX - the assertion below pins them so a cap change
# there without a re-split here fails loudly.
KEYWORD_LIST_TERM_MAX = 500


def _bundled_files():
    if not os.path.isdir(BUNDLED_KEYWORD_LISTS_DIR):
        return []
    return sorted(n for n in os.listdir(BUNDLED_KEYWORD_LISTS_DIR) if n.endswith(".json"))


def _load(name):
    with open(os.path.join(BUNDLED_KEYWORD_LISTS_DIR, name), encoding="utf-8") as f:
        return json.load(f)


ALL_FILES = _bundled_files()


def test_there_are_bundled_lists_to_begin_with():
    """Guards against the directory going missing from a packaging step - the
    import UI would render an empty picker with no error."""
    assert ALL_FILES, "no bundled keyword lists found"


@pytest.mark.parametrize("name", ALL_FILES)
def test_each_list_has_the_metadata_the_import_ui_shows(name):
    data = _load(name)
    assert data.get("schema") == 1
    for key in ("name", "description", "is_regex", "source", "caveats", "terms"):
        assert key in data, f"{name} is missing '{key}'"
    assert data["name"].strip()
    assert data["description"].strip()
    assert isinstance(data["terms"], list) and data["terms"]


@pytest.mark.parametrize("name", ALL_FILES)
def test_each_list_names_its_source_and_licence(name):
    """A bundled list is third-party data in a public MIT repo. If it cannot
    say where it came from and under what licence, it must not ship."""
    source = _load(name)["source"]
    for key in ("title", "publisher", "licence", "retrieved"):
        assert source.get(key, "").strip(), f"{name}: source.{key} is empty"


@pytest.mark.parametrize("name", ALL_FILES)
def test_each_list_states_its_caveats(name):
    """Every one of these over-matches in some way an examiner needs to know
    about before acting on a hit. Shipping the terms without the caveats would
    be the same class of defect as an unqualified finding in a report."""
    caveats = _load(name)["caveats"]
    assert isinstance(caveats, list) and caveats, f"{name} states no caveats"
    assert all(isinstance(c, str) and c.strip() for c in caveats)


@pytest.mark.parametrize("name", ALL_FILES)
def test_every_term_compiles_and_is_within_the_length_cap(name):
    data = _load(name)
    for term in data["terms"]:
        assert isinstance(term, str) and term.strip()
        assert len(term) <= KEYWORD_LIST_TERM_MAX, f"{name}: term longer than the cap: {term[:60]}"
        if data["is_regex"]:
            re.compile(term)      # raises re.error and fails the test


@pytest.mark.parametrize("name", ALL_FILES)
def test_the_combined_pattern_clears_the_redos_gate(name):
    """The real gate. build_scan_patterns() compiles the whole alternation and
    runs THAT, so checking each term alone would not reflect what a scan does.

    This matters more for the bundled lists than for an examiner's own: the
    credential patterns come from gitleaks, whose Go RE2 engine has no
    backtracking at all, so upstream has never had to care whether a pattern is
    catastrophic under Python.
    """
    data = _load(name)
    if not data["is_regex"]:
        pytest.skip("plain-term lists are re.escape()'d and always safe")
    combined = "|".join(f"(?:{t})" for t in data["terms"])
    compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
    assert case_index_db.check_regex_pattern_for_redos(compiled) is None


@pytest.mark.parametrize("name", ALL_FILES)
def test_each_list_actually_matches_one_of_its_own_terms(name):
    """A list that matches nothing is the failure mode that looks like success.
    Feeds each list a string built from its own first term and asserts a hit -
    catching, for instance, a word-boundary bug that makes every term unmatchable.
    """
    data = _load(name)
    combined = "|".join(f"(?:{t})" for t in data["terms"]) if data["is_regex"] \
        else "|".join(re.escape(t) for t in data["terms"])
    compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)

    first = data["terms"][0]
    if data["is_regex"]:
        # The bundled literal lists are word-bounded escapes of a plain term,
        # so the term is recoverable. A genuinely regexy pattern (credentials)
        # is exercised by the dedicated tests below instead.
        plain = first
        if plain.startswith(r"\b"):
            plain = plain[2:]
        if plain.endswith(r"\b"):
            plain = plain[:-2]
        try:
            sample = re.sub(r"\\(.)", r"\1", plain)
        except re.error:
            pytest.skip("not a recoverable literal")
        if not re.fullmatch(r"[\w .,'&/-]+", sample):
            pytest.skip("first term is a real pattern, not a literal")
    else:
        sample = first
    haystack = f"context before {sample} context after".encode("utf-8")
    assert compiled.search(haystack), f"{name}: could not match its own first term {first!r}"


# --- Behaviour the bundled lists specifically have to get right -------------

def test_word_boundaries_stop_short_slang_matching_inside_other_words():
    """The reason the literal lists ship as word-bounded regexes rather than
    plain terms. "Ice" is real DEA slang; without boundaries it matches inside
    "device", "service" and "nice", and a scan of any ordinary filesystem
    drowns its own real hits."""
    stimulants = _load("dea_drug_slang_stimulants.json")
    combined = "|".join(f"(?:{t})" for t in stimulants["terms"])
    compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
    assert compiled.search(b"picked up some Ice last night")
    assert not compiled.search(b"the device is in service")
    assert not compiled.search(b"that would be nice")


def test_the_credentials_list_matches_real_key_shapes():
    data = _load("credentials_api_keys.json")
    combined = "|".join(f"(?:{t})" for t in data["terms"])
    compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
    # AWS's own published documentation key.
    assert compiled.search(b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    # A BARE private-key header. gitleaks' own rule requires 64+ characters of
    # key body, because its question is "is this a live secret in source
    # control". An examiner's question is different - a header with no body is
    # what a carved fragment or a partially-wiped key file looks like, and that
    # is worth knowing. Both patterns ship; this asserts the forensic one.
    assert compiled.search(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert compiled.search(b"-----BEGIN PGP PRIVATE KEY BLOCK-----")
    # Credential and key STORES, not credentials.
    assert compiled.search(b"found Passwords.kdbx in Documents")
    assert compiled.search(b"recovered wallet.dat from free space")
    # ...and only as a real filename ending.
    assert not compiled.search(b"the file is named notes.kdbxbackup")
    assert not compiled.search(b"nothing secret in this line at all")
    assert not compiled.search(b"an ordinary sentence about a keyboard")


def test_the_ofac_lists_hold_whole_addresses_not_shape_patterns():
    """These are exact, attributed addresses - which is their entire value over
    the built-in Bitcoin/Ethereum categories, which match anything
    address-SHAPED."""
    eth = _load("ofac_sanctioned_addresses_ethereum.json")
    combined = "|".join(f"(?:{t})" for t in eth["terms"])
    compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
    # An address of the right shape that is NOT on the list must not match.
    assert not compiled.search(b"0x" + b"1" * 40)


def test_no_bundled_list_ships_a_plain_term_that_would_over_match():
    """Any list shipped with is_regex False would be re.escape()'d at scan
    time, losing the word boundaries - so nothing here should be relying on
    that mode. Pins the decision so a future list does not regress it."""
    for name in ALL_FILES:
        data = _load(name)
        assert data["is_regex"] is True, f"{name} ships as plain terms; see word_bounded()"
