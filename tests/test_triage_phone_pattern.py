"""TRIAGE_PATTERNS['phone_numbers'] - widened 2026-09-16.

The old pattern was rb'\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b'. Measured against the
real compiled pattern on the deployed station, it matched only a bare NANP
number and missed every form a phone extraction actually produces: the leading
\\b cannot match between two digits, so any country-code prefix defeated it
outright, and '(' was never accepted at all. In a tool whose primary evidence
source is phones - contacts, SMS and call logs all store E.164 - that is
strict in exactly the wrong direction, and the opposite of the "loose pattern,
over-flag for a human to review" philosophy core/case_index_db.py states for
credit-card numbers two lines above it.

core/case_index_db.py imports no POSIX-only module, so this runs everywhere.
All numbers below are in the reserved +1-555-01xx fictional range.
"""
import time

import pytest

from core.case_index_db import TRIAGE_PATTERNS

PATTERN = TRIAGE_PATTERNS["phone_numbers"]


def _matches(text):
    return [m.group().decode() for m in PATTERN.finditer(text.encode())]


# --- The five real forms that silently produced zero hits before ---

@pytest.mark.parametrize("text,expected", [
    ("+15555550172", "+15555550172"),          # E.164 - what mobile artifacts store
    ("+1 555 555 0172", "+1 555 555 0172"),
    ("(555) 555-0172", "(555) 555-0172"),      # most common US written form
    ("+44 20 7946 0958", "+44 20 7946 0958"),  # international
    ("tel:+15555550172", "+15555550172"),      # as it appears in a vCard / href
])
def test_forms_that_used_to_be_missed_are_found(text, expected):
    assert _matches(text) == [expected]


# --- The forms that already worked must keep working ---

@pytest.mark.parametrize("text,expected", [
    ("555-555-0172", "555-555-0172"),
    ("5555550172", "5555550172"),
    ("555.555.0172", "555.555.0172"),
])
def test_the_previously_matching_forms_are_unchanged(text, expected):
    assert _matches(text) == [expected]


def test_a_number_embedded_in_real_text_is_found_whole():
    found = _matches("Contact: +15555550172 / jane@example.com, or call 555.555.0172 today")
    assert found == ["+15555550172", "555.555.0172"]


# --- Bounds: loose is fine, unbounded is not ---

@pytest.mark.parametrize("text", [
    "no digits here at all",
    "12345",
    "2026-09-16",
])
def test_things_that_are_not_phone_numbers_do_not_match(text):
    assert _matches(text) == []


def test_a_longer_digit_run_does_not_match_a_slice_of_itself():
    """The digit lookarounds replace \\b for exactly this - without them a
    16-digit card number would also be reported as a phone number hidden
    inside it."""
    assert _matches("4111111111111111") == []


def test_the_pattern_cannot_backtrack_pathologically():
    """Every repetition in both branches consumes at least one character, but
    this is a scanner pointed at attacker-supplied evidence bytes - assert the
    property rather than reasoning about it. The station's own keyword-list
    ReDoS gate exists for the same reason."""
    hostile = ("+" + "1" * 4000 + "!") * 20
    start = time.perf_counter()
    PATTERN.findall(hostile.encode())
    assert time.perf_counter() - start < 1.0
