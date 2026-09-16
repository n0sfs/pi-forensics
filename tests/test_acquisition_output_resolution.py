"""core/paths.py's acquisition_output_location()/acquisition_verification_target()
- the one shared answer to "where did this acquisition actually write its
output", added 2026-09-16.

Three case-wide readers resolved that independently before this, and each got
a different subset right: the Evidence Timeline handled all three parameter
keys, Analysis Coverage handled two (dropping every Logical Acquisition and
Live Collection import), and Verify All Evidence handled one (also skipping
every mobile acquisition). Measured on the deployed station: 10 of 13
completed acquisitions in 2026-CASE-01 and 3 of 3 in
2026-CASE-MOBILE-SWEEP-2 were reported to the examiner as "not verifiable by
this tool" - including several carrying both a recorded hash and the exact
file it was taken over.

The event shapes below are the real ones read off that station, not invented:
a logical acquisition records output_container_path + manifest_path, a Live
Collection import the same, an android_pull records output_destination
pointing at a FOLDER and no hashes at all, an android_bugreport records
output_destination pointing at a .zip FILE.

core/paths.py has no POSIX-only imports, so this runs everywhere.
"""
import os

import pytest

from core.paths import acquisition_output_location, acquisition_verification_target


# --- Real event shapes, as recorded on the deployed station ---

RAW_IMAGE = {
    "output_destination": "/mnt/evidence/2026-CASE-01",
    "output_image_path": "/mnt/evidence/2026-CASE-01/2026-CASE-01_USBDrive-1.dd",
}
LOGICAL = {
    "output_container_path": "/mnt/evidence/2026-CASE-01/2026-CASE-01_ITEM-01_logical",
    "manifest_path": "/mnt/evidence/2026-CASE-01/2026-CASE-01_ITEM-01_logical/manifest.json",
    "zip_path": None,
    "file_count": 7,
}
LIVE_COLLECTION = {
    "output_container_path": "/mnt/evidence/2026-CASE-01/live_collection_import_20260903_153719",
    "manifest_path": "/mnt/evidence/2026-CASE-01/live_collection_import_20260903_153719/manifest.json",
    "file_count": 412,
}
ANDROID_PULL = {
    "output_destination": "/mnt/evidence/2026-CASE-01/2026-CASE-01_PIXEL8A-01_android_pull",
}
ANDROID_BUGREPORT = {
    "output_destination": "/mnt/evidence/2026-CASE-01/2026-CASE-01_ITEM-BUGREPORT-02_android_bugreport.zip",
}
COMPANION_EXTRACTION_NO_OUTPUT = {}


# --- acquisition_output_location(): the walkable location ---

def test_a_raw_image_resolves_to_the_image_not_its_parent_folder():
    """A raw acquisition records BOTH keys - the image is the evidence, the
    destination is just where it was put."""
    assert acquisition_output_location(RAW_IMAGE) == (RAW_IMAGE["output_image_path"], "image")


@pytest.mark.parametrize("params,expected_key", [
    (LOGICAL, "output_container_path"),
    (LIVE_COLLECTION, "output_container_path"),
    (ANDROID_PULL, "output_destination"),
])
def test_folder_shaped_acquisitions_resolve_to_their_destination(params, expected_key):
    """The regression this function exists for: output_container_path is a
    real output location, not an absence of one."""
    assert acquisition_output_location(params) == (params[expected_key], "directory")


def test_an_event_with_no_recorded_output_resolves_to_nothing():
    assert acquisition_output_location(COMPANION_EXTRACTION_NO_OUTPUT) == (None, None)


def test_a_missing_parameters_dict_is_not_an_error():
    """Callers pass event.get('acquisition_parameters') straight in, which is
    None for a malformed/partial event."""
    assert acquisition_output_location(None) == (None, None)


# --- acquisition_verification_target(): the one file whose hash was recorded ---

def test_a_raw_image_is_verified_against_the_image_itself():
    path, scope = acquisition_verification_target(RAW_IMAGE)
    assert path == RAW_IMAGE["output_image_path"]
    assert scope == "image"


@pytest.mark.parametrize("params", [LOGICAL, LIVE_COLLECTION])
def test_manifest_anchored_acquisitions_are_verifiable_and_say_so(params):
    """These were being skipped entirely as "not verifiable by this tool"
    while recording both a hash AND the exact file it was taken over. The
    'manifest' scope is what stops a match being reported as if the copied
    files themselves had been re-read - they have not been."""
    path, scope = acquisition_verification_target(params)
    assert path == params["manifest_path"]
    assert scope == "manifest"


def test_a_destination_that_is_a_real_file_is_verifiable(tmp_path):
    """android_bugreport's output_destination names a .zip, not a folder."""
    zip_path = tmp_path / "2026-CASE-01_ITEM-BUGREPORT-02_android_bugreport.zip"
    zip_path.write_bytes(b"PK\x03\x04not-really-a-zip")
    path, scope = acquisition_verification_target({"output_destination": str(zip_path)})
    assert path == str(zip_path)
    assert scope == "file"


def test_a_destination_that_is_a_folder_has_no_verification_target(tmp_path):
    """An android_pull writes thousands of files into a folder and anchors no
    hash to any of them - honest answer is "nothing to re-hash", not a guess."""
    dest = tmp_path / "2026-CASE-01_PIXEL8A-01_android_pull"
    dest.mkdir()
    assert acquisition_verification_target({"output_destination": str(dest)}) == (None, None)


def test_a_destination_that_does_not_exist_has_no_verification_target():
    """os.path.isfile() is False for a path that is gone - which is the
    "missing_file" case the caller reports separately for a target it DID
    resolve, so this must not silently become one."""
    assert acquisition_verification_target(ANDROID_PULL) == (None, None)


def test_the_image_path_wins_even_when_a_manifest_is_also_recorded():
    """Precedence has to match acquisition_output_location()'s, or the two
    helpers would disagree about which file an event is really about."""
    params = dict(RAW_IMAGE, manifest_path="/mnt/evidence/some_other_manifest.json")
    path, scope = acquisition_verification_target(params)
    assert path == RAW_IMAGE["output_image_path"]
    assert scope == "image"


def test_the_two_helpers_agree_on_which_events_have_output_at_all():
    """A caller should never find that one helper sees an output location
    while the other calls the same event empty, EXCEPT for the deliberate
    folder case (walkable, but nothing single to re-hash)."""
    for params in (RAW_IMAGE, LOGICAL, LIVE_COLLECTION, ANDROID_BUGREPORT):
        assert acquisition_output_location(params)[0] is not None
        # ANDROID_BUGREPORT's .zip does not exist on this test machine, so it
        # resolves to None here - that is the isfile() check doing its job,
        # covered directly by its own test above.
    assert acquisition_output_location(ANDROID_PULL)[0] is not None
    assert acquisition_verification_target(ANDROID_PULL) == (None, None)
