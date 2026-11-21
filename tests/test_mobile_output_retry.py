"""What a phone acquisition does when an earlier attempt left its output
behind (Eric's decision 2026-11-20, 10-09 item 6A): an empty leftover is
removed, partial output is kept and the new run gets _attemptN, and a
COMPLETED acquisition at that path is still refused (reused Evidence ID)."""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.mobile needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask

import routes.mobile as mobile


@pytest.fixture
def ctx():
    app = Flask(__name__)
    with app.app_context():
        yield


def _case(root, events=()):
    folder = os.path.join(root, "2026-M")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "2026-M_case.json"), "w") as f:
        json.dump({"case_number": "2026-M", "case_status": "Open", "events": list(events)}, f)
    return folder


def test_nothing_there(evidence_root, ctx):
    folder = _case(evidence_root)
    path, base, note, refusal = mobile._claim_mobile_output(folder, "2026-M_ITEM-01_android_pull")
    assert (path, base, note, refusal) == (os.path.join(folder, "2026-M_ITEM-01_android_pull"),
                                           "2026-M_ITEM-01_android_pull", None, None)


def test_empty_folder_and_zero_byte_file_are_removed(evidence_root, ctx):
    folder = _case(evidence_root)
    os.mkdir(os.path.join(folder, "B_android_pull"))
    open(os.path.join(folder, "B.ab"), "w").close()
    path, base, note, refusal = mobile._claim_mobile_output(folder, "B_android_pull")
    assert refusal is None and base == "B_android_pull" and not os.path.exists(path) and "Removed the empty" in note
    path, base, note, refusal = mobile._claim_mobile_output(folder, "B", ".ab")
    assert refusal is None and path.endswith("/B.ab") and not os.path.exists(path)


def test_partial_output_is_kept_and_the_retry_is_suffixed(evidence_root, ctx):
    folder = _case(evidence_root)
    old = os.path.join(folder, "C_ios_backup")
    os.makedirs(os.path.join(old, "partial"))
    os.makedirs(os.path.join(folder, "C_ios_backup_attempt2", "x"))  # an earlier retry, also partial
    path, base, note, refusal = mobile._claim_mobile_output(folder, "C_ios_backup")
    assert refusal is None
    assert base == "C_ios_backup_attempt3" and path == os.path.join(folder, "C_ios_backup_attempt3")
    assert os.path.isdir(os.path.join(old, "partial"))  # untouched
    assert "kept as it is" in note
    with open(os.path.join(folder, "D.zip"), "w") as f:
        f.write("partial")
    path, base, _note, _r = mobile._claim_mobile_output(folder, "D", ".zip")
    assert path.endswith("/D_attempt2.zip") and base == "D_attempt2"


def test_completed_acquisition_is_still_refused(evidence_root, ctx):
    root = evidence_root
    out = os.path.join(root, "2026-M", "E_android_pull")
    folder = _case(root, [{"acquisition_status": "COMPLETED",
                           "acquisition_parameters": {"output_destination": out}}])
    os.makedirs(out)  # even an empty folder: it's a recorded, completed acquisition
    path, _b, _n, refusal = mobile._claim_mobile_output(folder, "E_android_pull")
    assert path is None and refusal[1] == 409
    assert os.path.isdir(out)
