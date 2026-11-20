"""Deleting an acquisition output from an OPEN case needs its name typed
(Eric's decision 2026-11-20, 10-09 item 8). Server-enforced: the route
refuses without confirm_name == the item's own name."""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from tests.test_review_2026_09_27 import client  # noqa: F401  (fixture)


def _case(evidence_root, events, slug="2026-DEL"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": "Open",
                   "events": events}, f)
    return folder


def _ev(eid, **params):
    return {"tool": "dc3dd", "acquisition_status": "COMPLETED", "case_metadata": {"evidence_id": eid},
            "acquisition_parameters": params}


def _touch(p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").close()
    return p


@pytest.fixture
def case(evidence_root):
    folder = os.path.join(evidence_root, "2026-DEL")
    img = os.path.join(folder, "ITEM-01", "ITEM-01.dd")
    pull = os.path.join(folder, "PIXEL-02_android_pull")
    _case(evidence_root, [_ev("ITEM-01", output_image_path=img, output_destination=os.path.dirname(img)),
                          _ev("PIXEL-02", output_destination=pull),
                          _ev("TRIAGE", output_destination=folder)])  # wrote straight into the case folder
    for p in (img, img + ".log", os.path.join(pull, "sdcard", "a.jpg"), os.path.join(folder, "notes.txt"),
              os.path.join(folder, "ITEM-01", "unrelated.txt")):
        _touch(p)
    return folder, img, pull


def test_image_sidecar_pull_and_parent_need_the_typed_name(client, case):  # noqa: F811
    folder, img, pull = case
    for target in (img, img + ".log", pull, os.path.join(pull, "sdcard", "a.jpg"), os.path.dirname(img)):
        chk = client.post("/api/files/delete_check", json={"path": target}).get_json()
        assert chk["typed_name_required"] is True, target
        res = client.post("/api/files/delete", json={"path": target})
        assert res.status_code == 409 and res.get_json()["requires_typed_name"] is True, target
        res = client.post("/api/files/delete", json={"path": target, "confirm_name": "wrong"})
        assert res.status_code == 409, target
        assert os.path.lexists(target)


def test_typed_name_deletes(client, case):  # noqa: F811
    _folder, img, _pull = case
    res = client.post("/api/files/delete", json={"path": img, "confirm_name": "ITEM-01.dd"})
    assert res.status_code == 200 and not os.path.exists(img)


def test_ordinary_files_keep_the_plain_confirm(client, case):  # noqa: F811
    folder, _img, _pull = case
    for target in (os.path.join(folder, "notes.txt"), os.path.join(folder, "ITEM-01", "unrelated.txt")):
        assert client.post("/api/files/delete_check", json={"path": target}).get_json()["typed_name_required"] is False
        assert client.post("/api/files/delete", json={"path": target}).status_code == 200


def test_unreadable_case_file_falls_back_to_plain_confirm(client, evidence_root):  # noqa: F811
    folder = os.path.join(evidence_root, "2026-BAD")
    os.makedirs(folder)
    with open(os.path.join(folder, "2026-BAD_case.json"), "w") as f:
        f.write("{not json")
    target = _touch(os.path.join(folder, "x.dd"))
    assert client.post("/api/files/delete_check", json={"path": target}).get_json()["typed_name_required"] is False
