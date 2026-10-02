"""routes/image_browser.py /api/image/extract (2026-10-02 review).

- It opened the destination with a truncating open(), so extracting an
  in-image file silently replaced a same-named file already in the case -
  possibly an attached exhibit whose recorded hash then no longer matched.
- Its error path removed the destination even when the failure came before
  anything was written, deleting a pre-existing file of that name.
- It was the one extraction route with no Closed/Archived-case check, so
  "Extract & Attach" on a finished case wrote the file and only the attach
  was refused.

Skipped (not failed) on a non-POSIX dev machine: routes.image_browser needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.image_browser as image_browser
from tests.conftest import RemoteTestClient, login_user_session


class _FakeFs:
    def open_meta(self, inode):
        return ("tsk-file", inode)


@pytest.fixture
def client(runtime_config_file, monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(image_browser.image_browser_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    monkeypatch.setattr(image_browser, "carry_over_image_tags_to_extracted_file", lambda *a, **k: None)
    monkeypatch.setattr(image_browser, "log_chain_of_custody", lambda *a, **k: None)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


@pytest.fixture
def image(evidence_root, monkeypatch):
    path = os.path.join(evidence_root, "disk.dd")
    with open(path, "wb") as f:
        f.write(b"\0" * 512)
    monkeypatch.setattr(image_browser, "_resolve_browsable_source", lambda raw: path)
    monkeypatch.setattr(image_browser, "_tsk_open_fs", lambda image_path, offset: _FakeFs())
    monkeypatch.setattr(image_browser, "_tsk_stream_file", lambda tsk_file, write: write(b"EXTRACTED"))
    return path


def _case(evidence_root, status, slug="2026-EXTRACT-TEST"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder,
                   "case_status": status, "events": []}, f)
    return folder


def _extract(client, image, dest, name="IMG_0001.JPG"):
    return client.post("/api/image/extract", json={"image_path": image, "offset": 0, "inode": "42",
                                                   "output_name": name, "destination_dir": dest})


def test_extracts_into_an_open_case(client, evidence_root, image):
    folder = _case(evidence_root, "Open")
    res = _extract(client, image, folder)
    assert res.status_code == 200, res.get_json()
    with open(os.path.join(folder, "IMG_0001.JPG"), "rb") as f:
        assert f.read() == b"EXTRACTED"


def test_an_existing_file_is_never_overwritten(client, evidence_root, image):
    folder = _case(evidence_root, "Open")
    exhibit = os.path.join(folder, "IMG_0001.JPG")
    with open(exhibit, "wb") as f:
        f.write(b"ORIGINAL EXHIBIT")
    res = _extract(client, image, folder)
    assert res.status_code == 409
    assert "nothing was overwritten" in res.get_json()["error"]
    with open(exhibit, "rb") as f:
        assert f.read() == b"ORIGINAL EXHIBIT"


def test_a_failure_before_writing_creates_nothing(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root, "Open")

    def broken_open(image_path, offset):
        raise OSError("not a filesystem")

    monkeypatch.setattr(image_browser, "_tsk_open_fs", broken_open)
    res = _extract(client, image, folder)
    assert res.status_code == 500
    assert not os.path.exists(os.path.join(folder, "IMG_0001.JPG"))


def test_a_failure_mid_write_removes_only_the_file_it_created(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root, "Open")
    neighbour = os.path.join(folder, "keep_me.txt")
    with open(neighbour, "w") as f:
        f.write("untouched")

    def broken_stream(tsk_file, write):
        write(b"PART")
        raise IOError("read error inside the image")

    monkeypatch.setattr(image_browser, "_tsk_stream_file", broken_stream)
    res = _extract(client, image, folder)
    assert res.status_code == 500
    assert not os.path.exists(os.path.join(folder, "IMG_0001.JPG"))
    assert open(neighbour).read() == "untouched"


@pytest.mark.parametrize("status", ["Closed", "Archived"])
def test_a_finished_case_takes_no_extraction(client, evidence_root, image, status):
    folder = _case(evidence_root, status)
    res = _extract(client, image, folder)
    assert res.status_code == 409
    assert res.get_json()["closed_case"] == status
    assert not os.path.exists(os.path.join(folder, "IMG_0001.JPG"))
