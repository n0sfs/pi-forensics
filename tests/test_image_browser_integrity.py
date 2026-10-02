"""routes/image_browser.py integrity fixes from the 2026-10-02 review.

- iOS backups inside an image: Manifest.db's fileID became a write path, so a
  crafted '//...' fileID wrote anywhere on the station.
- Recover Deleted overwrote same-path files and followed a crafted '..' name
  out of its output folder into the rest of the evidence root.
- Extract: '.', '..', NUL and over-long names failed (or aimed at the parent).
- In-image scans claimed "none found" for parts of the image they never
  searched; an image that could not be opened read as "no filesystem".
- Nothing refused new work in a Closed/Archived case.
- A leaked device-preview ACL was only logged at startup, and Exit could not
  remove a grant this process had not recorded.

Fakes stand in for pytsk3 objects; the image browser's own control flow is
what is under test. Skipped (not failed) on a non-POSIX dev machine:
routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import json
import os
import plistlib
import sqlite3
import types

import pytest

pytest.importorskip("core.jobs", reason="routes.image_browser needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.image_browser as image_browser
from core.jobs import current_job, job_lock
from core.mobile_artifacts import parse_mobile_backup_manifest
from core.tsk_utils import ImageUnreadable
from tests.conftest import RemoteTestClient, login_user_session


# --- fakes ---------------------------------------------------------------------------

class _File:
    """A pytsk3-file stand-in: `readable` bytes of `data` can be read, even if
    the recorded size says more."""

    def __init__(self, data, size=None, readable=None):
        self.data = data
        self.readable = len(data) if readable is None else readable
        self.info = types.SimpleNamespace(meta=types.SimpleNamespace(size=len(data) if size is None else size))

    def read_random(self, offset, length):
        end = min(offset + length, self.readable)
        return self.data[offset:end] if end > offset else b""


class _Fs:
    def __init__(self, files):
        self.files = files

    def open_meta(self, inode):
        return self.files[int(inode)]


def _entry(name, inode, deleted=False, is_dir=False, size=0):
    return {"name": name, "inode": str(inode), "is_dir": is_dir, "deleted": deleted, "is_virtual": False,
            "size": size, "mtime": 0, "atime": 0, "ctime": 0, "crtime": 0}


def _case(evidence_root, status="Open", slug="2026-B2-TEST"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{slug}_case.json"), "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder,
                   "case_status": status, "events": []}, f)
    return folder


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
    return path


# --- extract names -----------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("report.pdf", "report.pdf"),
    ("..", "extracted_42"),
    (".", "extracted_42"),
    ("", "extracted_42"),
    ("/", "extracted_42"),
    ("a\x00b.txt", "ab.txt"),
    ("dir/inner.txt", "inner.txt"),
    (None, "extracted_42"),
    (12345, "extracted_42"),
])
def test_extract_names_are_always_a_bare_writable_name(raw, expected):
    assert image_browser._safe_extract_name(raw, "extracted_42") == expected


def test_an_over_long_name_is_cut_to_fit_and_keeps_its_extension():
    name = image_browser._safe_extract_name("é" * 300 + ".jpeg", "fallback")
    assert len(name.encode("utf-8")) <= 255
    assert name.endswith(".jpeg")
    name.encode("utf-8")  # whole characters only - never a split UTF-8 sequence


def test_extracting_a_dot_dot_entry_lands_in_the_destination_under_a_fallback(client, evidence_root, image,
                                                                              monkeypatch):
    folder = _case(evidence_root)
    monkeypatch.setattr(image_browser, "_tsk_open_fs", lambda p, o: _Fs({42: _File(b"DATA")}))
    monkeypatch.setattr(image_browser, "carry_over_image_tags_to_extracted_file", lambda *a, **k: None)
    res = client.post("/api/image/extract", json={"image_path": image, "offset": 0, "inode": "42",
                                                  "output_name": "..", "destination_dir": folder})
    assert res.status_code == 200, res.get_json()
    assert open(os.path.join(folder, "extracted_42"), "rb").read() == b"DATA"


def test_a_file_that_cannot_be_read_in_full_is_not_extracted(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root)
    monkeypatch.setattr(image_browser, "_tsk_open_fs",
                        lambda p, o: _Fs({42: _File(b"x" * 5000, readable=1000)}))
    res = client.post("/api/image/extract", json={"image_path": image, "offset": 0, "inode": "42",
                                                  "output_name": "partial.bin", "destination_dir": folder})
    assert res.status_code == 500
    assert "1000 of 5000" in res.get_json()["error"]
    assert not os.path.exists(os.path.join(folder, "partial.bin"))


# --- recover deleted -------------------------------------------------------------------

def _install_walk(monkeypatch, fs, entries):
    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems",
                        lambda image_path, skipped=None: [{"offset": 0, "label": "Whole Image"}])
    monkeypatch.setattr(image_browser, "_tsk_open_fs", lambda p, o: fs)
    monkeypatch.setattr(image_browser, "_tsk_walk", lambda f, start=None, stats=None, **k: iter(entries))


def test_recovery_never_leaves_its_output_folder_or_overwrites(evidence_root, image, monkeypatch):
    case_dir = _case(evidence_root)
    other_case = _case(evidence_root, slug="2026-OTHER-CASE")
    fs = _Fs({10: _File(b"EVIL"), 11: _File(b"first version"), 12: _File(b"second version"),
              13: _File(b"y" * 5000, readable=100)})
    entries = [
        # One crafted name carrying separators - a real directory entry can.
        (_entry("../../2026-OTHER-CASE/escape.txt", 10, deleted=True, size=4), "/docs/../../2026-OTHER-CASE/escape.txt"),
        (_entry("~WRL0001.tmp", 11, deleted=True, size=13), "/tmp/~WRL0001.tmp"),
        (_entry("~WRL0001.tmp", 12, deleted=True, size=14), "/tmp/~WRL0001.tmp"),
        (_entry("damaged.doc", 13, deleted=True, size=5000), "/tmp/damaged.doc"),
    ]
    _install_walk(monkeypatch, fs, entries)

    result = image_browser._run_recover_deleted_body(image, case_dir)
    out = result["output_dir"]
    assert out == os.path.join(case_dir, "disk_recovered_deleted")
    assert not os.path.exists(os.path.join(other_case, "escape.txt"))
    assert open(os.path.join(out, "docs", "2026-OTHER-CASE", "escape.txt"), "rb").read() == b"EVIL"
    assert open(os.path.join(out, "tmp", "~WRL0001.tmp"), "rb").read() == b"first version"
    assert open(os.path.join(out, "tmp", "~WRL0001__inode12.tmp"), "rb").read() == b"second version"
    assert result["files_incomplete"] == 1
    assert not os.path.exists(os.path.join(out, "tmp", "damaged.doc"))
    assert result["files_recovered"] == 3

    # A second run gets its own folder - the first run's files are untouched.
    _install_walk(monkeypatch, _Fs({11: _File(b"third")}),
                  [(_entry("~WRL0001.tmp", 11, deleted=True, size=5), "/tmp/~WRL0001.tmp")])
    again = image_browser._run_recover_deleted_body(image, case_dir)
    assert again["output_dir"] != out
    assert open(os.path.join(out, "tmp", "~WRL0001.tmp"), "rb").read() == b"first version"


def test_a_collision_on_a_maximum_length_name_still_gets_a_free_name(tmp_path):
    first = tmp_path / ("a" * 251 + ".tmp")          # 255 bytes - no room left for a tag
    first.write_bytes(b"already here")
    fd, path = image_browser._create_new_file(str(first), "77")
    os.close(fd)
    assert os.path.basename(path).endswith("__inode77.tmp")
    assert len(os.path.basename(path).encode()) <= 255
    assert first.read_bytes() == b"already here"


# --- iOS backup inside an image ------------------------------------------------------

def _manifest_bytes(tmp_path, file_id):
    db = tmp_path / "Manifest.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.execute("INSERT INTO Files VALUES (?, 'HomeDomain', 'Library/SMS/sms.db', 1, NULL)", (file_id,))
    conn.commit()
    conn.close()
    return db.read_bytes()


def test_a_crafted_file_id_cannot_choose_where_the_extractor_writes(tmp_path, monkeypatch):
    target = tmp_path / "outside" / "pwned"
    target.parent.mkdir()
    evil_id = "/" + str(target)          # '//...' - os.path.join() treats it as absolute
    assert evil_id.startswith("//")
    manifest = _manifest_bytes(tmp_path, evil_id)
    fs = _Fs({1: _File(manifest), 2: _File(plistlib.dumps({})), 4: _File(b"attacker-chosen bytes")})
    listing = {
        100: [_entry("Manifest.db", 1, size=len(manifest)), _entry("Info.plist", 2, size=10),
              _entry("//", 3, is_dir=True)],
        3: [_entry(evil_id, 4, size=21)],
    }
    monkeypatch.setattr(image_browser, "_tsk_list_dir", lambda f, inode: listing[int(inode)])

    temp_dir, problems = image_browser._extract_ios_backup_essentials_to_temp(fs, 100)
    try:
        assert temp_dir is not None
        assert not target.exists()
        records, summary = parse_mobile_backup_manifest(temp_dir)
        assert "invalid fileID" in summary["unreadable"]["mobile_sms_message"]
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


# --- coverage and unreadable images ---------------------------------------------------

def test_a_scan_whose_walk_was_cut_short_says_so(client, evidence_root, image, monkeypatch):
    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems",
                        lambda image_path, skipped=None: [{"offset": 2048, "label": "NTFS"}])
    monkeypatch.setattr(image_browser, "_tsk_open_fs", lambda p, o: _Fs({}))

    def walk(fs, start=None, stats=None, **k):
        stats.update({"dirs_capped": True, "max_dirs": 5000, "dirs_unreadable": 0, "unreadable_paths": []})
        return iter([])

    monkeypatch.setattr(image_browser, "_tsk_walk", walk)
    data = client.post("/api/image/parse_registry", json={"image_path": image}).get_json()
    assert data["success"] and data["candidates_found"] == 0
    assert data["truncated"] is True
    assert any("5000 directories" in g for g in data["search_gaps"])


def test_skipped_partitions_are_listed_but_are_not_a_gap(client, image, monkeypatch):
    def resolve(image_path, skipped=None):
        skipped.append({"offset": 206848, "label": "Microsoft reserved partition", "error": "no fs"})
        return [{"offset": 2048, "label": "NTFS"}]

    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems", resolve)
    monkeypatch.setattr(image_browser, "_tsk_open_fs", lambda p, o: _Fs({}))
    monkeypatch.setattr(image_browser, "_tsk_walk", lambda fs, start=None, stats=None, **k: iter([]))
    data = client.post("/api/image/parse_evtx", json={"image_path": image}).get_json()
    assert data["truncated"] is False and data["search_gaps"] == []
    assert data["partitions_skipped"][0]["label"] == "Microsoft reserved partition"


def test_an_image_that_cannot_be_opened_is_reported_as_such(client, image, monkeypatch):
    def resolve(image_path, skipped=None):
        raise ImageUnreadable("The image could not be opened: I/O error")

    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems", resolve)
    res = client.post("/api/image/parse_registry", json={"image_path": image})
    assert res.status_code == 422
    body = res.get_json()
    assert body["image_unreadable"] is True and "could not be opened" in body["error"]
    assert "No recognized filesystem" not in body["error"]


# --- Closed/Archived cases take no new work ----------------------------------------------

@pytest.mark.parametrize("route, body_key", [
    ("/api/image/parse_registry", "case_folder"),
    ("/api/image/hash_manifest", "destination_dir"),
    ("/api/image/recover_deleted", "destination_dir"),
    ("/api/image/parse_lnk", "case_folder"),
])
@pytest.mark.parametrize("status", ["Closed", "Archived"])
def test_a_finished_case_takes_no_new_in_image_work(client, evidence_root, image, route, body_key, status):
    folder = _case(evidence_root, status=status)
    res = client.post(route, json={"image_path": image, body_key: folder, "inode": "5", "offset": 0})
    assert res.status_code == 409
    assert res.get_json()["closed_case"] == status


def test_a_refused_job_never_claims_the_job_slot(client, evidence_root, image):
    folder = _case(evidence_root, status="Closed")
    with job_lock:
        current_job["active"] = False
    res = client.post("/api/image/start_triage_scan", json={"image_path": image, "destination_dir": folder})
    assert res.status_code == 409
    assert current_job["active"] is False


def test_an_open_case_is_not_refused(client, evidence_root, image, monkeypatch):
    folder = _case(evidence_root, status="Open")
    monkeypatch.setattr(image_browser, "_tsk_resolve_filesystems", lambda image_path, skipped=None: [])
    res = client.post("/api/image/parse_registry", json={"image_path": image, "case_folder": folder})
    assert res.status_code == 500  # past the gate: this fake image simply has no filesystem
    assert "closed_case" not in res.get_json()


# --- the in-image path a single-file tool files its records under ----------------------

def test_a_missing_in_image_path_is_named_by_inode_not_left_null():
    assert image_browser._in_image_source_path({"path": "/Users/a/x.lnk"}, "9") == "/Users/a/x.lnk"
    assert image_browser._in_image_source_path({"name": "x.lnk"}, "9") == "<inode 9>/x.lnk"
    assert image_browser._in_image_source_path({"path": None}, "9") == "<inode 9>"


# --- Live Device Preview read grants --------------------------------------------------------

def test_exit_removes_a_grant_this_process_never_recorded(client, monkeypatch):
    revoked = []
    monkeypatch.setattr(image_browser, "is_valid_block_device_or_partition", lambda p: True)
    monkeypatch.setattr(image_browser, "_service_account_acl_present", lambda p: True)
    monkeypatch.setattr(image_browser, "_revoke_device_preview_acl", lambda p: (revoked.append(p) or (True, None)))
    res = client.post("/api/image/preview/exit", json={"device_path": "/dev/sdz"})
    assert res.get_json()["success"] is True
    assert revoked == ["/dev/sdz"]


def test_exit_with_nothing_to_remove_is_a_quiet_no_op(client, monkeypatch):
    monkeypatch.setattr(image_browser, "is_valid_block_device_or_partition", lambda p: True)
    monkeypatch.setattr(image_browser, "_service_account_acl_present", lambda p: False)
    monkeypatch.setattr(image_browser, "_revoke_device_preview_acl",
                        lambda p: pytest.fail("nothing to revoke"))
    assert client.post("/api/image/preview/exit", json={"device_path": "/dev/sdz"}).get_json()["success"]


def test_a_revoke_that_fails_is_reported_not_assumed(client, monkeypatch):
    with image_browser.device_previews_lock:
        image_browser.active_device_previews["/dev/sdz"] = {"granted_at": 0, "last_activity": 0}
    monkeypatch.setattr(image_browser, "_revoke_device_preview_acl", lambda p: (False, "Operation not permitted"))
    res = client.post("/api/image/preview/exit", json={"device_path": "/dev/sdz"})
    assert res.status_code == 500
    assert "could not be removed" in res.get_json()["error"]


def test_startup_revokes_a_leaked_grant(monkeypatch):
    logged, revoked = [], []
    monkeypatch.setattr(image_browser, "glob", types.SimpleNamespace(
        glob=lambda pattern: ["/dev/sdz"] if pattern == "/dev/sd*" else []))
    monkeypatch.setattr(image_browser, "is_valid_block_device_or_partition", lambda p: True)
    monkeypatch.setattr(image_browser, "_service_account_acl_present", lambda p: True)
    monkeypatch.setattr(image_browser, "_revoke_device_preview_acl", lambda p: (revoked.append(p) or (True, None)))
    monkeypatch.setattr(image_browser, "log_chain_of_custody", lambda action, details, **k: logged.append(action))
    image_browser._device_preview_startup_reconciliation()
    assert revoked == ["/dev/sdz"]
    assert logged == ["device_preview_orphan_acl_revoked"]


def test_the_revoke_helper_checks_setfacl_s_result(monkeypatch, tmp_path):
    node = tmp_path / "sdz"
    node.write_bytes(b"")

    class _Res:
        returncode = 1
        stderr = "setfacl: Operation not permitted"
        stdout = ""

    proxy = types.SimpleNamespace(run=lambda *a, **k: _Res(), TimeoutExpired=Exception)
    monkeypatch.setattr(image_browser, "subprocess", proxy)
    assert image_browser._revoke_device_preview_acl(str(node)) == (False, "setfacl: Operation not permitted")
    # A node that is gone has nothing left to revoke.
    assert image_browser._revoke_device_preview_acl(str(tmp_path / "unplugged")) == (True, None)
