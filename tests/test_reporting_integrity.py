"""Reporting fixes from the 2026-10-02 review (batch 3).

- The report save's three-way merge wrote null for a field the examiner
  deleted, and kept BOTH versions of a list item two people edited.
- Analysis Coverage turned an unreadable case file into "no items", which the
  exported report printed as "Not Checked".
- Two note attachments with the same name overwrote each other; a note edit
  re-hashed around an attachment it could not read.
- One global case-write lock: a stalled case held every other case's writes.
- Custody log entries carried no UTC offset; the Audit Trail's 500 cap was
  silent.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import io
import json
import os
import threading

import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.case_file as case_file
import core.case_index_db as case_index_db
import core.config as config
import routes.reporting as reporting
from core.jobs import CaseFileUnreadable
from tests.conftest import RemoteTestClient, login_user_session

merge = reporting._three_way_merge
MISSING = reporting._MISSING


# --- three-way merge -------------------------------------------------------------------

def test_a_deleted_key_is_deleted_not_written_as_null():
    base = {"a": 1, "b": 2}
    merged, conflicts = merge(base, {"a": 1, "b": 2, "c": 3}, {"a": 1}, "f")
    assert conflicts == []
    assert merged == {"a": 1, "c": 3}


def test_a_list_item_both_sides_edited_is_a_conflict_not_a_duplicate():
    base = [{"path": "/x", "caption": "old"}]
    disk = [{"path": "/x", "caption": "theirs"}]
    mine = [{"path": "/x", "caption": "mine"}]
    merged, conflicts = merge(base, disk, mine, "attachments.files")
    assert conflicts == ["attachments.files"]
    assert merged == disk


def test_independent_list_additions_still_merge():
    merged, conflicts = merge(["a"], ["a", "from_explorer"], ["a", "mine"], "files")
    assert conflicts == []
    assert merged == ["a", "mine", "from_explorer"]


def test_a_top_level_field_absent_on_both_sides_stays_absent():
    merged, _ = merge("old", MISSING, MISSING, "x")
    assert merged is MISSING


# --- coverage --------------------------------------------------------------------------

def test_an_unreadable_case_file_is_not_an_empty_coverage(evidence_root):
    folder = os.path.join(evidence_root, "2026-COV")
    os.makedirs(folder)
    with open(os.path.join(folder, "2026-COV_case.json"), "w") as f:
        f.write("{ truncated")
    with pytest.raises(CaseFileUnreadable):
        case_index_db.compute_case_analysis_coverage(folder)


# --- note attachments ------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("photo.jpg", "photo.jpg"), ("..", "attachment_1"), (".", "attachment_1"), ("", "attachment_1"),
    ("C:\\Users\\x\\evidence.txt", "evidence.txt"), ("a\x00b.txt", "ab.txt"),
])
def test_note_attachment_names(raw, expected):
    assert reporting._note_attachment_name(raw, set(), "attachment_1") == expected


def test_same_named_attachments_get_distinct_names():
    taken = set()
    names = [reporting._note_attachment_name("photo.jpg", taken, "a") for _ in range(3)]
    assert names == ["photo.jpg", "photo (2).jpg", "photo (3).jpg"]


def test_a_hash_never_skips_an_unreadable_attachment(tmp_path):
    with pytest.raises(OSError):
        reporting._hash_note_content("text", [str(tmp_path / "gone.bin")])


@pytest.fixture
def client(runtime_config_file, monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test-only-secret-key"
    app.register_blueprint(reporting.reporting_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    monkeypatch.setattr(reporting, "log_chain_of_custody", lambda *a, **k: None)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _case(evidence_root, slug="2026-NOTES"):
    folder = os.path.join(evidence_root, slug)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{slug}_case.json")
    with open(path, "w") as f:
        json.dump({"schema_version": 1, "case_number": slug, "case_folder": folder, "case_status": "Open",
                   "events": [], "case_notes": [], "updated_at": "2026-10-02 10:00:00"}, f)
    return path


def test_two_uploads_with_one_name_are_both_kept(client, evidence_root):
    case_json = _case(evidence_root)
    res = client.post("/api/cases/notes/add", data={
        "report_path": case_json, "text": "two photos",
        "files": [(io.BytesIO(b"first"), "photo.jpg"), (io.BytesIO(b"second"), "photo.jpg")],
    }, content_type="multipart/form-data")
    assert res.status_code == 200, res.get_json()
    attachments = res.get_json()["note"]["attachments"]
    assert [a["filename"] for a in attachments] == ["photo.jpg", "photo (2).jpg"]
    assert [open(a["path"], "rb").read() for a in attachments] == [b"first", b"second"]


def test_an_edit_cannot_rehash_around_a_missing_attachment(client, evidence_root):
    case_json = _case(evidence_root)
    note = client.post("/api/cases/notes/add", data={
        "report_path": case_json, "text": "original",
        "files": [(io.BytesIO(b"bytes"), "exhibit.bin")],
    }, content_type="multipart/form-data").get_json()["note"]
    os.remove(note["attachments"][0]["path"])
    res = client.post("/api/cases/notes/edit", json={"report_path": case_json, "note_id": note["note_id"],
                                                     "text": "changed"})
    assert res.status_code == 409
    saved = json.load(open(case_json))["case_notes"][0]
    assert saved["text"] == "original" and saved["content_hash"] == note["content_hash"]


# --- per-case write locks ----------------------------------------------------------------

def test_a_stalled_case_does_not_block_another_case(tmp_path):
    a, b = tmp_path / "A", tmp_path / "B"
    a.mkdir()
    b.mkdir()
    held = threading.Event()
    release = threading.Event()

    def stall():
        with case_file.case_write_lock(str(a)):
            held.set()
            release.wait(5)

    t = threading.Thread(target=stall)
    t.start()
    assert held.wait(5)
    try:
        with case_file.case_write_lock(str(b), timeout=1):
            pass  # another case: immediate
        with pytest.raises(case_file.CaseWriteBusy):
            with case_file.case_write_lock(str(a / "A_case.json"), timeout=0.2):
                pass  # the same case, named by its file: busy
    finally:
        release.set()
        t.join(5)


def test_the_case_lock_is_reentrant_for_one_thread(tmp_path):
    with case_file.case_write_lock(str(tmp_path)):
        with case_file.case_write_lock(str(tmp_path / "x_case.json"), timeout=0.1):
            pass


# --- custody log timestamps, Audit Trail cap --------------------------------------------

def test_custody_entries_carry_their_utc_offset(tmp_path, monkeypatch):
    import core.paths as paths
    log = tmp_path / "coc.log"
    monkeypatch.setattr(paths, "COC_LOG_FILE", str(log))
    paths.log_chain_of_custody("test_action", {"x": 1}, source_ip="127.0.0.1", user="t")
    entry = json.loads(log.read_text().splitlines()[-1])
    assert len(entry["utc_offset"]) == 5 and entry["utc_offset"][0] in "+-"


def test_a_capped_html_audit_trail_says_so():
    entries = reporting._CaseHistory([{"timestamp": "t", "action": "a", "details": {}}])
    entries.total_matched = 7
    html = reporting._html_audit_trail_block(entries)
    assert "most recent 1 of 7" in html
