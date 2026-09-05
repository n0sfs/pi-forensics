"""POST /api/files/extract_android_backup (routes/file_explorer.py) - a
2026-09-05 fix found during a code-grounded mobile-forensics review:
core/android_backup_utils.py's own extract_backup_to_directory() (real
tar-slip-guarded full extraction of every file bundled inside a .ab,
already unit-tested in tests/test_android_backup_utils.py) had no route
calling it at all - the only wired-up .ab action was parse_android_backup(),
which only ever pulls out SMS/MMS records, silently leaving every other
bundled file (APKs, shared-storage files, per-app data blobs) unextracted
and unlisted. This tests the new route's own wiring: real end-to-end
extraction with real file-content verification, the destination-directory
safety guard, and the collision-refusal guard - not the underlying
decode/decrypt logic itself, which already has dedicated coverage.

Skipped (not failed) on a non-POSIX dev machine: routes/file_explorer.py
needs core.jobs, which imports POSIX-only pwd/fcntl at module level.
"""
import io
import json
import os
import tarfile
import zlib

import pytest

pytest.importorskip("core.jobs", reason="routes.file_explorer needs core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
from routes.file_explorer import file_explorer_bp
from tests.conftest import RemoteTestClient, login_user_session


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.secret_key = "test-only-secret-key"
    flask_app.register_blueprint(file_explorer_bp)
    return flask_app


@pytest.fixture
def client(app, runtime_config_file):
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({
        "username": "admin_user", "password_hash": generate_password_hash("x"), "group_id": "admin",
    })
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def _write_plain_ab(path, files):
    """A minimal, unencrypted, uncompressed real .ab file - the route-level
    tests here only need to prove the route's own wiring (destination
    resolution, collision refusal, real file-count/content correctness),
    not re-exercise the decrypt/decompress logic itself (already covered
    by tests/test_android_backup_utils.py)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    tar_bytes = buf.getvalue()
    header = b"ANDROID BACKUP\n5\n0\nnone\n"  # version 5, uncompressed, no encryption
    with open(path, "wb") as f:
        f.write(header)
        f.write(tar_bytes)


def test_extract_android_backup_writes_every_bundled_file_with_real_content(client, evidence_root):
    # The .ab lives inside its own case-folder-like subdirectory, and the
    # destination is a SIBLING directory - never nested inside the
    # folder being analyzed, matching how a real case actually looks and
    # deliberately avoiding the exact "destination nested in source"
    # refusal _resolve_analysis_output_dir() is supposed to trigger for a
    # genuinely bad request (covered by its own dedicated test below).
    source_folder = os.path.join(evidence_root, "case_folder")
    os.makedirs(source_folder, exist_ok=True)
    ab_path = os.path.join(source_folder, "backup.ab")
    dest_dir = os.path.join(evidence_root, "dest")
    os.makedirs(dest_dir, exist_ok=True)
    _write_plain_ab(ab_path, {
        "apps/com.example.app/a/f.apk": b"fake apk bytes",
        "shared/0/app_data_blob.bin": b"some shared-storage content",
    })

    res = client.post("/api/files/extract_android_backup", json={
        "path": ab_path, "destination_dir": dest_dir,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["files_extracted"] == 2
    output_dir = data["output_dir"]
    assert output_dir == os.path.join(dest_dir, "backup_android_backup_extracted")
    with open(os.path.join(output_dir, "apps", "com.example.app", "a", "f.apk"), "rb") as f:
        assert f.read() == b"fake apk bytes"
    with open(os.path.join(output_dir, "shared", "0", "app_data_blob.bin"), "rb") as f:
        assert f.read() == b"some shared-storage content"


def test_extract_android_backup_refuses_to_overwrite_a_prior_extraction(client, evidence_root):
    source_folder = os.path.join(evidence_root, "case_folder")
    os.makedirs(source_folder, exist_ok=True)
    ab_path = os.path.join(source_folder, "backup.ab")
    dest_dir = os.path.join(evidence_root, "dest")
    os.makedirs(dest_dir, exist_ok=True)
    _write_plain_ab(ab_path, {"a_file.txt": b"hello"})

    first = client.post("/api/files/extract_android_backup", json={"path": ab_path, "destination_dir": dest_dir})
    assert first.status_code == 200

    second = client.post("/api/files/extract_android_backup", json={"path": ab_path, "destination_dir": dest_dir})
    assert second.status_code == 409
    assert second.get_json()["success"] is False


def test_extract_android_backup_rejects_a_destination_nested_inside_the_source_folder(client, evidence_root):
    ab_path = os.path.join(evidence_root, "backup.ab")
    _write_plain_ab(ab_path, {"a_file.txt": b"hello"})

    res = client.post("/api/files/extract_android_backup", json={
        "path": ab_path, "destination_dir": evidence_root,  # same folder the .ab itself sits in
    })
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_extract_android_backup_rejects_a_missing_source_file(client, evidence_root):
    res = client.post("/api/files/extract_android_backup", json={
        "path": os.path.join(evidence_root, "does_not_exist.ab"),
        "destination_dir": evidence_root,
    })
    assert res.status_code == 400
    assert res.get_json()["success"] is False
