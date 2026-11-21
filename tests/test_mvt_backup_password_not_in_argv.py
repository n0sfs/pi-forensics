"""An Android backup password reaches mvt through MVT_ANDROID_BACKUP_PASSWORD,
never argv (readable by any local user via ps / /proc/<pid>/cmdline)."""
import os
from unittest import mock

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from flask import Flask
from werkzeug.security import generate_password_hash

import core.config as config
import routes.file_explorer as fe
from tests.conftest import RemoteTestClient, login_user_session


def _run(tmp_path, platform, password):
    fake_bin = tmp_path / "mvt-bin"
    fake_bin.write_text("")
    target = tmp_path / "backup.ab"
    target.write_text("x")
    dest = tmp_path / "out"
    dest.mkdir()
    done = mock.Mock(returncode=0, stdout="ok", stderr="")
    with mock.patch.object(fe, "MVT_IOS_BIN", str(fake_bin)), \
            mock.patch.object(fe, "MVT_ANDROID_BIN", str(fake_bin)), \
            mock.patch.object(fe.subprocess, "run", return_value=done) as run:
        result = fe._run_mvt_scan_body(str(target), str(dest), platform, backup_password=password)
    return result, run.call_args


def test_password_goes_in_env_not_argv(tmp_path):
    result, call = _run(tmp_path, "android", "s3cret-PW")
    assert result["success"]
    argv = call.args[0]
    assert "s3cret-PW" not in argv and "--backup-password" not in argv
    assert call.kwargs["env"]["MVT_ANDROID_BACKUP_PASSWORD"] == "s3cret-PW"


def test_no_password_keeps_parent_env(tmp_path):
    result, call = _run(tmp_path, "android", None)
    assert result["success"]
    assert call.kwargs["env"] is None


@pytest.fixture
def client(runtime_config_file):
    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(fe.file_explorer_bp)
    cfg = config.load_runtime_config()
    cfg.setdefault("users", []).append({"username": "admin_user", "password_hash": generate_password_hash("x"),
                                        "group_id": "admin"})
    config.save_runtime_config(cfg)
    c = RemoteTestClient(app.test_client())
    login_user_session(c._raw, "admin_user")
    return c


def test_route_refuses_a_password_for_ios(client, evidence_root):
    backup = os.path.join(evidence_root, "ios_backup")
    out = os.path.join(evidence_root, "out")
    os.makedirs(backup)
    os.makedirs(out)
    with mock.patch.object(fe.subprocess, "run") as run:
        res = client.post("/api/files/mvt_scan", json={"path": backup, "platform": "ios",
                                                       "backup_password": "pw", "destination_dir": out})
    assert res.status_code == 400
    assert "Android .ab backup only" in res.get_json()["error"]
    run.assert_not_called()
