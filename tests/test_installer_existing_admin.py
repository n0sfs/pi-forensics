"""A re-run of install.py must not prompt for a password it won't apply, and
its "still the default password" warning must reflect the account's real
password. Runs the two helpers from install.py in isolation."""
import ast
import json
import os
import pathlib
import subprocess
import sys

from werkzeug.security import generate_password_hash

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = (ROOT / "install.py").read_text()


def _helpers(**globals_):
    tree = ast.parse(SRC)
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name in ("_existing_account_hash", "_default_password_in_use")]
    ns = {"os": os, "json": json, "subprocess": subprocess, "INSTALL_DIR": "/nonexistent", **globals_}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), "install.py", "exec"), ns)
    return ns


def test_existing_account_hash(tmp_path):
    cfg = tmp_path / "runtime_config.json"
    cfg.write_text(json.dumps({"users": [{"username": "admin", "password_hash": "h1"}]}))
    ns = _helpers()
    assert ns["_existing_account_hash"]("admin", str(cfg)) == "h1"
    assert ns["_existing_account_hash"]("other", str(cfg)) is None
    assert ns["_existing_account_hash"]("admin", str(tmp_path / "missing.json")) is None
    cfg.write_text("{not json")
    assert ns["_existing_account_hash"]("admin", str(cfg)) is None


def test_default_password_check_uses_the_stored_hash():
    for password, expected in (("forensics", True), ("a-real-password", False)):
        ns = _helpers(EXISTING_ADMIN_HASH=generate_password_hash(password), FORENSIC_PASS="forensics",
                      venv_python=sys.executable)
        assert ns["_default_password_in_use"]() is expected


def test_new_install_uses_the_typed_password():
    ns = _helpers(EXISTING_ADMIN_HASH=None, FORENSIC_PASS="forensics", venv_python=sys.executable)
    assert ns["_default_password_in_use"]() is True
    ns = _helpers(EXISTING_ADMIN_HASH=None, FORENSIC_PASS="typed-pass-1", venv_python=sys.executable)
    assert ns["_default_password_in_use"]() is False


def test_prompt_loop_is_skipped_for_an_existing_account():
    assert "while EXISTING_ADMIN_HASH is None:" in SRC
    assert "re-run this installer" not in SRC.split("_default_password_in_use():")[-1]
