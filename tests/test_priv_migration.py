"""core/priv.py - migrated call sites use the pif-priv helper once it is
installed, and their exact legacy argv until then (2026-09-23)."""
from unittest import mock

import core.priv as priv


def test_legacy_argv_until_the_helper_is_installed(monkeypatch):
    monkeypatch.setattr(priv, "priv_available", lambda: False)
    assert priv.priv_argv("blockdev-setro", "/dev/sdb", legacy=["sudo", "/usr/sbin/blockdev", "--setro", "/dev/sdb"]) \
        == ["sudo", "/usr/sbin/blockdev", "--setro", "/dev/sdb"]


def test_helper_argv_once_installed(monkeypatch):
    monkeypatch.setattr(priv, "PIF_PRIV", "/usr/local/sbin/pif-priv")   # conftest pins it elsewhere
    monkeypatch.setattr(priv, "priv_available", lambda: True)
    assert priv.priv_argv("kill-pgroup", 4242, legacy=["x"]) == \
        ["sudo", "-n", "/usr/local/sbin/pif-priv", "kill-pgroup", "4242"]


def test_needs_both_the_helper_and_its_root_config(monkeypatch, tmp_path):
    helper, conf = tmp_path / "pif-priv", tmp_path / "priv.conf"
    monkeypatch.setattr(priv, "PIF_PRIV", str(helper))
    monkeypatch.setattr(priv, "PIF_PRIV_CONFIG", str(conf))
    assert priv.priv_available() is False
    helper.write_text("#!/bin/sh\n")
    assert priv.priv_available() is False     # helper without its config: stay on legacy
    conf.write_text("{}")
    assert priv.priv_available() is True
