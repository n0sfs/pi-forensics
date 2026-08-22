"""core/config.py's get_app_version() - the VERSION file / release-tag mechanism.

Validates both that the real repo-root VERSION file is well-formed (so a
release can't be tagged with a malformed version string) and that the
reader degrades gracefully rather than crashing app startup when the file
is missing or unreadable.
"""
import re

import core.config as config

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def test_real_version_file_exists_and_is_valid_semver():
    assert config.VERSION_FILE.endswith("VERSION")
    with open(config.VERSION_FILE, "r") as f:
        content = f.read().strip()
    assert _SEMVER_RE.match(content), f"VERSION file content {content!r} isn't MAJOR.MINOR.PATCH"


def test_get_app_version_returns_the_real_file_content():
    with open(config.VERSION_FILE, "r") as f:
        expected = f.read().strip()
    assert config.get_app_version() == expected


def test_get_app_version_falls_back_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VERSION_FILE", str(tmp_path / "does_not_exist" / "VERSION"))
    assert config.get_app_version() == "0.0.0-unknown"


def test_get_app_version_falls_back_when_file_is_empty(monkeypatch, tmp_path):
    empty = tmp_path / "VERSION"
    empty.write_text("")
    monkeypatch.setattr(config, "VERSION_FILE", str(empty))
    assert config.get_app_version() == "0.0.0-unknown"
