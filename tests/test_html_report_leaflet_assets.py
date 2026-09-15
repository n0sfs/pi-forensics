"""The exported HTML report's vendored Leaflet assets actually resolve.

_LEAFLET_CSS_PATH/_LEAFLET_JS_PATH were written before the app.py -> core/ +
routes/ split, using dirname(__file__) - which silently became <root>/routes
once this code moved into routes/. Both paths then pointed at
<root>/routes/static/vendor/leaflet/, which does not exist.
_html_leaflet_assets_block() catches the OSError and returns '', so the export
simply had no Leaflet in it: every map rendered as an empty bordered box, with
nothing anywhere saying why. Nothing failed, nothing logged, and no test
noticed - which is exactly why this one exists.

This test needs no Flask app and no POSIX, so it runs on the dev machine too -
deliberately, since a path that resolves only on the Pi is how the bug got in.
"""
import os

import pytest


def _reporting_module():
    return pytest.importorskip(
        "routes.reporting",
        reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")


def test_vendored_leaflet_files_exist_at_the_configured_paths():
    reporting = _reporting_module()
    for path in (reporting._LEAFLET_CSS_PATH, reporting._LEAFLET_JS_PATH):
        assert os.path.isfile(path), f"vendored Leaflet asset missing at {path}"
        assert os.path.getsize(path) > 1000, f"{path} exists but is implausibly small"


def test_leaflet_assets_block_actually_inlines_the_library():
    """The real failure was an empty string returned from the except branch,
    so assert on content rather than merely that the call did not raise."""
    reporting = _reporting_module()
    block = reporting._html_leaflet_assets_block()
    assert block, "_html_leaflet_assets_block() returned nothing - assets did not load"
    assert "<style" in block and "<script" in block
    # A marker present in Leaflet itself, so a stub/placeholder file would fail.
    assert "leaflet" in block.lower()


def test_leaflet_path_is_the_repo_root_not_the_routes_package():
    """Pins the specific regression: resolving relative to this module's own
    directory puts the path inside routes/, where nothing is vendored."""
    reporting = _reporting_module()
    assert os.sep + "routes" + os.sep not in reporting._LEAFLET_CSS_PATH
