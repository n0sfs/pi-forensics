"""Template-level accessibility guards from the 2026-11-23 whole-app UI audit.

axe-core flagged every modal as unnamed (no aria-labelledby), every modal close
button as an empty button, and ~25 form controls with no programmatic label.
These checks keep new markup from regressing that without needing a browser.
"""
import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = sorted(glob.glob(os.path.join(ROOT, "templates", "**", "*.html"), recursive=True))


def _all_markup():
    return {os.path.relpath(p, ROOT): open(p, encoding="utf-8").read() for p in TEMPLATES}


def test_every_modal_is_named_by_an_existing_element():
    for path, html in _all_markup().items():
        for tag in re.findall(r'<div class="modal fade[^"]*"[^>]*>', html):
            m = re.search(r'aria-labelledby="([^"]+)"', tag)
            assert m or "aria-label=" in tag, f"{path}: modal without a name: {tag[:120]}"
            if m:
                assert f'id="{m.group(1)}"' in html, f"{path}: aria-labelledby points at missing id {m.group(1)}"


def test_every_close_button_has_an_accessible_name():
    for path, html in _all_markup().items():
        for tag in re.findall(r'<button[^>]*\bbtn-close\b[^>]*>', html):
            assert "aria-label=" in tag, f"{path}: icon-only close button without aria-label: {tag[:120]}"


def test_progress_bars_are_named():
    for path, html in _all_markup().items():
        for tag in re.findall(r'<div[^>]*role="progressbar"[^>]*>', html):
            assert "aria-label=" in tag or "aria-labelledby=" in tag, f"{path}: unnamed progressbar: {tag[:120]}"


def test_scrolling_log_windows_are_keyboard_reachable():
    for path, html in _all_markup().items():
        for tag in re.findall(r'<pre[^>]*\blog-window\b[^>]*>', html):
            assert 'tabindex="0"' in tag, f"{path}: scrollable log not focusable: {tag[:120]}"
