"""The UI loads no third-party assets (Maintainer decision 2026-11-20): an
offline station or isolated lab LAN must get a styled, working page. Every
<link>/<script> in the page templates is local, and each referenced vendor
file exists."""
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")
TEMPLATES = [os.path.join(ROOT, "templates", n) for n in ("index.html", "login.html")]
ASSET_RE = re.compile(r'<(?:script|link)\b[^>]*\b(?:src|href)="([^"]+)"', re.IGNORECASE)


def test_page_assets_are_local_and_present():
    seen = 0
    for path in TEMPLATES:
        with open(path, encoding="utf-8") as f:
            for url in ASSET_RE.findall(f.read()):
                assert not re.match(r"(https?:)?//", url), f"{os.path.basename(path)} loads {url}"
                if url.startswith("/static/"):
                    seen += 1
                    assert os.path.isfile(os.path.join(ROOT, url.lstrip("/"))), url
    assert seen >= 6


def test_icon_font_files_exist():
    css = os.path.join(ROOT, "static", "vendor", "bootstrap-icons-1.10.0", "bootstrap-icons.css")
    with open(css, encoding="utf-8") as f:
        fonts = re.findall(r'url\("\./([^"?]+)', f.read())
    assert fonts
    for rel in fonts:
        assert os.path.isfile(os.path.join(os.path.dirname(css), rel)), rel
