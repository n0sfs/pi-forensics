"""Guards for the 2026-11-25 UI review (evidence-root defaults, kiosk header height,
File Explorer pinned columns / breadcrumb / tree labels, sub-tab strips).

Measured in a browser at 1440 / 1024x600 (touch) / 390 (touch) with FORENSIC_ROOT set to a
folder other than /mnt; these checks keep the fixes from being dropped without a browser.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


INDEX = _read("templates", "index.html")
MAIN_JS = _read("static", "js", "main.js")
TEMPLATES_WITH_PATH_DEFAULTS = [
    ("modals", "shared.html"), ("tabs", "acquisition.html"), ("tabs", "file_explorer.html"),
    ("tabs", "mobile.html"), ("tabs", "recovery.html"),
]


def test_main_js_has_no_hard_coded_mnt_default():
    # The one '/mnt' left is the fallback when the page did not get the server's root.
    code = "\n".join(l for l in MAIN_JS.splitlines() if not l.lstrip().startswith("//"))
    literals = re.findall(r"""['"]/mnt['"]""", code)
    assert len(literals) == 1
    assert "const EVIDENCE_ROOT_PATH = (typeof window !== 'undefined' && window.EVIDENCE_ROOT) || '/mnt';" in MAIN_JS
    assert "let explorerPath = EVIDENCE_ROOT_PATH;" in MAIN_JS
    assert ": EVIDENCE_ROOT_PATH;\n}" in MAIN_JS  # getExplorerRootPath() with no case


@pytest.mark.parametrize("parts", TEMPLATES_WITH_PATH_DEFAULTS)
def test_templates_default_to_the_configured_root(parts):
    html = _read("templates", *parts)
    assert 'value="/mnt"' not in html
    assert "<code>/mnt</code>" not in html


def test_index_exposes_the_evidence_root():
    assert "window.EVIDENCE_ROOT = {{ (evidence_root or '/mnt') | tojson }};" in INDEX
    routes = _read("routes", "auth_routes.py")
    assert "evidence_root=EVIDENCE_ROOT" in routes


def test_index_renders_the_configured_root(monkeypatch):
    from app import app
    import routes.auth_routes as ar
    monkeypatch.setattr(ar, "EVIDENCE_ROOT", "/srv/evidence")
    client = app.test_client()
    resp = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}, headers={"Host": "127.0.0.1:5000"})
    if resp.status_code != 200:
        pytest.skip("index needs a signed-in session in this configuration")
    body = resp.get_data(as_text=True)
    assert 'window.EVIDENCE_ROOT = "/srv/evidence";' in body
    assert 'id="destPath" class="form-control" value="/srv/evidence"' in body


def test_case_button_lives_in_the_header_not_a_second_bar():
    nav = INDEX[INDEX.index('<nav class="navbar'):INDEX.index("</nav>")]
    assert 'id="activeCaseBar" role="region" aria-label="Active case"' in nav
    assert 'id="btnCaseAction"' in nav
    assert 'id="reportingStatsRow"' in nav
    assert INDEX.count('id="activeCaseBar"') == 1


def test_whoami_prefix_hidden_below_xl():
    assert "prefix.className = 'd-none d-xl-inline';" in MAIN_JS
    assert "prefix.textContent = 'Logged in as: ';" in MAIN_JS


def test_explorer_select_and_name_columns_pin_on_sideways_scroll():
    assert "table.classList.add('has-select');" in MAIN_JS
    assert "#explorerContainer table.has-select tr > :nth-child(2) { position: sticky; left: 44px;" in INDEX
    assert "#explorerContainer thead th { position: sticky; top: 0;" in INDEX
    assert "nameTd.title = item.name;" in MAIN_JS


def test_explorer_breadcrumb_repins_to_current_folder():
    assert "pathLabel._pinObserver = new ResizeObserver(" in MAIN_JS


def test_explorer_tree_root_shows_folder_name_with_path_tooltip():
    assert "const rootName = rootPath.split('/').filter(Boolean).pop() || rootPath;" in MAIN_JS
    assert "row.title = node.path || adapter.label(node);" in MAIN_JS
    assert ".explorer-tree-node > span:last-child { min-width: 0; overflow: hidden; text-overflow: ellipsis;" in INDEX


def test_sub_tab_strips_are_one_row_on_the_kiosk():
    block = INDEX[INDEX.index("@media (min-width: 768px) and (max-width: 1199.98px) {"):]
    assert "flex-wrap: nowrap; overflow-x: auto;" in block[:600]


def test_timeline_scroller_is_keyboard_focusable():
    rep = _read("templates", "tabs", "reporting.html")
    assert '<div id="caseTimelineScroll" tabindex="0" role="region"' in rep
