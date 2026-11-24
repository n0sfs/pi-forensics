"""Guards for the 2026-11-24 UI polish rounds (touch targets, help-icon hit areas,
phone gutters, breadcrumb, export preview empty state).

Measured in a browser at 1440 / 1024x600 (touch) / 390 (touch); these template-level
checks keep the fixes from being dropped without needing a browser in CI.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


INDEX = _read("templates", "index.html")
MAIN_JS = _read("static", "js", "main.js")
REPORTING = _read("templates", "tabs", "reporting.html")


def _coarse_blocks():
    return re.findall(r"@media \(pointer: coarse\) \{(.*?)\n        \}", INDEX, re.S)


def test_touch_close_buttons_get_a_44px_hit_area():
    assert any(".btn-close::after" in b and "width: 44px" in b and "height: 44px" in b for b in _coarse_blocks())


def test_touch_checkbox_rows_and_summaries_are_44px():
    blocks = "\n".join(_coarse_blocks())
    assert re.search(r"\.form-check \{[^}]*min-height: 44px", blocks)
    assert re.search(r"label:has\(> input\.form-check-input\) \{[^}]*min-height: 44px", blocks)
    assert re.search(r"details > summary \{[^}]*padding-top: 11px", blocks)


def test_touch_help_icons_do_not_extend_sideways():
    # A negative horizontal margin made the icon's hit area cover the control beside it.
    blocks = "\n".join(_coarse_blocks())
    m = re.search(r'i\.bi\[data-bs-toggle="tooltip"\] \{ padding: (\d+)px (\d+)px; margin: -(\d+)px 0; \}', blocks)
    assert m, "help icon hit-area rule missing"
    pad_v, pad_h, margin_v = map(int, m.groups())
    assert pad_v == margin_v and pad_v <= 8
    assert 12 + 2 * pad_h >= 40  # 12px glyph + side padding = finger-wide


def test_mouse_targets_meet_wcag_24px():
    fine = "\n".join(re.findall(r"@media \(pointer: fine\) \{(.*?)\n        \}", INDEX, re.S))
    assert "min-width: 24px" in fine and "min-height: 24px" in fine
    assert re.search(r"\.btn-xs \{ min-height: 2[4-9]px", fine)


def test_phone_gutters_are_tightened():
    m = re.search(r"@media \(max-width: 575\.98px\) \{(.*?)\n        \}", INDEX, re.S)
    assert m and ".app-content-area > .container-fluid" in m.group(1)


def test_explorer_breadcrumb_scrolls_to_current_folder_and_is_keyboard_usable():
    assert "pathLabel.scrollLeft = pathLabel.scrollWidth" in MAIN_JS
    assert "seg.setAttribute('role', 'link')" in MAIN_JS
    assert re.search(r"#explorerPath \{[^}]*overflow-x: auto", INDEX)


def test_export_preview_empty_state_is_dark():
    assert '#exportPreviewFrame:not([data-loaded])' in INDEX
    assert "iframe.dataset.loaded = '1'" in MAIN_JS
    assert "delete iframe.dataset.loaded" in MAIN_JS


def test_reporting_header_controls_are_named():
    assert re.search(r'<select id="editCaseStatus"[^>]*aria-label="Case status"', REPORTING)
    assert "addInput.setAttribute('aria-label', 'Add an examiner name')" in MAIN_JS


# ---- round 2 ----

def test_tall_popups_scroll_their_body_so_buttons_stay_on_screen():
    assert re.search(r"\.modal-content \{ max-height: calc\(100dvh - var\(--bs-modal-margin\) \* 2\); \}", INDEX)
    assert re.search(r"\.modal-content > \.modal-body \{ overflow-y: auto; min-height: 0;", INDEX)


def test_no_text_below_about_12px_in_badges_and_kickers():
    assert ".badge { font-size: max(.75em, 11.5px); }" in INDEX
    m = re.search(r"\.faq-group-kicker, \.tool-ref-kicker \{\s*font-size: ([\d.]+)rem", INDEX)
    assert m and float(m.group(1)) >= 0.75


def test_tag_popup_close_button_stays_right_aligned():
    html = _read("templates", "tabs", "file_explorer.html")
    footer = html[html.index('id="tagModalAttachBtn"'):]
    footer = footer[:footer.index("</div>")]
    assert 'class="btn btn-sm btn-secondary ms-auto" data-bs-dismiss="modal">Close' in footer


def test_help_tab_strip_breaks_into_two_balanced_rows():
    html = _read("templates", "tabs", "help.html")
    tools = html.index('id="helpNavTools"')
    fields = html.index('id="helpNavReportFields"')
    assert '<span class="reports-nav-break" aria-hidden="true"></span>' in html[tools:fields]
