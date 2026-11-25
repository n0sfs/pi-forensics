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
    assert re.search(r"details > summary \{[^}]*padding-top: 1[12]px", blocks)


def test_touch_help_icons_do_not_extend_sideways():
    # Hit area is vertical-only overlap (negative vertical margin); the box is 44px tall and
    # at least 44px wide, with no negative horizontal margin over the control beside it.
    blocks = "\n".join(_coarse_blocks())
    ms = re.findall(r'i\.bi\[data-bs-toggle="tooltip"\] \{([^}]*)\}', blocks)
    m = ms[-1] if ms else None
    assert m, "help icon hit-area rule missing"
    rule = m
    assert "height: 44px" in rule and "min-width: 44px" in rule
    assert re.search(r"margin: -\d+px 0;", rule)


def test_mouse_targets_meet_wcag_24px():
    fine = "\n".join(re.findall(r"@media \(pointer: fine\) \{(.*?)\n        \}", INDEX, re.S))
    assert "min-width: 24px" in fine and "min-height: 24px" in fine
    assert re.search(r"\.btn-xs \{ min-height: 2[4-9]px", fine)


def test_phone_gutters_are_tightened():
    blocks = re.findall(r"@media \(max-width: 575\.98px\) \{(.*?)\n        \}", INDEX, re.S)
    assert any(".app-content-area > .container-fluid" in b for b in blocks)


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


# --- 2026-11-25 round 1 ------------------------------------------------------------------

def test_explorer_rows_stay_on_one_line_and_listing_is_tall_enough():
    # Four date columns wrapping to 3 lines made touch rows 70px: the kiosk showed 1 of 30 rows.
    assert re.search(r"#explorerContainer tbody td \{ white-space: nowrap;", INDEX)
    tab = _read("templates", "tabs", "file_explorer.html")
    assert 'id="explorerContainer" class="file-pane" style="height: clamp(220px, 46vh, 480px);"' in tab


def test_explorer_breadcrumb_crumbs_are_target_sized():
    assert re.search(r'#explorerPath \[role="link"\] \{[^}]*min-height: 24px', INDEX)
    assert re.search(r'#explorerPath \[role="link"\]\[tabindex\] \{[^}]*min-height: 44px', INDEX)


def test_form_check_labels_are_part_of_the_hit_area():
    blocks = "\n".join(_coarse_blocks())
    assert re.search(r"\.form-check \.form-check-label \{[^}]*align-self: stretch", blocks)
    fine = "\n".join(re.findall(r"@media \(pointer: fine\) \{(.*?)\n        \}", INDEX, re.S))
    assert re.search(r"\.form-check \.form-check-label \{[^}]*min-height: 24px", fine)
    assert re.search(r"label:has\(> input\.form-check-input\) \{[^}]*min-height: 24px", fine)


def test_tablist_divider_is_presentational():
    assert '<li role="presentation"><hr class="border-secondary my-2 mx-2" role="none"></li>' in INDEX


def test_placeholders_fit_their_fields():
    for name, ids in (("acquisition", ("caseNum", "evidenceId", "encVolCredential")), ("mobile", ("mobileCaseNum", "mobileEvidenceId")),
                      ("recovery", ("recoverySourcePath", "recoveryCaseNum", "recoveryEvidenceId", "recoveryExaminer")),
                      ("reporting", ("repSearchInput", "caseTimelineSearchInput", "newCaseNoteAssignedTo")), ("settings", ("settingsSearchInput",))):
        html = _read("templates", "tabs", name + ".html")
        for i in ids:
            ph = re.search(r'id="%s"[^>]*placeholder="([^"]*)"' % i, html) or re.search(r'placeholder="([^"]*)"[^>]*id="%s"' % i, html)
            assert ph and len(ph.group(1).replace("&quot;", "\"")) <= 34, (i, ph and ph.group(1))  # longer ones were clipped on the 1024x600 kiosk


# --- 2026-11-25 round 2 ------------------------------------------------------------------

def test_layout_fills_viewport_without_a_hardcoded_navbar_height():
    # `min-height: calc(100vh - 67px)` assumed one navbar height; the kiosk/phone header is
    # taller, so short pages scrolled by 8px / 28px.
    assert "calc(100vh - 67px)" not in INDEX
    assert re.search(r"body \{ min-height: 100vh; display: flex; flex-direction: column; \}", INDEX)
    assert re.search(r"\.app-layout \{[^}]*flex: 1 0 auto", INDEX)


def test_short_screens_use_48px_sidebar_rows():
    m = re.search(r"@media \(max-height: 640px\) \{(.*?)\n        \}", INDEX, re.S)
    assert m and "padding-top: 10px; padding-bottom: 10px" in m.group(1)


def test_page_has_landmarks_and_a_level_one_heading():
    assert '<main class="app-content-area">' in INDEX and "</main>" in INDEX
    assert 'role="heading" aria-level="1"' in INDEX
    assert 'id="activeCaseBar" role="region" aria-label="Active case"' in INDEX
    assert 'id="appSidebar" role="navigation"' in INDEX


# --- 2026-11-25 round 3 ------------------------------------------------------------------

def test_reporting_header_puts_save_beside_the_title_on_short_widths():
    assert 'id="reportHeaderLeft"' in REPORTING
    m = re.search(r"@media \(max-width: 1100px\) \{(.*?)\n        \}", INDEX, re.S)
    assert m and "#reportHeaderLeft { display: contents !important; }" in m.group(1)
    assert "#reportHeaderSaveControls { order: 2; margin-left: auto; }" in m.group(1)
    assert "#reportHeaderCaseMeta { order: 3; flex-basis: 100%; }" in m.group(1)


def test_phone_timeline_table_keeps_a_readable_detail_column():
    m = re.search(r"@media \(max-width: 575\.98px\) \{\s*\.case-timeline-scroll \{ overflow-x: auto; \}\s*\.case-timeline-table \{ min-width: 38rem; \}", INDEX)
    assert m, "phone timeline min-width rule missing"
