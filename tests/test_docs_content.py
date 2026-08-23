"""core/config.py's get_doc_content()/DOC_FILES - the mechanism behind
Help > Quick-Start/User Manual/Release Notes links and Settings > Diagnostics
> View Release Notes, letting an examiner read the shipped docs without
leaving the app or needing internet/GitHub access.

Validates both that the real repo-shipped doc files exist and are readable
through this mechanism, and that an unknown id degrades to None (never
raises) so the route serving it can turn that into a clean 404.
"""
import core.config as config


def test_every_known_doc_id_resolves_to_a_real_readable_file():
    for doc_id in config.DOC_FILES:
        content = config.get_doc_content(doc_id)
        assert content is not None, f"{doc_id} should have real content"
        assert len(content) > 0


def test_quickstart_starts_with_its_real_heading():
    content = config.get_doc_content("quickstart")
    assert content.startswith("# Quick-Start Guide")


def test_user_manual_starts_with_its_real_heading():
    content = config.get_doc_content("user-manual")
    assert content.startswith("# Pi Forensics Suite")


def test_changelog_starts_with_its_real_heading():
    content = config.get_doc_content("changelog")
    assert content.startswith("# Changelog")


def test_unknown_doc_id_returns_none_not_a_crash():
    assert config.get_doc_content("bogus-id") is None
    assert config.get_doc_content("") is None
    assert config.get_doc_content("../../etc/passwd") is None


def test_missing_file_on_disk_returns_none(monkeypatch, tmp_path):
    monkeypatch.setitem(config.DOC_FILES, "quickstart", str(tmp_path / "does_not_exist.md"))
    assert config.get_doc_content("quickstart") is None


def test_render_doc_html_produces_a_full_self_contained_page():
    for doc_id in config.DOC_FILES:
        page = config.render_doc_html(doc_id)
        assert page is not None
        assert page.startswith("<!doctype html>")
        assert "<style>" in page  # self-contained, no external stylesheet
        assert "cdn." not in page.lower()  # never reaches out for CSS/fonts/JS


def test_render_doc_html_converts_markdown_syntax_not_just_passes_it_through():
    page = config.render_doc_html("quickstart")
    # toc extension adds an id="..." to every heading (a nice side effect -
    # every section gets a stable deep-link anchor), so this checks the
    # real text content landed inside a real <h1>, not the exact attribute-
    # free tag shape.
    assert "<h1" in page and ">Quick-Start Guide</h1>" in page
    assert "# Quick-Start Guide" not in page  # raw markdown syntax gone


def test_render_doc_html_unknown_id_returns_none():
    assert config.render_doc_html("bogus-id") is None


def _sidenav_links(page):
    import re
    m = re.search(r'<nav class="doc-sidenav">.*?</nav>', page, re.S)
    if not m:
        return []
    return re.findall(r'<a href="#([^"]+)">', m.group())


def test_quickstart_has_no_sidenav_or_two_column_layout():
    # Only Release Notes/User Manual get the left-nav treatment - Quick-
    # Start is short enough to stay a plain single column.
    page = config.render_doc_html("quickstart")
    assert '<div class="doc-layout">' not in page
    assert 'class="doc-sidenav"' not in page


def test_changelog_sidenav_lists_every_version_and_only_the_first_is_open():
    page = config.render_doc_html("changelog")
    links = _sidenav_links(page)
    assert len(links) >= 2  # at least 1.0.0 and 1.0.1
    entry_count = page.count('class="doc-entry"')
    open_count = page.count('doc-entry" open')
    assert entry_count == len(links)
    assert open_count == 1
    # The open one is the FIRST entry in the document (changelog is
    # newest-first), not just any single entry - confirmed by checking the
    # <details ... open> that appears earliest in the article body comes
    # before every non-open one.
    first_open_pos = page.index('doc-entry" open')
    first_plain_pos = page.index('class="doc-entry">')
    assert first_open_pos < first_plain_pos


def test_changelog_sidenav_link_targets_resolve_to_real_ids_in_the_body():
    page = config.render_doc_html("changelog")
    for link_id in _sidenav_links(page):
        assert f'id="{link_id}"' in page


def test_user_manual_sidenav_lists_all_nine_top_level_sections_not_collapsible():
    page = config.render_doc_html("user-manual")
    links = _sidenav_links(page)
    assert len(links) == 9
    # No <details> wrapping in the article body itself (the shared <style>
    # block mentions the .doc-entry class name regardless of doc, since
    # it's one CSS stylesheet reused across all three pages - that's
    # expected and harmless, only the body content matters here).
    article_body = page.split("<article>", 1)[1].split("</article>", 1)[0]
    assert "<details" not in article_body


def test_user_manual_no_longer_has_the_old_inline_numbered_contents_list():
    # The old "## Contents" heading + its 9 numbered markdown links were
    # removed from the source (docs/user-manual.md) once the real left-nav
    # made them redundant - confirms that edit stuck, not just that the new
    # nav exists alongside a leftover duplicate.
    raw = config.get_doc_content("user-manual")
    assert "## Contents" not in raw


def test_split_html_by_h2_basic_contract():
    body = (
        '<p>intro text</p>'
        '<h2 id="a">Section A</h2><p>content a</p>'
        '<h2 id="b">Section B</h2><p>content b</p>'
    )
    intro, sections = config._split_html_by_h2(body)
    assert intro == "<p>intro text</p>"
    assert [s["id"] for s in sections] == ["a", "b"]
    assert sections[0]["heading_text"] == "Section A"
    assert sections[0]["body_html"] == "<p>content a</p>"
    assert sections[1]["body_html"] == "<p>content b</p>"


def test_split_html_by_h2_no_headings_returns_everything_as_intro():
    body = "<p>just a paragraph, no h2 at all</p>"
    intro, sections = config._split_html_by_h2(body)
    assert intro == body
    assert sections == []
