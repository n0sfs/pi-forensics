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
