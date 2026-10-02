"""Every element id static/js/main.js looks up must exist (2026-10-02 review).

The suite never runs main.js, so a renamed or removed template id turns a
getElementById() into null and the feature fails silently - or with a
TypeError that aborts the rest of its handler. This cross-references every
literal getElementById('x') against the ids the templates declare and the ids
main.js itself creates (innerHTML strings, element.id = ...).
"""
import glob
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def test_every_looked_up_id_exists():
    js = _read(os.path.join(ROOT, 'static', 'js', 'main.js'))
    templates = ''.join(_read(p) for p in glob.glob(os.path.join(ROOT, 'templates', '**', '*.html'), recursive=True))

    used = set(re.findall(r"getElementById\(\s*['\"`]([A-Za-z0-9_\-]+)['\"`]\s*\)", js))
    id_attr = re.compile(r"""id\s*=\s*\\?["']([A-Za-z0-9_\-]+)""")
    declared = set(id_attr.findall(templates)) | set(id_attr.findall(js))
    declared |= set(re.findall(r"\.id\s*=\s*['\"`]([A-Za-z0-9_\-]+)['\"`]", js))

    missing = sorted(used - declared)
    assert not missing, f"main.js looks up ids nothing declares: {missing}"
