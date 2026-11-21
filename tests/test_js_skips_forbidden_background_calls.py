"""Background loaders skip requests the account's permissions would 403
(2026-11-21: an analyst's page load logged 3 'Failed to load resource' 403s)."""
import re
from pathlib import Path

JS = (Path(__file__).resolve().parent.parent / 'static' / 'js' / 'main.js').read_text(encoding='utf-8')


def _body(name):
    m = re.search(r'async function ' + name + r'\([^)]*\)\s*\{', JS)
    assert m, name
    return JS[m.end():m.end() + 1500]


def test_helper_defers_to_server_until_whoami_answers():
    m = re.search(r'function userKnownToLack\(\.\.\.permKeys\) \{(.*?)\n\}', JS, re.S)
    assert m
    assert 'currentUserRole === null) return false' in m.group(1)


def test_each_loader_checks_the_permission_its_route_requires():
    for fn, perm, url in [('checkForAppUpdate', 'settings', '/api/system/check_update'),
                          ('loadChainOfCustodyLog', 'settings', '/api/coc/log'),
                          ('loadUserGroups', 'manage_users', '/api/user_groups')]:
        body = _body(fn)
        guard = body.find(f"userKnownToLack('{perm}')")
        assert guard != -1, fn
        assert guard < body.find(url), f'{fn} must check before fetching'
