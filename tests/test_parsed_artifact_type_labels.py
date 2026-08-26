"""Regression test for a real bug caught live while verifying Part C
(2026-08-25): routes/case_index.py's PARSED_ARTIFACT_TYPE_LABELS is a
hardcoded allowlist that gates case_index_parsed_artifacts() (the row-
fetch route File Views' "Parsed Artifacts" category actually calls) -
forgetting a new artifact_type there means case_index_summary()'s COUNT
still shows real rows exist (no such gate on that query) while the
row-fetch route silently returns an empty list for that exact type. This
asserts the label map stays in sync with every artifact_type string the
parser modules can actually produce, so a future new artifact_type
missing from this map fails a test instead of shipping silently broken.

Skipped (not failed) on a non-POSIX dev machine: routes/case_index.py
needs core.jobs, which imports POSIX-only pwd/fcntl.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.case_index needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.case_index as case_index
import core.evtx_utils as evtx_utils

_BROWSER_ARTIFACT_TYPES = {
    "chrome_history", "chrome_downloads", "chrome_bookmarks", "chrome_cookies",
    "firefox_history", "firefox_downloads", "firefox_bookmarks", "firefox_cookies",
}
_REGISTRY_ARTIFACT_TYPES = {
    "registry_recent_docs", "registry_typed_urls", "registry_run_history",
    "registry_usb_history", "registry_installed_programs", "registry_amcache",
}
_LNK_ARTIFACT_TYPES = {"lnk_shortcut"}
_PREFETCH_ARTIFACT_TYPES = {"prefetch_execution"}
_RECYCLEBIN_ARTIFACT_TYPES = {"recyclebin_deleted_file"}
_LINUX_ARTIFACT_TYPES = {
    "linux_shell_history", "linux_passwd_account", "linux_cron_job",
    "linux_auth_log", "linux_journald_log", "linux_wtmp_login",
}
_URL_IOC_ARTIFACT_TYPES = {"browser_url_ioc_match"}
_CRYPTO_ARTIFACT_TYPES = {"crypto_wallet_file"}


def test_parsed_artifact_type_labels_covers_every_known_producer():
    evtx_types = {v[0] for v in evtx_utils.EVENT_ID_ALLOWLIST.values()}
    expected = (_BROWSER_ARTIFACT_TYPES | _REGISTRY_ARTIFACT_TYPES | evtx_types | _LNK_ARTIFACT_TYPES
                | _PREFETCH_ARTIFACT_TYPES | _RECYCLEBIN_ARTIFACT_TYPES | _LINUX_ARTIFACT_TYPES
                | _URL_IOC_ARTIFACT_TYPES | _CRYPTO_ARTIFACT_TYPES)
    actual = set(case_index.PARSED_ARTIFACT_TYPE_LABELS.keys())
    missing = expected - actual
    assert not missing, f"artifact_type(s) producible by a parser but missing from PARSED_ARTIFACT_TYPE_LABELS (row-fetch route would silently return no rows for these): {missing}"
