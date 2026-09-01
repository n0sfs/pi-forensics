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
_MOBILE_ARTIFACT_TYPES = {"mobile_sms_message", "mobile_contact", "mobile_call_log"}
_NTFS_JOURNAL_ARTIFACT_TYPES = {"mft_file_record", "usnjrnl_change_record"}
_REGISTRY_ARTIFACT_TYPES = _REGISTRY_ARTIFACT_TYPES | {"registry_shellbag", "registry_shimcache"}
_EMAIL_ARTIFACT_TYPES = {"email_message"}
# Live Collection USB, Phase 2 (2026-09-01) - core/live_collection_results_utils.py.
_LIVE_COLLECTION_ARTIFACT_TYPES = {
    "live_collection_process", "live_collection_network_connection",
    "live_collection_logged_on_user", "live_collection_service",
    "live_collection_scheduled_task", "live_collection_autorun",
    "live_collection_mapped_drive", "live_collection_clipboard",
    "live_collection_hash_list_match",
}
# Android forensics expansion, Phase B - core/android_artifacts.py. In-image
# only (rooted `physical` acquisitions), never a real-fs `pull` output.
_ANDROID_ARTIFACT_TYPES = {"android_sms_message", "android_contact", "android_call_log"}
# Android forensics expansion, Phase A - core/leapp_tsv_utils.py. Imported
# directly (not hand-copied) since this set is the module's own single
# source of truth for what it can produce - duplicating it by hand here
# would just be a second place to forget an update.
import core.leapp_tsv_utils as leapp_tsv_utils
_LEAPP_TSV_ARTIFACT_TYPES = leapp_tsv_utils.LEAPP_TSV_ALL_ARTIFACT_TYPES
# Android forensics expansion, Phase D - core/takeout_utils.py.
_TAKEOUT_ARTIFACT_TYPES = {
    "takeout_search_history", "takeout_youtube_history", "takeout_location_history",
    "takeout_maps_place", "takeout_photo_metadata",
}
# Android/iOS forensics expansion, Apple export - core/apple_export_utils.py.
_APPLE_EXPORT_ARTIFACT_TYPES = {
    "apple_contact", "apple_calendar_event", "apple_reminder",
    "apple_safari_bookmark", "apple_photo_metadata",
}


def test_parsed_artifact_type_labels_covers_every_known_producer():
    evtx_types = {v[0] for v in evtx_utils.EVENT_ID_ALLOWLIST.values()}
    expected = (_BROWSER_ARTIFACT_TYPES | _REGISTRY_ARTIFACT_TYPES | evtx_types | _LNK_ARTIFACT_TYPES
                | _PREFETCH_ARTIFACT_TYPES | _RECYCLEBIN_ARTIFACT_TYPES | _LINUX_ARTIFACT_TYPES
                | _URL_IOC_ARTIFACT_TYPES | _CRYPTO_ARTIFACT_TYPES | _MOBILE_ARTIFACT_TYPES
                | _NTFS_JOURNAL_ARTIFACT_TYPES | _EMAIL_ARTIFACT_TYPES | _LIVE_COLLECTION_ARTIFACT_TYPES
                | _ANDROID_ARTIFACT_TYPES | _LEAPP_TSV_ARTIFACT_TYPES | _TAKEOUT_ARTIFACT_TYPES
                | _APPLE_EXPORT_ARTIFACT_TYPES)
    actual = set(case_index.PARSED_ARTIFACT_TYPE_LABELS.keys())
    missing = expected - actual
    assert not missing, f"artifact_type(s) producible by a parser but missing from PARSED_ARTIFACT_TYPE_LABELS (row-fetch route would silently return no rows for these): {missing}"
