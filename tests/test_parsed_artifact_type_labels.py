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
    # Safari, 2026-09-01 - core/browser_artifacts.py's own third browser family.
    "safari_history", "safari_downloads", "safari_bookmarks", "safari_cookies",
}
_REGISTRY_ARTIFACT_TYPES = {
    "registry_recent_docs", "registry_typed_urls", "registry_run_history",
    "registry_usb_history", "registry_installed_programs", "registry_amcache",
}
_LNK_ARTIFACT_TYPES = {"lnk_shortcut"}
_PREFETCH_ARTIFACT_TYPES = {"prefetch_execution"}
_RECYCLEBIN_ARTIFACT_TYPES = {"recyclebin_deleted_file"}
# Windows Jump Lists, 2026-09-01 - core/jumplist_utils.py.
_JUMPLIST_ARTIFACT_TYPES = {"jumplist_automatic_entry", "jumplist_custom_shortcut"}
# Windows Thumbcache, 2026-09-01 - core/thumbcache_utils.py.
_THUMBCACHE_ARTIFACT_TYPES = {"thumbcache_thumbnail"}
_LINUX_ARTIFACT_TYPES = {
    "linux_shell_history", "linux_passwd_account", "linux_cron_job",
    "linux_auth_log", "linux_journald_log", "linux_wtmp_login",
}
_URL_IOC_ARTIFACT_TYPES = {"browser_url_ioc_match"}
_CRYPTO_ARTIFACT_TYPES = {"crypto_wallet_file"}
_MOBILE_ARTIFACT_TYPES = {"mobile_sms_message", "mobile_contact", "mobile_call_log"}
_NTFS_JOURNAL_ARTIFACT_TYPES = {"mft_file_record", "usnjrnl_change_record"}
_REGISTRY_ARTIFACT_TYPES = _REGISTRY_ARTIFACT_TYPES | {
    "registry_shellbag", "registry_shimcache", "registry_userassist",
    "registry_bam_dam", "registry_rdp_server", "registry_rdp_mru",
    "office_mru_file", "office_mru_place", "registry_wordwheelquery",
    "registry_bluetooth_device",
}
# Windows Sticky Notes, 2026-09-01 - core/stickynotes_utils.py.
_STICKY_NOTES_ARTIFACT_TYPES = {"sticky_note"}
_EMAIL_ARTIFACT_TYPES = {"email_message"}
# Live Collection USB, Phase 2 (2026-09-01) - core/live_collection_results_utils.py.
_LIVE_COLLECTION_ARTIFACT_TYPES = {
    "live_collection_process", "live_collection_network_connection",
    "live_collection_logged_on_user", "live_collection_service",
    "live_collection_scheduled_task", "live_collection_autorun",
    "live_collection_mapped_drive", "live_collection_clipboard",
    "live_collection_hash_list_match",
    # 2026-09-03: already-collected-but-never-parsed files.
    "live_collection_system_info", "live_collection_system_boot",
    "live_collection_arp_entry", "live_collection_dns_cache_entry",
    "live_collection_installed_hotfix", "live_collection_loaded_driver",
}
# Android forensics expansion, Phase B - core/android_artifacts.py. In-image
# only (rooted `physical` acquisitions), never a real-fs `pull` output.
# android_mms_message added 2026-09-04, Android pattern-of-life item 5 -
# same mmssms.db file, same rooted-physical-image-only constraint.
_ANDROID_ARTIFACT_TYPES = {"android_sms_message", "android_contact", "android_call_log", "android_mms_message"}
# .ab Android Backup Format decoder (core/android_backup_utils.py,
# 2026-09-04) - reachable both real-fs (this app's own "Backup" acquisition
# mode's own output - the common case, needs no root at all) and in-image (a
# .ab file found inside an already-acquired image).
_ANDROID_AB_ARTIFACT_TYPES = {"android_ab_sms_message", "android_ab_mms_message"}
# Installed-app inventory (routes/mobile.py, 2026-09-04) - deliberately
# NOT in the set above: unlike those 3, this needs no root at all and is
# captured automatically during a plain `adb pull`, recorded directly by
# the acquisition worker itself rather than a later File Explorer "Parse
# ..." action.
_ANDROID_APP_INVENTORY_ARTIFACT_TYPES = {"android_installed_app"}
# Configured accounts + notification snapshot (routes/mobile.py, 2026-09-04)
# - same no-root, captured-automatically-during-a-pull shape as the app
# inventory above.
_ANDROID_ACCOUNTS_NOTIFICATIONS_ARTIFACT_TYPES = {"android_configured_account", "android_notification_snapshot"}
# Native WhatsApp msgstore.db/wa.db parsing (core/whatsapp_utils.py,
# 2026-09-04) - reachable both real-fs (this app's own decrypt feature's
# output) and in-image (a rooted physical image).
_WHATSAPP_NATIVE_ARTIFACT_TYPES = {"whatsapp_message", "whatsapp_call_log", "whatsapp_contact"}
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
    "takeout_contact", "takeout_calendar_event", "takeout_reminder",
}
# Android/iOS forensics expansion, Apple export - core/apple_export_utils.py.
_APPLE_EXPORT_ARTIFACT_TYPES = {
    "apple_contact", "apple_calendar_event", "apple_reminder",
    "apple_safari_bookmark", "apple_photo_metadata",
}
# wpndatabase.db / ActivitiesCache.db, 2026-09-01 - core/windows_activity_utils.py.
_WINDOWS_ACTIVITY_ARTIFACT_TYPES = {"windows_notification", "windows_timeline_activity"}
# SRUM (SRUDB.dat), 2026-09-01 - core/srum_utils.py.
_SRUM_ARTIFACT_TYPES = {"srum_app_usage", "srum_network_usage"}
# PowerShell console history / Windows Firewall log, 2026-09-01 -
# core/powershell_history_utils.py / core/firewall_log_utils.py.
_POWERSHELL_HISTORY_ARTIFACT_TYPES = {"powershell_console_history"}
_FIREWALL_LOG_ARTIFACT_TYPES = {"firewall_connection_log"}
# macOS LaunchAgents/LaunchDaemons, 2026-09-01 - core/macos_launchd_utils.py.
_MACOS_LAUNCHD_ARTIFACT_TYPES = {"macos_launchd_item"}
# Windows Search Index / legacy IE-Edge WebCache / BITS job queue,
# 2026-09-01 - core/winsearch_utils.py / core/webcache_utils.py /
# core/bits_utils.py.
_WINSEARCH_ARTIFACT_TYPES = {"winsearch_indexed_item"}
_WEBCACHE_ARTIFACT_TYPES = {"webcache_entry"}
_BITS_ARTIFACT_TYPES = {"bits_job"}
# RDP Bitmap Cache, 2026-09-01 - core/rdp_bitmap_cache_utils.py.
_RDP_BITMAP_CACHE_ARTIFACT_TYPES = {"rdp_bitmap_cache_tile"}
# Android bugreport deep-parse, structured extraction (core/bugreport_
# utils.py, 2026-09-04, Android pattern-of-life item 6) - see that
# module's _extract_parsed_artifact_records() docstring for exact scope.
_ANDROID_BUGREPORT_ARTIFACT_TYPES = {
    "android_bugreport_package_event", "android_bugreport_location",
    "android_bugreport_crash", "android_bugreport_kernel_module", "android_bugreport_power_event",
}


def test_parsed_artifact_type_labels_covers_every_known_producer():
    evtx_types = {v[0] for v in evtx_utils.EVENT_ID_ALLOWLIST.values()}
    expected = (_BROWSER_ARTIFACT_TYPES | _REGISTRY_ARTIFACT_TYPES | evtx_types | _LNK_ARTIFACT_TYPES
                | _PREFETCH_ARTIFACT_TYPES | _RECYCLEBIN_ARTIFACT_TYPES | _JUMPLIST_ARTIFACT_TYPES
                | _THUMBCACHE_ARTIFACT_TYPES | _STICKY_NOTES_ARTIFACT_TYPES | _LINUX_ARTIFACT_TYPES
                | _URL_IOC_ARTIFACT_TYPES | _CRYPTO_ARTIFACT_TYPES | _MOBILE_ARTIFACT_TYPES
                | _NTFS_JOURNAL_ARTIFACT_TYPES | _EMAIL_ARTIFACT_TYPES | _LIVE_COLLECTION_ARTIFACT_TYPES
                | _ANDROID_ARTIFACT_TYPES | _ANDROID_AB_ARTIFACT_TYPES | _ANDROID_APP_INVENTORY_ARTIFACT_TYPES
                | _ANDROID_ACCOUNTS_NOTIFICATIONS_ARTIFACT_TYPES | _WHATSAPP_NATIVE_ARTIFACT_TYPES
                | _LEAPP_TSV_ARTIFACT_TYPES | _TAKEOUT_ARTIFACT_TYPES
                | _APPLE_EXPORT_ARTIFACT_TYPES | _WINDOWS_ACTIVITY_ARTIFACT_TYPES | _SRUM_ARTIFACT_TYPES
                | _POWERSHELL_HISTORY_ARTIFACT_TYPES | _FIREWALL_LOG_ARTIFACT_TYPES
                | _MACOS_LAUNCHD_ARTIFACT_TYPES | _WINSEARCH_ARTIFACT_TYPES | _WEBCACHE_ARTIFACT_TYPES
                | _BITS_ARTIFACT_TYPES | _RDP_BITMAP_CACHE_ARTIFACT_TYPES | _ANDROID_BUGREPORT_ARTIFACT_TYPES)
    actual = set(case_index.PARSED_ARTIFACT_TYPE_LABELS.keys())
    missing = expected - actual
    assert not missing, f"artifact_type(s) producible by a parser but missing from PARSED_ARTIFACT_TYPE_LABELS (row-fetch route would silently return no rows for these): {missing}"
