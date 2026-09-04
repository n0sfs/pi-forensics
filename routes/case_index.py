"""Case Index: the per-case SQLite tag/analysis-history index's route
handlers (tagging a file/in-image entry, listing tags, per-path analysis-
result history, the File Views summary/files/hits queries). The shared
query/write helpers these call (_case_index_open_readonly,
_case_index_open_write, _tags_for_paths, _analysis_results_for_paths,
_record_analysis_result) live in core/case_index_db.py, not here - this
module only holds the Flask route layer.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import json
import time
import sqlite3

from flask import Blueprint, jsonify, request, g

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, classify_extension, case_consolidated_path, FILE_VIEW_EXTENSION_CATEGORIES
from core.case_index_db import (
    case_index_db_path, _case_index_connect,
    _case_index_open_readonly, _case_index_open_write,
    _tags_for_paths, _analysis_results_for_paths, TRIAGE_PATTERNS,
    _backfill_case_artifact_tags, KEYWORD_CATEGORY_PREFIX, resolve_scan_category_label,
    has_case_analysis_activity, cross_case_hash_search, correlate_contacts,
)

case_index_bp = Blueprint('case_index', __name__)

# Only routes/case_index.py uses this - genuinely single-consumer, so it
# stays a local constant rather than moving into core/.
ALLOWED_TAG_COLORS = ('primary', 'secondary', 'success', 'danger', 'warning', 'info')

# _case_index_open_readonly/_case_index_open_write/_tags_for_paths/
# _analysis_results_for_paths/_record_analysis_result (and
# ANALYSIS_RESULT_MAX_PER_PATH/ANALYSIS_RESULT_MAX_OUTPUT_CHARS) now live in
# core/case_index_db.py (imported at the top of this file) - see the Step 0
# core/ extraction.

@case_index_bp.route('/api/case_index/tags_for_paths', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def case_index_tags_for_paths():
    req = request.get_json() or {}
    paths = [safe_path(p) for p in (req.get('paths') or [])]
    paths = [p for p in paths if p]
    return jsonify({"success": True, "tags": _tags_for_paths(req.get('case_folder'), paths)})

@case_index_bp.route('/api/case_index/analysis_for_paths', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def case_index_analysis_for_paths():
    req = request.get_json() or {}
    paths = [safe_path(p) for p in (req.get('paths') or [])]
    paths = [p for p in paths if p]
    return jsonify({"success": True, "results": _analysis_results_for_paths(req.get('case_folder'), paths)})

@case_index_bp.route('/api/cases/cross_search', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def cases_cross_search():
    """Station-wide hash lookup across EVERY case's own case JSON (not
    scoped to whichever case is currently active) - v1 of a genuinely new
    capability, not an extension of anything that existed before (confirmed
    via a full repo search: no cross-case query mechanism existed anywhere
    prior to this). No new permission key was introduced for this - an
    account with 'reporting' or 'file_explorer' already has broad evidence-
    reading capability station-wide via other routes (e.g. File Explorer's
    own path browsing is bounded only by EVIDENCE_ROOT, not by which case
    is "active"), so this doesn't cross a genuinely new privilege boundary,
    just adds a new UI surface onto already-reachable data - see core/
    case_index_db.py's cross_case_hash_search() for the actual search and
    its documented v1 scope (hash-only; keyword/tag search is an explicit,
    deferred v2)."""
    req = request.get_json() or {}
    hash_value = (req.get('hash') or '').strip()
    if not hash_value:
        return jsonify({"success": False, "error": "No hash value provided."}), 400
    results, truncated = cross_case_hash_search(hash_value)
    return jsonify({"success": True, "results": results, "truncated": truncated})

@case_index_bp.route('/api/case_index/summary', methods=['POST'])
@requires_auth
@requires_permission('file_explorer', 'reporting')  # Reporting's Files tab reads parsed_artifact_counts for its Web Artifacts section too
def case_index_summary():
    req = request.get_json() or {}
    case_folder = req.get('case_folder')
    # Self-heals the four role-specific artifact-tag buckets (Report Export /
    # Analysis Log & Hash / Geolocation Export / Backup Snapshot) every time
    # File Views loads, and migrates any pre-existing lump 'Case Artifact'
    # tag off onto them - see the function's own docstring for why this
    # can't just rely on the per-write-site auto-tagging alone.
    _backfill_case_artifact_tags(case_folder)
    conn = _case_index_open_readonly(case_folder)
    by_extension = {cat: 0 for cat in FILE_VIEW_EXTENSION_CATEGORIES}
    keyword_hits = {name: 0 for name in TRIAGE_PATTERNS}
    custom_keyword_hits = []  # any keyword-list-derived categories ('kw_<id>') a scan actually recorded hits under - see build_scan_patterns()
    parsed_artifact_counts = {}  # {artifact_type: count} - whatever core/browser_artifacts.py has actually parsed into this case; see routes/file_explorer.py's/routes/image_browser.py's parse_browser_artifacts routes
    deleted_files = 0
    total_files = 0
    tags = []
    analysis_results_count = 0
    if conn:
        try:
            for row in conn.execute("SELECT category, COUNT(*) FROM indexed_files WHERE deleted=0 GROUP BY category"):
                if row[0] in by_extension:
                    by_extension[row[0]] = row[1]
            deleted_files = conn.execute("SELECT COUNT(*) FROM indexed_files WHERE deleted=1").fetchone()[0]
            total_files = conn.execute("SELECT COUNT(*) FROM indexed_files WHERE deleted=0").fetchone()[0]
            for row in conn.execute("SELECT category, COUNT(*) FROM triage_hits GROUP BY category"):
                if row[0] in keyword_hits:
                    keyword_hits[row[0]] = row[1]
                elif row[0].startswith(KEYWORD_CATEGORY_PREFIX):
                    custom_keyword_hits.append({"category": row[0], "label": resolve_scan_category_label(row[0]), "count": row[1]})
            for row in conn.execute("SELECT artifact_type, COUNT(*) FROM parsed_artifacts GROUP BY artifact_type"):
                parsed_artifact_counts[row[0]] = row[1]
            for row in conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, t.is_default, "
                    "(SELECT COUNT(*) FROM tagged_items WHERE tag_id=t.id) "
                    "FROM tags t ORDER BY t.is_default DESC, t.name"):
                tags.append({"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3]),
                             "is_default": bool(row[4]), "count": row[5]})
            # Binwalk/ClamAV/Strings/Memory Forensics/Hash-Directory-Tree all
            # write here via core.case_index_db._record_analysis_result() -
            # the one signal below (has_analysis_activity) that isn't already
            # covered by total_files/keyword_hits/parsed_artifact_counts, all
            # three of which are specific to the whole-image Triage Scan /
            # keyword-list scans / browser-artifact parsing respectively.
            analysis_results_count = conn.execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0]
        finally:
            conn.close()
    keyword_hit_total = sum(keyword_hits.values()) + sum(c['count'] for c in custom_keyword_hits)
    has_analysis_activity = has_case_analysis_activity(
        analysis_results_count, total_files, keyword_hit_total, parsed_artifact_counts, tags)
    return jsonify({
        "success": True,
        "indexed": conn is not None,
        "total_files": total_files,
        "by_extension": by_extension,
        "deleted_files": deleted_files,
        "keyword_hits": {"total": keyword_hit_total, **keyword_hits},
        "custom_keyword_hits": custom_keyword_hits,
        "parsed_artifact_counts": parsed_artifact_counts,
        "tags": tags,
        "analysis_results_count": analysis_results_count,
        "has_analysis_activity": has_analysis_activity,
    })

PARSED_ARTIFACT_TYPE_LABELS = {
    "chrome_history": "Chrome/Chromium History", "chrome_downloads": "Chrome/Chromium Downloads",
    "chrome_bookmarks": "Chrome/Chromium Bookmarks", "chrome_cookies": "Chrome/Chromium Cookies",
    "firefox_history": "Firefox History", "firefox_downloads": "Firefox Downloads",
    "firefox_bookmarks": "Firefox Bookmarks", "firefox_cookies": "Firefox Cookies",
    "safari_history": "Safari History", "safari_downloads": "Safari Downloads",
    "safari_bookmarks": "Safari Bookmarks", "safari_cookies": "Safari Cookies",
    # Part C (2026-08-25) - Registry/Event Log/LNK parsing. A real bug was
    # caught live while verifying this: this allowlist is what actually
    # gates case_index_parsed_artifacts() below - forgetting an entry here
    # meant the summary count (case_index_summary(), which has no such
    # gate) correctly showed real rows existed, while the row-fetch route
    # silently returned an empty list for every one of these 7 new types.
    "registry_recent_docs": "Registry: Recent Documents", "registry_typed_urls": "Registry: Typed URLs/Paths",
    "registry_run_history": "Registry: Run History", "registry_usb_history": "Registry: USB Device History",
    "registry_installed_programs": "Registry: Installed Programs",
    "evtx_logon_success": "Event Log: Successful Logons", "evtx_logon_failure": "Event Log: Failed Logons",
    "evtx_process_creation": "Event Log: Process Creation", "evtx_account_created": "Event Log: Account Created",
    "evtx_service_installed": "Event Log: Service Installed", "evtx_audit_log_cleared": "Event Log: Audit Log Cleared",
    # 2026-09-03: closing the "not globally unique" gap found while
    # building Live Collection USB's own live .evtx export (see
    # core/evtx_utils.py's EVENT_ID_ALLOWLIST comment).
    "evtx_service_state_change": "Event Log: Service Started/Stopped",
    "evtx_workstation_locked": "Event Log: Workstation Locked",
    "evtx_workstation_unlocked": "Event Log: Workstation Unlocked",
    "lnk_shortcut": "LNK Shortcuts",
    # Follow-up (2026-08-25) - Amcache (a 4th registry hive, folded into
    # the existing registry_utils.py dispatch), Prefetch, and Recycle Bin -
    # the same "add every new artifact_type here or the row-fetch route
    # silently returns nothing for it" gate this comment already warns
    # about above.
    "registry_amcache": "Registry: Amcache Application Inventory",
    "prefetch_execution": "Prefetch: Program Execution",
    "recyclebin_deleted_file": "Recycle Bin: Deleted Files",
    "jumplist_automatic_entry": "Jump List: Automatic Destinations",
    "jumplist_custom_shortcut": "Jump List: Custom Destinations",
    # Thumbcache (2026-09-01) - core/thumbcache_utils.py. The one artifact
    # type in this whole map whose 'value' is a real, extracted, directly
    # openable image file on disk rather than a text summary - every other
    # field/behavior (this label map, File Views, the Evidence Timeline's
    # NULL-timestamp filtering) needed zero special-casing for that.
    "thumbcache_thumbnail": "Thumbcache: Extracted Thumbnail",
    # Linux Artifact Parsing (2026-08-25) - this app's first Linux-specific
    # artifact parsers (core/linux_artifacts.py). wtmp is deliberately
    # labeled "Experimental" - see that module's own docstring for why
    # (an architecture/glibc-build-dependent raw struct layout, not a
    # stable OS-defined wire format like every other binary artifact here).
    "linux_shell_history": "Linux: Shell History",
    "linux_passwd_account": "Linux: /etc/passwd Accounts",
    "linux_cron_job": "Linux: Cron Jobs",
    "linux_auth_log": "Linux: Auth Log (SSH/sudo/session)",
    "linux_journald_log": "Linux: Journal Log (SSH/sudo/session)",
    "linux_wtmp_login": "Linux: Login History (wtmp, Experimental)",
    # URL Lists (2026-08-26) - a flagged match between a parsed browser
    # history/bookmark/download URL and a station-wide known-bad URL list
    # (e.g. an imported URLhaus feed).
    "browser_url_ioc_match": "Browser: Known-Bad URL Match",
    # Crypto wallet-file detection (2026-08-26, gap-closing round) - a
    # filename/path classifier only (core/crypto_artifacts.py), not internal
    # wallet-content parsing - see that module's docstring for why.
    "crypto_wallet_file": "Cryptocurrency Wallet File",
    # Mobile chat/app artifact parsing (2026-08-26, gap-closing round) - an
    # already-pulled, unencrypted iOS backup's SMS/iMessage/Contacts/Call
    # History (core/mobile_artifacts.py).
    "mobile_sms_message": "Mobile: SMS/iMessage",
    "mobile_contact": "Mobile: Contacts",
    "mobile_call_log": "Mobile: Call History",
    # Android SMS/Contacts/Call Log, in-image only (core/android_
    # artifacts.py) - a rooted `physical` acquisition's raw image only,
    # never a non-rooted `pull`'s /sdcard folder (see that module's own
    # docstring for the grounded reasoning). Not yet tested against real
    # rooted-device hardware - disclosed gap, see the same docstring.
    "android_sms_message": "Android: SMS (Rooted Physical Image Only)",
    "android_contact": "Android: Contacts (Rooted Physical Image Only)",
    "android_call_log": "Android: Call Log (Rooted Physical Image Only)",
    # MMS (2026-09-04, Android pattern-of-life item 5) - the pdu/part/addr
    # tables live in this exact same mmssms.db file, so it carries the
    # identical rooted-physical-image-only constraint as the 3 above.
    # android_sms_message's own label was corrected from "SMS/MMS" to
    # plain "SMS" in this same pass - it never actually produced MMS
    # records before this type existed.
    "android_mms_message": "Android: MMS (Rooted Physical Image Only)",
    # .ab Android Backup Format decoder (core/android_backup_utils.py,
    # 2026-09-04, same pattern-of-life follow-up) - the non-root counterpart
    # to the 4 rooted-only android_* types above: this app's own Mobile
    # Forensics "Backup" acquisition mode (`adb backup`) already produces a
    # real .ab file with no root needed at all, reachable both real-fs (the
    # common case) and in-image (a .ab file found inside an already-acquired
    # image).
    "android_ab_sms_message": "Android Backup (.ab): SMS",
    "android_ab_mms_message": "Android Backup (.ab): MMS",
    # Installed-app inventory (routes/mobile.py::_capture_android_app_
    # inventory(), 2026-09-04) - unlike the 3 rooted-physical-only types
    # right above, this needs NO root: it's a live `adb shell dumpsys
    # package packages` query captured automatically during any real
    # `adb pull` acquisition, so the label must not carry the misleading
    # "Rooted Physical Image Only" caveat those 3 correctly do.
    "android_installed_app": "Android: Installed App Inventory (adb pull)",
    # Native WhatsApp msgstore.db/wa.db parsing (core/whatsapp_utils.py,
    # 2026-09-04) - reachable either from this app's own WhatsApp-decrypt
    # feature's output (a real file, no root needed) or a rooted physical
    # image's /data/data/com.whatsapp/databases/ folder - see that
    # module's own docstring for the full ALEAPP-grounded schema
    # confirmation. Distinct from the leapp_whatsapp_* types just below,
    # since this is a genuinely different source (native parse vs ALEAPP).
    "whatsapp_message": "WhatsApp: Messages (Native Parse)",
    "whatsapp_call_log": "WhatsApp: Calls (Native Parse)",
    "whatsapp_contact": "WhatsApp: Contacts (Native Parse)",
    # ALEAPP/iLEAPP TSV-export parsing (core/leapp_tsv_utils.py) - real,
    # confirmed module names promoted to their own type, plus one shared
    # fallback bucket ("Module Finding") for any other module that finds
    # real data this app's own curated list didn't anticipate. Findings
    # here vary heavily by acquisition mode - see that module's own
    # docstring for the real, grounded reason a non-rooted `pull`
    # extraction commonly yields few or no hits.
    "leapp_device_info": "ALEAPP/iLEAPP: Device Info",
    "leapp_wifi_network": "ALEAPP/iLEAPP: WiFi Networks",
    "leapp_installed_app": "ALEAPP/iLEAPP: Installed Apps",
    "leapp_account": "ALEAPP/iLEAPP: Accounts",
    "leapp_sms_message": "ALEAPP/iLEAPP: SMS Messages",
    # Timeline-timestamp parsing added 2026-09-01, per real module-source
    # archaeology against this app's own pinned ALEAPP commit (see core/
    # leapp_tsv_utils.py's own docstring for the full grounding) - several
    # new curated types added alongside it (MMS, WhatsApp Calls, Web
    # Visits, and the message-level modules for Instagram/Snapchat/
    # Facebook Messenger/Telegram/Signal/TikTok/Reddit) so the Evidence
    # Timeline's new category filter (Communications/Web Activity/Social
    # Media - routes/reporting.py's TIMELINE_ACTIVITY_CATEGORY) has real
    # timestamped data to show for a phone, not just a searchable-but-
    # timeline-invisible entry the way every LEAPP-sourced type was before.
    "leapp_mms_message": "ALEAPP/iLEAPP: MMS Messages",
    "leapp_call_log": "ALEAPP/iLEAPP: Call Logs",
    "leapp_contact": "ALEAPP/iLEAPP: Contacts",
    "leapp_browser_history": "ALEAPP/iLEAPP: Browser History",
    "leapp_browser_web_visit": "ALEAPP/iLEAPP: Browser Web Visits",
    "leapp_browser_bookmark": "ALEAPP/iLEAPP: Browser Bookmarks",
    "leapp_browser_autofill": "ALEAPP/iLEAPP: Browser Autofill",
    "leapp_whatsapp_message": "ALEAPP/iLEAPP: WhatsApp Messages",
    "leapp_whatsapp_call_log": "ALEAPP/iLEAPP: WhatsApp Calls",
    "leapp_whatsapp_contact": "ALEAPP/iLEAPP: WhatsApp Contacts",
    "leapp_instagram_message": "ALEAPP/iLEAPP: Instagram Direct Messages",
    "leapp_snapchat_message": "ALEAPP/iLEAPP: Snapchat Messages",
    "leapp_facebook_messenger_message": "ALEAPP/iLEAPP: Facebook Messenger Chats",
    "leapp_telegram_message": "ALEAPP/iLEAPP: Telegram Messages",
    "leapp_signal_message": "ALEAPP/iLEAPP: Signal Messages",
    "leapp_tiktok_message": "ALEAPP/iLEAPP: TikTok Messages",
    "leapp_reddit_message": "ALEAPP/iLEAPP: Reddit Chat Messages",
    "leapp_app_usage": "ALEAPP/iLEAPP: App Usage Stats",
    "leapp_module_finding": "ALEAPP/iLEAPP: Other Module Finding",
    # Google Takeout import (core/takeout_utils.py) - an already-obtained
    # archive from Google's own official export tool, never live account
    # access. Search/YouTube History use a stable, Google-documented
    # schema; the rest are explicitly labeled "(Best-Effort)" per that
    # module's own disclosed real-world format uncertainty.
    "takeout_search_history": "Google Takeout: Search History",
    "takeout_youtube_history": "Google Takeout: YouTube History",
    "takeout_location_history": "Google Takeout: Location History (Best-Effort)",
    "takeout_maps_place": "Google Takeout: Maps Places (Best-Effort)",
    "takeout_photo_metadata": "Google Takeout: Photo Metadata (Best-Effort)",
    # Gmail/Contacts/Calendar (2026-09-04, Android pattern-of-life
    # follow-up) - all 3 ride genuine open standards this app already
    # parses with high confidence (see the module's own docstring), so
    # none needs a "(Best-Effort)" suffix, matching Contacts/Calendar's
    # own Apple-export siblings just below.
    "takeout_contact": "Google Takeout: Contacts",
    "takeout_calendar_event": "Google Takeout: Calendar Events",
    "takeout_reminder": "Google Takeout: Reminders",
    # Apple "Data & Privacy" export import (core/apple_export_utils.py) -
    # same scope boundary as Google Takeout above. Contacts/Calendars ride
    # genuine open standards (vCard/iCalendar) and need no best-effort
    # label; Safari/Photos do, per that module's own disclosed research.
    "apple_contact": "Apple Export: Contacts",
    "apple_calendar_event": "Apple Export: Calendar Events",
    "apple_reminder": "Apple Export: Reminders",
    "apple_safari_bookmark": "Apple Export: Safari Bookmarks (Best-Effort)",
    "apple_photo_metadata": "Apple Export: Photo Metadata (Best-Effort)",
    # NTFS $MFT / $UsnJrnl parsing (2026-08-30, tool-survey follow-up) -
    # core/mft_utils.py (wraps analyzeMFT) and core/usnjrnl_utils.py
    # (hand-rolled USN_RECORD_V2 parser).
    "mft_file_record": "NTFS: $MFT File Record",
    "usnjrnl_change_record": "NTFS: $UsnJrnl Change Record",
    # ShellBags / Shimcache (2026-08-30, tool-survey follow-up) - both ride
    # the existing Registry hive dispatch (core/registry_utils.py), no new
    # routes needed.
    "registry_shellbag": "Registry: ShellBags (Folder Access)",
    "registry_shimcache": "Registry: Shimcache (Program Execution)",
    "registry_userassist": "Registry: UserAssist (Program Launch History)",
    "registry_bam_dam": "Registry: BAM/DAM (Program Execution)",
    "registry_rdp_server": "Registry: RDP Connection History (Server)",
    "registry_rdp_mru": "Registry: RDP Connection History (Recent)",
    "office_mru_file": "Registry: Office Recent Files",
    "office_mru_place": "Registry: Office Recent Folders",
    "registry_wordwheelquery": "Registry: Explorer Search History",
    # Bluetooth pairing history (2026-09-03, Live Collection USB pattern-
    # of-life follow-up) - rides the existing SYSTEM-hive Registry
    # dispatch too, no new route needed.
    "registry_bluetooth_device": "Registry: Bluetooth Paired Device",
    "sticky_note": "Windows Sticky Notes",
    # SRUM/wpndatabase.db/ActivitiesCache.db (2026-09-01) - a third round of
    # Windows artifact coverage. windows_notification/windows_timeline_
    # activity share one core module (core/windows_activity_utils.py) and
    # ride real-fs+in-image routes; srum_app_usage/srum_network_usage ride
    # a separate ESE-format module (core/srum_utils.py). REMEMBER: also add
    # to FILE_VIEWS_WEB_ARTIFACT_LABELS (static/js/main.js) and
    # tests/test_parsed_artifact_type_labels.py.
    "windows_notification": "Windows Notification History (Action Center)",
    "windows_timeline_activity": "Windows Timeline (Activity History)",
    "srum_app_usage": "SRUM: Application Resource Usage",
    "srum_network_usage": "SRUM: Network Data Usage",
    "powershell_console_history": "PowerShell Console History",
    "firewall_connection_log": "Windows Firewall Connection Log",
    "macos_launchd_item": "macOS: LaunchAgent/LaunchDaemon (Persistence)",
    # Windows Search/WebCache/BITS (2026-09-01, tool-survey reconsidered +
    # newly-identified items) - all three are ESE-format (pyesedb-backed)
    # single-well-known-filename parsers, riding real-fs+in-image routes
    # like every other artifact-parser module. REMEMBER: also add to
    # FILE_VIEWS_WEB_ARTIFACT_LABELS (static/js/main.js) and
    # tests/test_parsed_artifact_type_labels.py.
    "winsearch_indexed_item": "Windows Search Index (Windows.edb)",
    "webcache_entry": "Legacy IE/Edge WebCache History (WebCacheV01/V24.dat)",
    "bits_job": "BITS Job Queue (qmgr.db)",
    "rdp_bitmap_cache_tile": "RDP Bitmap Cache Tile (metadata only)",
    # Email parsing (2026-08-30, tool-survey follow-up) - .eml/.mbox via the
    # standard library, .pst/.ost via libpff-python (core/email_utils.py).
    "email_message": "Email Message",
    # Live Collection USB, Phase 2 (2026-09-01) - volatile artifacts parsed
    # out of a completed collection run's Windows-JSON output (core/live_
    # collection_results_utils.py); clipboard is the one Unix-side type
    # that's individually parsed too (see that module's own docstring for
    # why the rest of UAC's own raw-text output isn't). REMEMBER: also add
    # every new key here to FILE_VIEWS_WEB_ARTIFACT_LABELS in static/js/
    # main.js - forgetting that exact side has already caused a real,
    # documented bug once in this codebase (see that constant's own
    # comment).
    "live_collection_process": "Live Collection: Running Process",
    "live_collection_network_connection": "Live Collection: Network Connection",
    "live_collection_logged_on_user": "Live Collection: Logged-On User/Session",
    "live_collection_service": "Live Collection: Service",
    "live_collection_scheduled_task": "Live Collection: Scheduled Task",
    "live_collection_autorun": "Live Collection: Autorun/Startup Item",
    "live_collection_mapped_drive": "Live Collection: Mapped Network Drive",
    "live_collection_clipboard": "Live Collection: Clipboard Contents",
    "live_collection_hash_list_match": "Live Collection: Hash List Match",
    # 2026-09-03: system_info/arp_cache/dns_cache/installed_hotfixes/
    # loaded_drivers were already collected by windows_collector.ps1 but
    # never had a parser at all - real data sitting unindexed until now.
    "live_collection_system_info": "Live Collection: System Info",
    "live_collection_system_boot": "Live Collection: System Boot Time",
    "live_collection_arp_entry": "Live Collection: ARP Cache Entry",
    "live_collection_dns_cache_entry": "Live Collection: DNS Cache Entry",
    "live_collection_installed_hotfix": "Live Collection: Installed Hotfix",
    "live_collection_loaded_driver": "Live Collection: Loaded Driver",
    # Android bugreport deep-parse, structured extraction (core/bugreport_
    # utils.py::_extract_parsed_artifact_records(), 2026-09-04, Android
    # pattern-of-life item 6) - the genuinely record-shaped sections of a
    # parsed `adb bugreport` archive, now individually searchable instead
    # of only sitting in a raw JSON sidecar file. See that function's own
    # docstring for exactly which 5 of Dumpstate's 17 real fields this
    # covers and why the rest are deliberately out of scope.
    "android_bugreport_package_event": "Android Bugreport: Package Install/Delete Event",
    "android_bugreport_location": "Android Bugreport: GPS Location",
    "android_bugreport_crash": "Android Bugreport: Crash (Tombstone)",
    "android_bugreport_kernel_module": "Android Bugreport: Loaded Kernel Module",
    "android_bugreport_power_event": "Android Bugreport: Power Off/Reset Event",
}

@case_index_bp.route('/api/case_index/parsed_artifacts', methods=['POST'])
@requires_auth
@requires_permission('file_explorer', 'reporting')
def case_index_parsed_artifacts():
    """Lists parsed browser-artifact records (core/browser_artifacts.py) of
    one artifact_type - the query side of File Views' "Web Artifacts"
    category, same request/response shape as case_index_files()/
    case_index_hits() above (category in, rows out) but against
    parsed_artifacts instead of indexed_files/triage_hits, since these rows
    are structured records (a visited URL, a download, a bookmark, a
    cookie), not files - the frontend renders them into their own small
    table rather than reusing the file-row Listing pipeline. Reporting's
    Files tab reuses this same route for its own Web Artifacts section
    (renderReportWebArtifactCategory() in main.js), hence the added
    'reporting' permission key above alongside file_explorer."""
    req = request.get_json() or {}
    category = req.get('category', '')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn and category in PARSED_ARTIFACT_TYPE_LABELS:
        try:
            cur = conn.execute(
                "SELECT source_type, image_path, fs_offset, inode, source_path, title, url, value, timestamp, extra_json "
                "FROM parsed_artifacts WHERE artifact_type=? ORDER BY timestamp DESC LIMIT 5000",
                (category,))
            for r in cur:
                rows.append({
                    "source_type": r[0], "image_path": r[1], "fs_offset": r[2], "inode": r[3],
                    "source_path": r[4], "title": r[5], "url": r[6], "value": r[7], "timestamp": r[8],
                    "extra": json.loads(r[9]) if r[9] else {},
                })
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

@case_index_bp.route('/api/case_index/contact_correlation', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def case_index_contact_correlation():
    """Contact correlation report (core/case_index_db.py::correlate_
    contacts()) - the "who did the evidence owner actually talk to"
    pattern-of-life view: cross-references every already-parsed contact
    source (android_contact/apple_contact/takeout_contact/mobile_contact/
    whatsapp_contact) against every already-parsed communication source
    (SMS/call log/WhatsApp messages+calls, Android and iOS both), resolving
    a raw phone number/JID to a real name wherever the two agree. Purely
    read-only against the already-indexed parsed_artifacts table - runs
    fresh on every request, same as /api/cases/timeline, no new schema."""
    req = request.get_json() or {}
    result = correlate_contacts(req.get('case_folder'))
    return jsonify({"success": True, **result})

@case_index_bp.route('/api/case_index/files', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_files():
    req = request.get_json() or {}
    category = req.get('category', '')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn:
        try:
            if category == '__deleted__':
                cur = conn.execute(
                    "SELECT image_path, fs_offset, inode, path, name, size, deleted, mtime, atime, ctime, crtime FROM indexed_files WHERE deleted=1 ORDER BY path LIMIT 2000")
            elif category in FILE_VIEW_EXTENSION_CATEGORIES:
                cur = conn.execute(
                    "SELECT image_path, fs_offset, inode, path, name, size, deleted, mtime, atime, ctime, crtime FROM indexed_files WHERE category=? AND deleted=0 ORDER BY path LIMIT 2000",
                    (category,))
            else:
                cur = None
            if cur:
                for r in cur:
                    rows.append({"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "name": r[4], "size": r[5], "deleted": bool(r[6]),
                                 "mtime": r[7], "atime": r[8], "ctime": r[9], "crtime": r[10]})
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

@case_index_bp.route('/api/case_index/hits', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_hits():
    req = request.get_json() or {}
    category = req.get('category', '')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn and (category in TRIAGE_PATTERNS or category.startswith(KEYWORD_CATEGORY_PREFIX)):
        try:
            # LEFT JOIN indexed_files for MACB timestamps/size/deleted-status -
            # triage_hits itself never duplicates that data (the same walk
            # that finds a hit always indexes the file too, see
            # execution_worker_image_triage_scan), so this is a read-time
            # enrichment, not a second copy that could drift out of sync.
            cur = conn.execute(
                "SELECT h.image_path, h.fs_offset, h.inode, h.path, h.value, h.source_type, "
                "f.size, f.deleted, f.mtime, f.atime, f.ctime, f.crtime "
                "FROM triage_hits h LEFT JOIN indexed_files f "
                "ON h.image_path = f.image_path AND h.fs_offset = f.fs_offset AND h.inode = f.inode "
                "WHERE h.category=? ORDER BY h.path LIMIT 2000",
                (category,))
            for r in cur:
                row = {"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "value": r[4], "source_type": r[5],
                       "size": r[6], "deleted": bool(r[7]) if r[7] is not None else False,
                       "mtime": r[8], "atime": r[9], "ctime": r[10], "crtime": r[11]}
                if row["image_path"] is None:
                    # A real_fs hit (Quick Triage Scan against a real file) has
                    # no matching indexed_files row - those scans are
                    # deliberately never indexed there (see quick_triage_scan).
                    # Best-effort a live os.stat() instead of leaving these
                    # rows perpetually blank; harmless if the file has since
                    # moved/been deleted.
                    try:
                        st = os.stat(row["path"])
                        row["mtime"], row["atime"], row["ctime"] = int(st.st_mtime), int(st.st_atime), int(st.st_ctime)
                    except OSError:
                        pass
                rows.append(row)
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

# --- Tagging: flag a real filesystem or in-image file as evidence of
# interest (Bookmark/Follow Up/Notable Item by default, custom tags
# supported), modeled on Autopsy's tagging feature. Lives in the same
# per-case SQLite index File Views already reads/writes - tagging is just
# one more analysis-index concern, not a separate subsystem. ---

def _resolve_tag_identity(req):
    """Validates and normalizes the item-identity fields tag_item/
    untag_item/item_tags all take: {source_type, image_path, fs_offset,
    inode, path, name}. Returns the normalized dict, or None if invalid.
    Every path-shaped field is safe_path()-sandboxed - even though most of
    these routes never read the file's content, this app's rule is that any
    endpoint accepting a path from the client goes through safe_path(), and
    the real_fs os.stat() fallback below does read filesystem metadata at
    that path, so the validation is load-bearing there specifically."""
    source_type = req.get('source_type')
    name = (req.get('name') or '').strip()
    if not name:
        return None
    if source_type == 'real_fs':
        path = safe_path(req.get('path')) if req.get('path') else None
        if not path:
            return None
        return {"source_type": "real_fs", "image_path": None, "fs_offset": None, "inode": None,
                "path": path, "name": name}
    elif source_type == 'image':
        image_path = safe_path(req.get('image_path')) if req.get('image_path') else None
        inode = str(req.get('inode') or '').strip()
        if not image_path or not inode:
            return None
        try:
            fs_offset = int(req.get('fs_offset') or 0)
        except (TypeError, ValueError):
            fs_offset = 0
        # Best-effort only - not every in-image call site (full image-mode
        # browsing, inline-nested tree browsing) has a full path string on
        # hand the way a File Views result row does; None here just means
        # this tagged item displays by name alone rather than a full path.
        path = req.get('path') or None
        return {"source_type": "image", "image_path": image_path, "fs_offset": fs_offset, "inode": inode,
                "path": path, "name": name}
    return None

@case_index_bp.route('/api/case_index/tag_item', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_tag_item():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    if not identity:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_write(req.get('case_folder'))
    if not conn:
        return jsonify({"success": False, "error": "No active, consolidated case selected."}), 400

    comment = (req.get('comment') or '').strip() or None
    try:
        tag_id = req.get('tag_id')
        if tag_id:
            row = conn.execute("SELECT id, name, color, notable FROM tags WHERE id=?", (tag_id,)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Tag not found."}), 404
        else:
            new_name = (req.get('new_tag_name') or '').strip()[:60]
            if not new_name:
                return jsonify({"success": False, "error": "Provide either tag_id or new_tag_name."}), 400
            color = req.get('new_tag_color') if req.get('new_tag_color') in ALLOWED_TAG_COLORS else 'secondary'
            notable = 1 if req.get('new_tag_notable') else 0
            # Soft-dedupe by name (INSERT OR IGNORE against the UNIQUE
            # constraint), matching this app's existing precedent for
            # custom report templates/case fields - "creating" a tag whose
            # name already exists just resolves to the existing one rather
            # than erroring or silently making a second copy.
            conn.execute(
                "INSERT OR IGNORE INTO tags (name, color, notable, is_default, created_at) VALUES (?,?,?,0,?)",
                (new_name, color, notable, time.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            row = conn.execute("SELECT id, name, color, notable FROM tags WHERE name=?", (new_name,)).fetchone()
        tag_id, tag_name, tag_color, tag_notable = row[0], row[1], row[2], bool(row[3])

        if identity["source_type"] == "real_fs":
            existing = conn.execute(
                "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
                (tag_id, identity["path"])).fetchone()
        else:
            existing = conn.execute(
                "SELECT id FROM tagged_items WHERE tag_id=? AND source_type='image' AND image_path=? AND fs_offset=? AND inode=?",
                (tag_id, identity["image_path"], identity["fs_offset"], identity["inode"])).fetchone()

        already_tagged = existing is not None
        if already_tagged:
            if comment is not None:
                conn.execute("UPDATE tagged_items SET comment=? WHERE id=?", (comment, existing[0]))
        else:
            conn.execute(
                "INSERT INTO tagged_items (tag_id, source_type, image_path, fs_offset, inode, path, name, comment, tagged_by, tagged_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (tag_id, identity["source_type"], identity["image_path"], identity["fs_offset"], identity["inode"],
                 identity["path"], identity["name"], comment, getattr(g, 'forensic_user', None),
                 time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        log_chain_of_custody("item_tagged", {
            "tag": tag_name, "name": identity["name"],
            "path": identity["path"] or identity.get("image_path"),
        })
    finally:
        conn.close()

    return jsonify({"success": True, "already_tagged": already_tagged,
                     "tag": {"id": tag_id, "name": tag_name, "color": tag_color, "notable": tag_notable}})

@case_index_bp.route('/api/case_index/untag_item', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_untag_item():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    tag_id = req.get('tag_id')
    if not identity or not tag_id:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn:
        return jsonify({"success": True, "removed": False})
    removed = False
    try:
        if identity["source_type"] == "real_fs":
            cur = conn.execute(
                "DELETE FROM tagged_items WHERE tag_id=? AND source_type='real_fs' AND path=?",
                (tag_id, identity["path"]))
        else:
            cur = conn.execute(
                "DELETE FROM tagged_items WHERE tag_id=? AND source_type='image' AND image_path=? AND fs_offset=? AND inode=?",
                (tag_id, identity["image_path"], identity["fs_offset"], identity["inode"]))
        removed = cur.rowcount > 0
        conn.commit()
        if removed:
            log_chain_of_custody("item_untagged", {"tag_id": tag_id, "name": identity["name"],
                                                     "path": identity["path"] or identity.get("image_path")})
    finally:
        conn.close()
    return jsonify({"success": True, "removed": removed})

@case_index_bp.route('/api/case_index/item_tags', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_item_tags():
    req = request.get_json() or {}
    identity = _resolve_tag_identity(req)
    if not identity:
        return jsonify({"success": False, "error": "Invalid or missing item identity."}), 400

    conn = _case_index_open_readonly(req.get('case_folder'))
    tags = []
    if conn:
        try:
            if identity["source_type"] == "real_fs":
                cur = conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, ti.comment FROM tagged_items ti "
                    "JOIN tags t ON ti.tag_id=t.id WHERE ti.source_type='real_fs' AND ti.path=?",
                    (identity["path"],))
            else:
                cur = conn.execute(
                    "SELECT t.id, t.name, t.color, t.notable, ti.comment FROM tagged_items ti "
                    "JOIN tags t ON ti.tag_id=t.id WHERE ti.source_type='image' AND ti.image_path=? AND ti.fs_offset=? AND ti.inode=?",
                    (identity["image_path"], identity["fs_offset"], identity["inode"]))
            for row in cur:
                tags.append({"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3]), "comment": row[4]})
        finally:
            conn.close()
    return jsonify({"success": True, "tags": tags})

@case_index_bp.route('/api/case_index/tagged_files', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_tagged_files():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn and tag_id:
        try:
            cur = conn.execute(
                "SELECT ti.image_path, ti.fs_offset, ti.inode, ti.path, ti.name, ti.comment, ti.source_type, "
                "f.size, f.deleted, f.mtime, f.atime, f.ctime, f.crtime "
                "FROM tagged_items ti LEFT JOIN indexed_files f "
                "ON ti.image_path = f.image_path AND ti.fs_offset = f.fs_offset AND ti.inode = f.inode "
                "WHERE ti.tag_id=? ORDER BY ti.tagged_at DESC LIMIT 2000",
                (tag_id,))
            for r in cur:
                row = {"image_path": r[0], "fs_offset": r[1], "inode": r[2], "path": r[3], "name": r[4],
                       "comment": r[5], "source_type": r[6],
                       "size": r[7], "deleted": bool(r[8]) if r[8] is not None else False,
                       "mtime": r[9], "atime": r[10], "ctime": r[11], "crtime": r[12]}
                if row["image_path"] is None and row["path"]:
                    try:
                        st = os.stat(row["path"])
                        row["mtime"], row["atime"], row["ctime"] = int(st.st_mtime), int(st.st_atime), int(st.st_ctime)
                    except OSError:
                        pass
                rows.append(row)
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

@case_index_bp.route('/api/case_index/all_tagged_items', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def case_index_all_tagged_items():
    """Every tagged item across every tag, in one call - unlike
    case_index_tagged_files() above (one tag at a time, for File Views'
    per-tag browsing), this feeds the Custom Case Field item-picker
    (Reporting > Report Narrative > Case Details), which needs a single
    flat, searchable list of "everything tagged in this case" rather than
    one request per tag."""
    req = request.get_json() or {}
    conn = _case_index_open_readonly(req.get('case_folder'))
    rows = []
    if conn:
        try:
            cur = conn.execute(
                "SELECT ti.path, ti.name, ti.source_type, t.name, t.color "
                "FROM tagged_items ti JOIN tags t ON ti.tag_id = t.id "
                "ORDER BY ti.tagged_at DESC LIMIT 500")
            for path, name, source_type, tag_name, tag_color in cur:
                rows.append({"path": path, "name": name, "source_type": source_type,
                             "tag_name": tag_name, "tag_color": tag_color})
        finally:
            conn.close()
    return jsonify({"success": True, "rows": rows})

# --- Tag management: create/rename/recolor/delete tags themselves (distinct
# from tag_item/untag_item above, which apply/remove a tag on one specific
# file). Reached from Settings > Case & Reporting > Manage Tags, scoped to
# whichever case is active there - tags are per-case data, not a station-wide
# default like the rest of that Settings section. ---

@case_index_bp.route('/api/case_index/tags/create', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_create_tag():
    req = request.get_json() or {}
    conn = _case_index_open_write(req.get('case_folder'))
    if not conn:
        return jsonify({"success": False, "error": "No active, consolidated case selected."}), 400
    try:
        name = (req.get('name') or '').strip()[:60]
        if not name:
            return jsonify({"success": False, "error": "Tag name can't be empty."}), 400
        color = req.get('color') if req.get('color') in ALLOWED_TAG_COLORS else 'secondary'
        notable = 1 if req.get('notable') else 0
        try:
            conn.execute(
                "INSERT INTO tags (name, color, notable, is_default, created_at) VALUES (?,?,?,0,?)",
                (name, color, notable, time.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "error": f'A tag named "{name}" already exists.'}), 409
        row = conn.execute("SELECT id, name, color, notable FROM tags WHERE name=?", (name,)).fetchone()
        log_chain_of_custody("tag_created", {"tag_id": row[0], "name": name})
    finally:
        conn.close()
    return jsonify({"success": True, "tag": {"id": row[0], "name": row[1], "color": row[2], "notable": bool(row[3])}})

@case_index_bp.route('/api/case_index/tags/update', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_update_tag():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn or not tag_id:
        return jsonify({"success": False, "error": "No case index found, or missing tag_id."}), 400
    try:
        row = conn.execute("SELECT id, name FROM tags WHERE id=?", (tag_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Tag not found."}), 404
        new_name = (req.get('name') or '').strip()[:60]
        if not new_name:
            return jsonify({"success": False, "error": "Tag name can't be empty."}), 400
        color = req.get('color') if req.get('color') in ALLOWED_TAG_COLORS else 'secondary'
        notable = 1 if req.get('notable') else 0
        try:
            conn.execute("UPDATE tags SET name=?, color=?, notable=? WHERE id=?", (new_name, color, notable, tag_id))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "error": f'A tag named "{new_name}" already exists.'}), 409
        log_chain_of_custody("tag_updated", {"tag_id": tag_id, "old_name": row[1], "new_name": new_name})
    finally:
        conn.close()
    return jsonify({"success": True})

@case_index_bp.route('/api/case_index/tags/delete', methods=['POST'])
@requires_auth
@requires_permission('file_explorer')
def case_index_delete_tag():
    req = request.get_json() or {}
    tag_id = req.get('tag_id')
    conn = _case_index_open_readonly(req.get('case_folder'))
    if not conn or not tag_id:
        return jsonify({"success": False, "error": "No case index found, or missing tag_id."}), 400
    try:
        row = conn.execute("SELECT id, name, is_default FROM tags WHERE id=?", (tag_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Tag not found."}), 404
        if row[2]:
            return jsonify({"success": False, "error": "Default tags can't be deleted - you can still rename or recolor them."}), 400
        # No FK enforcement in this DB (matches the rest of this schema) -
        # cascade the delete manually so a removed tag doesn't leave orphaned
        # tagged_items rows with a dangling tag_id behind.
        conn.execute("DELETE FROM tagged_items WHERE tag_id=?", (tag_id,))
        conn.execute("DELETE FROM tags WHERE id=?", (tag_id,))
        conn.commit()
        log_chain_of_custody("tag_deleted", {"tag_id": tag_id, "name": row[1]})
    finally:
        conn.close()
    return jsonify({"success": True})
