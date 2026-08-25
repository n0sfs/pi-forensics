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
    has_case_analysis_activity,
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
    "lnk_shortcut": "LNK Shortcuts",
    # Follow-up (2026-08-25) - Amcache (a 4th registry hive, folded into
    # the existing registry_utils.py dispatch), Prefetch, and Recycle Bin -
    # the same "add every new artifact_type here or the row-fetch route
    # silently returns nothing for it" gate this comment already warns
    # about above.
    "registry_amcache": "Registry: Amcache Application Inventory",
    "prefetch_execution": "Prefetch: Program Execution",
    "recyclebin_deleted_file": "Recycle Bin: Deleted Files",
    # Linux Artifact Parsing (2026-08-25) - this app's first Linux-specific
    # artifact parsers (core/linux_artifacts.py). wtmp is deliberately
    # labeled "Experimental" - see that module's own docstring for why
    # (an architecture/glibc-build-dependent raw struct layout, not a
    # stable OS-defined wire format like every other binary artifact here).
    "linux_shell_history": "Linux: Shell History",
    "linux_passwd_account": "Linux: /etc/passwd Accounts",
    "linux_cron_job": "Linux: Cron Jobs",
    "linux_auth_log": "Linux: Auth Log (SSH/sudo/session)",
    "linux_wtmp_login": "Linux: Login History (wtmp, Experimental)",
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
