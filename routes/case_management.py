"""Case Management: create/discover case folders, and one-shot migration
of legacy (pre-consolidated-schema) cases into the modern one-file-
per-case format.

A small, simple cluster - GET/logging routes (list, log_select,
migrate_preview - all read-only, see each one's own comment) stay
@requires_auth-only, matching this app's established "reads are open,
writes are permission-gated" convention. The two genuinely mutating routes
(create_case, migrate_case_apply) originally had NO permission check at
all - found during the 2026-08-22 security audit: even a custom group with
every permission key False could still create case folders and rewrite
on-disk report files via migration, inconsistent with the near-identical,
already-gated case-notes/attach/discover cluster routes/reporting.py
absorbs. No server-side "active case" state is kept here - every
job-starting route already takes `destination` per-request, so selecting a
case is purely a frontend concern.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import json
import time
import uuid

from flask import Blueprint, jsonify, request

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, sanitize_case_slug
from core.config import EVIDENCE_ROOT, get_custom_case_fields
from core.jobs import job_lock, current_job, _write_case_file, _read_case_file
from core.case_index_db import list_case_folders

case_management_bp = Blueprint('case_management', __name__)

# The same 5 values Reporting's own Case Details Status <select> (templates/
# tabs/reporting.html) and its client-side CASE_STATUS_BADGE_CLASS/
# CASE_STATUS_BAR_COLOR mirrors (static/js/main.js) already use - no prior
# backend-side constant existed before /api/cases/set_status needed one to
# validate against (create_case() below just hardcodes the single "Open"
# starting value, never needed the full enum).
CASE_STATUS_VALUES = ('Open', 'In Review', 'On Hold', 'Closed', 'Archived')


@case_management_bp.route('/api/cases/create', methods=['POST'])
@requires_auth
# Broad OR, not just 'reporting': the Active Case Bar (and its Case
# Manager modal, where this is reached) is a global element visible from
# every tab, and creating a case is the prerequisite for using ANY of
# them - an Acquisition-only account must still be able to create a case
# before starting an acquisition. Only an account with none of these four
# (effectively a read-only/no-operational-access group) is excluded.
@requires_permission('acquisition', 'mobile', 'recovery', 'reporting')
def create_case():
    req = request.get_json() or {}
    case_number_raw = req.get('case_number', '').strip()
    examiner = req.get('examiner', '').strip()
    notes = req.get('notes', '').strip()
    parent_dir = safe_path(req.get('parent_dir', EVIDENCE_ROOT).strip())

    if not parent_dir or not os.path.isdir(parent_dir):
        return jsonify({"success": False, "error": "Parent location is not a valid directory in the permitted evidence directory."}), 400

    slug = sanitize_case_slug(case_number_raw)
    if not slug:
        return jsonify({"success": False, "error": "Case number must contain at least one letter, number, underscore, or hyphen."}), 400

    # Belt-and-suspenders: slug is already whitelisted to [A-Za-z0-9_-] so
    # os.path.join(parent_dir, slug) can't escape parent_dir on its own, but
    # re-validating through safe_path matches the posture every other
    # path-accepting endpoint in this app uses.
    case_dir = safe_path(os.path.join(parent_dir, slug))
    if not case_dir:
        return jsonify({"success": False, "error": "Resulting case path is outside the permitted evidence directory."}), 400

    if os.path.exists(case_dir):
        return jsonify({"success": False, "error": f"A case folder named '{slug}' already exists at this location. Choose a different case number or parent location."}), 409

    # The exists() check above and this makedirs() call are two separate
    # steps - a concurrent request naming the exact same case number/parent
    # location can create case_dir in the narrow window between them
    # (found during a 2026-09-09 review pass). os.makedirs() itself never
    # half-creates or overwrites anything if the directory already exists,
    # so this race was never a data-safety issue - only a UX one: without
    # this specific except, the loser of the race fell into the broad
    # except below and got a generic 500 with a raw errno message instead
    # of the same clean 409 "already exists" response a non-racing
    # duplicate request already gets from the check above.
    try:
        os.makedirs(case_dir)
    except FileExistsError:
        return jsonify({"success": False, "error": f"A case folder named '{slug}' already exists at this location. Choose a different case number or parent location."}), 409
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not create case folder: {e}"}), 500

    try:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        # New cases go straight onto the consolidated one-file-per-case
        # format (see "Consolidated Per-Case Reporting" above) - only cases
        # created before this existed need the explicit migration path
        # (/api/cases/migrate_preview / _apply) to get folded in.
        case_record = {
            "schema_version": 1,
            "case_number": case_number_raw,
            "case_folder": case_dir,
            "examiner": examiner,
            # Multiple Examiner Names per Case (item 7 of the investigation-
            # workflow backlog) - a case-level list, editable afterward in
            # Reporting > Report Narrative. Seeded with the single examiner
            # typed here (auto-filled from the logged-in account, see
            # #newCaseExaminer's own readonly behavior) as its first entry -
            # the singular "examiner" field above stays the untouched,
            # immutable examiner-of-record; this list is what actually
            # displays/exports (core.case_index_db.derive_examiner_display()
            # prefers it, falling back to "examiner" only when it's empty).
            "examiners": [examiner] if examiner else [],
            "notes": notes,
            "case_status": "Open",
            "created_at": now,
            "updated_at": now,
            "attachments": {"files": [], "reference_urls": []},
            # Pre-populated from the station's currently configured custom-
            # field *definitions* (Settings > Case & Reporting) so this dict
            # is always fully shaped rather than sparse - definitions live
            # station-wide, values live per-case. A field with a configured
            # default_value (e.g. "Agency" defaulting to the station's own
            # agency name) seeds every new case with it directly, saving the
            # examiner from retyping the same value case after case; a field
            # with no default still seeds "" exactly as before.
            "custom_fields": {f["key"]: f.get("default_value", "") for f in get_custom_case_fields()},
            "events": [],
        }
        _write_case_file(os.path.join(case_dir, f"{slug}_case.json"), case_record)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not create case folder: {e}"}), 500

    log_chain_of_custody("case_create", {"case_number": case_number_raw, "examiner": examiner, "case_folder": case_dir})
    return jsonify({"success": True, "case": case_record})


@case_management_bp.route('/api/cases/list', methods=['GET'])
@requires_auth
def list_cases():
    """Thin wrapper - the actual EVIDENCE_ROOT walk lives in core/
    case_index_db.py's list_case_folders() now, factored out once cross-
    case search (routes/case_index.py's cross_case_hash_search()) became a
    2nd caller (2026-08-26, gap-closing round). Pure code motion, verified
    zero behavior change - same response shape, same sort order."""
    try:
        return jsonify({"success": True, "cases": list_case_folders()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@case_management_bp.route('/api/cases/log_select', methods=['POST'])
@requires_auth
def log_case_select():
    # No state is stored here - this exists purely so selecting a case
    # leaves a chain-of-custody entry, same as every other significant
    # action in this app.
    req = request.get_json() or {}
    log_chain_of_custody("case_select", {
        "case_number": req.get('case_number', ''),
        "case_folder": req.get('case_folder', ''),
    })
    return jsonify({"success": True})


@case_management_bp.route('/api/cases/set_status', methods=['POST'])
@requires_auth
# Same broad OR as create_case() above - archiving/reopening a case is a
# quick lifecycle action, not a reporting-specific one; any operational
# account should be able to do it from the Case Manager list.
@requires_permission('acquisition', 'mobile', 'recovery', 'reporting')
def set_case_status():
    """A fast, single-field way to change a case's status (most commonly:
    archive it) directly from the Case Manager list - previously the ONLY
    way was open Reporting for that exact case, find Report Narrative >
    Case Details, change the Status dropdown, then click "Save Report
    Changes" at the top of the page, which round-trips the ENTIRE report
    JSON through saveReportMetadata()/currentLoadedReportData. That's the
    right flow for editing a case's own narrative while you're already
    working it; it's real friction for "I'm looking at a list of 20 old
    cases and want to archive a few" - genuinely different actions.

    Writes directly to the case's own MARKER file ({slug}_case.json, or
    the legacy case_info.json for a not-yet-migrated case) - both already
    store case_status as a plain top-level key, confirmed via list_case_
    folders()'s own identical read pattern for both schemas (the nested
    case_metadata shape only exists in legacy per-job _report.json files,
    never the case-level marker itself, so there's no dual-schema branch
    needed here the way saveReportMetadata()'s full-report save has)."""
    req = request.get_json() or {}
    case_folder = safe_path(req.get('case_folder'))
    status = req.get('status')
    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found."}), 400
    if status not in CASE_STATUS_VALUES:
        return jsonify({"success": False, "error": f"Invalid status - must be one of: {', '.join(CASE_STATUS_VALUES)}"}), 400

    slug = os.path.basename(case_folder.rstrip('/'))
    consolidated_path = os.path.join(case_folder, f"{slug}_case.json")
    legacy_path = os.path.join(case_folder, "case_info.json")
    if os.path.exists(consolidated_path):
        marker_path = consolidated_path
    elif os.path.exists(legacy_path):
        marker_path = legacy_path
    else:
        return jsonify({"success": False, "error": "No case marker file found in this folder."}), 400

    try:
        data = _read_case_file(marker_path)
        old_status = data.get('case_status') or 'Open'
        data['case_status'] = status
        data['updated_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
        # Remember the status a case held right before being archived, so a
        # later "Re-open" (from the Case Manager list's own dedicated
        # button - see static/js/main.js's setCaseStatus()) can restore it
        # instead of always landing back on the generic "Open" default
        # (2026-09-09 fix, from a review pass's own lower-confidence
        # findings). Only ever captured on a genuine transition INTO
        # Archived (never overwrites an already-recorded value by
        # re-archiving an already-archived case, which this route
        # otherwise treats as a harmless no-op status write) and cleared
        # the moment the case leaves Archived via ANY path - not just a
        # "Re-open" click, any status change - so a much later archive
        # cycle always captures a fresh snapshot rather than reusing a
        # stale one from a completely different point in the case's life.
        if status == 'Archived' and old_status != 'Archived':
            data['status_before_archive'] = old_status
        elif old_status == 'Archived' and status != 'Archived':
            data.pop('status_before_archive', None)
        _write_case_file(marker_path, data)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not update case status: {e}"}), 500

    log_chain_of_custody("case_status_changed", {
        "case_folder": case_folder, "case_number": data.get('case_number', ''),
        "old_status": old_status, "new_status": status,
    })
    return jsonify({"success": True, "case_status": status})


# --- Legacy Case Migration: fold scattered case_info.json + *_report.json
# files into the new one-file-per-case consolidated schema ---
# Non-destructive by design: originals are renamed with a
# ".pre_consolidation_backup" suffix (never deleted), and only after the new
# consolidated file has been written and confirmed. One-shot per case - if
# it already has a *_case.json, both routes below refuse rather than risk
# merging/duplicating; picking up reports created after a migration is a
# known, documented limitation, not handled here.
def _scan_case_folder_for_migration(case_dir):
    """Read-only: returns (case_info_data_or_None, [(path, parsed_report_dict), ...], [unreadable_paths])."""
    case_info = None
    case_info_path = os.path.join(case_dir, "case_info.json")
    if os.path.isfile(case_info_path):
        try:
            with open(case_info_path, 'r') as f:
                case_info = json.load(f)
        except Exception:
            pass

    reports = []
    unreadable = []
    for root, dirs, files in os.walk(case_dir):
        for fname in files:
            if fname.endswith('_report.json'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r') as f:
                        reports.append((fpath, json.load(f)))
                except Exception:
                    unreadable.append(fpath)
    return case_info, reports, unreadable


@case_management_bp.route('/api/cases/migrate_preview', methods=['POST'])
@requires_auth
def migrate_case_preview():
    req = request.get_json() or {}
    case_dir = safe_path(req.get('case_folder', ''))
    if not case_dir or not os.path.isdir(case_dir):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404

    slug = os.path.basename(case_dir.rstrip(os.sep))
    already_migrated = os.path.isfile(os.path.join(case_dir, f"{slug}_case.json"))

    case_info, reports, unreadable = _scan_case_folder_for_migration(case_dir)
    return jsonify({
        "success": True,
        "already_migrated": already_migrated,
        "case_info_found": case_info is not None,
        "reports": [{
            "path": p,
            "case_number": r.get("case_metadata", {}).get("case_number", "--"),
            "evidence_id": r.get("case_metadata", {}).get("evidence_id", "--"),
            "tool": r.get("tool", "--"),
            "status": r.get("acquisition_status", "--"),
            "timestamp_start": r.get("timestamp_start", "--"),
        } for p, r in reports],
        "unreadable": unreadable,
    })


@case_management_bp.route('/api/cases/migrate_apply', methods=['POST'])
@requires_auth
# 'reporting' specifically (narrower than create_case's broad OR above):
# migration is about rewriting a case's REPORT files into the consolidated
# format, a report-management concern, not a prerequisite for selecting or
# using a legacy case for acquisition/recovery/mobile work - those keep
# working against an unmigrated case regardless of this permission.
@requires_permission('reporting')
def migrate_case_apply():
    req = request.get_json() or {}
    case_dir = safe_path(req.get('case_folder', ''))
    if not case_dir or not os.path.isdir(case_dir):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404

    slug = os.path.basename(case_dir.rstrip(os.sep))
    case_file = os.path.join(case_dir, f"{slug}_case.json")
    if os.path.isfile(case_file):
        return jsonify({"success": False, "error": "This case is already on the consolidated format."}), 409

    with job_lock:
        if current_job["active"]:
            return jsonify({"success": False, "error": "Wait for the current job to finish before migrating - migration renames files a running job may still be writing to."}), 409

    case_info, reports, unreadable = _scan_case_folder_for_migration(case_dir)

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    events = []
    migrated_paths = []
    for path, data in reports:
        event = dict(data)
        event["event_id"] = uuid.uuid4().hex
        events.append(event)
        migrated_paths.append(path)
    events.sort(key=lambda e: e.get("timestamp_start", ""))

    case_record = {
        "schema_version": 1,
        "case_number": (case_info or {}).get("case_number", slug),
        "case_folder": case_dir,
        "examiner": (case_info or {}).get("examiner", ""),
        # Same reasoning as create_case()'s own "examiners" seed above - a
        # legacy case_info.json never had this key at all, so this is
        # always a fresh single-entry list from whatever the old singular
        # field recorded (or empty, if that was blank too).
        "examiners": [(case_info or {}).get("examiner")] if (case_info or {}).get("examiner") else [],
        "notes": (case_info or {}).get("notes", ""),
        # Real bug, fixed 2026-09-09: this is the OTHER place (besides
        # create_case() above) that produces a brand-new {slug}_case.json
        # for the first time, but it previously omitted both of these keys
        # entirely - a migrated case never got a configured custom field's
        # station-wide default_value seeded the way a freshly-created case
        # already does, and case_status silently fell back to list_case_
        # folders()'s own generic "or 'Open'" default rather than preserving
        # whatever status a legacy case_info.json happened to already record
        # (a legacy case could genuinely have been marked Closed/Archived
        # before consolidation ever existed).
        "case_status": (case_info or {}).get("case_status") or "Open",
        "created_at": (case_info or {}).get("created_at") or (events[0]["timestamp_start"] if events else now),
        "updated_at": now,
        "attachments": {"files": [], "reference_urls": []},
        "custom_fields": {f["key"]: f.get("default_value", "") for f in get_custom_case_fields()},
        "events": events,
    }

    try:
        _write_case_file(case_file, case_record)
        if not os.path.isfile(case_file):
            raise IOError("consolidated file did not appear on disk after write")
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed writing consolidated case file - nothing was renamed: {e}"}), 500

    # Only rename originals after the new file is confirmed written - if the
    # process dies partway through renaming, worst case is duplicate data on
    # disk (old files still present next to a complete new one), never loss.
    case_info_path = os.path.join(case_dir, "case_info.json")
    if case_info is not None and os.path.isfile(case_info_path):
        try:
            os.rename(case_info_path, case_info_path + ".pre_consolidation_backup")
        except Exception:
            pass
    for path in migrated_paths:
        try:
            os.rename(path, path + ".pre_consolidation_backup")
        except Exception:
            pass

    log_chain_of_custody("case_migrate", {"case_folder": case_dir, "events_migrated": len(events), "skipped": len(unreadable)})
    return jsonify({"success": True, "case_file": case_file, "events_migrated": len(events), "skipped": unreadable})
