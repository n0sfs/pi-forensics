"""Case Management: create/discover case folders, and one-shot migration
of legacy (pre-consolidated-schema) cases into the modern one-file-
per-case format.

Deliberately a small, simple cluster - none of these 5 routes carry a
@requires_permission decorator (just @requires_auth), a genuinely
different, simpler concern from the bigger reclassified case-notes/
attach/discover cluster reporting.py absorbs in a later step. No
server-side "active case" state is kept here - every job-starting
route already takes `destination` per-request, so selecting a case is
purely a frontend concern.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import json
import time
import uuid

from flask import Blueprint, jsonify, request

from core.auth import requires_auth
from core.paths import safe_path, log_chain_of_custody, sanitize_case_slug
from core.config import EVIDENCE_ROOT, get_custom_case_fields
from core.jobs import job_lock, current_job, _write_case_file

case_management_bp = Blueprint('case_management', __name__)


@case_management_bp.route('/api/cases/create', methods=['POST'])
@requires_auth
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

    try:
        os.makedirs(case_dir)
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
            "notes": notes,
            "created_at": now,
            "updated_at": now,
            "attachments": {"files": [], "reference_urls": []},
            # Pre-populated (empty values) from the station's currently
            # configured custom-field *definitions* (Settings > Case &
            # Reporting) so this dict is always fully shaped rather than
            # sparse - definitions live station-wide, values live per-case.
            "custom_fields": {f["key"]: "" for f in get_custom_case_fields()},
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
    cases = []
    try:
        for root, dirs, files in os.walk(EVIDENCE_ROOT):
            # Bound the scan depth so this can't turn into a very slow crawl
            # of a huge or deeply-mounted evidence tree.
            depth = root[len(EVIDENCE_ROOT):].count(os.sep)
            if depth >= 6:
                dirs[:] = []
                continue

            # A case folder's marker filename is always derived from its own
            # basename (see case_consolidated_path) - check for that exact
            # name first (new consolidated schema), falling back to the old
            # generic case_info.json for cases created before this existed
            # and not yet migrated (see /api/cases/migrate_preview/_apply).
            consolidated_name = f"{os.path.basename(root)}_case.json"
            if consolidated_name in files:
                try:
                    with open(os.path.join(root, consolidated_name), 'r') as f:
                        data = json.load(f)
                    cases.append({
                        "case_number": data.get('case_number', '--'),
                        "examiner": data.get('examiner', '--'),
                        "case_folder": data.get('case_folder', root),
                        "created_at": data.get('created_at', '--'),
                        "notes": data.get('notes', ''),
                        "event_count": len(data.get('events', [])),
                        "schema": "consolidated",
                    })
                except (json.JSONDecodeError, OSError):
                    pass
                dirs[:] = []  # a case folder never contains another case folder
            elif 'case_info.json' in files:
                try:
                    with open(os.path.join(root, 'case_info.json'), 'r') as f:
                        data = json.load(f)
                    cases.append({
                        "case_number": data.get('case_number', '--'),
                        "examiner": data.get('examiner', '--'),
                        "case_folder": data.get('case_folder', root),
                        "created_at": data.get('created_at', '--'),
                        "notes": data.get('notes', ''),
                        "event_count": None,
                        "schema": "legacy",
                    })
                except (json.JSONDecodeError, OSError):
                    pass
                dirs[:] = []

        cases.sort(key=lambda c: c.get('created_at', ''), reverse=True)
        return jsonify({"success": True, "cases": cases})
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
        "notes": (case_info or {}).get("notes", ""),
        "created_at": (case_info or {}).get("created_at") or (events[0]["timestamp_start"] if events else now),
        "updated_at": now,
        "attachments": {"files": [], "reference_urls": []},
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
