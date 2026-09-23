"""Case Management: create, list and set the status of case folders.

Legacy-case migration lived here until 2026-09-15 and has been removed along
with the rest of pre-consolidated-schema support - `{slug}_case.json` is now
the only case format the app recognises, so there is nothing to migrate from.
The dual-schema handling that remains elsewhere (notably the report exporter's
`events[]`-or-not branch) is NOT about that: it serves reports written by a
job run with no active case, which is a current, supported workflow.

A small, simple cluster - GET/logging routes (list, log_select - both
read-only, see each one's own comment) stay @requires_auth-only, matching this
app's established "reads are open, writes are permission-gated" convention.
create_case originally had NO permission check at all - found during the
2026-08-22 security audit: even a custom group with every permission key False
could still create case folders, inconsistent with the near-identical,
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

from flask import Blueprint, jsonify, request

from core.auth import requires_auth, requires_permission
from core.paths import safe_path, log_chain_of_custody, sanitize_case_slug
from core.config import EVIDENCE_ROOT, get_custom_case_fields
from core.jobs import _write_case_file, _read_case_file, serialize_case_writes
from core.case_index_db import list_case_folders

case_management_bp = Blueprint('case_management', __name__)

# The same 6 values Reporting's own Case Details Status <select> (templates/
# tabs/reporting.html), the Case Manager's own status filter (templates/
# modals/shared.html), and their client-side CASE_STATUS_BADGE_CLASS/
# CASE_STATUS_BAR_COLOR mirrors (static/js/main.js) already use - no prior
# backend-side constant existed before /api/cases/set_status needed one to
# validate against (create_case() below just hardcodes the single "Open"
# starting value, never needed the full enum). "In Progress" (2026-09-10,
# user-flagged live) sits between Open and In Review specifically to
# distinguish "created but not yet actively worked" from "an examiner is
# actively working it" from "handed off to another examiner/supervisor to
# review" - three genuinely different states this enum only had two of
# before.
CASE_STATUS_VALUES = ('Open', 'In Progress', 'In Review', 'On Hold', 'Closed', 'Archived')


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
        # The consolidated one-file-per-case format is the only case format
        # (see "Consolidated Per-Case Reporting" above). The pre-consolidation
        # layout and its migration routes were removed on 2026-09-15.
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
        # The folder was created a moment ago and is still empty - remove it,
        # or a retry hits the 409 above for a "case" that never appears in the
        # list (no marker) and the case number is blocked here for good.
        try:
            os.rmdir(case_dir)
        except OSError:
            pass
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
@serialize_case_writes
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

    Writes directly to the case's own MARKER file ({slug}_case.json), which
    stores case_status as a plain top-level key. The nested case_metadata
    shape only ever existed in per-job _report.json files, never in the
    case-level marker, so there is no dual-schema branch needed here the way
    saveReportMetadata()'s full-report save has."""
    req = request.get_json() or {}
    case_folder = safe_path(req.get('case_folder'))
    status = req.get('status')
    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found."}), 400
    if status not in CASE_STATUS_VALUES:
        return jsonify({"success": False, "error": f"Invalid status - must be one of: {', '.join(CASE_STATUS_VALUES)}"}), 400

    slug = os.path.basename(case_folder.rstrip('/'))
    marker_path = os.path.join(case_folder, f"{slug}_case.json")
    if not os.path.exists(marker_path):
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
