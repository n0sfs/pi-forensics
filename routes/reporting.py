"""Reporting: chain-of-custody log viewing/export, station-wide report
export defaults + custom Report Template Builder + report branding
(Settings > Case & Reporting's actual save targets, even though they're
reached from Settings), report/load + report/save (the loaded-case JSON
editor), the case-notes/attach/discover cluster, and the ~2,500-line PDF/
HTML report-builder helper block (REPORT_TEMPLATES/REPORT_SECTION_BLOCKS,
every _draw_pdf_*/_html_* drawing helper, and /api/export_report itself).

/api/report/load and /api/report/save moved here from routes/
file_explorer.py (Step 6 left them behind deliberately - they're
reporting-permission-gated, not file_explorer-gated). The cases/
discover_files, attach_file, notes/add, notes/edit cluster moved here
from app.py rather than routes/case_management.py - every one of them is
reporting-permission-gated, and discover_case_files()'s own
_discover_case_files() helper is also called directly by this file's own
report-building code (_collect_case_kml_files), so keeping the cluster
here avoids forcing that helper into core/ just to satisfy one caller
outside reporting.

reportlab imports stay exactly as lazy/local as they were in app.py -
never hoisted to module level - so a missing reportlab install only
breaks report *export*, not this blueprint's registration.

Part of the app.py -> core/ + routes/ split. See the dated CLAUDE.md
entry for this refactor.
"""
import os
import re
import io
import csv
import time
import json
import html
import uuid
import math
import base64
import hashlib
import textwrap
import subprocess
import xml.etree.ElementTree as ET
import urllib.request

from flask import Blueprint, jsonify, request, g, send_file, Response

from core.auth import requires_auth, requires_permission, get_current_user_permissions
from core.paths import (
    safe_path, log_chain_of_custody, case_consolidated_path,
    classify_extension, classify_case_role, sanitize_case_slug,
)
from core.config import (
    EVIDENCE_ROOT, INSTALL_DIR, COC_LOG_FILE, ALLOWED_HASH_ALGOS,
    load_runtime_config, save_runtime_config,
    get_report_defaults, get_custom_case_fields,
)
from core.jobs import _read_case_file, _write_case_file
from core.case_index_db import _tags_for_paths, _analysis_results_for_paths, _auto_tag_case_artifact, _case_index_open_readonly
from core.tsk_utils import _tsk_walk, _tsk_resolve_filesystems, _tsk_open_fs, TSK_MAX_TIMELINE_ENTRIES

reporting_bp = Blueprint('reporting', __name__)

@reporting_bp.route('/api/settings/case_reporting', methods=['GET', 'POST'])
@requires_auth
def settings_case_reporting():
    if request.method == 'GET':
        cfg = load_runtime_config()
        return jsonify({
            "success": True,
            "report_defaults": cfg.get('report_defaults', {}),
            "custom_case_fields": cfg.get('custom_case_fields', []),
        })

    # GET is left ungated above - Reporting's Export pane reads these
    # defaults too, not just Settings - only the write path is
    # Settings-exclusive.
    if not get_current_user_permissions().get('settings', False):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    req = request.get_json() or {}
    cfg = load_runtime_config()

    if 'report_defaults' in req:
        incoming = req['report_defaults'] or {}
        # logo_path is deliberately not settable here - it's managed only
        # by /api/settings/report_logo (upload) and its /clear counterpart,
        # so this save path can never point it at an arbitrary path string.
        existing_logo = cfg.get('report_defaults', {}).get('branding', {}).get('logo_path', '')
        # A station default must never persist a dangling custom:<id>
        # reference (e.g. the template was deleted, or the value is just
        # garbage) - _resolve_template_ref() is the single source of truth
        # for what a template string resolves to, shared with export_report().
        incoming_template = incoming.get('template')
        if incoming_template in REPORT_TEMPLATES:
            stored_template = incoming_template
        elif isinstance(incoming_template, str) and incoming_template.startswith('custom:'):
            try:
                _resolve_template_ref(incoming_template, cfg)
                stored_template = incoming_template
            except ValueError:
                stored_template = 'standard'
        else:
            stored_template = 'standard'
        cfg['report_defaults'] = {
            "template": stored_template,
            "sections": {k: bool(v) for k, v in (incoming.get('sections') or {}).items()},
            "job_fields": {k: bool(v) for k, v in (incoming.get('job_fields') or {}).items()},
            "branding": {
                "header_text": (incoming.get('branding', {}).get('header_text') or '').strip()[:200],
                "logo_path": existing_logo,
            },
        }

    if 'custom_case_fields' in req:
        # Each field's key is derived from its label (whitelisted charset,
        # matching sanitize_case_slug()'s approach elsewhere) rather than
        # accepted from the client directly, and de-duplicated - this is
        # what every case record's custom_fields dict gets keyed by, so it
        # must stay a safe, stable identifier even if two examiners pick
        # the same display label.
        fields = []
        seen_keys = set()
        for f in (req['custom_case_fields'] or []):
            label = (f.get('label') or '').strip()[:60]
            if not label:
                continue
            base_key = re.sub(r'[^a-z0-9_]+', '_', label.lower()).strip('_') or 'field'
            key = base_key
            n = 2
            while key in seen_keys:
                key = f"{base_key}_{n}"
                n += 1
            seen_keys.add(key)
            # Optional per-field default - seeded into every NEW case's own
            # custom_fields value at creation time (see create_case() in
            # routes/case_management.py), never retroactively applied to an
            # existing case's already-saved (possibly deliberately blank)
            # value.
            default_value = (f.get('default_value') or '').strip()[:200]
            fields.append({"key": key, "label": label, "default_value": default_value})
        cfg['custom_case_fields'] = fields

    save_runtime_config(cfg)
    return jsonify({"success": True})

CUSTOM_REPORT_TEMPLATE_NAME_MAX = 80

def _custom_report_template_from_payload(req):
    """Validates and normalizes a create/update payload for a custom report
    template into the stored record shape (minus id/created_at, which the
    caller fills in - id in particular never changes across an update, see
    the PUT handler below). Returns (record_dict, None) or (None,
    error_message) - caller decides the HTTP status for an error.

    Unknown section keys are rejected outright (400) rather than silently
    dropped, since accepting them would let stale/malformed client state
    corrupt storage. Any of the 13 known blocks missing from the payload is
    defensively auto-filled (default title, enabled) rather than rejected -
    every stored record is expected to always cover all 13 keys (what the
    builder UI edits, and what _resolve_section_order() reads), so this is
    a self-healing default a slightly-out-of-date client shouldn't be
    punished for."""
    name = (req.get('name') or '').strip()[:CUSTOM_REPORT_TEMPLATE_NAME_MAX]
    if not name:
        return None, "Template name is required."

    by_key = {}
    for entry in (req.get('sections') or []):
        key = entry.get('key')
        if key not in _REPORT_SECTION_BLOCK_MAP:
            return None, f"Unknown report section '{key}'."
        block = _REPORT_SECTION_BLOCK_MAP[key]
        row = {
            "key": key,
            "title": (entry.get('title') or '').strip()[:120],
            "enabled": bool(entry.get('enabled', True)),
        }
        # source_field only ever stored for a remappable block, and only if
        # it's actually one of the recognized narrative fields - an
        # unrecognized value (stale client, hand-edited request) falls back
        # to the block's own default rather than being rejected outright,
        # matching this function's existing self-healing posture for a
        # missing block entirely (see the docstring above).
        if block["remappable"]:
            requested = entry.get('source_field')
            row["source_field"] = requested if requested in NARRATIVE_BLOCK_FIELD_MAP.values() else NARRATIVE_BLOCK_FIELD_MAP[key]
        by_key[key] = row
    # Preserve the payload's own order for keys it included, then append
    # any of the 15 registry blocks it left out, in the registry's own
    # default order.
    sections = list(by_key.values())
    for block in REPORT_SECTION_BLOCKS:
        if block['key'] not in by_key:
            row = {"key": block['key'], "title": block['default_title'], "enabled": True}
            if block["remappable"]:
                row["source_field"] = NARRATIVE_BLOCK_FIELD_MAP[block['key']]
            sections.append(row)

    job_fields_in = req.get('job_fields') or {}
    job_fields = {
        "telemetry": bool(job_fields_in.get('telemetry', True)),
        "params": bool(job_fields_in.get('params', True)),
        "hashes": bool(job_fields_in.get('hashes', True)),
    }

    return {
        "name": name,
        "sections": sections,
        "job_fields": job_fields,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, None

@reporting_bp.route('/api/report_templates/custom', methods=['GET', 'POST'])
@requires_auth
def report_templates_custom():
    cfg = load_runtime_config()
    if request.method == 'GET':
        return jsonify({
            "success": True,
            "templates": cfg.get('custom_report_templates', []),
            # Single source of truth for the frontend builder's palette -
            # it never hardcodes the 15-block list itself. field_options is
            # the same 7-entry map every remappable block can choose among
            # (value = header field name the way source_field stores it,
            # label = what a human calls it) - identical for every
            # remappable row, sent once at the top level rather than
            # repeated per block.
            "blocks": [{"key": b["key"], "default_title": b["default_title"], "remappable": b["remappable"]} for b in REPORT_SECTION_BLOCKS],
            "field_options": [{"value": v, "label": NARRATIVE_FIELD_LABELS[v]} for v in NARRATIVE_BLOCK_FIELD_MAP.values()],
        })

    # GET is left ungated above - both the Reporting Export pane and
    # Settings > Case & Reporting need the template list - only creating a
    # new one is gated, and by either area since the builder is reachable
    # from both.
    perms = get_current_user_permissions()
    if not (perms.get('settings', False) or perms.get('reporting', False)):
        return jsonify({"success": False, "error": "Your account's user group doesn't have permission to perform this action."}), 403

    req = request.get_json() or {}
    record, error = _custom_report_template_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400

    templates = cfg.setdefault('custom_report_templates', [])
    # Soft-dedupe on name collision (numeric suffix), not a hard 409 like
    # case-folder creation - there's no on-disk artifact at stake for a
    # duplicate template *name*, just a cosmetic label.
    base_id = re.sub(r'[^a-z0-9_]+', '_', record['name'].lower()).strip('_') or 'template'
    existing_ids = {r['id'] for r in templates}
    template_id = base_id
    n = 2
    while template_id in existing_ids:
        template_id = f"{base_id}_{n}"
        n += 1

    record['id'] = template_id
    record['created_at'] = record['updated_at']
    templates.append(record)
    save_runtime_config(cfg)
    return jsonify({"success": True, "template": record})

@reporting_bp.route('/api/report_templates/custom/<template_id>', methods=['PUT', 'DELETE'])
@requires_auth
@requires_permission('settings', 'reporting')
def report_templates_custom_detail(template_id):
    cfg = load_runtime_config()
    templates = cfg.get('custom_report_templates', [])
    idx = next((i for i, r in enumerate(templates) if r.get('id') == template_id), None)
    if idx is None:
        return jsonify({"success": False, "error": "Custom report template not found."}), 404

    if request.method == 'DELETE':
        templates.pop(idx)
        # id never changes across an update (see below), so this exact
        # match is reliable - a station default that was pointing at the
        # just-deleted template must not be left dangling.
        if cfg.get('report_defaults', {}).get('template') == f'custom:{template_id}':
            cfg.setdefault('report_defaults', {})['template'] = 'standard'
        save_runtime_config(cfg)
        return jsonify({"success": True})

    req = request.get_json() or {}
    record, error = _custom_report_template_from_payload(req)
    if error:
        return jsonify({"success": False, "error": error}), 400
    # id is fixed at creation and never regenerated from a new name - a
    # rename must not silently invalidate a station default (or a bookmarked
    # per-export selection) already pointing at 'custom:<id>'.
    record['id'] = template_id
    record['created_at'] = templates[idx].get('created_at', record['updated_at'])
    templates[idx] = record
    save_runtime_config(cfg)
    return jsonify({"success": True, "template": record})

REPORT_LOGO_MAX_BYTES = 2_000_000

@reporting_bp.route('/api/settings/report_logo', methods=['POST'])
@requires_auth
@requires_permission('settings')
def upload_report_logo():
    logo_file = request.files.get('logo')
    if not logo_file or not logo_file.filename:
        return jsonify({"success": False, "error": "No logo file provided."}), 400

    ext = os.path.splitext(logo_file.filename)[1].lower()
    if ext not in ATTACHMENT_IMAGE_EXT:
        return jsonify({"success": False, "error": f"Unsupported image type '{ext}'. Use one of: {', '.join(sorted(ATTACHMENT_IMAGE_EXT))}"}), 400

    logo_file.seek(0, os.SEEK_END)
    size = logo_file.tell()
    logo_file.seek(0)
    if size > REPORT_LOGO_MAX_BYTES:
        return jsonify({"success": False, "error": f"Logo file too large ({size} bytes) - max {REPORT_LOGO_MAX_BYTES} bytes."}), 400

    logo_path = os.path.join(INSTALL_DIR, f"report_logo{ext}")
    # Remove any previously-saved logo under a different extension so
    # switching image types doesn't leave a stale, unreferenced file behind.
    for other_ext in ATTACHMENT_IMAGE_EXT:
        stale_path = os.path.join(INSTALL_DIR, f"report_logo{other_ext}")
        if stale_path != logo_path and os.path.exists(stale_path):
            try:
                os.remove(stale_path)
            except OSError:
                pass

    logo_file.save(logo_path)

    cfg = load_runtime_config()
    cfg.setdefault('report_defaults', {}).setdefault('branding', {})['logo_path'] = logo_path
    save_runtime_config(cfg)
    return jsonify({"success": True, "message": "Logo uploaded."})

@reporting_bp.route('/api/settings/report_logo/clear', methods=['POST'])
@requires_auth
@requires_permission('settings')
def clear_report_logo():
    cfg = load_runtime_config()
    logo_path = cfg.get('report_defaults', {}).get('branding', {}).get('logo_path', '')
    if logo_path and os.path.exists(logo_path):
        try:
            os.remove(logo_path)
        except OSError:
            pass
    if 'report_defaults' in cfg and 'branding' in cfg['report_defaults']:
        cfg['report_defaults']['branding']['logo_path'] = ''
    save_runtime_config(cfg)
    return jsonify({"success": True})

@reporting_bp.route('/api/report/load', methods=['POST'])
@requires_auth
def load_report_json():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report file not found or outside the permitted evidence directory."}), 404

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        return jsonify({"success": True, "report": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@reporting_bp.route('/api/report/save', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def save_report_json():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    data = req.get('report_data')

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report target file not found or outside the permitted evidence directory."}), 404

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
        log_chain_of_custody("report_edit", {"report_path": report_file})
        return jsonify({"success": True, "message": "Report JSON updated successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def _read_coc_entries(limit=None):
    """Read chain-of-custody log entries, most recent first. limit=None reads the whole file."""
    entries = []
    if os.path.exists(COC_LOG_FILE):
        with open(COC_LOG_FILE, 'r') as f:
            lines = f.readlines()
        if limit:
            lines = lines[-limit:]
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    entries.reverse()
    return entries

@reporting_bp.route('/api/coc/log', methods=['GET'])
@requires_auth
def get_chain_of_custody_log():
    limit = request.args.get('limit', 200, type=int)
    try:
        return jsonify({"success": True, "entries": _read_coc_entries(limit)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Case-scoped view of the same log, for the Reporting tab's History sub-tab -
# distinct from /api/coc/log above, which is the station-wide Audit Log in
# Settings. No log entries are tagged with a case_number field (retrofitting
# that onto every one of the ~20 log_chain_of_custody() call sites would be
# a much larger change), so this filters by substring match against every
# logged detail value instead - covers both old flat-file evidence (case
# number was always the filename prefix) and new case-folder evidence (case
# number is the folder name) with one heuristic, no directory resolution
# needed.
def _case_history_entries(case_number, limit=200):
    """Same substring-match filter used by /api/coc/case_history below,
    factored out so the report exporter's Audit Trail section can reuse it
    without an extra HTTP round-trip."""
    matched = []
    for entry in _read_coc_entries(limit=None):
        details = entry.get("details", {})
        if any(case_number in str(v) for v in details.values()):
            matched.append(entry)
        if len(matched) >= limit:
            break
    return matched

@reporting_bp.route('/api/coc/case_history', methods=['GET'])
@requires_auth
def get_case_history():
    case_number = request.args.get('case_number', '').strip()
    limit = request.args.get('limit', 200, type=int)
    if not case_number:
        return jsonify({"success": False, "error": "case_number is required."}), 400

    try:
        return jsonify({"success": True, "entries": _case_history_entries(case_number, limit)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@reporting_bp.route('/api/coc/export_csv', methods=['GET'])
@requires_auth
def export_chain_of_custody_csv():
    # Unlike /api/coc/log above (capped to the most recent `limit` entries
    # for the on-screen view), an export is expected to be the complete
    # record - no limit here.
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "action", "source_ip", "details"])

    try:
        if os.path.exists(COC_LOG_FILE):
            with open(COC_LOG_FILE, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # `details` is a free-form dict that varies by action
                    # type - flatten it to a single JSON string column
                    # rather than guessing at a fixed set of sub-columns.
                    writer.writerow([
                        entry.get("timestamp", ""),
                        entry.get("action", ""),
                        entry.get("source_ip", ""),
                        json.dumps(entry.get("details", {})),
                    ])
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    filename = f"chain_of_custody_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# /api/cases/create, /api/cases/list, /api/cases/log_select,
# /api/cases/migrate_preview, and /api/cases/migrate_apply now live in
# routes/case_management.py (registered as a Blueprint below) - see the
# dated CLAUDE.md entry for this refactor. A second, unrelated /api/cases/*
# cluster (discover_files, attach_file, notes/add, notes/edit) stays inline
# here for now - it is reporting-permission-gated, not case-management, and
# moves into routes/reporting.py in a later step.

# --- Sleuth Kit (pytsk3): Browse/Search/Timeline Filesystems Inside Acquired Images ---
# --- Sleuth Kit (pytsk3) Image Browser routes (browse/search/timeline/
# preview/hex/extract, plus the whole-image Geolocation/Hash-Manifest/
# Triage-Scan actions) moved to routes/image_browser.py - see the dated
# CLAUDE.md entry for this refactor.
# _case_index_open_readonly/_case_index_open_write/_tags_for_paths/
# --- Case Index (/api/case_index/*) routes moved to routes/case_index.py -
# see the dated CLAUDE.md entry for this refactor.
# --- Binwalk / Strings, run directly against a single selected in-image file ---
# --- Binwalk/Strings/ExifTool-on-a-single-in-image-file, and filesystem-
# aware deleted-file recovery, moved to routes/image_browser.py - see the
# dated CLAUDE.md entry for this refactor.
# --- Filesystem Timeline report block: reuses the pytsk3 walk above against
# a case's already-acquired disk image(s), rather than the interactive,
# single-image-at-a-time /api/image/timeline route. First real entry in the
# "feature module" pattern discussed for this app - see REPORT_SECTION_BLOCKS
# and FEATURE_MODULES further below.
TIMELINE_MIN_PER_FS_BUDGET = 200

# _tsk_resolve_filesystems now lives in core/tsk_utils.py (imported at the
# top of this file) - see the Step 0 core/ extraction.

def _collect_case_timeline(events):
    """Builds a combined MACB timeline across every acquired disk image in a
    case's events, for the 'timeline' report block below. Returns
    {"events": [...], "notes": [...], "truncated": bool}.

    Three correctness fixes folded in here that a naive version of this
    would not have had:

    1. Status + existence gating: only a COMPLETED event's output_image_path
       is considered, and only after routing it through safe_path() (matching
       this file's existing pattern for every other image-path input) and
       confirming the file still exists - a FAILED/IN_PROGRESS event's path
       can point at a partial image that might still open "successfully" and
       walk garbage without pytsk3 raising anything.
    2. Dedup by resolved path, not by event: ddrescue's base_name has no
       per-run component, and its own multi-pass design (stage1_fast/
       stage2_trim/stage3_intensive/reverse, each a separate POST against the
       same source/destination) means multiple distinct COMPLETED events can
       legitimately share one on-disk file, each overwriting the last. Only
       the event with the latest timestamp_start per unique resolved path is
       kept; how many earlier events were superseded is recorded so the
       report can disclose it rather than silently drop or (worse) triple-
       walk the same bytes.
    3. Per-(image, filesystem) budget, not one shared global cap:
       image_timeline() above truncates in walk order, before sorting by
       time - so a single real filesystem can consume the entire
       TSK_MAX_TIMELINE_ENTRIES cap by itself. Splitting the budget across
       every qualifying (image, filesystem) pair means one large acquired
       image can't silently reduce every other evidence item in the case to
       zero timeline entries."""
    candidates = {}  # resolved image_path -> {"event": event, "superseded_count": int}
    for event in events:
        if event.get('acquisition_status') != 'COMPLETED':
            continue
        raw_path = event.get('acquisition_parameters', {}).get('output_image_path')
        if not raw_path:
            continue
        image_path = safe_path(raw_path)
        if not image_path or not os.path.isfile(image_path):
            continue
        existing = candidates.get(image_path)
        if existing is None:
            candidates[image_path] = {"event": event, "superseded_count": 0}
        elif event.get('timestamp_start', '') > existing["event"].get('timestamp_start', ''):
            existing["event"] = event
            existing["superseded_count"] += 1
        else:
            existing["superseded_count"] += 1

    notes = []
    per_image_filesystems = {}
    for image_path in candidates:
        filesystems = _tsk_resolve_filesystems(image_path)
        per_image_filesystems[image_path] = filesystems
        evidence_id = candidates[image_path]["event"].get('case_metadata', {}).get('evidence_id', 'N/A')
        if not filesystems:
            notes.append(f"{evidence_id}: no recognized filesystem found in the acquired image - skipped.")
        superseded = candidates[image_path]["superseded_count"]
        if superseded:
            plural = "es" if superseded != 1 else ""
            verb = "share" if superseded != 1 else "shares"
            notes.append(f"{evidence_id}: {superseded} earlier completed acquisition pass{plural} {verb} this "
                         f"same output file; showing the most recent only.")

    total_filesystems = sum(len(fss) for fss in per_image_filesystems.values())
    if total_filesystems == 0:
        return {"events": [], "notes": notes, "truncated": False}
    per_fs_budget = max(TSK_MAX_TIMELINE_ENTRIES // total_filesystems, TIMELINE_MIN_PER_FS_BUDGET)

    all_events = []
    truncated = False
    for image_path, filesystems in per_image_filesystems.items():
        evidence_id = candidates[image_path]["event"].get('case_metadata', {}).get('evidence_id', 'N/A')
        for fs_info in filesystems:
            try:
                fs = _tsk_open_fs(image_path, fs_info['offset'])
            except Exception as e:
                notes.append(f"{evidence_id} ({fs_info['label']}): could not open filesystem - {e}")
                continue
            count = 0
            for entry, path in _tsk_walk(fs):
                if entry['is_virtual']:
                    continue  # TSK's own $MBR/$FAT1/$FAT2/$OrphanFiles pseudo-entries, not real evidence
                for ts_field, label in (('mtime', 'M'), ('atime', 'A'), ('ctime', 'C'), ('crtime', 'B')):
                    ts = entry.get(ts_field)
                    if ts:
                        all_events.append({"timestamp": ts, "activity": label, "path": path,
                                            "evidence_id": evidence_id, "filesystem": fs_info['label']})
                        count += 1
                if count >= per_fs_budget:
                    truncated = True
                    break

    all_events.sort(key=lambda e: e['timestamp'], reverse=True)
    if len(all_events) > TSK_MAX_TIMELINE_ENTRIES:
        truncated = True
    return {"events": all_events[:TSK_MAX_TIMELINE_ENTRIES], "notes": notes, "truncated": truncated}


def _epoch_from_case_timestamp(ts_str):
    """Every string timestamp this app writes into a case JSON (case_notes[],
    custody_log[], events[].timestamp_start) uses the exact same
    "%Y-%m-%d %H:%M:%S" format - converts to a Unix epoch float so it can be
    sorted/merged alongside _collect_case_timeline()'s own epoch-typed MACB
    rows. Returns None (never raises) for an unset/malformed value, matching
    this file's established "graceful, not an error" handling for optional
    fields."""
    if not ts_str:
        return None
    try:
        return time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return None


CASE_TIMELINE_MAX_TOTAL_ENTRIES = 6000  # a bit above TSK_MAX_TIMELINE_ENTRIES (5000) to leave room for the 3 merged non-MACB sources without starving the MACB contribution

@reporting_bp.route('/api/cases/timeline', methods=['GET'])
@requires_auth
@requires_permission('reporting')
def case_timeline():
    """Interactive, case-wide timeline - merges _collect_case_timeline()'s
    existing MACB aggregation (unmodified, reused exactly as the PDF/HTML
    report builders already use it) with three more already-timestamped
    sources: case_notes[], custody_log[] (empty until that feature ships -
    reading via .get() so this never errors on a case predating it), and
    parsed_artifacts rows (browser/registry/event-log records once those
    exist). Every row gets a "source" tag for client-side filtering, since a
    busy case's MACB contribution alone can run to thousands of rows."""
    case_folder = safe_path(request.args.get('case_folder'))
    if not case_folder or not case_consolidated_path(case_folder):
        return jsonify({"success": False, "error": "Not a valid consolidated case folder."}), 400

    case_file = case_consolidated_path(case_folder)
    data = _read_case_file(case_file)
    events = data.get('events', [])

    macb = _collect_case_timeline(events)
    combined = []
    for row in macb["events"]:
        combined.append({
            "timestamp": row["timestamp"], "source": "macb",
            "activity": row["activity"], "detail": row["path"],
            "evidence_id": row["evidence_id"],
        })

    for note in data.get('case_notes', []):
        ts = _epoch_from_case_timestamp(note.get('timestamp'))
        if ts is None:
            continue
        combined.append({
            "timestamp": ts, "source": "case_note",
            "activity": f"Case Note: {note.get('category', 'General')}",
            "detail": (note.get('text') or '')[:200], "evidence_id": None,
        })

    for entry in data.get('custody_log', []):
        ts = _epoch_from_case_timestamp(entry.get('timestamp'))
        if ts is None:
            continue
        combined.append({
            "timestamp": ts, "source": "custody",
            "activity": f"Custody: {entry.get('from_custodian', '?')} → {entry.get('to_custodian', '?')}",
            "detail": entry.get('reason') or '', "evidence_id": None,
        })

    conn = _case_index_open_readonly(case_folder)
    if conn:
        try:
            for row in conn.execute(
                    "SELECT artifact_type, title, value, timestamp FROM parsed_artifacts WHERE timestamp IS NOT NULL"):
                combined.append({
                    "timestamp": row[3], "source": "parsed_artifact",
                    "activity": row[0], "detail": row[1] or row[2] or '', "evidence_id": None,
                })
        finally:
            conn.close()

    combined.sort(key=lambda r: r["timestamp"], reverse=True)
    truncated = macb["truncated"] or len(combined) > CASE_TIMELINE_MAX_TOTAL_ENTRIES
    return jsonify({
        "success": True, "events": combined[:CASE_TIMELINE_MAX_TOTAL_ENTRIES],
        "notes": macb["notes"], "truncated": truncated,
    })


# --- Forensic Audit Report Exporter (PDF / HTML, configurable sections) ---
def _draw_pdf_job_section(c, y, event, job_fields=None):
    """Draws one job/event's telemetry + acquisition params + hashes block,
    each independently toggleable via job_fields - shared between the
    single-legacy-report path and the per-event loop for a consolidated case
    file below. Returns the y position after drawing."""
    job_fields = job_fields if job_fields is not None else {'telemetry': True, 'params': True, 'hashes': True}

    if job_fields.get('telemetry', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Source Media Telemetry")
        y -= 15
        c.setFont("Helvetica", 10)
        drive = event.get('source_drive_telemetry', {})
        c.drawString(50, y, f"Device: {drive.get('device_path')} ({drive.get('capacity_gb')} GB)")
        c.drawString(300, y, f"Model: {drive.get('vendor_model')}")
        y -= 15
        c.drawString(50, y, f"Serial: {drive.get('serial_number')}")
        c.drawString(300, y, f"SMART Status: {'PASSED' if drive.get('smart_healthy') else 'FAILING'}")
        y -= 30

    if job_fields.get('params', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Acquisition Parameters")
        y -= 15
        c.setFont("Helvetica", 10)
        params = event.get('acquisition_parameters', {})
        c.drawString(50, y, f"Format: {params.get('output_format', event.get('tool', 'N/A')).upper()}")
        c.drawString(300, y, f"Status: {event.get('acquisition_status')}")
        y -= 15
        if params.get('bitlocker_key'):
            c.drawString(50, y, f"BitLocker Recovery Key/Password: {params['bitlocker_key']}")
            y -= 15
        y -= 10

    if job_fields.get('hashes', True):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Verification Hashes")
        y -= 15
        c.setFont("Helvetica", 10)
        hashes = event.get('computed_verification_hashes', {})
        if hashes:
            for k, v in hashes.items():
                c.drawString(50, y, f"{k.upper()}: {v}")
                y -= 15
        else:
            c.drawString(50, y, "No hashes recorded.")
            y -= 15
        y -= 5
    return y

def _draw_pdf_acquisition_method(c, y, events, job_fields, title="Acquisition Method"):
    """Renders the per-event acquisition loop - factored out of what used to
    be inlined directly in _build_pdf_report_standard so the registry-driven
    draw loop (see REPORT_SECTION_BLOCKS/_resolve_section_order) can treat
    it as one dispatchable block like every other section. `title` is used
    only for the block's bookmark/Report Contents label - there is no
    on-page heading for the block as a whole, each event draws its own
    "Evidence Item: ..." heading, matching this block's existing behavior.
    Every event after the first always starts on a fresh page (unchanged
    from before); the *first* event does NOT force its own page break here -
    the caller (the registry-driven loop) is responsible for that via this
    block's force_page_break=True registry entry, since _draw_pdf_job_section
    has no internal pagination guard of its own and would otherwise risk
    drawing past the bottom margin if this block isn't first in a custom
    template's order."""
    for i, event in enumerate(events):
        if i > 0:
            c.showPage()
            y = 750
        meta = event.get('case_metadata', {})
        c.setFont("Helvetica-Bold", 13)
        c.drawString(50, y, f"Evidence Item: {meta.get('evidence_id', 'N/A')} ({event.get('tool', 'N/A')})")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Date: {event.get('timestamp_start', 'N/A')}")
        y -= 25
        y = _draw_pdf_job_section(c, y, event, job_fields)
    return y

def _draw_pdf_header(c, header, title="Case Information"):
    c.setFont("Helvetica-Bold", 12)
    y = 730
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Case Number: {header['case_number']}")
    c.drawString(300, y, f"Examiner: {header['examiner']}")
    y -= 20
    c.drawString(50, y, f"Created: {header['created_at']}")
    c.drawString(300, y, f"Status: {header.get('case_status', 'Open')}")
    y -= 20
    c.drawString(50, y, f"Notes: {header['notes'] or 'None'}")
    y -= 20
    for field in header.get('custom_fields', []):
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = 750
        c.drawString(50, y, f"{field['label']}: {field['value']}"[:110])
        y -= 15
    y -= 15
    return y

def _draw_pdf_audit_trail(c, y, entries, title="Case Activity Log (Audit Trail)"):
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 8)
    if not entries:
        c.drawString(50, y, "No activity log entries found for this case.")
        y -= 12
    for entry in entries:
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 8)
        c.drawString(50, y, f"{entry.get('timestamp', '')}  {entry.get('action', '')}"[:120])
        y -= 11
        details = entry.get('details') or {}
        if details:
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(60, y, ', '.join(f'{k}={v}' for k, v in details.items())[:130])
            c.setFillColorRGB(0, 0, 0)
            y -= 11
    return y

def _draw_pdf_custody_log_block(c, y, custody_log, title="Physical Evidence Custody Log"):
    """Renders the append-only physical-evidence custody_log[] (from-person
    -> to-person handoffs, distinct from the software Audit Trail above) -
    same internal-pagination-guard shape as _draw_pdf_audit_trail, not the
    header/job_section pattern (those two lack their own guard and are only
    safe because REPORT_SECTION_BLOCKS forces them to always draw first -
    see that registry's force_page_break docstring; this block has no such
    restriction, so it must guard itself)."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 8)
    if not custody_log:
        c.drawString(50, y, "No custody log entries recorded for this case.")
        y -= 12
        return y
    for entry in custody_log:
        if y < 65:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 8)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(50, y, f"{entry.get('timestamp', '')}  {entry.get('from_custodian', '')} -> {entry.get('to_custodian', '')}"[:120])
        y -= 11
        c.setFont("Helvetica", 8)
        detail = f"Reason: {entry.get('reason', '')}   Method: {entry.get('method', '')}"[:130]
        c.drawString(60, y, detail)
        y -= 11
        if entry.get('notes'):
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(60, y, f"Notes: {entry.get('notes', '')}"[:130])
            c.setFillColorRGB(0, 0, 0)
            y -= 11
        logged_by = entry.get('logged_by')
        if logged_by:
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(60, y, f"Logged by: {logged_by}"[:130])
            c.setFillColorRGB(0, 0, 0)
            y -= 11
        y -= 4
    return y

# --- Case File Attachments: discovery + embedding ---
# Images and small text-ish files get their actual content embedded into
# the exported report (not just listed by path), since the point of
# attaching a photo or a note to a case is that it shows up IN the report
# an examiner hands off - a bare file path is not useful to someone who
# doesn't have filesystem access to the Pi.
ATTACHMENT_IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
ATTACHMENT_TEXT_EXT = {'.txt', '.log', '.md', '.csv', '.json', '.eml', '.msg', '.rtf', '.xml', '.yaml', '.yml'}
ATTACHMENT_EXCLUDE_EXT = {'.dd', '.e01', '.aff', '.001', '.raw', '.img'}
ATTACHMENT_MAX_TEXT_EMBED_BYTES = 100_000
ATTACHMENT_MAX_IMAGE_EMBED_BYTES = 8_000_000
ATTACHMENT_DISCOVERY_MAX_FILES = 200
ATTACHMENT_DISCOVERY_SKIP_DIRS = {'RECOVERED_FILES'}  # extundelete's fixed output dir name

def _discover_case_files(case_folder):
    """Find files physically present in a case folder that are candidates
    for attaching to a report (photos, notes, extracted emails, etc.) but
    weren't necessarily added via the explicit 'Add File Attachment' flow -
    e.g. dropped in via File Explorer's Copy-to action. Skips this case's
    own report artifacts, raw acquisition images (too large, already
    represented via the Jobs section), and recovery tools' bulk carved-file
    output directories (could be thousands of tiny files, impractical to
    list individually). Each result also carries category (classify_extension()
    - images/videos/audio/archives/documents/executables/other) and case_role
    (classify_case_role() - report/analysis_log/geolocation/backup, or None
    for real evidence) so a caller can group results the same way File
    Explorer's own folder tree already does, rather than everything landing
    in one undifferentiated list. Returns (files, truncated)."""
    slug = os.path.basename(case_folder.rstrip(os.sep))
    own_artifact_names = {f"{slug}_case.json", f"{slug}_case.pdf", f"{slug}_case.html", "case_info.json"}

    results = []
    truncated = False
    for root, dirs, files in os.walk(case_folder):
        dirs[:] = [d for d in dirs if d not in ATTACHMENT_DISCOVERY_SKIP_DIRS
                   and not d.endswith(('_photorec', '_foremost', '_scalpel', '_triagescan'))]
        for fname in files:
            if fname in own_artifact_names or fname.endswith(('.pre_consolidation_backup', '_report.json')):
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in ATTACHMENT_EXCLUDE_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            kind = 'image' if ext in ATTACHMENT_IMAGE_EXT else ('text' if ext in ATTACHMENT_TEXT_EXT else 'other')
            category, _ext = classify_extension(fname)
            case_role = classify_case_role(fname)
            results.append({
                "path": fpath, "name": fname, "size_bytes": size, "kind": kind,
                "category": category, "case_role": case_role,
            })
            if len(results) >= ATTACHMENT_DISCOVERY_MAX_FILES:
                return results, True
    return results, truncated


def _kml_find_local(elem, tag_name):
    """First descendant of elem whose tag's local name (namespace prefix
    stripped) matches tag_name, in document order - the closest ElementTree
    equivalent of a namespace-agnostic querySelector() lookup, since KML's
    default namespace makes exact-tag matching fragile."""
    for child in elem.iter():
        if child is elem:
            continue
        if child.tag.rsplit('}', 1)[-1] == tag_name:
            return child
    return None


def _parse_kml_placemarks(kml_text):
    """Mirrors parseKmlPlacemarks() (main.js) - stdlib ElementTree,
    namespace-agnostic tag matching, Placemark -> Point -> coordinates
    (lon,lat[,alt]) + name + description. Skips any Placemark without valid
    parseable coordinates. Returns [] (never raises) on malformed/
    unparseable XML, matching the JS side's own try/except-and-return-
    whatever-was-collected behavior - this may be a hand-edited or
    third-party KML file, not necessarily one this app generated itself."""
    placemarks = []
    try:
        root = ET.fromstring(kml_text)
    except ET.ParseError:
        return placemarks

    for elem in root.iter():
        if elem.tag.rsplit('}', 1)[-1] != 'Placemark':
            continue
        point = _kml_find_local(elem, 'Point')
        coords_el = _kml_find_local(point, 'coordinates') if point is not None else None
        if coords_el is None or not (coords_el.text or '').strip():
            continue
        parts = coords_el.text.strip().split(',')
        if len(parts) < 2:
            continue
        try:
            lon, lat = float(parts[0]), float(parts[1])
        except ValueError:
            continue
        name_el = _kml_find_local(elem, 'name')
        desc_el = _kml_find_local(elem, 'description')
        placemarks.append({
            "name": (name_el.text or '').strip() if name_el is not None else '',
            "description": (desc_el.text or '').strip() if desc_el is not None else '',
            "lat": lat, "lon": lon,
        })
    return placemarks


def _collect_case_kml_files(case_folder, attachment_files):
    """Mirrors renderReportGeolocationList()'s (main.js) union logic: every
    .kml path already in the case's explicit attachments.files list, plus
    every .kml file _discover_case_files() finds sitting in the case folder
    that wasn't necessarily added through the explicit attach flow. Returns
    a de-duplicated, sorted list of absolute paths."""
    paths = set()
    for p in (attachment_files or []):
        if str(p).lower().endswith('.kml'):
            paths.add(p)
    if case_folder and os.path.isdir(case_folder):
        discovered, _truncated = _discover_case_files(case_folder)
        for f in discovered:
            if f['path'].lower().endswith('.kml'):
                paths.add(f['path'])
    return sorted(paths)


def _collect_case_geolocation(case_folder, attachment_files):
    """Reads every case KML file (_collect_case_kml_files) and parses its
    placemarks (_parse_kml_placemarks), returning one entry per file that
    has at least one valid placemark. A KML with zero parseable points
    contributes nothing to a 'map with pins' export section, so it's
    silently skipped here - the same reasoning _build_geo_kml() already
    applies to its own KML *generation* (refuses to write an empty KML with
    zero placemarks in the first place)."""
    results = []
    for path in _collect_case_kml_files(case_folder, attachment_files):
        real_path = safe_path(path)
        if not real_path or not os.path.isfile(real_path):
            continue
        try:
            with open(real_path, 'r', encoding='utf-8', errors='replace') as f:
                kml_text = f.read()
        except OSError:
            continue
        placemarks = _parse_kml_placemarks(kml_text)
        if not placemarks:
            continue
        results.append({"name": os.path.basename(real_path), "path": real_path, "placemarks": placemarks})
    return results


@reporting_bp.route('/api/cases/discover_files', methods=['GET'])
@requires_auth
@requires_permission('reporting')
def discover_case_files():
    case_folder = safe_path(request.args.get('case_folder', ''))
    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 404
    files, truncated = _discover_case_files(case_folder)
    return jsonify({"success": True, "files": files, "truncated": truncated})

@reporting_bp.route('/api/cases/attach_file', methods=['POST'])
@requires_auth
@requires_permission('reporting', 'file_explorer')
def attach_file_to_case():
    """Lets File Explorer's "Attach to Case" context-menu action bookmark a
    file the moment an examiner is looking at it, rather than requiring a
    separate trip to Reporting > Files to browse back to the same path -
    the same "tag it where you find it" model AXIOM/Autopsy use, adapted to
    this app's file-path-based attachment model. Writes straight to the
    case JSON on disk (unlike Reporting's own attachment editing, which is
    staged client-side and only persisted on "Save Report Changes") since
    File Explorer has no loaded-report state or Save button to stage
    through - matches how every other File Explorer action (hash, extract,
    scan) already commits immediately rather than queuing a pending edit."""
    req = request.get_json() or {}
    case_folder = safe_path(req.get('case_folder'))
    file_path = safe_path(req.get('file_path'))
    # Optional provenance note - populated automatically by call sites that
    # know something worth recording (e.g. "extracted from inside an
    # acquired image"), which is otherwise lost the moment the file lands on
    # disk as just another path. Only ever applied on first attach and only
    # if no caption already exists for this path - never overwrites an
    # examiner's own edit made since.
    caption = (req.get('caption') or '').strip() or None

    if not case_folder or not os.path.isdir(case_folder):
        return jsonify({"success": False, "error": "Case folder not found or outside the permitted evidence directory."}), 400
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found or outside the permitted evidence directory."}), 400

    case_file = case_consolidated_path(case_folder)
    if not case_file:
        return jsonify({"success": False, "error": "This case hasn't been migrated to the consolidated report format yet - attach files from the Reporting tab instead."}), 400

    data = _read_case_file(case_file)
    attachments = data.setdefault('attachments', {})
    files = attachments.setdefault('files', [])
    already_attached = file_path in files
    if not already_attached:
        files.append(file_path)
        if caption:
            captions = attachments.setdefault('file_captions', {})
            if file_path not in captions:
                captions[file_path] = caption
        data['updated_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
        _write_case_file(case_file, data)
        log_chain_of_custody("file_attached_to_case", {"case_folder": case_folder, "file_path": file_path})

    return jsonify({"success": True, "already_attached": already_attached, "file_count": len(files)})

# --- Case Notes: timestamped, append-only journal entries ---
# Inspired by forensicnotes.com's contemporaneous-notes model, adapted to
# what this appliance can honestly provide: there's no real cryptographic
# timestamp authority here, so instead each note gets a local SHA-256
# integrity hash (detects local tampering, not a legal notarization
# service) and edits are append-only - a note's original text/timestamp/
# author is never overwritten, only superseded with the prior version kept
# in edit_history. This is what the "Forensic Analysis / Steps Taken"
# report section renders (see _draw_pdf_case_notes below).
def _hash_note_content(text, attachment_paths):
    h = hashlib.sha256()
    h.update((text or '').encode('utf-8'))
    for path in attachment_paths:
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
        except OSError:
            pass
    return h.hexdigest()

@reporting_bp.route('/api/cases/notes/add', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def add_case_note():
    report_file = safe_path(request.form.get('report_path', ''))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report/case file not found or outside the permitted evidence directory."}), 404

    text = request.form.get('text', '').strip()
    category = request.form.get('category', 'General').strip() or 'General'
    if not text:
        return jsonify({"success": False, "error": "Note text cannot be empty."}), 400

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read report: {e}"}), 500

    # Optional links to already-attached exhibit files, so a note can say
    # "found in DCIM, see Exhibit 3" with a real reference instead of just
    # prose. Add-time only - not editable via /api/cases/notes/edit, since
    # editing is for correcting text, not changing which files a note
    # references. Sent as a JSON-encoded string in a form field (this route
    # is multipart, unlike the JSON-bodied edit route). Any path not
    # currently a real attached exhibit is silently dropped - a note
    # shouldn't fail to save over a stale reference.
    try:
        requested_links = json.loads(request.form.get('linked_files', '[]'))
    except (TypeError, ValueError):
        requested_links = []
    attached_files = set((data.get('attachments') or {}).get('files', []))
    linked_files = [p for p in requested_links if isinstance(p, str) and p in attached_files]

    note_id = uuid.uuid4().hex
    saved_attachments = []
    uploaded_files = request.files.getlist('files')
    if uploaded_files and any(f.filename for f in uploaded_files):
        note_dir = safe_path(os.path.join(os.path.dirname(report_file), "case_notes_attachments", note_id))
        if not note_dir:
            return jsonify({"success": False, "error": "Could not resolve a safe attachment directory for this note."}), 500
        os.makedirs(note_dir, exist_ok=True)
        for uf in uploaded_files:
            if not uf.filename:
                continue
            fname = os.path.basename(uf.filename)
            if not fname:
                continue
            fpath = os.path.join(note_dir, fname)
            uf.save(fpath)
            ext = os.path.splitext(fname)[1].lower()
            kind = 'image' if ext in ATTACHMENT_IMAGE_EXT else ('text' if ext in ATTACHMENT_TEXT_EXT else 'other')
            saved_attachments.append({
                "filename": fname,
                "path": fpath,
                "size_bytes": os.path.getsize(fpath),
                "kind": kind,
            })

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    note = {
        "note_id": note_id,
        "timestamp": now,
        "author": getattr(g, 'forensic_user', None),
        "category": category,
        "text": text,
        "attachments": saved_attachments,
        "linked_files": linked_files,
        "content_hash": _hash_note_content(text, [a["path"] for a in saved_attachments]),
        "edited_at": None,
        "edit_history": [],
    }

    data.setdefault('case_notes', []).append(note)
    if 'updated_at' in data:
        data['updated_at'] = now

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not save note: {e}"}), 500

    log_chain_of_custody("case_note_add", {"report_path": report_file, "note_id": note_id, "category": category})
    return jsonify({"success": True, "note": note})

@reporting_bp.route('/api/cases/notes/edit', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def edit_case_note():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    note_id = req.get('note_id', '')
    new_text = (req.get('text') or '').strip()

    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report/case file not found or outside the permitted evidence directory."}), 404
    if not new_text:
        return jsonify({"success": False, "error": "Note text cannot be empty."}), 400

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read report: {e}"}), 500

    notes = data.get('case_notes', [])
    note = next((n for n in notes if n.get('note_id') == note_id), None)
    if not note:
        return jsonify({"success": False, "error": "Note not found on this case/report."}), 404

    # Append-only: the prior text/hash/edited_at is preserved in
    # edit_history rather than overwritten - note_id/timestamp/author never
    # change, so a note's contemporaneous origin stays provable after edits.
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    note.setdefault('edit_history', []).append({
        "text": note["text"],
        "content_hash": note["content_hash"],
        "edited_at": note.get("edited_at"),
    })
    note["text"] = new_text
    note["content_hash"] = _hash_note_content(new_text, [a["path"] for a in note.get("attachments", [])])
    note["edited_at"] = now

    if 'updated_at' in data:
        data['updated_at'] = now

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not save note edit: {e}"}), 500

    log_chain_of_custody("case_note_edit", {"report_path": report_file, "note_id": note_id})
    return jsonify({"success": True, "note": note})

@reporting_bp.route('/api/cases/custody/add', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def add_custody_entry():
    """Appends one physical evidence custody-transfer entry (from-person ->
    to-person, e.g. 'field examiner' -> 'evidence locker') - a genuinely
    different concept from a Case Note (investigative narrative) or the
    software Audit Trail (who did what in the app), closing a gap this
    codebase's own Police report template comment already disclosed. No
    edit endpoint on purpose - a correction is a new entry, matching real
    physical chain-of-custody practice, and deliberately simpler than Case
    Notes' own edit_history mechanism."""
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"success": False, "error": "Report/case file not found or outside the permitted evidence directory."}), 404

    from_custodian = (req.get('from_custodian') or '').strip()
    to_custodian = (req.get('to_custodian') or '').strip()
    if not from_custodian or not to_custodian:
        return jsonify({"success": False, "error": "Both From and To custodian are required."}), 400

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not read report: {e}"}), 500

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "entry_id": uuid.uuid4().hex,
        "timestamp": now,
        "from_custodian": from_custodian,
        "to_custodian": to_custodian,
        "reason": (req.get('reason') or '').strip(),
        "method": (req.get('method') or '').strip(),
        "notes": (req.get('notes') or '').strip(),
        "logged_by": getattr(g, 'forensic_user', None),
    }

    data.setdefault('custody_log', []).append(entry)
    if 'updated_at' in data:
        data['updated_at'] = now

    try:
        with open(report_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not save custody entry: {e}"}), 500

    log_chain_of_custody("custody_log_add", {"report_path": report_file, "entry_id": entry["entry_id"]})
    return jsonify({"success": True, "entry": entry})

def _embed_file_into_pdf(c, y, file_path, caption=None, exhibit_number=None, category=None, tags=None, analysis_summary=None):
    """Draws one file's content (image/text embedded, or a path+size
    fallback) at the current y and returns the new y. Shared by Exhibits
    (case attachments) and the Case Notes journal so the per-extension
    embedding dispatch isn't duplicated a third time. caption is
    examiner-entered free text, rendered as a small italic line under the
    filename heading when present.

    exhibit_number/category/tags/analysis_summary are Exhibits-only
    enrichment - the Case Notes journal's own call to this function never
    passes them (its attachments aren't exhibits), so they default to None
    and add nothing there. exhibit_number is the file's 1-based position in
    attachments.files; category is a plain string from classify_extension();
    tags is a list of {name, notable, comment} dicts; analysis_summary is a
    pre-formatted string of recent tool-run results. All render via
    _draw_pdf_wrapped_text (self-paginating), never a raw drawString, since
    an exhibit with several tags/analysis runs can genuinely run past one
    page's remaining room."""
    name = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        size = 0

    label_prefix = f"Exhibit {exhibit_number}: " if exhibit_number else ""
    category_suffix = f" [{category}]" if category else ""

    def _draw_meta(y):
        c.setFont("Helvetica-Oblique", 8)
        if caption:
            y = _draw_pdf_wrapped_text(c, y, caption, x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        if tags:
            tag_line = "Tags: " + "; ".join(
                (f"* {t['name']}" if t.get('notable') else t['name']) + (f' - "{t["comment"]}"' if t.get('comment') else "")
                for t in tags)
            y = _draw_pdf_wrapped_text(c, y, tag_line, x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        if analysis_summary:
            y = _draw_pdf_wrapped_text(c, y, f"Analysis: {analysis_summary}", x=50, width_chars=100, font="Helvetica-Oblique", size=8, leading=10)
        c.setFont("Helvetica", 10)
        return y

    if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
        if y < 280:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{label_prefix}Image: {name}{category_suffix}"[:110])
        y -= 14
        y = _draw_meta(y)
        y -= 131
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(file_path), 60, y, width=220, height=140, preserveAspectRatio=True, anchor='sw')
        except Exception as img_err:
            c.setFont("Helvetica", 9)
            c.drawString(60, y + 130, f"(could not render image: {img_err})"[:100])
        y -= 15
        c.setFont("Helvetica", 10)
    elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
        if y < 160:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{label_prefix}Text File: {name}{category_suffix}"[:110])
        y -= 14
        y = _draw_meta(y)
        c.setFont("Courier", 7.5)
        try:
            with open(file_path, 'r', errors='replace') as tf:
                text_content = tf.read(ATTACHMENT_MAX_TEXT_EMBED_BYTES)
        except OSError as e:
            text_content = f"(could not read file: {e})"
        for line in text_content.splitlines()[:400]:
            if y < 50:
                c.showPage()
                y = 750
                c.setFont("Courier", 7.5)
            c.drawString(55, y, line[:130])
            y -= 9
        y -= 10
        c.setFont("Helvetica", 10)
    else:
        if y < 110:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 10)
        size_note = f" ({size:,} bytes)" if size else ""
        c.drawString(60, y, f"* {label_prefix}Document: {name}{category_suffix}{size_note} - {file_path}"[:140])
        y -= 15
        y = _draw_meta(y)
    return y

def _draw_pdf_wrapped_text(c, y, text, x=50, width_chars=95, font="Helvetica", size=9, leading=12):
    """Word-wraps and paginates a block of examiner-entered narrative text -
    shared by the narrative sections and the Case Notes journal, since both
    can run to multiple paragraphs (unlike the header's single-line fields,
    which stay truncated)."""
    c.setFont(font, size)
    for para in (text or '').splitlines() or ['']:
        for line in (textwrap.wrap(para, width_chars) or ['']):
            if y < 60:
                c.showPage()
                y = 750
                c.setFont(font, size)
            c.drawString(x, y, line)
            y -= leading
    return y

def _draw_pdf_narrative_section(c, y, title, text):
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18
    if not (text or '').strip():
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "(Not provided)")
        c.setFillColorRGB(0, 0, 0)
        y -= 14
        return y
    y = _draw_pdf_wrapped_text(c, y, text)
    y -= 8
    return y

_HASH_DISPLAY_PRIORITY = ('sha256', 'sha1', 'md5')

def _pick_display_hash(hashes):
    """Evidence Inventory's summary table shows one hash per item - picking
    silently via next(iter(hashes.values())) (the old behavior) shows a bare,
    unlabeled value with no way to tell which algorithm it is, which defeats
    the point of a verification hash. Always label the algorithm, and prefer
    the strongest one actually computed rather than whichever happened to be
    first in the dict. The full labeled set is always available in each
    item's own Verification Hashes section further down - this is only the
    at-a-glance summary column."""
    if not hashes:
        return "N/A"
    for algo in _HASH_DISPLAY_PRIORITY:
        if hashes.get(algo):
            return f"{algo.upper()}: {hashes[algo]}"
    algo, value = next(iter(hashes.items()))
    return f"{algo.upper()}: {value}"

def _draw_pdf_evidence_inventory(c, y, events, title="Evidence Inventory"):
    if not events:
        return y
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    headers = ["Evidence ID", "Device", "Model", "Serial", "Capacity", "Acquisition Hash"]
    xpos = [50, 130, 225, 320, 400, 460]
    c.setFont("Helvetica-Bold", 8)
    for label, x in zip(headers, xpos):
        c.drawString(x, y, label)
    y -= 4
    c.line(50, y, 550, y)
    y -= 12
    c.setFont("Helvetica", 7.5)
    for event in events:
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 7.5)
        meta = event.get('case_metadata', {})
        drive = event.get('source_drive_telemetry', {})
        hash_display = _pick_display_hash(event.get('computed_verification_hashes', {}))
        row = [
            str(meta.get('evidence_id', 'N/A'))[:14],
            str(drive.get('device_path', 'N/A'))[:16],
            str(drive.get('vendor_model', 'N/A'))[:15],
            str(drive.get('serial_number', 'N/A'))[:13],
            f"{drive.get('capacity_gb', 'N/A')} GB",
            str(hash_display)[:26],
        ]
        for val, x in zip(row, xpos):
            c.drawString(x, y, val)
        y -= 11
    y -= 12
    return y

def _draw_pdf_case_notes(c, y, notes, title="Forensic Analysis / Steps Taken (Case Notes)", exhibit_numbers=None):
    exhibit_numbers = exhibit_numbers or {}
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 16
    c.setFont("Helvetica-Oblique", 7)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(50, y, "Chronological case notes, each with a local SHA-256 integrity hash (tamper-evidence only, not a legal timestamp authority).")
    c.setFillColorRGB(0, 0, 0)
    y -= 16
    if not notes:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No case notes recorded.")
        y -= 15
        return y
    for note in notes:
        if y < 100:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"[{note.get('category', 'General')}] {note.get('timestamp', '')} — {note.get('author') or 'unknown'}"[:110])
        y -= 13
        if note.get('edited_at'):
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(50, y, f"(edited {note['edited_at']})")
            c.setFillColorRGB(0, 0, 0)
            y -= 11
        y = _draw_pdf_wrapped_text(c, y, note.get('text') or '', x=60, width_chars=90)
        y -= 4
        linked = [p for p in (note.get('linked_files') or []) if p in exhibit_numbers]
        if linked:
            link_line = "Linked Exhibit(s): " + "; ".join(
                f"Exhibit {exhibit_numbers[p]} - {os.path.basename(p)}" for p in linked)
            y = _draw_pdf_wrapped_text(c, y, link_line, x=60, width_chars=90, font="Helvetica-Oblique", size=8, leading=10)
            y -= 2
        for att in note.get('attachments', []):
            file_path = safe_path(att.get('path', ''))
            if file_path and os.path.exists(file_path):
                y = _embed_file_into_pdf(c, y, file_path)
        y -= 10
    return y

def _format_analysis_summary(results):
    """Turns the list of {tool, summary, run_by, run_at} dicts from
    _analysis_results_for_paths() into one compact string, e.g. "Binwalk: 3
    signature(s) found (2026-08-18 13:10); Strings: 142 line(s) extracted
    (2026-08-18 12:05)". Returns None for an empty/missing list so callers
    can skip the "Analysis:" line entirely rather than rendering an empty
    one."""
    if not results:
        return None
    return "; ".join(f"{r['tool']}: {r['summary']} ({r['run_at']})" for r in results)

def _draw_pdf_attachments(c, y, urls, files, title="Exhibits", captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    captions = captions or {}
    tags_by_path = tags_by_path or {}
    analysis_by_path = analysis_by_path or {}
    # Looked up, not enumerated from `files` - `files` here can be a
    # per-export FILTERED subset of the case's real attachments.files list
    # (attachment_selection), and a number must stay stable against the
    # FULL list regardless of which subset any one export includes, since
    # Case Notes' "Linked Exhibit(s)" references and the Reporting gallery
    # both key off the same full-list numbering. export_report() computes
    # this dict once from the unfiltered list.
    exhibit_numbers = exhibit_numbers or {}
    if not (urls or files):
        return y

    if y < 150:
        c.showPage()
        y = 730

    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 20
    c.setFont("Helvetica", 10)

    if urls:
        c.drawString(50, y, "Reference Links / URLs:")
        y -= 15
        for url in urls:
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 10)
            c.setFillColorRGB(0, 0, 0.8)
            c.drawString(60, y, f"• {url}"[:110])
            c.setFillColorRGB(0, 0, 0)
            y -= 15
        y -= 5

    # Exhibit numbers are each file's 1-based position in the case's FULL,
    # order-preserved attachments.files list (not this possibly-filtered
    # `files` subset) - a deliberately simple scheme, not a
    # permanently-retired Bates number: removing an exhibit and re-exporting
    # shifts later numbers down.
    if files:
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "Exhibit numbers reflect this case's current attachment order.")
        c.setFillColorRGB(0, 0, 0)
        y -= 12
        c.setFont("Helvetica", 10)

    for raw_path in files:
        file_path = safe_path(raw_path)
        if not file_path or not os.path.exists(file_path):
            continue
        category, _ext = classify_extension(os.path.basename(file_path))
        y = _embed_file_into_pdf(
            c, y, file_path, caption=captions.get(raw_path),
            exhibit_number=exhibit_numbers.get(raw_path), category=category,
            tags=tags_by_path.get(raw_path), analysis_summary=_format_analysis_summary(analysis_by_path.get(raw_path)))
    return y

# Shared by the DFIR and Police report templates below - not used by the
# Standard template, which keeps its existing journal-style Case Notes
# rendering (_draw_pdf_case_notes above) instead of a table.
_METHODOLOGY_STATIC_TEXT = (
    "This examination followed a standard write-blocked digital forensic acquisition and analysis "
    "workflow: source media was write-protected before connection, imaged using a forensically "
    "sound bit-for-bit acquisition tool with on-the-fly or post-acquisition cryptographic hashing, "
    "and the resulting image verified against its recorded hash before analysis began."
)
_SIGNOFF_STATIC_TEXT = (
    "I hereby affirm that the forensic examination detailed in this report was conducted in "
    "accordance with established procedures and forensic standards. The findings presented above "
    "are a true and accurate reflection of the data recovered from the submitted evidence."
)

def _draw_pdf_timeline_table(c, y, case_notes, title="Incident Timeline"):
    """Renders case_notes as a Timestamp/Category/Description table instead
    of the Standard template's narrative-journal style (_draw_pdf_case_notes)
    - the DFIR and Police reference templates both ask for a chronological
    timeline table, and the case notes journal is this app's only source of
    examiner-authored chronological entries, so it's reused here in a
    different shape rather than collecting a second, separate timeline."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 16
    c.setFont("Helvetica-Oblique", 7)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(50, y, "Chronological entries from the examiner's case notes journal.")
    c.setFillColorRGB(0, 0, 0)
    y -= 14
    if not case_notes:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No timeline entries recorded.")
        y -= 15
        return y

    headers = ["Timestamp", "Category", "Description"]
    xpos = [50, 160, 230]
    c.setFont("Helvetica-Bold", 8)
    for label, x in zip(headers, xpos):
        c.drawString(x, y, label)
    y -= 4
    c.line(50, y, 550, y)
    y -= 12
    c.setFont("Helvetica", 7.5)
    for note in sorted(case_notes, key=lambda n: n.get('timestamp', '')):
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 7.5)
        row = [
            str(note.get('timestamp', 'N/A'))[:19],
            str(note.get('category', 'General'))[:14],
            str(note.get('text', '')).replace('\n', ' ')[:62],
        ]
        for val, x in zip(row, xpos):
            c.drawString(x, y, val)
        y -= 11
    y -= 12
    return y

def _draw_pdf_timeline_block(c, y, events, title="Filesystem Timeline (MACB)"):
    """Renders a real filesystem MACB timeline for the case's acquired
    disk image(s) - see _collect_case_timeline() for how the underlying
    events are gathered (dedup/status-gating/per-image budget). Unlike
    _draw_pdf_timeline_table() above (a much shorter, case-notes-sourced
    table reused by the DFIR/Police templates), this table can legitimately
    run to thousands of rows across many pages, so - deliberately, not by
    silently copying that function's behavior - the column headers are
    redrawn after every page break rather than only once at the top."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18

    result = _collect_case_timeline(events)
    timeline_events = result["events"]

    headers = ["Timestamp", "Act.", "Evidence ID", "Path"]
    xpos = [50, 155, 195, 270]

    def _draw_header_row(y):
        c.setFont("Helvetica-Bold", 8)
        for label, x in zip(headers, xpos):
            c.drawString(x, y, label)
        y -= 4
        c.line(50, y, 550, y)
        y -= 12
        c.setFont("Helvetica", 7.5)
        return y

    if not timeline_events:
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "No filesystem timeline available for this case's evidence items.")
        y -= 15
    else:
        y = _draw_header_row(y)
        for entry in timeline_events:
            if y < 60:
                c.showPage()
                y = 750
                y = _draw_header_row(y)
            row = [
                str(entry.get('timestamp', 'N/A'))[:19],
                str(entry.get('activity', '')),
                str(entry.get('evidence_id', 'N/A'))[:14],
                str(entry.get('path', ''))[:58],
            ]
            for val, x in zip(row, xpos):
                c.drawString(x, y, val)
            y -= 11
        y -= 6
        if result["truncated"]:
            c.setFont("Helvetica-Oblique", 7)
            c.setFillColorRGB(0.4, 0.4, 0.4)
            c.drawString(50, y, "Timeline truncated - not every timestamped filesystem event fit within the report's size limits.")
            c.setFillColorRGB(0, 0, 0)
            y -= 12

    if result["notes"]:
        if y < 100:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 8)
        c.drawString(50, y, "Notes:")
        y -= 12
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColorRGB(0.4, 0.4, 0.4)
        for note in result["notes"]:
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica-Oblique", 7)
                c.setFillColorRGB(0.4, 0.4, 0.4)
            y = _draw_pdf_wrapped_text(c, y, note, x=55, width_chars=100, font="Helvetica-Oblique", size=7, leading=10)
        c.setFillColorRGB(0, 0, 0)

    y -= 12
    return y

def _draw_pdf_methodology_tools(c, y, events):
    """Static description of this app's standard acquisition workflow, plus
    a 'tools used in this case' list derived from the distinct event.tool
    values already recorded per job - zero new data entry, zero live
    subprocess/version-check calls added to report export."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Forensic Methodology & Tools")
    y -= 18
    c.setFont("Helvetica", 9.5)
    y = _draw_pdf_wrapped_text(c, y, _METHODOLOGY_STATIC_TEXT, width_chars=95)
    y -= 10

    tools = sorted({str(e.get('tool')).upper() for e in events if e.get('tool')})
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Tools Used in This Case:")
    y -= 14
    c.setFont("Helvetica", 10)
    c.drawString(60, y, ", ".join(tools) if tools else "No acquisition/recovery tool recorded.")
    y -= 20
    return y

def _draw_pdf_signoff(c, y, examiner):
    """Static sign-off block - examiner name (already-collected data) plus
    blank signature/date lines. No new data entry."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Sign-off & Signatures")
    y -= 18
    c.setFont("Helvetica", 9.5)
    y = _draw_pdf_wrapped_text(c, y, _SIGNOFF_STATIC_TEXT, width_chars=95)
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Examiner: {examiner}")
    y -= 35
    c.line(50, y, 250, y)
    c.drawString(50, y - 12, "Signature")
    c.line(320, y, 520, y)
    c.drawString(320, y - 12, "Date")
    y -= 25
    return y

# --- Geolocation report section: static tile-mosaic map image + placemark table ---
# Tile math ported (not imported) from install.py's _latlon_to_tile_xy/_tile_range_for_bbox -
# this file and install.py deliberately never import from each other (separate deployment
# contexts, e.g. TOOL_INSTALLABLE_PACKAGES is already duplicated the same way), so this is a
# second, independent copy of the same standard slippy-map-tilenames formula, not a shared import.
GEO_MAP_PX_WIDTH = 480
GEO_MAP_PX_HEIGHT = 300
GEO_MAP_ZOOM_MIN = 1
GEO_MAP_ZOOM_MAX = 16
GEO_TILE_FETCH_TIMEOUT = 6
GEO_TILE_MAX_COUNT = 40
GEO_TILE_USER_AGENT = "PiForensicsSuite/1.0 (report export map; +https://github.com/n0sfs/pi-forensics)"

def _latlon_to_global_pixel(lat, lon, zoom):
    """WGS84 lat/lon -> continuous (not tile-floored) global pixel coordinates
    at a zoom level, standard OSM 256px-tile Web Mercator projection - used
    both to size/position the tile grid and to project each placemark onto
    it at the exact same scale."""
    lat = max(min(lat, 85.05112878), -85.05112878)
    lat_rad = math.radians(lat)
    n = 2 ** zoom
    x = (lon + 180.0) / 360.0 * n * 256.0
    y = (1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n * 256.0
    return x, y

def _choose_geo_map_zoom(placemarks):
    """Picks the highest zoom level (most detail) at which this placemark
    set's bounding box still fits within the target map image size (minus a
    small margin) - starts at the max and steps down, matching how a normal
    map viewer auto-fits a bounds. Falls back to the minimum zoom for a
    genuinely widescattered set (e.g. evidence from two continents)."""
    lats = [p['lat'] for p in placemarks]
    lons = [p['lon'] for p in placemarks]
    min_lat, max_lat = min(lats), max(lats)
    min_lon, max_lon = min(lons), max(lons)
    for zoom in range(GEO_MAP_ZOOM_MAX, GEO_MAP_ZOOM_MIN - 1, -1):
        x1, y1 = _latlon_to_global_pixel(max_lat, min_lon, zoom)
        x2, y2 = _latlon_to_global_pixel(min_lat, max_lon, zoom)
        if abs(x2 - x1) <= GEO_MAP_PX_WIDTH - 40 and abs(y2 - y1) <= GEO_MAP_PX_HEIGHT - 40:
            return zoom
    return GEO_MAP_ZOOM_MIN

def _fetch_osm_tile(z, x, y):
    """Fetches one 256x256 OSM tile's raw PNG bytes - live first (with a
    real, honest User-Agent per OSM's tile usage policy), falling back to
    install.py's optional local offline-tile cache per tile if present -
    mirrors the live app's own online-first/offline-fallback tile behavior
    (_createGeoTileLayer() in main.js), just server-side and per-request
    instead of a persistent map widget. Returns None (never raises) if both
    sources come up empty or the server signals a policy block (the same
    X-Blocked detection install.py's own bulk tile-cache downloader already
    uses) - the map image simply leaves that tile blank, matching the
    interactive viewer's own graceful per-tile degradation."""
    try:
        req = urllib.request.Request(
            f"https://tile.openstreetmap.org/{z}/{x}/{y}.png",
            headers={"User-Agent": GEO_TILE_USER_AGENT})
        with urllib.request.urlopen(req, timeout=GEO_TILE_FETCH_TIMEOUT) as resp:
            if not resp.headers.get("X-Blocked"):
                return resp.read()
    except Exception:
        pass
    # Flask's default static_folder is <app root>/static - computed directly
    # via INSTALL_DIR rather than importing the app object itself (which
    # would be a circular import: app.py -> routes.reporting -> app.py).
    local_path = os.path.join(INSTALL_DIR, 'static', 'vendor', 'osm_tiles', str(z), str(x), f"{y}.png")
    if os.path.exists(local_path):
        try:
            with open(local_path, 'rb') as f:
                return f.read()
        except OSError:
            pass
    return None

def _draw_pdf_geo_map_image(c, x0, y0, placemarks):
    """Draws a static tile-mosaic map (live-fetched or offline-cache-
    fallback tiles, see _fetch_osm_tile) with small pin markers at (x0, y0)
    (bottom-left corner, PDF points) sized GEO_MAP_PX_WIDTH x
    GEO_MAP_PX_HEIGHT - a reference-quality on-page map, not a print-
    resolution figure. Each 256x256 tile is drawn individually via
    reportlab's own drawImage (which decodes the PNG via Pillow internally,
    already a working dependency in this app via existing photo-exhibit
    embedding) at its correct projected position - reportlab composites the
    mosaic on the page itself, no separate image-compositing library
    needed. Returns True if at least one tile was actually drawn, so the
    caller can fall back to a disclosed 'map imagery unavailable' note
    instead of leaving a silently blank box when every tile fetch/fallback
    came up empty (no internet, no offline cache)."""
    from reportlab.lib.utils import ImageReader

    zoom = _choose_geo_map_zoom(placemarks)
    lats = [p['lat'] for p in placemarks]
    lons = [p['lon'] for p in placemarks]
    center_px, center_py = _latlon_to_global_pixel((min(lats) + max(lats)) / 2.0, (min(lons) + max(lons)) / 2.0, zoom)
    window_left = center_px - GEO_MAP_PX_WIDTH / 2.0
    window_top = center_py - GEO_MAP_PX_HEIGHT / 2.0
    n = 2 ** zoom

    c.saveState()
    clip = c.beginPath()
    clip.rect(x0, y0, GEO_MAP_PX_WIDTH, GEO_MAP_PX_HEIGHT)
    c.clipPath(clip, stroke=0, fill=0)

    any_drawn = False
    tile_count = 0
    tile_x_min = int(window_left // 256)
    tile_x_max = int((window_left + GEO_MAP_PX_WIDTH) // 256)
    tile_y_min = int(window_top // 256)
    tile_y_max = int((window_top + GEO_MAP_PX_HEIGHT) // 256)
    for tx in range(tile_x_min, tile_x_max + 1):
        for ty in range(tile_y_min, tile_y_max + 1):
            tile_count += 1
            if tile_count > GEO_TILE_MAX_COUNT or tx < 0 or ty < 0 or tx >= n or ty >= n:
                continue
            tile_bytes = _fetch_osm_tile(zoom, tx, ty)
            if not tile_bytes:
                continue
            try:
                img = ImageReader(io.BytesIO(tile_bytes))
                draw_x = x0 + (tx * 256 - window_left)
                draw_y = y0 + (GEO_MAP_PX_HEIGHT - (ty * 256 - window_top) - 256)
                c.drawImage(img, draw_x, draw_y, width=256, height=256, mask='auto')
                any_drawn = True
            except Exception:
                continue

    if any_drawn:
        for placemark in placemarks:
            px, py = _latlon_to_global_pixel(placemark['lat'], placemark['lon'], zoom)
            mx = x0 + (px - window_left)
            my = y0 + (GEO_MAP_PX_HEIGHT - (py - window_top))
            c.setFillColorRGB(0.85, 0.15, 0.1)
            c.setStrokeColorRGB(1, 1, 1)
            c.circle(mx, my, 4, stroke=1, fill=1)

    c.restoreState()
    c.setStrokeColorRGB(0.6, 0.6, 0.6)
    c.rect(x0, y0, GEO_MAP_PX_WIDTH, GEO_MAP_PX_HEIGHT, stroke=1, fill=0)
    return any_drawn

def _draw_pdf_geolocation_block(c, y, kml_data, title="Geolocation / GPS Evidence"):
    """Renders each case KML file with >=1 valid placemark (see
    _collect_case_geolocation) as a static tile-mosaic map image with pin
    markers, followed by a Name/Latitude/Longitude/Description placemark
    table - the PDF counterpart to the live app's interactive Leaflet
    viewer. A file whose tile fetch comes up completely empty still gets
    its table, just with a disclosed note in place of the map image - the
    underlying coordinate data is never hidden behind a map that failed to
    render."""
    if y < 150:
        c.showPage()
        y = 730
    y -= 15
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18

    if not kml_data:
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, "No geolocation (KML) evidence with GPS placemarks found for this case.")
        c.setFillColorRGB(0, 0, 0)
        y -= 14
        return y

    for entry in kml_data:
        min_needed = GEO_MAP_PX_HEIGHT + 30 + 40
        if y < min_needed:
            c.showPage()
            y = 750

        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, entry['name'][:90])
        y -= 13
        c.setFont("Helvetica-Oblique", 7.5)
        c.setFillColorRGB(0.5, 0.5, 0.5)
        c.drawString(50, y, entry['path'][:115])
        c.setFillColorRGB(0, 0, 0)
        y -= 14

        map_y0 = y - GEO_MAP_PX_HEIGHT
        drawn = _draw_pdf_geo_map_image(c, 50, map_y0, entry['placemarks'])
        if not drawn:
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColorRGB(0.5, 0.5, 0.5)
            c.drawCentredString(50 + GEO_MAP_PX_WIDTH / 2.0, map_y0 + GEO_MAP_PX_HEIGHT / 2.0,
                                 "Map imagery unavailable for this evidence item - showing coordinates only.")
            c.setFillColorRGB(0, 0, 0)
        y = map_y0 - 12

        headers = ["Name", "Latitude", "Longitude", "Description"]
        xpos = [50, 200, 270, 340]

        def _draw_geo_header_row(y):
            c.setFont("Helvetica-Bold", 8)
            for label, x in zip(headers, xpos):
                c.drawString(x, y, label)
            y -= 4
            c.line(50, y, 550, y)
            y -= 12
            c.setFont("Helvetica", 7.5)
            return y

        y = _draw_geo_header_row(y)
        for p in entry['placemarks']:
            if y < 60:
                c.showPage()
                y = 750
                y = _draw_geo_header_row(y)
            c.drawString(xpos[0], y, (p['name'] or '(unnamed)')[:26])
            c.drawString(xpos[1], y, f"{p['lat']:.6f}")
            c.drawString(xpos[2], y, f"{p['lon']:.6f}")
            c.drawString(xpos[3], y, (p['description'] or '').replace('\n', ' ')[:38])
            y -= 10
        y -= 14

    return y

def _draw_pdf_contents_page(c, resolved_sections, event_count):
    """A plain Report Contents listing, not page-number cross-referenced -
    this renderer draws in a single streaming pass with no forward
    knowledge of final page numbers, so a real "Executive Summary ... 4"
    style TOC would need a second pass. This still gives the upfront
    section outline the DFIR report structure this feature was built
    against calls for; real point-and-click navigation is handled
    separately via the PDF outline/bookmarks added at each section below,
    which don't need page numbers at all.

    `resolved_sections` is the already-filtered, already-ordered list from
    _resolve_section_order() - this function only decides how to *display*
    each entry (the one special case: acquisition_method gets an evidence-
    item-count suffix here, matching its pre-existing behavior, while its
    bookmark/on-page label elsewhere stays plain)."""
    y = 700
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Report Contents")
    y -= 25
    c.setFont("Helvetica", 10.5)

    for i, entry in enumerate(resolved_sections, start=1):
        display = entry["title"]
        if entry["key"] == "acquisition_method" and event_count > 0:
            plural = "s" if event_count != 1 else ""
            display = f"{display} ({event_count} evidence item{plural})"
        c.drawString(60, y, f"{i}.  {display}")
        y -= 18

def _numbered_canvas_class():
    """Returns a reportlab Canvas subclass that stamps a 'Page N' footer on
    every page as it's flushed, without needing to touch every individual
    showPage() call site scattered across the drawing helpers above -
    showPage() is the one choke point they all already go through. save()
    doesn't need its own override: reportlab's own Canvas.save() calls
    showPage() internally for whatever page is still pending when save()
    runs, so the last page gets stamped through this same override
    automatically. Shared by all three report-template PDF builders below;
    reportlab is imported here rather than at module level, matching this
    file's existing lazy-import convention for it (routes that never touch
    PDF generation shouldn't need the dependency)."""
    from reportlab.pdfgen import canvas

    class _NumberedCanvas(canvas.Canvas):
        def showPage(self):
            self.setFont("Helvetica", 8)
            self.setFillColorRGB(0.45, 0.45, 0.45)
            self.drawRightString(550, 30, f"Page {self.getPageNumber()}")
            self.setFillColorRGB(0, 0, 0)
            canvas.Canvas.showPage(self)

    return _NumberedCanvas

def _draw_pdf_fixed_contents_page(c, entries):
    """Simpler counterpart to _draw_pdf_contents_page for the DFIR/Police
    templates below, which have a fixed section list (no per-section
    sections dict to check) - entries is just the final ordered list of
    section titles to print, already resolved by the caller (e.g.
    conditionally including "Exhibits" only when there are attachments)."""
    y = 700
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Report Contents")
    y -= 25
    c.setFont("Helvetica", 10.5)
    for i, entry in enumerate(entries, start=1):
        c.drawString(60, y, f"{i}.  {entry}")
        y -= 18

# Registry of selectable report shapes (Settings > Case & Reporting sets a
# station default; the Export pane can override it per-export). Only used
# for display labels/descriptions and to validate incoming 'template'
# values - 'dfir'/'police' each still have their own dedicated, fixed-
# structure builder-function pair (clearer and lower-risk than forcing an
# intentionally rigid, reference-document-matched shape through a generic
# loop). 'standard' and any user-defined 'custom:<id>' template (see
# REPORT_SECTION_BLOCKS/_resolve_section_order below) share ONE
# registry-driven builder pair instead - a custom template is really just a
# saved, reordered/renamed/filtered configuration of the same building
# blocks Standard's own section checkboxes already expose.
REPORT_TEMPLATES = {
    'standard': {
        'label': 'Standard',
        'description': 'The default configurable report - toggle sections and job fields freely.',
    },
    'dfir': {
        'label': 'DFIR Report',
        'description': 'Fixed-structure incident response report: Executive Summary, Incident Timeline, Indicators of Compromise, Containment & Next Steps.',
    },
    'police': {
        'label': 'Forensics Report',
        'description': 'Fixed-structure law-enforcement examination report: Administrative Information, Evidence Collection & Chain of Custody, Sign-off & Signatures.',
    },
    'caseuco': {
        'label': 'CASE/UCO Report',
        'description': 'Fixed-structure investigation report aligned with the CASE/UCO cyber-forensic ontology (Investigation, Observable Objects, Investigative Actions, Provenance Records) - the only built-in template that also includes Geolocation/GPS evidence.',
    },
}

# The building blocks available to the Standard template and to
# user-defined custom templates (Report Template Builder, Settings > Case &
# Reporting) - a custom template is a saved, ordered subset of these with
# optional per-block title overrides. Every field below is REQUIRED (no
# .get(key, True)-style implicit default anywhere this registry is read) so
# a future 15th block that forgets a field fails loudly at import time
# instead of silently drifting what every station's default report shows.
#
#   default_title     - shown on the page (where the block has an on-page
#                        heading) and used as the Report Contents/TOC label
#                        and PDF bookmark title unless a custom template
#                        overrides it.
#   in_legacy_default  - included when a report uses the plain sections:{key:
#                        bool} dict (today's Export-modal checkboxes/Settings
#                        station defaults, i.e. no custom template selected).
#                        False for iocs/recommendations - Standard never
#                        showed these before (only DFIR did), so they stay
#                        opt-in-only via a custom template rather than
#                        silently appearing in every station's existing
#                        default export.
#   requires_events    - skipped entirely (not merely rendered empty) when
#                        the case has zero acquisition/recovery events,
#                        regardless of whether it's enabled - there is
#                        nothing to show either way.
#   force_page_break   - the registry-driven draw loop unconditionally
#                        starts this block on a fresh page (unless it's the
#                        very first block rendered, which is already on one)
#                        rather than trusting the block's own drawer to be
#                        pagination-safe at an arbitrary position. Needed
#                        because _draw_pdf_header ignores its y argument
#                        entirely (always draws at a hardcoded y=730) and
#                        _draw_pdf_job_section (the per-event acquisition
#                        loop's first event) has no internal pagination
#                        guard at all - both are safe today only because
#                        case_info/acquisition_method are always drawn in a
#                        fixed, page-fresh position; a reordered custom
#                        template could otherwise silently overlap/clip
#                        content.
#   remappable         - whether a custom template can point this block at a
#                        different narrative field than its own default (see
#                        NARRATIVE_BLOCK_FIELD_MAP below and source_field in
#                        _resolve_section_order()) - true only for the 7
#                        free-text blocks. Every other block's content is
#                        structured data (a table, a log, a filesystem walk)
#                        that isn't something a dropdown can meaningfully
#                        rewire, so remapping is deliberately scoped to just
#                        these 7 rather than offered everywhere.
REPORT_SECTION_BLOCKS = [
    {"key": "case_info", "default_title": "Case Information",
     "in_legacy_default": True, "requires_events": False, "force_page_break": True, "remappable": False},
    {"key": "executive_summary", "default_title": "Executive Summary",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "objectives", "default_title": "Objectives",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "evidence_inventory", "default_title": "Evidence Inventory",
     "in_legacy_default": True, "requires_events": True, "force_page_break": False, "remappable": False},
    {"key": "acquisition_method", "default_title": "Acquisition Method",
     "in_legacy_default": True, "requires_events": True, "force_page_break": True, "remappable": False},
    {"key": "forensic_analysis", "default_title": "Forensic Analysis / Steps Taken (Case Notes)",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": False},
    {"key": "relevant_findings", "default_title": "Relevant Findings",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "limitations", "default_title": "Limitations & Statement of Uncertainty",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "conclusion", "default_title": "Conclusion",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "iocs", "default_title": "Indicators of Compromise",
     "in_legacy_default": False, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "recommendations", "default_title": "Recommendations / Next Steps",
     "in_legacy_default": False, "requires_events": False, "force_page_break": False, "remappable": True},
    {"key": "attachments", "default_title": "Exhibits",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": False},
    # Unlike timeline/iocs/recommendations (in_legacy_default=False, custom-
    # template-only - _expand_legacy_sections_dict() unconditionally skips
    # any False-flagged block, so there is no other way for a block to be
    # checkbox-controlled on the Standard template), Geolocation deliberately
    # gets a real checkbox on the plain Export pane / Settings station
    # defaults - the actual <input> elements just start unchecked in the
    # markup, so a case with no GPS evidence doesn't grow an empty section
    # by default.
    {"key": "geolocation", "default_title": "Geolocation / GPS Evidence",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": False},
    {"key": "audit_trail", "default_title": "Case Activity Log (Audit Trail)",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": False},
    {"key": "timeline", "default_title": "Filesystem Timeline (MACB)",
     "in_legacy_default": False, "requires_events": True, "force_page_break": True, "remappable": False},
    {"key": "custody_log", "default_title": "Physical Evidence Custody Log",
     "in_legacy_default": True, "requires_events": False, "force_page_break": False, "remappable": False},
]
# key -> the header dict field a remappable block draws from by default -
# also the full set of choices a custom template's Report Template Builder
# can point ANY remappable block's source_field at (see
# _custom_report_template_from_payload/_resolve_section_order below). Field
# names are header dict keys, not block keys - relevant_findings/
# recommendations differ from their own block key (findings_summary/
# recommendations_next_steps) because the underlying narrative field was
# named before this remapping feature existed and renaming it would be a
# larger, unrelated schema change.
NARRATIVE_BLOCK_FIELD_MAP = {
    "executive_summary": "executive_summary",
    "objectives": "objectives",
    "relevant_findings": "findings_summary",
    "limitations": "limitations",
    "conclusion": "conclusion",
    "iocs": "iocs",
    "recommendations": "recommendations_next_steps",
}
# Reverse lookup for populating the Report Template Builder's per-row
# dropdown with a human label instead of a raw header-field name.
NARRATIVE_FIELD_LABELS = {
    "executive_summary": "Executive Summary text",
    "objectives": "Objectives text",
    "findings_summary": "Relevant Findings text",
    "limitations": "Limitations text",
    "conclusion": "Conclusion text",
    "iocs": "Indicators of Compromise text",
    "recommendations_next_steps": "Recommendations / Next Steps text",
}
assert all(
    {"key", "default_title", "in_legacy_default", "requires_events", "force_page_break", "remappable"} <= b.keys()
    for b in REPORT_SECTION_BLOCKS
), "every REPORT_SECTION_BLOCKS entry needs all 6 fields - see the docstring above"

_REPORT_SECTION_BLOCK_MAP = {b["key"]: b for b in REPORT_SECTION_BLOCKS}

# Lightweight capability registry - documents what a "feature module" needs
# (apt packages, sudo, where its UI lives) without any dynamic loading,
# dependency isolation, or versioning machinery. Nothing in this app reads
# this dict yet; it exists to establish one consistent shape for describing
# a module's requirements, so install.py can eventually turn a module with
# real optional apt_packages into an install-time checklist item (falling
# back to the existing Settings > Tool Versions "Install" button for anyone
# who skips it - that mechanism already exists and needs no changes).
# Timeline is a deliberately light first entry: it needs no new packages
# (pytsk3/sleuthkit/libewf-dev are already required for the Sleuth Kit
# Image Browser this reuses), so this entry mostly documents linkage
# rather than driving any new install-time gating - that part of the
# pattern will actually get exercised by a future module with real
# optional dependencies (e.g. video thumbnail extraction needing ffmpeg).
FEATURE_MODULES = {
    "timeline": {
        "label": "Filesystem Timeline",
        "category": "analysis",
        "apt_packages": [],
        "needs_sudo": False,
        "ui_hooks": ["file_explorer_image_browser", "report_block:timeline"],
    },
}

def _expand_legacy_sections_dict(sections_dict):
    """Converts the plain sections:{key: bool} dict (today's Export-modal
    checkboxes / Settings station defaults, used only when no custom
    template is selected) into the canonical ordered {key, title} list
    _resolve_section_order()/the registry-driven builders consume - in
    REPORT_SECTION_BLOCKS' own fixed order, default titles only (no
    per-block custom titles are possible via this legacy checkbox path).
    'objectives' has no checkbox of its own - the single existing
    'executive_summary' checkbox continues to control both blocks together,
    unchanged from before this refactor. iocs/recommendations are always
    excluded here (in_legacy_default=False) - Standard's default output
    never showed these before this feature, only DFIR/Police did; they're
    opt-in-only via a custom template."""
    sections_dict = sections_dict or {}
    result = []
    for block in REPORT_SECTION_BLOCKS:
        if not block["in_legacy_default"]:
            continue
        legacy_key = "executive_summary" if block["key"] == "objectives" else block["key"]
        if sections_dict.get(legacy_key, True):
            # source_field always the block's own default here - the plain
            # checkbox path has no per-section remapping capability, only a
            # saved custom template does (see _resolve_section_order below).
            result.append({"key": block["key"], "title": block["default_title"],
                            "source_field": NARRATIVE_BLOCK_FIELD_MAP.get(block["key"])})
    return result

def _resolve_section_order(mode, sections_dict, custom_record, event_count):
    """Single source of truth for 'which blocks render, in what order, with
    what title, from which underlying field' - used by both the plain
    Standard export path (mode='legacy', driven by the checkbox dict) and
    any user-defined custom template (mode='custom', driven by a saved
    runtime_config record). Also the single place that filters out blocks
    needing events the case doesn't have, so the draw loop / PDF Contents
    page / HTML TOC never need to separately re-derive that condition (see
    REPORT_SECTION_BLOCKS' requires_events docstring) - a future duplicated
    copy of this check silently drifting out of sync is exactly the
    fragility this centralizes away. source_field on each returned entry is
    only ever meaningful for a remappable block (see NARRATIVE_BLOCK_FIELD_MAP)
    - None for every other block, which the draw-loop dispatch simply
    ignores. A custom template's own source_field per section is already
    validated/defaulted at save time (_custom_report_template_from_payload),
    so this just passes it through unchanged."""
    if mode == "custom":
        raw = []
        for e in custom_record.get("sections", []):
            key = e.get("key")
            if not e.get("enabled", True) or key not in _REPORT_SECTION_BLOCK_MAP:
                continue
            block = _REPORT_SECTION_BLOCK_MAP[key]
            source_field = None
            if block["remappable"]:
                # Falls back to the block's own default field, not None, if
                # this entry has no source_field at all - covers a custom
                # template saved before this remapping feature existed,
                # which otherwise would have silently blanked every one of
                # its narrative sections the first time it was used again.
                stored = e.get("source_field")
                source_field = stored if stored in NARRATIVE_BLOCK_FIELD_MAP.values() else NARRATIVE_BLOCK_FIELD_MAP[key]
            raw.append({"key": key, "title": (e.get("title") or "").strip() or block["default_title"],
                        "source_field": source_field})
    else:
        raw = _expand_legacy_sections_dict(sections_dict)
    return [e for e in raw if not _REPORT_SECTION_BLOCK_MAP[e["key"]]["requires_events"] or event_count > 0]

def _resolve_template_ref(value, cfg):
    """Single source of truth for turning a 'template' string (from an
    export request or a saved station default) into what to actually
    render - used by both export_report() and settings_case_reporting(),
    which previously each had their own copy of this check (and neither
    knew about custom:<id> references at all). Returns ('standard'|'dfir'|
    'police', None) or ('custom', <template record dict>). Raises
    ValueError if value looks like a custom:<id> reference but that id
    doesn't currently exist in cfg['custom_report_templates'] - callers
    decide what that means for them (export_report() turns it into a 400
    rather than silently rendering something else; settings_case_reporting()
    catches it and stores 'standard' instead, since a station default
    should never be allowed to persist a dangling reference). Any other
    unrecognized value (missing, garbage, an old/bogus string) falls back
    to ('standard', None) silently, matching this app's existing lenient
    behavior for that case."""
    value = value or 'standard'
    if value in REPORT_TEMPLATES:
        return value, None
    if value.startswith('custom:'):
        template_id = value[len('custom:'):]
        for rec in cfg.get('custom_report_templates', []):
            if rec.get('id') == template_id:
                return 'custom', rec
        raise ValueError(f"Selected custom template '{template_id}' no longer exists.")
    return 'standard', None

def _build_pdf_report_standard(pdf_path, header, events, urls, files, audit_entries, case_notes, resolved_sections, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None, custody_log=None):
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "PI FORENSICS SUITE ACQUISITION AUDIT REPORT")

    # Station branding (Settings > Case & Reporting) renders as an ADDED
    # subtitle line and/or a small top-right logo, never replacing the
    # fixed title above - keeps every report immediately recognizable as
    # coming from this app regardless of what a station has customized.
    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass

    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    # Report Contents gets its own page, right after the title - so the
    # title page reads as a title page and the outline reads as an outline,
    # rather than blending into the Case Information that follows.
    c.showPage()
    _draw_pdf_contents_page(c, resolved_sections, len(events))
    c.showPage()
    y = 750

    # Per-key dispatch table - each entry knows how to draw its own block
    # given the current y and its (possibly custom) title. Built fresh per
    # call so each closure captures this call's own header/events/etc.
    # A remappable block's lambda reads `field` (the resolved source_field
    # from _resolve_section_order() - the block's own default header key
    # unless a custom template pointed it elsewhere) instead of a hardcoded
    # header key. Every lambda takes the same (y, title, field) signature,
    # even ones that ignore `field`, so the call site below can stay a
    # single uniform dispatch[key](y, title, field) with no per-block
    # special-casing.
    dispatch = {
        "case_info": lambda y, title, field: _draw_pdf_header(c, header, title=title),
        "executive_summary": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "objectives": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "evidence_inventory": lambda y, title, field: _draw_pdf_evidence_inventory(c, y, events, title=title),
        "acquisition_method": lambda y, title, field: _draw_pdf_acquisition_method(c, y, events, job_fields, title=title),
        "forensic_analysis": lambda y, title, field: _draw_pdf_case_notes(c, y, case_notes, title=title, exhibit_numbers=exhibit_numbers),
        "relevant_findings": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "limitations": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "conclusion": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "iocs": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "recommendations": lambda y, title, field: _draw_pdf_narrative_section(c, y, title, header.get(field)),
        "attachments": lambda y, title, field: _draw_pdf_attachments(c, y, urls, files, title=title, captions=captions,
                                                                       tags_by_path=tags_by_path, analysis_by_path=analysis_by_path,
                                                                       exhibit_numbers=exhibit_numbers),
        "audit_trail": lambda y, title, field: _draw_pdf_audit_trail(c, y, audit_entries, title=title),
        "timeline": lambda y, title, field: _draw_pdf_timeline_block(c, y, events, title=title),
        "geolocation": lambda y, title, field: _draw_pdf_geolocation_block(c, y, geo_data or [], title=title),
        "custody_log": lambda y, title, field: _draw_pdf_custody_log_block(c, y, custody_log or [], title=title),
    }

    for i, entry in enumerate(resolved_sections):
        key, title = entry["key"], entry["title"]
        # Some blocks (case_info, acquisition_method) draw at a fixed
        # y/page-fresh position internally and have no pagination guard of
        # their own - safe today only because they're always drawn first,
        # unsafe at an arbitrary custom-template position unless the loop
        # itself forces a fresh page before them. See REPORT_SECTION_BLOCKS'
        # force_page_break docstring.
        if i > 0 and _REPORT_SECTION_BLOCK_MAP[key]["force_page_break"]:
            c.showPage()
            y = 750
        c.bookmarkPage(key)
        c.addOutlineEntry(title, key, level=0)
        y = dispatch[key](y, title, entry.get("source_field"))

    c.save()

def _build_pdf_report_dfir(pdf_path, header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """Fixed-structure DFIR Incident Report - no sections/job_fields dict,
    since a template's whole point is a defined shape. Reuses the same
    low-level drawing helpers the Standard template uses; only the section
    list, order, and labels differ, matching the reference DFIR report
    structure this was built against (see the plan's field-mapping table -
    most sections reuse existing narrative fields under a different label
    for this template, only Indicators of Compromise and Containment/Next
    Steps are genuinely new fields)."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "DIGITAL FORENSICS AND INCIDENT RESPONSE REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    entries = ["Case Information", "Executive Summary", "Incident Overview & Scope",
               "Incident Timeline", "Technical Analysis & Forensic Findings",
               "Indicators of Compromise", "Containment, Eradication & Next Steps"]
    has_exhibits = bool(urls or files)
    if has_exhibits:
        entries.append("Exhibits")
    entries.append("Audit Trail")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('case_info')
    c.addOutlineEntry("Case Information", 'case_info', level=0)
    y = _draw_pdf_header(c, header)

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('overview_scope')
    c.addOutlineEntry("Incident Overview & Scope", 'overview_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Incident Overview & Scope", header.get('objectives'))

    c.bookmarkPage('timeline')
    c.addOutlineEntry("Incident Timeline", 'timeline', level=0)
    y = _draw_pdf_timeline_table(c, y, case_notes, title="Incident Timeline")

    c.bookmarkPage('technical_analysis')
    c.addOutlineEntry("Technical Analysis & Forensic Findings", 'technical_analysis', level=0)
    y = _draw_pdf_narrative_section(c, y, "Technical Analysis & Forensic Findings", header.get('findings_summary'))

    c.bookmarkPage('iocs')
    c.addOutlineEntry("Indicators of Compromise", 'iocs', level=0)
    y = _draw_pdf_narrative_section(c, y, "Indicators of Compromise", header.get('iocs'))

    c.bookmarkPage('containment')
    c.addOutlineEntry("Containment, Eradication & Next Steps", 'containment', level=0)
    y = _draw_pdf_narrative_section(c, y, "Containment, Eradication & Next Steps", header.get('recommendations_next_steps'))

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('audit_trail')
    c.addOutlineEntry("Audit Trail", 'audit_trail', level=0)
    y = _draw_pdf_audit_trail(c, y, audit_entries)

    c.save()

def _build_pdf_report_police(pdf_path, header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """Fixed-structure Forensics (Police) Report, modeled on the reference
    law-enforcement examination report. Reuses the same low-level drawing
    helpers as the other two templates - see the plan's field-mapping table
    for what's reused vs. genuinely new.

    One disclosed gap: the reference report's "Chain of Custody Log" is
    about physical evidence handoffs between people (officer to analyst to
    evidence vault) - this app has no concept of that. Reusing this app's
    Audit Trail (a log of actions taken in the software) under that heading
    is the closest real fit, not a literal personnel custody-transfer log -
    labeled "Chain of Custody / Activity Log" rather than silently passed
    off as the real thing."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "POLICE FORENSICS INVESTIGATION REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    has_exhibits = bool(urls or files)
    entries = ["Administrative Information", "Executive Summary", "Case Background & Scope",
               "Evidence Collection & Chain of Custody", "Forensic Methodology & Tools",
               "Detailed Findings & Analysis", "Conclusion & Summary", "Sign-off & Signatures"]
    if has_exhibits:
        entries.append("Exhibits & Appendices")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('admin_info')
    c.addOutlineEntry("Administrative Information", 'admin_info', level=0)
    y = _draw_pdf_header(c, header, title="Administrative Information")

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('background_scope')
    c.addOutlineEntry("Case Background & Scope", 'background_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Case Background & Scope", header.get('objectives'))

    c.bookmarkPage('evidence_coc')
    c.addOutlineEntry("Evidence Collection & Chain of Custody", 'evidence_coc', level=0)
    y = _draw_pdf_evidence_inventory(c, y, events, title="Itemized Evidence & Integrity Hashing")
    y = _draw_pdf_audit_trail(c, y, audit_entries, title="Chain of Custody / Activity Log")

    c.bookmarkPage('methodology')
    c.addOutlineEntry("Forensic Methodology & Tools", 'methodology', level=0)
    y = _draw_pdf_methodology_tools(c, y, events)

    c.bookmarkPage('findings')
    c.addOutlineEntry("Detailed Findings & Analysis", 'findings', level=0)
    y = _draw_pdf_timeline_table(c, y, case_notes, title="Chronological Timeline of Events")
    y = _draw_pdf_narrative_section(c, y, "Artifact Analysis", header.get('findings_summary'))

    c.bookmarkPage('conclusion')
    c.addOutlineEntry("Conclusion & Summary", 'conclusion', level=0)
    y = _draw_pdf_narrative_section(c, y, "Conclusion", header.get('conclusion'))
    y = _draw_pdf_narrative_section(c, y, "Recommendations", header.get('recommendations_next_steps'))

    c.bookmarkPage('signoff')
    c.addOutlineEntry("Sign-off & Signatures", 'signoff', level=0)
    y = _draw_pdf_signoff(c, y, header['examiner'])

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits & Appendices", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.save()

def _build_pdf_report_caseuco(pdf_path, header, events, urls, files, audit_entries, case_notes, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    """Fixed-structure report aligned with the CASE/UCO cyber-forensic
    ontology (caseontology.org) - Investigation, ObservableObject,
    InvestigativeAction, ProvenanceRecord, Analysis, Tool, Location. Reuses
    the same low-level drawing helpers as the other two fixed templates;
    every section maps onto an existing data source or shared helper, no
    new schema fields were needed - see the plan's section-mapping table.

    Two disclosed simplifications, matching the honesty already established
    for DFIR/Police: (1) the ontology models distinct Examiner/Investigator/
    Subject/Attorney roles - this app has one Examiner field, not separate
    per-role records, so "Investigation Overview" only ever shows the one
    Examiner; a station that wants Authorization/Investigation Status/Form
    captured can add them as Custom Case Fields, the same mechanism Police's
    Administrative Information already relies on. (2) "Provenance Record /
    Chain of Custody" reuses this app's Audit Trail (a software-action log),
    not a literal ProvenanceRecord graph of wasDerivedFrom/wasInformedBy
    relationships - same substitution reasoning as Police's own Chain of
    Custody section.

    Unlike DFIR/Police, this template always includes a Geolocation section
    (maps directly onto the ontology's Location module) - geo_data is
    computed unconditionally for this template in export_report(), not
    gated behind a checkbox like Standard's opt-in version.

    Pagination note: _draw_pdf_header has no internal page-break guard, but
    it's always safe here as the very first section drawn right after the
    contents page's own showPage(). _draw_pdf_acquisition_method also has
    no internal guard and is NOT first, so it needs an explicit showPage()
    immediately before it - see _draw_pdf_acquisition_method's own
    docstring for why. Every other helper below already guards its own
    pagination internally."""
    from reportlab.lib.pagesizes import letter

    c = _numbered_canvas_class()(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "CASE/UCO CYBER-INVESTIGATION REPORT")

    branding = header.get('branding', {})
    title_bottom = 740
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        c.setFont("Helvetica", 10)
        c.drawString(50, 730, header_text[:120])
        title_bottom = 720
    logo_path = branding.get('logo_path') or ''
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            c.drawImage(ImageReader(logo_path), 470, 725, width=80, height=40, preserveAspectRatio=True, anchor='ne')
        except Exception:
            pass
    c.setLineWidth(1)
    c.line(50, title_bottom, 550, title_bottom)

    has_exhibits = bool(urls or files)
    entries = ["Investigation Overview", "Investigation Focus & Scope", "Executive Summary",
               "Observable Objects (Digital Evidence)", "Investigative Actions",
               "Analysis & Analytic Results (Case Notes)", "Relevant Findings",
               "Tools & Configured Tools", "Geolocation / Location Evidence", "Conclusion",
               "Limitations & Data Handling Markings", "Provenance Record / Chain of Custody"]
    if has_exhibits:
        entries.append("Exhibits (Evidence Provenance Records)")
    entries.append("Sign-off & Signatures")

    c.showPage()
    _draw_pdf_fixed_contents_page(c, entries)
    c.showPage()

    c.bookmarkPage('investigation_overview')
    c.addOutlineEntry("Investigation Overview", 'investigation_overview', level=0)
    y = _draw_pdf_header(c, header, title="Investigation Overview")

    c.bookmarkPage('focus_scope')
    c.addOutlineEntry("Investigation Focus & Scope", 'focus_scope', level=0)
    y = _draw_pdf_narrative_section(c, y, "Investigation Focus & Scope", header.get('objectives'))

    c.bookmarkPage('exec_summary')
    c.addOutlineEntry("Executive Summary", 'exec_summary', level=0)
    y = _draw_pdf_narrative_section(c, y, "Executive Summary", header.get('executive_summary'))

    c.bookmarkPage('observable_objects')
    c.addOutlineEntry("Observable Objects (Digital Evidence)", 'observable_objects', level=0)
    y = _draw_pdf_evidence_inventory(c, y, events, title="Observable Objects (Digital Evidence)")

    c.showPage()
    y = 750
    c.bookmarkPage('investigative_actions')
    c.addOutlineEntry("Investigative Actions", 'investigative_actions', level=0)
    y = _draw_pdf_acquisition_method(c, y, events, job_fields, title="Investigative Actions")

    c.bookmarkPage('analysis_findings')
    c.addOutlineEntry("Analysis & Analytic Results (Case Notes)", 'analysis_findings', level=0)
    y = _draw_pdf_case_notes(c, y, case_notes, title="Analysis & Analytic Results (Case Notes)", exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('relevant_findings')
    c.addOutlineEntry("Relevant Findings", 'relevant_findings', level=0)
    y = _draw_pdf_narrative_section(c, y, "Relevant Findings", header.get('findings_summary'))

    c.bookmarkPage('tools')
    c.addOutlineEntry("Tools & Configured Tools", 'tools', level=0)
    y = _draw_pdf_methodology_tools(c, y, events)

    c.bookmarkPage('geolocation')
    c.addOutlineEntry("Geolocation / Location Evidence", 'geolocation', level=0)
    y = _draw_pdf_geolocation_block(c, y, geo_data or [], title="Geolocation / Location Evidence")

    c.bookmarkPage('conclusion')
    c.addOutlineEntry("Conclusion", 'conclusion', level=0)
    y = _draw_pdf_narrative_section(c, y, "Conclusion", header.get('conclusion'))

    c.bookmarkPage('limitations')
    c.addOutlineEntry("Limitations & Data Handling Markings", 'limitations', level=0)
    y = _draw_pdf_narrative_section(c, y, "Limitations & Data Handling Markings", header.get('limitations'))

    c.bookmarkPage('provenance_coc')
    c.addOutlineEntry("Provenance Record / Chain of Custody", 'provenance_coc', level=0)
    y = _draw_pdf_audit_trail(c, y, audit_entries, title="Provenance Record / Chain of Custody")

    if has_exhibits:
        c.bookmarkPage('exhibits')
        c.addOutlineEntry("Exhibits (Evidence Provenance Records)", 'exhibits', level=0)
        y = _draw_pdf_attachments(c, y, urls, files, title="Exhibits (Evidence Provenance Records)", captions=captions,
                                   tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)

    c.bookmarkPage('signoff')
    c.addOutlineEntry("Sign-off & Signatures", 'signoff', level=0)
    y = _draw_pdf_signoff(c, y, header['examiner'])

    c.save()

def _embed_file_into_html(file_path, caption=None, exhibit_number=None, category=None, tags=None, analysis_summary=None):
    """HTML counterpart to _embed_file_into_pdf - shared by Exhibits (case
    attachments) and the Case Notes journal. caption is examiner-entered
    free text. exhibit_number/category/tags/analysis_summary are
    Exhibits-only enrichment - the Case Notes journal's own call never
    passes them, so they default to None and add nothing there. Every value
    is examiner/evidence-derived (filename, tag comment, analysis summary),
    so everything goes through html.escape() before interpolation, same
    discipline as every other untrusted string this app embeds into a
    report that might later be reopened in a browser."""
    esc = html.escape
    name = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    try:
        size = os.path.getsize(file_path)
    except OSError:
        size = 0

    heading = (f"Exhibit {exhibit_number}: " if exhibit_number else "") + esc(name) + (f" [{esc(category)}]" if category else "")
    caption_html = f'<p class="muted"><em>{esc(caption)}</em></p>' if caption else ''
    tags_html = ''
    if tags:
        tag_bits = [
            ('&#9733; ' if t.get('notable') else '') + esc(t['name']) + (f' &mdash; &quot;{esc(t["comment"])}&quot;' if t.get('comment') else '')
            for t in tags
        ]
        tags_html = f'<p class="muted"><strong>Tags:</strong> {"; ".join(tag_bits)}</p>'
    analysis_html = f'<p class="muted"><strong>Analysis:</strong> {esc(analysis_summary)}</p>' if analysis_summary else ''
    meta_html = caption_html + tags_html + analysis_html

    if ext in ATTACHMENT_IMAGE_EXT and size <= ATTACHMENT_MAX_IMAGE_EMBED_BYTES:
        mime = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
        }.get(ext, 'application/octet-stream')
        try:
            with open(file_path, 'rb') as imf:
                b64 = base64.b64encode(imf.read()).decode('ascii')
            return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<img src="data:{mime};base64,{b64}"></div>'
        except OSError as e:
            return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<p class="muted">Could not read image: {esc(str(e))}</p></div>'
    elif ext in ATTACHMENT_TEXT_EXT and size <= ATTACHMENT_MAX_TEXT_EMBED_BYTES:
        try:
            with open(file_path, 'r', errors='replace') as tf:
                text_content = tf.read(ATTACHMENT_MAX_TEXT_EMBED_BYTES)
        except OSError as e:
            text_content = f"(could not read file: {e})"
        return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<pre>{esc(text_content)}</pre></div>'
    else:
        size_note = f" ({size:,} bytes)" if size else ""
        return f'<div class="attach-item"><h3>{heading}</h3>{meta_html}<p class="muted mono">{esc(file_path)}{esc(size_note)}</p></div>'

def _html_timeline_table(case_notes, title="Incident Timeline", anchor_id=None):
    """HTML counterpart to _draw_pdf_timeline_table - same case_notes source,
    rendered as a table instead of the Standard template's journal style."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [
        f'<h2{id_attr}>{esc(title)}</h2>',
        '<p class="muted">Chronological entries from the examiner\'s case notes journal.</p>',
    ]
    if not case_notes:
        parts.append('<p class="muted">No timeline entries recorded.</p>')
        return ''.join(parts)
    parts.append('<table><tr><th>Timestamp</th><th>Category</th><th>Description</th></tr>')
    for note in sorted(case_notes, key=lambda n: n.get('timestamp', '')):
        parts.append(
            f'<tr><td>{esc(str(note.get("timestamp", "N/A")))}</td>'
            f'<td>{esc(str(note.get("category", "General")))}</td>'
            f'<td>{esc(str(note.get("text", "")))}</td></tr>'
        )
    parts.append('</table>')
    return ''.join(parts)

def _html_timeline_block(events, title="Filesystem Timeline (MACB)", anchor_id=None):
    """HTML counterpart to _draw_pdf_timeline_block - see
    _collect_case_timeline() for how these events are gathered (dedup/
    status-gating/per-image budget)."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    result = _collect_case_timeline(events)
    timeline_events = result["events"]

    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if not timeline_events:
        parts.append('<p class="muted">No filesystem timeline available for this case\'s evidence items.</p>')
    else:
        parts.append('<table><tr><th>Timestamp</th><th>Activity</th><th>Evidence ID</th><th>Path</th></tr>')
        for entry in timeline_events:
            parts.append(
                f'<tr><td>{esc(str(entry.get("timestamp", "N/A")))}</td>'
                f'<td>{esc(str(entry.get("activity", "")))}</td>'
                f'<td>{esc(str(entry.get("evidence_id", "N/A")))}</td>'
                f'<td class="mono">{esc(str(entry.get("path", "")))}</td></tr>'
            )
        parts.append('</table>')
        if result["truncated"]:
            parts.append('<p class="muted">Timeline truncated - not every timestamped filesystem event fit within the report\'s size limits.</p>')

    if result["notes"]:
        parts.append('<p class="muted"><strong>Notes:</strong></p><ul>')
        for note in result["notes"]:
            parts.append(f'<li class="muted">{esc(note)}</li>')
        parts.append('</ul>')

    return ''.join(parts)

_LEAFLET_CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'vendor', 'leaflet', 'leaflet.css')
_LEAFLET_JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'vendor', 'leaflet', 'leaflet.js')

def _html_leaflet_assets_block():
    """Inlines the vendored Leaflet library as literal <style>/<script>
    content - not a <link>/<script src> pointing at a server-relative path
    - so an exported HTML report stays genuinely self-contained and
    reopenable months later with this app's server long gone, matching
    every other embedded asset in this export (attachment images, the
    branding logo). Live OSM tile *imagery* still needs a real network
    connection at view time regardless - that part can't be vendored into a
    static file, the same already-accepted tradeoff the live in-app
    Leaflet viewer has. Only called when the Geolocation section is
    actually being rendered (see _build_html_report_standard), so every
    export that doesn't use it stays exactly as small as before this
    feature. Leaflet's own CSS references its default marker-icon PNGs via
    relative url(...) paths that won't resolve once inlined this way - not
    fixed here since _html_geolocation_block below only ever uses
    L.circleMarker pins, which never need those default icons."""
    try:
        with open(_LEAFLET_CSS_PATH, 'r', encoding='utf-8') as f:
            css = f.read()
        with open(_LEAFLET_JS_PATH, 'r', encoding='utf-8') as f:
            js = f.read()
    except OSError:
        return ''
    return f'<style>{css}</style><script>{js}</script>'

def _html_geolocation_block(kml_data, title="Geolocation / GPS Evidence", anchor_id=None):
    """HTML counterpart to _draw_pdf_geolocation_block - a real interactive
    Leaflet map (live OSM tiles only; no offline-cache fallback attempt,
    since this exported file may be reopened completely disconnected from
    this app's own server, where a /static/vendor/osm_tiles/... URL
    wouldn't resolve anyway) per KML file, followed by the same
    Name/Latitude/Longitude/Description placemark table PDF renders.
    Placemark name/description are untrusted KML content (an examiner can
    open ANY .kml, not just one this app generated) - the table cells go
    through html.escape() like every other field in this document, and the
    popup content is built via textContent (never innerHTML) in the inline
    script below, matching this app's existing untrusted-content discipline
    for the live Leaflet viewer (escapeHtmlForPopup() in main.js)."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']

    if not kml_data:
        parts.append('<p class="muted">No geolocation (KML) evidence with GPS placemarks found for this case.</p>')
        return ''.join(parts)

    for i, entry in enumerate(kml_data):
        map_id = f'geomap_{i}'
        parts.append('<div class="job">')
        parts.append(f'<h3>{esc(entry["name"])}</h3>')
        parts.append(f'<div class="muted mono">{esc(entry["path"])}</div>')
        parts.append(f'<div id="{esc(map_id)}" style="height:340px;width:100%;margin:.6em 0;border:1px solid #ccc;border-radius:6px;"></div>')

        parts.append('<table><tr><th>Name</th><th>Latitude</th><th>Longitude</th><th>Description</th></tr>')
        for p in entry['placemarks']:
            parts.append(
                f'<tr><td>{esc(p["name"] or "(unnamed)")}</td>'
                f'<td class="mono">{p["lat"]:.6f}</td><td class="mono">{p["lon"]:.6f}</td>'
                f'<td>{esc(p["description"])}</td></tr>'
            )
        parts.append('</table>')

        # Placemark data is passed to the browser as a JSON literal, not raw
        # JS interpolation - untrusted name/description text could otherwise
        # contain a literal </script> sequence that would prematurely close
        # this tag, so every '</' is escaped to '<\/' (a standard, safe fix
        # for embedding arbitrary JSON inside an inline <script> block).
        points = [{"lat": p["lat"], "lon": p["lon"], "name": p["name"], "description": p["description"]} for p in entry['placemarks']]
        points_json = json.dumps(points).replace('</', '<\\/')
        parts.append(
            '<script>(function(){'
            f'var pts={points_json};'
            f'var mapDiv=document.getElementById("{map_id}");'
            'if(!mapDiv||typeof L==="undefined"||!pts.length)return;'
            'var map=L.map(mapDiv);'
            'L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",'
            '{attribution:"&copy; OpenStreetMap contributors",maxZoom:19}).addTo(map);'
            'var bounds=[];'
            'pts.forEach(function(p){'
            'var m=L.circleMarker([p.lat,p.lon],{radius:7,color:"#c0392b",weight:2,fillColor:"#e74c3c",fillOpacity:0.9}).addTo(map);'
            'var div=document.createElement("div");'
            'var b=document.createElement("b");b.textContent=p.name||"(unnamed)";div.appendChild(b);'
            'div.appendChild(document.createElement("br"));'
            'var span=document.createElement("span");span.textContent=p.description||"";div.appendChild(span);'
            'm.bindPopup(div);'
            'bounds.push([p.lat,p.lon]);'
            '});'
            'if(bounds.length===1){map.setView(bounds[0],14);}else{map.fitBounds(bounds,{padding:[20,20]});}'
            'setTimeout(function(){map.invalidateSize();},50);'
            '})();</script>'
        )
        parts.append('</div>')
    return ''.join(parts)

def _html_methodology_tools(events, anchor_id=None):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    tools = sorted({str(e.get('tool')).upper() for e in events if e.get('tool')})
    tools_str = ', '.join(tools) if tools else 'No acquisition/recovery tool recorded.'
    return (
        f'<h2{id_attr}>Forensic Methodology &amp; Tools</h2>'
        f'<p>{esc(_METHODOLOGY_STATIC_TEXT)}</p>'
        f'<p><strong>Tools Used in This Case:</strong> {esc(tools_str)}</p>'
    )

def _html_signoff(examiner, anchor_id=None):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    return (
        f'<h2{id_attr}>Sign-off &amp; Signatures</h2>'
        f'<p>{esc(_SIGNOFF_STATIC_TEXT)}</p>'
        f'<p>Examiner: {esc(str(examiner))}</p>'
        '<div style="display:flex;gap:60px;margin-top:2em;max-width:600px;">'
        '<div style="flex:1;border-top:1px solid #333;padding-top:4px;">Signature</div>'
        '<div style="flex:1;border-top:1px solid #333;padding-top:4px;">Date</div>'
        '</div>'
    )

def _html_narrative_block(title, text, anchor_id=None):
    esc = html.escape
    text = (text or '').strip()
    body = f'<span style="white-space:pre-wrap;">{esc(text)}</span>' if text else '<span class="muted">(Not provided)</span>'
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    return f'<h2{id_attr}>{esc(title)}</h2><p>{body}</p>'

def _build_html_toc(resolved_sections, has_exhibits):
    """Mirrors the PDF's Report Contents page - a plain section list, but as
    real anchor links since HTML doesn't have the PDF's single-pass-render
    page-number problem to work around. resolved_sections is the same
    already-filtered/ordered list the draw loop below consumes (see
    _resolve_section_order) - the one condition not modeled there, since
    it's a property of this specific export's data rather than a fixed
    property of the block itself, is 'attachments': skipped here (and in
    the draw loop) when there's nothing to attach, matching this section's
    pre-existing behavior."""
    esc = html.escape
    entries = []
    for entry in resolved_sections:
        if entry["key"] == "attachments" and not has_exhibits:
            continue
        anchor = "sec-" + entry["key"].replace("_", "-")
        entries.append((anchor, esc(entry["title"])))

    if not entries:
        return ''
    items = ''.join(f'<li><a href="#{anchor}">{label}</a></li>' for anchor, label in entries)
    return f'<nav class="toc"><h2>Report Contents</h2><ol>{items}</ol></nav>'

def _html_evidence_inventory_table(events, title="Evidence Inventory", anchor_id=None):
    """HTML counterpart to _draw_pdf_evidence_inventory - shared by all
    three templates. The Police template reuses this under a different
    title ("Itemized Evidence & Integrity Hashing")."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2><table>']
    parts.append('<tr><th>Evidence ID</th><th>Device</th><th>Model</th><th>Serial</th><th>Capacity</th><th>Acquisition Hash</th></tr>')
    for event in events:
        meta = event.get('case_metadata', {})
        drive = event.get('source_drive_telemetry', {})
        hash_display = _pick_display_hash(event.get('computed_verification_hashes', {}))
        parts.append(
            f'<tr><td>{esc(str(meta.get("evidence_id", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("device_path", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("vendor_model", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("serial_number", "N/A")))}</td>'
            f'<td>{esc(str(drive.get("capacity_gb", "N/A")))} GB</td>'
            f'<td class="mono">{esc(str(hash_display))}</td></tr>'
        )
    parts.append('</table>')
    return ''.join(parts)

def _html_exhibits_block(urls, files, anchor_id=None, title="Exhibits", captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _draw_pdf_attachments - shared by all three
    templates' Exhibits section. Caller already checks whether there's
    anything to show (urls or files) before calling this."""
    captions = captions or {}
    tags_by_path = tags_by_path or {}
    analysis_by_path = analysis_by_path or {}
    # Looked up against the case's FULL attachments.files list, not
    # enumerated from `files` (a possibly-filtered per-export subset) - see
    # the matching comment in _draw_pdf_attachments.
    exhibit_numbers = exhibit_numbers or {}
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if urls:
        parts.append('<p><strong>Reference Links / URLs:</strong></p><ul>')
        for url in urls:
            parts.append(f'<li><a href="{esc(str(url))}">{esc(str(url))}</a></li>')
        parts.append('</ul>')
    if files:
        parts.append('<p class="muted"><em>Exhibit numbers reflect this case\'s current attachment order.</em></p>')
    for raw_path in files:
        file_path = safe_path(raw_path)
        if not file_path or not os.path.exists(file_path):
            continue
        category, _ext = classify_extension(os.path.basename(file_path))
        parts.append(_embed_file_into_html(
            file_path, caption=captions.get(raw_path), exhibit_number=exhibit_numbers.get(raw_path), category=category,
            tags=tags_by_path.get(raw_path), analysis_summary=_format_analysis_summary(analysis_by_path.get(raw_path))))
    return ''.join(parts)

def _html_audit_trail_block(audit_entries, anchor_id=None, title="Case Activity Log (Audit Trail)"):
    """HTML counterpart to _draw_pdf_audit_trail - shared by all three
    templates. The Police template reuses this under a different title
    ("Chain of Custody / Activity Log") since this app's audit trail is the
    closest real substitute it has for that section, not a literal personnel
    custody-transfer log - see _build_pdf_report_police's own comment."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if audit_entries:
        parts.append('<table><tr><th>Timestamp</th><th>Action</th><th>Details</th></tr>')
        for entry in audit_entries:
            details_str = ', '.join(f'{k}={v}' for k, v in (entry.get('details') or {}).items())
            parts.append(f'<tr><td>{esc(str(entry.get("timestamp", "")))}</td><td>{esc(str(entry.get("action", "")))}</td><td>{esc(details_str)}</td></tr>')
        parts.append('</table>')
    else:
        parts.append('<p class="muted">No activity log entries found for this case.</p>')
    return ''.join(parts)

def _html_custody_log_block(custody_log, anchor_id=None, title="Physical Evidence Custody Log"):
    """HTML counterpart to _draw_pdf_custody_log_block - see that function
    for the from/to-custodian, append-only physical-handoff shape this
    renders (distinct from the software Audit Trail above)."""
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    if custody_log:
        parts.append('<table><tr><th>Timestamp</th><th>From</th><th>To</th><th>Reason</th><th>Method</th><th>Notes</th><th>Logged By</th></tr>')
        for entry in custody_log:
            parts.append(
                '<tr><td>' + esc(str(entry.get('timestamp', ''))) + '</td>'
                '<td>' + esc(str(entry.get('from_custodian', ''))) + '</td>'
                '<td>' + esc(str(entry.get('to_custodian', ''))) + '</td>'
                '<td>' + esc(str(entry.get('reason', ''))) + '</td>'
                '<td>' + esc(str(entry.get('method', ''))) + '</td>'
                '<td>' + esc(str(entry.get('notes', ''))) + '</td>'
                '<td>' + esc(str(entry.get('logged_by', ''))) + '</td></tr>'
            )
        parts.append('</table>')
    else:
        parts.append('<p class="muted">No custody log entries recorded for this case.</p>')
    return ''.join(parts)

def _html_report_style_block():
    """Shared CSS for all three report-template HTML builders below - one
    definition, so restyling the report format doesn't mean editing it in
    three places."""
    return (
        '<style>'
        'body{font-family:Arial,Helvetica,sans-serif;color:#111;max-width:900px;margin:2em auto;padding:0 1em;}'
        'h1{font-size:1.4em;border-bottom:2px solid #333;padding-bottom:.3em;}'
        'h2{font-size:1.15em;margin-top:1.6em;border-bottom:1px solid #999;padding-bottom:.2em;}'
        'h3{font-size:1em;margin:.8em 0 .3em;}'
        'table{border-collapse:collapse;width:100%;margin:.4em 0;}'
        'td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:.9em;vertical-align:top;}'
        '.job{margin-top:1.2em;padding:.8em;border:1px solid #ccc;border-radius:6px;}'
        '.muted{color:#666;font-size:.85em;}'
        '.mono{font-family:"Courier New",monospace;}'
        '.attach-item{margin-top:1em;padding:.7em;border:1px solid #ddd;border-radius:6px;}'
        '.attach-item img{max-width:100%;border:1px solid #ccc;display:block;margin-top:.4em;}'
        '.attach-item pre{background:#f5f5f5;padding:.6em;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.8em;margin-top:.4em;}'
        '.branding-header{display:flex;justify-content:space-between;align-items:flex-start;gap:1em;border-bottom:2px solid #333;padding-bottom:.3em;}'
        '.branding-header h1{border-bottom:none;padding-bottom:0;margin:0;}'
        '.branding-header img{max-height:50px;max-width:160px;}'
        '.branding-subtitle{color:#444;font-size:.9em;margin:.2em 0 1em;}'
        '.toc{background:#f7f7f7;border:1px solid #ddd;border-radius:6px;padding:.8em 1.2em;margin:1em 0;}'
        '.toc h2{margin-top:0;font-size:1em;border-bottom:none;padding-bottom:0;}'
        '.toc ol{margin:.3em 0 0;padding-left:1.4em;}'
        '.toc li{margin:.25em 0;}'
        '.toc a{color:#1a4d8f;text-decoration:none;}'
        '.toc a:hover{text-decoration:underline;}'
        '</style>'
    )

def _html_report_branding_header(header, title):
    """Renders the branding-header block (fixed template title + station's
    optional added subtitle/logo from Settings > Case & Reporting) - shared
    by all three HTML builders, only the title text differs per template."""
    esc = html.escape
    branding = header.get('branding', {})
    logo_path = branding.get('logo_path') or ''
    logo_html = ''
    if logo_path and os.path.exists(logo_path):
        ext = os.path.splitext(logo_path)[1].lower()
        mime = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
        }.get(ext, 'application/octet-stream')
        try:
            with open(logo_path, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode('ascii')
            logo_html = f'<img src="data:{mime};base64,{logo_b64}" alt="station logo">'
        except OSError:
            logo_html = ''
    parts = [f'<div class="branding-header"><h1>{esc(title)}</h1>{logo_html}</div>']
    header_text = (branding.get('header_text') or '').strip()
    if header_text:
        parts.append(f'<div class="branding-subtitle">{esc(header_text)}</div>')
    return ''.join(parts)

def _html_case_info_block(header, event_count, anchor_id=None, title="Case Information"):
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2><table>']
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Status</th><td>{esc(str(header.get("case_status", "Open")))}</td><th>Evidence Items</th><td>{event_count}</td></tr>')
    parts.append(f'<tr><th>Created</th><td colspan="3">{esc(str(header["created_at"]))}</td></tr>')
    parts.append(f'<tr><th>Notes</th><td colspan="3">{esc(str(header["notes"] or "None"))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')
    return ''.join(parts)

def _html_acquisition_method(events, job_fields, anchor_id=None):
    """HTML counterpart to _draw_pdf_acquisition_method - no title param,
    since (matching the PDF side) there's no single on-page heading for
    this block, only per-event headings; the anchor lands on the first
    event's div."""
    esc = html.escape
    parts = []
    for i, event in enumerate(events):
        meta = event.get('case_metadata', {})
        anchor_attr = f' id="{esc(anchor_id)}"' if (i == 0 and anchor_id) else ''
        parts.append(f'<div class="job"{anchor_attr}>')
        parts.append(f'<h2>Evidence Item: {esc(str(meta.get("evidence_id", "N/A")))} ({esc(str(event.get("tool", "N/A")))})</h2>')
        parts.append(f'<div class="muted">Date: {esc(str(event.get("timestamp_start", "N/A")))} &middot; Status: {esc(str(event.get("acquisition_status", "N/A")))}</div>')

        if job_fields.get('telemetry', True):
            drive = event.get('source_drive_telemetry', {})
            parts.append('<h3>Source Media Telemetry</h3><table>')
            parts.append(f'<tr><th>Device</th><td>{esc(str(drive.get("device_path")))}</td><th>Capacity</th><td>{esc(str(drive.get("capacity_gb")))} GB</td></tr>')
            parts.append(f'<tr><th>Model</th><td>{esc(str(drive.get("vendor_model")))}</td><th>Serial</th><td>{esc(str(drive.get("serial_number")))}</td></tr>')
            parts.append(f'<tr><th>SMART Status</th><td colspan="3">{"PASSED" if drive.get("smart_healthy") else "FAILING"}</td></tr>')
            parts.append('</table>')

        if job_fields.get('params', True):
            params = event.get('acquisition_parameters', {})
            parts.append('<h3>Acquisition Parameters</h3><table>')
            parts.append(f'<tr><th>Format</th><td>{esc(str(params.get("output_format", event.get("tool", "N/A"))).upper())}</td><th>Status</th><td>{esc(str(event.get("acquisition_status")))}</td></tr>')
            if params.get('bitlocker_key'):
                parts.append(f'<tr><th>BitLocker Recovery Key/Password</th><td class="mono" colspan="3">{esc(str(params["bitlocker_key"]))}</td></tr>')
            parts.append('</table>')

        if job_fields.get('hashes', True):
            hashes = event.get('computed_verification_hashes', {})
            parts.append('<h3>Verification Hashes</h3><table>')
            if hashes:
                for k, v in hashes.items():
                    parts.append(f'<tr><th>{esc(k.upper())}</th><td class="mono">{esc(str(v))}</td></tr>')
            else:
                parts.append('<tr><td colspan="2" class="muted">No hashes recorded.</td></tr>')
            parts.append('</table>')

        parts.append('</div>')
    return ''.join(parts)

def _html_case_notes_block(case_notes, anchor_id=None, title="Forensic Analysis / Steps Taken (Case Notes)", exhibit_numbers=None):
    exhibit_numbers = exhibit_numbers or {}
    esc = html.escape
    id_attr = f' id="{esc(anchor_id)}"' if anchor_id else ''
    parts = [f'<h2{id_attr}>{esc(title)}</h2>']
    parts.append('<p class="muted">Chronological case notes, each with a local SHA-256 integrity hash (tamper-evidence only, not a legal timestamp authority).</p>')
    if not case_notes:
        parts.append('<p class="muted">No case notes recorded.</p>')
    for note in case_notes:
        parts.append('<div class="job">')
        author = esc(str(note.get('author') or 'unknown'))
        parts.append(f'<h3>[{esc(str(note.get("category", "General")))}] {esc(str(note.get("timestamp", "")))} &mdash; {author}</h3>')
        if note.get('edited_at'):
            parts.append(f'<div class="muted">(edited {esc(str(note["edited_at"]))})</div>')
        parts.append(f'<p style="white-space:pre-wrap;">{esc(str(note.get("text", "")))}</p>')
        linked = [p for p in (note.get('linked_files') or []) if p in exhibit_numbers]
        if linked:
            link_bits = [f'Exhibit {exhibit_numbers[p]} &mdash; {esc(os.path.basename(p))}' for p in linked]
            parts.append(f'<p class="muted"><strong>Linked Exhibit(s):</strong> {"; ".join(link_bits)}</p>')
        for att in note.get('attachments', []):
            file_path = safe_path(att.get('path', ''))
            if file_path and os.path.exists(file_path):
                parts.append(_embed_file_into_html(file_path))
        parts.append('</div>')
    return ''.join(parts)

def _build_html_report_standard(header, events, urls, files, audit_entries, case_notes, resolved_sections, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None, custody_log=None):
    """Self-contained HTML report - every value is escaped since it may
    contain examiner-entered text or evidence-derived strings (filenames,
    device paths) that this file could later be reopened/served from disk.
    resolved_sections (see _resolve_section_order) is the already-filtered,
    already-ordered {key, title} list this registry-driven loop dispatches
    over - shared with the PDF builder's own version of this same loop."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    # The vendored Leaflet library is only inlined into <head> when the
    # Geolocation section is both selected AND actually has real placemark
    # data to render - every export that doesn't use it stays exactly as
    # small as before this feature (see _html_leaflet_assets_block).
    needs_leaflet = bool(geo_data) and any(e["key"] == "geolocation" for e in resolved_sections)
    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>Case Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        _html_leaflet_assets_block() if needs_leaflet else '',
        '</head><body>',
        _html_report_branding_header(header, "Pi Forensics Suite Acquisition Audit Report"),
    ]

    parts.append(_build_html_toc(resolved_sections, has_exhibits))

    # See the PDF builder's own dispatch dict for why every lambda takes a
    # uniform (anchor, title, field) signature even when it ignores `field`.
    dispatch = {
        "case_info": lambda anchor, title, field: _html_case_info_block(header, len(events), anchor_id=anchor, title=title),
        "executive_summary": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "objectives": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "evidence_inventory": lambda anchor, title, field: _html_evidence_inventory_table(events, title=title, anchor_id=anchor),
        "acquisition_method": lambda anchor, title, field: _html_acquisition_method(events, job_fields, anchor_id=anchor),
        "forensic_analysis": lambda anchor, title, field: _html_case_notes_block(case_notes, anchor_id=anchor, title=title, exhibit_numbers=exhibit_numbers),
        "relevant_findings": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "limitations": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "conclusion": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "iocs": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "recommendations": lambda anchor, title, field: _html_narrative_block(title, header.get(field), anchor),
        "attachments": lambda anchor, title, field: _html_exhibits_block(urls, files, anchor_id=anchor, title=title, captions=captions,
                                                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path,
                                                                           exhibit_numbers=exhibit_numbers),
        "audit_trail": lambda anchor, title, field: _html_audit_trail_block(audit_entries, anchor_id=anchor, title=title),
        "timeline": lambda anchor, title, field: _html_timeline_block(events, title=title, anchor_id=anchor),
        "geolocation": lambda anchor, title, field: _html_geolocation_block(geo_data or [], title=title, anchor_id=anchor),
        "custody_log": lambda anchor, title, field: _html_custody_log_block(custody_log or [], anchor_id=anchor, title=title),
    }

    for entry in resolved_sections:
        key, title = entry["key"], entry["title"]
        if key == "attachments" and not has_exhibits:
            continue
        anchor = "sec-" + key.replace("_", "-")
        parts.append(dispatch[key](anchor, title, entry.get("source_field")))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_dfir(header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _build_pdf_report_dfir - same fixed section list,
    same reused data sources, see that function's docstring."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-case-info', 'Case Information'), ('sec-exec-summary', 'Executive Summary'),
        ('sec-overview-scope', 'Incident Overview &amp; Scope'), ('sec-timeline', 'Incident Timeline'),
        ('sec-technical-analysis', 'Technical Analysis &amp; Forensic Findings'),
        ('sec-iocs', 'Indicators of Compromise'),
        ('sec-containment', 'Containment, Eradication &amp; Next Steps'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits'))
    toc_entries.append(('sec-audit-trail', 'Audit Trail'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>DFIR Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        '</head><body>',
        _html_report_branding_header(header, "Digital Forensics and Incident Response Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append('<h2 id="sec-case-info">Case Information</h2><table>')
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Status</th><td colspan="3">{esc(str(header.get("case_status", "Open")))}</td></tr>')
    parts.append(f'<tr><th>Created</th><td colspan="3">{esc(str(header["created_at"]))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')

    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_narrative_block('Incident Overview & Scope', header.get('objectives'), 'sec-overview-scope'))
    parts.append(_html_timeline_table(case_notes, title="Incident Timeline", anchor_id='sec-timeline'))
    parts.append(_html_narrative_block('Technical Analysis & Forensic Findings', header.get('findings_summary'), 'sec-technical-analysis'))
    parts.append(_html_narrative_block('Indicators of Compromise', header.get('iocs'), 'sec-iocs'))
    parts.append(_html_narrative_block('Containment, Eradication & Next Steps', header.get('recommendations_next_steps'), 'sec-containment'))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append(_html_audit_trail_block(audit_entries, anchor_id='sec-audit-trail'))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_police(header, events, urls, files, audit_entries, case_notes, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None):
    """HTML counterpart to _build_pdf_report_police - same fixed section
    list, same reused data sources, same disclosed Chain-of-Custody-vs-
    Audit-Trail caveat, see that function's docstring."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-admin-info', 'Administrative Information'), ('sec-exec-summary', 'Executive Summary'),
        ('sec-background-scope', 'Case Background &amp; Scope'),
        ('sec-evidence-coc', 'Evidence Collection &amp; Chain of Custody'),
        ('sec-methodology', 'Forensic Methodology &amp; Tools'),
        ('sec-findings', 'Detailed Findings &amp; Analysis'),
        ('sec-conclusion', 'Conclusion &amp; Summary'),
        ('sec-signoff', 'Sign-off &amp; Signatures'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits &amp; Appendices'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>Police Forensics Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        '</head><body>',
        _html_report_branding_header(header, "Police Forensics Investigation Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append('<h2 id="sec-admin-info">Administrative Information</h2><table>')
    parts.append(f'<tr><th>Case Number</th><td>{esc(str(header["case_number"]))}</td><th>Examiner</th><td>{esc(str(header["examiner"]))}</td></tr>')
    parts.append(f'<tr><th>Status</th><td colspan="3">{esc(str(header.get("case_status", "Open")))}</td></tr>')
    parts.append(f'<tr><th>Created</th><td colspan="3">{esc(str(header["created_at"]))}</td></tr>')
    for field in header.get('custom_fields', []):
        parts.append(f'<tr><th>{esc(str(field["label"]))}</th><td colspan="3">{esc(str(field["value"]))}</td></tr>')
    parts.append('</table>')

    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_narrative_block('Case Background & Scope', header.get('objectives'), 'sec-background-scope'))

    parts.append(f'<h2 id="sec-evidence-coc">Evidence Collection &amp; Chain of Custody</h2>')
    if events:
        parts.append(_html_evidence_inventory_table(events, title="Itemized Evidence & Integrity Hashing"))
    parts.append(_html_audit_trail_block(audit_entries, title="Chain of Custody / Activity Log"))

    parts.append(_html_methodology_tools(events, anchor_id='sec-methodology'))

    parts.append(f'<h2 id="sec-findings">Detailed Findings &amp; Analysis</h2>')
    parts.append(_html_timeline_table(case_notes, title="Chronological Timeline of Events"))
    parts.append(_html_narrative_block('Artifact Analysis', header.get('findings_summary')))

    parts.append(f'<h2 id="sec-conclusion">Conclusion &amp; Summary</h2>')
    parts.append(_html_narrative_block('Conclusion', header.get('conclusion')))
    parts.append(_html_narrative_block('Recommendations', header.get('recommendations_next_steps')))

    parts.append(_html_signoff(header['examiner'], anchor_id='sec-signoff'))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append('</body></html>')
    return ''.join(parts)

def _build_html_report_caseuco(header, events, urls, files, audit_entries, case_notes, job_fields, captions=None, tags_by_path=None, analysis_by_path=None, exhibit_numbers=None, geo_data=None):
    """HTML counterpart to _build_pdf_report_caseuco - same fixed section
    list, same reused data sources, same disclosed role/provenance
    simplifications, see that function's docstring.

    Deliberate departure from DFIR/Police's HTML builders: reuses
    _html_case_info_block() wholesale for "Investigation Overview" instead
    of hand-inlining a stripped-down case-info table like they do - this
    template's Investigation Overview benefits from that helper's existing
    Notes row (investigation description) and Evidence Items count, and
    reusing it outright is less code than a third hand-inlined copy of the
    same loop."""
    esc = html.escape
    has_exhibits = bool(urls or files)
    toc_entries = [
        ('sec-investigation-overview', 'Investigation Overview'),
        ('sec-focus-scope', 'Investigation Focus &amp; Scope'),
        ('sec-exec-summary', 'Executive Summary'),
        ('sec-observable-objects', 'Observable Objects (Digital Evidence)'),
        ('sec-investigative-actions', 'Investigative Actions'),
        ('sec-analysis-findings', 'Analysis &amp; Analytic Results (Case Notes)'),
        ('sec-relevant-findings', 'Relevant Findings'),
        ('sec-tools', 'Tools &amp; Configured Tools'),
        ('sec-geolocation', 'Geolocation / Location Evidence'),
        ('sec-conclusion', 'Conclusion'),
        ('sec-limitations', 'Limitations &amp; Data Handling Markings'),
        ('sec-provenance-coc', 'Provenance Record / Chain of Custody'),
    ]
    if has_exhibits:
        toc_entries.append(('sec-exhibits', 'Exhibits (Evidence Provenance Records)'))
    toc_entries.append(('sec-signoff', 'Sign-off &amp; Signatures'))
    toc_items = ''.join(f'<li><a href="#{esc(a)}">{t}</a></li>' for a, t in toc_entries)

    # Only inlined when this export actually has real placemark data to
    # render - every export that doesn't use it stays exactly as small as
    # before, matching _build_html_report_standard's own condition.
    needs_leaflet = bool(geo_data)

    parts = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f'<title>CASE/UCO Report - {esc(str(header["case_number"]))}</title>',
        _html_report_style_block(),
        _html_leaflet_assets_block() if needs_leaflet else '',
        '</head><body>',
        _html_report_branding_header(header, "CASE/UCO Cyber-Investigation Report"),
        f'<nav class="toc"><h2>Report Contents</h2><ol>{toc_items}</ol></nav>',
    ]

    parts.append(_html_case_info_block(header, len(events), anchor_id='sec-investigation-overview', title="Investigation Overview"))
    parts.append(_html_narrative_block('Investigation Focus & Scope', header.get('objectives'), 'sec-focus-scope'))
    parts.append(_html_narrative_block('Executive Summary', header.get('executive_summary'), 'sec-exec-summary'))
    parts.append(_html_evidence_inventory_table(events, title="Observable Objects (Digital Evidence)", anchor_id='sec-observable-objects'))
    parts.append(f'<h2 id="sec-investigative-actions">Investigative Actions</h2>')
    parts.append(_html_acquisition_method(events, job_fields))
    parts.append(_html_case_notes_block(case_notes, anchor_id='sec-analysis-findings', title="Analysis & Analytic Results (Case Notes)", exhibit_numbers=exhibit_numbers))
    parts.append(_html_narrative_block('Relevant Findings', header.get('findings_summary'), 'sec-relevant-findings'))
    parts.append(_html_methodology_tools(events, anchor_id='sec-tools'))
    parts.append(_html_geolocation_block(geo_data or [], title="Geolocation / Location Evidence", anchor_id='sec-geolocation'))
    parts.append(_html_narrative_block('Conclusion', header.get('conclusion'), 'sec-conclusion'))
    parts.append(_html_narrative_block('Limitations & Data Handling Markings', header.get('limitations'), 'sec-limitations'))
    parts.append(_html_audit_trail_block(audit_entries, anchor_id='sec-provenance-coc', title="Provenance Record / Chain of Custody"))

    if has_exhibits:
        parts.append(_html_exhibits_block(urls, files, anchor_id='sec-exhibits', title="Exhibits (Evidence Provenance Records)", captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers))

    parts.append(_html_signoff(header['examiner'], anchor_id='sec-signoff'))

    parts.append('</body></html>')
    return ''.join(parts)

@reporting_bp.route('/api/export_report', methods=['POST'])
@requires_auth
@requires_permission('reporting')
def export_report():
    req = request.get_json() or {}
    report_file = safe_path(req.get('report_path'))
    if not report_file or not os.path.exists(report_file):
        return jsonify({"error": "Report file not found or outside the permitted evidence directory."}), 404

    fmt = req.get('format', 'pdf')
    if fmt not in ('pdf', 'html'):
        return jsonify({"error": "format must be 'pdf' or 'html'."}), 400

    cfg = load_runtime_config()
    report_defaults = cfg.get('report_defaults', {})
    requested_event_ids = req.get('event_ids')
    attachment_selection = req.get('attachment_selection')

    # Falls back to the station's configured default template the same way
    # sections/job_fields below fall back to their own station defaults. A
    # custom:<id> reference that doesn't resolve is a hard error (400), not
    # a silent substitution - re-rendering a report under a materially
    # different structure than what was explicitly requested is exactly the
    # kind of surprise this app avoids elsewhere (case-folder collisions are
    # a 409, never an auto-rename).
    template_value = req.get('template') or report_defaults.get('template') or 'standard'
    try:
        template, custom_record = _resolve_template_ref(template_value, cfg)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # sections/job_fields (the Export modal's checkboxes / station defaults)
    # only ever apply to the 'standard' template - reading them regardless
    # of which template is selected let stale, CSS-hidden-but-still-checked
    # checkbox state leak into a custom-template export. DFIR/Police never
    # used these at all; 'custom' sources its own section list/job_fields
    # exclusively from the saved template record instead.
    if template == 'standard':
        sections = req.get('sections') or report_defaults.get('sections') or {}
        job_fields = req.get('job_fields') or report_defaults.get('job_fields') or {}
    elif template == 'custom':
        sections = None
        job_fields = custom_record.get('job_fields') or {}
    else:
        sections = None
        job_fields = {}

    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Could not read report: {e}"}), 500

    # Custom-field *definitions* are station-wide; a case's custom-field
    # *values* live on the case record itself (top-level for consolidated,
    # nested under case_metadata for legacy - same split every other
    # per-case field already uses). Join the two here into simple
    # label/value pairs so the drawing functions don't need to know
    # anything about where definitions are stored - empty values are
    # skipped rather than rendered blank.
    field_defs = get_custom_case_fields()

    def _custom_field_pairs(values_dict):
        values_dict = values_dict or {}
        return [
            {"label": f["label"], "value": values_dict[f["key"]]}
            for f in field_defs
            if values_dict.get(f["key"])
        ]

    # A consolidated case file (has "events") exposes a case-level header +
    # a filterable list of job events; a legacy single-job report (no
    # "events" key - either never migrated, or a genuine no-case ad-hoc job)
    # is always treated as its own single, always-included event.
    if isinstance(data.get('events'), list):
        all_events = data['events']
        if requested_event_ids:
            events = [e for e in all_events if e.get('event_id') in requested_event_ids]
        else:
            events = all_events
        header = {
            "case_number": data.get('case_number', 'N/A'),
            "examiner": data.get('examiner', 'N/A'),
            "notes": data.get('notes', ''),
            "case_status": data.get('case_status') or 'Open',
            "created_at": data.get('created_at', 'N/A'),
            "custom_fields": _custom_field_pairs(data.get('custom_fields')),
            "executive_summary": data.get('executive_summary', ''),
            "objectives": data.get('objectives', ''),
            "findings_summary": data.get('findings_summary', ''),
            "limitations": data.get('limitations', ''),
            "conclusion": data.get('conclusion', ''),
            "iocs": data.get('iocs', ''),
            "recommendations_next_steps": data.get('recommendations_next_steps', ''),
        }
        attachments = data.get('attachments', {})
    else:
        events = [data]
        meta = data.get('case_metadata', {})
        header = {
            "case_number": meta.get('case_number', 'N/A'),
            "examiner": meta.get('examiner', 'N/A'),
            "notes": meta.get('notes', ''),
            "case_status": meta.get('case_status') or 'Open',
            "created_at": data.get('timestamp_start', 'N/A'),
            "custom_fields": _custom_field_pairs(meta.get('custom_fields')),
            "executive_summary": meta.get('executive_summary', ''),
            "objectives": meta.get('objectives', ''),
            "findings_summary": meta.get('findings_summary', ''),
            "limitations": meta.get('limitations', ''),
            "conclusion": meta.get('conclusion', ''),
            "iocs": meta.get('iocs', ''),
            "recommendations_next_steps": meta.get('recommendations_next_steps', ''),
        }
        attachments = data.get('attachments', {})

    # case_notes is top-level in both schemas (same precedent as
    # attachments) - not nested under case_metadata for the legacy branch.
    case_notes = data.get('case_notes', [])
    # custody_log is top-level in both schemas too, same precedent as
    # case_notes/attachments - a case written before this feature existed
    # simply has no key, so this must always fall back to [].
    custody_log = data.get('custody_log', [])

    # Examiner-entered per-attachment captions, keyed by the same path string
    # used in attachments['files'] - looked up at render time regardless of
    # whether a file came from the full explicit list or a per-export
    # checked subset (attachment_selection.files below), since it's a
    # superset lookup table either way.
    captions = attachments.get('file_captions', {})

    header["branding"] = report_defaults.get('branding', {})

    # attachment_selection lets the export modal pick a subset of
    # explicitly-attached files/URLs plus any extra files discovered in the
    # case folder (via /api/cases/discover_files) that weren't necessarily
    # added through the "Add File Attachment" flow. If the caller doesn't
    # supply one, fall back to everything in the report's own attachments
    # dict (today's behavior, and the sane default for non-UI callers).
    if attachment_selection is not None:
        sel_urls = attachment_selection.get('urls') or []
        sel_files = attachment_selection.get('files') or []
    else:
        sel_urls = attachments.get('reference_urls', [])
        sel_files = attachments.get('files', [])
        if not sel_files and attachments.get('image_path'):
            sel_files = [attachments.get('image_path')]

    # DFIR/Police always include an Audit Trail section (part of their
    # fixed structure); for 'standard'/'custom', consult the same resolved
    # block list the draw loop itself will use, so this can never drift
    # from what the export actually renders.
    resolved_sections = None
    if template in ('standard', 'custom'):
        mode = 'legacy' if template == 'standard' else 'custom'
        resolved_sections = _resolve_section_order(mode, sections, custom_record, len(events))
        needs_audit_trail = any(e['key'] == 'audit_trail' for e in resolved_sections)
    else:
        needs_audit_trail = True

    audit_entries = []
    if needs_audit_trail and header['case_number'] not in (None, '', 'N/A'):
        audit_entries = _case_history_entries(header['case_number'], limit=500)

    # Unified evidence-item enrichment - tags and persisted analysis results
    # for whichever files this particular export actually includes
    # (sel_files), plus exhibit numbers derived from the case's FULL
    # attachments list (not sel_files) so a number stays stable regardless
    # of which subset any one export selects - see the matching comment on
    # _draw_pdf_attachments/_html_exhibits_block. case_folder here is just
    # this report's own containing directory; both helpers gracefully
    # return {} if it isn't actually a real, indexed, consolidated case.
    case_folder = os.path.dirname(report_file)
    tags_by_path = _tags_for_paths(case_folder, sel_files)
    analysis_by_path = _analysis_results_for_paths(case_folder, sel_files)
    exhibit_numbers = {p: i for i, p in enumerate(attachments.get('files', []), start=1)}

    # Geolocation section data (KML files + parsed placemarks) - walked/
    # parsed when the section is either always-on (the caseuco template,
    # which has no opt-out checkbox - Geolocation is a fixed part of its
    # structure, mapping onto the ontology's Location module) or reachable
    # and selected (standard/custom templates via their checkbox; DFIR/
    # Police never include it at all, matching their fixed structure), same
    # "compute once before dispatch" pattern as tags_by_path/
    # analysis_by_path/exhibit_numbers above.
    geo_data = None
    if template == 'caseuco' or (resolved_sections is not None and any(e['key'] == 'geolocation' for e in resolved_sections)):
        geo_data = _collect_case_geolocation(case_folder, attachments.get('files', []))

    # preview=True renders the exact same document a real export would
    # produce, but returns it inline (no Content-Disposition, so a browser
    # shows it in an iframe rather than downloading it) and skips writing
    # anything to disk - no out_path write, no .sha256 sidecar. Every other
    # part of this route above (template resolution, sections, event
    # filtering, attachment selection, tags/analysis/exhibit numbers,
    # geolocation data) is identical for both modes.
    preview = bool(req.get('preview'))

    try:
        pdf_buf = io.BytesIO() if fmt == 'pdf' else None
        html_content = None

        if template == 'dfir':
            if fmt == 'html':
                html_content = _build_html_report_dfir(header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                                         tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
            else:
                _build_pdf_report_dfir(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                        tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
        elif template == 'police':
            if fmt == 'html':
                html_content = _build_html_report_police(header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
            else:
                _build_pdf_report_police(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, captions=captions,
                                          tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers)
        elif template == 'caseuco':
            if fmt == 'html':
                html_content = _build_html_report_caseuco(header, events, sel_urls, sel_files, audit_entries, case_notes, job_fields, captions=captions,
                                                            tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)
            else:
                _build_pdf_report_caseuco(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, job_fields, captions=captions,
                                           tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data)
        elif fmt == 'html':
            html_content = _build_html_report_standard(header, events, sel_urls, sel_files, audit_entries, case_notes, resolved_sections, job_fields, captions=captions,
                                                         tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data, custody_log=custody_log)
        else:
            _build_pdf_report_standard(pdf_buf, header, events, sel_urls, sel_files, audit_entries, case_notes, resolved_sections, job_fields, captions=captions,
                                        tags_by_path=tags_by_path, analysis_by_path=analysis_by_path, exhibit_numbers=exhibit_numbers, geo_data=geo_data, custody_log=custody_log)

        if fmt == 'html':
            content_bytes = html_content.encode('utf-8')
            mimetype = 'text/html; charset=utf-8'
        else:
            content_bytes = pdf_buf.getvalue()
            mimetype = 'application/pdf'

        if preview:
            return Response(content_bytes, mimetype=mimetype)

        out_path = report_file.rsplit('.json', 1)[0] + ('.html' if fmt == 'html' else '.pdf')
        with open(out_path, 'wb') as f:
            f.write(content_bytes)

        # A report-level integrity hash - computed over the exported file's
        # actual bytes (already in memory, the same bytes just written to
        # disk above), not the source case JSON, so it verifies the specific
        # PDF/HTML artifact an examiner hands off, not just the data behind
        # it. Written as a standard sha256sum-format sidecar file (so
        # `sha256sum -c` works directly against it later) and also returned
        # as a response header so the examiner sees it immediately, not only
        # by going and finding the sidecar file afterward.
        digest = hashlib.sha256(content_bytes).hexdigest()
        with open(out_path + '.sha256', 'w') as f:
            f.write(f"{digest}  {os.path.basename(out_path)}\n")
        _auto_tag_case_artifact(case_folder, out_path)
        _auto_tag_case_artifact(case_folder, out_path + '.sha256')

        resp = send_file(out_path, as_attachment=True)
        resp.headers['X-Report-Sha256'] = digest
        return resp
    except Exception as e:
        return jsonify({"error": f"Report export failed: {str(e)}"}), 500
