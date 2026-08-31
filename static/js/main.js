// --- Idle-session redirect: a single global fetch() wrapper ---
// Sessions now idle-timeout server-side (core/auth.py, FORENSIC_IDLE_TIMEOUT,
// default 30 min of no requests). Once that happens, this app's own
// background polling (fetchSystemInfo() etc., every 2s) starts getting real
// 401s instead of data - left alone, that would just show up as silently-
// broken telemetry forever, never a clear "please log back in". Patching the
// one shared fetch() primitive covers all ~100+ call sites in this file
// uniformly, with nothing to keep in sync at each one individually - the
// alternative (teaching every call site its own 401 handling) doesn't scale
// and is easy to miss on a new one. Placed as the very first executable
// statement in this file, before any other code runs, so it's guaranteed to
// wrap fetch() before anything (including DOMContentLoaded's own early
// fetchWhoami() call) has a chance to use the original. /login and /logout
// are excluded since neither ever needs a session to begin with - a wrong-
// password 401 from /login is handled inline by whatever called it (the
// login form itself, or Switch User), not a real logout.
(function () {
    const _origFetch = window.fetch.bind(window);
    window.fetch = async function (input, init) {
        const res = await _origFetch(input, init);
        if (res.status === 401 && window.location.pathname !== '/login') {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            let path;
            try { path = new URL(url, window.location.origin).pathname; } catch (e) { path = url; }
            if (path !== '/login' && path !== '/logout') {
                window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname) + '&expired=1';
            }
        }
        return res;
    };
})();

let isWriteBlockActive = true;
let throughputChart = null;
const maxGraphPoints = 30;
const graphData = Array(maxGraphPoints).fill(0);
const graphLabels = Array(maxGraphPoints).fill('');

let currentDrivesList = [];

// Consolidated "Encrypted Volume" pre-acquisition unlock state (BitLocker/
// LUKS/VeraCrypt, 2026-08-26 - was 2 separate trios of variables, one per
// type, replaced by one generic trio + an explicit type tag since only one
// type can ever be unlocked at a time here) - null unless a dislocker/
// cryptsetup mount is currently active for the Acquisition tab's selected
// drive. Cleared on a successful/attempted Lock, and left for the examiner
// to clean up manually otherwise (mirrors this app's existing "no
// automatic cleanup of things the examiner explicitly did" posture
// elsewhere, e.g. active network mounts).
let encVolActiveMountId = null;
let encVolUnlockedSourcePath = null;
let encVolActiveType = null; // 'bitlocker'|'luks'|'veracrypt' - which type is currently unlocked, needed to route Lock/status calls to the right /api/${type}/... endpoint
let encVolMountConsumedByJob = false; // true once a started job is actually using the unlocked mount, so fetchProgress() knows the backend's own post-job auto-unlock applies

let currentBrowsePath = '/mnt';
let folderModalInstance = null;
let modalPickerMode = 'folder';
let targetInputIdForModal = 'destPath';

let explorerPath = '/mnt';
let activeSelectedFile = null;
let activeSelectedIsDir = false;

let currentLoadedReportData = null;
let currentReportPath = null;
let currentAttachedFilesList = [];
let currentAttachmentCaptions = {};
let currentReferenceUrlsList = [];

// activeCase shape: {case_number, examiner, case_folder} | null
let activeCase = null;
let caseManagerModalInstance = null;
const ACTIVE_CASE_STORAGE_KEY = 'pi_forensics_active_case';

// Shared non-blocking status notification, replacing this app's old habit of plain alert()
// popups for action results. alert() blocks the entire tab (including this app's own 2s telemetry
// poll) until dismissed, doesn't match the dark Bootstrap theme, and isn't touch-friendly on the
// kiosk - a real usability complaint, not a cosmetic one. Genuine yes/no gates before a destructive
// action still use native confirm() elsewhere in this file (deliberately unchanged here) - a toast
// can't block execution or return a boolean, so it was never a fit for those.
function showToast(message, type) {
    const container = document.getElementById('toastContainer');
    if (!container) { alert(message); return; } // defensive fallback only - should never happen

    const bgClass = {
        success: 'text-bg-success',
        danger: 'text-bg-danger',
        warning: 'text-bg-warning',
        info: 'text-bg-info',
    }[type] || 'text-bg-secondary';

    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center ${bgClass} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');

    const flexDiv = document.createElement('div');
    flexDiv.className = 'd-flex';

    const body = document.createElement('div');
    body.className = 'toast-body';
    body.style.whiteSpace = 'pre-line';
    body.style.wordBreak = 'break-word';
    body.textContent = message; // untrusted (often embeds a filename/path/backend error) - text node only
    flexDiv.appendChild(body);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
    closeBtn.setAttribute('data-bs-dismiss', 'toast');
    closeBtn.setAttribute('aria-label', 'Close');
    flexDiv.appendChild(closeBtn);

    toastEl.appendChild(flexDiv);
    container.appendChild(toastEl);

    // Errors/warnings stay up longer than a plain success/info confirmation - worth more of the
    // examiner's attention, and often longer text (a backend error message).
    const delay = (type === 'danger' || type === 'warning') ? 8000 : 4500;
    const bsToast = new bootstrap.Toast(toastEl, { delay });
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
    bsToast.show();
}

async function toggleOnscreenKeyboard() {
    try {
        const res = await fetch('/api/system/toggle_keyboard', { method: 'POST' });
        const data = await res.json();
        if (!data.success) showToast(`Keyboard toggle failed: ${data.error}`, 'danger');
    } catch (err) {}
}

function toggleFormatControls() {
    const fmtSelect = document.getElementById("imageFormatSelect");
    if (!fmtSelect) return;

    const fmt = fmtSelect.value;
    const compSelect = document.getElementById("compressionSelect");
    const splitSelect = document.getElementById("splitSizeSelect");
    const affRow = document.getElementById("affRawOptionRow");
    const ddrescueRow = document.getElementById("ddrescueOptionRow");
    const logicalRow = document.getElementById("logicalAcqOptionRow");
    const hashRow = document.getElementById("hashRow");
    const helpText = document.getElementById("formatHelpText");

    if (fmt === 'e01') {
        if (compSelect) compSelect.disabled = false;
        if (splitSelect) splitSelect.disabled = false;
    } else {
        if (compSelect) compSelect.disabled = true;
        if (splitSelect) splitSelect.disabled = true;
    }

    if (affRow) affRow.style.display = (fmt === 'aff') ? '' : 'none';
    if (ddrescueRow) ddrescueRow.style.display = (fmt === 'ddrescue') ? '' : 'none';
    // Logical Acquisition (folded into this same Format dropdown 2026-08-27,
    // mirroring ddrescue's own precedent) - its own folder-list/zip controls.
    if (logicalRow) logicalRow.style.display = (fmt === 'logical') ? '' : 'none';
    // ddrescue has no built-in hashing the way dc3dd/dcfldd/ewfacquire do -
    // hide the checkboxes rather than show controls that don't apply. Logical
    // Acquisition DOES hash (each copied file + the manifest itself), via
    // these same shared checkboxes - see startLogicalAcquisition().
    if (hashRow) hashRow.style.display = (fmt === 'ddrescue') ? 'none' : '';

    // Guided Workflow automation Tier 2's chain-into-Auto-Analyze checkbox
    // only applies to the shared execution_worker() path (dc3dd/dcfldd/plain
    // dd/E01) - ddrescue and AFF each run their own separate worker function
    // server-side (execution_worker_aff() for AFF; a wholly different route,
    // /api/start_ddrescue, for ddrescue) that the chaining logic was never
    // extended to, and Logical Acquisition produces a folder bundle, not a
    // disk image classify_image_profile() can make sense of. Hidden rather
    // than left checked-but-silently-ignored.
    const chainRow = document.getElementById("chainAutoAnalyzeRow");
    if (chainRow) chainRow.style.display = (fmt === 'ddrescue' || fmt === 'aff' || fmt === 'logical') ? 'none' : '';

    const FORMAT_HELP = {
        dd: "Raw bit-for-bit copy using dc3dd, with hashing built in. A solid default for most acquisitions.",
        dcfldd: "Same idea as dc3dd (raw copy + hashing), from a different tool - useful if you specifically need dcfldd's output style.",
        plain_dd: "Plain GNU dd, no built-in hashing (computed separately after). Supports true direct disk access, bypassing the cache on read.",
        e01: "EnCase-compatible format (.E01) - widely used in law enforcement/EnCase workflows, supports compression and splitting into segments.",
        aff: "Advanced Forensic Format - acquires a raw image first, then converts it to .aff. You'll be asked whether to keep the intermediate raw file.",
        ddrescue: "For damaged, clicking, or failing drives - works around bad sectors instead of stopping, with configurable retry strategy below. No built-in hashing; verify the result separately once you have a usable copy.",
        logical: "Copies specific folders from an already-mounted evidence source into one hash-verified container with a manifest - without imaging the whole device. No target drive selection needed above; add folders below, then Start.",
    };
    if (helpText) helpText.textContent = FORMAT_HELP[fmt] || '';
}

function toggleSidebarCompact() {
    const sidebar = document.getElementById("appSidebar");
    const icon = document.getElementById("sidebarToggleIcon");
    if (!sidebar) return;

    const isCompact = sidebar.classList.toggle("compact");
    if (icon) icon.className = isCompact ? "bi bi-chevron-double-right" : "bi bi-chevron-double-left";
    localStorage.setItem("pi_forensics_sidebar_compact", isCompact ? "1" : "0");

    // Chart.js sizes itself against its container's measured width, which
    // only changes here because of a CSS transition on a *sibling* element -
    // dispatching a resize event prompts it to recompute rather than staying
    // sized for the old sidebar width.
    setTimeout(() => window.dispatchEvent(new Event('resize')), 200);
}

function switchToTab(tabId) {
    const el = document.getElementById(tabId);
    if (el) new bootstrap.Tab(el).show();
}

// Reporting's station-wide case-status stat (moved here from Home,
// 2026-08-21, then trimmed back to just this one block the same day - see
// the dated CLAUDE.md entry) - built entirely from the already-existing,
// @requires_auth-only /api/cases/list (no new backend route, no permission
// gating beyond being logged in).
// Segment colors for the Total Cases mini status-chart - deliberately the
// same Bootstrap bg-* families (minus the text-contrast modifiers a badge
// needs but a bare bar segment doesn't) as CASE_STATUS_BADGE_CLASS further
// down this file, so a status reads as the same color everywhere in the app.
const CASE_STATUS_BAR_COLOR = {
    'Open': 'bg-info', 'In Review': 'bg-warning', 'On Hold': 'bg-secondary',
    'Closed': 'bg-success', 'Archived': 'bg-dark',
};

async function loadReportingStats() {
    const casesEl = document.getElementById('repStatCases');
    const barEl = document.getElementById('repStatCasesBar');
    const legendEl = document.getElementById('repStatCasesLegend');
    if (!casesEl) return; // Reporting tab isn't in the DOM (shouldn't happen, but don't throw if so)

    try {
        const res = await fetch('/api/cases/list');
        const data = await res.json();
        if (!data.success) {
            casesEl.textContent = '--';
            if (barEl) barEl.style.display = 'none';
            if (legendEl) legendEl.innerHTML = '';
            return;
        }

        const cases = data.cases || [];
        casesEl.textContent = String(cases.length);

        // Status breakdown mini-chart - one segment per distinct status
        // actually present (proportional width), plus a horizontal dot-
        // legend with counts (stacked below the bar in the original
        // standalone box; inline here since this now shares one header
        // row with the Case Report title and Save button). Hidden
        // entirely when there are no cases yet, rather than showing an
        // empty bar. A legacy (pre-case_status-field) case buckets into
        // "Legacy" rather than being silently dropped.
        if (barEl && legendEl) {
            const counts = {};
            cases.forEach(c => {
                const status = c.case_status || 'Legacy';
                counts[status] = (counts[status] || 0) + 1;
            });
            barEl.innerHTML = '';
            legendEl.innerHTML = '';
            if (cases.length > 0) {
                Object.keys(counts).forEach(status => {
                    const seg = document.createElement('div');
                    seg.className = CASE_STATUS_BAR_COLOR[status] || 'bg-secondary';
                    seg.style.flex = String(counts[status]);
                    seg.title = `${status}: ${counts[status]}`;
                    barEl.appendChild(seg);

                    const legendItem = document.createElement('span');
                    const dot = document.createElement('span');
                    dot.className = `reports-stat-legend-dot ${CASE_STATUS_BAR_COLOR[status] || 'bg-secondary'}`;
                    legendItem.appendChild(dot);
                    legendItem.appendChild(document.createTextNode(`${status} (${counts[status]})`));
                    legendEl.appendChild(legendItem);
                });
                barEl.style.display = 'flex';
            } else {
                barEl.style.display = 'none';
            }
        }
    } catch (err) {
        casesEl.textContent = '--';
        if (barEl) barEl.style.display = 'none';
        if (legendEl) legendEl.innerHTML = '';
    }
}

// Persist and restore whichever top-level sidebar tab the examiner was last on, so refreshing the
// page (or the kiosk browser restarting) doesn't always land back on Forensic Acquisition - a real
// reported annoyance for anyone mid-review on Reporting/Settings/etc. Scoped to exactly these 8 real
// tabs (not sub-navs like Reporting's/Settings'/Help's own list-group-as-tabs, which reuse the same
// Bootstrap Tab component and would otherwise also fire this listener).
const LAST_TAB_STORAGE_KEY = 'pi_forensics_last_tab';
const TOP_LEVEL_TAB_IDS = ['home-tab', 'acquisition-tab', 'mobile-tab', 'ddrescue-tab', 'explorer-tab', 'reports-tab', 'settings-tab', 'help-tab'];
document.addEventListener('shown.bs.tab', (ev) => {
    if (TOP_LEVEL_TAB_IDS.includes(ev.target?.id)) {
        localStorage.setItem(LAST_TAB_STORAGE_KEY, ev.target.id);
    }
});

const GUIDE_SCENARIOS = {
    healthy: {
        title: "Drive works fine - straightforward copy",
        steps: [
            "Optional first step: create or select a case from the \"Create / Select Case\" button at the top of the page - it auto-fills Case #, Examiner, and Destination on every tab below, including this one. Not required; every tool works fine with no case selected too.",
            "On the Forensic Acquisition tab, pick your drive from the dropdown in \"Target Source Selection\".",
            "Optional but recommended: check the drive's health first (SMART status shown once selected).",
            "Leave the write-blocker switched on (it's on by default) - this guarantees nothing can be written to the original drive. The top-right \"Write Blocker\" badge always shows the state of whichever drive is selected here.",
            "Under \"Format\", the default (Raw / dc3dd) is a safe choice for most cases - hover the format dropdown for what each option means.",
            "Fill in Case #, Evidence ID, and Examiner if you haven't already, then click \"Start Acquisition\" and wait for it to finish.",
            "Once done, open Reporting - if a case was active, the job's hashes and telemetry are already there under the Jobs tab. Use Export to generate a PDF/HTML report.",
        ]
    },
    damaged: {
        title: "Damaged, clicking, or not detected properly",
        steps: [
            "Stay on the Forensic Acquisition tab. Select your drive, then change Format to \"ddrescue (Recovery)\".",
            "Start with strategy \"1. Fast Copy\" - it copies everything readable quickly without stressing a failing drive.",
            "When it finishes, go to the File Recovery tab and use the Mapfile Inspector (right column) to check for bad sectors - it shows rescued/bad-sector/error counts as a structured summary, not raw text.",
            "If bad sectors remain, try strategy 2 (Edge Trimming), then 3 (Intensive Scraping) if needed - each is more thorough but harder on the drive, so go in order.",
            "Once you have a usable copy, the File Recovery tab's tool selector (PhotoRec, extundelete, foremost, scalpel) can recover files even from damaged or partly-corrupted areas of that image.",
        ],
        tabId: "acquisition-tab"
    },
    deleted: {
        title: "Need to recover deleted files",
        steps: [
            "If you don't have an image yet, acquire one first (see the \"drive works fine\" guide above).",
            "Go to the File Recovery tab, choose PhotoRec from the tool selector, and point it at your image (or the drive directly) as the source.",
            "PhotoRec finds files by matching known file signatures rather than trusting the file system, so it works even on formatted or damaged drives - but recovered files lose their original names and folder structure.",
            "If you specifically need files with their original names/paths intact, go to File Explorer instead, right-click (or press-and-hold) the image, and choose \"Browse as Image (Sleuth Kit)\" - it browses the real filesystem inline, including deleted-but-still-listed entries, and can search across the whole image or generate a MACB timeline.",
        ],
        tabId: "ddrescue-tab"
    },
    encrypted: {
        title: "The drive (or image) is BitLocker, LUKS, or VeraCrypt encrypted",
        steps: [
            "Recovery key/passphrase/password in hand? On the Forensic Acquisition tab, select the drive as usual, then expand the \"Encrypted Volume\" section below it and pick the type (BitLocker, LUKS, or VeraCrypt) from the dropdown - the credential field's label changes to match. Click Detect for BitLocker/LUKS to confirm which one applies (VeraCrypt volumes have no fixed signature by design, so Detect always says it can't tell for those - a failed Unlock attempt tells you the real answer instead), enter the credential, and click Unlock.",
            "Once unlocked, the decrypted volume becomes the acquisition source automatically - proceed with Start Acquisition as normal. The volume re-locks itself the moment the job finishes, whether it succeeds or fails.",
            "Already have an acquired image (.dd/.E01) that's encrypted, rather than a live drive? Right-click it in File Explorer and choose \"Unlock Encrypted Volume & Browse...\" to browse the decrypted contents inline with the same Sleuth Kit tools used for any other image - no need to re-acquire.",
            "The recovery key/passphrase/password you enter is recorded in the case report as plain-text documentation, not encrypted at rest - so whoever reviews the report later has what they need to decrypt the image again themselves.",
        ],
        tabId: "acquisition-tab"
    },
    phone: {
        title: "It's a phone, not a drive",
        steps: [
            "Go to the Mobile Forensics tab and connect the device with a USB cable.",
            "Use the mode selector to pick iOS or Android - the matching device list, options, and detail fields (model, OS version, storage, serial, and more) appear on the left; Start/Stop and status/console are on the right.",
            "iPhone: tap \"Trust This Computer?\" on the phone's own screen when it appears, then select the device here and start a backup.",
            "Android: approve the USB debugging prompt on the phone's own screen, then select the device here. \"Pull Accessible Storage\" is the most reliable mode for most cases.",
            "Once finished, an acquired backup can be scanned for spyware/compromise indicators - right-click it in File Explorer and choose the MVT scan matching its platform (iOS works cleanly against any backup this tab produces; Android is best-effort and needs a decrypted adb-backup-format folder).",
        ],
        tabId: "mobile-tab"
    },
    report: {
        title: "Documenting findings / writing a report",
        steps: [
            "Before writing anything up, consider running \"Auto Analyze...\" (top of File Explorer's right-click menu) against your acquired evidence - it detects what kind of image or backup you have and runs a curated set of analysis tools (registry/log/artifact parsing, hashing, and more) automatically, giving you real findings to write about instead of a blank page.",
            "Make sure the case you're reporting on is the active case (top-left \"Case\" button), then open the Reporting tab - it loads that case automatically, no manual file browsing needed. \"Overview\" (the default view) gives you a dashboard of everything recorded so far - evidence items, tags, analysis activity, case notes - plus \"Verify All Evidence\" (re-checks every acquisition's hash) and \"Export Case Bundle\" (zips the whole case for handoff).",
            "Use \"Case Notes\" as you work, not just at the end - it's a timestamped, append-only journal (each note gets an author and a local integrity hash; editing keeps the original text rather than overwriting it). This becomes the \"Forensic Analysis / Steps Taken\" section of the exported report.",
            "\"Report Narrative\" holds the polished closing write-up (executive summary, objectives, findings, limitations, conclusion) - a separate, deliberately distinct thing from the running Case Notes journal.",
            "\"Jobs\" shows every acquisition/recovery/mobile job run against this case with full telemetry and hashes; \"Evidence Timeline\" merges every acquired image's filesystem timeline with parsed-artifact timestamps; \"Audit Trail\" is the station-wide activity log filtered to this case number; \"Custody Log\" records physical evidence handoffs between people, separate from all of the above.",
            "When ready, go to Export - pick PDF, HTML, JSON, or CSV, choose a report template (Standard, or a fixed DFIR/Police/CASE-UCO structure), and which sections/evidence items to include, then export. Attached photos and text files get embedded directly in the output, not just listed by path.",
        ],
        tabId: "reports-tab"
    },
};

function showGuideStep(scenario) {
    const container = document.getElementById("guideStepsContainer");
    if (!container) return;
    const data = GUIDE_SCENARIOS[scenario];
    if (!data) return;

    container.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'guide-result-panel';

    const titleEl = document.createElement('div');
    titleEl.className = 'text-info fw-bold mb-2';
    titleEl.textContent = data.title;
    wrap.appendChild(titleEl);

    const ol = document.createElement('ol');
    ol.className = 'small text-light mb-3 ps-3';
    data.steps.forEach(step => {
        const li = document.createElement('li');
        li.className = 'mb-1';
        li.textContent = step;
        ol.appendChild(li);
    });
    wrap.appendChild(ol);

    if (data.tabId) {
        const goBtn = document.createElement('button');
        goBtn.className = 'btn btn-sm btn-info text-dark fw-bold';
        goBtn.innerHTML = '<i class="bi bi-arrow-right-circle me-1"></i>Take me there';
        goBtn.onclick = () => switchToTab(data.tabId);
        wrap.appendChild(goBtn);
    }

    container.appendChild(wrap);
}

// ===================== HELP TAB =====================
// Help used to be a Bootstrap modal (openHelpModal()) - converted to a real
// sidebar tab (2026-08-23, at the user's own request: "the help page looks
// pretty ugly, can we push that into a tab like Settings/Reporting instead
// of a popup?"), same horizontal-top-tabs shell as Settings/Reporting.
// populateFaq()/populateToolReference()/populateReportFieldMapping() are
// still called from help-tab's own onclick in index.html (they each
// build-once-and-guard, so repeated calls are safe). The old "Additional
// Info" tab (populateHelpInfo()) was removed the same day - its genuinely
// non-redundant content was folded into FAQ_GROUPS instead, and the rest
// was already duplicated by an existing FAQ answer.
//
// User Manual moved to the first/default nav position (2026-08-23, at the
// user's own request) - help-tab's onclick calls loadHelpDocFrame() for it
// eagerly, same as the other build-once-and-guard calls above, since it's
// now what's actually visible the instant Help opens rather than something
// reached by a click. Quick-Start/Release Notes stay purely lazy (see
// loadHelpDocFrame()'s own comment) since neither is shown by default.

// Lazy-loads one of the three embedded doc iframes (Quick-Start/User
// Manual/Release Notes) - Quick-Start and Release Notes only load the
// first time their own nav item is actually clicked, avoiding two extra
// requests on every page load for docs most sessions never open; User
// Manual is the one exception, loaded eagerly from help-tab's own onclick
// since it's the default-shown pane (see above). Idempotent either way: a
// second call against an already-loaded pane is a no-op.
function loadHelpDocFrame(frameId, docId) {
    const frame = document.getElementById(frameId);
    if (!frame || frame.src) return;
    frame.src = `/docs/${docId}`;
}

// Grouped by which sidebar tab (or cross-cutting topic) each question
// belongs to, rendered as a flat accordion with a non-collapsible group
// label before each group's items - keeps the simple accordion component
// but reads as organized instead of an unordered pile of questions.
const FAQ_GROUPS = [
    {
        group: "Forensic Acquisition",
        items: [
            {
                q: "What does the write-blocker do, and should I leave it on?",
                a: "It forces the source drive into read-only mode at the kernel level, so nothing - this app or anything else - can accidentally modify the original evidence. Leave it on for any drive you're imaging from. You'd only turn it off for a destination drive you're writing an image to. Settings > Drive Management lets you check or toggle it per-drive without going through the Forensic Acquisition tab."
            },
            {
                q: "Which format should I use - dd, E01, or AFF?",
                a: "Raw / dc3dd (the default) is a solid choice for most cases and includes built-in hashing. E01 is the standard if you need EnCase compatibility or want compression/splitting into segments. AFF is less common now but supported if your workflow needs it. Hover the Format dropdown on the Forensic Acquisition tab for a live explanation of whichever one is selected."
            },
            {
                q: "What happened to ddrescue's own tab?",
                a: "It's not a separate tab - select \"ddrescue (Recovery)\" as the Format on the Forensic Acquisition tab. It shares the exact same status/progress/console display as every other format, just with its own strategy/retry options underneath."
            },
            {
                q: "How do I know my acquisition actually completed successfully?",
                a: "Check the status text and console during the job - it'll say \"Completed Successfully\" or \"Failed\" clearly. Afterward, if the job ran against an active case, open Reporting - its hashes and telemetry are already recorded under the Jobs tab. Otherwise, right-click the resulting image in File Explorer and use \"Verify Image Hash\"."
            },
            {
                q: "The drive I need to image is BitLocker, LUKS, or VeraCrypt encrypted - can this station handle that?",
                a: "Yes, all three. On the Forensic Acquisition tab, below drive selection, expand \"Encrypted Volume\" and pick the type from the dropdown - the credential field's label changes to match (Recovery Key, Passphrase, or Password). Click Detect to confirm which applies for BitLocker/LUKS (VeraCrypt volumes have no fixed signature by design, so Detect can't tell for those - try Unlock directly instead). Once unlocked, the decrypted volume becomes the acquisition source automatically, and locks itself again once the job completes. Already-acquired encrypted images can also be unlocked and browsed directly from File Explorer's right-click menu (\"Unlock Encrypted Volume & Browse...\"), without re-acquiring."
            },
            {
                q: "Can I look inside a drive before committing to a full acquisition?",
                a: "Yes - \"Preview\" (next to Scan on the Forensic Acquisition tab) lets you browse a connected drive's real filesystem, read files, and run analysis tools against it read-only, before deciding whether (or how) to image it. It's clearly labeled as a live preview, not a substitute for a real acquisition - nothing is saved as evidence until you actually run Start Acquisition."
            },
            {
                q: "I only need specific folders, not a full bit-for-bit image - is that possible?",
                a: "Yes - Logical (Custom Content) Acquisition, also on the Forensic Acquisition tab (select it from the Format dropdown), lets you pick one or more specific folders and package them into a single hash-verified container with a manifest, instead of imaging an entire drive. Useful when you only need a user's documents or a particular app's data, not the whole disk."
            },
        ]
    },
    {
        group: "File Recovery & Analysis",
        items: [
            {
                q: "What's the difference between PhotoRec and browsing an image with Sleuth Kit?",
                a: "PhotoRec (File Recovery tab) finds files by matching known file signatures in the raw data - it works even on damaged or reformatted drives, but recovered files lose their original names and folder structure. Sleuth Kit's Image Browser (right-click an image in File Explorer → \"Browse as Image (Sleuth Kit)\") reads the actual filesystem structure inline, so it shows real file names and paths, including deleted-but-still-listed entries - but needs a filesystem it can understand."
            },
            {
                q: "PhotoRec recovered files but with generic names like f0001234.jpg - is that normal?",
                a: "Yes - PhotoRec identifies file types by content, not by reading filesystem metadata, so it has no way to know the original filename. If you need original names, right-click the image in File Explorer and choose \"Browse as Image (Sleuth Kit)\" instead (works only if the filesystem itself is still readable)."
            },
            {
                q: "How do I view hidden metadata like GPS coordinates or camera info in a photo?",
                a: "Select the file in File Explorer, then click the \"Metadata\" tab next to Preview in the right panel - it runs ExifTool and shows every field found, right there in place of the file preview."
            },
            {
                q: "What does the MVT scan check for?",
                a: "Amnesty International's Mobile Verification Toolkit checks an already-acquired mobile backup against known spyware/compromise indicators. Right-click a backup folder in File Explorer and choose the MVT scan for its platform. iOS matches this station's backup format directly; Android is best-effort, since it needs a decrypted adb-backup-format folder rather than the pull/bugreport formats Mobile Forensics normally produces here - it'll error clearly rather than silently produce nothing if the format doesn't match."
            },
            {
                q: "Can I analyze a memory (RAM) dump on this station?",
                a: "Yes - Windows and x86_64 Linux memory images. Right-click a memory-image file (.raw/.mem/.vmem/.dmp/.lime) in File Explorer and choose \"Memory Forensics...\", then pick the engine: Volatility3 for Windows (process lists, network connections, loaded DLLs, and more; the first run needs internet access, to fetch matching OS symbol information), or mquire for x86_64 Linux (reads symbol info the kernel embeds in the image itself, so no download is needed there). This station only analyzes an already-captured memory image; it has no way to capture memory from a live system itself. ARM Linux and macOS memory images aren't supported by either engine."
            },
            {
                q: "Can I convert an image between raw (.dd) and E01 format after the fact?",
                a: "Yes - right-click an already-acquired image in File Explorer and choose \"Convert Image Format...\". Works in both directions (raw to E01 and E01 to raw) and independently re-verifies the converted file's hash against the original rather than just trusting the conversion tool."
            },
            {
                q: "Does this station recover browser history or bookmarks?",
                a: "Yes - right-click a folder (or an acquired image) in File Explorer and choose \"Parse Browser Artifacts\" to extract history, bookmarks, downloads, and cookies from a Chrome/Chromium- or Firefox-family profile. Results show up under File Views' \"Parsed Artifacts\" category, alongside anything found by the Registry hive, Event Log (.evtx), Prefetch, Recycle Bin, Linux artifact, mobile chat/app, and .lnk shortcut parsers (also reached from the right-click menu). Safari isn't supported - its data lives inside an iOS/macOS backup rather than a portable profile folder."
            },
            {
                q: "What's \"Auto Analyze\" and how is it different from running tools by hand?",
                a: "Auto Analyze (the top item on File Explorer's right-click menu) detects what kind of evidence you've selected - a Windows disk image, a Linux disk image, a memory image, or a mobile backup - and runs a curated, sensible default set of analysis tools against it in one background job, instead of you running each one individually. It always shows the detected profile for confirmation (or correction) before anything runs, and every tool it runs is still available individually if you'd rather pick and choose."
            },
            {
                q: "Can I check a file against known-good/known-bad hash lists, or scan it with YARA rules?",
                a: "Yes - Settings > Case & Reporting > Analysis & IOC Lists lets you save your own Hash Sets (known-good/known-bad, one-click import of a recent-malware feed from MalwareBazaar), URL Lists (known-bad URLs, one-click import from URLhaus), and YARA Rulesets. Then right-click any file in File Explorer and choose \"Check Against Hash Sets\" or \"Scan with YARA Rules\" - Hash Sets are also checked automatically whenever you run a Hash Manifest, and URL Lists are checked automatically against every URL a browser-artifact scan finds."
            },
            {
                q: "Can I browse a SQLite database file directly, without a separate tool?",
                a: "Yes - select any .db/.sqlite/.sqlite3 file in File Explorer and a \"Database\" tab appears next to Preview/Hex/Metadata, showing its tables and rows read-only. Works the same whether the file is a real one on disk or sitting inside an unmounted acquired image."
            },
            {
                q: "What's File Views, and how is it different from tagging a file?",
                a: "File Views (in File Explorer's folder tree) is a per-case index that automatically groups everything found so far - by file type, by keyword-scan hit, by tag, or by parsed artifact - so you don't have to remember where a specific result landed. Tagging is how you flag something yourself: right-click any file and choose Tag... to mark it Bookmark/Follow Up/Notable Item (or a custom tag you define in Settings), with an optional comment. Tagged files show up as their own File Views category and, once attached to the case, are called out in the exported report too."
            },
        ]
    },
    {
        group: "Case Management & Reporting",
        items: [
            {
                q: "What's an Active Case, and do I have to use one?",
                a: "The \"Case\" button at the top of every page creates or selects a case, which then auto-fills Case #, Examiner, and Destination on every tool below - including Reporting, which loads that case's data automatically with no manual file browsing. A case is a real folder on disk, with all of its metadata/notes/job telemetry consolidated into one JSON file rather than scattered per-job files. Using a case is entirely optional; every tool works the same with none selected, you'll just fill those fields in by hand. An older case created before consolidated case files existed can be migrated to the current format from the Case Manager, non-destructively - the original files are kept, renamed with a backup suffix, never deleted."
            },
            {
                q: "Case Notes vs. Report Narrative - what's the difference?",
                a: "Case Notes (Reporting tab) is a timestamped, append-only journal you add to as you work - each note gets an author and a local integrity hash, and editing keeps the original text rather than overwriting it. It becomes the exported report's \"Forensic Analysis / Steps Taken\" section. Report Narrative is the polished closing write-up (executive summary, objectives, findings, limitations, conclusion) you write once, near the end - a deliberately separate thing from the running notes journal."
            },
            {
                q: "What's the Case Status field for?",
                a: "Reporting's Case Details block has a Status dropdown (Open / In Review / On Hold / Closed / Archived) for your own case tracking. The Case Manager's case list shows a colored badge for each case's current status, and Reporting's own header shows a live breakdown of every case's status across the whole station."
            },
            {
                q: "How does this station track what was done and by whom?",
                a: "Settings > Audit Log keeps a station-wide, append-only log of significant actions (acquisitions, deletes, copies, report edits, logins) with a timestamp, source IP, and - since real per-user accounts are supported rather than one shared login - which logged-in user did it. Reporting's own \"Audit Trail\" sub-tab shows that same log filtered down to just the active case."
            },
            {
                q: "Custody Log vs. Case Notes vs. Audit Trail - what's the difference between the three?",
                a: "All three live in Reporting but track genuinely different things. Custody Log is a dedicated, append-only record of physical evidence handoffs between people - who had it, who it went to, why, and how. Case Notes is your own running, timestamped investigative journal (\"what did I do/observe just now\"). Audit Trail is the software's own activity log - actions taken in this app - filtered to the active case. Only Case Notes and Custody Log are things you write yourself; Audit Trail is fully automatic."
            },
            {
                q: "Can I verify that an already-acquired image hasn't been tampered with, without re-checking each one by hand?",
                a: "Yes - Reporting's Overview tab (the default view once a case is active) has a \"Verify All Evidence\" button that re-hashes every completed acquisition's own output file for the case and compares it against the hash recorded at acquisition time, all in one background job - the case-wide equivalent of right-clicking one file and choosing \"Verify Image Hash\"."
            },
            {
                q: "Can I export or back up an entire case, not just the report?",
                a: "Yes - Reporting's Overview tab has an \"Export Case Bundle\" button that zips the whole case folder (everything it actually contains - notes, attachments, generated reports, recovered files, and optionally the raw acquisition images) for archival or handing off to another examiner. This is different from exporting a PDF/HTML report, which is just the written-up deliverable."
            },
            {
                q: "Has this exact file/hash shown up in a different case on this station?",
                a: "Settings > Case & Reporting > Cross-Case Search checks a specific hash against every other case on the station - useful for spotting the same file reappearing across unrelated cases. It's scoped to exact hash matches, not free-text search across cases."
            },
            {
                q: "What's the Evidence Timeline tab?",
                a: "Reporting's \"Evidence Timeline\" merges every acquired image's own filesystem (MACB - Modified/Accessed/Changed/Born) timeline with the timestamps from any parsed artifacts (Registry, Event Logs, browser history, and more), shown as a stacked chart by source (click a bar to filter the table below it) plus a filterable, exportable table. Anti-forensic indicators (like a cleared audit log) and deleted-file entries are flagged directly in it."
            },
        ]
    },
    {
        group: "Accounts, Security & Remote Access",
        items: [
            {
                q: "How do I change my login password?",
                a: "Click \"Logged in as: ...\" in the top-right and choose \"Change My Password\" - you'll need your current password to set a new one. This works for every account regardless of user group. If this station has multiple accounts, someone with User & Group Management access can also reset another user's password from Settings > Security > User Accounts."
            },
            {
                q: "Can more than one person have their own login on this station?",
                a: "Yes - Settings > Security lets an account with User & Group Management access create real per-user accounts, each assigned to a group. Admin always has full access to everything; Analyst is the default operational group (every tool, no station configuration or user management); you can also create custom groups with checkboxes for exactly which tabs/actions they can access. The \"Logged in as\" button in the top-right lets you switch accounts (a real re-login under the hood) or log out fully, without closing the browser."
            },
            {
                q: "My browser says this site isn't secure or the certificate isn't trusted - what do I do?",
                a: "This station uses a self-signed HTTPS certificate, so every browser warns on first visit until that specific device explicitly trusts it. Settings > Security has a \"Generate & Install\" button if you need a fresh certificate (e.g. after the Pi's IP changed), a \"Download Certificate\" button, and step-by-step trust instructions for Windows, macOS, Linux, iOS, Android, and Firefox specifically."
            },
            {
                q: "How do I access this station from another computer?",
                a: "Navigate to the station's IP address (or hostname, if you set one up) on port 5000, or over HTTPS if a TLS reverse proxy was configured. Every remote connection requires a real login - there's no bypass for remote/LAN access. The physical touchscreen kiosk is the one exception (a setting called FORENSIC_KIOSK_AUTH_BYPASS, on by default) - physical access to the device already implies a high level of trust."
            },
        ]
    },
    {
        group: "General",
        items: [
            {
                q: "Does this station need an internet connection to work?",
                a: "No - acquisition, recovery, and analysis tools all run locally and don't need internet access. Internet is only used for optional things: the initial software install, ClamAV virus definition updates, MVT indicator updates, and the git-pull self-update feature, all in Settings."
            },
            {
                q: "What happens if power is lost mid-acquisition?",
                a: "The partial image file remains on disk, but it won't have a valid hash recorded, since the job never completed. Treat an interrupted acquisition as failed and start over once power is restored - don't rely on a partial image as evidence."
            },
            {
                q: "Where does my acquired data and case data get stored?",
                a: "Under the evidence root (/mnt by default) - acquisitions, recovered files, and reports all land there, and a case's own folder holds everything for that case in one place. Nothing is uploaded anywhere automatically; every tool this station runs works entirely locally."
            },
            {
                q: "How do I update this station, and how do I know what changed?",
                a: "Settings > Service Controls & Diagnostics has buttons to pull the latest app code (git) or update OS packages (apt) - both need internet access and pull from external sources, so only use them on a station where you trust those sources. \"View Release Notes\" right next to them (also in Help's own nav list) shows exactly what changed in each version before or after updating."
            },
        ]
    },
];

function populateFaq() {
    const container = document.getElementById("faqAccordion");
    if (!container || container.children.length > 0) return; // build once
    let idx = 0;
    FAQ_GROUPS.forEach(group => {
        const groupLabel = document.createElement('div');
        groupLabel.className = 'faq-group-kicker help-mono';
        groupLabel.textContent = group.group;
        container.appendChild(groupLabel);

        group.items.forEach(item => {
            const wrap = document.createElement('div');
            wrap.className = 'accordion-item bg-dark border-secondary';

            const header = document.createElement('h2');
            header.className = 'accordion-header';
            const btn = document.createElement('button');
            btn.className = 'accordion-button collapsed bg-dark text-light';
            btn.type = 'button';
            btn.setAttribute('data-bs-toggle', 'collapse');
            btn.setAttribute('data-bs-target', `#faqCollapse${idx}`);
            btn.textContent = item.q; // untrusted-safe habit even though this is static content
            header.appendChild(btn);
            wrap.appendChild(header);

            const collapse = document.createElement('div');
            collapse.id = `faqCollapse${idx}`;
            collapse.className = 'accordion-collapse collapse';
            const body = document.createElement('div');
            body.className = 'accordion-body small text-subtle';
            body.textContent = item.a;
            collapse.appendChild(body);
            wrap.appendChild(collapse);

            container.appendChild(wrap);
            idx++;
        });
    });
}

// Grouped by which sidebar tab each tool lives under (or "File Explorer &
// Analysis" for the right-click actions there) - the same 19 tools this
// list always had, now reorganized instead of an unordered flat list.
const TOOL_REFERENCE_GROUPS = [
    {
        group: "Forensic Acquisition",
        tools: [
            ["dc3dd", "Forensic raw disk imaging with built-in hashing. The default acquisition engine."],
            ["dcfldd", "Alternate raw imaging engine, similar to dc3dd - useful if you specifically need its output style."],
            ["GNU dd", "Plain raw copy, no built-in hashing (computed separately). Supports true direct-I/O reads."],
            ["ewfacquire", "Creates EnCase-compatible .E01 images with compression and segment splitting."],
            ["affconvert", "Converts a raw image into AFF (.aff) format."],
            ["ddrescue", "Recovery-focused imaging for damaged/failing drives - select it as a Format on the Forensic Acquisition tab. Works around bad sectors instead of stopping."],
            ["smartctl", "Reads a drive's built-in health/diagnostic data (SMART) before committing to a long acquisition."],
            ["dislocker", "Unlocks a BitLocker-encrypted drive or image so it can be imaged or browsed as a normal decrypted volume."],
            ["cryptsetup", "Unlocks a LUKS-encrypted drive or image (the standard Linux disk-encryption format), and a VeraCrypt-encrypted one, the same way dislocker handles BitLocker."],
        ]
    },
    {
        group: "File Recovery",
        tools: [
            ["PhotoRec", "Recovers files by matching known file signatures in raw data, even on damaged/reformatted media. Loses original filenames."],
            ["extundelete", "Recovers deleted files from ext2/3/4 Linux filesystems by reading the filesystem journal - can restore original filenames/paths, unlike carving tools."],
            ["foremost / scalpel", "Alternative file carvers to PhotoRec - narrower format support but sometimes faster. scalpel is multithreaded and uses a curated signature list (jpg/png/gif/pdf/zip by default)."],
            ["TestDisk (partition analysis)", "Read-only listing of partitions TestDisk can find on a device or image - never writes anything back, unlike TestDisk's separate (and not exposed here) repair mode."],
            ["Quick Triage Scan", "Scans a device or image for emails, URLs, IP addresses, card-like numbers, and phone numbers - built in, no external tool needed."],
        ]
    },
    {
        group: "File Explorer & Analysis",
        tools: [
            ["Sleuth Kit (Image Browser)", "Browses the real filesystem inside an acquired image inline, including deleted-but-listed entries, with original names/paths - plus recursive search and a MACB timeline. Right-click an image → \"Browse as Image (Sleuth Kit)\"."],
            ["ExifTool", "Reads hidden metadata inside a file - camera info, GPS coordinates, document properties. Select a file, then use the \"Metadata\" tab next to Preview."],
            ["Binwalk", "Looks for other files or filesystems hidden inside a binary - useful for firmware/router images."],
            ["ClamAV", "Scans a file or folder against known malware signatures."],
            ["hashdeep", "Generates a fingerprint (hash) for every file in a folder at once, as a single manifest."],
            ["SQLite Dissect", "Recovers deleted rows still present in a SQLite file's freeblocks, unallocated space, or a surviving WAL/rollback-journal file. Right-click a .db/.sqlite/.sqlite3 file and choose \"Recover Deleted SQLite Records\". Recovery reliability depends heavily on how the file was closed - a database with its own WAL file still present is the most reliable case."],
            ["androguard (APK Analysis)", "Static analysis of an Android .apk file - package/version metadata, permissions, activities/services/receivers/providers, every signing certificate, and a raw scan for embedded URLs. Right-click an .apk file and choose \"Analyze APK (androguard)\". Never runs or installs the app."],
            ["wadecrypt (WhatsApp Decryption)", "Decrypts a WhatsApp local backup file (msgstore.db.crypt12/14/15) against the device's own key file, producing a browsable SQLite database. Pull the key from a rooted device via Mobile Forensics > select an Android device > \"Pull WhatsApp Key File\", then right-click the .crypt12/14/15 file and choose \"Decrypt WhatsApp Backup\"."],
            ["IPA Static Analysis (LIEF)", "Static analysis of an iOS .ipa file - Info.plist metadata, permission usage descriptions, the embedded mobile provisioning profile (team, entitlements, provisioned devices), and optional Mach-O binary analysis (architecture, FairPlay encryption status). Right-click an .ipa file and choose \"Analyze IPA\". Never runs or installs the app."],
            ["dumpstate-py (Bugreport Deep Parse)", "Deep-parses an adb bugreport .zip (already captured via Mobile Forensics' own Bug Report mode) into structured sections - mount points, process list, package install/delete log, loaded kernel modules, GPS coordinates, crash traces/tombstones, network sockets, battery stats, power events. Right-click the bugreport .zip and choose \"Deep-Parse Bugreport\"."],
            ["idevicecrashreport", "Pulls a connected, trusted iOS device's own crash-report logs (decoded into readable .crash files). Never removes the originals from the device. Mobile Forensics > select an iOS device > \"Pull Crash Reports\"."],
            ["pysim (SIM/UICC Card Forensics)", "Reads a SIM/UICC card inserted in a connected PC/SC card reader - ICCID, ATR, EID, and application IDs. Mobile Forensics > SIM/UICC Card > Detect Readers > select a reader > Read Card. Requires PC/SC reader hardware connected to this station."],
            ["MVT (Mobile Verification Toolkit)", "Checks an already-acquired iOS or Android backup for spyware/compromise indicators. Right-click the backup folder and choose the scan for its platform."],
            ["ALEAPP / iLEAPP", "Comprehensive, community-maintained mobile artifact parsers - hundreds of app-specific artifacts (WhatsApp, Signal, Chrome, WiFi history, and more) from an already-acquired Android pull or iOS backup. Right-click the extraction folder and choose \"Parse with ALEAPP/iLEAPP...\". Runs as a background job - large extractions can take several minutes."],
            ["Volatility3", "Analyzes an already-captured Windows memory (RAM) image - process lists, network connections, loaded modules, and more. Right-click a memory-image file and choose \"Memory Forensics...\"."],
            ["mquire", "Analyzes an already-captured x86_64 Linux memory (RAM) image, reading symbol info the kernel embeds in the image itself - no separate download needed. Same \"Memory Forensics...\" action, pick the mquire engine."],
            ["Browser Artifact Parser", "Extracts history, bookmarks, downloads, and cookies from a Chrome/Chromium- or Firefox-family browser profile, on disk or inside an acquired image. Built in, no external tool needed."],
            ["Registry / Event Log / Prefetch / Recycle Bin / LNK Parsers", "Built-in parsers for Windows Registry hives (incl. Amcache), .evtx Event Logs, Prefetch execution history, Recycle Bin metadata, and .lnk shortcuts - no external tool needed, work on a real folder or directly inside an acquired image."],
            ["Linux Artifact Parser", "Built-in parser for shell history, /etc/passwd, cron jobs, and auth.log/secure authentication events on a Linux filesystem - no external tool needed."],
            ["YARA", "Scans a file against your own saved YARA rulesets (Settings > Case & Reporting > Analysis & IOC Lists). Right-click a file and choose \"Scan with YARA Rules\"."],
            ["Auto Analyze", "Not a single external tool - detects what kind of evidence you've selected (Windows/Linux disk image, memory image, mobile backup) and runs a curated set of the tools above automatically, as one background job. Top of the right-click menu."],
        ]
    },
    {
        group: "Mobile Forensics",
        tools: [
            ["adb", "Android Debug Bridge - used to pull files, back up, or capture diagnostics from a connected Android device."],
            ["idevicebackup2 / idevicepair", "Used to pair with and back up a connected iPhone/iPad, the same protocol iTunes/Finder use."],
        ]
    },
];

function populateToolReference() {
    const tbody = document.getElementById("toolReferenceBody");
    if (!tbody || tbody.children.length > 0) return; // build once
    TOOL_REFERENCE_GROUPS.forEach(group => {
        const headerRow = document.createElement('tr');
        const headerCell = document.createElement('td');
        headerCell.colSpan = 2;
        headerCell.className = 'tool-ref-kicker help-mono pt-3';
        headerCell.style.borderTop = 'none';
        headerCell.textContent = group.group;
        headerRow.appendChild(headerCell);
        tbody.appendChild(headerRow);

        group.tools.forEach(([name, desc]) => {
            const row = document.createElement('tr');
            const nameCell = document.createElement('td');
            nameCell.className = 'text-info fw-bold text-nowrap';
            nameCell.style.width = '22%';
            nameCell.textContent = name;
            const descCell = document.createElement('td');
            descCell.className = 'text-light';
            descCell.textContent = desc;
            row.appendChild(nameCell);
            row.appendChild(descCell);
            tbody.appendChild(row);
        });
    });
}

// Mirrors routes/reporting.py's REPORT_SECTION_BLOCKS one-for-one (same 16
// keys, same order) - kept as a second, hand-written copy rather than
// fetched from the backend, since this is static reference prose (what a
// section IS), not live template data the way the Report Template Builder's
// own block list already is. "Remappable" flags the 7 free-text sections a
// custom template's Report Template Builder can point at a different
// narrative field than their own default (see source_field) - every other
// section pulls from structured data (a table, a log, a filesystem walk)
// that isn't something a dropdown can meaningfully rewire.
const REPORT_FIELD_MAPPING = [
    ["Case Information", "Case #, Examiner, Status, Created date, Custom Fields", "Case #/Examiner set at creation (not editable after); Report Narrative &gt; Case Status; Custom Fields defined in Settings &gt; Case &amp; Reporting, values in Report Narrative &gt; Case Details"],
    ["Executive Summary", "Free text (Remappable)", "Report Narrative"],
    ["Objectives", "Free text (Remappable)", "Report Narrative"],
    ["Evidence Inventory", "Auto-built table (make/model/serial/capacity/hash)", "Not directly editable - comes from the acquisition job itself"],
    ["Acquisition Method", "Full per-job telemetry/parameters/hashes", "Not directly editable - comes from the acquisition job itself"],
    ["Forensic Analysis / Steps Taken", "The Case Notes journal, in order", "Case Notes"],
    ["Relevant Findings", "Free text (Remappable)", "Report Narrative"],
    ["Limitations &amp; Statement of Uncertainty", "Free text (Remappable)", "Report Narrative"],
    ["Conclusion", "Free text (Remappable)", "Report Narrative"],
    ["Indicators of Compromise", "Free text (Remappable)", "Report Narrative"],
    ["Recommendations / Next Steps", "Free text (Remappable)", "Report Narrative"],
    ["Exhibits", "Attached files/URLs + captions + tags + analysis results", "Files &amp; Artifacts tab (check/caption); File Explorer (tag/analyze)"],
    ["Geolocation / GPS Evidence", "KML files attached to or found in the case folder", "Auto-discovered; generate via File Explorer's \"Extract Geolocation (KML)\""],
    ["Case Activity Log (Audit Trail)", "Chain-of-custody entries matching this case #", "Automatic"],
    ["Filesystem Timeline (MACB)", "MACB walk of an acquired disk image, or real file timestamps from a mobile pull/backup or Logical Acquisition folder", "Automatic, needs the image or output folder still on disk"],
    ["Physical Evidence Custody Log", "From/To custodian handoff entries, append-only", "Custody Log tab"],
];

function populateReportFieldMapping() {
    const tbody = document.getElementById("reportFieldMappingBody");
    if (!tbody || tbody.children.length > 0) return; // build once
    REPORT_FIELD_MAPPING.forEach(([section, source, whereToEdit]) => {
        const row = document.createElement('tr');
        const sectionCell = document.createElement('td');
        sectionCell.className = 'text-info fw-bold';
        sectionCell.style.width = '20%';
        sectionCell.innerHTML = section; // static reference prose, not user data
        const sourceCell = document.createElement('td');
        sourceCell.style.width = '32%';
        sourceCell.innerHTML = source;
        const editCell = document.createElement('td');
        editCell.className = 'text-subtle';
        editCell.innerHTML = whereToEdit;
        row.append(sectionCell, sourceCell, editCell);
        tbody.appendChild(row);
    });
}

function updateAndroidModeHelp() {
    const sel = document.getElementById("mobileAndroidMode");
    const helpText = document.getElementById("androidModeHelpText");
    if (!sel || !helpText) return;

    const MODE_HELP = {
        pull: "Copies files from the phone's visible storage (photos, downloads, documents). Reliable on any modern Android version, but only sees what's directly accessible - not inside individual apps' private data.",
        backup: "Asks the phone to package up app data. The phone will show an on-screen prompt the user has to approve - check the device screen. Often disabled or unreliable on Android 12 and newer.",
        bugreport: "Captures a system diagnostic snapshot (logs, running processes, device state) - not a copy of personal files, but useful supporting evidence about what the device was doing.",
        physical: "Reads the device's raw block storage directly, the same way this app images a USB drive - but requires the device to ALREADY be rooted (this app never roots a device itself; rooting is an evidence-altering action). Only raw/dd output is supported (no E01). See the disclosure banner below for what's verified and what isn't.",
    };
    helpText.textContent = MODE_HELP[sel.value] || '';

    const physicalPanel = document.getElementById("mobileAndroidPhysicalPanel");
    if (physicalPanel) {
        physicalPanel.style.display = sel.value === 'physical' ? '' : 'none';
        if (sel.value === 'physical') renderAndroidPhysicalRootBanner();
    }
}

// Physical/raw Android acquisition (2026-08-30) - see the approved plan
// (iridescent-leaping-mist.md) for the full design. mobileAndroidDevices is
// populated by refreshMobileDevices() already - reused here rather than a
// second device fetch, since root_available/selinux_mode are already
// returned on every device entry.
function _currentlySelectedAndroidDevice() {
    const sel = document.getElementById("mobileAndroidSelect");
    if (!sel || !sel.value || typeof mobileAndroidDevices === 'undefined') return null;
    return (mobileAndroidDevices || []).find((d) => d.serial === sel.value) || null;
}

function renderAndroidPhysicalRootBanner() {
    const banner = document.getElementById("mobilePhysicalRootBanner");
    if (!banner) return;
    const dev = _currentlySelectedAndroidDevice();
    if (!dev) {
        banner.className = "small p-2 mb-2 rounded-2 border border-secondary text-subtle";
        banner.textContent = "Select a device first.";
        return;
    }
    if (!dev.root_available) {
        banner.className = "small p-2 mb-2 rounded-2 border border-danger text-danger";
        banner.textContent = "Not rooted (or root access could not be confirmed via su). Physical/raw acquisition "
            + "requires the device to already be rooted. Rooting a device is itself an evidence-altering action - "
            + "only proceed if rooting is a deliberate, documented, examiner-authorized step, and use Logical "
            + "acquisition (Pull/Backup/Bugreport) otherwise.";
        return;
    }
    banner.className = "small p-2 mb-2 rounded-2 border border-warning text-warning";
    banner.textContent = `Root access confirmed via su. Whether this device/root method actually permits reading `
        + `raw block devices is unknown until attempted - SELinux enforcing mode can block even root from `
        + `/dev/block/* even when su itself succeeds. A permission-denied failure on the first read is a real, `
        + `distinguishable outcome, not a bug. SELinux mode reported by the device: ${dev.selinux_mode || 'Unknown'}. `
        + `If this is the first root access attempt, check the phone screen for a root-grant prompt.`;
}

async function detectAndroidPhysicalTargets() {
    const dev = _currentlySelectedAndroidDevice();
    const targetSelect = document.getElementById("mobilePhysicalTargetSelect");
    const notesEl = document.getElementById("mobilePhysicalTargetNotes");
    if (!dev || !targetSelect) {
        showToast('Select a connected Android device first.', 'warning');
        return;
    }
    targetSelect.innerHTML = '<option value="">Detecting...</option>';
    if (notesEl) notesEl.style.display = 'none';
    try {
        const res = await fetch(`/api/mobile/android/${encodeURIComponent(dev.serial)}/physical_targets`);
        const data = await res.json();
        if (!data.success) {
            showToast(data.error || 'Failed to detect targets.', 'danger');
            targetSelect.innerHTML = '<option value="">-- Detection failed, try again --</option>';
            return;
        }
        targetSelect.innerHTML = '';
        if (!data.targets.length) {
            targetSelect.innerHTML = '<option value="">-- No targets found - use the manual path below --</option>';
        } else {
            data.targets.forEach((t) => {
                const opt = document.createElement('option');
                opt.value = t.device_path;
                const sizeLabel = t.size_bytes ? `${(t.size_bytes / (1024 ** 3)).toFixed(2)} GB` : 'size unknown';
                opt.textContent = `${t.label} (${t.device_path}, ${sizeLabel})`;
                targetSelect.appendChild(opt);
            });
        }
        if (notesEl && data.notes && data.notes.length) {
            notesEl.textContent = data.notes.join(' ');
            notesEl.style.display = '';
        }
    } catch (err) {
        showToast('Request failed while detecting targets.', 'danger');
        targetSelect.innerHTML = '<option value="">-- Detection failed, try again --</option>';
    }
}

function updateDdrescueStrategyHelp() {
    const sel = document.getElementById("ddrescueStrategySelect");
    const helpText = document.getElementById("ddrescueStrategyHelpText");
    if (!sel || !helpText) return;

    const STRATEGY_HELP = {
        stage1_fast: "Safest first pass - copies everything readable quickly, skipping bad areas rather than dwelling on them. Start here on a failing drive.",
        stage2_trim: "Second pass - carefully narrows in on the edges of bad areas found in the first pass, to recover a bit more without excessive stress on the drive.",
        stage3_intensive: "Third pass - repeatedly retries the toughest bad sectors. Slower and harder on a failing drive, so run this last, after the safer passes.",
        reverse: "Reads the drive back-to-front instead of front-to-back - sometimes recovers data a forward pass missed, especially near the end of a failing drive.",
    };
    helpText.textContent = STRATEGY_HELP[sel.value] || '';
}

function initThroughputGraph() {
    const canvas = document.getElementById('throughputChart');
    if (!canvas) return;

    throughputChart = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: graphLabels,
            datasets: [{
                label: 'Throughput (MB/s)',
                data: graphData,
                borderColor: '#00f2fe',
                backgroundColor: 'rgba(0, 242, 254, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });
}

// --- Dual Pane File Explorer ---
// --- File Explorer: sortable listing table (shared by real-fs and image mode) ---
// One small generic "current listing" pipeline: whoever populates
// #explorerContainer (loadExplorer() for the real filesystem,
// loadExplorerImageDir()/runExplorerImageSearch() for Sleuth Kit image
// browsing) sets explorerActiveRows/explorerActiveRowRenderer/
// explorerRenderUpRow and calls renderExplorerActiveTable() - clicking a
// column header re-sorts and re-renders from the already-fetched array,
// no new request. Timeline results are NOT part of this pipeline - they're
// a genuinely different data shape (MACB events, not files) and keep their
// own dedicated rendering, unchanged.
let explorerSortField = 'name';
let explorerSortDir = 'asc';
let explorerActiveRows = [];          // [{name, size, modified, raw}, ...]
let explorerActiveRowRenderer = null; // (tbody, rawItem) => appends one <tr>
let explorerRenderUpRow = null;       // () => void, appends the context's "Up"/"Back" row, or null for none
let explorerListingExtraCols = [];    // extra non-sortable column labels appended after the standard 6 (File Views only - reset to [] by every other populator)

function buildExplorerListingTable() {
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm table-hover mb-0';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    [['name', 'Name'], ['size', 'Size'], ['modified', 'Modified'], ['accessed', 'Accessed'], ['changed', 'Changed'], ['created', 'Created']].forEach(([field, label]) => {
        const th = document.createElement('th');
        th.className = 'explorer-sort-th';
        th.onclick = () => sortExplorerRows(field);
        let text = label;
        if (explorerSortField === field) text += explorerSortDir === 'asc' ? ' ▲' : ' ▼';
        th.textContent = text;
        headRow.appendChild(th);
    });
    explorerListingExtraCols.forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    tbody.id = 'explorerListBody';
    table.appendChild(tbody);
    return table;
}

function sortExplorerRows(field) {
    if (explorerSortField === field) {
        explorerSortDir = explorerSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        explorerSortField = field;
        explorerSortDir = 'asc';
    }
    renderExplorerActiveTable();
}

function renderExplorerActiveTable() {
    const container = document.getElementById('explorerContainer');
    if (!container || !explorerActiveRowRenderer) return;
    container.innerHTML = '';
    if (explorerRenderUpRow) explorerRenderUpRow();

    if (explorerActiveRows.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'p-2 text-subtle small';
        empty.textContent = '(empty)';
        container.appendChild(empty);
        return;
    }

    const table = buildExplorerListingTable();
    container.appendChild(table);
    const tbody = table.querySelector('#explorerListBody');

    const sorted = explorerActiveRows.slice().sort((a, b) => {
        let av = a[explorerSortField], bv = b[explorerSortField];
        if (av === null || av === undefined) av = '';
        if (bv === null || bv === undefined) bv = '';
        if (typeof av === 'string') av = av.toLowerCase();
        if (typeof bv === 'string') bv = bv.toLowerCase();
        if (av < bv) return explorerSortDir === 'asc' ? -1 : 1;
        if (av > bv) return explorerSortDir === 'asc' ? 1 : -1;
        return 0;
    });
    sorted.forEach(row => explorerActiveRowRenderer(tbody, row.raw));
}

function buildFileTableRow(tbody, item) {
    const tr = document.createElement('tr');
    tr.className = 'file-item';
    tr.dataset.itemPath = item.path; // lets the tree's own file-click handler find and select this exact row

    const nameTd = document.createElement('td');
    const icon = item.is_dir
        ? '<i class="bi bi-folder-fill folder-icon me-2 fs-6"></i>'
        : '<i class="bi bi-file-earmark-text text-info me-2 fs-6"></i>';
    // Filenames come from browsing evidence/suspect media, i.e. they are
    // attacker-controlled data. Build the label from DOM nodes (item.name as
    // a text node) instead of interpolating it into innerHTML, so a crafted
    // filename can't inject markup/script into the examiner's authenticated
    // session.
    const labelSpan = document.createElement('span');
    labelSpan.className = item.is_dir ? 'folder-text' : 'text-light';
    labelSpan.innerHTML = icon; // icon markup is static/trusted, not user data
    labelSpan.appendChild(document.createTextNode(item.name));
    nameTd.appendChild(labelSpan);

    const sizeTd = document.createElement('td');
    sizeTd.className = 'text-subtle font-monospace';
    sizeTd.textContent = item.size_str;

    const modTd = document.createElement('td');
    modTd.className = 'text-subtle font-monospace';
    modTd.textContent = item.modified || '--';

    const accTd = document.createElement('td');
    accTd.className = 'text-subtle font-monospace';
    accTd.textContent = item.accessed || '--';

    const chgTd = document.createElement('td');
    chgTd.className = 'text-subtle font-monospace';
    chgTd.textContent = item.changed || '--';

    const createdTd = document.createElement('td');
    createdTd.className = 'text-subtle font-monospace';
    createdTd.textContent = item.created || '--';

    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);
    tr.appendChild(accTd);
    tr.appendChild(chgTd);
    tr.appendChild(createdTd);

    tr.onclick = () => {
        document.querySelectorAll(`.file-pane .file-item`).forEach(el => el.classList.remove('active'));
        tr.classList.add('active');

        activeSelectedFile = item.path;
        activeSelectedIsDir = item.is_dir;
        explorerDetailsIsImage = false;

        updateContextToolbar(item);
        previewSelectedFile(item);
        refreshExplorerDetailsView();
    };

    tr.ondblclick = () => {
        if (item.is_dir) {
            loadExplorer(item.path);
        } else if (isImageFile(item.name)) {
            enterExplorerImageFor(item);
        }
    };

    tr.oncontextmenu = (ev) => {
        ev.preventDefault();
        showFileContextMenu(ev, item);
        return false;
    };

    tbody.appendChild(tr);
}

// --- File Explorer folder tree (left column) ---
// A single generic, lazily-expanding tree renderer shared by both the real
// filesystem and Sleuth Kit image browsing (see the two adapters below) -
// this app had no tree/hierarchy UI component anywhere before this. Each
// adapter supplies how to fetch a node's children, derive a stable
// cache/DOM key, and what "navigate here" means for that context; the
// renderer itself doesn't know or care which one it's driving.
let explorerTreeChildrenCache = {};      // real-fs: path -> [{path,name}, ...] (folders only)
let explorerImageTreeChildrenCache = {}; // image mode: "img:<inode>" -> [{inode,name}, ...]
let explorerRealTreeRootEl = null;       // persisted <ul> DOM node - kept alive (with full expand state) across an image-mode excursion, not rebuilt on exit
let explorerImageFsRootsCache = {};      // image_path -> [{offset,label}, ...] from /api/image/mmls, so expanding a .dd inline doesn't re-run mmls on every re-expand

// Resolves what an image's root filesystem(s) are: a single pass-through
// entry (no partition table, or exactly one partition - the common case,
// including this project's own primary test image) or one entry per
// partition when there are several. Mirrors the same "no partition table ->
// whole image at offset 0" fallback loadExplorerImagePartitions() already
// uses for the full image-mode toolbar's own partition dropdown - this is
// the inline-tree-nesting equivalent, reusing the same /api/image/mmls route.
// Each root is {offset, label, browsable} - browsable=false marks an
// unallocated/non-filesystem Volume_Info entry (is_allocated=false from
// /api/image/mmls, the same TSK_VS_PART_FLAG_ALLOC check
// _tsk_resolve_filesystems() uses server-side): still shown, Autopsy-style,
// as a plain informational leaf in the tree (real forensic signal - e.g. a
// hidden pre-partition gap), just never offered as something to open as a
// filesystem, which would either error or - worse - risk opening a stale
// filesystem signature left over in space that's no longer really part of
// the evidence's current partition layout.
async function resolveImageFsRoots(imagePath) {
    if (explorerImageFsRootsCache[imagePath]) return explorerImageFsRootsCache[imagePath];
    let roots;
    try {
        const res = await fetch('/api/image/mmls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: imagePath })
        });
        const data = await res.json();
        if (!data.success || !data.partitions || data.partitions.length === 0) {
            roots = [{ offset: 0, label: 'Whole image (offset 0)', browsable: true }];
        } else {
            // Always the full Autopsy-style label (not just the bare
            // description) - the single-real-filesystem, no-unallocated-
            // regions case (the common one) never actually renders this at
            // all, since the fast path below skips straight into folder
            // browsing without showing a partition-level node first; this
            // only becomes visible for a genuinely multi-entry Volume_Info
            // (real partitions and/or unallocated gaps), where the fuller
            // label carries real information.
            roots = data.partitions.map(p => ({
                offset: p.start_sector,
                label: `vol${p.slot} (${p.description}: ${p.start_sector}-${p.end_sector})`,
                browsable: p.is_allocated,
            }));
            // Every entry came back unallocated/unopenable (an unusual
            // partition table, or a format mmls half-understands) - fall
            // back to offering the whole image directly rather than leaving
            // the examiner with nothing they can actually open.
            if (!roots.some(r => r.browsable)) {
                roots.push({ offset: 0, label: 'Whole image (offset 0)', browsable: true });
            }
        }
    } catch (err) {
        roots = [{ offset: 0, label: 'Whole image (offset 0)', browsable: true }];
    }
    explorerImageFsRootsCache[imagePath] = roots;
    return roots;
}

// In-image entry -> tree-node mapping, shared between a freshly-resolved
// filesystem root and any deeper directory inside it - identical filter to
// explorerTreeImageAdapter's own fetchChildren (deleted/virtual directories
// never expandable, same "don't walk a possibly-reallocated inode" rule used
// everywhere else in this app TSK-walks), just additionally carrying
// imageCtx on every child instead of relying on the module-level
// explorerImagePath/explorerImageOffset globals - this is what lets an
// inline-nested image subtree keep working correctly regardless of whatever
// else the examiner does elsewhere in the tree/Listing at the same time.
function mapImageEntriesToNodes(entries, imageCtx) {
    return entries.map(e => ({
        imageCtx, inode: e.inode, name: e.name,
        kind: (e.is_dir && !e.is_virtual && !e.deleted) ? 'dir' : 'file',
        raw: e,
    }));
}

async function fetchImageFls(imageCtx, inode) {
    const res = await fetch('/api/image/fls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_path: imageCtx.image_path, offset: imageCtx.offset, inode: inode || '' })
    });
    const data = await res.json();
    return data.success ? data.entries : [];
}

function explorerTreeRealAdapter() {
    return {
        cache: explorerTreeChildrenCache,
        // Only the real-fs adapter groups disk images into their own
        // section (see appendExplorerTreeChildren) - image-mode browsing
        // and File Views keep their existing plain child order.
        groupDiskImages: true,
        key: (node) => node.imageCtx ? `img:${node.imageCtx.image_path}:${node.imageCtx.offset}:${node.inode}` : (node.id || node.path),
        label: (node) => node.name,
        async fetchChildren(node) {
            // A synthetic group header (kind:'group', see appendExplorerTreeChildren)
            // already has its full, known child-node list in hand - no fetch
            // needed, same as File Views' own static category nodes.
            if (node.staticChildren) return node.staticChildren;
            // In-image node (a resolved filesystem root, or anything deeper inside
            // one) - expands inline as real nested tree children instead of
            // swapping the whole panel to full image mode, using the same
            // /api/image/fls route full image-mode's own tree already uses.
            if (node.imageCtx) {
                try {
                    return mapImageEntriesToNodes(await fetchImageFls(node.imageCtx, node.inode), node.imageCtx);
                } catch (err) {
                    return [];
                }
            }
            // The image FILE itself (.dd/.e01/.aff), first expand - resolve its
            // filesystem(s)/partition layout via mmls. A single real
            // filesystem with no other Volume_Info entries at all (the
            // common case, incl. this project's own primary test images)
            // skips straight to that filesystem's root entries as this
            // node's children, so expanding a typical image goes directly to
            // its real folders with no extra "Partition 1" pseudo-level in
            // between. Anything richer than that (real multi-partition
            // media, or unallocated gaps alongside a single real filesystem)
            // instead shows one child per Volume_Info entry - browsable ones
            // (is_allocated) expand further into that filesystem, non-
            // browsable ones (unallocated/meta placeholder regions) render
            // as plain informational leaves, Autopsy's own Data Sources tree
            // convention, folded into this same inline location instead of
            // a separate top-level section - see resolveImageFsRoots().
            if (node.kind === 'image') {
                try {
                    const roots = await resolveImageFsRoots(node.path);
                    if (roots.length === 1 && roots[0].browsable) {
                        const imageCtx = { image_path: node.path, offset: roots[0].offset };
                        return mapImageEntriesToNodes(await fetchImageFls(imageCtx, ''), imageCtx);
                    }
                    return roots.map(r => r.browsable ? {
                        imageCtx: { image_path: node.path, offset: r.offset },
                        // raw is a synthetic entry-dict-shaped stand-in (no real inode/size -
                        // this node represents "a whole filesystem", not a file or folder
                        // inside one) so context-menu/is_dir-based logic elsewhere doesn't
                        // choke on a null entry if this node is ever right-clicked.
                        inode: '', name: r.label, kind: 'dir',
                        raw: { name: r.label, inode: '', is_dir: true, deleted: false, is_virtual: false, size: null },
                    } : {
                        // Unallocated/non-filesystem region - a real, unique
                        // path-shaped key (not just node.path, which is the
                        // parent image's own path and would collide across
                        // sibling unallocated entries) so tree selection sync
                        // never confuses two of these for each other; no
                        // expand affordance since there's no filesystem here
                        // to open. unallocated:true short-circuits
                        // selectFile()/contextMenu() below to a no-op instead
                        // of treating this synthetic path as a real
                        // selectable/right-clickable file.
                        path: `${node.path}#unalloc-${r.offset}`, name: r.label, kind: 'file', unallocated: true,
                    });
                } catch (err) {
                    return [];
                }
            }
            try {
                const res = await fetch('/api/files/browse', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: node.path })
                });
                const data = await res.json();
                if (data.error) return [];
                // Files are included as leaf nodes (not just folders) so the
                // tree mirrors the full hierarchy, matching Autopsy's Data
                // Sources tree - a recognized forensic image gets its own
                // 'image' kind so it expands inline into its own filesystem
                // (above) instead of a normal real-fs folder expand.
                return data.items.map(it => ({
                    path: it.path,
                    name: it.name,
                    kind: it.is_dir ? 'dir' : (isImageFile(it.name) ? 'image' : 'file'),
                    raw: it,
                }));
            } catch (err) {
                return [];
            }
        },
        navigate: (node, ancestorPath) => {
            if (node.imageCtx || node.kind === 'image') return loadInlineImageDir(node, ancestorPath);
            return loadExplorer(node.path);
        },
        // Clicking a file in the tree now navigates the Listing pane to that file's own folder
        // (not just Details, as this originally shipped) - reported as confusing/broken, since the
        // Listing pane could be showing a completely unrelated directory with no visible connection
        // to the file just selected in the tree. Reuses the exact same row-click code path via a
        // real .click() on the matching <tr> (see buildFileTableRow's data-item-path) rather than
        // duplicating what a click already does.
        selectFile: async (node) => {
            if (node.unallocated) return; // informational-only entry (see fetchChildren's kind==='image' branch) - nothing real to select/preview
            if (node.imageCtx) {
                selectImageBackedFile(node.imageCtx, node.raw);
                return;
            }
            const parentDir = node.raw.path.split('/').slice(0, -1).join('/') || '/';
            if (explorerPath !== parentDir) {
                await loadExplorer(parentDir);
            }
            const row = document.querySelector(`#explorerListBody tr[data-item-path="${CSS.escape(node.raw.path)}"]`);
            if (row) {
                row.click();
            } else {
                // Fallback for the unusual case the file doesn't appear in its own directory's
                // listing (e.g. a stale/filtered view) - Details still updates directly.
                activeSelectedFile = node.raw.path;
                activeSelectedIsDir = false;
                explorerDetailsIsImage = false;
                updateContextToolbar(node.raw);
                previewSelectedFile(node.raw);
                refreshExplorerDetailsView();
            }
            // loadExplorer() above (if it ran) already re-synced the tree's own highlight to the
            // parent DIRECTORY it just navigated to, not this file - move it back onto the file
            // itself so the tree's selection state matches what's actually selected.
            syncExplorerTreeSelection(node.raw.path);
        },
        contextMenu: (ev, node) => {
            if (node.unallocated) return; // informational-only entry - nothing real to act on
            if (node.imageCtx) {
                // showExplorerImageContextMenu() itself sets explorerImageSelected,
                // but the actual action buttons (Extract, Attach to Case, etc.) read
                // explorerImagePath/explorerImageOffset when clicked later, not at
                // menu-open time - repoint those first, same as a real selection would.
                explorerImagePath = node.imageCtx.image_path;
                explorerImageOffset = node.imageCtx.offset;
                showExplorerImageContextMenu(ev, node.raw);
                return;
            }
            showFileContextMenu(ev, node.raw);
        },
    };
}

// Populates the Listing table with an in-image directory's contents WITHOUT
// entering full image mode - reuses the exact same sortable-table pipeline
// (explorerActiveRows/explorerActiveRowRenderer/explorerRenderUpRow/
// renderExplorerActiveTable()) real-fs folders and full image-mode browsing
// both already use, not a third bespoke rendering path. `node` is the
// tree node just navigated to (either the image file itself, kind:'image',
// or a deeper node carrying imageCtx); `ancestorPath` is threaded through
// from the tree renderer the same way real-fs navigation already gets it.
async function loadInlineImageDir(node, ancestorPath) {
    const container = document.getElementById("explorerContainer");
    if (container) container.innerHTML = '<div class="p-2 text-subtle small">Loading...</div>';

    let childNodes;
    try {
        childNodes = await explorerTreeRealAdapter().fetchChildren(node);
    } catch (err) {
        if (container) container.innerHTML = '<div class="p-2 text-danger small">Request failed.</div>';
        return;
    }
    if (!container) return;

    const childAncestors = ancestorPath.concat([node]);

    // "Up" always recurses back through the SAME adapter.navigate() dispatch
    // that got us here - ancestorPath's last entry is either another
    // in-image directory, the image file itself (re-resolves its filesystem
    // root/partition chooser, cached), or - once fully unwound - the real
    // folder the image lives in (a plain 'dir' node with no imageCtx, so
    // navigate() correctly falls through to the ordinary loadExplorer() path).
    // No separate "exit" concept needed - it's the same tree ancestry the
    // real-fs side already threads through for exactly this purpose.
    explorerRenderUpRow = () => {
        const upDiv = document.createElement('div');
        upDiv.className = 'file-item text-warning fw-bold';
        upDiv.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. [Up]';
        const parent = ancestorPath[ancestorPath.length - 1];
        const grandparents = ancestorPath.slice(0, -1);
        upDiv.onclick = () => explorerTreeRealAdapter().navigate(parent, grandparents);
        container.appendChild(upDiv);
    };

    explorerActiveRows = childNodes.map(child => ({
        name: child.raw.name, size: child.raw.size, modified: child.raw.mtime,
        accessed: child.raw.atime, changed: child.raw.ctime, created: child.raw.crtime, raw: child,
    }));
    explorerListingExtraCols = [];
    explorerActiveRowRenderer = (tbody, child) => renderInlineImageEntryRow(tbody, child, childAncestors);
    renderExplorerActiveTable();
}

// Row for one entry inside an inline-nested image directory - reuses
// renderExplorerImageEntryRow()'s visual construction (icon, DELETED badge,
// size/MACB columns) but overrides the click handlers afterward to close
// over this row's own imageCtx instead of the module-level
// explorerImagePath/explorerImageOffset globals renderExplorerImageEntryRow's
// own handlers read - avoids duplicating the DOM-building code for what's
// visually the same row. `childNode` is a tree-node ({imageCtx, inode, name,
// kind, raw}), not a bare entry-dict - `childNode.raw` is what
// renderExplorerImageEntryRow() itself expects.
function renderInlineImageEntryRow(tbody, childNode, childAncestors) {
    renderExplorerImageEntryRow(tbody, childNode.raw);
    const tr = tbody.lastElementChild;
    tr.onclick = () => {
        document.querySelectorAll('.file-pane .file-item').forEach(el => el.classList.remove('active'));
        tr.classList.add('active');
        if (!childNode.raw.is_dir) {
            selectImageBackedFile(childNode.imageCtx, childNode.raw);
        } else {
            // Matches renderExplorerImageEntryRow's own convention: a single
            // click on a folder row just selects/highlights it; double-click
            // (below) descends into it.
            explorerImageSelected = childNode.raw;
            explorerDetailsIsImage = true;
            refreshExplorerDetailsView();
        }
    };
    tr.ondblclick = () => {
        if (childNode.kind === 'dir') {
            explorerTreeRealAdapter().navigate(childNode, childAncestors);
        }
    };
    tr.oncontextmenu = (ev) => {
        ev.preventDefault();
        if (childNode.imageCtx) {
            explorerImagePath = childNode.imageCtx.image_path;
            explorerImageOffset = childNode.imageCtx.offset;
        }
        showExplorerImageContextMenu(ev, childNode.raw);
        return false;
    };
}

function explorerTreeImageAdapter() {
    return {
        cache: explorerImageTreeChildrenCache,
        key: (node) => `img:${node.inode}`,
        label: (node) => node.name,
        async fetchChildren(node) {
            try {
                const res = await fetch('/api/image/fls', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, inode: node.inode })
                });
                const data = await res.json();
                if (!data.success) return [];
                // Files (including deleted/virtual entries, matching what the
                // Listing table already shows with a DELETED badge) are leaf
                // nodes. Deleted/virtual directories are still listed but
                // never expandable - their inode may already be reallocated
                // on a live evidence filesystem, same exclusion this app
                // already applies to recursive TSK walks elsewhere (the
                // hash-manifest/timeline routes).
                return data.entries.map(e => ({
                    inode: e.inode,
                    name: e.name,
                    kind: (e.is_dir && !e.is_virtual && !e.deleted) ? 'dir' : 'file',
                    raw: e,
                }));
            } catch (err) {
                return [];
            }
        },
        navigate: (node, ancestorPath) => {
            explorerImagePathStack = ancestorPath.concat([node]);
            explorerImageView = 'browse';
            loadExplorerImageDir(node.inode);
        },
        selectFile: (node) => {
            explorerImageSelected = node.raw;
            explorerDetailsIsImage = true;
            if (!node.raw.is_dir) previewExplorerImageEntry(node.raw);
            refreshExplorerDetailsView();
        },
        contextMenu: (ev, node) => showExplorerImageContextMenu(ev, node.raw),
    };
}

// Renders one <li> for `node`. `ancestorPath` is the array of nodes from the
// tree root down to (but not including) `node` itself - threaded through so
// image-mode navigation can rebuild explorerImagePathStack without a
// Appends one directory level's children to its <ul>, grouping disk images
// (node.kind === 'image' - a .dd/.e01/.aff, already distinguished from a
// plain file for the double-click/right-click "Browse as Image" behavior)
// into their own visually separated section instead of leaving them
// scattered wherever they happen to fall alphabetically among regular
// files - reported directly by the user from a real case folder where two
// acquired images landed far apart in the list. Real-fs directories only
// (adapter.groupDiskImages, set on explorerTreeRealAdapter() below) - image-
// mode browsing and the File Views tree keep their existing plain order,
// since neither one mixes disk-image files in with regular ones the way a
// real case folder does.
// case_role (core/paths.py's classify_case_role(), passed through on each
// node's raw.case_role) identifies this app's own generated artifacts -
// report exports, hash-manifest/triage-scan logs, KML geolocation files,
// migration backups - which otherwise land wherever they fall
// alphabetically among real evidence files. Grouped into two tree sections,
// not one per case_role - report/analysis_log/backup are all "this app's
// own housekeeping output" from the examiner's point of view and read as
// one section; geolocation (.kml) is visually distinct enough (a map, not a
// log) to warrant its own. Keeping case_role itself more granular than the
// grouping (see core/paths.py) matters for auto-tagging these into the
// case database, even though the tree only needs the coarser split.
const CASE_ROLE_TREE_GROUP = { report: 'artifacts', analysis_log: 'artifacts', backup: 'artifacts', case_bundle: 'artifacts', geolocation: 'geolocation' };

function buildExplorerTreeDivider() {
    const divider = document.createElement('li');
    divider.className = 'explorer-tree-divider';
    return divider;
}

function appendExplorerTreeChildren(ul, children, adapter, ancestorPath) {
    if (!adapter.groupDiskImages) {
        children.forEach(child => ul.appendChild(renderExplorerTreeNode(child, adapter, ancestorPath)));
        return;
    }
    const dirs = children.filter(c => c.kind === 'dir');
    const images = children.filter(c => c.kind === 'image');
    const rest = children.filter(c => c.kind !== 'dir' && c.kind !== 'image');
    const artifacts = rest.filter(c => CASE_ROLE_TREE_GROUP[c.raw?.case_role] === 'artifacts');
    const geolocation = rest.filter(c => CASE_ROLE_TREE_GROUP[c.raw?.case_role] === 'geolocation');
    const plainFiles = rest.filter(c => !CASE_ROLE_TREE_GROUP[c.raw?.case_role]);

    // Real folders and disk images stay flat/immediately visible - they're
    // usually few and are the most directly actionable content (navigate
    // into a folder, browse inside an image). Everything else - this app's
    // own generated artifacts, geolocation exports, and the directory's
    // plain files - is what actually grows long in a real case folder (see
    // the user-reported screenshot: 18 flat rows with no way to collapse
    // any of it), so each of those three becomes one collapsible synthetic
    // group node instead of a flat dump. Reuses the exact same node-
    // rendering/expand-collapse machinery every real folder already has
    // (kind:'group' + staticChildren, mirroring File Views' own static
    // category nodes) - starts collapsed for free, since every tree node
    // already defaults to collapsed until its toggle is clicked.
    const flatGroups = [dirs, images].filter(g => g.length > 0);
    flatGroups.forEach((group, i) => {
        if (i > 0) ul.appendChild(buildExplorerTreeDivider());
        group.forEach(child => ul.appendChild(renderExplorerTreeNode(child, adapter, ancestorPath)));
    });

    const parentKey = ancestorPath.length ? adapter.key(ancestorPath[ancestorPath.length - 1]) : 'root';
    const collapsibleGroups = [
        { items: artifacts, label: 'Case Artifacts', idSuffix: 'artifacts' },
        { items: geolocation, label: 'Geolocation', idSuffix: 'geolocation' },
        { items: plainFiles, label: 'Files', idSuffix: 'files' },
    ].filter(g => g.items.length > 0);

    if (flatGroups.length > 0 && collapsibleGroups.length > 0) ul.appendChild(buildExplorerTreeDivider());
    collapsibleGroups.forEach((g, i) => {
        if (i > 0) ul.appendChild(buildExplorerTreeDivider());
        const groupNode = {
            id: `group:${parentKey}:${g.idSuffix}`,
            name: `${g.label} (${g.items.length})`,
            kind: 'group',
            staticChildren: g.items,
        };
        ul.appendChild(renderExplorerTreeNode(groupNode, adapter, ancestorPath));
    });
}

// separate lookup table. `node.kind` ('dir' | 'image' | 'file') drives icon,
// expand behavior, and click behavior - see the two adapters above for how
// each kind is derived.
function renderExplorerTreeNode(node, adapter, ancestorPath) {
    const li = document.createElement('li');
    li.dataset.treeKey = adapter.key(node);

    const row = document.createElement('div');
    row.className = 'explorer-tree-node';

    const toggle = document.createElement('span');
    toggle.className = 'explorer-tree-toggle';
    toggle.innerHTML = '<i class="bi bi-caret-right-fill"></i>';
    if (node.kind === 'file') toggle.classList.add('no-children'); // leaf, no expand affordance at all

    const icon = document.createElement('i');
    icon.className = node.kind === 'dir'
        ? 'bi bi-folder-fill folder-icon me-1'
        : (node.kind === 'image' ? 'bi bi-hdd-stack text-warning me-1'
            : (node.kind === 'group' ? 'bi bi-collection text-subtle me-1' : 'bi bi-file-earmark-text text-info me-1'));

    const label = document.createElement('span');
    label.className = node.kind === 'dir' ? 'folder-text' : 'text-light';
    label.appendChild(document.createTextNode(adapter.label(node))); // untrusted evidence folder/file name, text-only

    row.appendChild(toggle);
    row.appendChild(icon);
    row.appendChild(label);
    li.appendChild(row);

    let childrenUl = null;
    let expanded = false;

    // Exposed on the element (not just closed over) so external code -
    // syncing the tree to whatever path/inode the table just navigated to -
    // can force an ancestor open without simulating a click.
    li._expand = async function () {
        if (expanded || node.kind === 'file') return;
        // 'image'-kind nodes (a .dd/.e01/.aff) and any node carrying imageCtx
        // (something already inside one) expand inline exactly like a normal
        // folder - the real branching (mmls/fls, single-fs vs multi-partition)
        // lives in explorerTreeRealAdapter's fetchChildren(), not here. Full
        // Sleuth Kit browsing (the dedicated toolbar) is still reached
        // separately, via double-click or "Browse as Image" - unaffected.
        const cacheKey = adapter.key(node);
        let children = adapter.cache[cacheKey];
        if (!children) {
            children = await adapter.fetchChildren(node);
            adapter.cache[cacheKey] = children;
        }
        if (children.length === 0) {
            toggle.classList.add('no-children');
            return;
        }
        if (!childrenUl) {
            childrenUl = document.createElement('ul');
            const nextAncestors = ancestorPath.concat([node]);
            if (node.kind === 'group') {
                // A synthetic group's own children (see appendExplorerTreeChildren's
                // case-role grouping) are already a single homogeneous category -
                // re-running the grouping logic on them would just wrap them in
                // another redundant "Case Artifacts" sub-group instead of finally
                // showing the real files, so render them flatly here instead.
                children.forEach(child => childrenUl.appendChild(renderExplorerTreeNode(child, adapter, nextAncestors)));
            } else {
                appendExplorerTreeChildren(childrenUl, children, adapter, nextAncestors);
            }
            li.appendChild(childrenUl);
        }
        childrenUl.style.display = '';
        toggle.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
        expanded = true;
    };

    toggle.onclick = async (ev) => {
        ev.stopPropagation();
        if (toggle.classList.contains('no-children')) return;
        if (!expanded) {
            await li._expand();
        } else if (childrenUl) {
            childrenUl.style.display = 'none';
            toggle.innerHTML = '<i class="bi bi-caret-right-fill"></i>';
            expanded = false;
        }
    };

    row.onclick = () => {
        // A synthetic group header (see appendExplorerTreeChildren's case-role
        // grouping) is a pure expand/collapse container, not a real
        // file/folder - there's nothing to navigate to or select, and it has
        // no .raw to hand to adapter.selectFile(). Clicking anywhere on the
        // row toggles it, same as clicking just the caret, rather than
        // requiring a precise click on the small toggle icon.
        if (node.kind === 'group') {
            toggle.onclick({ stopPropagation() {} });
            return;
        }
        document.querySelectorAll('#explorerTreeContainer .explorer-tree-node.active').forEach(el => el.classList.remove('active'));
        row.classList.add('active');
        // 'image' nodes and any in-image directory (imageCtx set, kind !== 'file')
        // navigate the Listing table too, matching how a real folder's row
        // already behaves - only true file leaves go to adapter.selectFile().
        if (node.kind === 'dir' || node.kind === 'image') {
            adapter.navigate(node, ancestorPath);
        } else {
            adapter.selectFile(node);
        }
    };

    row.oncontextmenu = (ev) => {
        ev.preventDefault();
        if (node.kind === 'group') return false; // nothing to act on for a synthetic category header
        adapter.contextMenu(ev, node);
        return false;
    };

    return li;
}

// Recursively expands li and every 'dir'-kind descendant it reveals - used
// only for File Views (see initFileViewsTree below), so every category's
// live count (Images (60), Report Export (6), URLs (50), ...) is visible
// the moment File Views loads, AXIOM's "REFINED RESULTS" panel-style,
// instead of requiring a click per level to drill down to each count.
// Cheap here specifically because File Views' non-root dir nodes
// (buildFileViewsHierarchy()'s staticChildren) are pre-computed from the
// one /api/case_index/summary fetch already made for the root - expanding
// them is pure DOM work, no extra network round-trips. Not used for the
// real-fs tree, image-mode tree, or Data Sources - those can have
// arbitrarily many/deep real entries, where a full recursive expand would
// be wasteful (or, for Data Sources' partition lists, actively excessive
// on a large multi-partition image) rather than a free convenience.
async function autoExpandTreeSubtree(li) {
    if (!li || !li._expand) return;
    await li._expand();
    const childUl = li.querySelector(':scope > ul');
    if (!childUl) return;
    for (const childLi of childUl.children) {
        await autoExpandTreeSubtree(childLi);
    }
}

// Case-scoped: rooted at the active case's own folder so the tree only ever
// shows that case's evidence, matching every other job-launcher tab's
// auto-fill; falls back to the full evidence root when no case is selected.
function getExplorerRootPath() {
    return (activeCase && activeCase.case_folder) ? activeCase.case_folder : '/mnt';
}

async function initExplorerTree(forceRebuild) {
    const container = document.getElementById('explorerTreeContainer');
    if (!container) return;
    container.innerHTML = '';
    if (explorerRealTreeRootEl && !forceRebuild) {
        // Re-attach the already-built tree, preserving whatever the examiner
        // had expanded before an image-mode excursion swapped it out - no
        // re-fetch, no lost state.
        container.appendChild(explorerRealTreeRootEl);
    } else {
        explorerTreeChildrenCache = {}; // stale once the root changes (e.g. switching active case)
        const rootUl = document.createElement('ul');
        rootUl.className = 'explorer-tree';
        const rootPath = getExplorerRootPath();
        const rootNode = { path: rootPath, name: rootPath, kind: 'dir' };
        const rootLi = renderExplorerTreeNode(rootNode, explorerTreeRealAdapter(), []);
        rootUl.appendChild(rootLi);
        container.appendChild(rootUl);
        explorerRealTreeRootEl = rootUl;
        await rootLi._expand(); // show top-level contents immediately, matching the initial listing
    }
    // File Views is a second case-wide root sitting alongside the real
    // folder tree (not gated behind first entering one specific image) -
    // appended AFTER the real-fs root so container.querySelector('li')
    // elsewhere (syncExplorerTreeSelection et al) keeps finding the real-fs
    // root first, unaffected by this addition.
    await initFileViewsTree(forceRebuild);
}

async function initExplorerImageTree() {
    const container = document.getElementById('explorerTreeContainer');
    if (!container) return;
    explorerImageTreeChildrenCache = {}; // fresh per image/partition - inode numbering is partition-specific
    container.innerHTML = '';

    // Mirrors the Listing table's own ".. [Up]" row at the image root
    // (explorerImageGoUp() already calls exitExplorerImage() once the path
    // stack is empty) - the tree itself had no way back out of image mode
    // at all, only the toolbar's "Exit Image" button on the opposite side
    // of the screen. Reported live: an examiner navigating primarily via
    // the tree reaches for "Up" in whichever pane they're looking at.
    const exitRow = document.createElement('div');
    exitRow.className = 'explorer-tree-node text-warning fw-bold';
    exitRow.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. Exit Image';
    exitRow.onclick = () => exitExplorerImage();
    container.appendChild(exitRow);

    const rootUl = document.createElement('ul');
    rootUl.className = 'explorer-tree';
    const imageName = explorerImagePath ? explorerImagePath.split('/').pop() : 'Image';
    const rootNode = { inode: '', name: imageName, kind: 'dir' };
    const rootLi = renderExplorerTreeNode(rootNode, explorerTreeImageAdapter(), []);
    rootUl.appendChild(rootLi);
    container.appendChild(rootUl);
    await rootLi._expand();
}

// --- File Views (Autopsy-style analysis index tree) ---
// A second, case-wide tree root mounted alongside the real folder tree
// (see initExplorerTree() above) - By Extension / Deleted Files / Keyword
// Hits, backed by the per-case SQLite index the filesystem-aware Triage
// Scan (and Quick Triage Scan) populate. The tree *shape* is static -
// only the counts are fetched, once, when the root is first expanded.
// Deliberately reuses node.kind 'dir'/'file' from the generic renderer
// unchanged (no new kind value) - a query leaf is just a 'file'-kind node
// carrying an extra queryType/queryCategory the adapter's selectFile()
// reads, so renderExplorerTreeNode() needed zero changes for this.
let explorerFileViewsChildrenCache = {};
let explorerFileViewsTreeRootEl = null;

const FILE_VIEWS_EXTENSION_LABELS = {
    images: 'Images', videos: 'Videos', audio: 'Audio', archives: 'Archives',
    documents: 'Documents', executables: 'Executables', other: 'Other',
};
const FILE_VIEWS_HIT_LABELS = {
    emails: 'Email Addresses', urls: 'URLs', ip_addresses: 'IP Addresses',
    credit_card_numbers: 'Credit Card-like Numbers', phone_numbers: 'Phone Numbers',
};
// Mirrors routes/case_index.py's PARSED_ARTIFACT_TYPE_LABELS - real per-app
// artifact parsing (core/browser_artifacts.py), Chrome/Chromium family + Firefox.
const FILE_VIEWS_WEB_ARTIFACT_LABELS = {
    chrome_history: 'Chrome/Chromium History', chrome_downloads: 'Chrome/Chromium Downloads',
    chrome_bookmarks: 'Chrome/Chromium Bookmarks', chrome_cookies: 'Chrome/Chromium Cookies',
    firefox_history: 'Firefox History', firefox_downloads: 'Firefox Downloads',
    firefox_bookmarks: 'Firefox Bookmarks', firefox_cookies: 'Firefox Cookies',
    registry_recent_docs: 'Registry: Recent Documents', registry_typed_urls: 'Registry: Typed URLs/Paths',
    registry_run_history: 'Registry: Run History', registry_usb_history: 'Registry: USB Device History',
    registry_installed_programs: 'Registry: Installed Programs',
    evtx_logon_success: 'Event Log: Successful Logons', evtx_logon_failure: 'Event Log: Failed Logons',
    evtx_process_creation: 'Event Log: Process Creation', evtx_account_created: 'Event Log: Account Created',
    evtx_service_installed: 'Event Log: Service Installed', evtx_audit_log_cleared: 'Event Log: Audit Log Cleared',
    lnk_shortcut: 'LNK Shortcuts',
    // Follow-up (2026-08-25) - Amcache/Prefetch/Recycle Bin. This is the
    // client-side mirror of routes/case_index.py's PARSED_ARTIFACT_TYPE_
    // LABELS (used here, in Reporting's Web Artifacts gallery, and in the
    // Evidence Timeline's activity-label rendering/CSV export) - a real
    // gap caught live while verifying this exact follow-up: the tree
    // rendered correctly (real counts, real data) but fell back to the
    // raw artifact_type string instead of a readable label everywhere
    // this map is consulted, since only the backend copy had been updated.
    registry_amcache: 'Registry: Amcache Application Inventory',
    prefetch_execution: 'Prefetch: Program Execution',
    recyclebin_deleted_file: 'Recycle Bin: Deleted Files',
    // Linux Artifact Parsing (2026-08-25) - kept in sync with routes/
    // case_index.py's PARSED_ARTIFACT_TYPE_LABELS by hand, same as every
    // entry above (this is the exact class of gap this project's own
    // history already caught once for Amcache/Prefetch/Recycle Bin -
    // updated here proactively this time, not found live a second time).
    linux_shell_history: 'Linux: Shell History',
    linux_passwd_account: 'Linux: /etc/passwd Accounts',
    linux_cron_job: 'Linux: Cron Jobs',
    linux_auth_log: 'Linux: Auth Log (SSH/sudo/session)',
    linux_journald_log: 'Linux: Journal Log (SSH/sudo/session)',
    linux_wtmp_login: 'Linux: Login History (wtmp, Experimental)',
    browser_url_ioc_match: 'Browser: Known-Bad URL Match',
    crypto_wallet_file: 'Cryptocurrency Wallet File',
    mobile_sms_message: 'Mobile: SMS/iMessage',
    mobile_contact: 'Mobile: Contacts',
    mobile_call_log: 'Mobile: Call History',
    // NTFS $MFT / $UsnJrnl parsing (2026-08-30, tool-survey follow-up) -
    // kept in sync with routes/case_index.py's PARSED_ARTIFACT_TYPE_LABELS.
    mft_file_record: 'NTFS: $MFT File Record',
    usnjrnl_change_record: 'NTFS: $UsnJrnl Change Record',
    registry_shellbag: 'Registry: ShellBags (Folder Access)',
    registry_shimcache: 'Registry: Shimcache (Program Execution)',
    email_message: 'Email Message',
};

function buildFileViewsHierarchy(summary) {
    const byExtChildren = Object.keys(FILE_VIEWS_EXTENSION_LABELS).map(cat => ({
        id: `fv-ext-${cat}`, name: `${FILE_VIEWS_EXTENSION_LABELS[cat]} (${summary.by_extension[cat] || 0})`,
        kind: 'file', queryType: 'files', queryCategory: cat,
    }));
    const hitChildren = Object.keys(FILE_VIEWS_HIT_LABELS).map(cat => ({
        id: `fv-hit-${cat}`, name: `${FILE_VIEWS_HIT_LABELS[cat]} (${summary.keyword_hits[cat] || 0})`,
        kind: 'file', queryType: 'hits', queryCategory: cat,
    })).concat((summary.custom_keyword_hits || []).map(h => ({
        // Examiner keyword-list-derived categories (build_scan_patterns() in
        // core/case_index_db.py, 'kw_<list_id>') - dynamically discovered
        // from whatever a scan actually recorded hits under, unlike the 5
        // built-ins above which always render even at 0. case_index_hits()
        // already accepts a 'kw_'-prefixed category, so no other change is
        // needed for these to be clickable/queryable exactly like the
        // built-in ones.
        id: `fv-hit-${h.category}`, name: `${h.label} (${h.count})`,
        kind: 'file', queryType: 'hits', queryCategory: h.category,
    })));
    // A star prefix flags "notable" tags (Autopsy's convention for
    // examiner-flagged evidence of interest) - simple text, not a real icon,
    // so this doesn't need any change to the generic tree renderer's
    // kind-based icon logic.
    const tagChildren = (summary.tags || []).map(t => ({
        id: `fv-tag-${t.id}`, name: `${t.notable ? '★ ' : ''}${t.name} (${t.count})`,
        kind: 'file', queryType: 'tags', tagId: t.id, tagColor: t.color, tagNotable: t.notable,
    }));
    const children = [
        {
            id: 'fv-file-types', name: 'File Types', kind: 'dir',
            staticChildren: [
                { id: 'fv-by-ext', name: 'By Extension', kind: 'dir', staticChildren: byExtChildren },
            ],
        },
        {
            id: 'fv-deleted', name: `Deleted Files (${summary.deleted_files || 0})`, kind: 'file',
            queryType: 'files', queryCategory: '__deleted__',
        },
        {
            id: 'fv-tagged', name: 'Tagged Files', kind: 'dir',
            staticChildren: tagChildren.length ? tagChildren : [
                { id: 'fv-tagged-empty', name: 'No tags yet - right-click a file and choose Tag...', kind: 'file' },
            ],
        },
        {
            id: 'fv-analysis', name: 'Analysis Results', kind: 'dir',
            staticChildren: [
                { id: 'fv-keyword-hits', name: `Keyword Hits (${summary.keyword_hits.total || 0})`, kind: 'dir', staticChildren: hitChildren },
            ],
        },
    ];
    // Only shown once something's actually been parsed (right-click a
    // folder or a whole image -> Parse Browser Artifacts/Registry Hives/
    // Event Logs/LNK) - unlike the 5 built-in keyword-hit categories
    // above, there's no fixed set of artifact_types to always render at
    // 0; which ones exist depends entirely on what's been scanned.
    // Labeled "Parsed Artifacts" (not "Web Artifacts") since browser
    // history/bookmarks/etc. are no longer the only source feeding this
    // category - Registry/Event Log/LNK parsing (Part C) all land here too.
    const parsedCounts = summary.parsed_artifact_counts || {};
    const webArtifactTypes = Object.keys(parsedCounts);
    if (webArtifactTypes.length > 0) {
        children.push({
            id: 'fv-web-artifacts', name: 'Parsed Artifacts', kind: 'dir',
            staticChildren: webArtifactTypes.map(type => ({
                id: `fv-webart-${type}`, name: `${FILE_VIEWS_WEB_ARTIFACT_LABELS[type] || type} (${parsedCounts[type]})`,
                kind: 'file', queryType: 'parsed_artifacts', queryCategory: type,
            })),
        });
    }
    if (!summary.indexed) {
        children.unshift({ id: 'fv-note', name: 'Not indexed yet - run Triage Scan on an image to populate this', kind: 'file' });
    }
    return children;
}

function explorerFileViewsAdapter(caseFolder) {
    return {
        cache: explorerFileViewsChildrenCache,
        key: (node) => node.id,
        label: (node) => node.name,
        async fetchChildren(node) {
            if (node.staticChildren) return node.staticChildren; // static category nodes never fetch
            try {
                const res = await fetch('/api/case_index/summary', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ case_folder: caseFolder })
                });
                const data = await res.json();
                return data.success ? buildFileViewsHierarchy(data) : [];
            } catch (err) {
                return [];
            }
        },
        navigate: () => {}, // 'dir' nodes here are pure category containers, never used - selectFile handles every leaf
        selectFile: (node) => {
            if (node.queryType) runFileViewsQuery(node, caseFolder);
        },
        contextMenu: () => {}, // no context menu on synthetic category/query nodes
    };
}

async function initFileViewsTree(forceRebuild) {
    const container = document.getElementById('explorerTreeContainer');
    if (!container) return;
    if (explorerFileViewsTreeRootEl && !forceRebuild) {
        container.appendChild(explorerFileViewsTreeRootEl);
        return;
    }
    // A forced rebuild (tagging invalidates the tree this way so counts stay
    // current) must remove the OLD section before building a new one -
    // appendChild() alone would just add a second, stale-duplicate File
    // Views section next to the fresh one instead of replacing it.
    if (explorerFileViewsTreeRootEl && explorerFileViewsTreeRootEl.parentNode) {
        explorerFileViewsTreeRootEl.remove();
    }
    explorerFileViewsChildrenCache = {};
    const wrap = document.createElement('div');
    wrap.className = 'explorer-fileviews-section mt-2 pt-2 border-top';

    if (!activeCase || !activeCase.case_folder) {
        const msg = document.createElement('div');
        msg.className = 'text-subtle small px-2 py-1';
        msg.textContent = 'Select or create a case to see File Views.';
        wrap.appendChild(msg);
        container.appendChild(wrap);
        explorerFileViewsTreeRootEl = wrap;
        return;
    }

    const rootUl = document.createElement('ul');
    rootUl.className = 'explorer-tree';
    const rootNode = { id: 'fv-root', name: 'File Views', kind: 'dir' };
    const rootLi = renderExplorerTreeNode(rootNode, explorerFileViewsAdapter(activeCase.case_folder), []);
    rootUl.appendChild(rootLi);
    wrap.appendChild(rootUl);
    container.appendChild(wrap);
    explorerFileViewsTreeRootEl = wrap;
    await autoExpandTreeSubtree(rootLi);
}

// Clicking a File Views leaf category fetches matching rows and renders them
// into the Listing table - reusing the "swap the listing's content, add a
// Back pseudo-row" mechanism the in-image Search feature already proved,
// but via a dedicated renderer (renderFileViewsResults below) since these
// rows carry a per-row image_path/fs_offset (results can span multiple
// images) that the existing directory/search row renderers have no concept of.
async function runFileViewsQuery(node, caseFolder) {
    const container = document.getElementById('explorerContainer');
    if (container) container.innerHTML = '<div class="p-2 text-subtle small">Loading...</div>';
    const endpoint = node.queryType === 'hits' ? '/api/case_index/hits'
        : node.queryType === 'tags' ? '/api/case_index/tagged_files'
        : node.queryType === 'parsed_artifacts' ? '/api/case_index/parsed_artifacts'
        : '/api/case_index/files';
    const body = node.queryType === 'tags'
        ? { case_folder: caseFolder, tag_id: node.tagId }
        : { case_folder: caseFolder, category: node.queryCategory };
    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        // Parsed-artifact rows (a visited URL, a download, a bookmark, a
        // cookie) are structured records, not files - renderFileViewsResults()
        // below reuses the file-Listing pipeline (Name/Size/MACB columns),
        // which doesn't fit this shape at all, so these get their own
        // dedicated renderer instead.
        if (node.queryType === 'parsed_artifacts') {
            renderParsedArtifactsResults(node, data.rows || []);
        } else {
            renderFileViewsResults(node, data.rows || []);
        }
    } catch (err) {
        if (node.queryType === 'parsed_artifacts') {
            renderParsedArtifactsResults(node, []);
        } else {
            renderFileViewsResults(node, []);
        }
    }
}

// Dedicated Listing-pane renderer for parsed browser-artifact records
// (core/browser_artifacts.py) - Title/URL-or-Value/Timestamp/Source columns,
// nothing file-shaped about these rows (no size, no MACB times, some don't
// even have a URL). Reuses the same "swap #explorerContainer's content, add
// a Back pseudo-row" mechanism the in-image Search view already established,
// just with its own table markup instead of routing through
// renderExplorerActiveTable()'s file-row pipeline.
function renderParsedArtifactsResults(node, rows) {
    const container = document.getElementById('explorerContainer');
    if (!container) return;
    container.innerHTML = '';

    const backDiv = document.createElement('div');
    backDiv.className = 'file-item text-warning fw-bold';
    backDiv.innerHTML = '<i class="bi bi-arrow-left me-1"></i>Back to Browse';
    backDiv.onclick = () => loadExplorer(explorerPath);
    container.appendChild(backDiv);

    if (rows.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'p-2 text-subtle small';
        empty.textContent = 'No records found.';
        container.appendChild(empty);
        return;
    }
    container.appendChild(buildParsedArtifactsTable(rows));
}

// Shared Title/URL/Value/Timestamp/Source table builder for parsed browser-
// artifact records (core/browser_artifacts.py) - used by File Explorer's
// File Views results (renderParsedArtifactsResults above) and by
// Reporting's Files tab's own Web Artifacts section
// (renderReportWebArtifactCategory), so the two never drift into two
// different renderings of the same record shape.
function buildParsedArtifactsTable(rows) {
    if (!rows.length) {
        const empty = document.createElement('div');
        empty.className = 'p-2 text-subtle small';
        empty.textContent = 'No records found.';
        return empty;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Title</th><th>URL</th><th>Value</th><th>Timestamp</th><th>Source</th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    rows.forEach(row => {
        const tr = document.createElement('tr');
        [row.title, row.url, row.value].forEach(field => {
            const td = document.createElement('td');
            td.className = 'text-break';
            td.appendChild(document.createTextNode(field || '')); // examiner/evidence-derived, text node only
            tr.appendChild(td);
        });
        const tsTd = document.createElement('td');
        tsTd.className = 'text-subtle font-monospace small';
        tsTd.textContent = row.timestamp ? new Date(row.timestamp * 1000).toLocaleString() : '';
        tr.appendChild(tsTd);
        const srcTd = document.createElement('td');
        srcTd.className = 'text-subtle small';
        srcTd.textContent = row.source_type === 'image' ? (row.image_path || '').split('/').pop() : 'Real filesystem';
        tr.appendChild(srcTd);
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
}

// Routes File Views results through the exact same sortable-Listing pipeline
// (explorerActiveRows/explorerActiveRowRenderer/renderExplorerActiveTable)
// every other Listing view already uses, so results get the identical
// standard Name/Size/Modified/Accessed/Changed/Created columns (with real
// sorting) instead of a bespoke, narrower column set - plus a few extra
// columns (Source Image, and for hits, the matched Value) appended after
// them, since File Views results can span every image indexed in the case,
// something a normal single-directory listing never needs to show.
function renderFileViewsResults(node, rows) {
    explorerRenderUpRow = () => {
        const container = document.getElementById('explorerContainer');
        if (!container) return;
        const backDiv = document.createElement('div');
        backDiv.className = 'file-item text-warning fw-bold';
        backDiv.innerHTML = '<i class="bi bi-arrow-left me-1"></i>Back to Browse';
        backDiv.onclick = () => loadExplorer(explorerPath);
        container.appendChild(backDiv);
    };

    const isHits = node.queryType === 'hits';
    const isTags = node.queryType === 'tags';
    explorerListingExtraCols = isHits ? ['Source Image', 'Value', 'Path']
        : isTags ? ['Source Image', 'Comment', 'Path']
        : ['Source Image', 'Path'];
    explorerActiveRows = rows.map(row => ({
        name: row.name || (row.path ? row.path.split('/').pop() : '(unknown)'),
        size: row.size, modified: row.mtime, accessed: row.atime, changed: row.ctime, created: row.crtime,
        raw: row,
    }));
    explorerActiveRowRenderer = (tbody, row) => renderFileViewsResultRow(tbody, row, node.queryType);
    renderExplorerActiveTable();
}

// One result row - reuses renderExplorerImageEntryRow()'s visual
// construction (icon, DELETED badge, standard MACB columns) exactly like
// renderInlineImageEntryRow() does for inline-nested image browsing, then
// appends the File-Views-specific extra columns and overrides the click/
// right-click handlers to work against this row's own image_path/fs_offset
// (image-backed rows) or its real filesystem path (source_type='real_fs'
// Quick Triage Scan hits, or a real-fs tagged file) instead of whatever the
// shared globals currently point at.
function renderFileViewsResultRow(tbody, row, queryType) {
    const isHits = queryType === 'hits';
    const isTags = queryType === 'tags';
    const name = row.name || (row.path ? row.path.split('/').pop() : '(unknown)');
    const isImageBacked = !!row.image_path;
    const entry = {
        name, is_dir: false, size: row.size !== undefined ? row.size : null,
        deleted: !!row.deleted, is_virtual: false, inode: row.inode,
        mtime: row.mtime, atime: row.atime, ctime: row.ctime, crtime: row.crtime,
        path: row.path || null, // File Views already knows the full in-image path - carry it onto the
                                 // selected entry so anything reading explorerImageSelected later (tagging)
                                 // gets it too, unlike full/inline image-mode browsing which doesn't have one.
    };
    renderExplorerImageEntryRow(tbody, entry, name);
    const tr = tbody.lastElementChild;

    const imgTd = document.createElement('td');
    imgTd.className = 'text-subtle font-monospace';
    imgTd.appendChild(document.createTextNode(isImageBacked ? row.image_path.split('/').pop() : 'Real filesystem'));
    if (isImageBacked) {
        const browseBtn = document.createElement('button');
        browseBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 ms-2';
        browseBtn.title = 'Browse this image';
        browseBtn.innerHTML = '<i class="bi bi-hdd-stack"></i>';
        browseBtn.onclick = (ev) => { ev.stopPropagation(); browseFileViewsResultImage(row.image_path); };
        imgTd.appendChild(browseBtn);
    }
    tr.appendChild(imgTd);

    if (isHits) {
        const valTd = document.createElement('td');
        valTd.className = 'font-monospace text-warning';
        valTd.textContent = row.value; // untrusted evidence content, text node only
        tr.appendChild(valTd);
    }

    if (isTags) {
        const cmtTd = document.createElement('td');
        cmtTd.className = 'text-subtle small';
        cmtTd.textContent = row.comment || ''; // examiner-entered, still a text node only
        tr.appendChild(cmtTd);
    }

    const pathTd = document.createElement('td');
    pathTd.className = 'text-subtle font-monospace small';
    pathTd.textContent = row.path; // untrusted evidence path, text node only
    tr.appendChild(pathTd);

    tr.onclick = () => {
        document.querySelectorAll('.file-pane .file-item').forEach(el => el.classList.remove('active'));
        tr.classList.add('active');
        selectFileViewsResultRow(row, name);
    };

    tr.oncontextmenu = (ev) => {
        ev.preventDefault();
        if (isImageBacked) {
            explorerImagePath = row.image_path;
            explorerImageOffset = row.fs_offset || 0;
            showExplorerImageContextMenu(ev, entry);
        } else {
            showFileContextMenu(ev, { path: row.path, is_dir: false, name });
        }
        return false;
    };

    tbody.appendChild(tr);
}

// Targets Preview/Hex/Metadata at an arbitrary image-backed entry WITHOUT
// entering full image mode - the backend routes behind those panes already
// take image_path/offset per-request (not a server-side "current image"), so
// temporarily pointing the existing explorerImagePath/explorerImageOffset/
// explorerImageSelected globals at this entry's image is enough to reuse
// previewExplorerImageEntry()/loadExplorerImageHexPane()/
// loadExplorerImageMetadataPane() completely unchanged. Shared by File Views
// result rows and inline-nested tree/listing selections (both can point at a
// different image than whatever - if anything - was last browsed in full
// image mode, and this works regardless, since entering image mode for real
// later (enterExplorerImageFor()) always freshly overwrites these same
// globals anyway). `imageCtx` is `{image_path, offset}`; `entry` is whatever
// shape `previewExplorerImageEntry()`/the Hex/Metadata loaders expect
// (inode, name, is_dir, deleted, is_virtual, size - deleted/is_virtual/size
// are optional, matching entries that don't carry them e.g. a triage hit).
function selectImageBackedFile(imageCtx, entry) {
    explorerImagePath = imageCtx.image_path;
    explorerImageOffset = imageCtx.offset || 0;
    explorerImageSelected = entry;
    explorerDetailsIsImage = true;
    if (!entry.is_dir) previewExplorerImageEntry(entry);
    refreshExplorerDetailsView();
}

function selectFileViewsResultRow(row, displayName) {
    if (row.image_path) {
        selectImageBackedFile({ image_path: row.image_path, offset: row.fs_offset || 0 }, {
            inode: row.inode, name: displayName, is_dir: false,
            deleted: !!row.deleted, is_virtual: false,
            size: row.size !== undefined ? row.size : null,
            path: row.path || null,
        });
    } else {
        // source_type 'real_fs' - a Quick Triage Scan hit against a real file,
        // not anything living inside an acquired image.
        activeSelectedFile = row.path;
        activeSelectedIsDir = false;
        explorerDetailsIsImage = false;
        previewSelectedFile({ path: row.path, name: displayName, is_dir: false });
        refreshExplorerDetailsView();
    }
}

// --- Tagging: flag a real-fs or in-image file as evidence of interest
// (Bookmark/Follow Up/Notable Item by default, custom tags supported),
// modeled on Autopsy's tagging feature. Reachable from the "Tag..." button
// in both context-menu groups (real filesystem and in-image), which - since
// File Views results already route through those same two menus - means it
// works identically whether the file was reached by normal browsing, full
// image-mode browsing, inline-nested tree browsing, or a File Views result
// row, with zero per-surface special-casing needed here. ---
let tagItemModalInstance = null;
let currentTagTargetItem = null; // {source_type, image_path, fs_offset, inode, path, name}

// Reads whichever context-menu group is currently showing (set by
// showFileContextMenu()/showExplorerImageContextMenu(), both already called
// before "Tag..." can be clicked) to build the identity descriptor the
// backend's tag endpoints expect - same globals every other context-menu
// action already reads, just assembled into one object here.
function getCurrentTagTargetItem() {
    const imageActionsVisible = document.getElementById('ctxMenuImageActions')?.style.display !== 'none';
    if (imageActionsVisible && explorerImageSelected) {
        return {
            source_type: 'image', image_path: explorerImagePath, fs_offset: explorerImageOffset || 0,
            inode: explorerImageSelected.inode, path: explorerImageSelected.path || null,
            name: explorerImageSelected.name,
        };
    }
    if (activeSelectedFile) {
        return { source_type: 'real_fs', path: activeSelectedFile, name: activeSelectedFile.split('/').pop() };
    }
    return null;
}

async function openTagItemModal() {
    const item = getCurrentTagTargetItem();
    if (!item) return;
    if (!activeCase || !activeCase.case_folder) {
        showToast('Select or create a case before tagging.', 'warning');
        return;
    }
    currentTagTargetItem = item;
    hideFileContextMenu();

    document.getElementById('tagItemFileName').textContent = item.name;
    document.getElementById('tagItemComment').value = '';
    document.getElementById('tagItemModalStatus').textContent = '';
    document.getElementById('newTagName').value = '';
    document.getElementById('newTagNotable').checked = false;
    const formCollapse = document.getElementById('tagItemNewTagForm');
    if (formCollapse && formCollapse.classList.contains('show')) {
        bootstrap.Collapse.getOrCreateInstance(formCollapse).hide();
    }

    if (!tagItemModalInstance) {
        tagItemModalInstance = new bootstrap.Modal(document.getElementById('tagItemModal'));
    }
    tagItemModalInstance.show();
    await refreshTagItemModalList();
}

async function refreshTagItemModalList() {
    const listEl = document.getElementById('tagItemExistingList');
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading tags...</div>';
    try {
        const [summaryRes, itemRes] = await Promise.all([
            fetch('/api/case_index/summary', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_folder: activeCase.case_folder })
            }),
            fetch('/api/case_index/item_tags', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_folder: activeCase.case_folder, ...currentTagTargetItem })
            }),
        ]);
        const summary = await summaryRes.json();
        const itemTagsData = await itemRes.json();
        const appliedTags = itemTagsData.tags || [];
        const appliedIds = new Set(appliedTags.map(t => t.id));
        renderTagItemModalList(summary.tags || [], appliedIds, appliedTags);
    } catch (err) {
        listEl.innerHTML = '<div class="text-danger small p-2">Failed to load tags.</div>';
    }
}

// TEXT_BG_SAFE_COLORS: which Bootstrap contextual colors need dark text for
// readable contrast on this app's dark theme - matches the same small,
// fixed palette ALLOWED_TAG_COLORS (app.py) validates against.
const TAG_LIGHT_TEXT_COLORS = new Set(['warning', 'info', 'success']);

function renderTagItemModalList(allTags, appliedIds, appliedTags) {
    const listEl = document.getElementById('tagItemExistingList');
    listEl.innerHTML = '';
    if (allTags.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No tags defined yet - create one below.</div>';
        return;
    }
    allTags.forEach(tag => {
        const isApplied = appliedIds.has(tag.id);
        const row = document.createElement('div');
        row.className = 'list-group-item bg-dark text-light d-flex justify-content-between align-items-center py-2';

        const left = document.createElement('div');
        const badge = document.createElement('span');
        badge.className = `badge bg-${tag.color} me-2`;
        badge.textContent = tag.notable ? '★' : '•'; // star for notable, bullet otherwise
        left.appendChild(badge);
        left.appendChild(document.createTextNode(tag.name)); // tag names are examiner-entered, text node only
        const countSpan = document.createElement('span');
        countSpan.className = 'text-subtle small ms-2';
        countSpan.textContent = `(${tag.count})`;
        left.appendChild(countSpan);
        if (isApplied) {
            const detail = appliedTags.find(t => t.id === tag.id);
            if (detail && detail.comment) {
                const cmt = document.createElement('div');
                cmt.className = 'text-subtle small mt-1';
                cmt.textContent = detail.comment; // examiner-entered, text node only
                left.appendChild(cmt);
            }
        }
        row.appendChild(left);

        const btn = document.createElement('button');
        btn.className = isApplied ? 'btn btn-sm btn-outline-danger'
            : `btn btn-sm btn-${tag.color} ${TAG_LIGHT_TEXT_COLORS.has(tag.color) ? 'text-dark' : ''}`;
        btn.textContent = isApplied ? 'Remove' : 'Apply';
        btn.onclick = () => isApplied ? removeTagFromCurrentItem(tag.id) : applyTagToCurrentItem(tag.id);
        row.appendChild(btn);

        listEl.appendChild(row);
    });
}

async function applyTagToCurrentItem(tagId) {
    const statusEl = document.getElementById('tagItemModalStatus');
    statusEl.textContent = 'Applying...';
    try {
        const comment = document.getElementById('tagItemComment').value.trim();
        const res = await fetch('/api/case_index/tag_item', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, tag_id: tagId, comment, ...currentTagTargetItem })
        });
        const data = await res.json();
        if (data.success) {
            statusEl.textContent = `Tagged with "${data.tag.name}".`;
            document.getElementById('tagItemComment').value = '';
            await refreshTagItemModalList();
            initFileViewsTree(true);
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function removeTagFromCurrentItem(tagId) {
    const statusEl = document.getElementById('tagItemModalStatus');
    statusEl.textContent = 'Removing...';
    try {
        const res = await fetch('/api/case_index/untag_item', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, tag_id: tagId, ...currentTagTargetItem })
        });
        const data = await res.json();
        if (data.success) {
            statusEl.textContent = 'Tag removed.';
            await refreshTagItemModalList();
            initFileViewsTree(true);
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function createAndApplyNewTag() {
    const nameEl = document.getElementById('newTagName');
    const name = nameEl.value.trim();
    if (!name) { showToast('Enter a tag name first.', 'warning'); return; }
    const color = document.getElementById('newTagColor').value;
    const notable = document.getElementById('newTagNotable').checked;
    const comment = document.getElementById('tagItemComment').value.trim();
    const statusEl = document.getElementById('tagItemModalStatus');
    statusEl.textContent = 'Creating tag...';
    try {
        const res = await fetch('/api/case_index/tag_item', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                case_folder: activeCase.case_folder, new_tag_name: name, new_tag_color: color,
                new_tag_notable: notable, comment, ...currentTagTargetItem
            })
        });
        const data = await res.json();
        if (data.success) {
            statusEl.textContent = `Created and applied "${data.tag.name}".`;
            nameEl.value = '';
            document.getElementById('newTagNotable').checked = false;
            document.getElementById('tagItemComment').value = '';
            await refreshTagItemModalList();
            initFileViewsTree(true);
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

// --- Settings > Case & Reporting > Manage Tags: create/rename/recolor/
// delete tags themselves, distinct from applying them to a file above.
// Tags are per-case data (each case keeps its own tag list in its own
// analysis index), so this section always operates on whichever case is
// currently active rather than being a station-wide default like the rest
// of Case & Reporting - it just shows a "select a case" message otherwise. ---
let manageTagModalInstance = null;
let manageTagModalMode = 'create'; // 'create' | 'edit'
let manageTagModalTagId = null;

async function loadManageTagsSection() {
    const noteEl = document.getElementById('manageTagsCaseNote');
    const listEl = document.getElementById('manageTagsListContainer');
    if (!activeCase || !activeCase.case_folder) {
        noteEl.textContent = 'Select or create a case in the top bar to manage its tags.';
        listEl.innerHTML = '';
        return;
    }
    noteEl.textContent = `Managing tags for: ${activeCase.case_number || activeCase.case_folder.split('/').pop()}`;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading tags...</div>';
    try {
        const res = await fetch('/api/case_index/summary', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder })
        });
        const data = await res.json();
        renderManageTagsList(data.tags || []);
    } catch (err) {
        listEl.innerHTML = '<div class="text-danger small p-2">Failed to load tags.</div>';
    }
}

function renderManageTagsList(tags) {
    const listEl = document.getElementById('manageTagsListContainer');
    listEl.innerHTML = '';
    if (tags.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No tags yet - create one below.</div>';
        return;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Tag</th><th>Notable</th><th>Used</th><th></th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    tags.forEach(tag => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = `badge bg-${tag.color} me-2`;
        badge.innerHTML = '&nbsp;'; // static/trusted markup, a plain color swatch
        nameTd.appendChild(badge);
        nameTd.appendChild(document.createTextNode(tag.name)); // examiner-entered, text node only
        tr.appendChild(nameTd);

        const notableTd = document.createElement('td');
        notableTd.textContent = tag.notable ? '★' : '';
        tr.appendChild(notableTd);

        const countTd = document.createElement('td');
        countTd.className = 'text-subtle';
        countTd.textContent = tag.count;
        tr.appendChild(countTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-end';
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
        editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
        editBtn.title = 'Rename / recolor';
        editBtn.onclick = () => openEditTagModal(tag);
        actionsTd.appendChild(editBtn);
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        if (tag.is_default) {
            delBtn.disabled = true;
            delBtn.title = "Default tags can't be deleted";
        } else {
            delBtn.title = 'Delete tag';
            delBtn.onclick = () => deleteManageTag(tag.id, tag.name);
        }
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listEl.appendChild(table);
}

function openCreateTagModal() {
    if (!activeCase || !activeCase.case_folder) {
        showToast('Select or create a case before managing tags.', 'warning');
        return;
    }
    manageTagModalMode = 'create';
    manageTagModalTagId = null;
    document.getElementById('manageTagModalTitle').textContent = 'New Tag';
    document.getElementById('manageTagName').value = '';
    document.getElementById('manageTagColor').value = 'secondary';
    document.getElementById('manageTagNotable').checked = false;
    document.getElementById('manageTagModalStatus').textContent = '';
    if (!manageTagModalInstance) {
        manageTagModalInstance = new bootstrap.Modal(document.getElementById('manageTagModal'));
    }
    manageTagModalInstance.show();
}

function openEditTagModal(tag) {
    manageTagModalMode = 'edit';
    manageTagModalTagId = tag.id;
    document.getElementById('manageTagModalTitle').textContent = `Edit Tag: ${tag.name}`;
    document.getElementById('manageTagName').value = tag.name;
    document.getElementById('manageTagColor').value = tag.color;
    document.getElementById('manageTagNotable').checked = tag.notable;
    document.getElementById('manageTagModalStatus').textContent = '';
    if (!manageTagModalInstance) {
        manageTagModalInstance = new bootstrap.Modal(document.getElementById('manageTagModal'));
    }
    manageTagModalInstance.show();
}

async function saveManageTagModal() {
    const name = document.getElementById('manageTagName').value.trim();
    const color = document.getElementById('manageTagColor').value;
    const notable = document.getElementById('manageTagNotable').checked;
    const statusEl = document.getElementById('manageTagModalStatus');
    if (!name) { statusEl.textContent = 'Tag name is required.'; return; }
    statusEl.textContent = 'Saving...';
    const endpoint = manageTagModalMode === 'edit' ? '/api/case_index/tags/update' : '/api/case_index/tags/create';
    const body = { case_folder: activeCase.case_folder, name, color, notable };
    if (manageTagModalMode === 'edit') body.tag_id = manageTagModalTagId;
    try {
        const res = await fetch(endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            manageTagModalInstance.hide();
            loadManageTagsSection();
            initFileViewsTree(true);
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function deleteManageTag(tagId, name) {
    if (!confirm(`Delete tag "${name}"? It will be removed from every file it's currently applied to.`)) return;
    try {
        const res = await fetch('/api/case_index/tags/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, tag_id: tagId })
        });
        const data = await res.json();
        if (data.success) {
            loadManageTagsSection();
            initFileViewsTree(true);
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Delete failed: request error.', 'danger');
    }
}

// --- Settings > Case & Reporting > Keyword Lists: station-wide, unlike
// Manage Tags above (which is per-case) - the same CRUD list this section
// edits is read by fetchKeywordLists()/loadRecoveryKeywordListsChecklist()
// (File Recovery's Triage Scan tool) elsewhere in this file. ---
let keywordListModalInstance = null;
let keywordListModalMode = 'create'; // 'create' | 'edit'
let keywordListModalId = null;

async function loadKeywordListsSection() {
    const listEl = document.getElementById('keywordListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading keyword lists...</div>';
    const lists = await fetchKeywordLists(true); // always fresh here - this IS the management view
    renderKeywordListsList(lists);
}

function renderKeywordListsList(lists) {
    const listEl = document.getElementById('keywordListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '';
    if (lists.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No keyword lists yet - create one below.</div>';
        return;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>List</th><th>Terms</th><th>Type</th><th></th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    lists.forEach(l => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.appendChild(document.createTextNode(l.name)); // examiner-entered, text node only
        tr.appendChild(nameTd);

        const countTd = document.createElement('td');
        countTd.className = 'text-subtle';
        countTd.textContent = l.terms.length;
        tr.appendChild(countTd);

        const typeTd = document.createElement('td');
        typeTd.className = 'text-subtle';
        typeTd.textContent = l.is_regex ? 'Regex' : 'Plain text';
        tr.appendChild(typeTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-end';
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
        editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
        editBtn.title = 'Edit';
        editBtn.onclick = () => openEditKeywordListModal(l);
        actionsTd.appendChild(editBtn);
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.title = 'Delete list';
        delBtn.onclick = () => deleteKeywordList(l.id, l.name);
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listEl.appendChild(table);
}

function openCreateKeywordListModal() {
    keywordListModalMode = 'create';
    keywordListModalId = null;
    document.getElementById('keywordListModalTitle').textContent = 'New Keyword List';
    document.getElementById('keywordListName').value = '';
    document.getElementById('keywordListTerms').value = '';
    document.getElementById('keywordListIsRegex').checked = false;
    document.getElementById('keywordListModalStatus').textContent = '';
    if (!keywordListModalInstance) {
        keywordListModalInstance = new bootstrap.Modal(document.getElementById('keywordListModal'));
    }
    keywordListModalInstance.show();
}

function openEditKeywordListModal(list) {
    keywordListModalMode = 'edit';
    keywordListModalId = list.id;
    document.getElementById('keywordListModalTitle').textContent = `Edit Keyword List: ${list.name}`;
    document.getElementById('keywordListName').value = list.name;
    document.getElementById('keywordListTerms').value = list.terms.join('\n');
    document.getElementById('keywordListIsRegex').checked = list.is_regex;
    document.getElementById('keywordListModalStatus').textContent = '';
    if (!keywordListModalInstance) {
        keywordListModalInstance = new bootstrap.Modal(document.getElementById('keywordListModal'));
    }
    keywordListModalInstance.show();
}

async function saveKeywordListModal() {
    const name = document.getElementById('keywordListName').value.trim();
    const terms = document.getElementById('keywordListTerms').value.split('\n').map(t => t.trim()).filter(Boolean);
    const isRegex = document.getElementById('keywordListIsRegex').checked;
    const statusEl = document.getElementById('keywordListModalStatus');
    if (!name) { statusEl.textContent = 'List name is required.'; return; }
    if (terms.length === 0) { statusEl.textContent = 'At least one term is required.'; return; }
    statusEl.textContent = 'Saving...';
    const endpoint = keywordListModalMode === 'edit' ? `/api/settings/keyword_lists/${keywordListModalId}` : '/api/settings/keyword_lists';
    const method = keywordListModalMode === 'edit' ? 'PUT' : 'POST';
    try {
        const res = await fetch(endpoint, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, terms, is_regex: isRegex })
        });
        const data = await res.json();
        if (data.success) {
            keywordListModalInstance.hide();
            keywordListsCache = null; // invalidate - Recovery tab's checklist and this list must both see the change
            loadKeywordListsSection();
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function deleteKeywordList(listId, name) {
    if (!confirm(`Delete keyword list "${name}"? Any past scan results already recorded under it are kept, just no longer selectable for a new scan.`)) return;
    try {
        const res = await fetch(`/api/settings/keyword_lists/${listId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            keywordListsCache = null;
            loadKeywordListsSection();
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Delete failed: request error.', 'danger');
    }
}

// --- Settings > Case & Reporting > Hash Sets (D2) - station-wide known-
// good/known-bad hash sets, mirrors Keyword Lists above structurally.
// Displayed as "Hash Sets" (matching the standard NSRL/EnCase/FTK term for
// this exact concept) - the internal ids/functions/routes below all still
// say hash_list(s), a deliberate display-text-only rename (2026-08-25).
// The management view here always re-fetches fresh (forceRefresh) since
// it IS the management view - fetchHashLists()'s own cache is for the
// lighter-weight consumers (the File Explorer checklist, Hash Manifest's
// in-image checklist). ---
let hashListModalInstance = null;
let hashListModalMode = 'create'; // 'create' | 'edit'
let hashListModalId = null;
let hashListsCache = null;

async function fetchHashLists(forceRefresh) {
    if (hashListsCache && !forceRefresh) return hashListsCache;
    try {
        const res = await fetch('/api/settings/hash_lists');
        const data = await res.json();
        hashListsCache = (data.success && data.lists) || [];
    } catch (err) {
        hashListsCache = [];
    }
    return hashListsCache;
}

async function loadHashListsSection() {
    const listEl = document.getElementById('hashListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading hash lists...</div>';
    const lists = await fetchHashLists(true);
    renderHashListsList(lists);
    loadMalwarebazaarKeyStatus();
}

function renderHashListsList(lists) {
    const listEl = document.getElementById('hashListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '';
    if (lists.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No hash sets yet - create one below.</div>';
        return;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Set</th><th>Algorithm</th><th>Label</th><th>Source</th><th>Hashes</th><th></th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    lists.forEach(l => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.appendChild(document.createTextNode(l.name)); // examiner-entered, text node only
        tr.appendChild(nameTd);

        const algoTd = document.createElement('td');
        algoTd.className = 'text-subtle';
        algoTd.textContent = (l.algorithm || '').toUpperCase();
        tr.appendChild(algoTd);

        const labelTd = document.createElement('td');
        const labelBadge = document.createElement('span');
        labelBadge.className = `badge ${l.label === 'known_good' ? 'bg-success' : 'bg-danger'}`;
        labelBadge.textContent = l.label === 'known_good' ? 'Known Good' : 'Known Bad';
        labelTd.appendChild(labelBadge);
        tr.appendChild(labelTd);

        const sourceTd = document.createElement('td');
        sourceTd.className = 'text-subtle';
        sourceTd.textContent = l.source === 'malwarebazaar_recent' ? 'MalwareBazaar (auto)' : 'Manual';
        tr.appendChild(sourceTd);

        const countTd = document.createElement('td');
        countTd.className = 'text-subtle';
        countTd.textContent = l.hash_count;
        tr.appendChild(countTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-end';
        if (l.source === 'malwarebazaar_recent') {
            const refreshBtn = document.createElement('button');
            refreshBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
            refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i>';
            refreshBtn.title = 'Refresh from MalwareBazaar';
            refreshBtn.onclick = () => refreshMalwarebazaarList();
            actionsTd.appendChild(refreshBtn);
        } else {
            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
            editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
            editBtn.title = 'Edit';
            editBtn.onclick = () => openEditHashListModal(l);
            actionsTd.appendChild(editBtn);
        }
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.title = 'Delete set';
        delBtn.onclick = () => deleteHashList(l.id, l.name);
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listEl.appendChild(table);
}

function openCreateHashListModal() {
    hashListModalMode = 'create';
    hashListModalId = null;
    document.getElementById('hashListModalTitle').textContent = 'New Hash Set';
    document.getElementById('hashListName').value = '';
    document.getElementById('hashListAlgorithm').value = 'sha256';
    document.getElementById('hashListAlgorithm').disabled = false;
    document.getElementById('hashListLabel').value = 'known_bad';
    document.getElementById('hashListHashes').value = '';
    document.getElementById('hashListModalStatus').textContent = '';
    if (!hashListModalInstance) {
        hashListModalInstance = new bootstrap.Modal(document.getElementById('hashListModal'));
    }
    hashListModalInstance.show();
}

function openEditHashListModal(list) {
    hashListModalMode = 'edit';
    hashListModalId = list.id;
    document.getElementById('hashListModalTitle').textContent = `Edit Hash Set: ${list.name}`;
    document.getElementById('hashListName').value = list.name;
    document.getElementById('hashListAlgorithm').value = list.algorithm;
    document.getElementById('hashListAlgorithm').disabled = true; // fixed at creation - every hash already on disk matches it
    document.getElementById('hashListLabel').value = list.label || 'known_bad';
    document.getElementById('hashListHashes').value = '';
    document.getElementById('hashListModalStatus').textContent = '';
    if (!hashListModalInstance) {
        hashListModalInstance = new bootstrap.Modal(document.getElementById('hashListModal'));
    }
    hashListModalInstance.show();
}

async function saveHashListModal() {
    const name = document.getElementById('hashListName').value.trim();
    const algorithm = document.getElementById('hashListAlgorithm').value;
    const label = document.getElementById('hashListLabel').value;
    const hashesText = document.getElementById('hashListHashes').value;
    const statusEl = document.getElementById('hashListModalStatus');
    if (!name) { statusEl.textContent = 'List name is required.'; return; }
    if (hashListModalMode === 'create' && !hashesText.trim()) { statusEl.textContent = 'At least one hash is required.'; return; }
    statusEl.textContent = 'Saving...';
    const endpoint = hashListModalMode === 'edit' ? `/api/settings/hash_lists/${hashListModalId}` : '/api/settings/hash_lists';
    const method = hashListModalMode === 'edit' ? 'PUT' : 'POST';
    const body = { name, label };
    if (hashListModalMode === 'create') {
        body.algorithm = algorithm;
        body.hashes_text = hashesText;
    } else if (hashesText.trim()) {
        body.hashes_text = hashesText; // omitted entirely on an edit that only changes name/label - leaves hashes on disk untouched
    }
    try {
        const res = await fetch(endpoint, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            hashListModalInstance.hide();
            hashListsCache = null; // invalidate - the File Explorer/Hash Manifest checklists and this list must both see the change
            loadHashListsSection();
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function deleteHashList(listId, name) {
    if (!confirm(`Delete hash set "${name}"? This cannot be undone.`)) return;
    try {
        const res = await fetch(`/api/settings/hash_lists/${listId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            hashListsCache = null;
            loadHashListsSection();
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Delete failed: request error.', 'danger');
    }
}

// --- MalwareBazaar (abuse.ch) hash feed for Hash Sets (2026-08-26,
// Linux-DFIR-tools follow-up) - needs a free personal Auth-Key the
// examiner registers themselves at auth.abuse.ch, unlike URLhaus below.
// The key field is a plain <input type=password>, never pre-filled with
// the real value once saved (this app never sends it back down at all -
// GET only ever returns {configured: bool}).
async function loadMalwarebazaarKeyStatus() {
    const statusEl = document.getElementById('malwarebazaarKeyStatus');
    if (!statusEl) return;
    statusEl.textContent = 'Checking...';
    try {
        const res = await fetch('/api/settings/malwarebazaar_key');
        const data = await res.json();
        statusEl.textContent = data.configured
            ? 'Auth-Key configured.'
            : 'No Auth-Key configured yet - get a free one at auth.abuse.ch, then paste it above.';
    } catch (err) {
        statusEl.textContent = 'Could not check Auth-Key status.';
    }
}

async function saveMalwarebazaarKey() {
    const input = document.getElementById('malwarebazaarAuthKey');
    const statusEl = document.getElementById('malwarebazaarKeyStatus');
    const authKey = input.value.trim();
    statusEl.textContent = 'Saving...';
    try {
        const res = await fetch('/api/settings/malwarebazaar_key', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auth_key: authKey })
        });
        const data = await res.json();
        if (data.success) {
            input.value = '';
            showToast(data.configured ? 'MalwareBazaar Auth-Key saved.' : 'MalwareBazaar Auth-Key cleared.', 'success');
            loadMalwarebazaarKeyStatus();
        } else {
            showToast(`Failed to save Auth-Key: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Failed to save Auth-Key: request error.', 'danger');
    }
}

async function refreshMalwarebazaarList() {
    const btn = document.getElementById('btnRefreshMalwarebazaar');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching...'; }
    try {
        const res = await fetch('/api/settings/hash_lists/refresh_malwarebazaar', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast(`MalwareBazaar list refreshed - ${data.list.hash_count} hashes.`, 'success');
        } else {
            showToast(`MalwareBazaar refresh failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('MalwareBazaar refresh failed: request error.', 'danger');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>Import/Refresh MalwareBazaar Recent'; }
        loadHashListsSection();
    }
}

// --- Settings > Case & Reporting > URL Lists (2026-08-26, Linux-DFIR-
// tools follow-up) - station-wide known-bad URL lists, checked
// AUTOMATICALLY (no per-scan checklist, unlike Hash Sets) against every
// URL a browser-artifact scan extracts. Mirrors Hash Sets' management UI
// shape exactly, minus the algorithm concept a plain URL doesn't have. ---
let urlListModalInstance = null;
let urlListModalMode = 'create'; // 'create' | 'edit'
let urlListModalId = null;

async function loadUrlListsSection() {
    const listEl = document.getElementById('urlListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading URL lists...</div>';
    try {
        const res = await fetch('/api/settings/url_lists');
        const data = await res.json();
        renderUrlListsList((data.success && data.lists) || []);
    } catch (err) {
        listEl.innerHTML = '<div class="text-danger small p-2">Failed to load URL lists.</div>';
    }
}

function renderUrlListsList(lists) {
    const listEl = document.getElementById('urlListsListContainer');
    if (!listEl) return;
    listEl.innerHTML = '';
    if (lists.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No URL lists yet - create one, or import URLhaus\'s recent feed, below.</div>';
        return;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>List</th><th>Source</th><th>URLs</th><th>Updated</th><th></th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    lists.forEach(l => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.appendChild(document.createTextNode(l.name)); // examiner-entered, text node only
        tr.appendChild(nameTd);

        const sourceTd = document.createElement('td');
        sourceTd.className = 'text-subtle';
        sourceTd.textContent = l.source === 'urlhaus_recent' ? 'URLhaus (auto)' : 'Manual';
        tr.appendChild(sourceTd);

        const countTd = document.createElement('td');
        countTd.className = 'text-subtle';
        countTd.textContent = l.url_count;
        tr.appendChild(countTd);

        const updatedTd = document.createElement('td');
        updatedTd.className = 'text-subtle';
        updatedTd.textContent = l.updated_at || '';
        tr.appendChild(updatedTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-end';
        if (l.source === 'urlhaus_recent') {
            const refreshBtn = document.createElement('button');
            refreshBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
            refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i>';
            refreshBtn.title = 'Refresh from URLhaus';
            refreshBtn.onclick = () => refreshUrlhausList();
            actionsTd.appendChild(refreshBtn);
        } else {
            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
            editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
            editBtn.title = 'Edit';
            editBtn.onclick = () => openEditUrlListModal(l);
            actionsTd.appendChild(editBtn);
        }
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.title = 'Delete list';
        delBtn.onclick = () => deleteUrlList(l.id, l.name);
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listEl.appendChild(table);
}

function openCreateUrlListModal() {
    urlListModalMode = 'create';
    urlListModalId = null;
    document.getElementById('urlListModalTitle').textContent = 'New URL List';
    document.getElementById('urlListName').value = '';
    document.getElementById('urlListUrls').value = '';
    document.getElementById('urlListModalStatus').textContent = '';
    if (!urlListModalInstance) {
        urlListModalInstance = new bootstrap.Modal(document.getElementById('urlListModal'));
    }
    urlListModalInstance.show();
}

function openEditUrlListModal(list) {
    urlListModalMode = 'edit';
    urlListModalId = list.id;
    document.getElementById('urlListModalTitle').textContent = `Edit URL List: ${list.name}`;
    document.getElementById('urlListName').value = list.name;
    document.getElementById('urlListUrls').value = '';
    document.getElementById('urlListModalStatus').textContent = '';
    if (!urlListModalInstance) {
        urlListModalInstance = new bootstrap.Modal(document.getElementById('urlListModal'));
    }
    urlListModalInstance.show();
}

async function saveUrlListModal() {
    const name = document.getElementById('urlListName').value.trim();
    const urlsText = document.getElementById('urlListUrls').value;
    const statusEl = document.getElementById('urlListModalStatus');
    if (!name) { statusEl.textContent = 'List name is required.'; return; }
    if (urlListModalMode === 'create' && !urlsText.trim()) { statusEl.textContent = 'At least one URL is required.'; return; }
    statusEl.textContent = 'Saving...';
    const endpoint = urlListModalMode === 'edit' ? `/api/settings/url_lists/${urlListModalId}` : '/api/settings/url_lists';
    const method = urlListModalMode === 'edit' ? 'PUT' : 'POST';
    const body = { name };
    if (urlListModalMode === 'create' || urlsText.trim()) {
        body.urls_text = urlsText; // omitted on an edit that only changes the name - leaves URLs on disk untouched
    }
    try {
        const res = await fetch(endpoint, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            urlListModalInstance.hide();
            loadUrlListsSection();
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function deleteUrlList(listId, name) {
    if (!confirm(`Delete URL list "${name}"? This cannot be undone.`)) return;
    try {
        const res = await fetch(`/api/settings/url_lists/${listId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            loadUrlListsSection();
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Delete failed: request error.', 'danger');
    }
}

async function refreshUrlhausList() {
    const btn = document.getElementById('btnRefreshUrlhaus');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching...'; }
    try {
        const res = await fetch('/api/settings/url_lists/refresh_urlhaus', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast(`URLhaus list refreshed - ${data.list.url_count} URLs.`, 'success');
        } else {
            showToast(`URLhaus refresh failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('URLhaus refresh failed: request error.', 'danger');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>Import/Refresh URLhaus Recent'; }
        loadUrlListsSection();
    }
}

// --- Settings > Case & Reporting > YARA Rulesets (D3) - station-wide
// rulesets, mirrors Keyword Lists structurally (rule text stays fully
// inline, unlike Hash Lists' own-file-per-list treatment - see
// core/config.py's load_yara_ruleset_sources() comment for why). ---
let yaraRulesetModalInstance = null;
let yaraRulesetModalMode = 'create'; // 'create' | 'edit'
let yaraRulesetModalId = null;
let yaraRulesetsCache = null;

async function fetchYaraRulesets(forceRefresh) {
    if (yaraRulesetsCache && !forceRefresh) return yaraRulesetsCache;
    try {
        const res = await fetch('/api/settings/yara_rules');
        const data = await res.json();
        yaraRulesetsCache = (data.success && data.rulesets) || [];
    } catch (err) {
        yaraRulesetsCache = [];
    }
    return yaraRulesetsCache;
}

async function loadYaraRulesetsSection() {
    const listEl = document.getElementById('yaraRulesListContainer');
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading YARA rulesets...</div>';
    const rulesets = await fetchYaraRulesets(true);
    renderYaraRulesetsList(rulesets);
}

function renderYaraRulesetsList(rulesets) {
    const listEl = document.getElementById('yaraRulesListContainer');
    if (!listEl) return;
    listEl.innerHTML = '';
    if (rulesets.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No YARA rulesets yet - create one below.</div>';
        return;
    }
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm mb-0';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>Ruleset</th><th></th></tr>'; // static/trusted markup
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    rulesets.forEach(rs => {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        nameTd.appendChild(document.createTextNode(rs.name)); // examiner-entered, text node only
        tr.appendChild(nameTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-end';
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-xs btn-outline-info py-0 px-1 me-1';
        editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
        editBtn.title = 'Edit';
        editBtn.onclick = () => openEditYaraRulesetModal(rs);
        actionsTd.appendChild(editBtn);
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.title = 'Delete ruleset';
        delBtn.onclick = () => deleteYaraRuleset(rs.id, rs.name);
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listEl.appendChild(table);
}

function openCreateYaraRulesetModal() {
    yaraRulesetModalMode = 'create';
    yaraRulesetModalId = null;
    document.getElementById('yaraRulesetModalTitle').textContent = 'New YARA Ruleset';
    document.getElementById('yaraRulesetName').value = '';
    document.getElementById('yaraRulesetText').value = '';
    document.getElementById('yaraRulesetModalStatus').textContent = '';
    if (!yaraRulesetModalInstance) {
        yaraRulesetModalInstance = new bootstrap.Modal(document.getElementById('yaraRulesetModal'));
    }
    yaraRulesetModalInstance.show();
}

function openEditYaraRulesetModal(rs) {
    yaraRulesetModalMode = 'edit';
    yaraRulesetModalId = rs.id;
    document.getElementById('yaraRulesetModalTitle').textContent = `Edit YARA Ruleset: ${rs.name}`;
    document.getElementById('yaraRulesetName').value = rs.name;
    document.getElementById('yaraRulesetText').value = rs.rule_text;
    document.getElementById('yaraRulesetModalStatus').textContent = '';
    if (!yaraRulesetModalInstance) {
        yaraRulesetModalInstance = new bootstrap.Modal(document.getElementById('yaraRulesetModal'));
    }
    yaraRulesetModalInstance.show();
}

async function saveYaraRulesetModal() {
    const name = document.getElementById('yaraRulesetName').value.trim();
    const ruleText = document.getElementById('yaraRulesetText').value;
    const statusEl = document.getElementById('yaraRulesetModalStatus');
    if (!name) { statusEl.textContent = 'Ruleset name is required.'; return; }
    if (!ruleText.trim()) { statusEl.textContent = 'Rule text is required.'; return; }
    statusEl.textContent = 'Compiling and saving...';
    const endpoint = yaraRulesetModalMode === 'edit' ? `/api/settings/yara_rules/${yaraRulesetModalId}` : '/api/settings/yara_rules';
    const method = yaraRulesetModalMode === 'edit' ? 'PUT' : 'POST';
    try {
        const res = await fetch(endpoint, {
            method, headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, rule_text: ruleText })
        });
        const data = await res.json();
        if (data.success) {
            yaraRulesetModalInstance.hide();
            yaraRulesetsCache = null; // invalidate - the File Explorer scan checklist and this list must both see the change
            loadYaraRulesetsSection();
        } else {
            statusEl.textContent = `Failed: ${data.error}`;
        }
    } catch (err) {
        statusEl.textContent = 'Failed: request error.';
    }
}

async function deleteYaraRuleset(rulesetId, name) {
    if (!confirm(`Delete YARA ruleset "${name}"? This cannot be undone.`)) return;
    try {
        const res = await fetch(`/api/settings/yara_rules/${rulesetId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            yaraRulesetsCache = null;
            loadYaraRulesetsSection();
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Delete failed: request error.', 'danger');
    }
}

// --- Cross-Case Search (2026-08-26, gap-closing round) - a station-wide
// hash lookup across every case's own case JSON, not scoped to whichever
// case is currently active. Renders every result via real DOM text nodes
// (never innerHTML) since case_number/examiner/case_folder/evidence_id are
// all examiner-entered content, matching this app's established discipline
// for any examiner/evidence-derived text throughout the frontend. ---
async function runCrossCaseSearch() {
    const input = document.getElementById('crossCaseSearchHash');
    const resultsEl = document.getElementById('crossCaseSearchResults');
    if (!input || !resultsEl) return;
    const hashValue = input.value.trim();
    resultsEl.textContent = '';
    if (!hashValue) {
        resultsEl.appendChild(document.createTextNode('Enter a hash above and click Search.'));
        return;
    }
    resultsEl.appendChild(document.createTextNode('Searching...'));
    try {
        const res = await fetch('/api/cases/cross_search', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hashValue })
        });
        const data = await res.json();
        resultsEl.textContent = '';
        if (!data.success) {
            resultsEl.appendChild(document.createTextNode(`Search failed: ${data.error}`));
            return;
        }
        if (data.results.length === 0) {
            resultsEl.appendChild(document.createTextNode('No matches found in any case on this station.'));
            return;
        }
        const table = document.createElement('table');
        table.className = 'table table-dark table-sm mb-0';
        const thead = document.createElement('thead');
        thead.innerHTML = '<tr><th>Case</th><th>Examiner</th><th>Evidence ID</th><th>Algorithm</th></tr>'; // static/trusted markup
        table.appendChild(thead);
        const tbody = document.createElement('tbody');
        data.results.forEach(r => {
            const tr = document.createElement('tr');
            [r.case_number, r.examiner, r.evidence_id, r.algorithm.toUpperCase()].forEach(val => {
                const td = document.createElement('td');
                td.appendChild(document.createTextNode(val));
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        resultsEl.appendChild(table);
        if (data.truncated) {
            const note = document.createElement('div');
            note.className = 'small text-warning mt-1';
            note.appendChild(document.createTextNode('Results capped - narrow your search or check individual cases directly.'));
            resultsEl.appendChild(note);
        }
    } catch (err) {
        resultsEl.textContent = '';
        resultsEl.appendChild(document.createTextNode('Search failed: request error.'));
    }
}

// --- File Explorer: "Check Against Hash Sets" single-file action (D2) ---
// One modal, two modes (isImage=false real-fs / true in-image) - reads
// whichever selection state (activeSelectedFile / explorerImageSelected)
// is currently active at the moment it's opened, mirroring how the tag/
// verify-hash modals already scope themselves to "whatever was right-
// clicked" rather than tracking a separate target reference.
let hashListCheckModalInstance = null;
let hashListCheckIsImage = false;

async function openHashListCheckModal(isImage) {
    hashListCheckIsImage = isImage;
    const nameEl = document.getElementById('hashListCheckFileName');
    const fileName = isImage ? (explorerImageSelected && explorerImageSelected.name) : (activeSelectedFile && activeSelectedFile.split('/').pop());
    if (nameEl) nameEl.textContent = fileName || '--'; // untrusted (filename) - text node only via textContent
    document.getElementById('hashListCheckResult').innerHTML = '';

    const container = document.getElementById('hashListCheckContainer');
    container.innerHTML = '<span class="text-subtle small">Loading hash lists...</span>';
    const lists = await fetchHashLists();
    container.innerHTML = '';
    if (lists.length === 0) {
        container.innerHTML = '<span class="text-subtle small">No saved hash sets yet - create one in Settings &gt; Case &amp; Reporting &gt; Hash Sets.</span>';
    } else {
        lists.forEach(l => {
            const row = document.createElement('div');
            row.className = 'form-check';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.className = 'form-check-input hash-list-check-cb';
            input.id = `hashListCheckCb_${l.id}`;
            input.value = l.id;
            input.checked = true; // opt-out, not opt-in - the whole point of the action is checking against what's saved
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = input.id;
            label.textContent = `${l.name} (${l.algorithm.toUpperCase()}, ${l.label === 'known_good' ? 'Known Good' : 'Known Bad'}, ${l.hash_count} hash${l.hash_count === 1 ? '' : 'es'})`; // examiner-entered name - text node only
            row.appendChild(input);
            row.appendChild(label);
            container.appendChild(row);
        });
    }

    if (!hashListCheckModalInstance) {
        hashListCheckModalInstance = new bootstrap.Modal(document.getElementById('hashListCheckModal'));
    }
    hashListCheckModalInstance.show();
}

async function runHashListCheck() {
    const resultEl = document.getElementById('hashListCheckResult');
    const hashListIds = Array.from(document.querySelectorAll('.hash-list-check-cb:checked')).map(cb => cb.value);
    if (hashListIds.length === 0) {
        resultEl.innerHTML = '<span class="text-warning">Select at least one hash list.</span>';
        return;
    }
    resultEl.innerHTML = '<span class="text-subtle">Hashing and checking...</span>';

    const endpoint = hashListCheckIsImage ? '/api/image/check_hash_lists' : '/api/files/check_hash_lists';
    const body = hashListCheckIsImage
        ? { image_path: explorerImagePath, offset: explorerImageOffset, inode: explorerImageSelected?.inode, hash_list_ids: hashListIds }
        : { path: activeSelectedFile, hash_list_ids: hashListIds };

    try {
        const res = await fetch(endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) {
            resultEl.innerHTML = '';
            const err = document.createElement('span');
            err.className = 'text-danger';
            err.textContent = data.error; // untrusted, text node only
            resultEl.appendChild(err);
            return;
        }
        resultEl.innerHTML = '';
        const hashesLine = document.createElement('div');
        hashesLine.className = 'text-subtle mb-1';
        hashesLine.textContent = Object.entries(data.computed_hashes).map(([a, h]) => `${a.toUpperCase()}: ${h}`).join('  |  '); // computed hex digests, text node only
        resultEl.appendChild(hashesLine);

        if (data.matches.length === 0) {
            const clean = document.createElement('div');
            clean.className = 'text-success fw-bold';
            clean.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i>No matches - clean against all checked lists.';
            resultEl.appendChild(clean);
        } else {
            data.matches.forEach(m => {
                const line = document.createElement('div');
                line.className = m.label === 'known_good' ? 'text-success fw-bold' : 'text-danger fw-bold';
                const icon = m.label === 'known_good' ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill';
                line.innerHTML = `<i class="bi ${icon} me-1"></i>`; // static/trusted markup
                line.appendChild(document.createTextNode(`MATCH: ${m.list_name} (${m.label === 'known_good' ? 'Known Good' : 'Known Bad'})`)); // examiner-entered list name - text node only
                resultEl.appendChild(line);
            });
        }
    } catch (err) {
        resultEl.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

// --- File Explorer: "Scan with YARA Rules" single-file action (D3) ---
// Same isImage=false/true dual-mode shape as the Hash Sets check modal
// right above - one modal, reads whichever selection state is currently
// active. Unlike the hash-list check (a pure membership test, no analysis-
// history entry), a YARA scan's result IS persisted server-side via
// _record_analysis_result() - matching Binwalk/ClamAV/Strings' own
// per-exhibit analysis-history convention, since case_folder is sent here.
let yaraScanModalInstance = null;
let yaraScanIsImage = false;

async function openYaraScanModal(isImage) {
    yaraScanIsImage = isImage;
    const nameEl = document.getElementById('yaraScanFileName');
    const fileName = isImage ? (explorerImageSelected && explorerImageSelected.name) : (activeSelectedFile && activeSelectedFile.split('/').pop());
    if (nameEl) nameEl.textContent = fileName || '--'; // untrusted (filename) - text node only via textContent
    document.getElementById('yaraScanResult').innerHTML = '';

    const container = document.getElementById('yaraScanContainer');
    container.innerHTML = '<span class="text-subtle small">Loading YARA rulesets...</span>';
    const rulesets = await fetchYaraRulesets();
    container.innerHTML = '';
    if (rulesets.length === 0) {
        container.innerHTML = '<span class="text-subtle small">No saved YARA rulesets yet - create one in Settings &gt; Case &amp; Reporting &gt; YARA Rulesets.</span>';
    } else {
        rulesets.forEach(rs => {
            const row = document.createElement('div');
            row.className = 'form-check';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.className = 'form-check-input yara-scan-cb';
            input.id = `yaraScanCb_${rs.id}`;
            input.value = rs.id;
            input.checked = true; // opt-out, not opt-in - the whole point of the action is scanning against what's saved
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = input.id;
            label.textContent = rs.name; // examiner-entered name - text node only
            row.appendChild(input);
            row.appendChild(label);
            container.appendChild(row);
        });
    }

    if (!yaraScanModalInstance) {
        yaraScanModalInstance = new bootstrap.Modal(document.getElementById('yaraScanModal'));
    }
    yaraScanModalInstance.show();
}

async function runYaraScan() {
    const resultEl = document.getElementById('yaraScanResult');
    const rulesetIds = Array.from(document.querySelectorAll('.yara-scan-cb:checked')).map(cb => cb.value);
    if (rulesetIds.length === 0) {
        resultEl.innerHTML = '<span class="text-warning">Select at least one YARA ruleset.</span>';
        return;
    }
    resultEl.innerHTML = '<span class="text-subtle">Scanning...</span>';

    const endpoint = yaraScanIsImage ? '/api/image/yara_scan' : '/api/files/yara_scan';
    const caseFolder = activeCase ? activeCase.case_folder : null;
    const body = yaraScanIsImage
        ? { image_path: explorerImagePath, offset: explorerImageOffset, inode: explorerImageSelected?.inode,
            name: explorerImageSelected?.name, path: explorerImageSelected?.path || null,
            ruleset_ids: rulesetIds, case_folder: caseFolder }
        : { path: activeSelectedFile, ruleset_ids: rulesetIds, case_folder: caseFolder };

    try {
        const res = await fetch(endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) {
            resultEl.innerHTML = '';
            const err = document.createElement('span');
            err.className = 'text-danger';
            err.textContent = data.error; // untrusted, text node only
            resultEl.appendChild(err);
            return;
        }
        resultEl.innerHTML = '';
        if (data.matches.length === 0) {
            const clean = document.createElement('div');
            clean.className = 'text-success fw-bold';
            clean.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i>No matches against the selected ruleset(s).';
            resultEl.appendChild(clean);
        } else {
            data.matches.forEach(m => {
                const line = document.createElement('div');
                line.className = 'text-danger fw-bold';
                line.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-1"></i>'; // static/trusted markup
                const tagsSuffix = m.tags && m.tags.length ? ` (tags: ${m.tags.join(', ')})` : '';
                line.appendChild(document.createTextNode(`MATCH: ${m.rule} [${m.ruleset_name}]${tagsSuffix}`)); // examiner-entered ruleset/rule names - text node only
                resultEl.appendChild(line);
            });
        }
    } catch (err) {
        resultEl.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

// "Browse this image" - jumps into full Sleuth Kit navigation for the row's
// source image (its root, not deep-linked to the row's own directory/offset -
// a reasonable best-effort for a first pass, not a hard requirement).
function browseFileViewsResultImage(imagePath) {
    if (!imagePath) return;
    enterExplorerImageFor({ path: imagePath });
}

// Expands the tree down to `path` (relative to the real-fs tree's root) and
// highlights the matching node - called from loadExplorer()'s own success
// path, so the tree stays in sync no matter what triggered the navigation
// (tree click, table double-click, Up Directory, error-recovery fallback).
async function syncExplorerTreeSelection(path) {
    const container = document.getElementById('explorerTreeContainer');
    if (!container) return;
    document.querySelectorAll('#explorerTreeContainer .explorer-tree-node.active').forEach(el => el.classList.remove('active'));

    const rootLi = container.querySelector('li');
    if (!rootLi || !rootLi.dataset.treeKey || !path.startsWith(rootLi.dataset.treeKey)) return;

    let currentLi = rootLi;
    let currentPath = rootLi.dataset.treeKey;
    const remainder = path.slice(currentPath.length).split('/').filter(Boolean);

    for (const segment of remainder) {
        currentPath = currentPath.replace(/\/$/, '') + '/' + segment;
        if (currentLi._expand) await currentLi._expand();
        const childLi = currentLi.querySelector(`:scope > ul > li[data-tree-key="${CSS.escape(currentPath)}"]`);
        if (!childLi) { currentLi = null; break; }
        currentLi = childLi;
    }
    if (!currentLi) return;
    const row = currentLi.querySelector(':scope > .explorer-tree-node');
    if (row) row.classList.add('active');
}

// Same idea for image mode - explorerImagePathStack already IS the full
// ancestor-plus-current-directory chain by the time loadExplorerImageDir()
// finishes (see its own comment), so no separate path param is needed here.
async function syncExplorerImageTreeSelection() {
    const container = document.getElementById('explorerTreeContainer');
    if (!container) return;
    document.querySelectorAll('#explorerTreeContainer .explorer-tree-node.active').forEach(el => el.classList.remove('active'));

    const rootLi = container.querySelector('li');
    if (!rootLi) return;

    let currentLi = rootLi;
    for (const node of explorerImagePathStack) {
        if (currentLi._expand) await currentLi._expand();
        const childLi = currentLi.querySelector(`:scope > ul > li[data-tree-key="img:${CSS.escape(node.inode)}"]`);
        if (!childLi) { currentLi = null; break; }
        currentLi = childLi;
    }
    if (!currentLi) return;
    const row = currentLi.querySelector(':scope > .explorer-tree-node');
    if (row) row.classList.add('active');
}

function toggleExplorerTreeCol() {
    const col = document.getElementById('explorerTreeCol');
    if (col) col.classList.toggle('explorer-tree-shown');
}

// Called from applyActiveCaseToFields() whenever the active case changes
// after the page's initial load (create/select a different case) - re-roots
// an already-built tree/table to the new case folder. Deliberately a no-op
// on the very first page load (explorerRealTreeRootEl is still null then) -
// DOMContentLoaded's own initial initExplorerTree()/loadExplorer() calls
// already build correctly rooted the first time, since they run after
// initActiveCaseBar() has resolved activeCase.
function resyncExplorerRootToActiveCase() {
    if (!explorerRealTreeRootEl) return;
    const newRoot = getExplorerRootPath();
    const currentRootLi = explorerRealTreeRootEl.querySelector('li');
    const currentRoot = currentRootLi ? currentRootLi.dataset.treeKey : null;
    if (currentRoot === newRoot) return; // already scoped correctly
    initExplorerTree(true);
    loadExplorer(newRoot);
}

async function loadExplorer(path) {
    const container = document.getElementById('explorerContainer');
    const pathLabel = document.getElementById('explorerPath');
    if (!container) return;

    try {
        const res = await fetch('/api/files/browse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        const data = await res.json();

        if (data.error) {
            container.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'p-2 text-danger small';
            errDiv.textContent = data.error;
            container.appendChild(errDiv);

            // Don't leave the browser stuck on a dead end - fall back to
            // the last known-good path rather than requiring a full page
            // reload to recover. This is the common case when "Up
            // Directory" is clicked from the evidence root itself, which
            // correctly tries to go outside the permitted directory and
            // gets refused.
            if (path !== explorerPath) {
                setTimeout(() => loadExplorer(explorerPath), 1200);
            }
            return;
        }

        explorerPath = data.path;
        if (pathLabel) pathLabel.innerText = data.path;

        // With a case active, the case folder is the effective floor for "Up Directory" - stepping
        // out of it landed the examiner in /mnt with no indication they'd left the case at all
        // (reported directly: "up directory... takes me out of the case which should not happen
        // unless i'm not connected to a case"). No case active still browses the full evidence root
        // as before - this boundary only exists once a case is actually selected.
        const atCaseRoot = activeCase && activeCase.case_folder && data.path === activeCase.case_folder;
        explorerRenderUpRow = (data.path !== '/' && !atCaseRoot) ? () => {
            const upDiv = document.createElement('div');
            upDiv.className = 'file-item text-warning fw-bold';
            upDiv.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. [Up Directory]';
            upDiv.onclick = () => {
                const parent = data.path.split('/').slice(0, -1).join('/') || '/';
                loadExplorer(parent);
            };
            container.appendChild(upDiv);
        } : null;

        explorerActiveRows = data.items.map(item => ({
            name: item.name, size: item.size_bytes, modified: item.modified,
            accessed: item.accessed, changed: item.changed, created: item.created, raw: item
        }));
        explorerListingExtraCols = [];
        explorerActiveRowRenderer = buildFileTableRow;
        renderExplorerActiveTable();

        syncExplorerTreeSelection(data.path);

    } catch (err) {
        container.innerHTML = `<div class="p-2 text-danger small">Error loading files</div>`;
    }
}

// --- Shared KML viewer (File Explorer's Preview pane + Reporting's Files gallery modal) ---
// Parses simple KML - as generated by this app's own _build_geo_kml(), and
// reasonably tolerant of other well-formed KML an examiner might open - into
// {name, description, lat, lon} placemarks. Returns [] on malformed input
// rather than throwing, since a hostile/corrupt KML file from a suspect
// drive shouldn't crash the viewer.
function parseKmlPlacemarks(kmlText) {
    const placemarks = [];
    try {
        const doc = new DOMParser().parseFromString(kmlText, 'application/xml');
        if (doc.querySelector('parsererror')) return placemarks;
        doc.querySelectorAll('Placemark').forEach(pm => {
            const coordsEl = pm.querySelector('Point > coordinates');
            if (!coordsEl) return;
            const parts = coordsEl.textContent.trim().split(',');
            const lon = parseFloat(parts[0]);
            const lat = parseFloat(parts[1]);
            if (!isFinite(lat) || !isFinite(lon)) return;
            placemarks.push({
                name: pm.querySelector('name')?.textContent?.trim() || '',
                description: pm.querySelector('description')?.textContent?.trim() || '',
                lat, lon,
            });
        });
    } catch (err) {
        // fall through, return whatever was collected (possibly empty)
    }
    return placemarks;
}

// textContent -> innerHTML round-trip is the standard safe way to get an
// HTML-escaped string for APIs (like Leaflet's bindPopup()) that take raw
// HTML rather than a DOM node - placemark name/description come from a KML
// file that may not have been generated by this app (an examiner can open
// any .kml), so this can't rely on the file's own source already being
// escaped the way this app's own _build_geo_kml() output already is.
function escapeHtmlForPopup(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

// Renders a Leaflet map (one marker per placemark, fit to bounds) into
// `container`, plus a plain placemark table underneath that's always shown
// regardless of whether the map itself could render - this app already
// depends on CDN-loaded Bootstrap/Chart.js the same way (see the <head>),
// so a missing Leaflet/map-tile connection isn't a new dependency class,
// just another instance of the same one, and the raw coordinate data stays
// accessible either way.
function _createGeoTileLayer() {
    // If install.py's optional offline OSM tile cache step was run and found tiles
    // (window.OFFLINE_TILES set from app.py's manifest read), prefer live OpenStreetMap tiles when
    // reachable but silently fall back to the local cache per-tile on a load error - this is what
    // makes the map still show real imagery on a station that's actually offline, while still
    // showing fresher/wider live tiles whenever a connection IS available (e.g. a laptop reviewing
    // the same case remotely over a real internet connection). maxZoom stays a normal 19 either way
    // (zoom controls aren't restricted by what happens to be cached) - tiles beyond the offline
    // cache's own max_zoom just render blank if both the live fetch and the fallback come up empty,
    // same graceful-degradation the placemark table below the map already covers.
    const onlineUrl = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
    const attribution = '&copy; OpenStreetMap contributors';
    const offlineInfo = (typeof window.OFFLINE_TILES !== 'undefined') ? window.OFFLINE_TILES : null;

    if (!offlineInfo || !offlineInfo.max_zoom) {
        return L.tileLayer(onlineUrl, { attribution, maxZoom: 19 });
    }

    const offlineMaxZoom = offlineInfo.max_zoom;
    const OfflineFallbackTileLayer = L.TileLayer.extend({
        createTile: function (coords, done) {
            const tile = document.createElement('img');
            const localUrl = coords.z <= offlineMaxZoom
                ? L.Util.template('/static/vendor/osm_tiles/{z}/{x}/{y}.png', coords)
                : null;
            tile.onload = function () { done(null, tile); };
            tile.onerror = function () {
                if (localUrl && tile.src !== location.origin + localUrl) {
                    tile.onerror = function () { done(null, tile); }; // no further fallback - blank tile
                    tile.src = localUrl;
                } else {
                    done(null, tile);
                }
            };
            tile.src = this.getTileUrl(coords);
            return tile;
        }
    });
    return new OfflineFallbackTileLayer(onlineUrl, { attribution, maxZoom: 19 });
}

function renderVol3ResultTable(container, jsonText, truncated) {
    container.innerHTML = '';
    let rows;
    try {
        rows = JSON.parse(jsonText);
    } catch (err) {
        const bad = document.createElement('div');
        bad.className = 'text-danger small p-2';
        // A large result (e.g. filescan/handles on a busy system) can
        // exceed /api/files/preview_text's 200KB read cap, which cuts the
        // JSON off mid-byte rather than mid-row - that's a truncated-read
        // failure, not a corrupt file, so say so rather than implying
        // something is wrong with the file itself.
        bad.textContent = truncated
            ? 'This result is larger than the inline preview limit and cannot be rendered as a table here - the file itself is complete on disk.'
            : 'Could not parse this file as JSON.';
        container.appendChild(bad);
        return;
    }
    if (!Array.isArray(rows) || rows.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'text-subtle small p-2';
        empty.textContent = 'No rows in this Volatility3 result.';
        container.appendChild(empty);
        return;
    }

    // __children is Volatility3's own internal tree-structure field (used
    // by hierarchical plugins like pstree) - not meaningful as a flat table
    // column, so it's excluded here rather than shown as a raw nested blob.
    const columns = Object.keys(rows[0]).filter(k => k !== '__children');

    const wrap = document.createElement('div');
    wrap.style.overflowX = 'auto';
    const table = document.createElement('table');
    table.className = 'table table-sm table-dark table-striped mb-0';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    columns.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col; // text-node only - evidence-derived, never innerHTML
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach(row => {
        const tr = document.createElement('tr');
        columns.forEach(col => {
            const td = document.createElement('td');
            const val = row[col];
            td.textContent = (val === null || val === undefined) ? '' : (typeof val === 'object' ? JSON.stringify(val) : String(val));
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    container.appendChild(wrap);

    const note = document.createElement('div');
    note.className = 'text-subtle small p-1';
    note.textContent = `${rows.length} row(s)` + (truncated ? ' (file is larger than the preview limit - truncated)' : '');
    container.insertBefore(note, wrap);
}

function renderKmlViewer(container, kmlText, mapHeightCss) {
    container.innerHTML = '';
    const placemarks = parseKmlPlacemarks(kmlText);

    if (placemarks.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'text-subtle small p-2';
        empty.textContent = 'No placemarks found in this KML file.';
        container.appendChild(empty);
        return;
    }

    if (typeof L !== 'undefined') {
        const mapDiv = document.createElement('div');
        mapDiv.style.height = mapHeightCss || '280px';
        mapDiv.style.width = '100%';
        mapDiv.className = 'mb-2 rounded';
        container.appendChild(mapDiv);
        try {
            const map = L.map(mapDiv);
            _createGeoTileLayer().addTo(map);
            const bounds = [];
            placemarks.forEach(p => {
                const marker = L.marker([p.lat, p.lon]).addTo(map);
                marker.bindPopup(`<b>${escapeHtmlForPopup(p.name || '(unnamed)')}</b><br>${escapeHtmlForPopup(p.description)}`);
                bounds.push([p.lat, p.lon]);
            });
            if (bounds.length === 1) {
                map.setView(bounds[0], 14);
            } else {
                map.fitBounds(bounds, { padding: [20, 20] });
            }
            // A map created while its container is still mid-transition (e.g.
            // inside a Bootstrap modal that's still fading in) can compute the
            // wrong size and render broken/blank - a fresh invalidateSize()
            // once the container has settled fixes it in both this pane's
            // always-visible context and the modal's fade-in context.
            requestAnimationFrame(() => setTimeout(() => map.invalidateSize(), 50));
        } catch (err) {
            mapDiv.remove();
            const failMsg = document.createElement('div');
            failMsg.className = 'text-subtle small p-2';
            failMsg.textContent = 'Map could not be rendered - showing the placemark list below.';
            container.appendChild(failMsg);
        }
    } else {
        const noLeaflet = document.createElement('div');
        noLeaflet.className = 'text-subtle small p-2';
        noLeaflet.textContent = 'Map library unavailable (no internet connection?) - showing placemark list only.';
        container.appendChild(noLeaflet);
    }

    const table = document.createElement('table');
    table.className = 'table table-sm table-dark table-striped mb-0';
    const tbody = document.createElement('tbody');
    placemarks.forEach(p => {
        const row = document.createElement('tr');
        const nameCell = document.createElement('td');
        nameCell.className = 'text-info fw-bold text-nowrap';
        nameCell.textContent = p.name || '(unnamed)'; // untrusted KML content - text node only
        const coordCell = document.createElement('td');
        coordCell.className = 'font-monospace text-nowrap';
        coordCell.textContent = `${p.lat.toFixed(6)}, ${p.lon.toFixed(6)}`;
        const descCell = document.createElement('td');
        descCell.className = 'text-subtle small';
        descCell.textContent = p.description; // untrusted KML content - text node only
        row.appendChild(nameCell);
        row.appendChild(coordCell);
        row.appendChild(descCell);
        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    container.appendChild(table);
}

async function previewSelectedFile(item) {
    const preview = document.getElementById('explorerPreview');
    if (!preview) return;

    const dbBtn = document.getElementById('explorerViewDatabaseBtn');
    if (dbBtn) {
        const showDb = !item.is_dir && isSqliteFile(item.name);
        dbBtn.style.display = showDb ? '' : 'none';
        // Switching away from a .db to a non-.db file while Database was
        // the active view would otherwise leave a stale table browser
        // showing - fall back to Preview, matching every other view's own
        // "selection changed underneath me" handling.
        if (!showDb && explorerRightView === 'database') switchExplorerRightView('preview');
    }

    if (item.is_dir) {
        preview.innerHTML = '';
        const icon = document.createElement('i');
        icon.className = 'bi bi-folder-fill fs-1 text-warning mb-2';
        const label = document.createElement('span');
        label.className = 'text-subtle small';
        label.textContent = `${item.name} (folder) - double-tap to open`;
        preview.appendChild(icon);
        preview.appendChild(label);
        return;
    }

    const ext = '.' + (item.name.split('.').pop() || '').toLowerCase();
    const IMAGE_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
    const PDF_EXT = ['.pdf'];
    const HTML_EXT = ['.html', '.htm'];
    const KML_EXT = ['.kml'];
    const TEXT_EXT = ['.txt', '.json', '.log', '.md', '.csv', '.xml', '.py', '.js', '.sh', '.conf', '.ini', '.cfg', '.yaml', '.yml'];

    preview.innerHTML = '<span class="text-subtle small">Loading preview...</span>';

    if (IMAGE_EXT.includes(ext)) {
        preview.innerHTML = '';
        preview.className = 'file-pane p-2';
        const img = document.createElement('img');
        img.src = `/api/files/raw?path=${encodeURIComponent(item.path)}`;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '100%';
        img.style.objectFit = 'contain';
        img.alt = item.name; // filename is untrusted, but alt text isn't rendered as markup - safe as a plain attribute value
        preview.appendChild(img);
        return;
    }

    if (PDF_EXT.includes(ext)) {
        // Browser's own built-in PDF viewer renders this - no script-execution surface on
        // this app's origin, unlike HTML below, so a plain iframe pointed at the raw file is fine.
        preview.innerHTML = '';
        preview.className = 'file-pane p-0';
        const iframe = document.createElement('iframe');
        iframe.src = `/api/files/raw?path=${encodeURIComponent(item.path)}`;
        iframe.style.width = '100%';
        iframe.style.height = '100%';
        iframe.style.border = 'none';
        iframe.title = 'PDF preview';
        preview.appendChild(iframe);
        return;
    }

    if (HTML_EXT.includes(ext)) {
        // Rendered visually, but deliberately NOT via a raw same-origin URL (no route serves
        // raw HTML as text/html - see get_raw_file()'s comment in app.py). Content comes from
        // the same JSON-only preview_text endpoint plain text files use, then is set as
        // srcdoc on a fully sandboxed iframe (sandbox="" - no allow-scripts, no
        // allow-same-origin, no allow-forms/popups) so a hostile HTML file from a suspect
        // drive can render its layout for review with zero ability to execute script, read
        // this app's cookies/session, or navigate anywhere.
        try {
            const res = await fetch('/api/files/preview_text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: item.path })
            });
            const data = await res.json();
            preview.innerHTML = '';
            if (!data.success) {
                preview.className = 'file-pane p-2 d-block text-start';
                const errSpan = document.createElement('span');
                errSpan.className = 'text-danger small';
                errSpan.textContent = `[ERROR] ${data.error}`;
                preview.appendChild(errSpan);
                return;
            }
            preview.className = 'file-pane p-0';
            const iframe = document.createElement('iframe');
            iframe.setAttribute('sandbox', '');
            iframe.srcdoc = data.content;
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            iframe.style.backgroundColor = '#fff';
            iframe.title = 'HTML preview (sandboxed, scripts disabled)';
            preview.appendChild(iframe);
            if (data.truncated) {
                const note = document.createElement('div');
                note.className = 'text-subtle small p-1';
                note.textContent = 'Note: file is larger than the preview limit, rendered content is truncated.';
                preview.appendChild(note);
            }
        } catch (err) {
            preview.innerHTML = '<span class="text-danger small">Preview failed to load.</span>';
        }
        return;
    }

    if (KML_EXT.includes(ext)) {
        try {
            const res = await fetch('/api/files/preview_text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: item.path })
            });
            const data = await res.json();
            preview.innerHTML = '';
            preview.className = 'file-pane p-2 d-block text-start';
            if (!data.success) {
                const errSpan = document.createElement('span');
                errSpan.className = 'text-danger small';
                errSpan.textContent = `[ERROR] ${data.error}`;
                preview.appendChild(errSpan);
                return;
            }
            renderKmlViewer(preview, data.content);
        } catch (err) {
            preview.innerHTML = '<span class="text-danger small">Preview failed to load.</span>';
        }
        return;
    }

    // A Volatility3 memory-forensics result file (checked before the
    // generic TEXT_EXT/.json fallback below, so this renderer wins) -
    // rendered as a real dynamic-column table instead of a raw JSON dump,
    // since each plugin's own row shape (pslist's PID/PPID/ImageFileName
    // vs. netscan's LocalAddr/ForeignAddr/State/Owner) varies too much for
    // any one fixed column set.
    if (/_vol3_\w+\.json$/i.test(item.name)) {
        try {
            const res = await fetch('/api/files/preview_text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: item.path })
            });
            const data = await res.json();
            preview.innerHTML = '';
            preview.className = 'file-pane p-2 d-block text-start';
            if (!data.success) {
                const errSpan = document.createElement('span');
                errSpan.className = 'text-danger small';
                errSpan.textContent = `[ERROR] ${data.error}`;
                preview.appendChild(errSpan);
                return;
            }
            renderVol3ResultTable(preview, data.content, data.truncated);
        } catch (err) {
            preview.innerHTML = '<span class="text-danger small">Preview failed to load.</span>';
        }
        return;
    }

    if (TEXT_EXT.includes(ext)) {
        try {
            const res = await fetch('/api/files/preview_text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: item.path })
            });
            const data = await res.json();
            preview.innerHTML = '';
            preview.className = 'file-pane p-2 d-block text-start';
            const pre = document.createElement('pre');
            pre.className = 'log-window mb-0';
            pre.style.height = '100%';
            pre.textContent = data.success ? (data.content + (data.truncated ? '\n\n[... truncated, file is larger than the preview limit ...]' : '')) : `[ERROR] ${data.error}`;
            preview.appendChild(pre);
        } catch (err) {
            preview.innerHTML = '<span class="text-danger small">Preview failed to load.</span>';
        }
        return;
    }

    // Fallback: no inline preview for this type - just show file info.
    preview.innerHTML = '';
    preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
    const icon = document.createElement('i');
    icon.className = 'bi bi-file-earmark fs-1 text-subtle mb-2';
    const nameSpan = document.createElement('div');
    nameSpan.className = 'text-light small fw-bold mb-1';
    nameSpan.textContent = item.name;
    const sizeSpan = document.createElement('div');
    sizeSpan.className = 'text-subtle small';
    sizeSpan.textContent = `${item.size_str} - no inline preview for this file type. Use Actions for Metadata, Strings, etc.`;
    preview.appendChild(icon);
    preview.appendChild(nameSpan);
    preview.appendChild(sizeSpan);
}

// --- Right-click / press-and-hold context menu ---
// One menu element, two mutually exclusive action sets swapped in/out by
// display toggling (#ctxMenuRealActions vs #ctxMenuImageActions) - a real
// filesystem item gets the full action list, a virtual entry inside an
// image (Image Browser mode) only gets Extract, since Metadata/Binwalk/
// ClamAV/etc. all need a real path on disk to operate on.
let contextMenuTargetItem = null;

function toggleCtxMenuSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    const toggle = document.querySelector(`.ctx-menu-section-toggle[data-ctx-section="${sectionId}"]`);
    const expanded = section.style.display !== 'none';
    section.style.display = expanded ? 'none' : '';
    if (toggle) toggle.classList.toggle('expanded', !expanded);
}

function resetCtxMenuSections(rootId) {
    const root = document.getElementById(rootId);
    if (!root) return;
    root.querySelectorAll('.ctx-menu-section').forEach(section => { section.style.display = 'none'; });
    root.querySelectorAll('.ctx-menu-section-toggle').forEach(toggle => { toggle.classList.remove('expanded'); });
}

function positionContextMenu(ev) {
    const menu = document.getElementById('fileContextMenu');
    if (!menu) return;
    const x = ev.clientX || (ev.touches && ev.touches[0] && ev.touches[0].clientX) || 0;
    const y = ev.clientY || (ev.touches && ev.touches[0] && ev.touches[0].clientY) || 0;
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.style.display = 'block';

    // The menu has grown a lot of items over time (image/case actions,
    // whole-image shortcuts, analyze tools, file operations) and can now be
    // taller than a short viewport (the 480px kiosk touchscreen especially)
    // or wider/taller than whatever's left of a normal window below/right
    // of the click point. Clamp its position after it's actually rendered
    // (so real dimensions are known) so it opens fully reachable instead of
    // partially or entirely off-screen with no way to scroll to the rest -
    // the CSS max-height/overflow-y on #fileContextMenu is the backstop for
    // the case where even a fully top-aligned menu is still taller than the
    // whole viewport.
    const margin = 8;
    const rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
        menu.style.left = `${Math.max(margin, window.innerWidth - rect.width - margin)}px`;
    }
    if (rect.bottom > window.innerHeight) {
        menu.style.top = `${Math.max(margin, window.innerHeight - rect.height - margin)}px`;
    }
}

function showFileContextMenu(ev, item) {
    contextMenuTargetItem = item;
    // Right-click also selects the item, so the same actions used
    // elsewhere in File Explorer work correctly here too.
    activeSelectedFile = item.path;
    activeSelectedIsDir = item.is_dir;
    updateContextToolbar(item);

    const realActions = document.getElementById('ctxMenuRealActions');
    const imageActions = document.getElementById('ctxMenuImageActions');
    if (realActions) realActions.style.display = '';
    if (imageActions) imageActions.style.display = 'none';
    resetCtxMenuSections('ctxMenuRealActions');
    positionContextMenu(ev);
}

function showExplorerImageContextMenu(ev, entry) {
    explorerImageSelected = entry;
    const realActions = document.getElementById('ctxMenuRealActions');
    const imageActions = document.getElementById('ctxMenuImageActions');
    if (realActions) realActions.style.display = 'none';
    if (imageActions) imageActions.style.display = '';
    const extractBtn = document.getElementById('ctxMenuImageExtract');
    if (extractBtn) extractBtn.disabled = entry.is_dir;
    const attachBtn = document.getElementById('ctxMenuImageAttach');
    if (attachBtn) attachBtn.disabled = entry.is_dir || !activeCase;
    const tagBtn = document.getElementById('ctxMenuImageTag');
    if (tagBtn) tagBtn.disabled = entry.is_dir || !activeCase;
    const binwalkBtn = document.getElementById('ctxMenuImageBinwalk');
    if (binwalkBtn) binwalkBtn.disabled = entry.is_dir;
    const fuzzyHashBtn = document.getElementById('ctxMenuImageFuzzyHash');
    if (fuzzyHashBtn) fuzzyHashBtn.disabled = entry.is_dir;
    const stringsBtn = document.getElementById('ctxMenuImageStrings');
    if (stringsBtn) stringsBtn.disabled = entry.is_dir;
    const lnkBtn = document.getElementById('ctxMenuImageLnk');
    if (lnkBtn) {
        const isLnk = !entry.is_dir && (entry.name || '').toLowerCase().endsWith('.lnk');
        lnkBtn.style.display = isLnk ? '' : 'none';
    }
    const mftBtn = document.getElementById('ctxMenuImageMft');
    if (mftBtn) {
        const isMft = !entry.is_dir && (entry.name || '').toUpperCase() === '$MFT';
        mftBtn.style.display = isMft ? '' : 'none';
    }
    const usnjrnlBtn = document.getElementById('ctxMenuImageUsnjrnl');
    if (usnjrnlBtn) {
        const upperName = (entry.name || '').toUpperCase();
        const isUsnjrnl = !entry.is_dir && (upperName === '$J' || upperName.includes('USNJRNL'));
        usnjrnlBtn.style.display = isUsnjrnl ? '' : 'none';
    }
    resetCtxMenuSections('ctxMenuImageActions');
    positionContextMenu(ev);
}

function hideFileContextMenu() {
    const menu = document.getElementById('fileContextMenu');
    if (menu) menu.style.display = 'none';
}

document.addEventListener('click', (ev) => {
    const menu = document.getElementById('fileContextMenu');
    if (menu && menu.style.display === 'block' && !menu.contains(ev.target)) {
        hideFileContextMenu();
    }
});

// The menu borrows Bootstrap's `dropdown-menu` class for styling only - it's a plain
// position:fixed div, not a real Bootstrap Dropdown instance. Bootstrap's own global
// keydown data-api handler still tries to treat any `.dropdown-menu`-classed element as
// one of its managed instances on Escape and throws (no toggle element to look up), and
// never closes the menu either. Handle Escape ourselves, in the capture phase, so our
// hide-and-stopPropagation runs before Bootstrap's own document-level listener sees it.
document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Escape') return;
    const menu = document.getElementById('fileContextMenu');
    if (menu && menu.style.display === 'block') {
        hideFileContextMenu();
        ev.stopPropagation();
    }
}, true);

document.addEventListener('DOMContentLoaded', () => {
    const copyBtn = document.getElementById('contextMenuCopyBtn');
    const deleteBtn = document.getElementById('contextMenuDeleteBtn');
    const extractBtn = document.getElementById('ctxMenuImageExtract');
    if (copyBtn) copyBtn.onclick = () => { hideFileContextMenu(); promptCopySelected(); };
    if (deleteBtn) deleteBtn.onclick = () => { hideFileContextMenu(); deleteSelectedFile(); };
    if (extractBtn) extractBtn.onclick = () => { hideFileContextMenu(); extractExplorerImageSelected(); };
});

function updateContextToolbar(item) {
    const btnDelete = document.getElementById("btnDeleteFile");
    const btnCopy = document.getElementById("btnCopyFile");
    const btnBrowseImage = document.getElementById("btnBrowseImage");
    const btnUnlockEncVolImage = document.getElementById("btnUnlockEncVolImage");
    const btnVerifyHash = document.getElementById("btnVerifyHash");
    const btnConvertImageFormat = document.getElementById("btnConvertImageFormat");
    const btnAttachToCase = document.getElementById("btnAttachToCase");
    const btnTagFile = document.getElementById("btnTagFile");
    const btnRecoverFromImage = document.getElementById("btnRecoverFromImage");
    const btnBinwalk = document.getElementById("btnRunBinwalk");
    const btnClamscan = document.getElementById("btnRunClamscan");
    const btnStrings = document.getElementById("btnRunStrings");
    const btnQuickTriage = document.getElementById("btnQuickTriageScan");
    const btnHashdeep = document.getElementById("btnRunHashdeep");
    const btnCheckHashLists = document.getElementById("btnCheckHashLists");
    const btnFuzzyHash = document.getElementById("btnFuzzyHash");
    const btnRunYaraScan = document.getElementById("btnRunYaraScan");
    const btnGeolocation = document.getElementById("btnExtractGeolocation");
    const btnBrowserArtifacts = document.getElementById("btnParseBrowserArtifacts");
    const btnRegistryHives = document.getElementById("btnParseRegistryHives");
    const btnEvtxLogs = document.getElementById("btnParseEvtxLogs");
    const btnPrefetch = document.getElementById("btnParsePrefetch");
    const btnRecycleBin = document.getElementById("btnParseRecycleBin");
    const btnLinuxArtifacts = document.getElementById("btnParseLinuxArtifacts");
    const btnCryptoWallets = document.getElementById("btnParseCryptoWallets");
    const btnEmailArtifacts = document.getElementById("btnParseEmailArtifacts");
    const btnMobileArtifacts = document.getElementById("btnParseMobileArtifacts");
    const btnLeappScan = document.getElementById("btnLeappScan");
    const btnParseLnk = document.getElementById("btnParseLnk");
    const btnAnalyzeMft = document.getElementById("btnAnalyzeMft");
    const btnParseUsnjrnl = document.getElementById("btnParseUsnjrnl");
    const btnSqliteDissect = document.getElementById("btnSqliteDissect");
    const btnApkAnalyze = document.getElementById("btnApkAnalyze");
    const btnWhatsappDecrypt = document.getElementById("btnWhatsappDecrypt");
    const btnIpaAnalyze = document.getElementById("btnIpaAnalyze");
    const btnBugreportParse = document.getElementById("btnBugreportParse");
    const btnMvtIos = document.getElementById("btnRunMvtIos");
    const btnMvtAndroid = document.getElementById("btnRunMvtAndroid");
    const btnMemoryForensics = document.getElementById("btnMemoryForensics");
    const btnAutoAnalyze = document.getElementById("btnAutoAnalyze");

    if (btnDelete) btnDelete.disabled = false;
    if (btnCopy) btnCopy.disabled = false;
    if (btnBinwalk) btnBinwalk.disabled = item.is_dir;
    if (btnStrings) btnStrings.disabled = item.is_dir;
    if (btnQuickTriage) btnQuickTriage.disabled = item.is_dir;
    if (btnClamscan) btnClamscan.disabled = false;        // works on either a file or a directory (-r)
    if (btnHashdeep) btnHashdeep.disabled = !item.is_dir;  // recursive manifest - needs a directory
    if (btnCheckHashLists) btnCheckHashLists.disabled = item.is_dir;  // single-file, like Verify Image Hash
    if (btnFuzzyHash) btnFuzzyHash.disabled = item.is_dir;  // single-file, like Check Against Hash Sets
    if (btnRunYaraScan) btnRunYaraScan.disabled = item.is_dir;  // single-file, like Check Against Hash Sets
    if (btnGeolocation) btnGeolocation.disabled = !item.is_dir;  // scans a whole folder of photos at once
    if (btnBrowserArtifacts) btnBrowserArtifacts.disabled = !item.is_dir;  // recursively walks a folder for Chrome/Chromium + Firefox profile files
    if (btnRegistryHives) btnRegistryHives.disabled = !item.is_dir;    // recursively walks a folder for NTUSER.DAT/SYSTEM/SOFTWARE
    if (btnEvtxLogs) btnEvtxLogs.disabled = !item.is_dir;              // recursively walks a folder for .evtx files
    if (btnPrefetch) btnPrefetch.disabled = !item.is_dir;              // recursively walks a folder for .pf files
    if (btnRecycleBin) btnRecycleBin.disabled = !item.is_dir;          // recursively walks a folder for $Recycle.Bin/$I* files
    if (btnLinuxArtifacts) btnLinuxArtifacts.disabled = !item.is_dir;  // recursively walks a folder for Linux artifact files
    if (btnCryptoWallets) btnCryptoWallets.disabled = !item.is_dir;  // recursively walks a folder for wallet files
    if (btnEmailArtifacts) btnEmailArtifacts.disabled = !item.is_dir;  // recursively walks a folder for .eml/.mbox/.pst/.ost files
    if (btnMobileArtifacts) btnMobileArtifacts.disabled = !item.is_dir;  // scans a folder for an iOS backup (Manifest.db + Info.plist)
    if (btnLeappScan) btnLeappScan.disabled = !item.is_dir;  // runs ALEAPP/iLEAPP against an extraction folder
    if (btnParseLnk) btnParseLnk.disabled = item.is_dir || !item.name.toLowerCase().endsWith('.lnk');  // single-file, unlike the whole-folder scanners above
    if (btnAnalyzeMft) btnAnalyzeMft.disabled = item.is_dir || item.name.toUpperCase() !== '$MFT';  // single-file, exact-filename match
    if (btnParseUsnjrnl) btnParseUsnjrnl.disabled = item.is_dir || !(item.name.toUpperCase() === '$J' || item.name.toUpperCase().includes('USNJRNL'));  // single-file, already-extracted stream
    if (btnSqliteDissect) btnSqliteDissect.disabled = item.is_dir || !isSqliteFile(item.name);
    if (btnApkAnalyze) btnApkAnalyze.disabled = item.is_dir || !item.name.toLowerCase().endsWith('.apk');
    if (btnWhatsappDecrypt) btnWhatsappDecrypt.disabled = item.is_dir || !/\.(crypt12|crypt14|crypt15)$/i.test(item.name);
    if (btnIpaAnalyze) btnIpaAnalyze.disabled = item.is_dir || !item.name.toLowerCase().endsWith('.ipa');
    if (btnBugreportParse) btnBugreportParse.disabled = item.is_dir || !item.name.toLowerCase().endsWith('.zip');
    if (btnMvtIos) btnMvtIos.disabled = !item.is_dir;      // mvt check-backup needs a backup directory
    if (btnMvtAndroid) btnMvtAndroid.disabled = !item.is_dir;
    if (btnMemoryForensics) btnMemoryForensics.disabled = item.is_dir || !isMemoryImageFile(item.name);
    // Any folder (a potential mobile backup - detection gracefully falls
    // back to "pick manually" if it doesn't recognize the shape) or any
    // recognized disk/memory image file - never enabled for an unrelated
    // plain file, since Auto Analyze has nothing to detect/run against one.
    if (btnAutoAnalyze) btnAutoAnalyze.disabled = !(item.is_dir || isImageFile(item.name) || isMemoryImageFile(item.name));
    if (btnBrowseImage) btnBrowseImage.disabled = item.is_dir || !isImageFile(item.name);
    if (btnUnlockEncVolImage) btnUnlockEncVolImage.disabled = item.is_dir || !isImageFile(item.name);
    if (btnVerifyHash) btnVerifyHash.disabled = item.is_dir;
    if (btnConvertImageFormat) btnConvertImageFormat.disabled = item.is_dir || !isImageFile(item.name);
    if (btnAttachToCase) btnAttachToCase.disabled = item.is_dir || !activeCase;
    if (btnTagFile) btnTagFile.disabled = item.is_dir || !activeCase;
    if (btnRecoverFromImage) btnRecoverFromImage.disabled = item.is_dir || !isImageFile(item.name);

    // Whole-Image Analysis shortcuts - same gate as Browse as Image, since
    // each of these just enters full image mode first (see
    // contextMenuBrowseImageAnd()) before running its own tool.
    const wholeImageDisabled = item.is_dir || !isImageFile(item.name);
    ['btnEnterSearchImage', 'btnEnterTimelineImage', 'btnEnterGeoImage', 'btnEnterHashImage',
     'btnEnterTriageImage', 'btnEnterBrowserArtifactsImage', 'btnEnterRegistryImage', 'btnEnterEvtxImage',
     'btnEnterPrefetchImage', 'btnEnterRecycleBinImage', 'btnEnterLinuxArtifactsImage',
     'btnEnterEmailImage', 'btnEnterRecoverImage'].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = wholeImageDisabled;
    });
}

// Right-click "Whole-Image Analysis" shortcuts: enters full Sleuth Kit image
// mode for the right-clicked .dd/E01/AFF (exactly like double-clicking it,
// or "Browse as Image") and then immediately runs the requested tool -
// closing the gap where these tools only worked once already browsing
// inside an image, previously reachable only via the toolbar shown there.
// Awaits enterExplorerImageFor() (which now returns its own partition/
// initial-directory load) before running the follow-up action - Search and
// Timeline render their own view into #explorerContainer, and firing them
// before that load resolves would just have them get silently overwritten
// a moment later when the initial directory listing finishes loading.
async function contextMenuBrowseImageAnd(action) {
    if (!contextMenuTargetItem) return;
    hideFileContextMenu();
    await enterExplorerImageFor(contextMenuTargetItem);
    const actions = {
        search: explorerImageToggleSearch,
        timeline: explorerImageToggleTimeline,
        geo: runImageGeolocationExport,
        hash: runImageHashManifest,
        triage: startImageTriageScan,
        browserartifacts: runImageBrowserArtifactsParse,
        registryhives: runImageRegistryParse,
        evtxlogs: runImageEvtxParse,
        prefetch: runImagePrefetchParse,
        recyclebin: runImageRecycleBinParse,
        linuxartifacts: runImageLinuxArtifactsParse,
        cryptowallets: runImageCryptoWalletParse,
        email: runImageEmailParse,
        mobileartifacts: runImageMobileArtifactsParse,
        recover: runImageRecoverDeleted,
    };
    if (actions[action]) actions[action]();
}

function promptCopySelected() {
    if (!activeSelectedFile) return;
    openFolderModal('copyDestination');
}

async function performCopyTo(sourcePath, destDir) {
    try {
        const res = await fetch('/api/files/copy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: sourcePath, destination_dir: destDir })
        });
        const data = await res.json();
        if (data.success) {
            loadExplorer(explorerPath);
        } else {
            showToast(`Copy failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        console.error("Error copying file:", err);
    }
}

async function deleteSelectedFile() {
    if (!activeSelectedFile) return;
    if (!confirm(`Are you sure you want to delete ${activeSelectedFile}?`)) return;

    try {
        const res = await fetch('/api/files/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile })
        });
        const data = await res.json();
        if (data.success) {
            activeSelectedFile = null;
            const preview = document.getElementById('explorerPreview');
            if (preview) {
                preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
                preview.innerHTML = '<i class="bi bi-cursor fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file on the left to preview it here.</span>';
            }
            switchExplorerRightView('preview');
            loadExplorer(explorerPath);
        } else {
            showToast(`Delete failed: ${data.error}`, 'danger');
        }
    } catch (err) {}
}

// --- File Metadata Viewer (ExifTool) ---
// Lives inline in File Explorer's right panel as a second view alongside
// Preview (#explorerPreview / #explorerMetadata, toggled by
// switchExplorerRightView()) rather than a modal - switching files while
// the Metadata view is active re-fetches automatically, same as Preview
// already does.
let explorerRightView = 'preview'; // 'preview' | 'hex' | 'metadata'
// Which Hex/Metadata loader the current selection needs - real-fs or
// in-image. Deliberately NOT the same thing as explorerImageMode: File Views
// selects an image-backed file (see selectFileViewsResultRow()) without ever
// entering full image-mode browsing, so refreshExplorerDetailsView() can't
// use explorerImageMode to decide which loader to call. Every selection
// point below sets this explicitly.
let explorerDetailsIsImage = false;

// Both panes can carry Bootstrap's .d-flex utility in their className at
// various points (the default placeholder state, and previewSelectedFile()'s
// is_dir branch never resets className at all) - .d-flex is !important in
// Bootstrap, which silently beats a plain inline style.display='none' (the
// same gotcha already documented elsewhere in this project re: the Image
// Browser toolbar). Hiding must go through setProperty(..., 'important') to
// reliably win regardless of whichever classes happen to be on the element
// at toggle time; showing just clears the inline override entirely.
function setPaneVisible(el, visible) {
    if (!el) return;
    if (visible) el.style.removeProperty('display');
    else el.style.setProperty('display', 'none', 'important');
}

function switchExplorerRightView(view) {
    explorerRightView = view;
    const previewPane = document.getElementById('explorerPreview');
    const hexPane = document.getElementById('explorerHex');
    const metadataPane = document.getElementById('explorerMetadata');
    const databasePane = document.getElementById('explorerDatabase');
    const previewBtn = document.getElementById('explorerViewPreviewBtn');
    const hexBtn = document.getElementById('explorerViewHexBtn');
    const metadataBtn = document.getElementById('explorerViewMetadataBtn');
    const databaseBtn = document.getElementById('explorerViewDatabaseBtn');
    setPaneVisible(previewPane, view === 'preview');
    setPaneVisible(hexPane, view === 'hex');
    setPaneVisible(metadataPane, view === 'metadata');
    setPaneVisible(databasePane, view === 'database');
    if (previewBtn) previewBtn.className = `btn btn-xs py-0 px-2 ${view === 'preview' ? 'btn-info' : 'btn-outline-info'}`;
    if (hexBtn) hexBtn.className = `btn btn-xs py-0 px-2 ${view === 'hex' ? 'btn-info' : 'btn-outline-info'}`;
    if (metadataBtn) metadataBtn.className = `btn btn-xs py-0 px-2 ${view === 'metadata' ? 'btn-info' : 'btn-outline-info'}`;
    if (databaseBtn) databaseBtn.className = `btn btn-xs py-0 px-2 ${view === 'database' ? 'btn-info' : 'btn-outline-info'}`;
    // Preview doesn't need a load call here - previewSelectedFile()/
    // previewExplorerImageEntry() already populated it at selection time.
    // Hex/Metadata are fetched lazily instead, so switching to either one
    // (after selecting a file while looking at Preview) needs its own load.
    refreshExplorerDetailsView();
}

// Single dispatcher for "the currently selected file changed, or the
// examiner switched tabs - make sure whichever non-Preview view is active
// shows current data" - called both from switchExplorerRightView() and from
// every selection point (table row click, tree click, timeline click, File
// Views result row) in both real-fs and image mode, instead of each of those
// call sites repeating its own `if (explorerRightView === 'x') loadY()`
// check. Branches on explorerDetailsIsImage, NOT explorerImageMode - see
// that variable's own comment for why they're not interchangeable.
function refreshExplorerDetailsView() {
    if (explorerRightView === 'hex') {
        if (explorerDetailsIsImage) loadExplorerImageHexPane();
        else loadExplorerHexPane();
    } else if (explorerRightView === 'metadata') {
        if (explorerDetailsIsImage) loadExplorerImageMetadataPane();
        else loadExplorerMetadataPane();
    } else if (explorerRightView === 'database') {
        if (explorerDetailsIsImage) loadExplorerImageDatabasePane();
        else loadExplorerDatabasePane();
    }
}

// Renders a base64 byte payload as a classic offset/hex/ASCII dump (xxd-
// style, 16 bytes/row) - shared by the real-fs and in-image hex loaders
// below. Formatting happens client-side so both backend routes can just
// hand back raw base64 bytes, matching how image_preview() already does
// for image data rather than doing layout server-side.
function formatHexDump(base64Data) {
    const binary = atob(base64Data);
    const lines = [];
    for (let offset = 0; offset < binary.length; offset += 16) {
        const chunk = binary.slice(offset, offset + 16);
        const hexParts = [];
        let ascii = '';
        for (let i = 0; i < 16; i++) {
            if (i < chunk.length) {
                const byte = chunk.charCodeAt(i);
                hexParts.push(byte.toString(16).padStart(2, '0'));
                ascii += (byte >= 0x20 && byte <= 0x7e) ? chunk[i] : '.';
            } else {
                hexParts.push('  ');
            }
            if (i === 7) hexParts.push(''); // extra gap between the two 8-byte groups
        }
        lines.push(`${offset.toString(16).padStart(8, '0')}  ${hexParts.join(' ')}  |${ascii}|`);
    }
    return lines.join('\n') || '(empty file)';
}

async function loadExplorerHexPane() {
    const container = document.getElementById('explorerHex');
    if (!container) return;

    if (!activeSelectedFile || activeSelectedIsDir) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<i class="bi bi-code-square fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file on the left to view its raw bytes.</span>';
        return;
    }

    container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
    container.innerHTML = '<span class="text-subtle small">Loading hex view...</span>';

    // Snapshot which file this fetch is for - a fast second click while the
    // request is in flight shouldn't render stale bytes after the examiner
    // has already moved on.
    const requestedPath = activeSelectedFile;

    try {
        const res = await fetch('/api/files/hex', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile })
        });
        const data = await res.json();
        if (activeSelectedFile !== requestedPath) return;

        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }

        container.className = 'file-pane p-2 d-block text-start';
        container.innerHTML = '';
        const pre = document.createElement('pre');
        pre.className = 'log-window mb-0';
        pre.style.height = '100%';
        pre.textContent = formatHexDump(data.data) +
            (data.truncated ? `\n\n[... truncated, showing first ${data.bytes_read.toLocaleString()} of ${data.total_size.toLocaleString()} bytes ...]` : '');
        container.appendChild(pre);
    } catch (err) {
        if (activeSelectedFile !== requestedPath) return;
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<span class="text-danger small">Request failed.</span>';
    }
}

// Builds one labeled section (a small heading + a key/value table) - shared by the filesystem-info
// block (works for files and folders alike) and the ExifTool embedded-metadata block (files only)
// below it, so a selected file's Metadata pane shows both without two separate panes to switch
// between.
function _buildMetadataSection(title, rows) {
    const wrap = document.createElement('div');
    wrap.className = 'mb-3';
    const heading = document.createElement('div');
    heading.className = 'small text-info fw-bold mb-1';
    heading.textContent = title;
    wrap.appendChild(heading);

    const table = document.createElement('table');
    table.className = 'table table-sm table-dark table-striped mb-0';
    const tbody = document.createElement('tbody');
    if (rows.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.textContent = 'None found.';
        cell.className = 'text-subtle';
        row.appendChild(cell);
        tbody.appendChild(row);
    } else {
        rows.forEach(([key, value]) => renderMetadataRow(tbody, key, value));
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
}

// Filesystem-level facts (works for both files and folders) - always shown first. ExifTool's
// embedded-metadata table (file-only) is layered below it, so folders now get a real Metadata view
// instead of the placeholder this used to show unconditionally for anything but a file.
async function loadExplorerMetadataPane() {
    const container = document.getElementById('explorerMetadata');
    if (!container) return;

    if (!activeSelectedFile) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<i class="bi bi-info-circle fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file or folder on the left to view its details.</span>';
        return;
    }

    container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
    container.innerHTML = '<span class="text-subtle small">Loading details...</span>';

    const isDir = activeSelectedIsDir;
    const requestedPath = activeSelectedFile; // snapshot - a fast second click shouldn't render stale data
    try {
        const statRes = await fetch('/api/files/stat_info', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: requestedPath })
        });
        const statData = await statRes.json();
        if (activeSelectedFile !== requestedPath) return; // selection moved on while this was in flight

        if (!statData.success) {
            container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = statData.error;
            container.appendChild(err);
            return;
        }

        const fsRows = [
            ['Name', statData.name],
            ['Location', statData.path],
            ['Type', isDir ? 'Folder' : 'File'],
        ];
        if (!isDir) {
            fsRows.push(['Size', `${statData.size_str} (${statData.size_bytes.toLocaleString()} bytes)`]);
            if (statData.extension) fsRows.push(['Extension', statData.extension]);
            fsRows.push(['MIME Type', statData.mime_type || 'Unknown']);
        }
        fsRows.push(['Created', statData.created || 'Unknown (not exposed by this filesystem)']);
        fsRows.push(['Modified', statData.modified || 'Unknown']);
        fsRows.push(['Accessed', statData.accessed || 'Unknown']);
        fsRows.push(['Permissions', `${statData.permissions} (${statData.permissions_octal})`]);
        fsRows.push(['Owner / Group', `${statData.owner} / ${statData.group}`]);

        container.className = 'file-pane p-2 d-block text-start';
        container.innerHTML = '';
        container.appendChild(_buildMetadataSection('Filesystem Info', fsRows));

        if (isDir) {
            const hint = document.createElement('div');
            hint.className = 'text-subtle small';
            hint.textContent = 'Embedded (EXIF-style) metadata only applies to individual files. Right-click a file for a hash, or use Hash Directory Tree on this folder for a full manifest.';
            container.appendChild(hint);
            return;
        }

        const exifRes = await fetch('/api/files/exif', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: requestedPath })
        });
        const exifData = await exifRes.json();
        if (activeSelectedFile !== requestedPath) return;

        if (!exifData.success) {
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = exifData.error;
            container.appendChild(err);
            return;
        }
        const exifRows = Object.entries(exifData.metadata || {});
        container.appendChild(_buildMetadataSection('Embedded Metadata (ExifTool)', exifRows));
    } catch (err) {
        if (activeSelectedFile !== requestedPath) return;
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<span class="text-danger small">Request failed.</span>';
    }
}

// --- Generic SQLite Artifact Viewer (D1) ---
// Table list first, then a paginated read-only row browser for whichever
// table is clicked - shares the exact same explorerRightView='database'
// dispatch (switchExplorerRightView()/refreshExplorerDetailsView()) every
// other Details tab already uses, real-fs and in-image alike.
let explorerDbCurrentTable = null;  // null = showing the table list, not a specific table's rows
let explorerDbOffset = 0;

function _renderSqliteTableList(container, tables, onTableClick) {
    container.className = 'file-pane p-2 d-block text-start';
    container.innerHTML = '';
    if (!tables.length) {
        container.innerHTML = '<span class="text-subtle small">No tables found in this database.</span>';
        return;
    }
    const list = document.createElement('div');
    list.className = 'list-group list-group-flush';
    tables.forEach(t => {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'list-group-item list-group-item-action bg-black text-light border-secondary d-flex justify-content-between align-items-center py-1 px-2';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = t.name; // untrusted (table name from the evidence file), text node only
        const countSpan = document.createElement('span');
        countSpan.className = 'badge bg-secondary';
        countSpan.textContent = t.row_count === null ? '?' : t.row_count;
        row.appendChild(nameSpan);
        row.appendChild(countSpan);
        row.onclick = () => onTableClick(t.name);
        list.appendChild(row);
    });
    container.appendChild(list);
}

function _renderSqliteRowTable(container, data, onBack, onPage) {
    container.className = 'file-pane p-2 d-block text-start';
    container.innerHTML = '';

    const backBtn = document.createElement('button');
    backBtn.type = 'button';
    backBtn.className = 'btn btn-xs btn-outline-info py-0 px-2 mb-2';
    backBtn.innerHTML = '<i class="bi bi-arrow-left me-1"></i>Back to Tables';
    backBtn.onclick = onBack;
    container.appendChild(backBtn);

    const wrap = document.createElement('div');
    wrap.style.overflowX = 'auto';
    const table = document.createElement('table');
    table.className = 'table table-sm table-dark table-striped mb-2';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    data.columns.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col; // untrusted (column name), text node only
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    data.rows.forEach(row => {
        const tr = document.createElement('tr');
        row.forEach(cell => {
            const td = document.createElement('td');
            td.textContent = cell === null ? 'NULL' : String(cell); // untrusted (evidence cell content), text node only
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    container.appendChild(wrap);

    const pager = document.createElement('div');
    pager.className = 'd-flex justify-content-between align-items-center small text-subtle';
    const rangeStart = data.total_rows === 0 ? 0 : data.offset + 1;
    const rangeEnd = data.offset + data.returned;
    const rangeSpan = document.createElement('span');
    rangeSpan.textContent = `Rows ${rangeStart}-${rangeEnd} of ${data.total_rows}`;
    pager.appendChild(rangeSpan);
    const btnGroup = document.createElement('div');
    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.className = 'btn btn-xs btn-outline-info py-0 px-2 me-1';
    prevBtn.textContent = 'Prev';
    prevBtn.disabled = data.offset <= 0;
    prevBtn.onclick = () => onPage(Math.max(0, data.offset - data.page_size));
    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.className = 'btn btn-xs btn-outline-info py-0 px-2';
    nextBtn.textContent = 'Next';
    nextBtn.disabled = data.offset + data.returned >= data.total_rows;
    nextBtn.onclick = () => onPage(data.offset + data.page_size);
    btnGroup.appendChild(prevBtn);
    btnGroup.appendChild(nextBtn);
    pager.appendChild(btnGroup);
    container.appendChild(pager);
}

async function loadExplorerDatabasePane() {
    const container = document.getElementById('explorerDatabase');
    if (!container) return;
    if (!activeSelectedFile || !isSqliteFile(activeSelectedFile)) {
        container.className = 'file-pane p-2';
        container.innerHTML = '<div class="text-subtle small text-center p-3">Select a .db/.sqlite/.sqlite3 file on the left to browse it.</div>';
        return;
    }
    explorerDbCurrentTable = null;
    explorerDbOffset = 0;
    const requestedPath = activeSelectedFile;
    container.innerHTML = '<span class="text-subtle small">Loading tables...</span>';

    const showTables = async () => {
        try {
            const res = await fetch('/api/files/sqlite/tables', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: requestedPath }),
            });
            const data = await res.json();
            if (activeSelectedFile !== requestedPath) return;
            if (!data.success) {
                container.innerHTML = `<span class="text-danger small">${data.error}</span>`;
                return;
            }
            _renderSqliteTableList(container, data.tables, (tableName) => showRows(tableName, 0));
        } catch (err) {
            if (activeSelectedFile !== requestedPath) return;
            container.innerHTML = '<span class="text-danger small">Request failed.</span>';
        }
    };
    const showRows = async (tableName, offset) => {
        explorerDbCurrentTable = tableName;
        explorerDbOffset = offset;
        container.innerHTML = '<span class="text-subtle small">Loading rows...</span>';
        try {
            const res = await fetch('/api/files/sqlite/query', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: requestedPath, table: tableName, offset }),
            });
            const data = await res.json();
            if (activeSelectedFile !== requestedPath) return;
            if (!data.success) {
                container.innerHTML = `<span class="text-danger small">${data.error}</span>`;
                return;
            }
            _renderSqliteRowTable(container, data, showTables, (newOffset) => showRows(tableName, newOffset));
        } catch (err) {
            if (activeSelectedFile !== requestedPath) return;
            container.innerHTML = '<span class="text-danger small">Request failed.</span>';
        }
    };
    showTables();
}

async function loadExplorerImageDatabasePane() {
    const container = document.getElementById('explorerDatabase');
    if (!container) return;
    const entry = explorerImageSelected;
    if (!entry || entry.is_dir === true || !isSqliteFile(entry.name || '')) {
        container.className = 'file-pane p-2';
        container.innerHTML = '<div class="text-subtle small text-center p-3">Select a .db/.sqlite/.sqlite3 file on the left to browse it.</div>';
        return;
    }
    explorerDbCurrentTable = null;
    explorerDbOffset = 0;
    const requestedInode = entry.inode;
    container.innerHTML = '<span class="text-subtle small">Loading tables...</span>';

    const showTables = async () => {
        try {
            const res = await fetch('/api/image/sqlite/tables', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, inode: entry.inode }),
            });
            const data = await res.json();
            if (!explorerImageSelected || explorerImageSelected.inode !== requestedInode) return;
            if (!data.success) {
                container.innerHTML = `<span class="text-danger small">${data.error}</span>`;
                return;
            }
            _renderSqliteTableList(container, data.tables, (tableName) => showRows(tableName, 0));
        } catch (err) {
            if (!explorerImageSelected || explorerImageSelected.inode !== requestedInode) return;
            container.innerHTML = '<span class="text-danger small">Request failed.</span>';
        }
    };
    const showRows = async (tableName, rowOffset) => {
        explorerDbCurrentTable = tableName;
        explorerDbOffset = rowOffset;
        container.innerHTML = '<span class="text-subtle small">Loading rows...</span>';
        try {
            const res = await fetch('/api/image/sqlite/query', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    image_path: explorerImagePath, offset: explorerImageOffset, inode: entry.inode,
                    table: tableName, row_offset: rowOffset,
                }),
            });
            const data = await res.json();
            if (!explorerImageSelected || explorerImageSelected.inode !== requestedInode) return;
            if (!data.success) {
                container.innerHTML = `<span class="text-danger small">${data.error}</span>`;
                return;
            }
            _renderSqliteRowTable(container, data, showTables, (newOffset) => showRows(tableName, newOffset));
        } catch (err) {
            if (!explorerImageSelected || explorerImageSelected.inode !== requestedInode) return;
            container.innerHTML = '<span class="text-danger small">Request failed.</span>';
        }
    };
    showTables();
}

// --- Shared "run a scan, show text output" modal (binwalk / strings / clamscan) ---
let toolOutputModalInstance = null;

function showToolOutputModal(title, icon) {
    if (!toolOutputModalInstance) {
        toolOutputModalInstance = new bootstrap.Modal(document.getElementById('toolOutputModal'));
    }
    const titleEl = document.getElementById("toolOutputTitle");
    const iconEl = document.getElementById("toolOutputIcon");
    const badgeRow = document.getElementById("toolOutputBadgeRow");
    const container = document.getElementById("toolOutputContainer");
    if (titleEl) titleEl.textContent = title;
    if (iconEl) iconEl.className = `bi ${icon} me-2`;
    if (badgeRow) badgeRow.style.display = 'none';
    if (container) container.textContent = 'Running...';
    toolOutputModalInstance.show();
}

function setToolOutputBadge(text, badgeClass) {
    const badgeRow = document.getElementById("toolOutputBadgeRow");
    const badge = document.getElementById("toolOutputBadge");
    if (badge) { badge.textContent = text; badge.className = `badge ${badgeClass}`; }
    if (badgeRow) badgeRow.style.display = '';
}

async function runSelectedBinwalk() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Binwalk: ${activeSelectedFile.split('/').pop()}`, 'bi-cpu');

    try {
        const res = await fetch('/api/files/binwalk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = data.success ? data.output : `[ERROR] ${data.error}`;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedClamscan() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`ClamAV Scan: ${activeSelectedFile.split('/').pop()}`, 'bi-shield-exclamation');

    try {
        const res = await fetch('/api/files/clamscan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        setToolOutputBadge(data.infected ? 'THREAT(S) FOUND' : 'CLEAN', data.infected ? 'bg-danger' : 'bg-success');
        if (container) container.textContent = data.output;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedStrings() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Strings: ${activeSelectedFile.split('/').pop()}`, 'bi-fonts');

    try {
        const res = await fetch('/api/files/strings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = data.success ? data.output : `[ERROR] ${data.error}`;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

// Fast, capped (first 32MB) scan for emails/URLs/IPs/card-like numbers/phone
// numbers - a right-click quick look at a .dd/.E01 image (or any file)
// reusing the same TRIAGE_PATTERNS the background Triage Scan job in File
// Recovery uses, without needing to leave File Explorer to configure and
// run that job.
async function runSelectedQuickTriageScan() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Quick Triage Scan: ${activeSelectedFile.split('/').pop()}`, 'bi-binoculars');

    try {
        const res = await fetch('/api/files/quick_triage_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        setToolOutputBadge(`${data.total_hits} total match${data.total_hits === 1 ? '' : 'es'}`, data.total_hits > 0 ? 'bg-warning text-dark' : 'bg-success');
        if (container) container.textContent = data.output;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedHashdeep() {
    if (!activeSelectedFile) return;
    // Output is written to the active case's folder (or this folder's own
    // parent if no case is active) - never into activeSelectedFile itself,
    // which is the evidence folder being hashed. Matches every other
    // properly-designed analysis tool in this app (Memory Forensics,
    // Logical Acquisition, ALEAPP/iLEAPP) - see _resolve_analysis_output_
    // dir() in routes/file_explorer.py for the backend-side enforcement.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/hashdeep', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, algorithm: 'sha256', destination_dir: destinationDir })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Hashed ${data.file_count} file(s).\nManifest written to:\n${data.manifest_path}`, 'success');
            loadExplorer(explorerPath);
        } else {
            showToast(`hashdeep failed: ${data.error}`, 'danger');
        }
    } catch (err) {}
}

async function runSelectedSqliteDissect() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`SQLite Dissect: ${activeSelectedFile.split('/').pop()}`, 'bi-arrow-counterclockwise');
    // Same evidence-must-never-be-modified reasoning as runSelectedHashdeep() above.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/sqlite_dissect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        setToolOutputBadge(data.summary, 'bg-info');
        if (container) container.textContent = `${data.log}\n\nOutput written to:\n${data.output_dir}`;
        loadExplorer(explorerPath);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedApkAnalyze() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`APK Analysis: ${activeSelectedFile.split('/').pop()}`, 'bi-android2');
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/apk_analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        setToolOutputBadge(data.summary, 'bg-info');
        const p = data.package;
        const lines = [];
        lines.push(`Package: ${p.package_name || '(unknown)'}`);
        lines.push(`App Name: ${p.app_name || '(unknown)'}`);
        lines.push(`Version: ${p.version_name || '?'} (code ${p.version_code ?? '?'})`);
        lines.push(`SDK: min ${p.min_sdk ?? '?'} / target ${p.target_sdk ?? '?'}`);
        lines.push('');
        lines.push(`--- Signing (${(p.signing || []).length} signer(s)) ---`);
        (p.signing || []).forEach((s, i) => {
            lines.push(`[${i + 1}] Subject: ${s.subject}`);
            lines.push(`    Issuer: ${s.issuer}`);
            lines.push(`    Serial: ${s.serial_number}   SHA256: ${s.sha256}`);
            lines.push(`    Valid: ${s.valid_from} -> ${s.valid_to}`);
        });
        lines.push('');
        lines.push(`--- Permissions (${(p.permissions || []).length}) ---`);
        lines.push(...(p.permissions || []));
        lines.push('');
        lines.push(`--- Activities (${(p.activities || []).length}) ---`);
        lines.push(...(p.activities || []));
        lines.push('');
        lines.push(`--- Services (${(p.services || []).length}) ---`);
        lines.push(...(p.services || []));
        lines.push('');
        lines.push(`--- Receivers (${(p.receivers || []).length}) ---`);
        lines.push(...(p.receivers || []));
        lines.push('');
        lines.push(`--- Providers (${(p.providers || []).length}) ---`);
        lines.push(...(p.providers || []));
        lines.push('');
        lines.push(`--- URLs found in the raw APK bytes (${(p.urls_found || []).length}) ---`);
        lines.push(...(p.urls_found || []));
        if (data.output_path) {
            lines.push('');
            lines.push(`Full JSON report written to:\n${data.output_path}`);
        }
        if (container) container.textContent = lines.join('\n');
        if (data.output_path) loadExplorer(explorerPath);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

let whatsappDecryptModalInstance = null;

function openWhatsappDecryptModal() {
    if (!activeSelectedFile) return;
    document.getElementById("whatsappDecryptFileName").textContent = activeSelectedFile.split('/').pop();
    const keyPathEl = document.getElementById("whatsappDecryptKeyPath");
    if (keyPathEl) keyPathEl.value = '';
    const output = document.getElementById("whatsappDecryptOutput");
    if (output) output.textContent = 'Select a key file and click Decrypt.';
    const badge = document.getElementById("whatsappDecryptBadge");
    if (badge) { badge.className = 'badge bg-secondary'; badge.textContent = 'AWAITING INPUT'; }

    if (!whatsappDecryptModalInstance) {
        whatsappDecryptModalInstance = new bootstrap.Modal(document.getElementById('whatsappDecryptModal'));
    }
    whatsappDecryptModalInstance.show();
}

async function runWhatsappDecrypt() {
    if (!activeSelectedFile) return;
    const keyPathEl = document.getElementById("whatsappDecryptKeyPath");
    const keyPath = keyPathEl ? keyPathEl.value.trim() : '';
    const badge = document.getElementById("whatsappDecryptBadge");
    const output = document.getElementById("whatsappDecryptOutput");
    if (!keyPath) return showToast('Enter or browse to a key file first.', 'warning');

    if (badge) { badge.className = 'badge bg-info text-dark'; badge.textContent = 'DECRYPTING...'; }
    if (output) output.textContent = 'Running...';

    // Same evidence-must-never-be-modified reasoning as runSelectedHashdeep()/runSelectedApkAnalyze() above.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/whatsapp_decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, key_path: keyPath, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) {
            if (badge) { badge.className = 'badge bg-danger'; badge.textContent = 'FAILED'; }
            if (output) output.textContent = `[ERROR] ${data.error}`;
            return;
        }
        if (badge) { badge.className = 'badge bg-success'; badge.textContent = 'DECRYPTED'; }
        if (output) output.textContent = `${data.log}\n\nOutput written to:\n${data.output_path}`;
        loadExplorer(explorerPath);
    } catch (err) {
        if (badge) { badge.className = 'badge bg-danger'; badge.textContent = 'FAILED'; }
        if (output) output.textContent = '[REQUEST FAILED]';
    }
}

let ipaAnalyzeOptionsModalInstance = null;

function openIpaAnalyzeModal() {
    if (!activeSelectedFile) return;
    document.getElementById("ipaAnalyzeFileName").textContent = activeSelectedFile.split('/').pop();
    const machoToggle = document.getElementById("ipaAnalyzeMachoToggle");
    if (machoToggle) machoToggle.checked = true;

    if (!ipaAnalyzeOptionsModalInstance) {
        ipaAnalyzeOptionsModalInstance = new bootstrap.Modal(document.getElementById('ipaAnalyzeOptionsModal'));
    }
    ipaAnalyzeOptionsModalInstance.show();
}

async function runSelectedIpaAnalyze() {
    if (!activeSelectedFile) return;
    const runMacho = document.getElementById("ipaAnalyzeMachoToggle")?.checked !== false;
    if (ipaAnalyzeOptionsModalInstance) ipaAnalyzeOptionsModalInstance.hide();

    showToolOutputModal(`IPA Analysis: ${activeSelectedFile.split('/').pop()}`, 'bi-apple');
    try {
        const res = await fetch('/api/files/ipa_analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, run_macho: runMacho, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }

        const p = data.info_plist;
        const summary = `${p.bundle_id || '(unknown)'} v${p.version || '?'}`;
        setToolOutputBadge(summary, 'bg-info');

        const lines = [];
        lines.push(`Bundle ID: ${p.bundle_id || '(unknown)'}`);
        lines.push(`App Name: ${p.app_name || '(unknown)'}`);
        lines.push(`Version: ${p.version || '?'} (build ${p.build || '?'})`);
        lines.push(`Minimum OS: ${p.min_os_version || '(unknown)'}`);
        lines.push(`Executable: ${p.executable_name || '(unknown)'}`);
        lines.push('');
        const usageKeys = Object.keys(p.usage_descriptions || {});
        lines.push(`--- Permission Usage Descriptions (${usageKeys.length}) ---`);
        usageKeys.forEach((k) => lines.push(`${k}: ${p.usage_descriptions[k]}`));

        lines.push('');
        if (data.mobileprovision) {
            if (data.mobileprovision.error) {
                lines.push(`--- Mobile Provisioning Profile: ${data.mobileprovision.error} ---`);
            } else {
                const mp = data.mobileprovision;
                lines.push(`--- Mobile Provisioning Profile ---`);
                lines.push(`App ID Name: ${mp.app_id_name || '(unknown)'}`);
                lines.push(`Team: ${mp.team_name || '(unknown)'} (${(mp.team_identifiers || []).join(', ')})`);
                lines.push(`Valid: ${mp.creation_date || '?'} -> ${mp.expiration_date || '?'}`);
                lines.push(`Provisioned Devices (${(mp.provisioned_devices || []).length}):`);
                lines.push(...(mp.provisioned_devices || []));
                lines.push(`Entitlements (${Object.keys(mp.entitlements || {}).length}):`);
                Object.entries(mp.entitlements || {}).forEach(([k, v]) => lines.push(`  ${k}: ${JSON.stringify(v)}`));
            }
        } else {
            lines.push('--- No embedded mobile provisioning profile (not signed for a real device, e.g. a simulator build) ---');
        }

        lines.push('');
        if (data.macho) {
            lines.push(`--- Mach-O Binary Analysis (${data.macho.executable}) ---`);
            data.macho.slices.forEach((s) => {
                const encStatus = s.encrypted === null ? 'unknown' : (s.encrypted ? `ENCRYPTED (cryptid=${s.cryptid})` : `decrypted (cryptid=${s.cryptid})`);
                lines.push(`${s.architecture} (${s.is_64bit ? '64-bit' : '32-bit'}) - ${encStatus}`);
            });
        } else if (data.macho_error) {
            lines.push(`--- Mach-O Binary Analysis: ${data.macho_error} ---`);
        }

        if (container) container.textContent = lines.join('\n');
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedBugreportParse() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Bugreport Deep Parse: ${activeSelectedFile.split('/').pop()}`, 'bi-file-earmark-zip');
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/bugreport_parse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        setToolOutputBadge(data.summary, 'bg-info');
        if (container) container.textContent = `${JSON.stringify(data.sections, null, 2)}\n\nOutput written to:\n${data.output_path}`;
        loadExplorer(explorerPath);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedGeolocationExport() {
    if (!activeSelectedFile) return;
    // Same evidence-must-never-be-modified reasoning as runSelectedHashdeep() above.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/geolocation_kml', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir })
        });
        const data = await res.json();
        if (data.success) {
            if (data.points_found === 0) {
                showToast(`Scanned ${data.files_scanned} photo(s) - none had GPS location data. No KML file was needed.`, 'success');
            } else {
                showToast(`Found location data in ${data.points_found} of ${data.files_scanned} photo(s).\nKML file written to:\n${data.kml_path}`, 'info');
                loadExplorer(explorerPath);
            }
        } else {
            showToast(`Geolocation export failed: ${data.error}`, 'danger');
        }
    } catch (err) {}
}

// Browser-artifact field->plain-label map (Chrome/Chromium + Firefox),
// shared by the real-fs and in-image summary toasts below - kept in one
// place so the two entry points can never describe the same artifact_type
// differently.
const BROWSER_ARTIFACT_TYPE_LABELS = {
    chrome_history: 'history entries', chrome_downloads: 'downloads',
    chrome_bookmarks: 'bookmarks', chrome_cookies: 'cookies',
    firefox_history: 'Firefox history entries', firefox_downloads: 'Firefox downloads',
    firefox_bookmarks: 'Firefox bookmarks', firefox_cookies: 'Firefox cookies',
};

function summarizeBrowserArtifactCounts(counts) {
    const parts = Object.keys(counts || {}).map(k => `${counts[k]} ${BROWSER_ARTIFACT_TYPE_LABELS[k] || k}`);
    return parts.length ? parts.join(', ') : 'no records';
}

async function runSelectedBrowserArtifactsParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_browser_artifacts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Browser artifact scan failed: ${data.error}`, 'danger');
            return;
        }
        if (data.candidates_found === 0) {
            showToast('No Chrome/Chromium or Firefox profile files (History/Cookies/Bookmarks, places.sqlite/cookies.sqlite) found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeBrowserArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} profile file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} profile file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Browser artifact scan failed: request error.', 'danger');
    }
}

// --- Registry / Event Log / LNK parsing (Part C) ---
// Shared by all 6 new entry points below (real-fs + in-image, x Registry/
// EVTX/LNK) - a generic "N found across M type(s)" summary from a plain
// {artifact_type: count} dict, not browser-specific like
// summarizeBrowserArtifactCounts() above.
function summarizeParsedArtifactCounts(counts) {
    const entries = Object.entries(counts || {});
    if (!entries.length) return 'nothing recognized';
    return entries.map(([type, n]) => `${n} ${type.replace(/^registry_|^evtx_|^prefetch_|^recyclebin_|^linux_/, '').replace(/_/g, ' ')}`).join(', ');
}

async function runSelectedRegistryParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_registry', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Registry hive scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Registry hive files (NTUSER.DAT/SYSTEM/SOFTWARE) found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} hive file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} hive file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Registry hive scan failed: request error.', 'danger');
    }
}

async function runImageRegistryParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_registry', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Registry hive scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Registry hive files found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} hive file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} hive file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Registry hive scan failed: request error.', 'danger');
    }
}

async function runSelectedEvtxParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_evtx', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Event log scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Event Log (.evtx) files found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} event log(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} event log(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Event log scan failed: request error.', 'danger');
    }
}

async function runImageEvtxParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_evtx', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Event log scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Event Log (.evtx) files found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} event log(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} event log(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Event log scan failed: request error.', 'danger');
    }
}

async function runSelectedPrefetchParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_prefetch', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Prefetch scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Prefetch (.pf) files found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} prefetch file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} prefetch file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Prefetch scan failed: request error.', 'danger');
    }
}

async function runImagePrefetchParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_prefetch', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Prefetch scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Windows Prefetch (.pf) files found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} prefetch file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} prefetch file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Prefetch scan failed: request error.', 'danger');
    }
}

// --- Fuzzy hashing (TLSH) - closes a real gap in the exact-match-only
// Hash Sets check: a one-byte-modified copy of a known file is invisible
// to that, but similar/near-duplicate to a fuzzy hash. Deliberately a
// standalone compute-and-compare action, not integrated into the Hash
// Sets management UI/storage format - see core/fuzzy_hash_utils.py's own
// docstring for the scoping rationale. Uses a plain prompt() for the
// optional comparison input rather than a dedicated modal, given this is
// a small, secondary step (paste a hash from elsewhere, e.g. a threat-
// intel report) - a real, disclosed UX simplification, not an oversight.
async function _showFuzzyHashResult(title, icon, endpoint, body) {
    showToolOutputModal(title, icon);
    const container = document.getElementById("toolOutputContainer");
    try {
        const res = await fetch(endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) { if (container) container.textContent = `[ERROR] ${data.error}`; return; }
        if (!data.hash) {
            setToolOutputBadge('No digest', 'bg-secondary');
            if (container) container.textContent = data.note || 'TLSH could not compute a digest for this file.';
            return;
        }
        setToolOutputBadge('TLSH computed', 'bg-info');
        if (container) container.textContent = `TLSH digest:\n${data.hash}\n\nTo compare against a known hash, click "Compare Against Another Hash..." below.`;
        const compareBtn = document.createElement('button');
        compareBtn.className = 'btn btn-sm btn-outline-info mt-2';
        compareBtn.textContent = 'Compare Against Another Hash...';
        compareBtn.onclick = async () => {
            const other = prompt('Paste a TLSH hash to compare against:');
            if (!other) return;
            try {
                const cmpRes = await fetch('/api/files/fuzzy_hash_compare', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hash_a: data.hash, hash_b: other.trim() })
                });
                const cmp = await cmpRes.json();
                if (!cmp.success) { showToast(cmp.error || 'Comparison failed.', 'danger'); return; }
                const verdict = cmp.similar ? 'SIMILAR' : 'not similar';
                showToast(`Distance: ${cmp.distance} - ${verdict} (lower distance = more similar; threshold ~100).`, cmp.similar ? 'warning' : 'info');
            } catch (err) {
                showToast('Comparison failed: request error.', 'danger');
            }
        };
        if (container) container.appendChild(document.createElement('br'));
        if (container) container.appendChild(compareBtn);
    } catch (err) {
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedFuzzyHash() {
    if (!activeSelectedFile) return;
    await _showFuzzyHashResult(`Fuzzy Hash (TLSH): ${activeSelectedFile.split('/').pop()}`, 'bi-fingerprint',
        '/api/files/fuzzy_hash', { path: activeSelectedFile });
}

async function runImageFuzzyHash() {
    if (!explorerImageSelected || explorerImageSelected.is_dir) return;
    await _showFuzzyHashResult(`Fuzzy Hash (TLSH): ${explorerImageSelected.name}`, 'bi-fingerprint',
        '/api/image/fuzzy_hash', {
            image_path: explorerImagePath, offset: explorerImageOffset,
            inode: explorerImageSelected.inode, name: explorerImageSelected.name,
        });
}

async function runSelectedEmailParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_email', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Email scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No email files (.eml/.mbox/.pst/.ost) found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} email container(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} email container(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Email scan failed: request error.', 'danger');
    }
}

async function runImageEmailParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_email', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Email scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No email files (.eml/.mbox/.pst/.ost) found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} email container(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} email container(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Email scan failed: request error.', 'danger');
    }
}

async function runSelectedRecycleBinParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_recyclebin', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Recycle Bin scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Recycle Bin ($I) metadata files found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} deleted-file record(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} deleted-file record(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Recycle Bin scan failed: request error.', 'danger');
    }
}

async function runImageRecycleBinParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_recyclebin', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Recycle Bin scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Recycle Bin ($I) metadata files found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} deleted-file record(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} deleted-file record(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Recycle Bin scan failed: request error.', 'danger');
    }
}

async function runSelectedLinuxArtifactsParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_linux_artifacts', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Linux artifact scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Linux forensic artifacts (shell history, /etc/passwd, cron, auth.log) found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} artifact file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} artifact file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Linux artifact scan failed: request error.', 'danger');
    }
}

async function runImageLinuxArtifactsParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_linux_artifacts', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Linux artifact scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No Linux forensic artifacts found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} artifact file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} artifact file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Linux artifact scan failed: request error.', 'danger');
    }
}

async function runSelectedCryptoWalletParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_crypto_wallets', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Crypto wallet scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No cryptocurrency wallet files found under this folder.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} wallet file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} wallet file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Crypto wallet scan failed: request error.', 'danger');
    }
}

async function runImageCryptoWalletParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_crypto_wallets', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Crypto wallet scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No cryptocurrency wallet files found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} wallet file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} wallet file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Crypto wallet scan failed: request error.', 'danger');
    }
}

async function runSelectedMobileArtifactsParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_mobile_artifacts', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Mobile artifact scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No iOS backup (Manifest.db + Info.plist) found under this folder.', 'success');
            return;
        }
        if (data.any_encrypted) {
            showToast('Found a backup here, but it is password-encrypted - cannot extract app data without the backup password.', 'info');
            return;
        }
        const truncNote = data.truncated ? ' (capped)' : '';
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} backup(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} backup(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Mobile artifact scan failed: request error.', 'danger');
    }
}

async function runImageMobileArtifactsParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_mobile_artifacts', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(`Mobile artifact scan failed: ${data.error}`, 'danger'); return; }
        if (data.candidates_found === 0) {
            showToast('No iOS backup found in this image.', 'success');
            return;
        }
        if (data.any_encrypted) {
            showToast('Found a backup here, but it is password-encrypted - cannot extract app data without the backup password.', 'info');
            return;
        }
        const summary = summarizeParsedArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} backup(s): ${summary}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} backup(s): ${summary}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Mobile artifact scan failed: request error.', 'danger');
    }
}

async function runSelectedLnkParse() {
    if (!activeSelectedFile) return;
    try {
        const res = await fetch('/api/files/parse_lnk', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) { showToast(data.error || 'Could not parse this .lnk file.', 'danger'); return; }
        const r = data.record;
        const msg = `Shortcut target: ${r.value || '(none)'}${r.extra.arguments ? ' ' + r.extra.arguments : ''}`;
        showToast(data.indexed ? `${msg}. See File Views > Parsed Artifacts.` : `${msg}. Select an active case to save this into File Views.`, data.indexed ? 'success' : 'info');
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        showToast('LNK parse failed: request error.', 'danger');
    }
}

async function runImageLnkParse() {
    if (!explorerImageSelected || explorerImageSelected.is_dir) return;
    try {
        const res = await fetch('/api/image/parse_lnk', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: explorerImageSelected.inode, name: explorerImageSelected.name,
                path: explorerImageSelected.path || null,
                case_folder: activeCase ? activeCase.case_folder : null,
            })
        });
        const data = await res.json();
        if (!data.success) { showToast(data.error || 'Could not parse this .lnk file.', 'danger'); return; }
        const r = data.record;
        const msg = `Shortcut target: ${r.value || '(none)'}${r.extra.arguments ? ' ' + r.extra.arguments : ''}`;
        showToast(data.indexed ? `${msg}. See File Views > Parsed Artifacts.` : `${msg}. Select an active case to save this into File Views.`, data.indexed ? 'success' : 'info');
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        showToast('LNK parse failed: request error.', 'danger');
    }
}

// --- $MFT / $UsnJrnl: NTFS Master File Table and change-journal parsing ---
// analyzeMFT (core/mft_utils.py) and a hand-rolled USN_RECORD_V2 parser
// (core/usnjrnl_utils.py) - both write a real output file (like SQLite
// Dissect/hashdeep above), so both need a destinationDir, unlike LNK's
// pure inline-record result.
async function runSelectedMftAnalyze() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Analyze $MFT: ${activeSelectedFile.split('/').pop()}`, 'bi-clock-history');
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));
    try {
        const res = await fetch('/api/files/analyze_mft', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) { if (container) container.textContent = `[ERROR] ${data.error}`; return; }
        setToolOutputBadge(data.summary, data.timestomp_count > 0 ? 'bg-warning text-dark' : 'bg-info');
        if (container) container.textContent = `${data.summary}\n\nOutput written to:\n${data.output_path}${data.indexed ? '\n\nSee File Views > Parsed Artifacts and the Evidence Timeline for individually browsable records.' : '\n\nSelect an active case to also index individual records into File Views/the Evidence Timeline.'}`;
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runImageMftAnalyze() {
    if (!explorerImageSelected || explorerImageSelected.is_dir) return;
    showToolOutputModal(`Analyze $MFT: ${explorerImageSelected.name}`, 'bi-clock-history');
    const destinationDir = activeCase ? activeCase.case_folder : null;
    try {
        const res = await fetch('/api/image/analyze_mft', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: explorerImageSelected.inode, name: explorerImageSelected.name,
                path: explorerImageSelected.path || null, destination_dir: destinationDir,
                case_folder: activeCase ? activeCase.case_folder : null,
            })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) { if (container) container.textContent = `[ERROR] ${data.error}`; return; }
        setToolOutputBadge(data.summary, data.timestomp_count > 0 ? 'bg-warning text-dark' : 'bg-info');
        if (container) container.textContent = `${data.summary}\n\nOutput written to:\n${data.output_path}`;
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedUsnjrnlParse() {
    if (!activeSelectedFile) return;
    showToolOutputModal(`Parse $UsnJrnl: ${activeSelectedFile.split('/').pop()}`, 'bi-journal-arrow-up');
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));
    try {
        const res = await fetch('/api/files/parse_usnjrnl', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) { if (container) container.textContent = `[ERROR] ${data.error}`; return; }
        const summary = `${data.record_count} change-journal record(s) parsed`;
        setToolOutputBadge(summary, 'bg-info');
        if (container) container.textContent = `${summary}\n\nOutput written to:\n${data.output_path}${data.indexed ? '\n\nSee File Views > Parsed Artifacts and the Evidence Timeline for individually browsable records.' : '\n\nSelect an active case to also index individual records into File Views/the Evidence Timeline.'}`;
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runImageUsnjrnlParse() {
    if (!explorerImageSelected || explorerImageSelected.is_dir) return;
    showToolOutputModal(`Parse $UsnJrnl: ${explorerImageSelected.name}`, 'bi-journal-arrow-up');
    const destinationDir = activeCase ? activeCase.case_folder : null;
    try {
        const res = await fetch('/api/image/parse_usnjrnl', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: explorerImageSelected.inode, name: explorerImageSelected.name,
                path: explorerImageSelected.path || null, destination_dir: destinationDir,
                case_folder: activeCase ? activeCase.case_folder : null,
            })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) { if (container) container.textContent = `[ERROR] ${data.error}`; return; }
        const summary = `${data.record_count} change-journal record(s) parsed`;
        setToolOutputBadge(summary, 'bg-info');
        if (container) container.textContent = `${summary}\n\nOutput written to:\n${data.output_path}`;
        if (data.indexed) initFileViewsTree(true);
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runSelectedMvtScan(platform) {
    if (!activeSelectedFile) return;
    const label = platform === 'ios' ? 'MVT iOS Backup Scan' : 'MVT Android Backup Scan';
    showToolOutputModal(`${label}: ${activeSelectedFile.split('/').pop()}`, 'bi-phone');
    // Same evidence-must-never-be-modified reasoning as runSelectedHashdeep() above -
    // this is also Auto Analyze's own Mobile-profile hand-off, so this one fix covers both.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/mvt_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, platform, destination_dir: destinationDir })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (!data.success) {
            if (container) container.textContent = `[ERROR] ${data.error}`;
            return;
        }
        if (container) container.textContent = `${data.output}\n\n[Full results written to: ${data.output_dir}]`;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function updateMvtIndicators(btnEl) {
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Updating...';
    }

    try {
        const res = await fetch('/api/tools/mvt_update_iocs', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            const summary = Object.entries(data.results).map(([platform, msg]) => `${platform}: ${msg}`).join('\n\n');
            showToast(`MVT indicator update finished:\n\n${summary}`, 'info');
        } else {
            showToast(`Update failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast('Update request failed.', 'danger');
    } finally {
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.innerHTML = '<i class="bi bi-cloud-download me-1"></i>Update MVT Indicators';
        }
    }
}

// --- Image Browser (Sleuth Kit via pytsk3) - inline in File Explorer, not a modal ---
// Browsing inside an acquired image reuses the exact same #explorerContainer/
// #explorerPreview panes File Explorer already has for the real filesystem -
// entering "image mode" just swaps what those two panes are driven by.
let explorerImageMode = false;
// File Explorer's in-image background jobs (unlike every other in-image
// tool, which is synchronous) each need a completion notification, since
// #explorerJobProgress hides the instant the job goes inactive - add an
// entry here whenever another in-image tool becomes a real job.
const IMAGE_JOB_COMPLETION_MESSAGES = {
    image_triage_scan: (status) => `Filesystem-aware triage scan finished: ${status}\n\nCheck the case folder for the generated *_triage_scan_report.txt file.`,
    image_geolocation_kml: (status) => `Geolocation scan finished: ${status}\n\nCheck the case folder for the generated *_geolocation_export.kml file (only written if GPS-tagged photos were found).`,
    image_conversion: (status) => `Image conversion finished: ${status}\n\nSee the report event's "Hash Verified" field for whether the independently-computed source/output hashes matched.`,
    memory_forensics_scan: (status) => `Memory forensics scan finished: ${status}\n\nClick a *_vol3_<plugin>.json file next to the image in File Explorer to view its results.`,
    mquire_scan: (status) => `mquire memory forensics scan finished: ${status}\n\nClick a *_mquire_<table>.json file next to the image in File Explorer to view its results.`,
    leapp_scan: (status) => `ALEAPP/iLEAPP mobile artifact scan finished: ${status}\n\nOpen the new *_aleapp_output or *_ileapp_output folder next to the extraction in File Explorer, then click the HTML report inside it.`,
    verify_all_evidence: (status) => `Case-wide evidence verification finished: ${status}\n\nSee the Overview tab in Reporting for the full result.`,
    case_bundle_export: (status) => `Case bundle export finished: ${status}\n\nCheck the case folder for the generated *_case_bundle_<timestamp>.zip file.`,
    auto_analyze_image: (status) => `Auto Analyze finished: ${status}\n\nSee the Audit Log (Settings > Security) for the full per-step results, or File Views > Parsed Artifacts for the individual tools' output.`,
};
let lastImageJobActiveByFormat = {}; // job format -> was it active as of the last poll

// --- Per-tab job-completion sidebar badges ----------------------------------------
// This app has exactly one shared background job at a time (core/jobs.py's single
// current_job), startable from any of 4 different tabs - Forensic Acquisition,
// Mobile Forensics, File Recovery, or File Explorer's in-image tools (including the
// standalone image_conversion action above). If the tab that started it isn't the
// one currently visible when it finishes, the existing completion toast/alert for
// that specific tool can easily go unnoticed entirely. This gives each of those 4
// sidebar icons a small red count badge (templates/index.html's .nav-badge spans),
// bumped on the exact same active->inactive transition fetchProgress() already
// detects for IMAGE_JOB_COMPLETION_MESSAGES above, and cleared the moment the
// examiner actually switches to that tab (see the shown.bs.tab listener below).
const JOB_FORMAT_TO_NAV_BADGE = {
    // Forensic Acquisition
    dd: 'navBadgeAcquisition', raw: 'navBadgeAcquisition', dcfldd: 'navBadgeAcquisition',
    plain_dd: 'navBadgeAcquisition', e01: 'navBadgeAcquisition', aff: 'navBadgeAcquisition',
    ddrescue: 'navBadgeAcquisition', logical_acquisition: 'navBadgeAcquisition',
    // Mobile Forensics
    ios_backup: 'navBadgeMobile', android_pull: 'navBadgeMobile',
    android_backup: 'navBadgeMobile', android_bugreport: 'navBadgeMobile',
    // File Recovery (whole-device/whole-image tools reached from that tab)
    photorec: 'navBadgeRecovery', extundelete: 'navBadgeRecovery',
    foremost: 'navBadgeRecovery', scalpel: 'navBadgeRecovery', triage_scan: 'navBadgeRecovery',
    // File Explorer (in-image background jobs, reached via right-click/toolbar there)
    image_geolocation_kml: 'navBadgeExplorer', image_triage_scan: 'navBadgeExplorer',
    memory_forensics_scan: 'navBadgeExplorer', mquire_scan: 'navBadgeExplorer', image_conversion: 'navBadgeExplorer',
    auto_analyze_image: 'navBadgeExplorer', leapp_scan: 'navBadgeExplorer',
};
const NAV_BADGE_TO_TAB_ID = {
    navBadgeAcquisition: 'acquisition-tab', navBadgeMobile: 'mobile-tab',
    navBadgeRecovery: 'ddrescue-tab', navBadgeExplorer: 'explorer-tab',
};
let lastGlobalJobActive = false; // mirrors lastImageJobActiveByFormat's own pattern, just one shared flag since there's only ever one job station-wide
let lastGlobalJobFormat = null;

function bumpNavBadge(badgeId) {
    const badge = document.getElementById(badgeId);
    if (!badge) return;
    const next = (parseInt(badge.textContent, 10) || 0) + 1;
    badge.textContent = String(next);
    badge.style.display = 'inline-block';
}

function clearNavBadge(badgeId) {
    const badge = document.getElementById(badgeId);
    if (!badge) return;
    badge.textContent = '';
    badge.style.display = 'none';
}

document.addEventListener('shown.bs.tab', (ev) => {
    const badgeId = Object.keys(NAV_BADGE_TO_TAB_ID).find((k) => NAV_BADGE_TO_TAB_ID[k] === ev.target?.id);
    if (badgeId) clearNavBadge(badgeId);
});

let explorerImagePath = null;
let explorerImageOffset = 0;
let explorerImageEncVolMountId = null; // set only when the currently-browsed image is a decrypted BitLocker/LUKS/VeraCrypt volume, so exitExplorerImage() knows to lock/cleanup it
let explorerImageEncVolType = null; // 'bitlocker'|'luks'|'veracrypt' - which /api/${type}/lock exitExplorerImage() should call
let explorerDevicePreviewPath = null; // set only when the currently-browsed "image" is actually a live raw device (Live Device Preview), so exitExplorerImage() knows to revoke its ACL grant
let explorerImagePathStack = [];  // [{inode, name}, ...] for breadcrumb + "up" navigation
let explorerImageSelected = null; // {inode, name} or a timeline event with a .path
let explorerImageView = 'browse'; // 'browse' | 'search' | 'timeline'

function imgFormatBytes(n) {
    if (n === null || n === undefined) return '--';
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let val = n / 1024;
    let i = 0;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return `${val.toFixed(1)} ${units[i]}`;
}

function imgFormatTimestamp(epochSeconds) {
    if (!epochSeconds) return '--';
    try {
        return new Date(epochSeconds * 1000).toLocaleString();
    } catch (err) {
        return '--';
    }
}

function isImageFile(name) {
    const IMAGE_EXTENSIONS = ['.dd', '.raw', '.img', '.e01', '.aff'];
    return IMAGE_EXTENSIONS.some(ext => name.toLowerCase().endsWith(ext));
}

// Memory (RAM) image extensions - distinct from isImageFile() above, which
// detects forensic disk images. .raw is a real, unavoidable overlap: both
// WinPmem (memory) and dc3dd/dd (disk) commonly produce a plain .raw file,
// so a .raw selection can legitimately show both "Browse as Image" and
// "Memory Forensics..." enabled at once - the examiner knows which one
// they actually have, same as how BitLocker/LUKS/Convert Image Format
// already all share isImageFile()'s own gate on a single .dd/.E01 file.
function isMemoryImageFile(name) {
    const MEMORY_IMAGE_EXTENSIONS = ['.raw', '.mem', '.vmem', '.dmp', '.lime'];
    return MEMORY_IMAGE_EXTENSIONS.some(ext => name.toLowerCase().endsWith(ext));
}

// Generic SQLite artifact viewer (D1) - gates the Database Details tab.
function isSqliteFile(name) {
    const SQLITE_EXTENSIONS = ['.db', '.sqlite', '.sqlite3'];
    return SQLITE_EXTENSIONS.some(ext => name.toLowerCase().endsWith(ext));
}

// Photo/picture extensions (distinct from isImageFile() above, which
// detects forensic disk images) - used to decide whether a case attachment
// gets a thumbnail preview via /api/files/raw.
function isPhotoImagePath(path) {
    const PHOTO_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
    return PHOTO_EXTENSIONS.some(ext => path.toLowerCase().endsWith(ext));
}

// Entry point for both the context menu's "Browse as Image" action (reads
// the currently right-clicked/selected real file) and double-clicking a
// recognized image file directly in the file list.
function enterExplorerImage() {
    if (!activeSelectedFile) return;
    enterExplorerImageFor({ path: activeSelectedFile, name: activeSelectedFile.split('/').pop() });
}

function enterExplorerImageFor(item) {
    explorerImageMode = true;
    explorerImagePath = item.path;
    explorerImageOffset = 0;
    explorerImagePathStack = [];
    explorerImageSelected = null;
    explorerImageView = 'browse';
    explorerDetailsIsImage = true; // so switching to Hex/Metadata before selecting anything still uses the right (empty-state) loader

    const toolbar = document.getElementById("explorerImageToolbar");
    if (toolbar) toolbar.style.display = 'flex';

    const preview = document.getElementById("explorerPreview");
    if (preview) {
        preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        preview.innerHTML = '<span class="text-subtle small">Select a file to preview.</span>';
    }

    // Metadata is available in image mode too (loadExplorerImageMetadataPane()
    // extracts to a temp file for exiftool, same pattern as in-image Binwalk/
    // Strings) - just reset to Preview as the default view on entry.
    switchExplorerRightView('preview');

    // Returning this (rather than a fire-and-forget call) lets a caller that
    // needs the initial partition/directory load to actually finish first -
    // e.g. contextMenuBrowseImageAnd()'s Search/Timeline shortcuts, which
    // render their own view into #explorerContainer right after entering;
    // without awaiting this, loadExplorerImagePartitions()'s own trailing
    // loadExplorerImageDir('') call resolves a moment later and clobbers
    // that view back to a plain directory listing. Every existing caller
    // (double-click, "Browse as Image", etc.) already ignored this return
    // value, so returning a promise instead of undefined changes nothing
    // for them.
    return loadExplorerImagePartitions();
}

// Live Device Preview (FTK Imager's "Preview" feature) - browse a raw,
// write-blocked drive's real filesystem read-only, before ever running a
// full acquisition against it. Reuses enterExplorerImageFor() completely
// unmodified: every existing image-mode tool (Search, Timeline, Hex,
// Metadata, Geolocation, Hash Manifest, Recover Deleted, Triage Scan,
// browser-artifact parsing) already only cares about explorerImagePath/
// explorerImageOffset, not whether that path is a real acquired file or a
// live device the backend just ACL-granted read access to.
async function startDevicePreview() {
    // Deliberately reads #driveSelect directly rather than
    // getActiveTargetDrive() - that helper's "|| /dev/sda" fallback exists
    // for harmless read-only telemetry display when nothing's selected yet,
    // but silently defaulting a preview-and-ACL-grant action to /dev/sda
    // with no drive actually chosen would be a real footgun, not a
    // convenience.
    const devicePath = document.getElementById("driveSelect")?.value || "";
    if (!devicePath) return showToast('Select a target source drive first.', 'warning');
    if (!confirm(`Preview ${devicePath} read-only?\n\nThis browses the live drive directly - not yet an acquired image. The drive's existing write-blocking protection still applies; only read access is granted, and it's revoked again when you exit the preview.`)) return;

    try {
        const res = await fetch('/api/image/preview/enter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_path: devicePath })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Preview failed: ${data.error}`, 'danger');
            return;
        }
        explorerDevicePreviewPath = devicePath;
        switchToTab('explorer-tab');
        await enterExplorerImageFor({ path: devicePath, name: `LIVE PREVIEW: ${devicePath}` });
        const banner = document.getElementById('explorerLivePreviewBanner');
        if (banner) banner.style.display = 'block';
        showToast(`Previewing ${devicePath} read-only - found ${data.filesystem_count} filesystem(s).`, 'success');
    } catch (err) {
        showToast('Preview failed - see console.', 'danger');
    }
}

// --- Consolidated "Encrypted Volume" unlock-an-already-acquired-image flow
// (BitLocker/LUKS/VeraCrypt) and browse the decrypted volume with the
// normal Sleuth Kit Image Browser - zero new browsing code needed, since
// enterExplorerImageFor() doesn't care whether the path it's given is a
// real evidence file or a dislocker-file/cryptsetup-mapper virtual mount;
// both are just a path pytsk3 can open. Replaces what used to be 2
// separate near-identical blocks of 3 functions each with ONE generic set,
// parameterized by encVolImageTypeSelect's current value (2026-08-26,
// mirrors the pre-acquisition consolidation above for the same reason).
let encVolUnlockImageModalInstance = null;

function openEncVolUnlockImageModal() {
    if (!activeSelectedFile) return;
    document.getElementById("encVolImageFileName").textContent = activeSelectedFile.split('/').pop();
    const offsetEl = document.getElementById("encVolImageOffset");
    if (offsetEl) offsetEl.value = '0';
    const keyEl = document.getElementById("encVolImageKey");
    if (keyEl) keyEl.value = '';
    onEncVolImageTypeChange();

    if (!encVolUnlockImageModalInstance) {
        encVolUnlockImageModalInstance = new bootstrap.Modal(document.getElementById('encVolUnlockImageModal'));
    }
    encVolUnlockImageModalInstance.show();
}

function onEncVolImageTypeChange() {
    const type = document.getElementById("encVolImageTypeSelect")?.value || 'bitlocker';
    const keyEl = document.getElementById("encVolImageKey");
    if (keyEl) keyEl.placeholder = ENC_VOL_CREDENTIAL_PLACEHOLDER[type] || 'Recovery Key / Password';
    const status = document.getElementById("encVolImageStatus");
    if (status) status.textContent = "Select the encryption type, enter the byte offset of the encrypted partition (0 if this image has no partition table) and the credential, then click Unlock & Browse.";
}

async function detectEncVolImage() {
    if (!activeSelectedFile) return;
    const type = document.getElementById("encVolImageTypeSelect")?.value || 'bitlocker';
    const offset = document.getElementById("encVolImageOffset")?.value || '0';
    const status = document.getElementById("encVolImageStatus");
    if (status) status.textContent = `Checking for a ${ENC_VOL_TYPE_LABELS[type]} signature at this offset...`;
    try {
        const res = await fetch(`/api/${type}/detect_image`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: activeSelectedFile, offset })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Detect failed: ${data.error}`;
            return;
        }
        if (status) {
            if (data.note) {
                status.textContent = data.note;
            } else {
                const isMatch = data.is_bitlocker ?? data.is_luks;
                status.textContent = isMatch
                    ? `${ENC_VOL_TYPE_LABELS[type]} signature found at this offset. Enter the credential and click Unlock & Browse.`
                    : `No ${ENC_VOL_TYPE_LABELS[type]} signature found at this offset - double-check the partition byte offset (Use the whole-image \"Search Inside Image\"/mmls partition listing if unsure), or try Unlock & Browse anyway if you believe this is wrong.`;
            }
        }
    } catch (err) {
        if (status) status.textContent = "Detect failed - see console.";
    }
}

async function unlockEncVolImageAndBrowse() {
    if (!activeSelectedFile) return;
    const type = document.getElementById("encVolImageTypeSelect")?.value || 'bitlocker';
    const offset = document.getElementById("encVolImageOffset")?.value || '0';
    const credential = document.getElementById("encVolImageKey")?.value || "";
    const status = document.getElementById("encVolImageStatus");
    if (!credential.trim()) return showToast(`Enter the ${ENC_VOL_CREDENTIAL_PLACEHOLDER[type]} first.`, 'warning');
    if (status) status.textContent = "Unlocking (this can take a few seconds)...";
    try {
        const res = await fetch(`/api/${type}/unlock_image`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: activeSelectedFile, offset, [ENC_VOL_CREDENTIAL_FIELD[type]]: credential })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Unlock failed: ${data.error}`;
            showToast(`${ENC_VOL_TYPE_LABELS[type]} unlock failed: ${data.error}`, 'danger');
            return;
        }
        explorerImageEncVolMountId = data.mount_id;
        explorerImageEncVolType = type;
        if (encVolUnlockImageModalInstance) encVolUnlockImageModalInstance.hide();
        showToast(`${ENC_VOL_TYPE_LABELS[type]} volume unlocked - browsing the decrypted image now.`, 'success');
        const originalName = activeSelectedFile.split('/').pop();
        await enterExplorerImageFor({ path: data.source_path, name: `${originalName} (${ENC_VOL_TYPE_LABELS[type]} Decrypted)` });
    } catch (err) {
        if (status) status.textContent = "Unlock failed - see console.";
    }
}

// explorerPath (the JS variable, not the #explorerPath DOM label) is never
// mutated while in image mode - only loadExplorer() touches it, and nothing
// calls that until exitExplorerImage() does - so it still holds the real
// filesystem directory the image lives in, with no separate state needed.
function exitExplorerImage() {
    explorerImageMode = false;
    explorerDetailsIsImage = false;
    const toolbar = document.getElementById("explorerImageToolbar");
    if (toolbar) toolbar.style.display = 'none';

    // If this was a decrypted BitLocker/LUKS/VeraCrypt volume, lock/unmount
    // it now - a decrypted mount is sensitive and shouldn't linger past the
    // browsing session that needed it. Fire-and-forget: exiting the view
    // shouldn't block on the unmount, and there's nothing else in the UI
    // that needs to wait for it to finish.
    if (explorerImageEncVolMountId && explorerImageEncVolType) {
        const mountId = explorerImageEncVolMountId;
        const type = explorerImageEncVolType;
        explorerImageEncVolMountId = null;
        explorerImageEncVolType = null;
        fetch(`/api/${type}/lock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mount_id: mountId })
        }).catch(() => {});
    }

    // Live Device Preview: revoke the temporary read-ACL grant on exit -
    // same fire-and-forget reasoning as the BitLocker lock above, plus the
    // server-side idle-sweep as a backstop for an unclean exit (tab closed
    // without ever reaching here).
    if (explorerDevicePreviewPath) {
        const devicePath = explorerDevicePreviewPath;
        explorerDevicePreviewPath = null;
        fetch('/api/image/preview/exit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_path: devicePath })
        }).catch(() => {});
    }

    document.getElementById("explorerLivePreviewBanner")?.remove();

    initExplorerTree(); // restores the real-fs tree exactly as left, no re-fetch
    loadExplorer(explorerPath);
}

async function loadExplorerImagePartitions() {
    const select = document.getElementById("explorerImagePartitionSelect");
    if (select) select.innerHTML = '<option value="0">Loading...</option>';

    try {
        const res = await fetch('/api/image/mmls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath })
        });
        const data = await res.json();
        if (!select) return;
        select.innerHTML = '';

        if (!data.success || !data.partitions || data.partitions.length === 0) {
            // No partition table detected - fall back to treating the whole
            // image as a single filesystem at offset 0, common for a
            // single-partition raw dd of e.g. a phone or a small media card.
            const opt = document.createElement('option');
            opt.value = '0';
            opt.textContent = 'Whole image (offset 0)';
            select.appendChild(opt);
        } else {
            data.partitions.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.start_sector;
                opt.textContent = `Slot ${p.slot}: ${p.description} (offset ${p.start_sector})`;
                select.appendChild(opt);
            });
        }

        explorerImagePathStack = [];
        await initExplorerImageTree();
        await loadExplorerImageDir('');
    } catch (err) {
        if (select) select.innerHTML = '<option value="0">Error loading partitions</option>';
    }
}

function explorerImageChangePartition() {
    explorerImagePathStack = [];
    initExplorerImageTree(); // inode numbering is partition-specific, rebuild from scratch
    loadExplorerImageDir('');
}

function updateExplorerImagePathDisplay() {
    const pathLabel = document.getElementById("explorerPath");
    if (!pathLabel || !explorerImagePath) return;
    const imageName = explorerImagePath.split('/').pop();
    const innerPath = '/' + explorerImagePathStack.map(p => p.name).join('/');
    pathLabel.textContent = `💿 ${imageName} : ${innerPath}`;
    pathLabel.title = `${imageName} : ${innerPath}`;
}

async function loadExplorerImageDir(inode) {
    const select = document.getElementById("explorerImagePartitionSelect");
    explorerImageOffset = select ? parseInt(select.value, 10) || 0 : 0;
    explorerImageView = 'browse';
    explorerImageSelected = null;
    updateExplorerImagePathDisplay();

    const container = document.getElementById("explorerContainer");
    if (container) container.innerHTML = '<div class="p-2 text-subtle small">Loading...</div>';

    try {
        const res = await fetch('/api/image/fls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, inode })
        });
        const data = await res.json();
        if (!container) return;

        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'p-2 text-danger small';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }

        // "Up" pseudo-row: parent directory inside the image, or exit the
        // image entirely (back to the real filesystem) if already at its root.
        explorerRenderUpRow = () => {
            const upDiv = document.createElement('div');
            upDiv.className = 'file-item text-warning fw-bold';
            upDiv.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. [Up]';
            upDiv.onclick = () => explorerImageGoUp();
            container.appendChild(upDiv);
        };

        explorerActiveRows = data.entries.map(entry => ({
            name: entry.name, size: entry.size, modified: entry.mtime,
            accessed: entry.atime, changed: entry.ctime, created: entry.crtime, raw: entry
        }));
        explorerListingExtraCols = [];
        explorerActiveRowRenderer = (tbody, entry) => renderExplorerImageEntryRow(tbody, entry);
        renderExplorerActiveTable();

        syncExplorerImageTreeSelection();
    } catch (err) {
        if (container) container.innerHTML = '<div class="p-2 text-danger small">Request failed.</div>';
    }
}

function explorerImageGoUp() {
    if (explorerImagePathStack.length === 0) {
        exitExplorerImage();
        return;
    }
    explorerImagePathStack.pop();
    updateExplorerImagePathDisplay();
    const parentInode = explorerImagePathStack.length > 0 ? explorerImagePathStack[explorerImagePathStack.length - 1].inode : '';
    loadExplorerImageDir(parentInode);
}

// Shared row renderer for both directory listings and search results -
// displayName lets search show a full path while browse shows a bare name.
// `container` must be a <tbody> (or any element valid to hold a <tr>) -
// both call sites now render into a table, matching the real-fs listing.
function renderExplorerImageEntryRow(container, entry, displayName) {
    const tr = document.createElement('tr');
    tr.className = 'file-item';

    const nameTd = document.createElement('td');
    const icon = entry.is_dir
        ? '<i class="bi bi-folder-fill folder-icon me-2 fs-6"></i>'
        : '<i class="bi bi-file-earmark-text text-info me-2 fs-6"></i>';
    const labelSpan = document.createElement('span');
    labelSpan.className = entry.is_dir ? 'folder-text' : 'text-light';
    labelSpan.innerHTML = icon; // static/trusted markup
    labelSpan.appendChild(document.createTextNode(displayName || entry.name)); // untrusted evidence filename, text-only
    if (entry.deleted) {
        const delBadge = document.createElement('span');
        delBadge.className = 'badge bg-danger ms-2';
        delBadge.textContent = 'DELETED';
        labelSpan.appendChild(delBadge);
    }
    nameTd.appendChild(labelSpan);

    const sizeTd = document.createElement('td');
    sizeTd.className = 'text-subtle font-monospace';
    sizeTd.textContent = entry.is_dir ? '' : imgFormatBytes(entry.size);

    const modTd = document.createElement('td');
    modTd.className = 'text-subtle font-monospace';
    modTd.textContent = imgFormatTimestamp(entry.mtime);

    const accTd = document.createElement('td');
    accTd.className = 'text-subtle font-monospace';
    accTd.textContent = imgFormatTimestamp(entry.atime);

    const chgTd = document.createElement('td');
    chgTd.className = 'text-subtle font-monospace';
    chgTd.textContent = imgFormatTimestamp(entry.ctime);

    const createdTd = document.createElement('td');
    createdTd.className = 'text-subtle font-monospace';
    createdTd.textContent = imgFormatTimestamp(entry.crtime);

    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);
    tr.appendChild(accTd);
    tr.appendChild(chgTd);
    tr.appendChild(createdTd);

    tr.onclick = () => {
        document.querySelectorAll('.file-pane .file-item').forEach(el => el.classList.remove('active'));
        tr.classList.add('active');
        explorerImageSelected = entry;
        explorerDetailsIsImage = true;
        if (!entry.is_dir) previewExplorerImageEntry(entry);
        refreshExplorerDetailsView();
    };

    tr.ondblclick = () => {
        if (entry.is_dir && explorerImageView === 'browse') {
            explorerImagePathStack.push({ inode: entry.inode, name: entry.name });
            loadExplorerImageDir(entry.inode);
        }
    };

    tr.oncontextmenu = (ev) => {
        ev.preventDefault();
        showExplorerImageContextMenu(ev, entry);
        return false;
    };

    container.appendChild(tr);
}

// In-memory preview straight from the image - no extract-to-disk step
// first, unlike the old icat-then-browse-in-File-Explorer flow this
// replaced. Renders into the same #explorerPreview pane real files use.
async function previewExplorerImageEntry(entry) {
    const preview = document.getElementById("explorerPreview");
    if (!preview) return;

    const dbBtn = document.getElementById('explorerViewDatabaseBtn');
    if (dbBtn) {
        const showDb = !entry.is_dir && isSqliteFile(entry.name || '');
        dbBtn.style.display = showDb ? '' : 'none';
        if (!showDb && explorerRightView === 'database') switchExplorerRightView('preview');
    }

    preview.className = 'file-pane p-2';
    preview.innerHTML = '<span class="text-subtle small">Loading preview...</span>';

    try {
        const res = await fetch('/api/image/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, inode: entry.inode, name: entry.name })
        });
        const data = await res.json();
        preview.innerHTML = '';

        if (!data.success) {
            preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
            const err = document.createElement('span');
            err.className = 'text-danger small';
            err.textContent = data.error;
            preview.appendChild(err);
            return;
        }

        if (data.kind === 'image') {
            const img = document.createElement('img');
            img.src = `data:${data.mime};base64,${data.data}`;
            img.style.maxWidth = '100%';
            img.style.maxHeight = '100%';
            img.style.objectFit = 'contain';
            preview.appendChild(img);
        } else if (data.kind === 'pdf') {
            // Same browser-native-viewer-via-iframe approach as the real-
            // filesystem PDF preview (previewSelectedFile()) - just pointed
            // at a data: URI instead of /api/files/raw, since there's no
            // real on-disk path for a still-in-image file.
            preview.className = 'file-pane p-0';
            const iframe = document.createElement('iframe');
            iframe.src = `data:application/pdf;base64,${data.data}`;
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            iframe.title = 'PDF preview';
            preview.appendChild(iframe);
        } else if (data.kind === 'too_large') {
            preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
            preview.innerHTML = '<span class="text-subtle small">File too large to preview inline - use Extract instead.</span>';
        } else if (entry.name.toLowerCase().endsWith('.kml')) {
            // .kml isn't an image extension, so /api/image/preview already
            // returned it as kind:'text' - render the shared map viewer
            // instead of a plain <pre> dump.
            preview.className = 'file-pane p-2 d-block text-start';
            renderKmlViewer(preview, data.text);
        } else {
            preview.className = 'file-pane p-2 d-block text-start';
            const pre = document.createElement('pre');
            pre.className = 'log-window mb-0';
            pre.style.height = '100%';
            pre.textContent = data.text + (data.truncated ? '\n\n[... truncated, file is larger than the preview limit ...]' : ''); // untrusted evidence content, text node only
            preview.appendChild(pre);
        }
    } catch (err) {
        preview.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        preview.innerHTML = '<span class="text-danger small">Preview request failed.</span>';
    }
}

// In-image counterpart to loadExplorerMetadataPane() - two sections, mirroring
// Autopsy's own "File Metadata" tab: filesystem-level metadata (inode,
// allocation status, MACB timestamps) is already in hand from whichever
// directory listing/search/timeline row was clicked (explorerImageSelected),
// so it renders instantly with no request; embedded metadata (EXIF/GPS/
// camera info) is fetched from /api/image/exif, which extracts the file to a
// short-lived temp file for exiftool - the same pattern already proven for
// in-image Binwalk/Strings.
function renderMetadataRow(tbody, key, value) {
    const row = document.createElement('tr');
    const keyCell = document.createElement('td');
    keyCell.className = 'text-info fw-bold text-nowrap';
    keyCell.style.width = '35%';
    keyCell.textContent = key;
    const valCell = document.createElement('td');
    valCell.className = 'text-break';
    valCell.textContent = String(value); // untrusted evidence value - text node, never innerHTML
    row.appendChild(keyCell);
    row.appendChild(valCell);
    tbody.appendChild(row);
}

async function loadExplorerImageMetadataPane() {
    const container = document.getElementById('explorerMetadata');
    if (!container) return;

    const entry = explorerImageSelected;
    // entry.is_dir === true (not just truthy) so a timeline event - which
    // has no is_dir field at all - doesn't get mistaken for a directory here.
    if (!entry || entry.is_dir === true) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<i class="bi bi-info-circle fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file on the left to view its metadata.</span>';
        return;
    }

    container.className = 'file-pane p-2 d-block text-start';
    container.innerHTML = '';

    const fsHeading = document.createElement('div');
    fsHeading.className = 'text-subtle small fw-bold mb-1';
    fsHeading.textContent = 'Filesystem Metadata';
    container.appendChild(fsHeading);

    const fsTable = document.createElement('table');
    fsTable.className = 'table table-sm table-dark table-striped mb-2';
    const fsBody = document.createElement('tbody');
    // A timeline-event-shaped entry only carries {inode, path, deleted,
    // activity, timestamp} (see the Timeline results renderer) rather than a
    // full directory-listing entry - skip whichever fields it doesn't have
    // instead of showing "undefined" for them.
    const entryName = entry.name || (entry.path ? entry.path.split('/').pop() : null);
    [
        ['Name', entryName],
        ['Path', entry.path],
        ['Inode', entry.inode],
        ['Deleted', entry.deleted !== undefined ? (entry.deleted ? 'Yes' : 'No') : undefined],
        ['TSK Virtual Entry', entry.is_virtual !== undefined ? (entry.is_virtual ? 'Yes' : 'No') : undefined],
        ['Size', entry.size !== undefined ? imgFormatBytes(entry.size) : undefined],
        ['Modified (M)', entry.mtime !== undefined ? imgFormatTimestamp(entry.mtime) : undefined],
        ['Accessed (A)', entry.atime !== undefined ? imgFormatTimestamp(entry.atime) : undefined],
        ['Changed (C)', entry.ctime !== undefined ? imgFormatTimestamp(entry.ctime) : undefined],
        ['Born / Created (B)', entry.crtime !== undefined ? imgFormatTimestamp(entry.crtime) : undefined],
    ].filter(([, v]) => v !== undefined && v !== null)
     .forEach(([key, value]) => renderMetadataRow(fsBody, key, value));
    fsTable.appendChild(fsBody);
    container.appendChild(fsTable);

    const exifHeading = document.createElement('div');
    exifHeading.className = 'text-subtle small fw-bold mb-1';
    exifHeading.textContent = 'Embedded Metadata (ExifTool)';
    container.appendChild(exifHeading);
    const exifStatus = document.createElement('div');
    exifStatus.className = 'text-subtle small';
    exifStatus.textContent = 'Loading...';
    container.appendChild(exifStatus);

    // Snapshot which entry this fetch is for - a fast second click while the
    // first exiftool call is still in flight shouldn't render stale results
    // into the pane after the examiner has already moved on to another file.
    const requestedInode = entry.inode;

    try {
        const res = await fetch('/api/image/exif', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: entry.inode, name: entryName || 'selected_file',
            })
        });
        const data = await res.json();
        if (explorerImageSelected !== entry || explorerImageSelected.inode !== requestedInode) return;

        exifStatus.remove();
        if (!data.success) {
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }

        const exifEntries = Object.entries(data.metadata || {});
        const exifTable = document.createElement('table');
        exifTable.className = 'table table-sm table-dark table-striped mb-0';
        const exifBody = document.createElement('tbody');
        if (exifEntries.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = 'No embedded metadata found.';
            cell.className = 'text-subtle';
            row.appendChild(cell);
            exifBody.appendChild(row);
        } else {
            exifEntries.forEach(([key, value]) => renderMetadataRow(exifBody, key, value));
        }
        exifTable.appendChild(exifBody);
        container.appendChild(exifTable);
    } catch (err) {
        if (explorerImageSelected !== entry) return;
        exifStatus.textContent = 'Request failed.';
        exifStatus.className = 'text-danger small';
    }
}

// In-image counterpart to loadExplorerHexPane() - reuses the same
// formatHexDump() renderer, just fetches from /api/image/hex instead.
async function loadExplorerImageHexPane() {
    const container = document.getElementById('explorerHex');
    if (!container) return;

    const entry = explorerImageSelected;
    if (!entry || entry.is_dir === true) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<i class="bi bi-code-square fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file on the left to view its raw bytes.</span>';
        return;
    }

    container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
    container.innerHTML = '<span class="text-subtle small">Loading hex view...</span>';

    const requestedInode = entry.inode;

    try {
        const res = await fetch('/api/image/hex', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, inode: entry.inode })
        });
        const data = await res.json();
        if (explorerImageSelected !== entry || explorerImageSelected.inode !== requestedInode) return;

        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }

        container.className = 'file-pane p-2 d-block text-start';
        container.innerHTML = '';
        const pre = document.createElement('pre');
        pre.className = 'log-window mb-0';
        pre.style.height = '100%';
        pre.textContent = formatHexDump(data.data) +
            (data.truncated ? `\n\n[... truncated, showing first ${data.bytes_read.toLocaleString()} of ${data.total_size.toLocaleString()} bytes ...]` : '');
        container.appendChild(pre);
    } catch (err) {
        if (explorerImageSelected !== entry) return;
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<span class="text-danger small">Request failed.</span>';
    }
}

function explorerImageBackToBrowseRow(container) {
    const backDiv = document.createElement('div');
    backDiv.className = 'file-item text-warning fw-bold';
    backDiv.innerHTML = '<i class="bi bi-arrow-left me-1"></i>Back to Browse';
    backDiv.onclick = () => {
        const currentInode = explorerImagePathStack.length > 0 ? explorerImagePathStack[explorerImagePathStack.length - 1].inode : '';
        loadExplorerImageDir(currentInode);
    };
    container.appendChild(backDiv);
}

function explorerImageToggleSearch() {
    explorerImageView = 'search';
    const container = document.getElementById("explorerContainer");
    if (!container) return;
    container.innerHTML = '';
    explorerImageBackToBrowseRow(container);

    const formDiv = document.createElement('div');
    formDiv.className = 'p-2';
    formDiv.innerHTML = '<div class="input-group input-group-sm mb-1">' +
        '<input type="text" id="explorerImageSearchQuery" class="form-control" placeholder="Filename contains...">' +
        '<button class="btn btn-outline-info fw-bold" id="explorerImageSearchBtn"><i class="bi bi-search"></i></button>' +
        '</div><div class="text-subtle small">Searches recursively from this partition\'s root. Capped at 500 results.</div>';
    container.appendChild(formDiv);

    const resultsDiv = document.createElement('div');
    resultsDiv.id = 'explorerImageSearchResults';
    container.appendChild(resultsDiv);

    document.getElementById('explorerImageSearchBtn').onclick = runExplorerImageSearch;
    document.getElementById('explorerImageSearchQuery').onkeydown = (ev) => { if (ev.key === 'Enter') runExplorerImageSearch(); };
    document.getElementById('explorerImageSearchQuery').focus();
}

async function runExplorerImageSearch() {
    const queryEl = document.getElementById("explorerImageSearchQuery");
    const query = queryEl ? queryEl.value.trim() : '';
    const resultsEl = document.getElementById("explorerImageSearchResults");
    if (!resultsEl) return;
    if (!query) {
        resultsEl.innerHTML = '<div class="p-2 text-subtle small">Enter a search term above.</div>';
        return;
    }

    resultsEl.innerHTML = '<div class="p-2 text-subtle small">Searching...</div>';
    try {
        const res = await fetch('/api/image/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset, query })
        });
        const data = await res.json();
        resultsEl.innerHTML = '';

        if (!data.success) {
            const err = document.createElement('div');
            err.className = 'p-2 text-danger small';
            err.textContent = data.error;
            resultsEl.appendChild(err);
            return;
        }
        if (data.results.length === 0) {
            resultsEl.innerHTML = '<div class="p-2 text-subtle small">No matches found.</div>';
            return;
        }

        // renderExplorerImageEntryRow() emits <tr>s - give it a real table
        // to render into, matching the browse listing's row shape (plain,
        // non-clickable headers here since search results aren't re-sorted
        // client-side, unlike the browse table).
        const table = document.createElement('table');
        table.className = 'table table-dark table-sm table-hover mb-0';
        table.innerHTML = '<thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead>';
        const tbody = document.createElement('tbody');
        table.appendChild(tbody);
        resultsEl.appendChild(table);
        data.results.forEach(entry => renderExplorerImageEntryRow(tbody, entry, entry.path));

        if (data.truncated) {
            const note = document.createElement('div');
            note.className = 'p-2 text-subtle small';
            note.textContent = 'Showing the first 500 matches - narrow your search term for a complete result set.';
            resultsEl.appendChild(note);
        }
    } catch (err) {
        resultsEl.innerHTML = '<div class="p-2 text-danger small">Request failed.</div>';
    }
}

function explorerImageToggleTimeline() {
    explorerImageView = 'timeline';
    const container = document.getElementById("explorerContainer");
    if (!container) return;
    container.innerHTML = '';
    explorerImageBackToBrowseRow(container);

    const genDiv = document.createElement('div');
    genDiv.className = 'p-2';
    genDiv.innerHTML = '<button class="btn btn-sm btn-outline-info fw-bold w-100 mb-1" id="explorerImageTimelineBtn"><i class="bi bi-clock-history me-1"></i>Generate Timeline</button>' +
        '<div class="text-subtle small">MACB timestamps for every file on this partition, most recent first. Capped at 5000 events - can take a while on a large filesystem.</div>';
    container.appendChild(genDiv);

    const resultsDiv = document.createElement('div');
    resultsDiv.id = 'explorerImageTimelineResults';
    container.appendChild(resultsDiv);

    document.getElementById('explorerImageTimelineBtn').onclick = runExplorerImageTimeline;
}

async function runExplorerImageTimeline() {
    const resultsEl = document.getElementById("explorerImageTimelineResults");
    if (!resultsEl) return;
    resultsEl.innerHTML = '<div class="p-2 text-subtle small">Generating - this walks the entire filesystem and can take a while...</div>';

    try {
        const res = await fetch('/api/image/timeline', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, offset: explorerImageOffset })
        });
        const data = await res.json();
        resultsEl.innerHTML = '';

        if (!data.success) {
            const err = document.createElement('div');
            err.className = 'p-2 text-danger small';
            err.textContent = data.error;
            resultsEl.appendChild(err);
            return;
        }
        if (data.events.length === 0) {
            resultsEl.innerHTML = '<div class="p-2 text-subtle small">No timestamped entries found.</div>';
            return;
        }

        const activityLabels = { M: 'Modified', A: 'Accessed', C: 'Changed', B: 'Born' };
        const activityColors = { M: 'text-info', A: 'text-subtle', C: 'text-warning', B: 'text-success' };
        data.events.forEach(ev => {
            const row = document.createElement('div');
            row.className = 'file-item';

            const line1 = document.createElement('div');
            const actSpan = document.createElement('span');
            actSpan.className = `fw-bold me-2 ${activityColors[ev.activity] || ''}`;
            actSpan.textContent = `[${activityLabels[ev.activity] || ev.activity}]`;
            line1.appendChild(actSpan);
            line1.appendChild(document.createTextNode(imgFormatTimestamp(ev.timestamp)));

            const line2 = document.createElement('div');
            line2.className = 'text-subtle small text-break';
            line2.textContent = ev.path + (ev.deleted ? '  [DELETED]' : ''); // untrusted evidence path, text-only

            row.appendChild(line1);
            row.appendChild(line2);

            row.onclick = () => {
                document.querySelectorAll('.file-pane .file-item').forEach(el => el.classList.remove('active'));
                row.classList.add('active');
                explorerImageSelected = ev;
                explorerDetailsIsImage = true;
                refreshExplorerDetailsView();
            };

            resultsEl.appendChild(row);
        });

        if (data.truncated) {
            const note = document.createElement('div');
            note.className = 'p-2 text-subtle small';
            note.textContent = 'Showing the first 5000 events - this filesystem has more activity than fits in one timeline.';
            resultsEl.appendChild(note);
        }
    } catch (err) {
        resultsEl.innerHTML = '<div class="p-2 text-danger small">Request failed.</div>';
    }
}

async function extractExplorerImageSelected() {
    if (!explorerImageSelected) return;
    // Land in the active case's own folder when one is selected, instead of
    // dumping extracted files loose at the evidence root - matches how
    // every other job-launcher already routes its output once a case is
    // active (see applyActiveCaseToFields()).
    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    try {
        const res = await fetch('/api/image/extract', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath,
                offset: explorerImageOffset,
                inode: explorerImageSelected.inode,
                output_name: explorerImageSelected.name,
                destination_dir: destinationDir
            })
        });
        const data = await res.json();
        showToast(data.success ? data.message : `Extraction failed: ${data.error}`, data.success ? 'success' : 'danger');
    } catch (err) {}
}

// A virtual in-image entry has no real on-disk path to attach directly, so
// this pulls it out to the active case folder (the same extract route
// extractExplorerImageSelected() uses) and then attaches the resulting real
// file - one context-menu click instead of "Extract, then go find it in the
// real File Explorer and Attach to Case separately."
async function extractAndAttachExplorerImageSelected() {
    if (!explorerImageSelected || !activeCase) return;
    try {
        const extractRes = await fetch('/api/image/extract', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath,
                offset: explorerImageOffset,
                inode: explorerImageSelected.inode,
                output_name: explorerImageSelected.name,
                destination_dir: activeCase.case_folder
            })
        });
        const extractData = await extractRes.json();
        if (!extractData.success) {
            showToast(`Extraction failed: ${extractData.error}`, 'danger');
            return;
        }

        // Provenance the examiner would otherwise lose the moment this lands
        // as just another path on disk - auto-populated only here, since
        // this is the one attach path that actually knows something worth
        // saying. Applied server-side only if the attachment doesn't
        // already have a caption, so it never overwrites an examiner's own
        // edit made since a prior extract.
        const imageName = (explorerImagePath || '').split('/').pop();
        const inImagePath = explorerImageSelected.path || explorerImageSelected.name;
        const provenanceCaption = `Extracted from ${imageName} (in-image path: ${inImagePath})`;

        const attachRes = await fetch('/api/cases/attach_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, file_path: extractData.path, caption: provenanceCaption })
        });
        const attachData = await attachRes.json();
        if (attachData.success) {
            showToast(`Extracted and attached to ${activeCase.case_number} as a case exhibit (${attachData.file_count} file(s) now attached). Edit captions in Reporting > Files & Artifacts.`, 'success');
            if (currentReportPath) loadCaseForEditing();
        } else {
            showToast(`Extracted to ${extractData.path}, but attaching to the case failed: ${attachData.error}`, 'danger');
        }
    } catch (err) {}
}

async function runImageBinwalk() {
    if (!explorerImageSelected) return;
    showToolOutputModal(`Binwalk: ${explorerImageSelected.name}`, 'bi-cpu');
    try {
        const res = await fetch('/api/image/binwalk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: explorerImageSelected.inode, name: explorerImageSelected.name,
                path: explorerImageSelected.path || null,
                case_folder: activeCase ? activeCase.case_folder : null
            })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = data.success ? data.output : `[ERROR] ${data.error}`;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

async function runImageStrings() {
    if (!explorerImageSelected) return;
    showToolOutputModal(`Strings: ${explorerImageSelected.name}`, 'bi-fonts');
    try {
        const res = await fetch('/api/image/strings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: explorerImagePath, offset: explorerImageOffset,
                inode: explorerImageSelected.inode, name: explorerImageSelected.name,
                path: explorerImageSelected.path || null,
                case_folder: activeCase ? activeCase.case_folder : null
            })
        });
        const data = await res.json();
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = data.success ? data.output : `[ERROR] ${data.error}`;
    } catch (err) {
        const container = document.getElementById("toolOutputContainer");
        if (container) container.textContent = '[REQUEST FAILED]';
    }
}

// Like startImageTriageScan(), this used to be a synchronous request but
// each candidate photo costs a real exiftool subprocess spawn (can
// genuinely take a while for a few hundred candidates), so it now starts a
// trackable background job instead - progress shown via the same shared
// #explorerJobProgress row.
async function runImageGeolocationExport() {
    if (!explorerImagePath) return;
    // Same active-case-folder-first destination as every other in-image action.
    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    try {
        const res = await fetch('/api/image/start_geolocation_kml', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, destination_dir: destinationDir })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Could not start geolocation scan: ${data.error}`, 'danger');
        }
        // No success alert - #explorerJobProgress + the completion
        // notification in fetchProgress() are the feedback.
    } catch (err) {
        showToast('Request failed.', 'danger');
    }
}

async function runImageHashManifest() {
    if (!explorerImagePath) return;
    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    // D2: automatically cross-references against every saved SHA256 hash
    // list (matching this action's own hardcoded algorithm below) - opt-
    // out, not opt-in, same reasoning the single-file Check Against Hash
    // Lists action uses: this button has no options prompt at all today,
    // so requiring a new modal just to pick lists would be a bigger UI
    // change than this one action's own established fire-and-forget shape.
    const allLists = await fetchHashLists();
    const hashListIds = allLists.filter(l => l.algorithm === 'sha256').map(l => l.id);
    try {
        const res = await fetch('/api/image/hash_manifest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, destination_dir: destinationDir, algorithm: 'sha256', hash_list_ids: hashListIds })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Hash manifest failed: ${data.error}`, 'danger');
            return;
        }
        let msg = `Hashed ${data.files_hashed} file(s) inside the image.\nManifest written to:\n${data.manifest_path}`;
        if (data.files_errored > 0) {
            msg += `\n\n${data.files_errored} file(s) could not be read and were skipped.`;
        }
        if (data.truncated) {
            msg += `\n\nNote: this image has more files than could be hashed in one pass - results are partial.`;
        }
        if (hashListIds.length > 0) {
            msg += data.hash_list_match_count > 0
                ? `\n\n${data.hash_list_match_count} file(s) matched a saved hash list - see the manifest for details.`
                : `\n\nChecked against ${hashListIds.length} saved SHA256 hash list(s) - no matches.`;
        }
        showToast(msg, data.hash_list_match_count > 0 ? 'warning' : 'success');
    } catch (err) {}
}

async function runImageBrowserArtifactsParse() {
    if (!explorerImagePath) return;
    try {
        const res = await fetch('/api/image/parse_browser_artifacts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Browser artifact scan failed: ${data.error}`, 'danger');
            return;
        }
        if (data.candidates_found === 0) {
            showToast('No Chrome/Chromium or Firefox profile files (History/Cookies/Bookmarks, places.sqlite/cookies.sqlite) found in this image.', 'success');
            return;
        }
        const truncNote = data.truncated ? ' (capped - not every candidate file may have been reached)' : '';
        const summary = summarizeBrowserArtifactCounts(data.counts);
        if (!data.indexed) {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} profile file(s): ${summary}${truncNote}. Select an active case to save these into File Views.`, 'info');
        } else {
            showToast(`Found ${data.files_parsed} of ${data.candidates_found} profile file(s): ${summary}${truncNote}. See File Views > Parsed Artifacts.`, 'success');
            initFileViewsTree(true);
        }
    } catch (err) {
        showToast('Browser artifact scan failed: request error.', 'danger');
    }
}

// Unlike every other in-image tool on this toolbar (which run synchronously
// and just block the button click until done), this walks every real file
// in the image and can genuinely take a while - it starts a trackable
// background job instead (the same shared current_job system Acquisition/
// Recovery/Mobile jobs use) rather than tying up the request. Progress is
// shown via #explorerJobProgress, updated by the same fetchProgress() poll
// that already drives every other tab's progress display.
async function startImageTriageScan() {
    if (!explorerImagePath) return;
    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    try {
        const res = await fetch('/api/image/start_triage_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, destination_dir: destinationDir })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Could not start triage scan: ${data.error}`, 'danger');
        }
        // On success, no alert - #explorerJobProgress (updated by the
        // existing fetchProgress() poll) is the feedback; a completion
        // message would just be redundant with the progress log itself.
    } catch (err) {
        showToast('Request failed.', 'danger');
    }
}

async function runImageRecoverDeleted() {
    if (!explorerImagePath) return;
    if (!confirm('Recover deleted files from this image? Recovery odds vary by filesystem type - NTFS/FAT usually work well, ext filesystems often do not, since data is frequently already gone by the time a file shows as deleted. A recovered file may also be partially overwritten if its space was reused - verify hashes where it matters.')) return;

    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    try {
        const res = await fetch('/api/image/recover_deleted', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, destination_dir: destinationDir })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Recovery failed: ${data.error}`, 'danger');
            return;
        }
        let msg;
        if (data.files_recovered === 0) {
            msg = 'No recoverable deleted files were found (with an intact directory entry) in this image.';
        } else {
            const mb = (data.total_bytes / (1024 * 1024)).toFixed(1);
            msg = `Recovered ${data.files_recovered} file(s), ${mb} MB total.\nOriginal names/folder structure preserved under:\n${data.output_dir}`;
        }
        if (data.files_skipped_too_large > 0) {
            msg += `\n\n${data.files_skipped_too_large} file(s) were skipped for being too large or exceeding the total-size budget.`;
        }
        if (data.files_skipped_empty > 0) {
            msg += `\n\n${data.files_skipped_empty} file(s) were skipped as empty/unrecoverable.`;
        }
        if (data.files_errored > 0) {
            msg += `\n\n${data.files_errored} file(s) could not be read and were skipped.`;
        }
        if (data.truncated) {
            msg += `\n\nNote: this image has more deleted files than could be recovered in one pass - results are partial.`;
        }
        showToast(msg, 'success');
    } catch (err) {}
}

// --- Case Attachments Gallery (Reporting > Files) ---
// Reuses the same discover_files + thumbnail pattern the Export pane's own
// file picker already proved out (renderExportFilesList()), but for a
// different purpose: here the checkbox state IS the persistent attachment
// list (currentAttachedFilesList), not a one-time per-export selection, and
// checked rows get an inline caption field. Toggling stays purely
// client-side, staged like every other Reporting field, and only written to
// disk when "Save Report Changes" is clicked - except files added via File
// Explorer's "Attach to Case" shortcut, which commits straight to disk
// immediately (no loaded-report state to stage through there). A long-lived
// Reporting tab with unsaved edits could theoretically clobber a File-
// Explorer-added attachment on its next save - the same "last write wins"
// tradeoff this app already accepts everywhere /api/report/save is used,
// not a new risk introduced here.
// classify_case_role() (core/paths.py) labels - this app's own generated
// housekeeping output (reports, hash-manifest/triage logs, KML exports,
// migration backups), kept in its own "Case-Generated Artifacts" group so
// it never gets mixed in with actual evidence the same way File Explorer's
// folder tree already separates it (CASE_ROLE_TREE_GROUP).
const REPORT_CASE_ROLE_LABELS = {
    report: 'Reports', analysis_log: 'Analysis Logs & Hashes',
    geolocation: 'Geolocation Exports', backup: 'Backup Snapshots',
};
const REPORT_CASE_ROLE_ICONS = {
    report: 'bi bi-file-earmark-pdf', analysis_log: 'bi bi-list-check',
    geolocation: 'bi bi-geo-alt', backup: 'bi bi-archive',
};
const REPORT_EXTENSION_CATEGORY_ICONS = {
    images: 'bi bi-image', videos: 'bi bi-camera-reels', audio: 'bi bi-music-note-beamed',
    archives: 'bi bi-file-zip', documents: 'bi bi-file-earmark-text',
    executables: 'bi bi-terminal', other: 'bi bi-file-earmark',
};

// One collapsed-by-default category group (header button with a count
// badge + chevron, plus a body div) - the same "one line per category
// until asked for more" idea already used for the context-menu sections
// and Settings' accordion, applied here so Reporting's Files tab reads as
// labeled groups instead of one flat undifferentiated list. If onExpand is
// given, it's called once (async, given the body element) the first time
// the group is actually opened, for data that's worth deferring until the
// examiner asks for it (Web Artifacts' per-type record fetch) rather than
// eagerly fetching every category's rows up front.
function buildReportFileGroup(container, label, count, iconClass, onExpand) {
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'report-file-group-toggle';
    const icon = document.createElement('i');
    icon.className = iconClass || 'bi bi-folder2';
    toggle.appendChild(icon);
    const labelSpan = document.createElement('span');
    labelSpan.textContent = label;
    toggle.appendChild(labelSpan);
    const countBadge = document.createElement('span');
    countBadge.className = 'badge bg-secondary';
    countBadge.textContent = String(count);
    toggle.appendChild(countBadge);
    const chevron = document.createElement('i');
    chevron.className = 'bi bi-chevron-down';
    toggle.appendChild(chevron);

    const body = document.createElement('div');
    body.className = 'report-file-group-body';
    body.style.display = 'none';
    let loaded = !onExpand;

    toggle.onclick = async () => {
        const expanded = toggle.classList.toggle('expanded');
        body.style.display = expanded ? 'block' : 'none';
        if (expanded && !loaded) {
            loaded = true;
            body.innerHTML = '<span class="text-subtle small italic">Loading...</span>';
            try {
                await onExpand(body);
            } catch (err) {
                body.innerHTML = '<span class="text-danger small">Failed to load.</span>';
            }
        }
    };

    container.appendChild(toggle);
    container.appendChild(body);
    return body;
}

// Guards against overlapping renders: loadCaseForEditing() calls this
// unconditionally on every case load (same "populate every sub-tab up
// front" pattern the other Reporting sub-tabs already use), and the Files
// nav button's own onclick calls it again whenever the examiner actually
// switches to that tab - if the case-load call is still awaiting one of
// its several fetches when the tab-click call starts, both would otherwise
// interleave and each append their own copy of every group into the same
// container. Each call captures its own token and checks it's still the
// most recent one after every await; a call that's been superseded bails
// out instead of mutating the DOM with stale/duplicate content.
let reportFilesGalleryRenderToken = 0;

async function renderReportFilesGallery() {
    const myToken = ++reportFilesGalleryRenderToken;
    const exhibitsEl = document.getElementById("reportExhibitsList");
    const discoveredEl = document.getElementById("reportDiscoveredGroups");
    const artifactsEl = document.getElementById("reportArtifactGroups");
    const webWrapEl = document.getElementById("reportWebArtifactsWrap");
    const webGroupsEl = document.getElementById("reportWebArtifactGroups");
    if (!exhibitsEl) return;
    exhibitsEl.innerHTML = '<div class="text-subtle small p-2">Loading...</div>';
    discoveredEl.innerHTML = '';
    artifactsEl.innerHTML = '';
    webWrapEl.style.display = 'none';
    webGroupsEl.innerHTML = '';
    // Reference URLs need no fetch - already loaded into currentReferenceUrlsList
    // by loadCaseForEditing() - so this renders immediately rather than
    // waiting on the async chain below.
    renderReportUrlsGroup();

    const caseFolder = activeCase ? activeCase.case_folder : "";
    let discovered = [];
    let truncated = false;
    if (caseFolder) {
        try {
            const res = await fetch(`/api/cases/discover_files?case_folder=${encodeURIComponent(caseFolder)}`);
            const data = await res.json();
            if (data.success) {
                discovered = data.files || [];
                truncated = !!data.truncated;
            }
        } catch (err) {}
    }
    if (myToken !== reportFilesGalleryRenderToken) return;

    const attachedSet = new Set(currentAttachedFilesList);
    const extraFiles = discovered.filter(f => !attachedSet.has(f.path));
    // case_role (classify_case_role() in core/paths.py, passed through by
    // /api/cases/discover_files) splits this app's own generated files
    // (reports, logs, KML exports, backups) away from real evidence found
    // in the case folder - two genuinely different groups, not one pile.
    const caseArtifactFiles = extraFiles.filter(f => f.case_role);
    const discoveredEvidenceFiles = extraFiles.filter(f => !f.case_role);

    // Batch-fetch tags and recent analysis history for every path currently
    // in view (both attached and discovered-but-unattached) - lets an
    // examiner see tag/analysis status before deciding to attach, not just
    // after. Best-effort: an empty case index (no tags/analysis run yet, or
    // no case at all) just means every row's tag/analysis area stays empty.
    const allPaths = [...currentAttachedFilesList, ...extraFiles.map(f => f.path)];
    let tagsByPath = {}, analysisByPath = {};
    if (caseFolder && allPaths.length) {
        try {
            const [tagsRes, analysisRes] = await Promise.all([
                fetch('/api/case_index/tags_for_paths', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ case_folder: caseFolder, paths: allPaths })
                }),
                fetch('/api/case_index/analysis_for_paths', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ case_folder: caseFolder, paths: allPaths })
                }),
            ]);
            const tagsData = await tagsRes.json();
            const analysisData = await analysisRes.json();
            if (tagsData.success) tagsByPath = tagsData.tags || {};
            if (analysisData.success) analysisByPath = analysisData.results || {};
        } catch (err) {}
    }
    if (myToken !== reportFilesGalleryRenderToken) return;

    // Builds one file row into `target` (a group's body div, or the
    // always-visible Exhibits list) - unchanged row contents from before
    // this reorganization, just no longer tied to one single flat container.
    const addRow = (target, name, sublabel, filePath, checked, exhibitNumber) => {
        const row = document.createElement('div');
        row.className = 'd-flex align-items-start gap-2 bg-dark p-2 rounded mb-1 border border-secondary';

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'form-check-input mt-1 flex-shrink-0';
        cb.checked = checked;
        cb.addEventListener('change', () => toggleAttachmentFile(filePath, cb.checked));
        row.appendChild(cb);

        if (isPhotoImagePath(filePath)) {
            const thumb = document.createElement('img');
            thumb.src = `/api/files/raw?path=${encodeURIComponent(filePath)}`;
            thumb.className = 'rounded border border-secondary flex-shrink-0';
            thumb.style.cssText = 'width:36px;height:36px;object-fit:cover;';
            thumb.alt = '';
            row.appendChild(thumb);
        }

        const textWrap = document.createElement('div');
        textWrap.className = 'flex-grow-1';

        const line1 = document.createElement('div');
        line1.className = 'small text-break d-flex align-items-center flex-wrap gap-1';
        if (exhibitNumber) {
            const exBadge = document.createElement('span');
            exBadge.className = 'badge bg-info text-dark';
            exBadge.textContent = `Exhibit ${exhibitNumber}`;
            line1.appendChild(exBadge);
        }
        const baseNameForExt = filePath.split('/').pop();
        const dotIdx = baseNameForExt.lastIndexOf('.');
        const ext = dotIdx > 0 ? baseNameForExt.slice(dotIdx + 1).toUpperCase() : '';
        if (ext) {
            const extBadge = document.createElement('span');
            extBadge.className = 'badge bg-secondary';
            extBadge.textContent = ext;
            line1.appendChild(extBadge);
        }
        const nameSpan = document.createElement('span');
        nameSpan.textContent = name; // untrusted (filename) - text node only
        line1.appendChild(nameSpan);
        textWrap.appendChild(line1);

        if (sublabel) {
            const line2 = document.createElement('div');
            line2.className = 'text-subtle small text-break';
            line2.textContent = sublabel;
            textWrap.appendChild(line2);
        }

        const fileTags = tagsByPath[filePath] || [];
        if (fileTags.length) {
            const tagLine = document.createElement('div');
            tagLine.className = 'small mt-1 d-flex flex-wrap gap-1';
            fileTags.forEach(t => {
                const pill = document.createElement('span');
                pill.className = `badge bg-${t.color || 'secondary'}`;
                pill.textContent = (t.notable ? '★ ' : '') + t.name; // untrusted (tag name) - text node only
                if (t.comment) pill.title = t.comment; // untrusted (comment) - tooltip attribute, not markup
                tagLine.appendChild(pill);
            });
            textWrap.appendChild(tagLine);
        }

        const fileAnalysis = analysisByPath[filePath] || [];
        if (fileAnalysis.length) {
            const analysisLine = document.createElement('div');
            analysisLine.className = 'text-subtle small mt-1';
            analysisLine.textContent = 'Recently analyzed: ' + fileAnalysis
                .map(r => `${r.tool} (${r.summary}, ${r.run_at})`).join('; '); // untrusted (tool/summary text) - text node only
            textWrap.appendChild(analysisLine);
        }

        if (checked) {
            const capInput = document.createElement('input');
            capInput.type = 'text';
            capInput.className = 'form-control form-control-sm mt-1';
            capInput.placeholder = 'Optional caption for the exported report...';
            capInput.value = currentAttachmentCaptions[filePath] || '';
            capInput.addEventListener('input', () => { currentAttachmentCaptions[filePath] = capInput.value; });
            textWrap.appendChild(capInput);
        }
        row.appendChild(textWrap);

        if (filePath.toLowerCase().endsWith('.kml')) {
            const viewBtn = document.createElement('button');
            viewBtn.type = 'button';
            viewBtn.className = 'btn btn-xs btn-outline-info py-0 px-2 flex-shrink-0 align-self-center';
            viewBtn.innerHTML = '<i class="bi bi-geo-alt me-1"></i>Map';
            viewBtn.title = 'View the GPS placemarks in this KML file on a map';
            viewBtn.onclick = () => openKmlViewerModal(filePath);
            row.appendChild(viewBtn);
        }

        target.appendChild(row);
    };

    // --- Exhibits (always visible - the curated, report-facing set) ---
    // Exhibit numbers are each file's 1-based position in currentAttachedFilesList
    // (the same order-preserved list attachments.files gets saved as) -
    // matches export_report()'s own exhibit_numbers derivation exactly, so
    // what's shown here is always what a real export would print.
    exhibitsEl.innerHTML = '';
    if (currentAttachedFilesList.length === 0) {
        exhibitsEl.innerHTML = '<span class="text-subtle small">No exhibits attached yet. Check a file below, or right-click one in File Explorer and choose "Attach to Case".</span>';
    } else {
        currentAttachedFilesList.forEach((fp, i) => addRow(exhibitsEl, fp.split('/').pop(), fp, fp, true, i + 1));
    }

    // --- Found in Case Folder, grouped by extension category ---
    const byExtCategory = {};
    discoveredEvidenceFiles.forEach(f => {
        const cat = f.category || 'other';
        (byExtCategory[cat] = byExtCategory[cat] || []).push(f);
    });
    Object.keys(FILE_VIEWS_EXTENSION_LABELS).forEach(cat => {
        const files = byExtCategory[cat];
        if (!files || !files.length) return;
        const body = buildReportFileGroup(discoveredEl, FILE_VIEWS_EXTENSION_LABELS[cat], files.length, REPORT_EXTENSION_CATEGORY_ICONS[cat]);
        files.forEach(f => {
            const sizeKb = f.size_bytes ? `${(f.size_bytes / 1024).toFixed(1)} KB · ` : '';
            addRow(body, f.name, `${sizeKb}${f.path}`, f.path, false, null);
        });
    });
    if (truncated) {
        const note = document.createElement('div');
        note.className = 'text-subtle small p-2';
        note.textContent = 'Showing the first 200 discovered files - some case-folder files were not listed.';
        discoveredEl.appendChild(note);
    }
    discoveredEl.classList.toggle('report-file-groups-empty', discoveredEl.children.length === 0);

    // --- Case-Generated Artifacts, grouped by case_role ---
    const byRole = {};
    caseArtifactFiles.forEach(f => { (byRole[f.case_role] = byRole[f.case_role] || []).push(f); });
    Object.keys(REPORT_CASE_ROLE_LABELS).forEach(role => {
        const files = byRole[role];
        if (!files || !files.length) return;
        const body = buildReportFileGroup(artifactsEl, REPORT_CASE_ROLE_LABELS[role], files.length, REPORT_CASE_ROLE_ICONS[role]);
        files.forEach(f => addRow(body, f.name, f.path, f.path, false, null));
    });
    artifactsEl.classList.toggle('report-file-groups-empty', artifactsEl.children.length === 0);

    // --- Web Artifacts (parsed browser history/bookmarks/downloads/cookies)
    // - only shown once something's actually been parsed for this case
    // (File Explorer > right-click > "Parse Browser Artifacts"); each
    // category's rows are fetched lazily on first expand, not all up front,
    // since a busy case's history table alone can run into the thousands. ---
    if (caseFolder) {
        try {
            const res = await fetch('/api/case_index/summary', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_folder: caseFolder })
            });
            const data = await res.json();
            if (myToken !== reportFilesGalleryRenderToken) return;
            const counts = (data.success && data.parsed_artifact_counts) || {};
            const types = Object.keys(counts).filter(t => counts[t] > 0);
            if (types.length) {
                webWrapEl.style.display = '';
                types.forEach(type => {
                    buildReportFileGroup(webGroupsEl, FILE_VIEWS_WEB_ARTIFACT_LABELS[type] || type, counts[type], 'bi bi-globe2', async (body) => {
                        const res2 = await fetch('/api/case_index/parsed_artifacts', {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ case_folder: caseFolder, category: type })
                        });
                        const data2 = await res2.json();
                        body.innerHTML = '';
                        body.appendChild(buildParsedArtifactsTable(data2.rows || []));
                    });
                });
            }
        } catch (err) {}
    }
}

// Only http(s) URLs are rendered as a real clickable link - an examiner
// could type anything into this field (including a javascript: URL), and
// unlike every other examiner-entered string in this app (case notes, tag
// comments, captions), this one is specifically turned into a clickable
// <a href> rather than staying inert text, so it gets its own scheme check
// rather than relying on textContent alone to make it safe.
function isSafeHttpUrl(str) {
    return /^https?:\/\//i.test(str || '');
}

// Kept separate from renderReportUrlRows() below so the group's own
// expand/collapse state (set by buildReportFileGroup's toggle) survives an
// add/remove - only built once per renderReportFilesGallery() call, not
// rebuilt on every edit.
let reportUrlsGroupBodyEl = null;
let reportUrlsGroupCountBadgeEl = null;

function renderReportUrlsGroup() {
    const container = document.getElementById('reportUrlGroups');
    if (!container) return;
    container.innerHTML = '';
    reportUrlsGroupBodyEl = buildReportFileGroup(container, 'Reference URLs / Links', currentReferenceUrlsList.length, 'bi bi-link-45deg');
    reportUrlsGroupCountBadgeEl = container.querySelector('.report-file-group-toggle .badge');
    renderReportUrlRows();
}

// Rebuilds just the Add-URL row + URL list inside the already-built group
// body, and updates its count badge - called after every add/remove
// instead of renderReportUrlsGroup() so the toggle itself (and whether the
// examiner currently has the group expanded) is never disturbed.
function renderReportUrlRows() {
    if (!reportUrlsGroupBodyEl) return;
    if (reportUrlsGroupCountBadgeEl) reportUrlsGroupCountBadgeEl.textContent = String(currentReferenceUrlsList.length);
    const body = reportUrlsGroupBodyEl;
    body.innerHTML = '';

    const addRow = document.createElement('div');
    addRow.className = 'd-flex gap-2 mb-2';
    const addInput = document.createElement('input');
    addInput.type = 'text';
    addInput.className = 'form-control form-control-sm font-monospace';
    addInput.placeholder = 'https://cve.mitre.org/... or a case-tracker link...';
    const doAdd = () => {
        const val = addInput.value.trim();
        if (!val) return;
        currentReferenceUrlsList.push(val);
        renderReportUrlRows();
    };
    addInput.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); doAdd(); } });
    addRow.appendChild(addInput);
    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'btn btn-sm btn-outline-secondary flex-shrink-0';
    addBtn.title = 'Add';
    addBtn.innerHTML = '<i class="bi bi-plus-lg"></i>';
    addBtn.onclick = doAdd;
    addRow.appendChild(addBtn);
    body.appendChild(addRow);

    if (currentReferenceUrlsList.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'text-subtle small';
        empty.textContent = 'No reference URLs added yet.';
        body.appendChild(empty);
        return;
    }

    currentReferenceUrlsList.forEach((url, idx) => {
        const row = document.createElement('div');
        row.className = 'd-flex align-items-center gap-2 bg-dark p-2 rounded mb-1 border border-secondary';

        const icon = document.createElement('i');
        icon.className = 'bi bi-link-45deg text-subtle flex-shrink-0';
        row.appendChild(icon);

        let linkEl;
        if (isSafeHttpUrl(url)) {
            linkEl = document.createElement('a');
            linkEl.href = url;
            linkEl.target = '_blank';
            linkEl.rel = 'noopener noreferrer';
        } else {
            linkEl = document.createElement('span');
        }
        linkEl.className = 'small text-break flex-grow-1';
        linkEl.textContent = url; // examiner-entered - text node only
        row.appendChild(linkEl);

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-2 flex-shrink-0';
        delBtn.title = 'Remove';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.onclick = () => {
            currentReferenceUrlsList.splice(idx, 1);
            renderReportUrlRows();
        };
        row.appendChild(delBtn);

        body.appendChild(row);
    });
}

async function renderReportGeolocationList() {
    const container = document.getElementById("reportGeoContainer");
    if (!container) return;
    container.innerHTML = '<span class="text-subtle small italic">Loading...</span>';

    const caseFolder = activeCase ? activeCase.case_folder : "";
    let discovered = [];
    if (caseFolder) {
        try {
            const res = await fetch(`/api/cases/discover_files?case_folder=${encodeURIComponent(caseFolder)}`);
            const data = await res.json();
            if (data.success) discovered = data.files || [];
        } catch (err) {}
    }

    const kmlPaths = new Set();
    currentAttachedFilesList.forEach(fp => { if (fp.toLowerCase().endsWith('.kml')) kmlPaths.add(fp); });
    discovered.forEach(f => { if (f.path.toLowerCase().endsWith('.kml')) kmlPaths.add(f.path); });

    container.innerHTML = '';
    if (kmlPaths.size === 0) {
        container.innerHTML = '<span class="text-subtle small">No geolocation (KML) files found for this case yet.</span>';
        return;
    }

    for (const filePath of kmlPaths) {
        const block = document.createElement('div');
        block.className = 'mb-3 border border-secondary rounded p-2 bg-black';

        const heading = document.createElement('div');
        heading.className = 'small text-break fw-bold';
        heading.textContent = filePath.split('/').pop(); // untrusted (filename) - text node only
        block.appendChild(heading);

        const pathLine = document.createElement('div');
        pathLine.className = 'text-subtle small mb-2 text-break';
        pathLine.textContent = filePath; // untrusted (path) - text node only
        block.appendChild(pathLine);

        const mapHolder = document.createElement('div');
        mapHolder.textContent = 'Loading map...';
        mapHolder.className = 'text-subtle small';
        block.appendChild(mapHolder);

        container.appendChild(block);

        try {
            const res = await fetch('/api/files/preview_text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: filePath })
            });
            const data = await res.json();
            if (data.success) {
                renderKmlViewer(mapHolder, data.content, 'clamp(360px, 60vh, 700px)');
            } else {
                mapHolder.textContent = data.error || 'Failed to load this KML file.';
                mapHolder.className = 'text-danger small';
            }
        } catch (err) {
            mapHolder.textContent = 'Request failed.';
            mapHolder.className = 'text-danger small';
        }
    }
}

function toggleAttachmentFile(filePath, checked) {
    if (checked) {
        if (!currentAttachedFilesList.includes(filePath)) currentAttachedFilesList.push(filePath);
    } else {
        currentAttachedFilesList = currentAttachedFilesList.filter(p => p !== filePath);
        delete currentAttachmentCaptions[filePath];
    }
    renderReportFilesGallery();
}

function addFileAttachment(filePath) {
    if (filePath && !currentAttachedFilesList.includes(filePath)) {
        currentAttachedFilesList.push(filePath);
        renderReportFilesGallery();
    }
}

// --- Report Modifier Functions ---
function openFilePickerModal(mode) {
    modalPickerMode = mode;
    openFolderModal(modalPickerMode);
}

// Station-wide custom case-field *definitions* (Settings > Case &
// Reporting) - cached at page load so Reporting's Case Information block
// can render input rows without a fetch every time a case is loaded.
// Refetched whenever Settings saves new definitions, so the current
// session's cache never goes stale after an edit.
let customFieldDefsCache = [];

async function fetchCustomFieldDefs() {
    try {
        const res = await fetch('/api/settings/case_reporting');
        const data = await res.json();
        if (data.success) customFieldDefsCache = data.custom_case_fields || [];
    } catch (err) { /* non-fatal - Case Information just shows no custom fields */ }
}

// --- Report Template Builder (custom templates built from the same
// sections Standard uses - see REPORT_SECTION_BLOCKS in app.py) ---
// Station-wide, cached the same way customFieldDefsCache is - both
// selectors that offer a template choice (Settings' station default,
// Reporting's Export pane) read from this cache rather than fetching
// independently, so they always agree on what templates currently exist.
let customReportTemplatesCache = [];
// Mirrors routes/reporting.py's NARRATIVE_BLOCK_FIELD_MAP exactly - a
// remappable block's own default source field, used only to pre-fill a new
// row's dropdown (or an old, pre-remapping-feature template's row) before
// the examiner ever touches it. The backend re-validates/defaults this
// itself regardless, so a stale copy here can't corrupt storage - at worst
// a dropdown would show the wrong default until this constant is updated
// to match a future backend change.
const NARRATIVE_BLOCK_FIELD_MAP = {
    executive_summary: "executive_summary", objectives: "objectives",
    relevant_findings: "findings_summary", limitations: "limitations",
    conclusion: "conclusion", iocs: "iocs", recommendations: "recommendations_next_steps",
};
function defaultSourceFieldFor(key) { return NARRATIVE_BLOCK_FIELD_MAP[key] || null; }

let reportSectionBlocksCache = []; // [{key, default_title, remappable}, ...] - server truth for the builder's palette
let reportFieldOptionsCache = []; // [{value, label}, ...] - the narrative fields a remappable row's dropdown can choose among
let reportTemplateBuilderEditing = null; // array of {key, title, enabled, source_field?} while the modal is open, else null
let reportTemplateBuilderEditingId = null; // null = creating new, else the id being edited
let currentExportCustomTemplateId = null; // read by #exportEditTemplateBtn's onclick in index.html

async function fetchCustomReportTemplates() {
    try {
        const res = await fetch('/api/report_templates/custom');
        const data = await res.json();
        if (data.success) {
            customReportTemplatesCache = data.templates || [];
            reportSectionBlocksCache = data.blocks || [];
            reportFieldOptionsCache = data.field_options || [];
        }
    } catch (err) { /* non-fatal - both selects just show the 3 built-in templates */ }
    populateTemplateSelectOptions(document.getElementById("defReportTemplate"));
    populateTemplateSelectOptions(document.getElementById("exportTemplateSelect"));
    renderCustomReportTemplatesList();
}

// Appends one <option value="custom:ID"> per saved template after the 3
// built-in ones, preserving the select's current value if it's still
// valid - shared by both the Settings default select and the Export pane
// select so neither hardcodes the custom-template list itself.
function populateTemplateSelectOptions(selectEl) {
    if (!selectEl) return;
    const previousValue = selectEl.value;
    // Custom templates render inside their own <optgroup>, not just appended
    // as flat <option>s after the 4 built-ins - a station that's built up
    // several custom templates could otherwise no longer tell at a glance
    // which entries are the fixed built-ins vs. its own. Rebuilt fresh each
    // call (removed then recreated) since the underlying cache can change
    // (a template created/renamed/deleted).
    selectEl.querySelectorAll('option[value^="custom:"], optgroup[data-custom-templates]').forEach(el => el.remove());
    if (customReportTemplatesCache.length > 0) {
        const group = document.createElement('optgroup');
        group.label = 'Custom Templates';
        group.dataset.customTemplates = '1';
        customReportTemplatesCache.forEach(t => {
            const opt = document.createElement('option');
            opt.value = `custom:${t.id}`;
            opt.textContent = t.name; // set via textContent, not innerHTML - template names are examiner-entered
            group.appendChild(opt);
        });
        selectEl.appendChild(group);
    }
    if ([...selectEl.options].some(o => o.value === previousValue)) {
        selectEl.value = previousValue;
    }
}

function renderCustomReportTemplatesList() {
    const container = document.getElementById("customReportTemplatesList");
    if (!container) return;
    container.innerHTML = '';
    if (customReportTemplatesCache.length === 0) {
        const msg = document.createElement('span');
        msg.className = 'text-subtle small italic';
        msg.textContent = 'No custom templates yet.';
        container.appendChild(msg);
        return;
    }
    customReportTemplatesCache.forEach(t => {
        const row = document.createElement('div');
        row.className = 'd-flex justify-content-between align-items-center mb-1';
        const name = document.createElement('span');
        name.className = 'small';
        name.textContent = t.name; // examiner-entered - text node only
        const btns = document.createElement('div');
        btns.className = 'd-flex gap-1';
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-xs btn-outline-info py-0 px-2';
        editBtn.innerHTML = '<i class="bi bi-pencil-square"></i>';
        editBtn.title = 'Edit';
        editBtn.onclick = () => openReportTemplateBuilder(t.id);
        const dupBtn = document.createElement('button');
        // btn-outline-secondary's default gray read as barely visible
        // against this app's near-black theme at btn-xs size (caught live,
        // not assumed) - btn-outline-light gives real contrast while
        // staying visually distinct from Edit's cyan and Delete's red.
        dupBtn.className = 'btn btn-xs btn-outline-light py-0 px-2';
        dupBtn.innerHTML = '<i class="bi bi-copy"></i>';
        dupBtn.title = 'Duplicate';
        dupBtn.onclick = () => duplicateCustomReportTemplate(t.id);
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-2';
        delBtn.innerHTML = '<i class="bi bi-trash3"></i>';
        delBtn.title = 'Delete';
        delBtn.onclick = () => deleteCustomReportTemplate(t.id);
        btns.appendChild(editBtn);
        btns.appendChild(dupBtn);
        btns.appendChild(delBtn);
        row.appendChild(name);
        row.appendChild(btns);
        container.appendChild(row);
    });
}

function openReportTemplateBuilder(existingId = null) {
    reportTemplateBuilderEditingId = existingId;
    const nameEl = document.getElementById("rtbName");
    const statusEl = document.getElementById("rtbStatus");
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small mt-2'; }
    resetReportTemplateBuilderPreview(); // a stale preview from a previously-edited template must never linger into this one

    if (existingId) {
        const record = customReportTemplatesCache.find(t => t.id === existingId);
        if (!record) return;
        if (nameEl) nameEl.value = record.name;
        reportTemplateBuilderEditing = record.sections.map(s => ({ ...s }));
        // A template saved before a new block existed in the registry (e.g. Timeline,
        // added 2026-08-16) has no row for it - append any missing blocks, unchecked,
        // so the examiner can opt in rather than never seeing the new block at all.
        const knownKeys = new Set(reportTemplateBuilderEditing.map(s => s.key));
        reportSectionBlocksCache.forEach(b => {
            if (!knownKeys.has(b.key)) {
                reportTemplateBuilderEditing.push({ key: b.key, title: '', enabled: false, source_field: b.remappable ? defaultSourceFieldFor(b.key) : undefined });
            }
        });
    } else {
        if (nameEl) nameEl.value = '';
        reportTemplateBuilderEditing = reportSectionBlocksCache.map(b => ({ key: b.key, title: '', enabled: true, source_field: b.remappable ? defaultSourceFieldFor(b.key) : undefined }));
    }
    renderReportTemplateBuilderRows();

    const modalEl = document.getElementById('reportTemplateBuilderModal');
    (bootstrap.Modal.getOrCreateInstance(modalEl)).show();
}

function renderReportTemplateBuilderRows() {
    const container = document.getElementById("rtbRowsContainer");
    if (!container || !reportTemplateBuilderEditing) return;
    container.innerHTML = '';
    const blockByKey = Object.fromEntries(reportSectionBlocksCache.map(b => [b.key, b]));

    reportTemplateBuilderEditing.forEach((row, idx) => {
        const block = blockByKey[row.key];
        const wrap = document.createElement('div');
        wrap.className = 'd-flex align-items-center gap-2 mb-1 pb-1 border-bottom border-secondary';

        const moveWrap = document.createElement('div');
        moveWrap.className = 'd-flex flex-column';
        const upBtn = document.createElement('button');
        upBtn.type = 'button';
        upBtn.className = 'btn btn-xs btn-outline-secondary py-0 px-1';
        upBtn.innerHTML = '<i class="bi bi-caret-up-fill"></i>';
        upBtn.disabled = idx === 0;
        upBtn.onclick = () => moveTemplateBuilderRow(idx, -1);
        const downBtn = document.createElement('button');
        downBtn.type = 'button';
        downBtn.className = 'btn btn-xs btn-outline-secondary py-0 px-1';
        downBtn.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
        downBtn.disabled = idx === reportTemplateBuilderEditing.length - 1;
        downBtn.onclick = () => moveTemplateBuilderRow(idx, 1);
        moveWrap.appendChild(upBtn);
        moveWrap.appendChild(downBtn);

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'form-check-input flex-shrink-0';
        checkbox.checked = row.enabled !== false;
        checkbox.onchange = () => { reportTemplateBuilderEditing[idx].enabled = checkbox.checked; };

        const titleInput = document.createElement('input');
        titleInput.type = 'text';
        titleInput.className = 'form-control form-control-sm';
        titleInput.placeholder = block ? block.default_title : row.key;
        titleInput.value = row.title || '';
        titleInput.maxLength = 120;
        titleInput.style.flex = '1 1 auto';
        titleInput.oninput = () => { reportTemplateBuilderEditing[idx].title = titleInput.value; };

        wrap.appendChild(moveWrap);
        wrap.appendChild(checkbox);
        wrap.appendChild(titleInput);

        // Only the 7 free-text blocks are remappable (see REPORT_SECTION_
        // BLOCKS' own remappable flag, mirrored here via block.remappable) -
        // every other block's content is structured data a dropdown can't
        // meaningfully rewire, so it gets no source-field control at all.
        if (block && block.remappable) {
            const fieldSelect = document.createElement('select');
            fieldSelect.className = 'form-select form-select-sm';
            fieldSelect.style.flex = '0 0 auto';
            fieldSelect.style.width = '200px';
            fieldSelect.title = 'Which narrative field fills this section';
            reportFieldOptionsCache.forEach(opt => {
                const optEl = document.createElement('option');
                optEl.value = opt.value;
                optEl.textContent = opt.label;
                fieldSelect.appendChild(optEl);
            });
            fieldSelect.value = row.source_field || defaultSourceFieldFor(row.key);
            fieldSelect.onchange = () => { reportTemplateBuilderEditing[idx].source_field = fieldSelect.value; };
            wrap.appendChild(fieldSelect);
        } else {
            // Empty same-width spacer so non-remappable rows' title inputs
            // still line up with remappable ones' shorter title inputs.
            const spacer = document.createElement('div');
            spacer.style.width = '200px';
            spacer.style.flex = '0 0 auto';
            wrap.appendChild(spacer);
        }

        container.appendChild(wrap);
    });
}

function moveTemplateBuilderRow(idx, direction) {
    const target = idx + direction;
    if (target < 0 || target >= reportTemplateBuilderEditing.length) return;
    const [row] = reportTemplateBuilderEditing.splice(idx, 1);
    reportTemplateBuilderEditing.splice(target, 0, row);
    renderReportTemplateBuilderRows();
}

// Object URL for the builder's own PDF preview, if any - same leak-
// prevention pattern as exportPreviewObjectUrl (each refresh revokes the
// previous one before creating a new one).
let rtbPreviewObjectUrl = null;

function resetReportTemplateBuilderPreview() {
    const iframe = document.getElementById("rtbPreviewFrame");
    const statusEl = document.getElementById("rtbPreviewStatus");
    if (rtbPreviewObjectUrl) { URL.revokeObjectURL(rtbPreviewObjectUrl); rtbPreviewObjectUrl = null; }
    if (iframe) { iframe.removeAttribute('src'); iframe.style.display = 'none'; }
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small text-subtle'; }
}

// Renders exactly what this in-progress template would produce, without
// saving it first - reuses /api/export_report's existing preview:true
// contract (build the document, return it inline, skip the disk write),
// extended with an ad-hoc custom_sections override specifically for this
// not-yet-saved editor state (see export_report()'s own comment on why
// that's preview-only, never available to a real export). Always previews
// against the currently active case (matching how the builder is most
// often reached, from Settings) - if none is active, currentReportPath is
// unset and this says so rather than attempting a request that can't
// succeed.
async function refreshReportTemplateBuilderPreview() {
    const iframe = document.getElementById("rtbPreviewFrame");
    const statusEl = document.getElementById("rtbPreviewStatus");
    if (!iframe || !reportTemplateBuilderEditing) return;

    if (!currentReportPath) {
        if (statusEl) { statusEl.textContent = 'Select an active case first (top bar) to preview against real data.'; statusEl.className = 'small text-warning'; }
        return;
    }

    if (statusEl) { statusEl.textContent = 'Rendering preview...'; statusEl.className = 'small text-info'; }

    const customSections = reportTemplateBuilderEditing.map(r => ({
        key: r.key, title: r.title || '', enabled: r.enabled !== false,
        source_field: r.source_field || defaultSourceFieldFor(r.key),
    }));

    try {
        const res = await fetch('/api/export_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: currentReportPath, format: 'pdf', preview: true, custom_sections: customSections })
        });
        if (!res.ok) {
            const data = await res.json();
            if (statusEl) { statusEl.textContent = `Preview failed: ${data.error}`; statusEl.className = 'small text-danger'; }
            return;
        }
        if (rtbPreviewObjectUrl) { URL.revokeObjectURL(rtbPreviewObjectUrl); rtbPreviewObjectUrl = null; }
        const blob = await res.blob();
        rtbPreviewObjectUrl = URL.createObjectURL(blob);
        // No sandbox for PDF - Chrome's native PDF viewer refuses to render
        // inside a sandboxed iframe regardless of which tokens are set,
        // matching the exact same constraint the Export pane's own PDF
        // preview already documented and worked around.
        iframe.removeAttribute('sandbox');
        iframe.src = rtbPreviewObjectUrl;
        iframe.style.display = '';
        if (statusEl) { statusEl.textContent = 'Preview rendered.'; statusEl.className = 'small text-success'; }
    } catch (err) {
        if (statusEl) { statusEl.textContent = 'Preview request failed.'; statusEl.className = 'small text-danger'; }
    }
}

async function saveReportTemplateBuilder() {
    const statusEl = document.getElementById("rtbStatus");
    const name = document.getElementById("rtbName")?.value.trim();
    if (!name) {
        if (statusEl) { statusEl.textContent = 'Template name is required.'; statusEl.className = 'small mt-2 text-danger'; }
        return;
    }

    const payload = {
        name,
        sections: reportTemplateBuilderEditing.map(r => ({
            key: r.key, title: r.title || '', enabled: r.enabled !== false,
            source_field: r.source_field || defaultSourceFieldFor(r.key),
        })),
        job_fields: { telemetry: true, params: true, hashes: true },
    };
    const isEdit = !!reportTemplateBuilderEditingId;
    const url = isEdit ? `/api/report_templates/custom/${reportTemplateBuilderEditingId}` : '/api/report_templates/custom';

    try {
        const res = await fetch(url, {
            method: isEdit ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.success) {
            await fetchCustomReportTemplates();
            const modalEl = document.getElementById('reportTemplateBuilderModal');
            bootstrap.Modal.getInstance(modalEl)?.hide();
        } else if (statusEl) {
            statusEl.textContent = data.error || 'Save failed.';
            statusEl.className = 'small mt-2 text-danger';
        }
    } catch (err) {
        if (statusEl) { statusEl.textContent = 'Request failed.'; statusEl.className = 'small mt-2 text-danger'; }
    }
}

// Creates a genuine, independent saved copy immediately (reusing the
// existing create endpoint's own soft-dedupe-by-name handling for a
// colliding "Copy of X" name - no new backend route needed), then jumps
// straight into the builder on that new copy so the examiner can rename/
// tweak it right away. Duplicating first (not just pre-filling an unsaved
// draft) means the copy genuinely exists even if the examiner closes the
// modal without changing anything further - correct duplicate semantics.
async function duplicateCustomReportTemplate(id) {
    const record = customReportTemplatesCache.find(t => t.id === id);
    if (!record) return;
    try {
        const res = await fetch('/api/report_templates/custom', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: `Copy of ${record.name}`,
                sections: record.sections.map(s => ({ ...s })),
                job_fields: record.job_fields || { telemetry: true, params: true, hashes: true },
            }),
        });
        const data = await res.json();
        if (!data.success) { showToast(data.error || 'Duplicate failed.', 'danger'); return; }
        await fetchCustomReportTemplates();
        openReportTemplateBuilder(data.template.id);
    } catch (err) {
        showToast('Request failed.', 'danger');
    }
}

async function deleteCustomReportTemplate(id) {
    const record = customReportTemplatesCache.find(t => t.id === id);
    if (!record) return;
    if (!confirm(`Delete the custom report template "${record.name}"? Any station default or per-export selection pointing at it will fall back to Standard.`)) return;
    try {
        const res = await fetch(`/api/report_templates/custom/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            await fetchCustomReportTemplates();
        } else {
            showToast(data.error || 'Delete failed.', 'danger');
        }
    } catch (err) {
        showToast('Request failed.', 'danger');
    }
}

// Renders one label+input pair per configured custom-field definition,
// pre-filled from this specific case's stored values (a case's values dict
// only ever has keys for fields that existed when it was created/last
// saved - a field added to the station AFTER this case existed simply
// starts blank here, exactly like any other new field would).
function renderCustomFieldsForCase(values) {
    const container = document.getElementById("customFieldsContainer");
    if (!container) return;
    container.innerHTML = '';
    values = values || {};
    customFieldDefsCache.forEach(def => {
        const col = document.createElement('div');
        col.className = 'col-md-6';
        const label = document.createElement('label');
        label.className = 'telemetry-grid-label d-block mb-1';
        label.textContent = def.label;
        const group = document.createElement('div');
        group.className = 'input-group input-group-sm';
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control custom-field-input';
        input.dataset.fieldKey = def.key;
        input.value = values[def.key] || '';
        // Optional convenience filler - set this field's value from one of
        // the case's own attached exhibits or tagged items instead of
        // always typing it by hand (e.g. "Evidence Source" -> pick the
        // actual drive image already attached to the case).
        const pickBtn = document.createElement('button');
        pickBtn.type = 'button';
        pickBtn.className = 'btn btn-outline-secondary';
        pickBtn.title = 'Set from a case item (attached exhibit or tagged file)';
        pickBtn.innerHTML = '<i class="bi bi-link-45deg"></i>';
        pickBtn.onclick = () => openCustomFieldItemPicker(def.label, input);
        group.appendChild(input);
        group.appendChild(pickBtn);
        col.appendChild(label);
        col.appendChild(group);
        container.appendChild(col);
    });
}

// --- Custom Case Field item picker (set a field's value from an attached
// exhibit or a tagged item, instead of typing it) ---
let customFieldItemPickerModalInstance = null;
let cfPickerItems = [];
let cfPickerTargetInput = null;

async function openCustomFieldItemPicker(fieldLabel, inputEl) {
    cfPickerTargetInput = inputEl;
    const labelEl = document.getElementById("cfPickerFieldLabel");
    if (labelEl) labelEl.textContent = fieldLabel;
    const searchEl = document.getElementById("cfPickerSearch");
    if (searchEl) searchEl.value = '';
    const listEl = document.getElementById("cfPickerList");
    if (listEl) listEl.innerHTML = '<span class="text-subtle small p-2 d-block">Loading...</span>';

    if (!customFieldItemPickerModalInstance) {
        customFieldItemPickerModalInstance = new bootstrap.Modal(document.getElementById('customFieldItemPickerModal'));
    }
    customFieldItemPickerModalInstance.show();

    // Attached exhibits - already loaded client-side (currentLoadedReportData),
    // same 1-based exhibit numbering the Files/Exhibits gallery and report
    // export both already use - no extra fetch needed for this half.
    const exhibitFiles = currentLoadedReportData?.attachments?.files || [];
    const items = exhibitFiles.map((path, idx) => {
        const name = path.split('/').pop();
        return { label: `Exhibit ${idx + 1}: ${name}`, value: `Exhibit ${idx + 1}: ${name}` };
    });

    // Tagged items - a real fetch, since these live in the case's own
    // SQLite index, not anything already loaded on this page.
    if (activeCase) {
        try {
            const res = await fetch('/api/case_index/all_tagged_items', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_folder: activeCase.case_folder })
            });
            const data = await res.json();
            if (data.success) {
                (data.rows || []).forEach(row => {
                    items.push({ label: `[${row.tag_name}] ${row.name}`, value: `${row.name} (tagged: ${row.tag_name})` });
                });
            }
        } catch (err) { /* non-fatal - exhibit list above still shows */ }
    }

    cfPickerItems = items;
    renderCustomFieldItemPickerList();
}

function renderCustomFieldItemPickerList() {
    const listEl = document.getElementById("cfPickerList");
    if (!listEl) return;
    const query = (document.getElementById("cfPickerSearch")?.value || '').toLowerCase();
    const filtered = cfPickerItems.filter(item => item.label.toLowerCase().includes(query));
    listEl.innerHTML = '';
    if (filtered.length === 0) {
        listEl.innerHTML = '<span class="text-subtle small p-2 d-block">No matching case items found - attach a file (Reporting > Files &amp; Artifacts) or tag one (right-click in File Explorer) first.</span>';
        return;
    }
    filtered.forEach(item => {
        const row = document.createElement('div');
        row.className = 'p-2 small';
        row.style.cursor = 'pointer';
        row.style.borderBottom = '1px solid rgba(255,255,255,0.08)';
        row.onmouseenter = () => { row.style.backgroundColor = '#1e2638'; };
        row.onmouseleave = () => { row.style.backgroundColor = ''; };
        row.appendChild(document.createTextNode(item.label)); // untrusted evidence/tag/exhibit name, text-only
        row.onclick = () => {
            if (cfPickerTargetInput) cfPickerTargetInput.value = item.value;
            customFieldItemPickerModalInstance?.hide();
        };
        listEl.appendChild(row);
    });
}

function gatherCustomFieldValues() {
    const values = {};
    document.querySelectorAll('#customFieldsContainer .custom-field-input').forEach(input => {
        values[input.dataset.fieldKey] = input.value;
    });
    return values;
}

// --- Case & Reporting (Settings) ---
// caseReportingFieldsEditing is a separate working copy from the shared
// customFieldDefsCache Reporting reads - editing/adding a row here (before
// Save) must never leak an incomplete/empty-key entry into Reporting's
// Case Information rendering if a case happens to get loaded mid-edit.
let caseReportingFieldsEditing = [];

async function loadCaseReportingSettings() {
    // Custom template options must exist in the <select> BEFORE setting its
    // value below - otherwise assigning a 'custom:<id>' value the browser
    // doesn't recognize yet silently no-ops, leaving the select stuck on
    // whatever its first option is.
    await fetchCustomReportTemplates();

    try {
        const res = await fetch('/api/settings/case_reporting');
        const data = await res.json();
        if (!data.success) return;

        const sections = data.report_defaults?.sections || {};
        const jobFields = data.report_defaults?.job_fields || {};
        const branding = data.report_defaults?.branding || {};

        const templateSel = document.getElementById("defReportTemplate");
        if (templateSel) templateSel.value = data.report_defaults?.template || 'standard';
        onDefReportTemplateChange();

        const setChecked = (id, obj, key) => {
            const el = document.getElementById(id);
            if (el) el.checked = Object.prototype.hasOwnProperty.call(obj, key) ? !!obj[key] : true;
        };
        setChecked('defSecCaseInfo', sections, 'case_info');
        setChecked('defSecExecSummary', sections, 'executive_summary');
        setChecked('defSecEvidenceInventory', sections, 'evidence_inventory');
        setChecked('defSecForensicAnalysis', sections, 'forensic_analysis');
        setChecked('defSecFindings', sections, 'relevant_findings');
        setChecked('defSecLimitations', sections, 'limitations');
        setChecked('defSecConclusion', sections, 'conclusion');
        setChecked('defSecAttachments', sections, 'attachments');
        // Unlike every other section key here (all pre-existing, where a
        // missing key means "saved before this field existed" and should
        // default true), Geolocation is brand new - every station's
        // already-saved config is missing this key, and the intended
        // default is unchecked (a case with no GPS evidence shouldn't grow
        // an empty section) - so this one defaults to false, not
        // setChecked()'s usual true, when absent.
        const geoDefEl = document.getElementById('defSecGeolocation');
        if (geoDefEl) geoDefEl.checked = Object.prototype.hasOwnProperty.call(sections, 'geolocation') ? !!sections.geolocation : false;
        setChecked('defSecAuditTrail', sections, 'audit_trail');
        setChecked('defFieldTelemetry', jobFields, 'telemetry');
        setChecked('defFieldParams', jobFields, 'params');
        setChecked('defFieldHashes', jobFields, 'hashes');

        const brandingText = document.getElementById("reportBrandingText");
        if (brandingText) brandingText.value = branding.header_text || '';

        const logoStatus = document.getElementById("reportLogoStatus");
        if (logoStatus) logoStatus.textContent = branding.logo_path
            ? `Current logo: ${branding.logo_path.split('/').pop()}`
            : 'No logo set.';

        caseReportingFieldsEditing = (data.custom_case_fields || []).map(f => ({ ...f }));
        renderCustomFieldDefsEditor();
    } catch (err) { /* non-fatal - card just shows its default markup state */ }
}

// Per-fixed-template hint text for the Settings > Case & Reporting default
// selector - each template's section list/data sources differ enough that
// one generic string (the old behavior) was actively inaccurate for some of
// them (e.g. mentioning IOCs/Recommendations, which Police never uses).
const DEF_FIXED_TEMPLATE_HINTS = {
    dfir: "This template has a fixed structure - the section/field checkboxes below only apply to Standard exports. See the Report Narrative tab for the Indicators of Compromise / Recommendations fields it draws on.",
    police: "This template has a fixed structure - the section/field checkboxes below only apply to Standard exports. Its Administrative Information section pulls from Case Number/Examiner plus whatever you configure under Custom Case Fields below (e.g. Agency, Badge Number, Requesting Authority).",
    caseuco: "This template has a fixed structure aligned with the CASE/UCO forensic ontology - the section/field checkboxes below only apply to Standard exports. It always includes Geolocation/GPS evidence. Add Custom Case Fields below for Authorization Identifier/Type, Investigation Status, or Investigation Form if your station wants those captured.",
};

function onDefReportTemplateChange() {
    const sel = document.getElementById("defReportTemplate");
    const hint = document.getElementById("defTemplateHint");
    if (!sel || !hint) return;
    const value = sel.value;
    if (value === 'standard') {
        hint.style.display = 'none';
        return;
    }
    hint.style.display = 'block';
    if (value.startsWith('custom:')) {
        const record = customReportTemplatesCache.find(t => `custom:${t.id}` === value);
        hint.textContent = `This is a custom template - its structure is edited via Custom Report Templates below${record ? ` ("${record.name}")` : ''}.`;
    } else {
        hint.textContent = DEF_FIXED_TEMPLATE_HINTS[value] || DEF_FIXED_TEMPLATE_HINTS.dfir;
    }
}

function renderCustomFieldDefsEditor() {
    const container = document.getElementById("customFieldDefsContainer");
    if (!container) return;
    container.innerHTML = '';
    if (caseReportingFieldsEditing.length === 0) {
        const msg = document.createElement('div');
        msg.className = 'small text-subtle';
        msg.textContent = 'No custom fields configured yet.';
        container.appendChild(msg);
        return;
    }
    caseReportingFieldsEditing.forEach((def, idx) => {
        const row = document.createElement('div');
        row.className = 'd-flex gap-2 mb-2 align-items-center';

        // Same tap-to-reorder shape as the Report Template Builder's own
        // rows (moveTemplateBuilderRow) - this app avoids drag-and-drop
        // throughout for touchscreen-kiosk reasons, so every reorderable
        // list here uses this same up/down-arrow convention.
        const moveWrap = document.createElement('div');
        moveWrap.className = 'd-flex flex-column';
        const upBtn = document.createElement('button');
        upBtn.type = 'button';
        upBtn.className = 'btn btn-xs btn-outline-secondary py-0 px-1';
        upBtn.innerHTML = '<i class="bi bi-caret-up-fill"></i>';
        upBtn.disabled = idx === 0;
        upBtn.onclick = () => moveCustomFieldDefRow(idx, -1);
        const downBtn = document.createElement('button');
        downBtn.type = 'button';
        downBtn.className = 'btn btn-xs btn-outline-secondary py-0 px-1';
        downBtn.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
        downBtn.disabled = idx === caseReportingFieldsEditing.length - 1;
        downBtn.onclick = () => moveCustomFieldDefRow(idx, 1);
        moveWrap.appendChild(upBtn);
        moveWrap.appendChild(downBtn);
        row.appendChild(moveWrap);

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control form-control-sm';
        input.placeholder = 'Field label (e.g. Agency)';
        input.value = def.label || '';
        input.oninput = () => { caseReportingFieldsEditing[idx].label = input.value; };
        // Free-text default, prefilled into this field's value on every
        // NEW case going forward (create_case() in routes/case_management.py)
        // - e.g. a station that's always the same agency can set that once
        // here instead of retyping it per case. Never touches an existing
        // case's already-saved value.
        const defaultInput = document.createElement('input');
        defaultInput.type = 'text';
        defaultInput.className = 'form-control form-control-sm';
        defaultInput.placeholder = 'Default value for new cases (optional)';
        defaultInput.value = def.default_value || '';
        defaultInput.oninput = () => { caseReportingFieldsEditing[idx].default_value = defaultInput.value; };
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-sm btn-outline-danger';
        delBtn.type = 'button';
        delBtn.innerHTML = '<i class="bi bi-trash3"></i>';
        delBtn.onclick = () => { caseReportingFieldsEditing.splice(idx, 1); renderCustomFieldDefsEditor(); };
        row.appendChild(input);
        row.appendChild(defaultInput);
        row.appendChild(delBtn);
        container.appendChild(row);
    });
}

function moveCustomFieldDefRow(idx, direction) {
    const target = idx + direction;
    if (target < 0 || target >= caseReportingFieldsEditing.length) return;
    const [row] = caseReportingFieldsEditing.splice(idx, 1);
    caseReportingFieldsEditing.splice(target, 0, row);
    renderCustomFieldDefsEditor();
}

function addCustomFieldDefRow() {
    caseReportingFieldsEditing.push({ key: '', label: '', default_value: '' });
    renderCustomFieldDefsEditor();
}

async function saveCaseReportingSettings() {
    const statusEl = document.getElementById("caseReportingStatus");

    const template = document.getElementById("defReportTemplate")?.value || 'standard';
    const sections = {
        case_info: document.getElementById("defSecCaseInfo")?.checked ?? true,
        executive_summary: document.getElementById("defSecExecSummary")?.checked ?? true,
        evidence_inventory: document.getElementById("defSecEvidenceInventory")?.checked ?? true,
        forensic_analysis: document.getElementById("defSecForensicAnalysis")?.checked ?? true,
        relevant_findings: document.getElementById("defSecFindings")?.checked ?? true,
        limitations: document.getElementById("defSecLimitations")?.checked ?? true,
        conclusion: document.getElementById("defSecConclusion")?.checked ?? true,
        attachments: document.getElementById("defSecAttachments")?.checked ?? true,
        geolocation: document.getElementById("defSecGeolocation")?.checked ?? false,
        audit_trail: document.getElementById("defSecAuditTrail")?.checked ?? true,
    };
    const jobFields = {
        telemetry: document.getElementById("defFieldTelemetry")?.checked ?? true,
        params: document.getElementById("defFieldParams")?.checked ?? true,
        hashes: document.getElementById("defFieldHashes")?.checked ?? true,
    };
    const headerText = document.getElementById("reportBrandingText")?.value || '';
    // key is included (not just label/default_value) so the backend can
    // preserve an existing field's key across a label rename, rather than
    // regenerating it fresh every save - see settings_case_reporting()'s
    // own comment on why that used to silently drop already-saved case
    // data. addCustomFieldDefRow() always seeds a brand-new row's key as
    // '', which the backend correctly treats as "generate a fresh one."
    const customFields = caseReportingFieldsEditing
        .map(f => ({ key: f.key || '', label: (f.label || '').trim(), default_value: (f.default_value || '').trim() }))
        .filter(f => f.label.length > 0);

    try {
        const res = await fetch('/api/settings/case_reporting', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                report_defaults: { template, sections, job_fields: jobFields, branding: { header_text: headerText } },
                custom_case_fields: customFields
            })
        });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small mt-2 text-success' : 'small mt-2 text-danger';
            statusEl.innerText = data.success ? 'Settings saved.' : data.error;
        }
        if (data.success) {
            // Refresh the shared cache Reporting reads, and reload this
            // card's own editor from the server-confirmed (deduplicated,
            // key-assigned) result rather than trusting the local working copy.
            await fetchCustomFieldDefs();
            loadCaseReportingSettings();
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small mt-2 text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

async function uploadReportLogo() {
    const fileInput = document.getElementById("reportLogoFile");
    const file = fileInput?.files[0];
    const statusEl = document.getElementById("reportLogoStatus");
    if (!file) return showToast("Select a logo image file first.", 'warning');

    const formData = new FormData();
    formData.append('logo', file);

    try {
        const res = await fetch('/api/settings/report_logo', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success && fileInput) fileInput.value = '';
        if (statusEl) {
            statusEl.className = data.success ? 'small text-success' : 'small text-danger';
            statusEl.innerText = data.success ? `Logo uploaded: ${file.name}` : data.error;
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

async function clearReportLogo() {
    const statusEl = document.getElementById("reportLogoStatus");
    try {
        const res = await fetch('/api/settings/report_logo/clear', { method: 'POST' });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small text-subtle' : 'small text-danger';
            statusEl.innerText = data.success ? 'No logo set.' : data.error;
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

// Reporting has no independent load step anymore - it always follows the
// Active Case Bar. Called once at the end of applyActiveCaseToFields() (so
// case create/select/page-load-restore all pick this up for free) and
// again after any case-notes add/edit to re-fetch authoritative on-disk
// state. Toggles #reportsNoCaseState / #reportsLoadedState depending on
// whether there's an active case at all vs. an active case whose
// consolidated report file doesn't exist yet (not-yet-migrated legacy case).
async function loadCaseForEditing() {
    const noCaseEl = document.getElementById("reportsNoCaseState");
    const loadedEl = document.getElementById("reportsLoadedState");
    const noCaseIcon = document.getElementById("reportsNoCaseIcon");
    const noCaseMsg = document.getElementById("reportsNoCaseMsg");

    if (!activeCase) {
        currentReportPath = null;
        currentLoadedReportData = null;
        if (noCaseIcon) noCaseIcon.className = 'bi bi-folder2-open fs-3 d-block mb-2';
        if (noCaseMsg) noCaseMsg.textContent = 'Select or create a case using the bar above to view its report.';
        if (noCaseEl) noCaseEl.style.display = 'block';
        if (loadedEl) loadedEl.style.display = 'none';
        return;
    }

    const slug = activeCase.case_folder.split('/').filter(Boolean).pop();
    currentReportPath = `${activeCase.case_folder}/${slug}_case.json`;

    try {
        const res = await fetch('/api/report/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: currentReportPath })
        });
        const data = await res.json();

        if (!data.success) {
            currentReportPath = null;
            currentLoadedReportData = null;
            if (noCaseIcon) noCaseIcon.className = 'bi bi-exclamation-triangle fs-3 d-block mb-2';
            if (noCaseMsg) noCaseMsg.textContent = `This case ("${activeCase.case_number}") hasn't been migrated to the consolidated report format yet - migrate it via the Case Manager.`;
            if (noCaseEl) noCaseEl.style.display = 'block';
            if (loadedEl) loadedEl.style.display = 'none';
            return;
        }

        currentLoadedReportData = data.report;
        if (noCaseEl) noCaseEl.style.display = 'none';
        if (loadedEl) loadedEl.style.display = 'block';

        // A consolidated case file has a top-level "events" array; a
        // legacy single-job report has case_number/examiner/notes
        // nested under case_metadata instead. Same Case Information
        // fields, different source location depending on which one
        // was loaded.
        const isConsolidated = Array.isArray(currentLoadedReportData.events);
        const legacyMeta = currentLoadedReportData.case_metadata || {};

        const legacyNotice = document.getElementById("repLegacyNotice");

        if (legacyNotice) legacyNotice.style.display = isConsolidated ? 'none' : 'block';

        renderCustomFieldsForCase(isConsolidated ? currentLoadedReportData.custom_fields : legacyMeta.custom_fields);

        // Report Narrative fields - same isConsolidated/legacyMeta split
        // as case_number/examiner/notes above.
        const narrativeSrc = isConsolidated ? currentLoadedReportData : legacyMeta;
        const caseStatusEl = document.getElementById("editCaseStatus");
        if (caseStatusEl) caseStatusEl.value = narrativeSrc.case_status || "Open";
        const execSummaryEl = document.getElementById("editExecSummary");
        const objectivesEl = document.getElementById("editObjectives");
        const findingsEl = document.getElementById("editFindingsSummary");
        const limitationsEl = document.getElementById("editLimitations");
        const conclusionEl = document.getElementById("editConclusion");
        const iocsEl = document.getElementById("editIocs");
        const recommendationsEl = document.getElementById("editRecommendations");
        if (execSummaryEl) execSummaryEl.value = narrativeSrc.executive_summary || "";
        if (objectivesEl) objectivesEl.value = narrativeSrc.objectives || "";
        if (findingsEl) findingsEl.value = narrativeSrc.findings_summary || "";
        if (limitationsEl) limitationsEl.value = narrativeSrc.limitations || "";
        if (conclusionEl) conclusionEl.value = narrativeSrc.conclusion || "";
        if (iocsEl) iocsEl.value = narrativeSrc.iocs || "";
        if (recommendationsEl) recommendationsEl.value = narrativeSrc.recommendations_next_steps || "";

        renderCaseNotesList();
        renderCustodyLogList();
        loadCaseHistory();
        renderCaseJobs();
        renderCaseDashboard();

        const attach = currentLoadedReportData.attachments || {};
        currentAttachedFilesList = attach.files || [];
        if (!currentAttachedFilesList.length && attach.image_path) {
            currentAttachedFilesList = [attach.image_path];
        }
        currentAttachmentCaptions = attach.file_captions || {};
        currentReferenceUrlsList = attach.reference_urls || [];
        renderReportFilesGallery();

        const previewEl = document.getElementById("jsonPreview");
        if (previewEl) {
            previewEl.innerText = JSON.stringify(currentLoadedReportData, null, 2);
        }
    } catch (err) {
        showToast(`Failed to load report: ${err.message}`, 'danger');
    }
}

// --- Case Jobs (consolidated-schema case files only) ---
// Renders currentLoadedReportData.events directly - already in memory from
// loadCaseForEditing(), no extra fetch. A legacy single-job report has no
// "events" array at all, so that case is called out distinctly rather than
// just showing an empty list.
function renderCaseJobs() {
    const container = document.getElementById("jobsContainer");
    if (!container) return;

    if (!currentLoadedReportData) {
        container.innerHTML = '<span class="text-subtle">Load a case above, then open this tab to see its jobs.</span>';
        return;
    }
    const events = currentLoadedReportData.events;
    if (!Array.isArray(events)) {
        container.innerHTML = '<span class="text-subtle">This is a single-job legacy report with no separate job history - migrate it via the Case Manager to see jobs listed individually.</span>';
        return;
    }
    if (events.length === 0) {
        container.innerHTML = '<span class="text-subtle">No jobs recorded against this case yet.</span>';
        return;
    }

    container.innerHTML = '';
    const sorted = [...events].sort((a, b) => (b.timestamp_start || '').localeCompare(a.timestamp_start || ''));
    sorted.forEach(ev => {
        const meta = ev.case_metadata || {};
        const wrapper = document.createElement('div');
        wrapper.className = 'mb-1 pb-1 border-bottom border-secondary';

        const summary = document.createElement('div');
        summary.className = 'd-flex justify-content-between align-items-center';
        summary.style.cursor = 'pointer';

        const left = document.createElement('span');
        const toolSpan = document.createElement('span');
        toolSpan.className = 'text-info fw-bold';
        toolSpan.textContent = (ev.tool || '--').toUpperCase() + '  ';
        left.appendChild(toolSpan);
        left.appendChild(document.createTextNode(`${meta.evidence_id || '--'}  ·  ${ev.timestamp_start || '--'}`));

        const status = (ev.acquisition_status || '--').toUpperCase();
        const statusBadge = document.createElement('span');
        statusBadge.className = 'badge ' + (status === 'COMPLETED' ? 'bg-success' : status === 'FAILED' ? 'bg-danger' : 'bg-info text-dark');
        statusBadge.textContent = status;

        summary.appendChild(left);
        summary.appendChild(statusBadge);

        const detail = document.createElement('pre');
        detail.className = 'text-light small mt-1 mb-0';
        detail.style.display = 'none';
        detail.style.whiteSpace = 'pre-wrap';
        detail.textContent = JSON.stringify(ev, null, 2); // this case's own data, but still rendered as text, never HTML

        summary.onclick = () => { detail.style.display = detail.style.display === 'none' ? 'block' : 'none'; };

        wrapper.appendChild(summary);
        wrapper.appendChild(detail);
        container.appendChild(wrapper);
    });
}

// --- Case Dashboard ("Overview" tab) ---------------------------------------------------
// Aggregates two already-existing, already-case-wide data sources into one at-a-glance view -
// currentLoadedReportData (already loaded on case open) for evidence/notes/attachments/age, and
// /api/case_index/summary (confirmed case-wide, not scoped to whichever image happens to be open in
// File Explorer right now - every query in that route has zero image_path filter) for tags/analysis
// activity. No new backend route needed. Complements Help's Guided Workflow (that answers
// "have I done X/Y/Z"; this answers "here's everything that's happened in this case").
async function renderCaseDashboard() {
    if (!currentLoadedReportData || !activeCase) return;

    renderVerifyAllEvidenceLastResult();

    const isConsolidated = Array.isArray(currentLoadedReportData.events);
    const events = isConsolidated ? currentLoadedReportData.events : [];
    const caseNotes = currentLoadedReportData.case_notes || [];
    const files = (currentLoadedReportData.attachments || {}).files || [];

    const evEl = document.getElementById('dashEvidenceCount');
    const evDetailEl = document.getElementById('dashEvidenceDetail');
    if (evEl) evEl.textContent = isConsolidated ? String(events.length) : '1';
    if (evDetailEl) {
        if (isConsolidated) {
            const completed = events.filter((e) => (e.acquisition_status || '') === 'COMPLETED').length;
            evDetailEl.textContent = `${completed} of ${events.length} completed`;
        } else {
            evDetailEl.textContent = 'Legacy single-job report';
        }
    }

    const notesEl = document.getElementById('dashNotesCount');
    if (notesEl) notesEl.textContent = String(caseNotes.length);
    const attachEl = document.getElementById('dashAttachmentCount');
    if (attachEl) attachEl.textContent = String(files.length);

    const ageEl = document.getElementById('dashCaseAge');
    if (ageEl) {
        const createdAt = isConsolidated ? currentLoadedReportData.created_at
            : (currentLoadedReportData.case_metadata || {}).created_at;
        if (createdAt) {
            const created = new Date(String(createdAt).replace(' ', 'T'));
            const days = Math.max(0, Math.floor((Date.now() - created.getTime()) / 86400000));
            ageEl.textContent = Number.isFinite(days) ? `${days}d` : '--';
        } else {
            ageEl.textContent = '--';
        }
    }

    const tagCountEl = document.getElementById('dashTagCount');
    const tagDetailEl = document.getElementById('dashTagDetail');
    const analysisCountEl = document.getElementById('dashAnalysisCount');
    const analysisDetailEl = document.getElementById('dashAnalysisDetail');
    try {
        const res = await fetch('/api/case_index/summary', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder }),
        });
        const data = await res.json();
        if (data.success) {
            const tags = data.tags || [];
            const taggedItems = tags.reduce((sum, t) => sum + (t.count || 0), 0);
            const notableTag = tags.find((t) => t.notable);
            if (tagCountEl) tagCountEl.textContent = String(taggedItems);
            if (tagDetailEl) {
                tagDetailEl.textContent = (notableTag && notableTag.count > 0)
                    ? `${notableTag.count} Notable Item(s) flagged` : 'No notable items flagged';
                tagDetailEl.className = (notableTag && notableTag.count > 0) ? 'small mt-1 text-danger fw-bold' : 'small mt-1 text-subtle';
            }

            const parsedArtifactTotal = Object.values(data.parsed_artifact_counts || {}).reduce((a, b) => a + b, 0);
            const analysisTotal = (data.analysis_results_count || 0) + (data.total_files || 0)
                + ((data.keyword_hits || {}).total || 0) + parsedArtifactTotal;
            if (analysisCountEl) analysisCountEl.textContent = data.has_analysis_activity ? String(analysisTotal) : '0';
            if (analysisDetailEl) analysisDetailEl.textContent = data.has_analysis_activity
                ? 'Tools have been run against this case' : 'No analysis tools run yet';
        }
    } catch (err) {}
}

// --- Case-wide "Verify All Evidence" (A4) -------------------------------------------------
// Shows the case's last_verification result (if any) on the Overview pane - purely a render
// of already-loaded currentLoadedReportData, no fetch. Live progress while a run is active is
// handled separately in fetchProgress()'s data.format === 'verify_all_evidence' block below.
function renderVerifyAllEvidenceLastResult() {
    const el = document.getElementById('verifyAllEvidenceLastResult');
    if (!el) return;
    const lv = currentLoadedReportData && currentLoadedReportData.last_verification;
    if (!lv) {
        el.innerHTML = '';
        return;
    }
    const results = lv.results || [];
    const skipped = lv.skipped || [];
    const mismatches = results.filter((r) => r.status === 'mismatch').length;
    const matches = results.filter((r) => r.status === 'match').length;
    const unverifiable = results.filter((r) => r.status === 'unverifiable' || r.status === 'missing_file').length;
    el.className = mismatches > 0 ? 'small mt-2 text-danger fw-bold' : 'small mt-2 text-subtle';
    el.textContent = `Last verified ${lv.timestamp || '--'}: ${matches} match(es), ${mismatches} mismatch(es), `
        + `${unverifiable} unverifiable, ${skipped.length} not checkable by this tool.`; // static/derived text only
}

async function startCaseBundleExport() {
    if (!activeCase) {
        showToast('Select an active case first.', 'warning');
        return;
    }
    const includeImages = document.getElementById('bundleIncludeImages')?.checked || false;
    const warnExtra = includeImages
        ? '\n\nRaw acquisition images are INCLUDED - this bundle may be very large and will block new acquisition/recovery jobs for a while.'
        : '\n\nRaw acquisition images are excluded from this bundle (check the box above to include them).';
    if (!confirm(`Zip the entire case folder for archival/handoff?\n\nThis runs as a background job and uses the one station-wide job slot.${warnExtra}`)) {
        return;
    }
    try {
        const res = await fetch('/api/cases/export_bundle', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, include_images: includeImages }),
        });
        const data = await res.json();
        if (data.success) {
            showToast('Case bundle export started.', 'info');
        } else {
            showToast(data.error || 'Failed to start bundle export.', 'danger');
        }
    } catch (err) {
        showToast(`Failed: ${err.message}`, 'danger');
    }
}

async function startVerifyAllEvidence() {
    if (!activeCase) {
        showToast('Select an active case first.', 'warning');
        return;
    }
    if (!confirm('Re-hash every completed acquisition in this case and compare against the hashes recorded at acquisition time?\n\nThis runs as a background job and uses the one station-wide job slot - it will block a new acquisition/recovery/mobile job from starting until it finishes. This may take a while on a case with large images.')) {
        return;
    }
    const btn = document.getElementById('btnVerifyAllEvidence');
    try {
        const res = await fetch('/api/cases/verify_all_evidence', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder }),
        });
        const data = await res.json();
        if (data.success) {
            showToast('Case-wide evidence verification started.', 'info');
        } else {
            showToast(data.error || 'Failed to start verification.', 'danger');
        }
    } catch (err) {
        showToast(`Failed: ${err.message}`, 'danger');
    }
}

// --- Evidence Timeline (B1) --------------------------------------------------------------
// Fetched once per tab-open (real work: filesystem walks + a SQLite query, not something to
// re-run per checkbox toggle), then filtered/re-rendered client-side by the 2 source checkboxes.
// Deliberately evidence-only (MACB + parsed artifacts) - case_notes[]/custody_log[] were dropped
// from this view (2026-08-25, confirmed with the user): both are examiner-authored workflow
// entries, not evidence pulled off a drive/phone, and both already have their own dedicated
// Reporting tabs - mixing them in here diluted what this view is actually for.
let caseTimelineCache = null;
const CASE_TIMELINE_SOURCE_BADGE = {
    macb: 'bg-info text-dark', parsed_artifact: 'bg-secondary',
};
const CASE_TIMELINE_SOURCE_LABEL = {
    macb: 'Filesystem', parsed_artifact: 'Artifact',
};
// Same sources as the badges above, as real hex values for Chart.js
// (Bootstrap's actual default palette for info/secondary) - kept as a
// separate map rather than deriving from the badge classes so the chart
// never depends on parsing a computed CSS color at render time.
const CASE_TIMELINE_SOURCE_COLOR = {
    macb: '#0dcaf0', parsed_artifact: '#6c757d',
};
const CASE_TIMELINE_SOURCES = ['macb', 'parsed_artifact'];
// Spelled-out labels for the single-letter MACB codes and the raw
// artifact_type strings, used only when rendering the interactive table -
// the underlying data (and the PDF/HTML report's own Filesystem Timeline
// section, which reuses the same backend collector) keeps the compact "M"/
// "A"/"C"/"B" codes unchanged, this is presentation-only. Parsed-artifact
// rows reuse FILE_VIEWS_WEB_ARTIFACT_LABELS (defined above) rather than a
// second copy of the same type->label mapping.
const MACB_ACTIVITY_LABEL = { M: 'Modified', A: 'Accessed', C: 'Changed', B: 'Created (Born)' };
let caseTimelineEvidenceFilter = '__all__'; // '__all__' | a real evidence_id string
let caseTimelineYearFilter = '__all__';     // '__all__' | a year as a string, e.g. "2026"
let caseTimelineMonthFilter = '__all__';    // '__all__' | "0"-"11" (Date.getMonth() indexing) - only meaningful once a specific year is picked
let caseTimelineFilteredRows = [];          // the table's currently-visible rows, stashed for CSV export
const CASE_TIMELINE_MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];

async function loadCaseTimeline() {
    const body = document.getElementById('caseTimelineBody');
    if (!body || !activeCase) return;
    body.innerHTML = '<tr><td colspan="4" class="text-subtle p-2">Building timeline...</td></tr>';
    caseTimelineBucketFilter = null;   // a fresh case load shouldn't carry over a stale drill-down from a previous case
    caseTimelineEvidenceFilter = '__all__';
    caseTimelineYearFilter = '__all__';
    caseTimelineMonthFilter = '__all__';
    try {
        const res = await fetch(`/api/cases/timeline?case_folder=${encodeURIComponent(activeCase.case_folder)}`);
        const data = await res.json();
        if (!data.success) {
            body.innerHTML = `<tr><td colspan="4" class="text-danger p-2">${data.error || 'Request failed.'}</td></tr>`;
            return;
        }
        caseTimelineCache = data;
        populateCaseTimelineEvidenceFilter(data.events);
        populateCaseTimelineYearFilter(data.events);
        renderCaseTimeline();
    } catch (err) {
        body.innerHTML = '<tr><td colspan="4" class="text-danger p-2">Request failed.</td></tr>';
    }
}

function populateCaseTimelineEvidenceFilter(events) {
    const sel = document.getElementById('caseTimelineEvidenceSelect');
    if (!sel) return;
    const ids = [...new Set(events.map((e) => e.evidence_id).filter(Boolean))].sort();
    sel.innerHTML = '';
    const allOpt = document.createElement('option');
    allOpt.value = '__all__';
    allOpt.textContent = 'All Evidence Items';
    sel.appendChild(allOpt);
    ids.forEach((id) => {
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = id; // examiner-entered evidence_id, but option.textContent is always a safe text node
        sel.appendChild(opt);
    });
    sel.value = '__all__';
}

// Year/Month drill-down filters - "condense" a timeline spanning years down to
// one calendar year (or one month within it) so the density chart's own
// adaptive granularity (pickTimelineGranularity()) has a narrow enough span to
// render something readable, instead of years of activity getting flattened
// into a handful of monthly bars. Month is deliberately disabled until a real
// year is picked - a hierarchical drill-down (year, then month within it),
// not an independent "every March across every year" filter, which would be
// a different, more surprising feature.
function populateCaseTimelineYearFilter(events) {
    const yearSel = document.getElementById('caseTimelineYearSelect');
    if (!yearSel) return;
    const years = [...new Set(events.map((e) => new Date(e.timestamp * 1000).getFullYear()))].sort((a, b) => b - a);
    yearSel.innerHTML = '';
    const allOpt = document.createElement('option');
    allOpt.value = '__all__';
    allOpt.textContent = 'All Years';
    yearSel.appendChild(allOpt);
    years.forEach((y) => {
        const opt = document.createElement('option');
        opt.value = String(y);
        opt.textContent = String(y);
        yearSel.appendChild(opt);
    });
    yearSel.value = '__all__';
    populateCaseTimelineMonthFilter();
}

function populateCaseTimelineMonthFilter() {
    const monthSel = document.getElementById('caseTimelineMonthSelect');
    const yearSel = document.getElementById('caseTimelineYearSelect');
    if (!monthSel) return;
    monthSel.innerHTML = '';
    const allOpt = document.createElement('option');
    allOpt.value = '__all__';
    allOpt.textContent = 'All Months';
    monthSel.appendChild(allOpt);
    CASE_TIMELINE_MONTH_NAMES.forEach((name, idx) => {
        const opt = document.createElement('option');
        opt.value = String(idx);
        opt.textContent = name;
        monthSel.appendChild(opt);
    });
    monthSel.value = '__all__';
    monthSel.disabled = !yearSel || yearSel.value === '__all__';
}

function onCaseTimelineYearChange() {
    caseTimelineBucketFilter = null; // a bucket drilled into under the old year/month scope would just show 0 rows under the new one
    populateCaseTimelineMonthFilter();
    renderCaseTimeline();
}

function onCaseTimelineMonthChange() {
    caseTimelineBucketFilter = null;
    renderCaseTimeline();
}

// --- Evidence Timeline density chart - a stacked bar chart of event counts per
// time bucket, colored by source, sitting above the existing table. Bucket
// granularity is picked adaptively from the span of the currently
// source-filtered events (not the bucket filter itself, so the chart always
// shows every bucket available to drill into) - a case spanning a couple of
// days gets hourly bars, one spanning years gets monthly ones, so the bar
// count stays readable regardless of how wide a timeline this case has.
// Clicking a bar sets caseTimelineBucketFilter, which renderCaseTimeline()
// then applies to the table below (the chart itself is never re-bucketed by
// its own click - only the table narrows, matching a drill-down, not a zoom).
let caseTimelineChart = null;
let caseTimelineBucketFilter = null; // null | {start, end, label} (start/end are Unix seconds)
let caseTimelineBuckets = [];        // the chart's current bucket list, index-aligned with its bars

function pickTimelineGranularity(minTs, maxTs) {
    const spanSeconds = maxTs - minTs;
    const DAY = 86400;
    if (spanSeconds <= 2 * DAY) return 'hour';
    if (spanSeconds <= 60 * DAY) return 'day';
    if (spanSeconds <= 2 * 365 * DAY) return 'week';
    return 'month';
}

function timelineBucketStart(epochMs, granularity) {
    const d = new Date(epochMs);
    if (granularity === 'hour') { d.setMinutes(0, 0, 0); return d; }
    d.setHours(0, 0, 0, 0);
    if (granularity === 'day') return d;
    if (granularity === 'week') { d.setDate(d.getDate() - d.getDay()); return d; } // week starts Sunday
    d.setDate(1); // month
    return d;
}

function timelineBucketEnd(start, granularity) {
    const d = new Date(start);
    if (granularity === 'hour') d.setHours(d.getHours() + 1);
    else if (granularity === 'day') d.setDate(d.getDate() + 1);
    else if (granularity === 'week') d.setDate(d.getDate() + 7);
    else d.setMonth(d.getMonth() + 1);
    return d;
}

function timelineBucketLabel(start, granularity) {
    if (granularity === 'hour') return start.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric' });
    if (granularity === 'day') return start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    if (granularity === 'week') return `Wk of ${start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}`;
    return start.toLocaleDateString(undefined, { month: 'short', year: 'numeric' });
}

function renderCaseTimelineChart(rows) {
    const canvas = document.getElementById('caseTimelineChart');
    if (!canvas) return;
    if (rows.length === 0) {
        if (caseTimelineChart) { caseTimelineChart.destroy(); caseTimelineChart = null; }
        canvas.style.display = 'none';
        return;
    }
    canvas.style.display = '';

    const timestamps = rows.map((e) => e.timestamp);
    const granularity = pickTimelineGranularity(Math.min(...timestamps), Math.max(...timestamps));

    const bucketMap = new Map(); // bucket-start epoch ms -> {start, end, label, counts:{source:n}, suspiciousCount}
    rows.forEach((e) => {
        const start = timelineBucketStart(e.timestamp * 1000, granularity);
        const key = start.getTime();
        if (!bucketMap.has(key)) {
            bucketMap.set(key, { start, end: timelineBucketEnd(start, granularity), label: timelineBucketLabel(start, granularity), counts: {}, suspiciousCount: 0 });
        }
        const bucket = bucketMap.get(key);
        bucket.counts[e.source] = (bucket.counts[e.source] || 0) + 1;
        if (e.suspicious) bucket.suspiciousCount += 1;
    });
    caseTimelineBuckets = [...bucketMap.values()].sort((a, b) => a.start - b.start);

    const labels = caseTimelineBuckets.map((b) => b.label);
    const datasets = CASE_TIMELINE_SOURCES.map((src) => ({
        label: CASE_TIMELINE_SOURCE_LABEL[src],
        data: caseTimelineBuckets.map((b) => b.counts[src] || 0),
        backgroundColor: CASE_TIMELINE_SOURCE_COLOR[src],
    }));

    if (caseTimelineChart) {
        caseTimelineChart.data.labels = labels;
        caseTimelineChart.data.datasets = datasets;
        caseTimelineChart.update();
        return;
    }

    caseTimelineChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: { stacked: true, ticks: { color: '#94a3b8', maxRotation: 0, autoSkip: true }, grid: { display: false } },
                y: { stacked: true, beginAtZero: true, ticks: { color: '#94a3b8', precision: 0 }, grid: { color: 'rgba(255,255,255,0.06)' } },
            },
            plugins: {
                legend: { labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 11 } } },
                tooltip: {
                    callbacks: {
                        title: (items) => (items[0] ? caseTimelineBuckets[items[0].dataIndex]?.label : '') || '',
                        afterBody: (items) => {
                            const b = items[0] ? caseTimelineBuckets[items[0].dataIndex] : null;
                            return b && b.suspiciousCount ? [`⚠ ${b.suspiciousCount} suspicious event(s) in this bucket`] : [];
                        },
                    },
                },
            },
            onClick: (evt, elements) => {
                if (!elements.length) return;
                const bucket = caseTimelineBuckets[elements[0].index];
                if (!bucket) return;
                caseTimelineBucketFilter = { start: bucket.start.getTime() / 1000, end: bucket.end.getTime() / 1000, label: bucket.label };
                renderCaseTimeline();
            },
        },
        // A small red dot above any bucket containing a "suspicious" event
        // (currently just an EVTX 1102 audit-log-cleared record - see
        // CASE_TIMELINE_SUSPICIOUS_ARTIFACT_TYPES in routes/reporting.py).
        // A plain Chart.js plugin, not a new dependency - reads
        // caseTimelineBuckets fresh on every draw, so it stays correct
        // across both chart creation and every later .update() call with no
        // extra wiring needed.
        plugins: [{
            id: 'caseTimelineSuspiciousMarker',
            afterDatasetsDraw(chart) {
                const buckets = caseTimelineBuckets;
                if (!buckets.length) return;
                const topMeta = chart.getDatasetMeta(chart.data.datasets.length - 1);
                const ctx = chart.ctx;
                ctx.save();
                buckets.forEach((b, i) => {
                    if (!b.suspiciousCount) return;
                    const el = topMeta.data[i];
                    if (!el) return;
                    ctx.fillStyle = '#ff4d4f';
                    ctx.strokeStyle = '#1a0000';
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.arc(el.x, el.y - 10, 4, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.stroke();
                });
                ctx.restore();
            },
        }],
    });
}

function clearCaseTimelineBucketFilter() {
    caseTimelineBucketFilter = null;
    renderCaseTimeline();
}

function renderCaseTimeline() {
    const body = document.getElementById('caseTimelineBody');
    const notesEl = document.getElementById('caseTimelineNotes');
    if (!body || !caseTimelineCache) return;

    const enabledSources = new Set(
        [...document.querySelectorAll('.case-timeline-source-check:checked')].map((el) => el.value)
    );
    const evidenceSel = document.getElementById('caseTimelineEvidenceSelect');
    caseTimelineEvidenceFilter = evidenceSel ? evidenceSel.value : '__all__';
    const yearSel = document.getElementById('caseTimelineYearSelect');
    caseTimelineYearFilter = yearSel ? yearSel.value : '__all__';
    const monthSel = document.getElementById('caseTimelineMonthSelect');
    caseTimelineMonthFilter = (monthSel && !monthSel.disabled) ? monthSel.value : '__all__';

    let rows = caseTimelineCache.events.filter((e) => enabledSources.has(e.source));
    if (caseTimelineEvidenceFilter !== '__all__') {
        rows = rows.filter((e) => e.evidence_id === caseTimelineEvidenceFilter);
    }
    if (caseTimelineYearFilter !== '__all__') {
        const y = Number(caseTimelineYearFilter);
        rows = rows.filter((e) => new Date(e.timestamp * 1000).getFullYear() === y);
        if (caseTimelineMonthFilter !== '__all__') {
            const m = Number(caseTimelineMonthFilter);
            rows = rows.filter((e) => new Date(e.timestamp * 1000).getMonth() === m);
        }
    }
    // Feeding the year/month-narrowed rows into the chart is what actually "condenses"
    // the view - pickTimelineGranularity() (in renderCaseTimelineChart()) picks its bucket
    // size from whatever span it's handed, so a full year renders as weekly bars and a
    // single month renders as daily ones, with zero changes needed to that logic itself.
    renderCaseTimelineChart(rows); // chart reflects source + evidence-item + year/month filters, never the bucket-click drill-down below (so every bucket stays clickable)

    const filterIndicator = document.getElementById('caseTimelineFilterIndicator');
    if (caseTimelineBucketFilter) {
        rows = rows.filter((e) => e.timestamp >= caseTimelineBucketFilter.start && e.timestamp < caseTimelineBucketFilter.end);
        if (filterIndicator) {
            filterIndicator.style.display = '';
            filterIndicator.querySelector('.timeline-filter-label').textContent = caseTimelineBucketFilter.label;
        }
    } else if (filterIndicator) {
        filterIndicator.style.display = 'none';
    }

    caseTimelineFilteredRows = rows; // whatever's currently visible in the table - CSV export reads this directly, no separate filter pass

    if (notesEl) {
        const noteLines = [...(caseTimelineCache.notes || [])];
        if (caseTimelineCache.truncated) noteLines.push('This timeline was truncated - not every event may be shown.');
        notesEl.textContent = noteLines.join(' ');
        notesEl.style.display = noteLines.length ? 'block' : 'none';
    }

    if (rows.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="text-subtle p-2">No timeline entries match the current filters.</td></tr>';
        return;
    }

    body.innerHTML = '';
    rows.forEach((e) => {
        const tr = document.createElement('tr');
        if (e.suspicious) {
            // Inline style, not a Bootstrap .table-danger class - this app's
            // tables are already .table-dark, and layering a light-mode
            // utility class on top of that has bitten this project before
            // (see CLAUDE.md's repeated ".d-flex !important" gotcha for the
            // same class of Bootstrap-vs-custom-dark-theme conflict). A
            // plain translucent red composites correctly over any theme.
            tr.style.backgroundColor = 'rgba(220, 53, 69, 0.18)';
        }

        const tsTd = document.createElement('td');
        tsTd.className = 'text-nowrap';
        tsTd.textContent = new Date(e.timestamp * 1000).toLocaleString();

        const srcTd = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = `badge ${CASE_TIMELINE_SOURCE_BADGE[e.source] || 'bg-secondary'}`;
        badge.textContent = CASE_TIMELINE_SOURCE_LABEL[e.source] || e.source;
        srcTd.appendChild(badge);
        if (e.deleted) {
            const delBadge = document.createElement('span');
            delBadge.className = 'badge bg-danger ms-1';
            delBadge.textContent = 'Deleted';
            srcTd.appendChild(delBadge);
        }
        // 2026-08-29: a mobile-pull-sourced 'M' event can now be a genuine,
        // captured-from-the-device modification time (an Android pull run
        // after this shipped) rather than the copy-time fallback every
        // folder-based entry used before it - this badge is the only place
        // an examiner looking at the interactive table (as opposed to an
        // exported report, which already labels this per-row) can tell the
        // two apart.
        if (e.real_device_timestamp) {
            const devBadge = document.createElement('span');
            devBadge.className = 'badge bg-success ms-1';
            devBadge.title = 'Captured directly from the device via adb shell right after the pull - not the file\'s copy-time.';
            devBadge.textContent = 'Device Time';
            srcTd.appendChild(devBadge);
        }

        const actTd = document.createElement('td');
        const activityLabel = e.source === 'macb' ? (MACB_ACTIVITY_LABEL[e.activity] || e.activity)
                                                    : (FILE_VIEWS_WEB_ARTIFACT_LABELS[e.activity] || e.activity);
        actTd.textContent = e.suspicious ? `⚠ ${activityLabel || ''}` : (activityLabel || '');

        const detailTd = document.createElement('td');
        detailTd.textContent = e.evidence_id ? `[${e.evidence_id}] ${e.detail || ''}` : (e.detail || '');

        tr.appendChild(tsTd);
        tr.appendChild(srcTd);
        tr.appendChild(actTd);
        tr.appendChild(detailTd);
        body.appendChild(tr);
    });
}

function exportCaseTimelineCsv() {
    if (!caseTimelineFilteredRows.length) {
        showToast('No timeline rows to export - check your current filters.', 'warning');
        return;
    }
    const csvCell = (val) => {
        const s = (val === null || val === undefined) ? '' : String(val);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = ['Timestamp', 'Source', 'Activity', 'Detail', 'Evidence ID', 'Deleted', 'Suspicious', 'Device Time'];
    const lines = [header];
    caseTimelineFilteredRows.forEach((e) => {
        const activityLabel = e.source === 'macb' ? (MACB_ACTIVITY_LABEL[e.activity] || e.activity)
                                                    : (FILE_VIEWS_WEB_ARTIFACT_LABELS[e.activity] || e.activity);
        lines.push([
            new Date(e.timestamp * 1000).toLocaleString(),
            CASE_TIMELINE_SOURCE_LABEL[e.source] || e.source,
            activityLabel || '', e.detail || '', e.evidence_id || '',
            e.deleted ? 'Yes' : 'No', e.suspicious ? 'Yes' : 'No',
            e.real_device_timestamp ? 'Yes' : 'No',
        ]);
    });
    const csvText = lines.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
    const blob = new Blob([csvText], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const caseLabel = (activeCase && activeCase.case_number ? activeCase.case_number : 'case').replace(/[^a-zA-Z0-9_-]+/g, '_');
    a.download = `${caseLabel}_evidence_timeline.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
}

// --- Case Notes: timestamped, append-only journal (Forensic Analysis / Steps Taken) ---
// case_notes[] rides along inside currentLoadedReportData exactly like
// events[] does for Jobs - no separate list endpoint. Editing never
// overwrites in place: the prior text is preserved in edit_history, see
// /api/cases/notes/edit in app.py.
let editingCaseNoteId = null;

// Populates the "Link to Exhibit(s)" checklist on the Add Note form from
// whatever's currently attached - exhibit numbers here are each file's
// 1-based position in currentAttachedFilesList, matching the Files gallery
// and export_report()'s own numbering exactly.
function renderNewCaseNoteLinkedFilesChecklist() {
    const container = document.getElementById("newCaseNoteLinkedFiles");
    if (!container) return;
    container.innerHTML = '';
    if (!currentAttachedFilesList.length) {
        container.innerHTML = '<span class="text-subtle small italic">No exhibits attached yet - see the Files &amp; Artifacts tab.</span>';
        return;
    }
    currentAttachedFilesList.forEach((fp, i) => {
        const row = document.createElement('div');
        row.className = 'form-check';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'form-check-input new-case-note-link-cb';
        cb.value = fp;
        cb.id = `newCaseNoteLink${i}`;
        const label = document.createElement('label');
        label.className = 'form-check-label small';
        label.htmlFor = cb.id;
        label.textContent = `Exhibit ${i + 1} - ${fp.split('/').pop()}`; // untrusted (filename) - text node only
        row.appendChild(cb);
        row.appendChild(label);
        container.appendChild(row);
    });
}

function renderCaseNotesList() {
    renderNewCaseNoteLinkedFilesChecklist();
    const container = document.getElementById("caseNotesContainer");
    if (!container) return;

    if (!currentLoadedReportData) {
        container.innerHTML = '<span class="text-subtle small italic">Load a case above, then open this tab to see and add case notes.</span>';
        return;
    }
    const notes = currentLoadedReportData.case_notes || [];
    if (notes.length === 0) {
        container.innerHTML = '<span class="text-subtle small italic">No case notes recorded yet - add the first one below.</span>';
        return;
    }

    container.innerHTML = '';
    const sorted = [...notes].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    sorted.forEach(note => {
        const card = document.createElement('div');
        card.className = 'mb-2 pb-2 border-bottom border-secondary';

        const headerLine = document.createElement('div');
        headerLine.className = 'd-flex justify-content-between align-items-start gap-2 mb-1';

        const left = document.createElement('div');
        const catBadge = document.createElement('span');
        catBadge.className = 'badge bg-info text-dark me-2';
        catBadge.textContent = note.category || 'General';
        left.appendChild(catBadge);
        left.appendChild(document.createTextNode(`${note.timestamp || '--'} · ${note.author || 'unknown'}`));
        if (note.edited_at) {
            const editedTag = document.createElement('div');
            editedTag.className = 'text-subtle small';
            editedTag.style.cursor = 'pointer';
            editedTag.textContent = `(edited ${note.edited_at} - click to view prior version${(note.edit_history || []).length > 1 ? 's' : ''})`;
            editedTag.onclick = () => {
                const hist = card.querySelector('.note-edit-history');
                if (hist) hist.style.display = hist.style.display === 'none' ? 'block' : 'none';
            };
            left.appendChild(editedTag);
        }

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-xs btn-outline-info py-0 px-2 flex-shrink-0';
        editBtn.textContent = 'Edit';
        editBtn.onclick = () => { editingCaseNoteId = note.note_id; renderCaseNotesList(); };

        headerLine.appendChild(left);
        headerLine.appendChild(editBtn);
        card.appendChild(headerLine);

        if (editingCaseNoteId === note.note_id) {
            const textarea = document.createElement('textarea');
            textarea.className = 'form-control form-control-sm mb-1';
            textarea.rows = 3;
            textarea.value = note.text || '';
            card.appendChild(textarea);

            const btnRow = document.createElement('div');
            const saveBtn = document.createElement('button');
            saveBtn.className = 'btn btn-xs btn-success py-0 px-2 me-1';
            saveBtn.textContent = 'Save Edit';
            saveBtn.onclick = () => saveCaseNoteEdit(note.note_id, textarea.value);
            const cancelBtn = document.createElement('button');
            cancelBtn.className = 'btn btn-xs btn-outline-secondary py-0 px-2';
            cancelBtn.textContent = 'Cancel';
            cancelBtn.onclick = () => { editingCaseNoteId = null; renderCaseNotesList(); };
            btnRow.appendChild(saveBtn);
            btnRow.appendChild(cancelBtn);
            card.appendChild(btnRow);
        } else {
            const textEl = document.createElement('div');
            textEl.className = 'small mb-1';
            textEl.style.whiteSpace = 'pre-wrap';
            textEl.textContent = note.text || ''; // untrusted, text node only
            card.appendChild(textEl);
        }

        const linkedFiles = (note.linked_files || []).filter(p => currentAttachedFilesList.includes(p));
        if (linkedFiles.length) {
            const linkLine = document.createElement('div');
            linkLine.className = 'small mt-1 d-flex flex-wrap gap-1';
            linkedFiles.forEach(fp => {
                const chip = document.createElement('span');
                chip.className = 'badge bg-info text-dark';
                chip.textContent = `Linked: Exhibit ${currentAttachedFilesList.indexOf(fp) + 1} - ${fp.split('/').pop()}`; // untrusted (filename) - text node only
                linkLine.appendChild(chip);
            });
            card.appendChild(linkLine);
        }

        (note.attachments || []).forEach(att => {
            if (att.kind === 'image') {
                const img = document.createElement('img');
                img.src = `/api/files/raw?path=${encodeURIComponent(att.path)}`;
                img.style.maxWidth = '160px';
                img.style.maxHeight = '160px';
                img.className = 'border border-secondary rounded-2 me-2 mb-1';
                img.alt = att.filename || '';
                card.appendChild(img);
            } else {
                const fileLine = document.createElement('div');
                fileLine.className = 'text-subtle small';
                fileLine.innerHTML = '<i class="bi bi-file-earmark me-1"></i>'; // static/trusted markup
                fileLine.appendChild(document.createTextNode(`${att.filename || ''} (${((att.size_bytes || 0) / 1024).toFixed(1)} KB)`)); // untrusted, text node only
                card.appendChild(fileLine);
            }
        });

        if (note.edit_history && note.edit_history.length > 0) {
            const histDiv = document.createElement('div');
            histDiv.className = 'note-edit-history text-subtle small mt-1 ps-2 border-start border-secondary';
            histDiv.style.display = 'none';
            note.edit_history.forEach((h, i) => {
                const line = document.createElement('div');
                line.className = 'mb-1';
                line.style.whiteSpace = 'pre-wrap';
                line.textContent = `Version ${i + 1} (superseded ${h.edited_at || note.timestamp}): ${h.text}`; // untrusted, text node only
                histDiv.appendChild(line);
            });
            card.appendChild(histDiv);
        }

        container.appendChild(card);
    });
}

async function addCaseNote() {
    const reportPath = currentReportPath;
    const statusEl = document.getElementById("caseNoteAddStatus");
    if (!reportPath || !currentLoadedReportData) {
        if (statusEl) { statusEl.textContent = 'Select an active case first.'; statusEl.className = 'small mt-1 text-danger'; }
        return;
    }
    const text = document.getElementById("newCaseNoteText")?.value.trim() || "";
    if (!text) {
        if (statusEl) { statusEl.textContent = 'Note text cannot be empty.'; statusEl.className = 'small mt-1 text-danger'; }
        return;
    }
    const category = document.getElementById("newCaseNoteCategory")?.value || "General";
    const filesInput = document.getElementById("newCaseNoteFiles");
    const linkedFiles = Array.from(document.querySelectorAll('.new-case-note-link-cb:checked')).map(cb => cb.value);

    const formData = new FormData();
    formData.append('report_path', reportPath);
    formData.append('text', text);
    formData.append('category', category);
    formData.append('linked_files', JSON.stringify(linkedFiles));
    if (filesInput && filesInput.files) {
        Array.from(filesInput.files).forEach(f => formData.append('files', f));
    }

    if (statusEl) { statusEl.textContent = 'Adding...'; statusEl.className = 'small mt-1 text-info'; }
    try {
        const res = await fetch('/api/cases/notes/add', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
            document.getElementById("newCaseNoteText").value = '';
            if (filesInput) filesInput.value = '';
            if (statusEl) { statusEl.textContent = 'Note added.'; statusEl.className = 'small mt-1 text-success'; }
            await loadCaseForEditing();
        } else {
            if (statusEl) { statusEl.textContent = `Error: ${data.error}`; statusEl.className = 'small mt-1 text-danger'; }
        }
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Failed: ${err.message}`; statusEl.className = 'small mt-1 text-danger'; }
    }
}

// --- Physical Evidence Custody Log (distinct from Case Notes above and
// the software Audit Trail - a record of who physically had the evidence,
// append-only, no edit endpoint by design). ---
function renderCustodyLogList() {
    const container = document.getElementById("custodyLogContainer");
    if (!container) return;

    if (!currentLoadedReportData) {
        container.innerHTML = '<span class="text-subtle small italic">Load a case above, then open this tab to see and log custody transfers.</span>';
        return;
    }
    const entries = currentLoadedReportData.custody_log || [];
    if (entries.length === 0) {
        container.innerHTML = '<span class="text-subtle small italic">No custody log entries recorded yet - log the first transfer below.</span>';
        return;
    }

    container.innerHTML = '';
    const sorted = [...entries].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    sorted.forEach(entry => {
        const card = document.createElement('div');
        card.className = 'mb-2 pb-2 border-bottom border-secondary small';

        const headerLine = document.createElement('div');
        headerLine.className = 'fw-bold mb-1';
        headerLine.textContent = `${entry.timestamp || '--'} · ${entry.from_custodian || '?'} → ${entry.to_custodian || '?'}`; // untrusted, text node only
        card.appendChild(headerLine);

        const detailLine = document.createElement('div');
        detailLine.className = 'text-subtle';
        detailLine.textContent = `Reason: ${entry.reason || '(none given)'}   ·   Method: ${entry.method || '(none given)'}`; // untrusted, text node only
        card.appendChild(detailLine);

        if (entry.notes) {
            const notesLine = document.createElement('div');
            notesLine.className = 'text-subtle';
            notesLine.style.whiteSpace = 'pre-wrap';
            notesLine.textContent = `Notes: ${entry.notes}`; // untrusted, text node only
            card.appendChild(notesLine);
        }

        if (entry.logged_by) {
            const loggedLine = document.createElement('div');
            loggedLine.className = 'text-subtle';
            loggedLine.textContent = `Logged by: ${entry.logged_by}`; // untrusted, text node only
            card.appendChild(loggedLine);
        }

        container.appendChild(card);
    });
}

async function addCustodyEntry() {
    const reportPath = currentReportPath;
    const statusEl = document.getElementById("custodyAddStatus");
    if (!reportPath || !currentLoadedReportData) {
        if (statusEl) { statusEl.textContent = 'Select an active case first.'; statusEl.className = 'small mt-1 text-danger'; }
        return;
    }
    const fromCustodian = document.getElementById("newCustodyFrom")?.value.trim() || "";
    const toCustodian = document.getElementById("newCustodyTo")?.value.trim() || "";
    if (!fromCustodian || !toCustodian) {
        if (statusEl) { statusEl.textContent = 'Both From and To custodian are required.'; statusEl.className = 'small mt-1 text-danger'; }
        return;
    }
    const body = {
        report_path: reportPath,
        from_custodian: fromCustodian,
        to_custodian: toCustodian,
        reason: document.getElementById("newCustodyReason")?.value.trim() || "",
        method: document.getElementById("newCustodyMethod")?.value || "",
        notes: document.getElementById("newCustodyNotes")?.value.trim() || "",
    };

    if (statusEl) { statusEl.textContent = 'Logging...'; statusEl.className = 'small mt-1 text-info'; }
    try {
        const res = await fetch('/api/cases/custody/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById("newCustodyFrom").value = '';
            document.getElementById("newCustodyTo").value = '';
            document.getElementById("newCustodyReason").value = '';
            document.getElementById("newCustodyNotes").value = '';
            if (statusEl) { statusEl.textContent = 'Custody transfer logged.'; statusEl.className = 'small mt-1 text-success'; }
            await loadCaseForEditing();
        } else {
            if (statusEl) { statusEl.textContent = `Error: ${data.error}`; statusEl.className = 'small mt-1 text-danger'; }
        }
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Failed: ${err.message}`; statusEl.className = 'small mt-1 text-danger'; }
    }
}

async function saveCaseNoteEdit(noteId, newText) {
    const reportPath = currentReportPath;
    if (!reportPath || !newText || !newText.trim()) return;
    try {
        const res = await fetch('/api/cases/notes/edit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath, note_id: noteId, text: newText.trim() })
        });
        const data = await res.json();
        if (data.success) {
            editingCaseNoteId = null;
            await loadCaseForEditing();
        } else {
            showToast(`Edit failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast(`Edit failed: ${err.message}`, 'danger');
    }
}

// --- Chain of Custody Log ---
// Shared row-rendering for both the station-wide Audit Log (Settings) and
// the per-case History tab (Reporting) - same entry shape from either
// /api/coc/log or /api/coc/case_history, just a different filter server-side.
function renderCocEntries(container, entries) {
    container.innerHTML = '';
    if (entries.length === 0) {
        container.innerHTML = '<span class="text-subtle">No entries found.</span>';
        return;
    }

    entries.forEach(entry => {
        const row = document.createElement('div');
        row.className = 'mb-1 pb-1 border-bottom border-secondary';

        const line1 = document.createElement('div');
        const tsSpan = document.createElement('span');
        tsSpan.className = 'text-subtle';
        tsSpan.textContent = entry.timestamp + '  ';
        const actionSpan = document.createElement('span');
        actionSpan.className = 'text-info fw-bold';
        actionSpan.textContent = entry.action;
        line1.appendChild(tsSpan);
        line1.appendChild(actionSpan);
        if (entry.user) {
            const userSpan = document.createElement('span');
            userSpan.className = 'text-warning ms-2';
            userSpan.textContent = `[${entry.user}]`; // examiner-chosen username - text node only
            line1.appendChild(userSpan);
        }
        row.appendChild(line1);

        const detailsStr = Object.entries(entry.details || {}).map(([k, v]) => `${k}=${v}`).join(', ');
        if (detailsStr) {
            const line2 = document.createElement('div');
            line2.className = 'text-light text-break';
            line2.style.fontSize = '0.85em';
            line2.textContent = detailsStr; // untrusted (contains file paths etc.) - text node only
            row.appendChild(line2);
        }

        container.appendChild(row);
    });
}

// force=true (manual Refresh click, or the initial load) always renders.
// force=false (the auto-refresh timer) skips the render entirely if the
// examiner has scrolled down to read older entries - renderCocEntries does
// a full wipe-and-rebuild, not a diff, so re-rendering under them would
// yank their scroll position back to the top every 20 seconds.
async function loadChainOfCustodyLog(force = true) {
    const container = document.getElementById("cocLogContainer");
    if (!container) return;
    if (!force && container.scrollTop > 20) return;

    if (force) container.innerHTML = '<span class="text-subtle">Loading...</span>';

    try {
        const res = await fetch('/api/coc/log?limit=200');
        const data = await res.json();
        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }
        cocEntriesCache = data.entries;
        applyCocSearchFilter();
    } catch (err) {
        if (force) container.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

// Client-side only, against the already-fetched 200-entry cache - matches
// the on-screen view already being an intentionally capped window (full-log
// search stays CSV export's job, which reads the complete file separately
// and needs no changes here).
let cocEntriesCache = [];

function applyCocSearchFilter() {
    const container = document.getElementById("cocLogContainer");
    if (!container) return;
    const query = (document.getElementById("cocSearchInput")?.value || '').trim().toLowerCase();
    const filtered = !query ? cocEntriesCache : cocEntriesCache.filter(entry => {
        const haystack = `${entry.timestamp} ${entry.action} ${JSON.stringify(entry.details || {})} ${entry.user || ''}`.toLowerCase();
        return haystack.includes(query);
    });
    renderCocEntries(container, filtered);
}

let cocAutoRefreshTimer = null;

function startCocAutoRefresh() {
    if (cocAutoRefreshTimer) return;
    cocAutoRefreshTimer = setInterval(() => loadChainOfCustodyLog(false), 20000);
}

function stopCocAutoRefresh() {
    if (cocAutoRefreshTimer) {
        clearInterval(cocAutoRefreshTimer);
        cocAutoRefreshTimer = null;
    }
}

function exportAuditLogCsv() {
    // A plain navigation (not fetch) so the browser's own download handling
    // takes over - the response's Content-Disposition: attachment header
    // means this never actually navigates away from the app.
    window.location.href = '/api/coc/export_csv';
}

// Case-scoped view of the same log, for Reporting's Audit Trail tab -
// distinct from the station-wide Audit Log in Settings. Uses whichever
// case is currently loaded (isConsolidated/legacyMeta split, same pattern
// used throughout this file for currentLoadedReportData).
//
// caseHistoryEntriesCache holds the same entries this function just
// rendered - runCaseSearch() (below) reads it directly rather than
// re-fetching, the same "search the already-fetched cache" pattern
// cocEntriesCache already established for the Settings Audit Log.
let caseHistoryEntriesCache = [];

async function loadCaseHistory() {
    const container = document.getElementById("caseHistoryContainer");
    if (!container) return;

    const isConsolidated = Array.isArray(currentLoadedReportData?.events);
    const caseNum = (isConsolidated ? currentLoadedReportData?.case_number : currentLoadedReportData?.case_metadata?.case_number) || '';
    if (!caseNum) {
        container.innerHTML = '<span class="text-subtle">Select an active case first - History needs a case number to filter by.</span>';
        return;
    }

    container.innerHTML = '<span class="text-subtle">Loading...</span>';
    try {
        const res = await fetch(`/api/coc/case_history?case_number=${encodeURIComponent(caseNum)}&limit=200`);
        const data = await res.json();
        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }
        caseHistoryEntriesCache = data.entries;
        renderCocEntries(container, data.entries);
    } catch (err) {
        container.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

// --- Case Search: keyword search across Report Narrative, Jobs, Case
// Notes, and Audit Trail for the currently loaded case, all client-side
// against data already in memory - no dedicated backend endpoint needed,
// same reasoning as the Settings Audit Log's search box. ---
function caseSearchSnippet(text, query) {
    if (!text) return '';
    const idx = text.toLowerCase().indexOf(query);
    if (idx === -1) return text.length > 120 ? text.slice(0, 120) + '...' : text;
    const start = Math.max(0, idx - 40);
    const end = Math.min(text.length, idx + query.length + 60);
    return (start > 0 ? '...' : '') + text.slice(start, end) + (end < text.length ? '...' : '');
}

function appendCaseSearchGroup(container, title, jumpToTabId, items) {
    const groupHeader = document.createElement('div');
    groupHeader.className = 'text-info fw-bold small text-uppercase mt-2 mb-1';
    groupHeader.textContent = `${title} (${items.length})`;
    container.appendChild(groupHeader);

    items.forEach(item => {
        const row = document.createElement('div');
        row.className = 'mb-1 pb-1 border-bottom border-secondary';
        row.style.cursor = 'pointer';
        row.title = `Jump to ${title}`;
        row.onclick = () => {
            const tabBtn = document.getElementById(jumpToTabId);
            if (tabBtn) new bootstrap.Tab(tabBtn).show();
        };

        const labelEl = document.createElement('div');
        labelEl.className = 'text-warning';
        labelEl.textContent = item.label; // case-derived text, text node only
        row.appendChild(labelEl);

        if (item.snippet) {
            const snippetEl = document.createElement('div');
            snippetEl.className = 'text-light text-break';
            snippetEl.style.fontSize = '0.85em';
            snippetEl.textContent = item.snippet;
            row.appendChild(snippetEl);
        }

        container.appendChild(row);
    });
}

function runCaseSearch() {
    const container = document.getElementById("repSearchResults");
    if (!container) return;

    const query = (document.getElementById("repSearchInput")?.value || '').trim().toLowerCase();
    if (!query) {
        container.innerHTML = '<span class="text-subtle">Type a keyword above to search.</span>';
        return;
    }
    if (!currentLoadedReportData) {
        container.innerHTML = '<span class="text-subtle">Select or create a case using the bar above first.</span>';
        return;
    }

    container.innerHTML = '';
    let totalMatches = 0;

    // Report Narrative - searches the live form fields (so it also finds
    // unsaved edits), the same ids loadCaseForEditing() already populates
    // for both consolidated and legacy schemas, rather than re-deriving
    // that split here too. Custom Case Details fields render at the top of
    // this same pane (see the Reporting layout reorg), so they're searched
    // and grouped alongside the narrative fields rather than as a separate
    // source - a match in either one jumps to the one pane that has both.
    const narrativeFields = [
        ['Executive Summary', 'editExecSummary'],
        ['Objectives', 'editObjectives'],
        ['Relevant Findings', 'editFindingsSummary'],
        ['Limitations', 'editLimitations'],
        ['Conclusion', 'editConclusion'],
        ['Indicators of Compromise', 'editIocs'],
        ['Recommendations / Next Steps', 'editRecommendations'],
    ];
    const customFieldMatches = Array.from(document.querySelectorAll('#customFieldsContainer .custom-field-input'))
        .map(input => ({
            label: `Case Details: ${input.closest('.col-md-6')?.querySelector('label')?.textContent || input.dataset.fieldKey}`,
            value: input.value || '',
        }))
        .filter(f => f.value.toLowerCase().includes(query));
    const narrativeMatches = narrativeFields
        .map(([label, id]) => ({ label, value: document.getElementById(id)?.value || '' }))
        .filter(f => f.value.toLowerCase().includes(query))
        .concat(customFieldMatches);
    if (narrativeMatches.length > 0) {
        totalMatches += narrativeMatches.length;
        appendCaseSearchGroup(container, 'Report Narrative', 'repNarrativeTab', narrativeMatches.map(f => (
            { label: f.label, snippet: caseSearchSnippet(f.value, query) }
        )));
    }

    // Files - explicit attachments (files/reference URLs) currently saved
    // on the case. Matches on filename or URL text; jumps to the Files tab.
    const attach = currentLoadedReportData.attachments || {};
    const fileMatches = (attach.files || []).filter(p => p.toLowerCase().includes(query));
    const urlMatches = (attach.reference_urls || []).filter(u => u.toLowerCase().includes(query));
    if (fileMatches.length > 0 || urlMatches.length > 0) {
        totalMatches += fileMatches.length + urlMatches.length;
        appendCaseSearchGroup(container, 'Files & Artifacts', 'repFilesTab', [
            ...fileMatches.map(p => ({ label: p.split('/').pop(), snippet: null })),
            ...urlMatches.map(u => ({ label: u, snippet: null })),
        ]);
    }

    // Jobs - substring match against the same JSON dump each job's own
    // expandable detail view already shows.
    const events = Array.isArray(currentLoadedReportData.events) ? currentLoadedReportData.events : [];
    const jobMatches = events.filter(ev => JSON.stringify(ev).toLowerCase().includes(query));
    if (jobMatches.length > 0) {
        totalMatches += jobMatches.length;
        appendCaseSearchGroup(container, 'Jobs', 'repJobsTab', jobMatches.map(ev => {
            const meta = ev.case_metadata || {};
            return { label: `${(ev.tool || '--').toUpperCase()} · ${meta.evidence_id || '--'} · ${ev.timestamp_start || '--'}`, snippet: null };
        }));
    }

    // Case Notes
    const notes = currentLoadedReportData.case_notes || [];
    const noteMatches = notes.filter(n => `${n.text || ''} ${n.category || ''} ${n.author || ''}`.toLowerCase().includes(query));
    if (noteMatches.length > 0) {
        totalMatches += noteMatches.length;
        appendCaseSearchGroup(container, 'Case Notes', 'repCaseNotesTab', noteMatches.map(n => (
            { label: `${n.category || 'General'} · ${n.timestamp || '--'} · ${n.author || 'unknown'}`, snippet: caseSearchSnippet(n.text || '', query) }
        )));
    }

    // Audit Trail - against caseHistoryEntriesCache (populated by
    // loadCaseHistory(), which loadCaseForEditing() already calls
    // unconditionally on case load), not a fresh fetch.
    const historyMatches = (caseHistoryEntriesCache || []).filter(entry => {
        const haystack = `${entry.timestamp} ${entry.action} ${JSON.stringify(entry.details || {})} ${entry.user || ''}`.toLowerCase();
        return haystack.includes(query);
    });
    if (historyMatches.length > 0) {
        totalMatches += historyMatches.length;
        appendCaseSearchGroup(container, 'Audit Trail', 'repHistoryTab', historyMatches.map(entry => (
            { label: `${entry.timestamp || '--'} · ${entry.action || '--'}${entry.user ? ' · ' + entry.user : ''}`, snippet: null }
        )));
    }

    if (totalMatches === 0) {
        container.innerHTML = '<span class="text-subtle">No matches found.</span>';
    }
}

async function saveReportMetadata() {
    const reportPath = currentReportPath;

    if (!reportPath || !currentLoadedReportData) {
        showToast("Select or create a case using the bar above first.", 'warning');
        return;
    }

    const customFieldValues = gatherCustomFieldValues();

    const narrativeFields = {
        case_status: document.getElementById("editCaseStatus")?.value || "Open",
        executive_summary: document.getElementById("editExecSummary")?.value || "",
        objectives: document.getElementById("editObjectives")?.value || "",
        findings_summary: document.getElementById("editFindingsSummary")?.value || "",
        limitations: document.getElementById("editLimitations")?.value || "",
        conclusion: document.getElementById("editConclusion")?.value || "",
        iocs: document.getElementById("editIocs")?.value || "",
        recommendations_next_steps: document.getElementById("editRecommendations")?.value || "",
    };

    if (Array.isArray(currentLoadedReportData.events)) {
        // Consolidated case file - narrative fields (now including
        // case_status, genuinely editable over a case's life unlike the
        // other three) are top-level; case_number/examiner/notes stay
        // untouched (notes is set once at case creation, the other two
        // come read-only from the Active Case Bar), same as events[] and
        // case_notes[] already are.
        currentLoadedReportData.custom_fields = customFieldValues;
        Object.assign(currentLoadedReportData, narrativeFields);
    } else {
        // Legacy single-job report - preserve case_number/examiner/notes/
        // evidence_id (no longer editable here, but still part of this
        // report's own data).
        currentLoadedReportData.case_metadata = {
            ...(currentLoadedReportData.case_metadata || {}),
            custom_fields: customFieldValues,
            ...narrativeFields
        };
    }

    currentLoadedReportData.attachments = {
        files: currentAttachedFilesList,
        reference_urls: currentReferenceUrlsList,
        file_captions: currentAttachmentCaptions
    };

    try {
        const res = await fetch('/api/report/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath, report_data: currentLoadedReportData })
        });
        const data = await res.json();

        if (data.success) {
            const previewEl = document.getElementById("jsonPreview");
            if (previewEl) {
                previewEl.innerText = JSON.stringify(currentLoadedReportData, null, 2);
            }
            showToast("Report JSON saved successfully!", 'success');
        } else {
            showToast(`Save Error: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast(`Save failed: ${err.message}`, 'danger');
    }
}

// --- Export pane (inline, part of Reporting's left-nav/right-pane) ---
// Deliberately a separate action from "Save Report Changes" - Export always
// reads whatever is currently on disk at currentReportPath (same as the old
// exportEditedPdf did after its own auto-save), so unsaved edits in the
// form are not silently included. If the examiner wants their edits in the
// exported file, Save Report Changes first, same as before. Called via the
// Export nav button's onclick, mirroring the Jobs/Audit Trail pattern.
// Per-fixed-template hint text for the Export pane's template selector -
// see DEF_FIXED_TEMPLATE_HINTS' comment (the Settings-side counterpart) for
// why this isn't one generic string.
const EXPORT_FIXED_TEMPLATE_HINTS = {
    dfir: "This template has a fixed structure and always includes every section - the checkboxes below don't apply. It reuses this case's existing data under the reference template's section labels; see the Report Narrative tab for the Indicators of Compromise / Recommendations fields it draws on.",
    police: "This template has a fixed structure and always includes every section - the checkboxes below don't apply. It reuses this case's existing data under the reference template's section labels.",
    caseuco: "This template has a fixed structure aligned with the CASE/UCO forensic ontology and always includes every section, including Geolocation/GPS evidence. Add Custom Case Fields below for Authorization Identifier/Type, Investigation Status, or Investigation Form if your station wants those captured.",
};

function onExportTemplateChange() {
    const sel = document.getElementById("exportTemplateSelect");
    const hint = document.getElementById("exportTemplateHint");
    const group = document.getElementById("exportSectionsFieldsGroup");
    const editBtn = document.getElementById("exportEditTemplateBtn");
    if (!sel) return;
    const value = sel.value;
    const isStandard = value === 'standard';
    if (group) group.style.display = isStandard ? '' : 'none';

    if (isStandard) {
        if (hint) hint.style.display = 'none';
        if (editBtn) editBtn.style.display = 'none';
        currentExportCustomTemplateId = null;
        return;
    }
    if (hint) hint.style.display = 'block';
    if (value.startsWith('custom:')) {
        currentExportCustomTemplateId = value.slice('custom:'.length);
        const record = customReportTemplatesCache.find(t => t.id === currentExportCustomTemplateId);
        if (hint) hint.textContent = `This is a custom template - it always includes exactly the sections it was built with, in that order. ${record ? `"${record.name}"` : 'Edit it'} via the button below.`;
        if (editBtn) editBtn.style.display = 'inline-block';
    } else {
        currentExportCustomTemplateId = null;
        if (hint) hint.textContent = EXPORT_FIXED_TEMPLATE_HINTS[value] || EXPORT_FIXED_TEMPLATE_HINTS.dfir;
        if (editBtn) editBtn.style.display = 'none';
    }
}

// Raw JSON is just the case file as-is - no template/sections/job_fields/
// evidence-item filtering applies to it (those are all PDF/HTML rendering
// concerns), so selecting it hides that whole side of the pane and shows
// the same live JSON preview that used to live in its own "Raw JSON" tab.
function onExportFormatChange() {
    const sel = document.getElementById("exportFormatSelect");
    const templateGroup = document.getElementById("exportTemplateGroup");
    const optionsRow = document.getElementById("exportPdfHtmlOptionsRow");
    const jsonGroup = document.getElementById("exportJsonPreviewGroup");
    const previewGroup = document.getElementById("exportPreviewGroup");
    if (!sel) return;
    const isJson = sel.value === 'json';
    // CSV never touches /api/export_report either (same client-side-only
    // reasoning as JSON - see runExportReport()), so it shares JSON's
    // template/sections-hiding treatment, just without a live preview pane.
    const isRawFormat = isJson || sel.value === 'csv';

    if (templateGroup) templateGroup.style.display = isRawFormat ? 'none' : '';
    if (optionsRow) optionsRow.style.display = isRawFormat ? 'none' : '';
    if (jsonGroup) jsonGroup.style.display = isJson ? 'block' : 'none';
    // The Refresh Preview button only ever renders PDF/HTML - json/csv have
    // their own live/on-download previews instead. Switching format always
    // clears any prior preview rather than leaving a stale PDF/HTML render
    // up that no longer matches the newly-selected format - Preview is
    // explicit-refresh-only, but a leftover render from a different format
    // would be actively misleading, not just stale.
    if (previewGroup) previewGroup.style.display = isRawFormat ? 'none' : '';
    resetExportPreview();

    if (isJson) {
        const previewEl = document.getElementById("jsonPreview");
        if (previewEl && currentLoadedReportData) {
            previewEl.innerText = JSON.stringify(currentLoadedReportData, null, 2);
        }
    } else if (!isRawFormat) {
        // Restore whatever the Sections/Fields group's own visibility
        // should be for the currently-selected template (standard vs.
        // fixed-structure vs. custom) - format and template toggle
        // overlapping UI, so switching back to pdf/html needs to re-run
        // the template-driven logic, not just blindly show everything.
        onExportTemplateChange();
    }
}

async function prepareExportPane() {
    const reportPath = currentReportPath;
    if (!reportPath || !currentLoadedReportData) {
        return; // Reporting's own no-case empty state already covers this
    }

    // Always start from a clean preview on entering this pane - regardless
    // of whether the settings-defaults fetch below succeeds, a stale
    // render from a previous visit/case should never linger.
    resetExportPreview();

    // Same ordering requirement as loadCaseReportingSettings() - custom
    // template options must exist before the select's value is set below.
    await fetchCustomReportTemplates();

    // Pre-set the section/field checkboxes from the station's configured
    // defaults (Settings > Case & Reporting) before showing - still fully
    // adjustable per-export from here, this only changes what starts checked.
    try {
        const res = await fetch('/api/settings/case_reporting');
        const data = await res.json();
        if (data.success) {
            const templateSel = document.getElementById("exportTemplateSelect");
            if (templateSel) templateSel.value = data.report_defaults?.template || 'standard';
            onExportTemplateChange();
            onExportFormatChange();

            const sections = data.report_defaults?.sections || {};
            const jobFields = data.report_defaults?.job_fields || {};
            const setIfKnown = (id, obj, key) => {
                if (Object.prototype.hasOwnProperty.call(obj, key)) {
                    const el = document.getElementById(id);
                    if (el) el.checked = !!obj[key];
                }
            };
            setIfKnown('expSecCaseInfo', sections, 'case_info');
            setIfKnown('expSecExecSummary', sections, 'executive_summary');
            setIfKnown('expSecEvidenceInventory', sections, 'evidence_inventory');
            setIfKnown('expSecForensicAnalysis', sections, 'forensic_analysis');
            setIfKnown('expSecFindings', sections, 'relevant_findings');
            setIfKnown('expSecLimitations', sections, 'limitations');
            setIfKnown('expSecConclusion', sections, 'conclusion');
            setIfKnown('expSecAttachments', sections, 'attachments');
            setIfKnown('expSecGeolocation', sections, 'geolocation');
            setIfKnown('expSecAuditTrail', sections, 'audit_trail');
            setIfKnown('expFieldTelemetry', jobFields, 'telemetry');
            setIfKnown('expFieldParams', jobFields, 'params');
            setIfKnown('expFieldHashes', jobFields, 'hashes');
        }
    } catch (err) { /* non-fatal - modal just keeps its current checkbox state */ }

    renderExportItemsList();
    renderExportFilesList();

    const statusEl = document.getElementById("exportReportStatus");
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small text-subtle'; }
}

function renderExportItemsList() {
    const listEl = document.getElementById("exportItemsList");
    if (!listEl) return;
    listEl.innerHTML = '';

    const events = Array.isArray(currentLoadedReportData?.events) ? currentLoadedReportData.events : null;

    if (!events) {
        listEl.innerHTML = '<div class="text-subtle small p-2">Single-job legacy report - always fully included, nothing to pick.</div>';
        return;
    }
    if (events.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No jobs recorded against this case yet.</div>';
        return;
    }

    [...events].sort((a, b) => (b.timestamp_start || '').localeCompare(a.timestamp_start || '')).forEach(ev => {
        const meta = ev.case_metadata || {};
        const row = document.createElement('label');
        row.className = 'list-group-item list-group-item-action bg-dark text-light border-secondary py-2 d-flex align-items-start gap-2';

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'form-check-input export-item-check mt-1';
        cb.checked = true;
        cb.dataset.eventId = ev.event_id || '';

        const textWrap = document.createElement('div');
        const line1 = document.createElement('div');
        line1.className = 'small';
        line1.appendChild(document.createTextNode(`${(ev.tool || '--').toUpperCase()}  ${meta.evidence_id || '--'}`)); // untrusted evidence data - text node only
        const line2 = document.createElement('div');
        line2.className = 'text-subtle small';
        line2.textContent = `${ev.timestamp_start || '--'} · ${ev.acquisition_status || '--'}`;
        textWrap.appendChild(line1);
        textWrap.appendChild(line2);

        row.appendChild(cb);
        row.appendChild(textWrap);
        listEl.appendChild(row);
    });
}

// Combines this case's explicit attachments (files added via "Add File
// Attachment" and reference URLs, both from currentLoadedReportData) with
// anything else physically sitting in the case folder that /api/cases/
// discover_files finds (e.g. dropped in via File Explorer's Copy-to
// action, or left behind by a recovery/analysis tool) - the latter start
// unchecked since they weren't deliberately attached, unlike the former.
async function renderExportFilesList() {
    const listEl = document.getElementById("exportFilesList");
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading...</div>';

    const attach = currentLoadedReportData?.attachments || {};
    const urls = attach.reference_urls || [];
    let explicitFiles = attach.files || [];
    if (!explicitFiles.length && attach.image_path) explicitFiles = [attach.image_path];

    const caseFolder = activeCase ? activeCase.case_folder : "";

    let discovered = [];
    let truncated = false;
    if (caseFolder) {
        try {
            const res = await fetch(`/api/cases/discover_files?case_folder=${encodeURIComponent(caseFolder)}`);
            const data = await res.json();
            if (data.success) {
                discovered = data.files || [];
                truncated = !!data.truncated;
            }
        } catch (err) {}
    }

    const explicitSet = new Set(explicitFiles);
    const extraFiles = discovered.filter(f => !explicitSet.has(f.path));

    listEl.innerHTML = '';

    if (urls.length === 0 && explicitFiles.length === 0 && extraFiles.length === 0) {
        listEl.innerHTML = '<div class="text-subtle small p-2">No attached files, notes, or reference URLs found for this case.</div>';
        return;
    }

    const addRow = (label, sublabel, kind, value, checked) => {
        const row = document.createElement('label');
        row.className = 'list-group-item list-group-item-action bg-dark text-light border-secondary py-2 d-flex align-items-start gap-2';

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'form-check-input export-attach-check mt-1';
        cb.checked = checked;
        cb.dataset.kind = kind;
        cb.dataset.value = value;

        if (kind === 'file' && isPhotoImagePath(value)) {
            const thumb = document.createElement('img');
            thumb.src = `/api/files/raw?path=${encodeURIComponent(value)}`;
            thumb.className = 'rounded border border-secondary flex-shrink-0';
            thumb.style.cssText = 'width:36px;height:36px;object-fit:cover;';
            thumb.alt = '';
            row.appendChild(cb);
            row.appendChild(thumb);
        } else {
            row.appendChild(cb);
        }

        const textWrap = document.createElement('div');
        const line1 = document.createElement('div');
        line1.className = 'small text-break';
        line1.textContent = label; // untrusted (url/filename) - text node only
        textWrap.appendChild(line1);
        if (sublabel) {
            const line2 = document.createElement('div');
            line2.className = 'text-subtle small';
            line2.textContent = sublabel;
            textWrap.appendChild(line2);
        }

        row.appendChild(textWrap);
        listEl.appendChild(row);
    };

    urls.forEach(u => addRow(u, 'Reference URL', 'url', u, true));
    explicitFiles.forEach(fp => addRow(fp.split('/').pop(), `Attached · ${fp}`, 'file', fp, true));
    extraFiles.forEach(f => {
        const kindLabel = f.kind === 'image' ? 'Image' : f.kind === 'text' ? 'Text' : 'File';
        const sizeKb = f.size_bytes ? ` · ${(f.size_bytes / 1024).toFixed(1)} KB` : '';
        addRow(f.name, `Found in case folder · ${kindLabel}${sizeKb}`, 'file', f.path, false);
    });

    if (truncated) {
        const note = document.createElement('div');
        note.className = 'text-subtle small p-2';
        note.textContent = 'Showing the first 200 discovered files - some case-folder files were not listed.';
        listEl.appendChild(note);
    }
}

function setExportCheckboxes(checked) {
    document.querySelectorAll('.export-section-check, .export-field-check').forEach(cb => { cb.checked = checked; });
}

function setExportItemCheckboxes(checked) {
    document.querySelectorAll('.export-item-check').forEach(cb => { cb.checked = checked; });
}

function setExportFileCheckboxes(checked) {
    document.querySelectorAll('.export-attach-check').forEach(cb => { cb.checked = checked; });
}

async function runExportReport() {
    const reportPath = currentReportPath;
    if (!reportPath) return showToast("Select an active case first.", 'warning');

    const format = document.getElementById("exportFormatSelect")?.value || 'pdf';

    // Raw JSON never touches /api/export_report - it's just the case file
    // already loaded client-side (the same data jsonPreview already shows),
    // downloaded directly as a Blob. No template/sections/job_fields
    // filtering applies to a raw dump.
    if (format === 'json') {
        const statusEl = document.getElementById("exportReportStatus");
        if (!currentLoadedReportData) {
            if (statusEl) { statusEl.textContent = 'No case data loaded.'; statusEl.className = 'small text-danger'; }
            return;
        }
        const blob = new Blob([JSON.stringify(currentLoadedReportData, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = reportPath.split('/').pop();
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        if (statusEl) { statusEl.textContent = 'Export complete.'; statusEl.className = 'small text-success'; }
        return;
    }

    // Evidence Inventory CSV, same client-side-only reasoning as Raw JSON -
    // the data's already loaded, no reason to round-trip through the backend
    // just to reformat it. Mirrors export_report()'s own dual-schema handling:
    // a consolidated case exposes .events; a legacy single-job report has no
    // such array and is treated as its own single event.
    if (format === 'csv') {
        const statusEl = document.getElementById("exportReportStatus");
        if (!currentLoadedReportData) {
            if (statusEl) { statusEl.textContent = 'No case data loaded.'; statusEl.className = 'small text-danger'; }
            return;
        }
        const data = currentLoadedReportData;
        const events = Array.isArray(data.events) ? data.events : [data];
        const csvCell = (val) => {
            const s = (val === null || val === undefined) ? '' : String(val);
            return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const header = ['Evidence ID', 'Device Path', 'Model', 'Serial Number', 'Capacity (GB)',
                         'Tool', 'Status', 'Timestamp Start', 'MD5', 'SHA1', 'SHA256'];
        const rows = [header];
        events.forEach(event => {
            const meta = event.case_metadata || {};
            const drive = event.source_drive_telemetry || {};
            const hashes = event.computed_verification_hashes || {};
            rows.push([
                meta.evidence_id ?? 'N/A', drive.device_path ?? 'N/A', drive.vendor_model ?? 'N/A',
                drive.serial_number ?? 'N/A', drive.capacity_gb ?? 'N/A', event.tool ?? 'N/A',
                event.acquisition_status ?? 'N/A', event.timestamp_start ?? 'N/A',
                hashes.md5 ?? '', hashes.sha1 ?? '', hashes.sha256 ?? ''
            ]);
        });
        const csvText = rows.map(r => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
        const blob = new Blob([csvText], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = reportPath.split('/').pop().replace('.json', '_evidence_inventory.csv');
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        if (statusEl) { statusEl.textContent = 'Export complete.'; statusEl.className = 'small text-success'; }
        return;
    }

    const body = gatherExportRequestBody();
    if (!body) return;

    const statusEl = document.getElementById("exportReportStatus");
    if (statusEl) { statusEl.textContent = 'Generating...'; statusEl.className = 'small text-info'; }

    try {
        const res = await fetch('/api/export_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath, ...body })
        });

        if (res.ok) {
            const reportHash = res.headers.get('X-Report-Sha256');
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const ext = format === 'html' ? '.html' : '.pdf';
            a.download = reportPath.split('/').pop().replace('.json', ext);
            document.body.appendChild(a);
            a.click();
            a.remove();
            if (statusEl) {
                statusEl.textContent = reportHash ? `Export complete. SHA256: ${reportHash}` : 'Export complete.';
                statusEl.className = 'small text-success';
            }
        } else {
            const data = await res.json();
            if (statusEl) { statusEl.textContent = `Export failed: ${data.error}`; statusEl.className = 'small text-danger'; }
        }
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Export failed: ${err.message}`; statusEl.className = 'small text-danger'; }
    }
}

// Gathers the exact {format, template, sections, job_fields, event_ids,
// attachment_selection} request body from the Export pane's current
// checkbox/select state - factored out of runExportReport() so the real
// Export action and the Preview action (see refreshExportPreview() below)
// can never send different data for the same visible checkbox state.
// Returns null (after showing a toast) if a required selection is missing
// (no evidence items checked) - both callers bail out the same way.
function gatherExportRequestBody() {
    const format = document.getElementById("exportFormatSelect")?.value || 'pdf';
    const template = document.getElementById("exportTemplateSelect")?.value || 'standard';

    // sections/job_fields only ever apply to the 'standard' template - the
    // checkboxes are only hidden (via CSS), not cleared or disabled, when a
    // different template is selected, so they'd otherwise still hold
    // whatever they were last checked to and silently leak into a
    // custom/DFIR/Police export. The backend also ignores these for
    // anything but 'standard' (defense in depth), but not sending them at
    // all here is the more honest signal of what this export actually uses.
    let sections = null;
    let job_fields = null;
    if (template === 'standard') {
        sections = {
            case_info: !!document.getElementById("expSecCaseInfo")?.checked,
            executive_summary: !!document.getElementById("expSecExecSummary")?.checked,
            evidence_inventory: !!document.getElementById("expSecEvidenceInventory")?.checked,
            forensic_analysis: !!document.getElementById("expSecForensicAnalysis")?.checked,
            relevant_findings: !!document.getElementById("expSecFindings")?.checked,
            limitations: !!document.getElementById("expSecLimitations")?.checked,
            conclusion: !!document.getElementById("expSecConclusion")?.checked,
            attachments: !!document.getElementById("expSecAttachments")?.checked,
            geolocation: !!document.getElementById("expSecGeolocation")?.checked,
            audit_trail: !!document.getElementById("expSecAuditTrail")?.checked,
        };
        job_fields = {
            telemetry: !!document.getElementById("expFieldTelemetry")?.checked,
            params: !!document.getElementById("expFieldParams")?.checked,
            hashes: !!document.getElementById("expFieldHashes")?.checked,
        };
    }

    const itemChecks = document.querySelectorAll('.export-item-check');
    let event_ids = null;
    if (itemChecks.length > 0) {
        event_ids = Array.from(itemChecks).filter(cb => cb.checked).map(cb => cb.dataset.eventId);
        if (event_ids.length === 0) {
            showToast("Select at least one evidence item to include.", 'warning');
            return null;
        }
    }

    const attachment_selection = { urls: [], files: [] };
    document.querySelectorAll('.export-attach-check:checked').forEach(cb => {
        (cb.dataset.kind === 'url' ? attachment_selection.urls : attachment_selection.files).push(cb.dataset.value);
    });

    return { format, template, sections, job_fields, event_ids, attachment_selection };
}

// Object URL for the currently-displayed PDF preview, if any - tracked so
// each refresh can revoke the previous one instead of leaking blob URLs.
let exportPreviewObjectUrl = null;

function resetExportPreview() {
    const iframe = document.getElementById("exportPreviewFrame");
    const statusEl = document.getElementById("exportPreviewStatus");
    if (exportPreviewObjectUrl) { URL.revokeObjectURL(exportPreviewObjectUrl); exportPreviewObjectUrl = null; }
    if (iframe) { iframe.removeAttribute('src'); iframe.srcdoc = ''; iframe.removeAttribute('sandbox'); }
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small text-subtle'; }
}

// Renders exactly what a real Export would currently produce into the
// preview iframe, without writing anything to disk - reuses
// gatherExportRequestBody() (the same state runExportReport() sends) plus
// preview:true, which /api/export_report treats as "build the document,
// return it inline, skip the disk write and the .sha256 sidecar" (see
// export_report() in app.py). Explicit-refresh only, per design - never
// called automatically on a checkbox/format/template change.
async function refreshExportPreview() {
    const reportPath = currentReportPath;
    const iframe = document.getElementById("exportPreviewFrame");
    const statusEl = document.getElementById("exportPreviewStatus");
    if (!reportPath || !iframe) return;

    const format = document.getElementById("exportFormatSelect")?.value || 'pdf';
    if (format !== 'pdf' && format !== 'html') return; // Refresh Preview is hidden for json/csv anyway

    const body = gatherExportRequestBody();
    if (!body) return;

    if (statusEl) { statusEl.textContent = 'Rendering preview...'; statusEl.className = 'small text-info'; }

    try {
        const res = await fetch('/api/export_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath, ...body, preview: true })
        });

        if (!res.ok) {
            const data = await res.json();
            if (statusEl) { statusEl.textContent = `Preview failed: ${data.error}`; statusEl.className = 'small text-danger'; }
            return;
        }

        if (exportPreviewObjectUrl) { URL.revokeObjectURL(exportPreviewObjectUrl); exportPreviewObjectUrl = null; }

        if (format === 'pdf') {
            // No sandbox at all for PDF - confirmed live that Chrome's native
            // PDF viewer refuses to render inside a sandboxed iframe
            // regardless of which tokens are set ("This page has been
            // blocked by Chrome"). Matches this app's own existing pattern
            // for previewing a real PDF file elsewhere (previewSelectedFile()
            // in File Explorer) - the native viewer has no script-execution
            // surface tied to this app's origin, so an unsandboxed iframe is
            // the correct, already-established choice here too.
            iframe.removeAttribute('sandbox');
            const blob = await res.blob();
            exportPreviewObjectUrl = URL.createObjectURL(blob);
            iframe.removeAttribute('srcdoc');
            iframe.src = exportPreviewObjectUrl;
        } else {
            // HTML previews may embed inline <script> (the Geolocation
            // section's Leaflet map) - allow-scripts only, deliberately
            // WITHOUT allow-same-origin, so the framed content runs in an
            // opaque unique origin: scripts execute (the map renders) but
            // can't read this app's cookies/session or reach the parent
            // page's DOM, unlike a real download of this same file (which
            // has no sandboxing at all once opened normally).
            iframe.setAttribute('sandbox', 'allow-scripts');
            const text = await res.text();
            iframe.removeAttribute('src');
            iframe.srcdoc = text;
        }
        if (statusEl) { statusEl.textContent = 'Preview updated.'; statusEl.className = 'small text-success'; }
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Preview failed: ${err.message}`; statusEl.className = 'small text-danger'; }
    }
}

// Context-menu shortcut: jump to File Recovery with this image pre-filled as
// the source, instead of making the examiner re-browse to the same path
// they just right-clicked in File Explorer. Defaults to PhotoRec (the most
// commonly reached-for recovery tool) - the tool selector is a normal field
// on the File Recovery tab if a different one is needed.
function recoverDeletedFilesFromImage() {
    if (!activeSelectedFile) return;
    const toolSelect = document.getElementById("recoveryToolSelect");
    if (toolSelect) toolSelect.value = 'photorec';
    updateRecoveryToolControls();
    const sourceEl = document.getElementById("recoverySourcePath");
    if (sourceEl) sourceEl.value = activeSelectedFile;
    switchToTab('ddrescue-tab');
}

// "Tag it where you find it" - bookmarks the right-clicked file as a case
// exhibit immediately (commits straight to the case JSON on disk, same as
// every other File Explorer action), rather than requiring a separate trip
// to Reporting > Files to browse back to the same path.
async function attachSelectedFileToCase() {
    if (!activeSelectedFile || !activeCase) return;

    try {
        const res = await fetch('/api/cases/attach_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, file_path: activeSelectedFile })
        });
        const data = await res.json();
        if (data.success) {
            if (data.already_attached) {
                showToast(`This file is already attached to ${activeCase.case_number}.`, 'success');
            } else {
                showToast(`Attached to ${activeCase.case_number} as a case exhibit (${data.file_count} file(s) now attached). Edit captions or reorder exhibits in Reporting > Files & Artifacts.`, 'success');
                if (currentReportPath) loadCaseForEditing();
            }
        } else {
            showToast(`Attach to case failed: ${data.error}`, 'danger');
        }
    } catch (err) {}
}

// --- Evidence Hash Verifier (context-menu action, scoped to the selected file) ---
// --- KML viewer modal (Reporting's Files gallery - File Explorer renders
// the same renderKmlViewer() inline in its own Preview pane instead) ---
let kmlViewerModalInstance = null;

async function openKmlViewerModal(filePath) {
    if (!kmlViewerModalInstance) {
        kmlViewerModalInstance = new bootstrap.Modal(document.getElementById('kmlViewerModal'));
    }
    const titleEl = document.getElementById('kmlViewerTitle');
    const container = document.getElementById('kmlViewerContainer');
    if (titleEl) titleEl.textContent = filePath.split('/').pop();
    if (container) container.innerHTML = '<span class="text-subtle small">Loading...</span>';
    kmlViewerModalInstance.show();

    try {
        const res = await fetch('/api/files/preview_text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: filePath })
        });
        const data = await res.json();
        if (!container) return;
        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger small';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }
        renderKmlViewer(container, data.content);
    } catch (err) {
        if (container) container.innerHTML = '<span class="text-danger small">Request failed.</span>';
    }
}

let verifyHashModalInstance = null;
let imageConversionModalInstance = null;

// --- Auto Analyze (Phase 3, 2026-08-25) ---
// Detects an evidence item's profile, then either starts a real sequenced
// background job (Windows/Linux disk images - /api/image/auto_analyze/start)
// or hands off to the already-existing single-tool flows for Memory/Mobile
// (openMemoryForensicsModal()/runSelectedMvtScan(), just pre-filled with a
// curated default) - see routes/auto_analyze.py's own module docstring for
// why Memory/Mobile don't get their own new orchestrated-job route.
let autoAnalyzeModalInstance = null;
// The path the modal is currently scoped to - deliberately NOT read from
// activeSelectedFile inside startAutoAnalyze() (see openAutoAnalyzeModal()'s
// explicitPath param below), so a Guided-Workflow-triggered run can never
// silently clobber or depend on whatever File Explorer's own selection
// state happens to be at the moment Start is clicked.
let autoAnalyzeTargetPath = null;
const AUTO_ANALYZE_STEP_LABELS = {
    hash_manifest: "Hash Manifest (SHA256)",
    registry: "Registry Hives (incl. Amcache)",
    evtx: "Event Logs",
    prefetch: "Prefetch Files",
    recyclebin: "Recycle Bin",
    browser_artifacts: "Browser Artifacts (Chrome/Firefox)",
    linux_artifacts: "Linux Artifacts (shell history/passwd/cron/auth log)",
    recover_deleted: "Recover Deleted Files (Filesystem-Aware)",
};
const AUTO_ANALYZE_WINDOWS_DEFAULTS = ["hash_manifest", "registry", "evtx", "prefetch", "recyclebin", "browser_artifacts"];
const AUTO_ANALYZE_LINUX_DEFAULTS = ["hash_manifest", "linux_artifacts"];
const AUTO_ANALYZE_EXTRA_STEPS = ["recover_deleted"];
const AUTO_ANALYZE_MEMORY_DEFAULT_PLUGINS = ["info", "pslist", "pstree", "cmdline", "netscan", "malfind"];

function _resetAutoAnalyzeModal() {
    document.getElementById('autoAnalyzeDetecting').style.display = '';
    document.getElementById('autoAnalyzeDetectedInfo').style.display = 'none';
    document.getElementById('autoAnalyzeImageStepsGroup').style.display = 'none';
    document.getElementById('autoAnalyzeMemoryGroup').style.display = 'none';
    document.getElementById('autoAnalyzeMobileGroup').style.display = 'none';
    document.getElementById('autoAnalyzeStatus').textContent = '';
    document.getElementById('autoAnalyzeStartBtn').disabled = true;
    document.getElementById('autoAnalyzeProfileSelect').value = '';
}

// explicitPath: optional - lets a caller other than the File Explorer context
// menu (e.g. Guided Workflow's step 3, which resolves the active case's own
// acquired-evidence path itself) open this modal pre-scoped to a specific
// path without needing activeSelectedFile to already point at it. Defaults
// to activeSelectedFile, unchanged from before this param existed, so the
// one pre-existing File Explorer call site needs no changes.
async function openAutoAnalyzeModal(explicitPath) {
    const path = explicitPath || activeSelectedFile;
    if (!path) return;
    autoAnalyzeTargetPath = path;
    document.getElementById('autoAnalyzeFileName').textContent = path.split('/').pop();
    _resetAutoAnalyzeModal();

    if (!autoAnalyzeModalInstance) {
        autoAnalyzeModalInstance = new bootstrap.Modal(document.getElementById('autoAnalyzeModal'));
    }
    autoAnalyzeModalInstance.show();

    try {
        const res = await fetch('/api/auto_analyze/detect', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        document.getElementById('autoAnalyzeDetecting').style.display = 'none';
        if (!data.success) {
            document.getElementById('autoAnalyzeStatus').textContent = `Detection failed: ${data.error}`;
            return;
        }

        const select = document.getElementById('autoAnalyzeProfileSelect');
        let initialValue = '';
        let infoText = '';
        if (data.profile === 'ambiguous') {
            infoText = 'Could not determine whether this is a memory image or a disk image (no recognizable filesystem found inside it) - pick the correct profile below.';
        } else if (data.profile === 'unknown_mobile') {
            infoText = "This looks like a folder, but doesn't match a known case acquisition record or a recognizable backup structure - pick the correct profile below if you know what it is, or leave unselected.";
        } else if (data.profile === 'unknown') {
            infoText = 'Could not determine what this evidence item is - pick a profile manually if you know what it is.';
        } else if (data.profile === 'mixed') {
            const fsList = (data.filesystems || []).map(f => `${f.fs_type} (${f.bucket})`).join(', ');
            infoText = `Detected multiple filesystem types - a likely dual-boot image: ${fsList}. Pick which profile to run now; run Auto Analyze again for the other.`;
            initialValue = (data.filesystems || []).find(f => f.bucket === 'windows') ? 'windows' : 'linux';
        } else if (data.profile === 'windows' || data.profile === 'linux') {
            const fsList = (data.filesystems || []).map(f => f.fs_type).join(', ') || data.signal;
            infoText = `Detected: ${data.profile === 'windows' ? 'Windows' : 'Linux'} disk image (${fsList}).`;
            initialValue = data.profile;
        } else if (data.profile === 'memory') {
            infoText = 'Detected: memory image (by file extension).';
            initialValue = 'memory';
        } else if (data.profile === 'mobile_ios') {
            infoText = `Detected: iOS mobile backup (${data.signal === 'case_event' ? 'matches a case acquisition record' : 'real backup folder structure'}).`;
            initialValue = 'mobile_ios';
        } else if (data.profile === 'mobile_android') {
            infoText = 'Detected: Android mobile backup (matches a case acquisition record).';
            initialValue = 'mobile_android';
        }
        const infoEl = document.getElementById('autoAnalyzeDetectedInfo');
        infoEl.textContent = infoText;
        infoEl.style.display = infoText ? '' : 'none';
        select.value = initialValue;
        onAutoAnalyzeProfileChange();
    } catch (err) {
        document.getElementById('autoAnalyzeDetecting').style.display = 'none';
        document.getElementById('autoAnalyzeStatus').textContent = 'Detection request failed.';
    }
}

function onAutoAnalyzeProfileChange() {
    const profile = document.getElementById('autoAnalyzeProfileSelect').value;
    document.getElementById('autoAnalyzeImageStepsGroup').style.display = 'none';
    document.getElementById('autoAnalyzeMemoryGroup').style.display = 'none';
    document.getElementById('autoAnalyzeMobileGroup').style.display = 'none';
    document.getElementById('autoAnalyzeStartBtn').disabled = !profile;

    if (profile === 'windows' || profile === 'linux') {
        const defaults = profile === 'windows' ? AUTO_ANALYZE_WINDOWS_DEFAULTS : AUTO_ANALYZE_LINUX_DEFAULTS;
        const allSteps = [...defaults, ...AUTO_ANALYZE_EXTRA_STEPS];
        const list = document.getElementById('autoAnalyzeStepsList');
        list.innerHTML = '';
        allSteps.forEach(key => {
            const row = document.createElement('div');
            row.className = 'form-check';
            const cb = document.createElement('input');
            cb.className = 'form-check-input';
            cb.type = 'checkbox';
            cb.value = key;
            cb.id = `autoAnalyzeStep_${key}`;
            cb.checked = defaults.includes(key);
            const label = document.createElement('label');
            label.className = 'form-check-label small';
            label.htmlFor = cb.id;
            label.textContent = AUTO_ANALYZE_STEP_LABELS[key] || key;
            row.appendChild(cb);
            row.appendChild(label);
            list.appendChild(row);
        });
        document.getElementById('autoAnalyzeImageStepsGroup').style.display = '';
    } else if (profile === 'memory') {
        document.getElementById('autoAnalyzeMemoryGroup').style.display = '';
    } else if (profile === 'mobile_ios' || profile === 'mobile_android') {
        document.getElementById('autoAnalyzeMobileGroup').style.display = '';
    }
}

async function startAutoAnalyze() {
    const profile = document.getElementById('autoAnalyzeProfileSelect').value;
    if (!profile) return;
    const statusEl = document.getElementById('autoAnalyzeStatus');

    if (profile === 'memory') {
        if (autoAnalyzeModalInstance) autoAnalyzeModalInstance.hide();
        // openMemoryForensicsModal()/runSelectedMvtScan() below both read
        // activeSelectedFile directly, not a passed-in path - already implicitly
        // true for the File Explorer-triggered case (that's where autoAnalyzeTargetPath
        // itself came from), made explicit here so it also holds for a Guided
        // Workflow-triggered run, where activeSelectedFile was never touched.
        activeSelectedFile = autoAnalyzeTargetPath;
        openMemoryForensicsModal();
        document.querySelectorAll('#memForensicsPluginList input[type=checkbox]').forEach(cb => {
            cb.checked = AUTO_ANALYZE_MEMORY_DEFAULT_PLUGINS.includes(cb.value);
        });
        return;
    }
    if (profile === 'mobile_ios' || profile === 'mobile_android') {
        if (autoAnalyzeModalInstance) autoAnalyzeModalInstance.hide();
        activeSelectedFile = autoAnalyzeTargetPath; // see the memory branch's comment above
        runSelectedMvtScan(profile === 'mobile_ios' ? 'ios' : 'android');
        return;
    }

    // windows / linux - the one genuinely orchestrated multi-step job
    const steps = Array.from(document.querySelectorAll('#autoAnalyzeStepsList input[type=checkbox]:checked')).map(el => el.value);
    if (!steps.length) return showToast('Select at least one step to run.', 'warning');

    statusEl.textContent = 'Starting Auto Analyze job...';
    try {
        const res = await fetch('/api/image/auto_analyze/start', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: autoAnalyzeTargetPath, case_folder: activeCase ? activeCase.case_folder : null, steps })
        });
        const data = await res.json();
        if (!data.success) {
            statusEl.textContent = `Failed to start: ${data.error}`;
            showToast(`Auto Analyze failed to start: ${data.error}`, 'danger');
            return;
        }
        if (autoAnalyzeModalInstance) autoAnalyzeModalInstance.hide();
        showToast(data.message || 'Auto Analyze started.', 'success');
    } catch (err) {
        statusEl.textContent = 'Request failed.';
    }
}

function openVerifyHashModal() {
    if (!activeSelectedFile) return;
    document.getElementById("verifyHashFileName").textContent = activeSelectedFile.split('/').pop();
    const expectedEl = document.getElementById("verifyExpectedHash");
    if (expectedEl) expectedEl.value = '';
    const output = document.getElementById("computedHashOutput");
    if (output) output.textContent = '--';
    const badge = document.getElementById("hashMatchBadge");
    if (badge) { badge.className = 'badge bg-secondary'; badge.textContent = 'AWAITING INPUT'; }

    if (!verifyHashModalInstance) {
        verifyHashModalInstance = new bootstrap.Modal(document.getElementById('verifyHashModal'));
    }
    verifyHashModalInstance.show();
}

async function runStandaloneHashVerification() {
    const imagePath = activeSelectedFile;

    const algoEl = document.getElementById("verifyAlgorithmSelect");
    const algorithm = algoEl ? algoEl.value : "sha256";

    const expectedEl = document.getElementById("verifyExpectedHash");
    const expectedHash = expectedEl ? expectedEl.value.trim().toLowerCase() : "";

    const badge = document.getElementById("hashMatchBadge");
    const output = document.getElementById("computedHashOutput");

    if (!imagePath) return showToast("Select a file first.", 'warning');

    if (badge) {
        badge.className = "badge bg-info text-dark";
        badge.innerText = "CALCULATING HASH...";
    }
    if (output) output.innerText = "Computing verification hash across storage chunks...";

    try {
        const res = await fetch('/api/verify_hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: imagePath, algorithm: algorithm })
        });
        const data = await res.json();

        if (data.success) {
            const computed = data.hash.toLowerCase();
            if (output) output.innerText = computed;

            if (expectedHash) {
                if (computed === expectedHash) {
                    if (badge) {
                        badge.className = "badge bg-success fs-6";
                        badge.innerText = "MATCH / PASSED";
                    }
                } else {
                    if (badge) {
                        badge.className = "badge bg-danger fs-6";
                        badge.innerText = "MISMATCH / FAIL";
                    }
                }
            } else {
                if (badge) {
                    badge.className = "badge bg-primary fs-6";
                    badge.innerText = "COMPUTED";
                }
            }
        } else {
            if (badge) {
                badge.className = "badge bg-danger";
                badge.innerText = "ERROR";
            }
            if (output) output.innerText = `Error: ${data.error}`;
        }
    } catch (err) {
        if (badge) {
            badge.className = "badge bg-danger";
            badge.innerText = "FAILED";
        }
        if (output) output.innerText = `Request Failed: ${err.message}`;
    }
}

// Runs as a real background job (converting a multi-GB image is genuinely
// long-running), reusing the same shared #explorerJobProgress row/
// completion-toast mechanism already established for Triage Scan and
// Geolocation Export - see IMAGE_JOB_COMPLETION_MESSAGES and fetchProgress().
function openImageConversionModal() {
    if (!activeSelectedFile) return;
    const name = activeSelectedFile.split('/').pop();
    document.getElementById("convertImageFileName").textContent = name;
    // Default the target format to whichever direction actually makes sense
    // for this file - the backend independently validates this regardless,
    // but defaulting correctly avoids a near-certain first-try rejection.
    const targetSelect = document.getElementById("convertImageTargetFormat");
    if (targetSelect) targetSelect.value = name.toLowerCase().endsWith('.e01') ? 'raw' : 'e01';
    const status = document.getElementById("convertImageStatus");
    if (status) status.textContent = '';

    if (!imageConversionModalInstance) {
        imageConversionModalInstance = new bootstrap.Modal(document.getElementById('imageConversionModal'));
    }
    imageConversionModalInstance.show();
}

async function startImageConversion() {
    if (!activeSelectedFile) return;
    const targetFormat = document.getElementById("convertImageTargetFormat")?.value || 'e01';
    const hashes = [];
    if (document.getElementById("convertHashSha256")?.checked) hashes.push('sha256');
    if (document.getElementById("convertHashSha1")?.checked) hashes.push('sha1');
    if (document.getElementById("convertHashMd5")?.checked) hashes.push('md5');
    if (!hashes.length) return showToast('Select at least one verification hash algorithm.', 'warning');

    const status = document.getElementById("convertImageStatus");
    if (status) status.textContent = 'Starting conversion job...';

    try {
        const res = await fetch('/api/start_image_conversion', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_image_path: activeSelectedFile,
                target_format: targetFormat,
                hashes: hashes,
                metadata: {
                    case_number: activeCase ? activeCase.case_number : null,
                    examiner: activeCase ? activeCase.examiner : null,
                },
            })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Failed to start: ${data.error}`;
            showToast(`Conversion failed to start: ${data.error}`, 'danger');
            return;
        }
        if (imageConversionModalInstance) imageConversionModalInstance.hide();
        showToast('Image conversion started - watch the progress bar in File Explorer.', 'success');
    } catch (err) {
        if (status) status.textContent = 'Request failed - see console.';
    }
}

// --- Memory Forensics (Volatility3 for Windows, mquire for Linux/x86_64) ---
// One modal, one Engine selector - mirrors how BitLocker/LUKS share one
// "unlock an encrypted volume" UI shape with two distinct backends, rather
// than two separate modals for what an examiner experiences as the same
// task ("analyze this memory image").
let memoryForensicsModalInstance = null;

function onMemForensicsEngineChange() {
    const engine = document.getElementById("memForensicsEngine").value;
    const isMquire = engine === 'mquire';
    document.getElementById("memForensicsVol3Desc").style.display = isMquire ? 'none' : '';
    document.getElementById("memForensicsMquireDesc").style.display = isMquire ? '' : 'none';
    document.getElementById("memForensicsPluginList").style.display = isMquire ? 'none' : '';
    document.getElementById("mquireTableList").style.display = isMquire ? '' : 'none';
}

function openMemoryForensicsModal() {
    if (!activeSelectedFile) return;
    document.getElementById("memForensicsFileName").textContent = activeSelectedFile.split('/').pop();
    const status = document.getElementById("memForensicsStatus");
    if (status) status.textContent = 'Select the plugins to run, then click Start Scan.';

    // .lime is LiME's own Linux-only memory-acquisition output format
    // (confirmed against mquire's own accepted-input-format list) -
    // unambiguous enough to default the engine choice, unlike .raw/.mem/
    // .vmem/.dmp which are shared/ambiguous across tools and OSes and stay
    // defaulted to Volatility3 (this feature's original, longer-standing
    // engine) rather than guessed.
    const engineSelect = document.getElementById("memForensicsEngine");
    engineSelect.value = activeSelectedFile.toLowerCase().endsWith('.lime') ? 'mquire' : 'vol3';
    onMemForensicsEngineChange();

    if (!memoryForensicsModalInstance) {
        memoryForensicsModalInstance = new bootstrap.Modal(document.getElementById('memoryForensicsModal'));
    }
    memoryForensicsModalInstance.show();
}

async function startMemoryForensicsScan() {
    if (!activeSelectedFile) return;
    const engine = document.getElementById("memForensicsEngine").value;
    const isMquire = engine === 'mquire';
    const listSelector = isMquire ? '#mquireTableList' : '#memForensicsPluginList';
    const selected = Array.from(document.querySelectorAll(`${listSelector} input[type=checkbox]:checked`)).map(el => el.value);
    if (!selected.length) return showToast(isMquire ? 'Select at least one table to query.' : 'Select at least one plugin to run.', 'warning');

    const status = document.getElementById("memForensicsStatus");
    if (status) status.textContent = 'Starting scan job...';

    // Output files land in the active case's folder if one is selected,
    // else next to the source file itself - same
    // activeCase ? activeCase.case_folder : ... pattern this app already
    // uses for every other in-image/whole-image tool's output destination.
    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    const endpoint = isMquire ? '/api/files/memory/start_mquire_scan' : '/api/files/memory/start_scan';
    const body = isMquire
        ? { path: activeSelectedFile, tables: selected, destination_dir: destinationDir }
        : { path: activeSelectedFile, plugins: selected, destination_dir: destinationDir };

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Failed to start: ${data.error}`;
            showToast(`Memory forensics scan failed to start: ${data.error}`, 'danger');
            return;
        }
        if (memoryForensicsModalInstance) memoryForensicsModalInstance.hide();
        showToast('Memory forensics scan started - watch the progress bar in File Explorer.', 'success');
    } catch (err) {
        if (status) status.textContent = 'Request failed - see console.';
    }
}

// ALEAPP/iLEAPP - runs on a whole extraction folder (unlike Memory
// Forensics above, which runs on a single selected file), same
// #explorerJobProgress background-job pattern.
let leappScanModalInstance = null;

function openLeappScanModal() {
    if (!activeSelectedFile) return;
    document.getElementById("leappFolderName").textContent = activeSelectedFile.split('/').filter(Boolean).pop();
    const status = document.getElementById("leappScanStatus");
    if (status) status.textContent = 'Select the correct parser for this extraction\'s platform, then click Start Scan.';
    if (!leappScanModalInstance) {
        leappScanModalInstance = new bootstrap.Modal(document.getElementById('leappScanModal'));
    }
    leappScanModalInstance.show();
}

async function startLeappScan() {
    if (!activeSelectedFile) return;
    const tool = document.getElementById("leappTool").value;
    const status = document.getElementById("leappScanStatus");
    if (status) status.textContent = 'Starting scan job...';

    const destinationDir = activeCase ? activeCase.case_folder : activeSelectedFile.substring(0, activeSelectedFile.lastIndexOf('/'));

    try {
        const res = await fetch('/api/files/leapp/start_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: tool, path: activeSelectedFile, destination_dir: destinationDir })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Failed to start: ${data.error}`;
            showToast(`ALEAPP/iLEAPP scan failed to start: ${data.error}`, 'danger');
            return;
        }
        if (leappScanModalInstance) leappScanModalInstance.hide();
        showToast('ALEAPP/iLEAPP scan started - watch the progress bar in File Explorer.', 'success');
    } catch (err) {
        if (status) status.textContent = 'Request failed - see console.';
    }
}

// --- Stacked Modals ---
// Bootstrap gives every modal (and the backdrop it creates on show) the
// same static default z-index, so opening one modal from inside an
// already-open one (e.g. clicking "Browse" for the case folder while the
// Case Manager modal is open) renders it behind the modal that's already
// showing - DOM order decides stacking when z-index ties. This listens
// globally for any modal being shown and, if more than one is open at
// once, bumps the newly-shown modal and the backdrop it just created
// above whatever was already open. General fix, not specific to the case
// manager - covers any future nested-modal case too.
document.addEventListener('shown.bs.modal', (ev) => {
    const openModals = document.querySelectorAll('.modal.show');
    if (openModals.length <= 1) return;
    const zBase = 1055 + (openModals.length - 1) * 20;
    ev.target.style.zIndex = zBase + 10;
    const backdrops = document.querySelectorAll('.modal-backdrop');
    const topBackdrop = backdrops[backdrops.length - 1];
    if (topBackdrop) topBackdrop.style.zIndex = zBase;
});

// --- Settings: left-nav category list + single right-hand content pane ---
// The left column (#settingsNavList) is a Bootstrap list-group used as tabs
// (data-bs-toggle="list"), which reuses the exact same Tab component/events
// as this app's regular horizontal tabs (shown.bs.tab/hidden.bs.tab) - no
// separate wiring needed for the nav-switching itself. Every pane's own
// sub-sections are now individually collapsible (default collapsed, to keep
// a merged pane like Security or Network from being one long wall of
// controls) - two side effects care specifically about their OWN section's
// expand/collapse state, not just which top-level category is active:
// Audit Log's auto-refresh interval, and Network Configuration's device
// list fetch (a live nmcli query per device - shouldn't run just because
// the examiner opened Network to look at Drive Mounting instead).
document.getElementById('secAuditLog')?.addEventListener('shown.bs.collapse', () => startCocAutoRefresh());
document.getElementById('secAuditLog')?.addEventListener('hidden.bs.collapse', () => stopCocAutoRefresh());
document.getElementById('secNetConfig')?.addEventListener('shown.bs.collapse', () => loadNetworkConfig());
document.getElementById('secManageTags')?.addEventListener('shown.bs.collapse', () => loadManageTagsSection());
// Keyword Lists/Hash Sets/URL Lists/YARA Rulesets were merged into one
// "Analysis & IOC Lists" accordion item (2026-08-26, too many top-level
// items) - one listener now fires all 4 former per-item load functions.
document.getElementById('secAnalysisLists')?.addEventListener('shown.bs.collapse', () => {
    loadKeywordListsSection();
    loadHashListsSection();
    loadUrlListsSection();
    loadYaraRulesetsSection();
});

document.addEventListener('shown.bs.tab', (ev) => {
    // Returning to the whole Settings sidebar tab while the Audit Log
    // accordion section happens to still be expanded underneath - a nested
    // Bootstrap .collapse keeps its own shown/hidden state even while its
    // ancestor tab-pane is hidden (display:none doesn't fire hidden.bs.collapse),
    // so this is the only way to know refresh should resume rather than stay
    // silently stopped while the section still displays as expanded.
    if (ev.target.id === 'settings-tab' && document.getElementById('secAuditLog')?.classList.contains('show')) {
        startCocAutoRefresh();
    }
});
document.addEventListener('hidden.bs.tab', (ev) => {
    if (ev.target.id === 'settings-tab') stopCocAutoRefresh();
});

// --- Active Case Management ---
// A "case" is just a folder (see /api/cases/create) that every tool's
// Destination field gets pointed at once active, so evidence for one case
// never lands as a sibling of another case's files. There's no server-side
// "active case" state - the backend is stateless per-request as everywhere
// else in this app - so the active case lives entirely here in the browser
// (persisted to localStorage) and is applied to each tab's fields once,
// at the moment of create/select/restore, never on a timer, so it can
// never fight a manual edit made afterward.
function initActiveCaseBar() {
    try {
        const saved = localStorage.getItem(ACTIVE_CASE_STORAGE_KEY);
        if (saved) activeCase = JSON.parse(saved);
    } catch (err) {
        activeCase = null;
    }
    renderActiveCaseBar();
    if (activeCase) applyActiveCaseToFields();
}

function persistActiveCase() {
    if (activeCase) {
        localStorage.setItem(ACTIVE_CASE_STORAGE_KEY, JSON.stringify(activeCase));
    } else {
        localStorage.removeItem(ACTIVE_CASE_STORAGE_KEY);
    }
}

function renderActiveCaseBar() {
    const label = document.getElementById("btnCaseActionLabel");
    const info = document.getElementById("activeCaseInfo");
    const numVal = document.getElementById("activeCaseNumVal");
    const examinerVal = document.getElementById("activeCaseExaminerVal");

    if (activeCase) {
        if (label) label.textContent = `Case: ${activeCase.case_number}`;
        if (info) info.style.display = 'flex';
        if (numVal) numVal.textContent = activeCase.case_number;
        if (examinerVal) examinerVal.textContent = activeCase.examiner || '--';
    } else {
        if (label) label.textContent = 'Create / Select Case';
        if (info) info.style.display = 'none';
    }
}

function applyActiveCaseToFields() {
    if (!activeCase) return;
    const fieldGroups = [
        ['caseNum', 'examiner', 'destPath'],
        ['recoveryCaseNum', 'recoveryExaminer', 'recoveryDest'],
        ['mobileCaseNum', 'mobileExaminer', 'mobileDest'],
    ];
    fieldGroups.forEach(([caseNumId, examinerId, destId]) => {
        const caseNumEl = document.getElementById(caseNumId);
        const examinerEl = document.getElementById(examinerId);
        const destEl = document.getElementById(destId);
        if (caseNumEl) caseNumEl.value = activeCase.case_number;
        if (examinerEl) examinerEl.value = activeCase.examiner || '';
        if (destEl) destEl.value = activeCase.case_folder;
    });
    // Single funnel point for Reporting's auto-load - covers createCase(),
    // selectCase(), and initActiveCaseBar()'s page-load restore, all three
    // of which call this function already.
    loadCaseForEditing();
    resyncExplorerRootToActiveCase();
    refreshGuidedWorkflow();
}

function openCaseManagerModal() {
    if (!caseManagerModalInstance) {
        caseManagerModalInstance = new bootstrap.Modal(document.getElementById('caseManagerModal'));
    }
    const statusEl = document.getElementById("createCaseStatus");
    if (statusEl) statusEl.textContent = '';
    // Examiner is no longer free-typed - it's whoever is currently logged
    // in (readonly field, see #newCaseExaminer), so a case's examiner of
    // record always matches its real chain-of-custody attribution.
    const examinerEl = document.getElementById("newCaseExaminer");
    if (examinerEl) examinerEl.value = currentUsername || '';
    caseManagerModalInstance.show();
    loadExistingCases();
}

async function createCase() {
    const caseNumber = document.getElementById("newCaseNumber")?.value.trim();
    const examiner = document.getElementById("newCaseExaminer")?.value.trim();
    const parentDir = document.getElementById("newCaseParentDir")?.value.trim() || '/mnt';
    const notes = document.getElementById("newCaseNotes")?.value.trim();
    const statusEl = document.getElementById("createCaseStatus");

    if (!caseNumber) {
        if (statusEl) { statusEl.textContent = 'Case number is required.'; statusEl.className = 'small mt-2 text-danger'; }
        return;
    }

    try {
        const res = await fetch('/api/cases/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_number: caseNumber, examiner, parent_dir: parentDir, notes })
        });
        const data = await res.json();
        if (!data.success) {
            if (statusEl) { statusEl.textContent = data.error; statusEl.className = 'small mt-2 text-danger'; }
            return;
        }

        activeCase = { case_number: data.case.case_number, examiner: data.case.examiner, case_folder: data.case.case_folder };
        persistActiveCase();
        renderActiveCaseBar();
        applyActiveCaseToFields();

        // Reset the form for next time and close - the bar now shows the result.
        ["newCaseNumber", "newCaseExaminer", "newCaseNotes"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        if (caseManagerModalInstance) caseManagerModalInstance.hide();
    } catch (err) {
        if (statusEl) { statusEl.textContent = 'Request failed.'; statusEl.className = 'small mt-2 text-danger'; }
    }
}

// Case Status badge colors - semantic, not the app's own cyan accent (that's
// reserved for interactive/branding use, per this app's existing convention
// of keeping status color separate from the accent hue).
const CASE_STATUS_BADGE_CLASS = {
    'Open': 'bg-info text-dark',
    'In Review': 'bg-warning text-dark',
    'On Hold': 'bg-secondary',
    'Closed': 'bg-success',
    'Archived': 'bg-dark border border-secondary text-subtle',
};

// Fetched once per loadExistingCases() call, then filtered client-side by renderCaseList() as the
// examiner types/picks a status - the list is already small and already fully fetched in one call
// (routes/case_management.py's /api/cases/list has no pagination/query-param support at all), so
// re-fetching per keystroke would be pure waste. null until the first successful fetch.
let caseManagerCasesCache = null;

async function loadExistingCases() {
    const listEl = document.getElementById("caseList");
    if (!listEl) return;
    listEl.innerHTML = '<div class="text-subtle small p-2">Loading...</div>';

    try {
        const res = await fetch('/api/cases/list');
        const data = await res.json();
        if (!data.success) {
            listEl.innerHTML = `<div class="text-danger small p-2">${data.error}</div>`;
            return;
        }
        caseManagerCasesCache = data.cases;
        renderCaseList();
    } catch (err) {
        listEl.innerHTML = '<div class="text-danger small p-2">Request failed.</div>';
    }
}

// Applies the search text + status dropdown (both above #caseList) to the already-fetched
// caseManagerCasesCache and rebuilds the row list - called on every filter change AND once after
// each real fetch, so it's the one place that actually builds #caseList's rows.
function renderCaseList() {
    const listEl = document.getElementById("caseList");
    if (!listEl || !caseManagerCasesCache) return;

    const searchTerm = (document.getElementById("caseSearchFilter")?.value || '').trim().toLowerCase();
    const statusFilter = document.getElementById("caseStatusFilter")?.value || '__active__';

    const cases = caseManagerCasesCache.filter(c => {
        const status = c.case_status || 'Open';
        if (statusFilter === '__active__' && status === 'Archived') return false;
        if (statusFilter !== '__active__' && statusFilter !== '__all__' && status !== statusFilter) return false;
        if (searchTerm) {
            const haystack = `${c.case_number || ''} ${c.examiner || ''}`.toLowerCase();
            if (!haystack.includes(searchTerm)) return false;
        }
        return true;
    });

    if (cases.length === 0) {
        listEl.innerHTML = caseManagerCasesCache.length === 0
            ? '<div class="text-subtle small p-2">No cases found yet - create one above.</div>'
            : '<div class="text-subtle small p-2">No cases match this filter.</div>';
        return;
    }

    listEl.innerHTML = '';
    cases.forEach(c => {
        // A plain div, not a <button>, because legacy rows nest their
        // own Migrate <button> inside it below - button-in-button is
        // invalid HTML.
        const btn = document.createElement("div");
        btn.className = "list-group-item list-group-item-action bg-dark text-light border-secondary py-2";
        btn.style.cursor = 'pointer';

        const topRow = document.createElement('div');
        topRow.className = 'd-flex justify-content-between align-items-center';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'fw-bold text-info';
        nameSpan.appendChild(document.createTextNode(c.case_number)); // examiner-entered, text-only
        const statusBadge = document.createElement('span');
        statusBadge.className = `badge ms-2 ${CASE_STATUS_BADGE_CLASS[c.case_status] || 'bg-info text-dark'}`;
        statusBadge.textContent = (c.case_status || 'Open').toUpperCase();
        nameSpan.appendChild(statusBadge);
        if (c.schema === 'legacy') {
            const legacyBadge = document.createElement('span');
            legacyBadge.className = 'badge bg-warning text-dark ms-2';
            legacyBadge.textContent = 'LEGACY';
            nameSpan.appendChild(legacyBadge);
        }
        const dateSpan = document.createElement('small');
        dateSpan.className = 'text-subtle';
        dateSpan.textContent = c.created_at;
        topRow.appendChild(nameSpan);
        topRow.appendChild(dateSpan);

        const subRow = document.createElement('div');
        subRow.className = 'small text-subtle font-monospace';
        subRow.appendChild(document.createTextNode(`${c.examiner || '--'} · ${c.case_folder}`));

        btn.appendChild(topRow);
        btn.appendChild(subRow);
        btn.onclick = () => selectCase(c);

        if (c.schema === 'legacy') {
            const migrateBtn = document.createElement('button');
            migrateBtn.type = 'button';
            migrateBtn.className = 'btn btn-xs btn-outline-warning py-0 px-2 mt-2';
            migrateBtn.innerHTML = '<i class="bi bi-arrow-up-circle me-1"></i>Migrate to Consolidated Format';
            migrateBtn.onclick = (ev) => { ev.stopPropagation(); migrateCase(c); };
            btn.appendChild(migrateBtn);
        }

        listEl.appendChild(btn);
    });
}

// Non-destructive: originals are renamed with a ".pre_consolidation_backup"
// suffix server-side, never deleted (see /api/cases/migrate_apply). Preview
// first so the examiner sees what will be folded in before committing.
async function migrateCase(c) {
    if (!confirm(`Migrate case "${c.case_number}" to the new consolidated one-file-per-case format?\n\nThe original case_info.json and *_report.json files will be renamed with a ".pre_consolidation_backup" suffix - nothing is deleted.`)) {
        return;
    }
    try {
        const previewRes = await fetch('/api/cases/migrate_preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: c.case_folder })
        });
        const preview = await previewRes.json();
        if (!preview.success) return showToast(`Migration preview failed: ${preview.error}`, 'danger');
        if (preview.already_migrated) {
            showToast('This case is already on the consolidated format.', 'info');
            loadExistingCases();
            return;
        }

        const unreadableNote = preview.unreadable.length ? `, ${preview.unreadable.length} unreadable file(s) will be skipped` : '';
        if (!confirm(`Found ${preview.reports.length} job report(s) to fold into this case${unreadableNote}.\n\nProceed with migration?`)) {
            return;
        }

        const applyRes = await fetch('/api/cases/migrate_apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: c.case_folder })
        });
        const applyData = await applyRes.json();
        if (!applyData.success) return showToast(`Migration failed: ${applyData.error}`, 'danger');

        showToast(`Migrated ${applyData.events_migrated} job(s) into ${applyData.case_file}.`, 'success');
        loadExistingCases();
    } catch (err) {
        showToast(`Migration request failed: ${err.message}`, 'danger');
    }
}

async function selectCase(c) {
    activeCase = { case_number: c.case_number, examiner: c.examiner, case_folder: c.case_folder };
    persistActiveCase();
    renderActiveCaseBar();
    applyActiveCaseToFields();
    if (caseManagerModalInstance) caseManagerModalInstance.hide();

    try {
        await fetch('/api/cases/log_select', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_number: c.case_number, case_folder: c.case_folder })
        });
    } catch (err) {}
}

function clearActiveCase() {
    activeCase = null;
    persistActiveCase();
    renderActiveCaseBar();
    loadCaseForEditing();
    resyncExplorerRootToActiveCase(); // falls File Explorer back to /mnt
    refreshGuidedWorkflow();
    if (caseManagerModalInstance) caseManagerModalInstance.hide();
}

// --- Help > Guided Workflow (2026-08-24, moved from Home 2026-08-26) ----------
// A stateful case -> acquisition -> tools checklist for whichever case is
// currently active, distinct from the plain always-the-same launcher tiles
// on Home (this pane moved out of Home to keep that page a plain launcher
// grid - see the dated CLAUDE.md entry). "Done" for each step is derived
// from real data already on disk, not client-side-only state, so it
// survives a reload and is correct even if the examiner did the actual work
// from a different browser tab/session: step 1 from activeCase itself, step
// 2 from /api/cases/list's existing per-case event_count, step 3 from
// /api/case_index/summary's has_analysis_activity (added alongside this
// feature - see routes/case_index.py). Refreshed from every place this app
// already treats as "the case may have changed" (applyActiveCaseToFields()/
// clearActiveCase() above), on visits/return to Help's own Guided Workflow
// sub-tab, a light poll while that sub-tab stays visible (mirrors the Audit
// Log auto-refresh pattern), and on any background job finishing while it
// happens to be the visible sub-tab.
async function refreshGuidedWorkflow() {
    const noCaseEl = document.getElementById('guidedWorkflowNoCase');
    const stepsEl = document.getElementById('guidedWorkflowSteps');
    if (!noCaseEl || !stepsEl) return;

    if (!activeCase) {
        noCaseEl.style.display = 'block';
        stepsEl.style.display = 'none';
        return;
    }
    noCaseEl.style.display = 'none';
    stepsEl.style.display = 'block';

    const caseLabelEl = document.getElementById('guidedWorkflowCaseLabel');
    if (caseLabelEl) caseLabelEl.textContent = activeCase.case_number;

    // Step 1 is always "done" the instant a case is active - this whole
    // block is hidden entirely otherwise (see above).
    setWorkflowStepDone('wfBadge1', 'wfStatus1', `Active case: ${activeCase.case_number}`);

    let eventCount = 0;
    let hasActivity = false;
    try {
        const casesRes = await fetch('/api/cases/list');
        const casesData = await casesRes.json();
        if (casesData.success) {
            const thisCase = casesData.cases.find((c) => c.case_folder === activeCase.case_folder);
            if (thisCase && typeof thisCase.event_count === 'number') eventCount = thisCase.event_count;
        }
    } catch (err) {}

    try {
        const idxRes = await fetch('/api/case_index/summary', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder }),
        });
        const idxData = await idxRes.json();
        if (idxData.success) hasActivity = !!idxData.has_analysis_activity;
    } catch (err) {}

    if (eventCount > 0) {
        setWorkflowStepDone('wfBadge2', 'wfStatus2', `${eventCount} acquisition event${eventCount === 1 ? '' : 's'} recorded`);
    } else {
        setWorkflowStepPending('wfBadge2', 'wfStatus2', 'Not started yet', '2');
    }

    if (hasActivity) {
        setWorkflowStepDone('wfBadge3', 'wfStatus3', 'Analysis activity recorded');
    } else {
        setWorkflowStepPending('wfBadge3', 'wfStatus3', 'No analysis activity yet', '3');
    }

    // Own fresh fetch of the case's full events[], deliberately not read from
    // currentLoadedReportData (populated by Reporting's loadCaseForEditing() -
    // could be stale by the time this function's own periodic poll runs, e.g.
    // an acquisition completing in the background between Reporting visits)
    // - matches this function's own existing pattern of each concern fetching
    // its own current truth rather than trusting another feature's cache.
    let evidenceCandidates = [];
    try {
        const slug = activeCase.case_folder.split('/').filter(Boolean).pop();
        const reportRes = await fetch('/api/report/load', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: `${activeCase.case_folder}/${slug}_case.json` }),
        });
        const reportData = await reportRes.json();
        if (reportData.success) evidenceCandidates = guidedWorkflowEvidenceCandidates(reportData.report.events);
    } catch (err) {}
    updateGuidedWorkflowStep3Button(evidenceCandidates);

    const doneEl = document.getElementById('guidedWorkflowDone');
    if (doneEl) doneEl.style.display = (eventCount > 0 && hasActivity) ? 'block' : 'none';
}

// Mirrors the exact COMPLETED + output_image_path/output_destination
// resolution _collect_case_timeline()/_mobile_profile_from_case_event()
// already use server-side (routes/reporting.py, routes/auto_analyze.py) -
// disk-image events use output_image_path, mobile-backup events use
// output_destination (confirmed genuinely different field names before
// relying on it, not assumed). Order follows events[]'s own on-disk order
// (oldest-first, this app's existing report-JSON convention), so the last
// entry is the most recently completed acquisition.
//
// output_destination is ONLY trusted when the event's own tool is a real
// mobile-acquisition tool (ios_backup / android_*) - mirroring
// _mobile_profile_from_case_event()'s exact same gate, not just "any
// COMPLETED event that happens to carry a destination field." Caught live
// against this app's own oldest real test case: a pre-schema-evolution
// event with tool=null had output_destination set to the bare case-folder
// path (its own generic job destination, not a specific evidence item) -
// without this gate it would have shown up as a bogus "evidence candidate"
// pointing Auto Analyze at the whole case folder instead of a real file.
const GUIDED_WORKFLOW_MOBILE_TOOLS = (tool) => tool === 'ios_backup' || (typeof tool === 'string' && tool.startsWith('android_'));

function guidedWorkflowEvidenceCandidates(events) {
    if (!Array.isArray(events)) return [];
    const seen = new Set();
    const candidates = [];
    events.forEach(event => {
        if (event.acquisition_status !== 'COMPLETED') return;
        const params = event.acquisition_parameters || {};
        const path = params.output_image_path || (GUIDED_WORKFLOW_MOBILE_TOOLS(event.tool) ? params.output_destination : null);
        if (!path || seen.has(path)) return;
        seen.add(path);
        const evidenceId = (event.case_metadata || {}).evidence_id || 'Evidence';
        candidates.push({ path, label: `${evidenceId} (${event.tool || 'unknown'})` });
    });
    return candidates;
}

// Cached alongside the button/select DOM update so runGuidedWorkflowAutoAnalyze()
// can resolve the single-candidate case without re-deriving it (the select
// stays hidden - and therefore unreadable - when there's only one candidate).
let guidedWorkflowEvidenceCandidatesCache = [];

function updateGuidedWorkflowStep3Button(candidates) {
    guidedWorkflowEvidenceCandidatesCache = candidates;
    const btn = document.getElementById('wfStep3Btn');
    const select = document.getElementById('wfStep3EvidenceSelect');
    if (!btn || !select) return;

    if (!candidates.length) {
        btn.textContent = 'Go to File Explorer';
        btn.title = '';
        btn.onclick = () => switchToTab('explorer-tab');
        select.style.display = 'none';
        select.innerHTML = '';
        return;
    }

    btn.textContent = 'Run Auto Analyze';
    btn.title = 'Detects what this evidence item is (Windows/Linux disk image, memory image, or mobile backup) and runs a curated set of analysis tools automatically - the same Auto Analyze already reachable from File Explorer, pre-scoped to this case\'s own acquired evidence.';
    btn.onclick = () => runGuidedWorkflowAutoAnalyze();

    if (candidates.length === 1) {
        select.style.display = 'none';
        select.innerHTML = '';
        return;
    }

    select.style.display = '';
    const prevValue = select.value;
    select.innerHTML = '';
    candidates.forEach((c) => {
        const opt = document.createElement('option');
        opt.value = c.path;
        opt.textContent = c.label;
        select.appendChild(opt);
    });
    // Preserve the examiner's own prior pick across a refresh if it's still a
    // valid candidate; otherwise default to the most recently completed one.
    select.value = candidates.some((c) => c.path === prevValue) ? prevValue : candidates[candidates.length - 1].path;
}

function runGuidedWorkflowAutoAnalyze() {
    const select = document.getElementById('wfStep3EvidenceSelect');
    const path = (select && select.style.display !== 'none') ? select.value : guidedWorkflowEvidenceCandidatesCache[0]?.path;
    if (!path) return;
    openAutoAnalyzeModal(path);
}

// Tier 1b: pre-select the target drive on the way to Acquisition, but only
// when the choice is genuinely unambiguous right now - re-scans first
// (refreshDrives(), rather than trusting a possibly-stale currentDrivesList
// from page load) so "exactly one" reflects what's actually connected at
// the moment of the click, and never overwrites a selection the examiner
// already made manually.
// mmcblk* = this Pi's own SD-card boot media; zram* = a virtual RAM-backed
// compressed-swap block device Linux always exposes, never a real
// evidence-acquisition target - both confirmed live against the real
// deployed station's own /api/drives response (a fresh Pi commonly reports
// nothing else connected but these two, which would otherwise wrongly read
// as "exactly one real candidate" and auto-select the zram device).
const GUIDED_WORKFLOW_NON_CANDIDATE_DRIVE_PREFIXES = ['mmcblk', 'zram'];

async function goToAcquisitionWithSmartDriveSelect() {
    switchToTab('acquisition-tab');
    await refreshDrives();
    const sel = document.getElementById('driveSelect');
    if (!sel || sel.value) return;
    const nonBoot = (currentDrivesList || []).filter((d) => !GUIDED_WORKFLOW_NON_CANDIDATE_DRIVE_PREFIXES.some((prefix) => (d.name || '').startsWith(prefix)));
    if (nonBoot.length === 1) {
        sel.value = nonBoot[0].device;
        checkSmartTelemetry();
    }
}

function setWorkflowStepDone(badgeId, statusId, statusText) {
    const badge = document.getElementById(badgeId);
    const status = document.getElementById(statusId);
    if (badge) { badge.className = 'workflow-step-badge done'; badge.innerHTML = '<i class="bi bi-check-lg"></i>'; }
    if (status) { status.className = 'small mt-1 text-success'; status.textContent = statusText; }
}

function setWorkflowStepPending(badgeId, statusId, statusText, num) {
    const badge = document.getElementById(badgeId);
    const status = document.getElementById(statusId);
    if (badge) { badge.className = 'workflow-step-badge'; badge.textContent = num; }
    if (status) { status.className = 'small mt-1 text-subtle'; status.textContent = statusText; }
}

let guidedWorkflowAutoRefreshTimer = null;
function startGuidedWorkflowAutoRefresh() {
    if (guidedWorkflowAutoRefreshTimer) return;
    guidedWorkflowAutoRefreshTimer = setInterval(refreshGuidedWorkflow, 20000);
}
function stopGuidedWorkflowAutoRefresh() {
    if (guidedWorkflowAutoRefreshTimer) {
        clearInterval(guidedWorkflowAutoRefreshTimer);
        guidedWorkflowAutoRefreshTimer = null;
    }
}
// Guided Workflow now lives as its own sub-tab inside Help (helpNavWorkflow),
// not the whole Home tab - start/stop on that specific nested tab becoming
// shown/hidden (covers switching between Help's own sub-panes), plus a
// second check on the outer Help tab itself (below), matching the exact
// two-tier pattern already established for Settings' Audit Log auto-refresh
// (a nested Bootstrap tab/collapse keeps its own active state even while its
// ancestor tab-pane is hidden via display:none, which fires neither
// hidden.bs.tab nor hidden.bs.collapse on the inner element).
document.getElementById('helpNavWorkflow')?.addEventListener('shown.bs.tab', () => { refreshGuidedWorkflow(); startGuidedWorkflowAutoRefresh(); });
document.getElementById('helpNavWorkflow')?.addEventListener('hidden.bs.tab', () => stopGuidedWorkflowAutoRefresh());
document.addEventListener('shown.bs.tab', (ev) => {
    if (ev.target.id === 'help-tab' && document.getElementById('helpNavWorkflow')?.classList.contains('active')) {
        refreshGuidedWorkflow();
        startGuidedWorkflowAutoRefresh();
    }
});
document.addEventListener('hidden.bs.tab', (ev) => {
    if (ev.target.id === 'help-tab') stopGuidedWorkflowAutoRefresh();
});

// --- Modular Folder & File Modals ---
function openFolderModal(mode = 'folder', targetInputId = 'destPath') {
    modalPickerMode = mode;
    targetInputIdForModal = targetInputId;
    
    const destPathEl = document.getElementById(targetInputIdForModal);
    currentBrowsePath = destPathEl ? (destPathEl.value.trim() || '/mnt') : '/mnt';
    
    const titleEl = document.getElementById("modalTitle");
    const selectBtn = document.getElementById("modalSelectBtn");

    if (modalPickerMode === 'attachment') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-paperclip me-2"></i>Select Case File / Photo Attachment';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'mapfile') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-bar-chart-line me-2"></i>Select ddrescue Mapfile (.map)';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'recoverySource') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-search-heart me-2"></i>Select Source Image';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'copyDestination') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-copy me-2"></i>Copy To...';
        if (selectBtn) { selectBtn.style.display = 'inline-block'; selectBtn.textContent = 'Copy Here'; }
    } else if (modalPickerMode === 'logicalAcqFolder') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-folder-plus me-2"></i>Add Folder to Logical Acquisition';
        if (selectBtn) { selectBtn.style.display = 'inline-block'; selectBtn.textContent = 'Add This Folder'; }
    } else if (modalPickerMode === 'whatsappKeyFile') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-key-fill me-2"></i>Select WhatsApp Key File';
        if (selectBtn) selectBtn.style.display = 'none';
    } else {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-folder2-open me-2"></i>Select Destination Directory';
        if (selectBtn) { selectBtn.style.display = 'inline-block'; selectBtn.textContent = 'Select This Directory'; }
    }

    const modalEl = document.getElementById('folderBrowserModal');
    if (modalEl) {
        if (!folderModalInstance) folderModalInstance = new bootstrap.Modal(modalEl);
        loadFolderList(currentBrowsePath);
        folderModalInstance.show();
    }
}

async function loadFolderList(path) {
    const folderListEl = document.getElementById("folderList");
    if (!folderListEl) return;

    try {
        const res = await fetch('/api/files/browse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        const data = await res.json();
        
        currentBrowsePath = data.path;
        const modalPathEl = document.getElementById("modalCurrentPath");
        if (modalPathEl) modalPathEl.value = currentBrowsePath;
        folderListEl.innerHTML = '';

        data.items.forEach(item => {
            let isSelectableFile = false;
            
            if (modalPickerMode === 'attachment' && !item.is_dir) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'mapfile' && !item.is_dir && item.name.toLowerCase().endsWith('.map')) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'recoverySource' && !item.is_dir) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'whatsappKeyFile' && !item.is_dir) {
                isSelectableFile = true;
            }

            if (item.is_dir || isSelectableFile) {
                const btn = document.createElement("button");
                btn.className = "list-group-item list-group-item-action bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center";
                
                let icon = item.is_dir ? '<i class="bi bi-folder-fill folder-icon me-2"></i>' : '<i class="bi bi-file-earmark-text text-info me-2 fs-5"></i>';
                if (isSelectableFile) {
                    if (modalPickerMode === 'attachment') icon = '<i class="bi bi-paperclip text-info me-2 fs-5"></i>';
                    else if (modalPickerMode === 'mapfile') icon = '<i class="bi bi-map text-warning me-2 fs-5"></i>';
                    else if (modalPickerMode === 'recoverySource') icon = '<i class="bi bi-disc text-primary me-2 fs-5"></i>';
                    else if (modalPickerMode === 'whatsappKeyFile') icon = '<i class="bi bi-key-fill text-success me-2 fs-5"></i>';
                }

                const outerSpan = document.createElement('span');
                outerSpan.innerHTML = icon; // icon markup is static/trusted, not user data

                const nameSpan = document.createElement('span');
                nameSpan.className = item.is_dir ? 'folder-text' : 'text-light';
                nameSpan.appendChild(document.createTextNode(item.name)); // untrusted evidence filename, text-only

                outerSpan.appendChild(nameSpan);

                const sizeEl = document.createElement('small');
                sizeEl.className = 'text-subtle font-monospace';
                sizeEl.textContent = item.size_str;

                btn.appendChild(outerSpan);
                btn.appendChild(sizeEl);

                btn.onclick = () => {
                    if (item.is_dir) {
                        loadFolderList(item.path);
                    } else if (modalPickerMode === 'attachment') {
                        addFileAttachment(item.path);
                        if (folderModalInstance) folderModalInstance.hide();
                    } else if (modalPickerMode === 'mapfile') {
                        const mapPathEl = document.getElementById("tabMapfilePath");
                        if (mapPathEl) mapPathEl.value = item.path;
                        if (folderModalInstance) folderModalInstance.hide();
                        inspectDdrescueMapfile();
                    } else if (modalPickerMode === 'recoverySource') {
                        const sourcePathEl = document.getElementById("recoverySourcePath");
                        if (sourcePathEl) sourcePathEl.value = item.path;
                        if (folderModalInstance) folderModalInstance.hide();
                    } else if (modalPickerMode === 'whatsappKeyFile') {
                        const keyPathEl = document.getElementById("whatsappDecryptKeyPath");
                        if (keyPathEl) keyPathEl.value = item.path;
                        if (folderModalInstance) folderModalInstance.hide();
                    }
                };
                folderListEl.appendChild(btn);
            }
        });
    } catch (err) {}
}

function navigateFolderUp() {
    const parts = currentBrowsePath.split('/').filter(p => p.length > 0);
    parts.pop();
    loadFolderList('/' + parts.join('/') || '/');
}

function selectCurrentFolder() {
    if (modalPickerMode === 'copyDestination') {
        if (folderModalInstance) folderModalInstance.hide();
        if (activeSelectedFile) performCopyTo(activeSelectedFile, currentBrowsePath);
        return;
    }
    if (modalPickerMode === 'logicalAcqFolder') {
        if (folderModalInstance) folderModalInstance.hide();
        addLogicalAcqFolder(currentBrowsePath);
        return;
    }
    const targetEl = document.getElementById(targetInputIdForModal);
    if (targetEl) targetEl.value = currentBrowsePath;
    if (folderModalInstance) folderModalInstance.hide();
}

// --- Logical Acquisition (selected whole folders, packaged into a hash-
// verified evidence container + manifest, no full-device image needed) ---
let logicalAcqFolders = [];

function addLogicalAcqFolder(path) {
    if (!logicalAcqFolders.includes(path)) logicalAcqFolders.push(path);
    renderLogicalAcqFolders();
}

function removeLogicalAcqFolder(path) {
    logicalAcqFolders = logicalAcqFolders.filter(p => p !== path);
    renderLogicalAcqFolders();
}

function renderLogicalAcqFolders() {
    const container = document.getElementById("logicalAcqFoldersList");
    if (!container) return;
    container.innerHTML = '';
    if (!logicalAcqFolders.length) {
        container.innerHTML = '<span class="text-subtle small">No folders added yet.</span>';
        return;
    }
    logicalAcqFolders.forEach(path => {
        const row = document.createElement('div');
        row.className = 'd-flex align-items-center justify-content-between bg-dark p-2 rounded mb-1 border border-secondary';
        const label = document.createElement('span');
        label.className = 'small font-monospace text-break';
        label.textContent = path; // examiner-picked path, from the folder-browser modal - text node only
        row.appendChild(label);
        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-2 flex-shrink-0 ms-2';
        delBtn.title = 'Remove';
        delBtn.innerHTML = '<i class="bi bi-trash"></i>';
        delBtn.onclick = () => removeLogicalAcqFolder(path);
        row.appendChild(delBtn);
        container.appendChild(row);
    });
}

async function startLogicalAcquisition() {
    // Condensed 2026-08-27 - Logical Acquisition is now a Format option
    // (mirroring ddrescue's own precedent) sharing the main Start/Stop
    // buttons and the same #jobStatus/#logOutput Output panel every other
    // acquisition format already does (fetchProgress() already mirrors ANY
    // active job into that panel unconditionally, regardless of format - no
    // separate status echo needed here anymore). Also reuses the shared
    // #hashMd5/#hashSha1/#hashSha256 checkboxes instead of its own set.
    if (!logicalAcqFolders.length) return showToast('Add at least one folder first.', 'warning');

    const hashes = [];
    if (document.getElementById("hashMd5")?.checked) hashes.push('md5');
    if (document.getElementById("hashSha1")?.checked) hashes.push('sha1');
    if (document.getElementById("hashSha256")?.checked) hashes.push('sha256');
    if (!hashes.length) return showToast('Select at least one verification hash algorithm.', 'warning');

    const makeZip = document.getElementById("logicalAcqMakeZip")?.checked || false;
    const destPath = document.getElementById("destPath")?.value.trim() || '/mnt';
    const metadata = {
        case_number: document.getElementById("caseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("evidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("examiner")?.value || "UNSPECIFIED",
        notes: document.getElementById("notes")?.value || "None",
    };

    try {
        const res = await fetch('/api/start_logical_acquisition', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                selected_folders: logicalAcqFolders,
                destination: destPath,
                metadata: metadata,
                hashes: hashes,
                make_zip: makeZip,
            })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Logical acquisition failed to start: ${data.error}`, 'danger');
            return;
        }
        showToast('Logical acquisition started - see the Output console for live progress.', 'success');
    } catch (err) {
        showToast('Request failed - see console.', 'danger');
    }
}

// --- Telemetry & Drives ---
function getActiveTargetDrive() {
    return document.getElementById("driveSelect")?.value || "/dev/sda";
}

// Writes to both the navbar's telemetry element (desktop-only, hidden
// below 768px) and its Settings > Service Controls & Diagnostics mirror
// (mobile-only) - one poll, two display targets, whichever is actually
// visible at the current viewport width just reflects the same fetch.
function setTelemetryText(baseId, text) {
    const el = document.getElementById(baseId);
    if (el) el.innerText = text;
    const mobileEl = document.getElementById(baseId + "Settings");
    if (mobileEl) mobileEl.innerText = text;
}
function setTelemetryWidth(baseId, percent) {
    const el = document.getElementById(baseId);
    if (el) el.style.width = `${percent}%`;
    const mobileEl = document.getElementById(baseId + "Settings");
    if (mobileEl) mobileEl.style.width = `${percent}%`;
}

async function fetchSystemInfo() {
    const activeDrive = getActiveTargetDrive();
    try {
        const res = await fetch(`/api/system_info?drive=${encodeURIComponent(activeDrive)}`);
        const data = await res.json();

        setTelemetryText("cpuVal", `${data.cpu_percent}%`);
        setTelemetryWidth("cpuBar", data.cpu_percent);

        if (data.local_storage) {
            setTelemetryText("storageVal", `${data.local_storage.used_gb} / ${data.local_storage.total_gb} GB`);
            setTelemetryWidth("storageBar", data.local_storage.percent_used);
        }

        if (data.memory) {
            setTelemetryText("memVal", `${data.memory.used_gb} / ${data.memory.total_gb} GB (${data.memory.percent_used}%)`);
            setTelemetryWidth("memBar", data.memory.percent_used);
        }

        isWriteBlockActive = data.write_blocker_active;
        const wbBadgeBtn = document.getElementById("wbBadgeBtn");
        if (wbBadgeBtn) {
            wbBadgeBtn.title = `${activeDrive} - go to Settings > Drive Management to change this`;
            if (isWriteBlockActive) {
                wbBadgeBtn.className = "btn btn-sm btn-success fw-bold";
                wbBadgeBtn.innerHTML = '<i class="bi bi-lock-fill me-1"></i>Write Blocker: On';
            } else {
                wbBadgeBtn.className = "btn btn-sm btn-danger fw-bold";
                wbBadgeBtn.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>Write Blocker: Off';
            }
        }
    } catch (err) {}
}

// The top-right badge is now a link, not a direct toggle - switches to
// Settings, expands the Drive Management card (collapsed by default like
// every other Settings card), and scrolls it into view. The actual toggle
// lives inside that card, scoped to whichever drive is selected there.
function goToDriveManagement() {
    switchToTab('settings-tab');
    const navBtn = document.getElementById('settingsNavEject');
    if (navBtn) new bootstrap.Tab(navBtn).show();
}

// Shows the write-block status of whichever drive is selected in Drive
// Management's own dropdown - deliberately a fresh /api/system_info lookup
// for that specific drive, not the global isWriteBlockActive (that reflects
// whatever drive Acquisition has selected, which may be a different drive).
async function refreshDriveManagementStatus() {
    const drive = document.getElementById("ejectDriveSelect")?.value;
    const badge = document.getElementById("driveMgmtWriteBlockBadge");
    if (!badge) return;
    if (!drive) {
        badge.className = 'badge bg-secondary';
        badge.textContent = 'Select a drive';
        return;
    }
    badge.className = 'badge bg-secondary';
    badge.textContent = 'Checking...';
    try {
        const res = await fetch(`/api/system_info?drive=${encodeURIComponent(drive)}`);
        const data = await res.json();
        if (data.write_blocker_active) {
            badge.className = 'badge bg-success';
            badge.textContent = 'PROTECTED (Read-Only)';
        } else {
            badge.className = 'badge bg-danger';
            badge.textContent = 'UNLOCKED (Read-Write)';
        }
    } catch (err) {
        badge.className = 'badge bg-secondary';
        badge.textContent = 'Unknown';
    }
}

async function toggleWriteBlockForSelectedDrive() {
    const drive = document.getElementById("ejectDriveSelect")?.value;
    if (!drive) return showToast("Select a connected drive first.", 'warning');

    try {
        // Check this specific drive's current status first, rather than
        // trusting isWriteBlockActive - that global reflects whichever
        // drive Acquisition currently has selected, not necessarily this one.
        const statusRes = await fetch(`/api/system_info?drive=${encodeURIComponent(drive)}`);
        const statusData = await statusRes.json();
        const newEnableState = !statusData.write_blocker_active;

        const res = await fetch('/api/toggle_write_block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: newEnableState, drive })
        });
        const data = await res.json();
        if (data.success) {
            await refreshDriveManagementStatus();
            await fetchSystemInfo(); // keeps the top-right badge in sync if it's the same drive
            showToast(`Drive ${drive} Write-Blocker status set to: ${newEnableState ? 'PROTECTED (Read-Only)' : 'UNLOCKED (Read-Write)'}`, 'info');
        } else {
            showToast(`Write Blocker Toggle Failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        console.error("Write blocker toggle error:", err);
    }
}

async function refreshDrives() {
    try {
        const res = await fetch('/api/drives');
        currentDrivesList = await res.json();
        
        const driveSelects = document.querySelectorAll(".drive-select");
        driveSelects.forEach(selectEl => {
            selectEl.innerHTML = '<option value="">-- Choose Target Source Drive --</option>';
            currentDrivesList.forEach(dev => {
                const opt = document.createElement("option");
                opt.value = dev.device;
                opt.innerText = `${dev.device} - [${(dev.transport||'usb').toUpperCase()}] ${dev.model} (${dev.size})`;
                selectEl.appendChild(opt);
            });
        });
        checkSmartTelemetry();
    } catch (err) {}
}

async function checkSmartTelemetry() {
    const driveSelect = document.getElementById("driveSelect");
    const targetDrive = driveSelect ? driveSelect.value : "";
    const healthBadge = document.getElementById("lblHealthBadge");

    const devPathLbl = document.getElementById("lblDevicePath");
    if (devPathLbl) devPathLbl.innerText = targetDrive || "--";
    if (!targetDrive) return;

    try {
        const res = await fetch('/api/smart_check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive: targetDrive })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("lblModel")) document.getElementById("lblModel").innerText = data.vendor_model || "--";
            if (document.getElementById("lblMediaType")) document.getElementById("lblMediaType").innerText = data.media_type || "--";
            if (document.getElementById("lblCapacity")) document.getElementById("lblCapacity").innerText = data.capacity || "--";
            if (document.getElementById("lblSerial")) document.getElementById("lblSerial").innerText = data.serial || "--";
            
            if (healthBadge) {
                healthBadge.className = data.healthy ? "badge bg-success" : "badge bg-danger";
                healthBadge.innerHTML = data.healthy ? 'PASSED (GOOD DRIVE)' : 'FAILING';
            }
            if (document.getElementById("lblTemp")) document.getElementById("lblTemp").innerText = data.temperature ? `${data.temperature} °C` : "N/A";
            if (document.getElementById("lblReallocated")) document.getElementById("lblReallocated").innerText = data.reallocated_sectors !== undefined ? data.reallocated_sectors : "0";
            if (document.getElementById("lblPending")) document.getElementById("lblPending").innerText = data.pending_sectors !== undefined ? data.pending_sectors : "0";
            if (document.getElementById("lblPowerHours")) document.getElementById("lblPowerHours").innerText = data.power_on_hours ? `${data.power_on_hours} hrs` : "N/A";
        }
        fetchSystemInfo();
    } catch (err) {}
}

// --- BitLocker pre-acquisition unlock (dislocker) ---
// Lets an examiner unlock a BitLocker-encrypted physical source drive with
// its recovery key/password before starting acquisition, so dc3dd/dcfldd/
// ewfacquire/plain dd image the decrypted volume instead of raw encrypted
// bytes. Reuses the #bitlockerKey field (also recorded as case-report
// documentation regardless of whether this unlock flow is used at all).
// --- Consolidated "Encrypted Volume" pre-acquisition unlock (BitLocker/
// LUKS/VeraCrypt via cryptsetup/dislocker) - replaces what used to be 2
// separate near-identical blocks of 6 functions each with ONE generic set,
// parameterized by encVolTypeSelect's current value, VeraCrypt added as a
// 3rd type without becoming a 3rd copy-pasted block (2026-08-26, matching
// this project's own established "don't let a 3rd near-duplicate block
// appear" precedent - see the dated CLAUDE.md entry). Each type's own
// backend route (/api/${type}/...) and credential JSON field name differ
// slightly - captured once here, not re-derived at each call site.
const ENC_VOL_CREDENTIAL_FIELD = { bitlocker: 'recovery_key', luks: 'passphrase', veracrypt: 'password' };
const ENC_VOL_TYPE_LABELS = { bitlocker: 'BitLocker', luks: 'LUKS', veracrypt: 'VeraCrypt' };
const ENC_VOL_CREDENTIAL_PLACEHOLDER = {
    bitlocker: 'Recovery Key / Password', luks: 'Passphrase', veracrypt: 'Password',
};

function toggleEncVolSection() {
    const on = document.getElementById("encVolSourceToggle")?.checked ?? false;
    const controls = document.getElementById("encVolSourceControls");
    if (controls) controls.style.display = on ? '' : 'none';
    updateEncVolCredentialHelp();
    if (on) loadEncVolPartitions();
}

// Condensed 2026-08-27 from 3 separate always-visible doc-only fields (one
// per type, each with its own paragraph help text) down to ONE field
// (#encVolCredential) that now serves both purposes at once - optional
// case-report documentation regardless of whether "Also unlock..." is
// checked, AND (when it is checked) the actual unlock() credential itself,
// keyed by whichever type is currently selected in #encVolTypeSelect. This
// also removes the old double-entry annoyance (typing the same key twice -
// once to unlock, once again in a separate field just to have it recorded).
function updateEncVolCredentialHelp() {
    const on = document.getElementById("encVolSourceToggle")?.checked ?? false;
    const type = document.getElementById("encVolTypeSelect")?.value || 'bitlocker';
    const noun = { bitlocker: 'key', luks: 'passphrase', veracrypt: 'password' }[type] || 'key';
    const help = document.getElementById("encVolCredentialHelp");
    if (!help) return;
    help.textContent = on
        ? `Used both to unlock the encrypted volume above AND recorded in the case report as documentation.`
        : `Recorded in the case report as documentation only - imaging still captures the source exactly as found (encrypted); the ${noun} is not used to decrypt anything unless "Also unlock this volume now" below is checked.`;
}

function onEncVolTypeChange() {
    const status = document.getElementById("encVolStatus");
    if (status) status.textContent = "Select the encrypted partition, enter the recovery key/password above, then click Unlock.";
    const credInput = document.getElementById("encVolCredential");
    if (credInput) credInput.placeholder = `${ENC_VOL_CREDENTIAL_PLACEHOLDER[document.getElementById("encVolTypeSelect")?.value] || 'Recovery Key / Password'} (optional)`;
    updateEncVolCredentialHelp();
    if (document.getElementById("encVolSourceToggle")?.checked) loadEncVolPartitions();
}

async function loadEncVolPartitions() {
    const type = document.getElementById("encVolTypeSelect")?.value || 'bitlocker';
    const device = document.getElementById("driveSelect")?.value || "";
    const select = document.getElementById("encVolPartitionSelect");
    const status = document.getElementById("encVolStatus");
    if (!select) return;
    if (!device) {
        select.innerHTML = '<option value="">-- Select a target drive above first --</option>';
        return;
    }
    select.innerHTML = '<option value="">Scanning...</option>';
    try {
        const res = await fetch(`/api/${type}/partitions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device })
        });
        const data = await res.json();
        select.innerHTML = '';
        // The whole device itself is always offered too - some encrypted
        // USB media (BitLocker-To-Go, a whole-device LUKS/VeraCrypt
        // container) is formatted with no partition table at all, so the
        // encrypted volume IS the whole disk, not a partition within it.
        const wholeOpt = document.createElement("option");
        wholeOpt.value = device;
        wholeOpt.textContent = `${device} (whole device, no partition table)`;
        select.appendChild(wholeOpt);
        if (data.success && data.partitions && data.partitions.length) {
            data.partitions.forEach(p => {
                const opt = document.createElement("option");
                opt.value = p.path;
                opt.textContent = `${p.path} - ${p.fstype || 'unknown fs'} (${p.size || '?'})`;
                select.appendChild(opt);
            });
        }
        if (status) status.textContent = data.success
            ? `Found ${(data.partitions || []).length} partition(s) on ${device}. Select the encrypted one, then Detect/Unlock.`
            : `Scan failed: ${data.error}`;
    } catch (err) {
        select.innerHTML = '<option value="">-- Scan failed --</option>';
    }
}

function getEncVolSelectedSource() {
    return document.getElementById("encVolPartitionSelect")?.value
        || document.getElementById("driveSelect")?.value
        || "";
}

async function detectEncVol() {
    const type = document.getElementById("encVolTypeSelect")?.value || 'bitlocker';
    const partition = getEncVolSelectedSource();
    const status = document.getElementById("encVolStatus");
    if (!partition) return showToast("Select a drive/partition first.", 'warning');
    if (status) status.textContent = `Checking for a ${ENC_VOL_TYPE_LABELS[type]} signature...`;
    try {
        const res = await fetch(`/api/${type}/detect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ partition })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Detect failed: ${data.error}`;
            return;
        }
        if (status) {
            // VeraCrypt's own detect route always returns is_bitlocker/
            // is_luks-shaped null (VeraCrypt volumes have no fixed
            // signature at all, by design) with an explanatory note -
            // shown directly rather than forced into the same true/false
            // phrasing the other two types use.
            if (data.note) {
                status.textContent = data.note;
            } else {
                const isMatch = data.is_bitlocker ?? data.is_luks;
                status.textContent = isMatch
                    ? `${partition} looks like ${ENC_VOL_TYPE_LABELS[type]} (filesystem type: ${data.fstype}). Enter the credential above and click Unlock.`
                    : `${partition} does not look like ${ENC_VOL_TYPE_LABELS[type]} (filesystem type: ${data.fstype || 'unrecognized'}). You can still try Unlock if you believe this is wrong.`;
            }
        }
    } catch (err) {
        if (status) status.textContent = "Detect failed - see console.";
    }
}

async function unlockEncVol() {
    const type = document.getElementById("encVolTypeSelect")?.value || 'bitlocker';
    const partition = getEncVolSelectedSource();
    const credential = document.getElementById("encVolCredential")?.value || "";
    const status = document.getElementById("encVolStatus");
    if (!partition) return showToast("Select a drive/partition first.", 'warning');
    if (!credential.trim()) return showToast(`Enter the ${ENC_VOL_CREDENTIAL_PLACEHOLDER[type]} first.`, 'warning');
    if (status) status.textContent = "Unlocking (this can take a few seconds)...";
    try {
        const res = await fetch(`/api/${type}/unlock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ partition, [ENC_VOL_CREDENTIAL_FIELD[type]]: credential })
        });
        const data = await res.json();
        if (!data.success) {
            if (status) status.textContent = `Unlock failed: ${data.error}`;
            showToast(`${ENC_VOL_TYPE_LABELS[type]} unlock failed: ${data.error}`, 'danger');
            return;
        }
        encVolActiveMountId = data.mount_id;
        encVolUnlockedSourcePath = data.source_path;
        encVolActiveType = type;
        if (status) status.textContent = `Unlocked. Acquisition will image the decrypted volume (not ${partition} directly) as long as this stays unlocked. Click Lock / Cleanup when finished.`;
        const lockBtn = document.getElementById("btnLockEncVol");
        if (lockBtn) lockBtn.style.display = '';
        showToast(`${ENC_VOL_TYPE_LABELS[type]} volume unlocked - acquisition will use the decrypted volume.`, 'success');
    } catch (err) {
        if (status) status.textContent = "Unlock failed - see console.";
    }
}

async function lockEncVol() {
    if (!encVolActiveMountId || !encVolActiveType) return;
    const type = encVolActiveType;
    const status = document.getElementById("encVolStatus");
    try {
        const res = await fetch(`/api/${type}/lock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mount_id: encVolActiveMountId })
        });
        const data = await res.json();
        if (!data.success) {
            showToast(`Lock/cleanup failed: ${data.error}`, 'danger');
            return;
        }
        encVolActiveMountId = null;
        encVolUnlockedSourcePath = null;
        encVolActiveType = null;
        if (status) status.textContent = "Locked and unmounted. Select the encrypted partition and Unlock again if needed.";
        const lockBtn = document.getElementById("btnLockEncVol");
        if (lockBtn) lockBtn.style.display = 'none';
        showToast(`${ENC_VOL_TYPE_LABELS[type]} volume locked/unmounted.`, 'success');
    } catch (err) {
        showToast("Lock/cleanup failed - see console.", 'danger');
    }
}

// --- Parameterized Network Shares Engine ---
async function loadNetworkHistory() {
    try {
        const res = await fetch('/api/mount_history');
        const history = await res.json();
        const shareSelects = [document.getElementById("serverShareSelect")];
        
        shareSelects.forEach(shareSelect => {
            if (!shareSelect) return;
            shareSelect.innerHTML = '<option value="">Select Exported Share...</option>';

            if (history.length > 0) {
                const grp = document.createElement("optgroup");
                grp.label = "Recent Mount History";
                history.forEach(item => {
                    const opt = document.createElement("option");
                    opt.value = item.share;
                    opt.dataset.host = item.host;
                    opt.dataset.protocol = item.protocol;
                    opt.dataset.mountPoint = item.mount_point;
                    opt.innerText = `[${item.protocol.toUpperCase()}] ${item.host}:${item.share} -> ${item.mount_point}`;
                    grp.appendChild(opt);
                });
                shareSelect.appendChild(grp);
            }
        });
    } catch (err) {}
}

// Shows/hides the credential fields, SSH-key textarea, and the
// share-dropdown-vs-free-text-path toggle based on the selected protocol.
// NFS: neither credentials nor a key, share comes from Query Shares.
// SMB: optional credentials (guest fallback if blank, see app.py), share
// comes from Query Shares. SFTP: credentials required (no anonymous SFTP)
// plus an optional key instead of a password, and there's no share-listing
// equivalent to query - the examiner types the remote path directly.
function updateNetworkMountControls() {
    const protocol = document.getElementById("netProtocol")?.value || "smb";
    const credRow = document.getElementById("netCredentialsRow");
    const keyRow = document.getElementById("netSftpKeyRow");
    const shareSelect = document.getElementById("serverShareSelect");
    const sftpPath = document.getElementById("netSftpPath");
    const queryBtn = document.getElementById("btnQueryShares");

    if (credRow) credRow.style.display = (protocol === 'smb' || protocol === 'sftp') ? '' : 'none';
    if (keyRow) keyRow.style.display = (protocol === 'sftp') ? '' : 'none';
    if (shareSelect) shareSelect.style.display = (protocol === 'sftp') ? 'none' : '';
    if (sftpPath) sftpPath.style.display = (protocol === 'sftp') ? '' : 'none';
    if (queryBtn) queryBtn.style.display = (protocol === 'sftp') ? 'none' : '';
}

async function queryNetworkShares(hostId, protocolId, shareSelectId, mountStatusId) {
    const hostEl = document.getElementById(hostId);
    const host = hostEl ? hostEl.value.trim() : "";
    const protocol = document.getElementById(protocolId)?.value || "smb";
    const shareSelect = document.getElementById(shareSelectId);
    const mountStatus = document.getElementById(mountStatusId);
    const user = document.getElementById("netUser")?.value.trim() || "";
    const pass = document.getElementById("netPass")?.value || "";

    if (!host) return showToast("Please enter a server IP address.", 'warning');

    if (mountStatus) mountStatus.innerText = "Querying available exports...";
    if (shareSelect) shareSelect.innerHTML = '<option value="">Querying...</option>';

    try {
        const res = await fetch('/api/list_server_shares', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, user, pass })
        });
        const data = await res.json();

        if (data.success && data.shares.length > 0) {
            if (shareSelect) {
                shareSelect.innerHTML = '<option value="">Select Exported Share...</option>';
                data.shares.forEach(s => {
                    const opt = document.createElement("option"); 
                    opt.value = s; 
                    opt.innerText = s; 
                    shareSelect.appendChild(opt);
                });
            }
            if (mountStatus) mountStatus.innerText = `Found ${data.shares.length} exported share(s).`;
        } else {
            if (shareSelect) shareSelect.innerHTML = '<option value="">Query Failed / No Shares</option>';
            if (mountStatus) mountStatus.innerText = `Query Error: ${data.error || 'No shares returned'}`;
        }
    } catch (err) {
        if (mountStatus) mountStatus.innerText = `Query Failed: ${err.message}`;
    }
}

async function mountNetworkDrive(hostId, protocolId, shareSelectId, mountStatusId) {
    const host = document.getElementById(hostId)?.value.trim() || "";
    const protocol = document.getElementById(protocolId)?.value || "smb";
    // SFTP has no share-listing dropdown to pick from - the examiner types
    // the remote path directly (see updateNetworkMountControls()).
    const share = protocol === 'sftp'
        ? (document.getElementById("netSftpPath")?.value.trim() || "")
        : (document.getElementById(shareSelectId)?.value || "");
    const mountStatus = document.getElementById(mountStatusId);
    const user = document.getElementById("netUser")?.value.trim() || "";
    const pass = document.getElementById("netPass")?.value || "";
    const key = protocol === 'sftp' ? (document.getElementById("netSftpKey")?.value || "") : "";
    const autoConnect = document.getElementById("netAutoConnect")?.checked || false;

    if (!share) return showToast(protocol === 'sftp' ? "Please enter a remote path first." : "Please select or enter an exported share name first.", 'warning');
    if (protocol === 'sftp' && !user) return showToast("SFTP requires a username.", 'warning');

    if (mountStatus) mountStatus.innerText = "Mounting share...";

    try {
        const res = await fetch('/api/mount_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, share, user, pass, key, auto_connect: autoConnect })
        });
        const data = await res.json();

        if (data.success) {
            // Mounting is system-wide now (Settings), not tied to any one
            // tab's destination field - just surface the new path clearly
            // so the examiner can Browse into it from wherever they need it.
            if (mountStatus) {
                mountStatus.innerHTML = '';
                const okLine = document.createElement('div');
                okLine.className = 'text-success fw-bold';
                okLine.textContent = `Mounted: ${data.mount_point}`;
                const hintLine = document.createElement('div');
                hintLine.className = 'text-subtle';
                hintLine.textContent = autoConnect
                    ? 'Use any tab\'s Browse button to navigate into this path. It will also reconnect automatically on every future reboot.'
                    : 'Use any tab\'s Browse button to navigate into this path.';
                mountStatus.appendChild(okLine);
                mountStatus.appendChild(hintLine);
            }

            loadExplorer(data.mount_point);
            loadNetworkHistory();
            loadAutoMountShares();
        } else {
            if (mountStatus) mountStatus.innerText = `Mount Error: ${data.error}`;
            showToast(`Mount Failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        if (mountStatus) mountStatus.innerText = `Mount Failed: ${err.message}`;
    }
}

// --- Auto-Connect Shares (reconnect on every app/station start) ---
async function loadAutoMountShares() {
    const container = document.getElementById("autoMountSharesList");
    if (!container) return;
    try {
        const res = await fetch('/api/network/auto_mounts');
        const data = await res.json();
        const shares = (data.success && data.shares) || [];

        container.innerHTML = '';
        if (shares.length === 0) {
            container.innerHTML = '<span class="text-subtle small">No shares configured to auto-connect yet.</span>';
            return;
        }

        shares.forEach(s => {
            const row = document.createElement('div');
            row.className = 'd-flex justify-content-between align-items-center bg-dark p-2 rounded mb-1 border border-secondary';

            const info = document.createElement('div');
            info.className = 'small';
            const line1 = document.createElement('div');
            line1.className = 'fw-bold text-info';
            line1.textContent = `${s.protocol.toUpperCase()} - ${s.host}:${s.share}`;
            const line2 = document.createElement('div');
            line2.className = 'text-subtle';
            const authNote = s.has_password ? ' - encrypted password stored' : (s.has_key ? ' - encrypted key stored' : '');
            line2.textContent = `${s.mount_point}${s.user ? ' - user: ' + s.user : ''}${authNote}`;
            info.appendChild(line1);
            info.appendChild(line2);

            const removeBtn = document.createElement('button');
            removeBtn.className = 'btn btn-sm btn-outline-danger';
            removeBtn.innerHTML = '<i class="bi bi-x-lg"></i>';
            removeBtn.title = 'Stop auto-connecting this share';
            removeBtn.addEventListener('click', () => removeAutoMountShare(s.id));

            row.appendChild(info);
            row.appendChild(removeBtn);
            container.appendChild(row);
        });
    } catch (err) {
        container.innerHTML = '<span class="text-danger small">Failed to load auto-connect shares.</span>';
    }
}

async function removeAutoMountShare(id) {
    if (!confirm('Stop auto-connecting this share on future reboots? The current mount (if any) is left untouched.')) return;
    try {
        const res = await fetch(`/api/network/auto_mounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
        const data = await res.json();
        if (!data.success) showToast(`Failed to remove: ${data.error}`, 'danger');
        loadAutoMountShares();
    } catch (err) {}
}

// --- Network Configuration (station's own IPv4 addressing, DHCP or static) ---
// Distinct from Network Drive Mounting above (mounts remote evidence
// shares). Every Apply here goes through a server-side auto-revert: the
// countdown/banner below is purely a UI reflection of that server-side
// timer, not the safety mechanism itself - if this tab is closed, refreshed,
// or the connection drops entirely, the station still reverts on schedule
// regardless, since the actual revert runs from a background thread in
// app.py, not from anything happening in this browser tab.
let networkRevertToken = null;
let networkRevertCountdownInterval = null;
let networkRevertWindowSeconds = 60; // overwritten from the server's actual REVERT_WINDOW_SECONDS on first load

function networkDeviceFieldId(device, field) {
    return `networkIface_${device}_${field}`;
}

function renderNetworkDeviceCard(dev) {
    const card = document.createElement('div');
    card.className = 'border border-secondary rounded-2 p-3 mb-3';

    const header = document.createElement('div');
    header.className = 'd-flex justify-content-between align-items-center mb-2';
    const title = document.createElement('div');
    title.className = 'fw-bold text-light';
    const icon = dev.type === 'wifi' ? 'bi-wifi' : 'bi-ethernet';
    title.innerHTML = `<i class="bi ${icon} me-2"></i>`;
    title.append(`${dev.device}${dev.connection ? ' (' + dev.connection + ')' : ''}`); // connection name may be examiner-set text on some systems - appended as a text node, not interpolated into innerHTML
    const stateBadge = document.createElement('span');
    const stateOk = dev.state === 'connected';
    stateBadge.className = `badge ${stateOk ? 'bg-success' : 'bg-secondary'}`;
    stateBadge.textContent = dev.state;
    header.appendChild(title);
    header.appendChild(stateBadge);
    card.appendChild(header);

    if (!dev.connection) {
        const note = document.createElement('div');
        note.className = 'text-subtle small';
        note.textContent = 'No connection profile found for this device - nothing to configure.';
        card.appendChild(note);
        return card;
    }

    const methodId = networkDeviceFieldId(dev.device, 'method');
    const addrId = networkDeviceFieldId(dev.device, 'address');
    const prefixId = networkDeviceFieldId(dev.device, 'prefix');
    const gwId = networkDeviceFieldId(dev.device, 'gateway');
    const dnsId = networkDeviceFieldId(dev.device, 'dns');
    const manualRowId = networkDeviceFieldId(dev.device, 'manualRow');

    const methodRow = document.createElement('div');
    methodRow.className = 'row g-2 mb-2';
    const methodCol = document.createElement('div');
    methodCol.className = 'col-md-4';
    const methodSelect = document.createElement('select');
    methodSelect.className = 'form-select form-select-sm';
    methodSelect.id = methodId;
    methodSelect.innerHTML = `<option value="auto">Automatic (DHCP)</option><option value="manual">Manual (Static)</option>`;
    methodSelect.value = dev.ipv4.method === 'manual' ? 'manual' : 'auto';
    methodSelect.onchange = () => updateNetworkMethodRow(dev.device);
    methodCol.appendChild(methodSelect);
    methodRow.appendChild(methodCol);

    const currentCol = document.createElement('div');
    currentCol.className = 'col-md-8 small text-subtle d-flex align-items-center';
    currentCol.textContent = dev.ipv4.method === 'manual'
        ? `Currently: ${dev.ipv4.address}/${dev.ipv4.prefix}${dev.ipv4.gateway ? ', gateway ' + dev.ipv4.gateway : ''}`
        : 'Currently: DHCP (automatic)';
    methodRow.appendChild(currentCol);
    card.appendChild(methodRow);

    const manualRow = document.createElement('div');
    manualRow.id = manualRowId;
    manualRow.className = 'row g-2 mb-2';
    manualRow.style.display = dev.ipv4.method === 'manual' ? '' : 'none';
    manualRow.innerHTML = `
        <div class="col-md-4"><input type="text" id="${addrId}" class="form-control form-control-sm" placeholder="IP Address (e.g. 192.168.1.50)" value="${dev.ipv4.address || ''}"></div>
        <div class="col-md-2"><input type="number" id="${prefixId}" class="form-control form-control-sm" placeholder="Prefix" min="1" max="32" value="${dev.ipv4.prefix || 24}"></div>
        <div class="col-md-3"><input type="text" id="${gwId}" class="form-control form-control-sm" placeholder="Gateway" value="${dev.ipv4.gateway || ''}"></div>
        <div class="col-md-3"><input type="text" id="${dnsId}" class="form-control form-control-sm" placeholder="DNS (comma-separated)" value="${(dev.ipv4.dns || []).join(', ')}"></div>
    `; // dev.ipv4.* values come from this station's own nmcli config, not examiner/attacker-controlled input - safe to interpolate as attribute values here
    card.appendChild(manualRow);

    const applyBtn = document.createElement('button');
    applyBtn.className = 'btn btn-sm btn-primary fw-bold';
    applyBtn.innerHTML = '<i class="bi bi-check2-circle me-1"></i>Apply';
    applyBtn.onclick = () => applyNetworkConfig(dev.device);
    card.appendChild(applyBtn);

    return card;
}

function updateNetworkMethodRow(device) {
    const method = document.getElementById(networkDeviceFieldId(device, 'method'))?.value;
    const row = document.getElementById(networkDeviceFieldId(device, 'manualRow'));
    if (row) row.style.display = method === 'manual' ? '' : 'none';
}

async function loadNetworkConfig() {
    const container = document.getElementById('networkIfaceDevices');
    if (!container) return;

    try {
        const res = await fetch('/api/network/config');
        const data = await res.json();
        if (!data.success) {
            container.innerHTML = '<span class="text-danger small">Failed to load network devices.</span>';
            return;
        }

        if (data.revert_window_seconds) networkRevertWindowSeconds = data.revert_window_seconds;

        container.innerHTML = '';
        if (data.devices.length === 0) {
            container.innerHTML = '<span class="text-subtle small">No configurable network devices found.</span>';
        } else {
            data.devices.forEach(dev => container.appendChild(renderNetworkDeviceCard(dev)));
        }

        if (data.pending_revert && !data.pending_revert.confirmed) {
            networkRevertToken = data.pending_revert.revert_token;
            showNetworkRevertBanner(data.pending_revert.device, data.pending_revert.revert_at);
        } else {
            hideNetworkRevertBanner();
        }
    } catch (err) {
        container.innerHTML = `<span class="text-danger small">Failed to load network devices: ${err.message}</span>`;
    }
}

async function applyNetworkConfig(device) {
    const method = document.getElementById(networkDeviceFieldId(device, 'method'))?.value;
    const body = { device, method };

    if (method === 'manual') {
        body.address = document.getElementById(networkDeviceFieldId(device, 'address'))?.value.trim() || '';
        body.prefix = document.getElementById(networkDeviceFieldId(device, 'prefix'))?.value || '';
        body.gateway = document.getElementById(networkDeviceFieldId(device, 'gateway'))?.value.trim() || '';
        body.dns = document.getElementById(networkDeviceFieldId(device, 'dns'))?.value.trim() || '';
    }

    const warning = method === 'manual'
        ? `Apply a static IP to ${device}? If any value is wrong, this may disconnect your session immediately. The station will automatically revert to its current settings in ${networkRevertWindowSeconds}s unless you confirm afterward.`
        : `Switch ${device} back to DHCP? This may change its IP address and disconnect your session. The station will automatically revert to its current settings in ${networkRevertWindowSeconds}s unless you confirm afterward.`;
    if (!confirm(warning)) return;

    try {
        const res = await fetch('/api/network/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (data.success) {
            networkRevertToken = data.revert_token;
            showNetworkRevertBanner(device, data.revert_at);
        } else {
            showToast(`Apply failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        showToast(`Apply failed: ${err.message}`, 'danger');
    }
}

async function confirmNetworkConfig() {
    if (!networkRevertToken) return;
    try {
        const res = await fetch('/api/network/confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ revert_token: networkRevertToken })
        });
        const data = await res.json();
        if (data.success) {
            hideNetworkRevertBanner();
        } else {
            showToast(data.error || 'Confirmation failed.', 'danger');
        }
    } catch (err) {
        showToast(`Confirmation failed: ${err.message}`, 'danger');
    }
}

function showNetworkRevertBanner(device, revertAt) {
    const banner = document.getElementById('networkRevertBanner');
    const text = document.getElementById('networkRevertBannerText');
    if (!banner || !text) return;
    banner.style.display = '';

    if (networkRevertCountdownInterval) clearInterval(networkRevertCountdownInterval);
    const tick = () => {
        const remaining = Math.max(0, Math.ceil(revertAt - (Date.now() / 1000)));
        if (remaining <= 0) {
            text.textContent = `Reverting ${device} to its previous settings now...`;
            clearInterval(networkRevertCountdownInterval);
            // Re-check server state shortly after the window closes, since the
            // actual revert runs server-side regardless of this tab's state.
            setTimeout(loadNetworkConfig, 3000);
            return;
        }
        text.textContent = `New settings applied to ${device} - reverting automatically in ${remaining}s unless confirmed.`;
    };
    tick();
    networkRevertCountdownInterval = setInterval(tick, 1000);
}

function hideNetworkRevertBanner() {
    const banner = document.getElementById('networkRevertBanner');
    if (banner) banner.style.display = 'none';
    if (networkRevertCountdownInterval) clearInterval(networkRevertCountdownInterval);
    networkRevertCountdownInterval = null;
    networkRevertToken = null;
}

async function startAcquisition() {
    const fmt = document.getElementById("imageFormatSelect")?.value;
    // Logical Acquisition doesn't image a raw device at all (it copies
    // already-mounted folders), so it's dispatched here before the
    // drive-selection guard below, which doesn't apply to it.
    if (fmt === 'logical') return startLogicalAcquisition();

    const rawSource = document.getElementById("driveSelect")?.value;
    const dest = document.getElementById("destPath")?.value;

    if (!rawSource) return showToast("Select target evidence drive first.", 'warning');

    // ddrescue deliberately never uses the unlocked (decrypted) source - see
    // the matching comment in app.py's start_ddrescue(): its whole purpose
    // is direct-I/O sector-level recovery against a real block device, which
    // doesn't apply to an already-decrypted FUSE/dm-mapper virtual source.
    // Every other format substitutes the decrypted path transparently - the
    // backend's _resolve_acquisition_source() only trusts it because it was
    // created by this app's own unlock call, never client-supplied otherwise.
    // Only one encrypted-volume type can ever be unlocked at once here
    // (encVolActiveType/encVolUnlockedSourcePath are a single trio, not one
    // per type - see their declaration) - no BitLocker-vs-LUKS-vs-VeraCrypt
    // priority logic needed the way an earlier, pre-consolidation version
    // of this code needed for 2 separate variable trios.
    const useUnlockedSource = fmt !== 'ddrescue' && !!encVolUnlockedSourcePath;
    const source = useUnlockedSource ? encVolUnlockedSourcePath : rawSource;

    const metadata = {
        case_number: document.getElementById("caseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("evidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("examiner")?.value || "UNSPECIFIED",
        notes: document.getElementById("notes")?.value || "None"
    };
    // Condensed 2026-08-27 - one credential field (#encVolCredential) now
    // covers all 3 encryption types (see updateEncVolCredentialHelp()'s own
    // comment); dispatched here by whichever type is currently selected
    // into the 3 distinct backend field names start_imaging()/
    // start_ddrescue() still expect, leaving the other two empty.
    const encVolDocType = document.getElementById("encVolTypeSelect")?.value || 'bitlocker';
    const encVolDocCredential = document.getElementById("encVolCredential")?.value || "";
    const bitlockerKey = encVolDocType === 'bitlocker' ? encVolDocCredential : "";
    const luksPassphrase = encVolDocType === 'luks' ? encVolDocCredential : "";
    const veracryptPassword = encVolDocType === 'veracrypt' ? encVolDocCredential : "";

    let endpoint, body;

    if (fmt === 'ddrescue') {
        const strategy = document.getElementById("ddrescueStrategySelect")?.value || "stage1_fast";
        const retries = document.getElementById("ddrescueRetries")?.value || "3";
        const directMode = document.getElementById("ddrescueDirect")?.checked ?? false;
        endpoint = '/api/start_ddrescue';
        body = { source, destination: dest, strategy, retry_passes: retries, direct_mode: directMode, metadata, bitlocker_key: bitlockerKey, luks_passphrase: luksPassphrase, veracrypt_password: veracryptPassword };
    } else {
        const compression = document.getElementById("compressionSelect")?.value;
        const split_size = document.getElementById("splitSizeSelect")?.value;
        const keep_raw = document.getElementById("affKeepRaw")?.checked ?? true;
        const selectedHashes = [];
        if (document.getElementById("hashMd5")?.checked) selectedHashes.push("md5");
        if (document.getElementById("hashSha1")?.checked) selectedHashes.push("sha1");
        if (document.getElementById("hashSha256")?.checked) selectedHashes.push("sha256");
        endpoint = '/api/start_imaging';
        body = { source, destination: dest, format: fmt, compression, split_size, hashes: selectedHashes, metadata, keep_raw, bitlocker_key: bitlockerKey, luks_passphrase: luksPassphrase, veracrypt_password: veracryptPassword };
        // Tier 2 chaining - AFF is excluded even though it shares this branch/
        // endpoint, since it runs execution_worker_aff() server-side, not the
        // shared execution_worker() the chaining logic hooks into (matches
        // toggleFormatControls() already hiding the checkbox for AFF, but
        // checked again here defensively in case the row's display state and
        // the format dropdown's value were ever out of sync).
        if (fmt !== 'aff' && document.getElementById("chainAutoAnalyzeCheck")?.checked) {
            if (activeCase) {
                body.chain_auto_analyze = true;
                body.case_folder = activeCase.case_folder;
            } else {
                showToast('No active case - "Automatically run Auto Analyze" needs one, so it was not enabled for this run.', 'warning');
            }
        }
    }

    if (fmt === 'ddrescue' && encVolUnlockedSourcePath) {
        showToast(`ddrescue does not support the unlocked ${ENC_VOL_TYPE_LABELS[encVolActiveType] || 'encrypted'} volume - it will image the raw encrypted device directly.`, 'warning');
    }

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = true;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = false;
            // The backend keeps the dislocker/cryptsetup mount alive for the
            // whole job and unmounts it automatically once the job finishes -
            // mirror that transition in fetchProgress() so the UI doesn't
            // keep offering "Lock / Cleanup" for a mount that's already gone.
            if (useUnlockedSource) encVolMountConsumedByJob = true;
        } else showToast(`Start Failed: ${data.error}`, 'danger');
    } catch (err) {}
}

// The right-hand pane shows either the live terminal (background jobs,
// TestDisk's raw partition dump) or a structured label/value panel (Mapfile
// Inspector's already-labeled fields) - never both at once.
function resetRecoveryOutputView() {
    const term = document.getElementById("recoveryLogOutput");
    const structured = document.getElementById("recoveryStructuredOutput");
    if (structured) { structured.style.display = 'none'; structured.innerHTML = ''; }
    if (term) term.style.display = '';
}

function showRecoveryStructuredOutput() {
    const term = document.getElementById("recoveryLogOutput");
    const structured = document.getElementById("recoveryStructuredOutput");
    if (term) term.style.display = 'none';
    if (structured) structured.style.display = '';
}

// Fetched once per page load (Settings' own Keyword Lists CRUD invalidates
// this the same way other station-config caches do - nothing else edits
// it), used both here and by loadRecoveryKeywordListsChecklist() below.
let keywordListsCache = null;

async function fetchKeywordLists(forceRefresh) {
    if (keywordListsCache && !forceRefresh) return keywordListsCache;
    try {
        const res = await fetch('/api/settings/keyword_lists');
        const data = await res.json();
        keywordListsCache = (data.success && data.lists) || [];
    } catch (err) {
        keywordListsCache = [];
    }
    return keywordListsCache;
}

async function loadRecoveryKeywordListsChecklist() {
    const container = document.getElementById("recoveryKeywordListsContainer");
    if (!container) return;
    const lists = await fetchKeywordLists();
    container.innerHTML = '';
    if (lists.length === 0) {
        container.innerHTML = '<span class="text-subtle">No saved keyword lists yet - create one in Settings &gt; Case &amp; Reporting.</span>';
        return;
    }
    lists.forEach(l => {
        const row = document.createElement('div');
        row.className = 'form-check';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.className = 'form-check-input recovery-keyword-list-check';
        input.id = `recoveryKwList_${l.id}`;
        input.value = l.id;
        const label = document.createElement('label');
        label.className = 'form-check-label';
        label.htmlFor = input.id;
        label.textContent = `${l.name} (${l.terms.length} term${l.terms.length === 1 ? '' : 's'}${l.is_regex ? ', regex' : ''})`; // examiner-entered name - text node only
        row.appendChild(input);
        row.appendChild(label);
        container.appendChild(row);
    });
}

function updateRecoveryToolControls() {
    const tool = document.getElementById("recoveryToolSelect")?.value;
    const sourceRow = document.getElementById("recoverySourceRow");
    const destCol = document.getElementById("recoveryDestCol");
    const mapfileRow = document.getElementById("recoveryMapfileRow");
    const metadataRow = document.getElementById("recoveryMetadataRow");
    const keywordListsRow = document.getElementById("recoveryKeywordListsRow");
    const stopBtn = document.getElementById("btnRecoveryStop");
    const startLabel = document.getElementById("btnRecoveryStartLabel");
    const helpText = document.getElementById("recoveryToolHelpText");

    resetRecoveryOutputView();

    const isMapfile = tool === 'mapfile_inspect';
    const isTestdisk = tool === 'testdisk_analyze';
    const isTriageScan = tool === 'triage_scan';
    const isSyncTool = isMapfile || isTestdisk;

    if (sourceRow) sourceRow.style.display = isMapfile ? 'none' : '';
    if (mapfileRow) mapfileRow.style.display = isMapfile ? '' : 'none';
    if (destCol) destCol.style.display = isTestdisk ? 'none' : '';
    if (metadataRow) metadataRow.style.display = isSyncTool ? 'none' : '';
    if (keywordListsRow) {
        keywordListsRow.style.display = isTriageScan ? '' : 'none';
        if (isTriageScan) loadRecoveryKeywordListsChecklist();
    }
    // Stop only makes sense for background jobs - the two synchronous
    // tools (mapfile inspect, testdisk analyze) return immediately.
    if (stopBtn) stopBtn.style.display = isSyncTool ? 'none' : '';

    if (startLabel) {
        startLabel.textContent = isMapfile ? 'Inspect Mapfile' : isTestdisk ? 'Analyze Partitions' : 'Start Recovery';
    }

    const HELP = {
        photorec: "Recovers files by matching known file signatures - works even on formatted or damaged drives, but recovered files lose their original names/folder structure.",
        extundelete: "Recovers deleted files from ext2/3/4 Linux filesystems via the filesystem journal - can restore original filenames/paths, unlike carving tools. Won't help on FAT/NTFS/APFS/HFS+.",
        foremost: "Alternative to PhotoRec - narrower format support, sometimes faster for common types. Scans for all supported file types by default.",
        scalpel: "Multithreaded file carving, often faster than PhotoRec/foremost on larger images - but only recovers the types enabled in scalpel.conf (jpg/png/gif/pdf/zip by default).",
        triage_scan: "Built-in scan for emails, URLs, IP addresses, card-like numbers, and phone numbers - no external tool, works on any system. Writes one text file per category.",
        testdisk_analyze: "Read-only listing of partitions TestDisk can find on the source - never writes anything back, unlike TestDisk's separate repair mode (not exposed here).",
        mapfile_inspect: "Reviews a completed ddrescue run's .map file for a bad-sector summary - point it at the .map file a prior ddrescue acquisition wrote.",
    };
    if (helpText) helpText.textContent = HELP[tool] || '';
}

async function startRecoveryTool() {
    const tool = document.getElementById("recoveryToolSelect")?.value;

    if (tool === 'mapfile_inspect') {
        return inspectDdrescueMapfile();
    }
    resetRecoveryOutputView();

    const sourcePath = document.getElementById("recoverySourcePath")?.value.trim();
    const sourceDrive = document.getElementById("recoverySourceDrive")?.value;
    const source = sourcePath || sourceDrive;

    if (!source) {
        showToast("Select a source drive, or browse to a source image file, first.", 'warning');
        return;
    }

    if (tool === 'testdisk_analyze') {
        const outEl = document.getElementById("recoveryLogOutput");
        if (outEl) outEl.textContent = "Running...";
        try {
            const res = await fetch('/api/recovery/testdisk_analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source })
            });
            const data = await res.json();
            if (outEl) outEl.textContent = data.success ? data.output : `[ERROR] ${data.error}`;
        } catch (err) {
            if (outEl) outEl.textContent = '[REQUEST FAILED]';
        }
        return;
    }

    const dest = document.getElementById("recoveryDest")?.value || "/mnt";
    const metadata = {
        case_number: document.getElementById("recoveryCaseNum")?.value || "RECOVERY",
        evidence_id: document.getElementById("recoveryEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("recoveryExaminer")?.value || "UNSPECIFIED",
        notes: `${tool} recovery`
    };

    const ENDPOINTS = {
        photorec: '/api/recovery/start_photorec',
        extundelete: '/api/recovery/start_extundelete',
        foremost: '/api/recovery/start_foremost',
        scalpel: '/api/recovery/start_scalpel',
        triage_scan: '/api/recovery/start_triage_scan',
    };
    const endpoint = ENDPOINTS[tool];
    if (!endpoint) return;

    const body = { source, destination: dest, metadata };
    if (tool === 'triage_scan') {
        body.keyword_list_ids = [...document.querySelectorAll('.recovery-keyword-list-check:checked')].map(el => el.value);
    }

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("btnRecoveryStart")) document.getElementById("btnRecoveryStart").disabled = true;
            if (document.getElementById("btnRecoveryStop")) document.getElementById("btnRecoveryStop").disabled = false;
        } else {
            showToast(`Start Failed: ${data.error}`, 'danger');
        }
    } catch (err) {
        console.error(`Error starting ${tool}:`, err);
    }
}

function recoveryStructuredRow(container, label, value) {
    const row = document.createElement('div');
    row.className = 'd-flex justify-content-between mb-1 pb-1 border-bottom border-secondary';
    const labelSpan = document.createElement('span');
    labelSpan.className = 'text-subtle';
    labelSpan.textContent = label;
    const valueSpan = document.createElement('span');
    valueSpan.className = 'text-info fw-bold text-break ms-2';
    valueSpan.textContent = value; // examiner-entered path or a computed number either way - text node only
    row.appendChild(labelSpan);
    row.appendChild(valueSpan);
    container.appendChild(row);
}

async function inspectDdrescueMapfile() {
    const mapPathEl = document.getElementById("recoveryMapfilePath");
    const mapPath = mapPathEl ? mapPathEl.value.trim() : "";

    if (!mapPath) {
        showToast("Please enter or select a .map file path first.", 'warning');
        return;
    }

    showRecoveryStructuredOutput();
    const structured = document.getElementById("recoveryStructuredOutput");
    if (structured) structured.innerHTML = '<span class="text-subtle">Reading mapfile...</span>';

    try {
        const res = await fetch('/api/ddrescue/inspect_map', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ map_path: mapPath })
        });
        const data = await res.json();
        if (!structured) return;
        structured.innerHTML = '';

        if (data.success) {
            recoveryStructuredRow(structured, 'Mapfile', mapPath);
            recoveryStructuredRow(structured, 'Rescued Data', `${data.rescued_gb} GB`);
            recoveryStructuredRow(structured, 'Unattempted Data', `${data.non_tried_mb} MB`);
            recoveryStructuredRow(structured, 'Bad Sectors Size', `${data.bad_sector_kb} KB`);
            recoveryStructuredRow(structured, 'Hard Error Blocks', String(data.bad_blocks_count));
        } else {
            const err = document.createElement('span');
            err.className = 'text-danger';
            err.textContent = `Error: ${data.error}`;
            structured.appendChild(err);
        }
    } catch (err) {
        if (structured) {
            structured.innerHTML = '';
            const errSpan = document.createElement('span');
            errSpan.className = 'text-danger';
            errSpan.textContent = 'Request failed.';
            structured.appendChild(errSpan);
        }
    }
}

async function stopAcquisition() {
    if (!confirm("Terminate current process?")) return;
    try {
        const res = await fetch('/api/stop_imaging', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = false;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = true;
            if (document.getElementById("btnRecoveryStart")) document.getElementById("btnRecoveryStart").disabled = false;
            if (document.getElementById("btnRecoveryStop")) document.getElementById("btnRecoveryStop").disabled = true;
        }
    } catch (err) {}
}

// ===================== MOBILE FORENSICS =====================
let mobileIosDevices = [];
let mobileAndroidDevices = [];

async function refreshMobileDevices() {
    try {
        const res = await fetch('/api/mobile/devices');
        const data = await res.json();
        mobileIosDevices = data.ios || [];
        mobileAndroidDevices = data.android || [];

        const iosSelect = document.getElementById("mobileIosSelect");
        if (iosSelect) {
            iosSelect.innerHTML = '';
            if (mobileIosDevices.length === 0) {
                iosSelect.innerHTML = '<option value="">No devices found - tap Refresh</option>';
            } else {
                mobileIosDevices.forEach(dev => {
                    const opt = document.createElement('option');
                    opt.value = dev.udid;
                    opt.textContent = dev.trusted ? `${dev.name} (${dev.model})` : `${dev.udid} (NOT TRUSTED)`;
                    iosSelect.appendChild(opt);
                });
            }
            onMobileIosSelect();
        }

        const androidSelect = document.getElementById("mobileAndroidSelect");
        if (androidSelect) {
            androidSelect.innerHTML = '';
            if (mobileAndroidDevices.length === 0) {
                androidSelect.innerHTML = '<option value="">No devices found - tap Refresh</option>';
            } else {
                mobileAndroidDevices.forEach(dev => {
                    const opt = document.createElement('option');
                    opt.value = dev.serial;
                    opt.textContent = dev.authorized ? `${dev.serial} (${dev.model})` : `${dev.serial} (${dev.state.toUpperCase()})`;
                    androidSelect.appendChild(opt);
                });
            }
            onMobileAndroidSelect();
        }
    } catch (err) {}
}

// Single Start button is shared between platforms - only enabled when the
// currently-selected device (for whichever platform is in mode) is ready.
// Called after every device-list refresh and every mode switch so it can
// never go stale (e.g. an Android device becoming ready shouldn't enable
// Start while iOS mode is still selected).
function refreshMobileStartButtonState() {
    const mode = document.getElementById("mobileDeviceMode")?.value || 'ios';
    const startBtn = document.getElementById("btnMobileStart");
    if (!startBtn) return;

    if (mode === 'ios') {
        const udid = document.getElementById("mobileIosSelect")?.value;
        const dev = mobileIosDevices.find(d => d.udid === udid);
        startBtn.disabled = !dev || !dev.trusted;
    } else if (mode === 'sim') {
        // SIM/UICC reading has no acquisition job at all (its own "Read
        // Card" button handles it) - the shared Start button is never
        // meaningful in this mode.
        startBtn.disabled = true;
    } else {
        const serial = document.getElementById("mobileAndroidSelect")?.value;
        const dev = mobileAndroidDevices.find(d => d.serial === serial);
        startBtn.disabled = !dev || !dev.authorized;
    }
}

function updateMobileDeviceMode() {
    const mode = document.getElementById("mobileDeviceMode")?.value || 'ios';
    const iosControls = document.getElementById("mobileIosControls");
    const androidControls = document.getElementById("mobileAndroidControls");
    const simControls = document.getElementById("mobileSimControls");
    const startLabel = document.getElementById("btnMobileStartLabel");

    if (iosControls) iosControls.style.display = mode === 'ios' ? '' : 'none';
    if (androidControls) androidControls.style.display = mode === 'android' ? '' : 'none';
    if (simControls) simControls.style.display = mode === 'sim' ? '' : 'none';
    if (startLabel) startLabel.textContent = mode === 'ios' ? 'Start iOS Backup' : mode === 'android' ? 'Start Android Acquisition' : 'N/A - Use Read Card Above';

    refreshMobileStartButtonState();
}

function onMobileIosSelect() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    const dev = mobileIosDevices.find(d => d.udid === udid);

    if (document.getElementById("mobileIosModel")) document.getElementById("mobileIosModel").innerText = dev?.model || '--';
    if (document.getElementById("mobileIosVersion")) document.getElementById("mobileIosVersion").innerText = dev?.ios_version || '--';
    if (document.getElementById("mobileIosBuild")) document.getElementById("mobileIosBuild").innerText = dev?.build_version || '--';
    if (document.getElementById("mobileIosStorage")) document.getElementById("mobileIosStorage").innerText = dev ? `${dev.storage_capacity_gb} GB` : '--';
    if (document.getElementById("mobileIosActivation")) document.getElementById("mobileIosActivation").innerText = dev?.activation_state || '--';
    if (document.getElementById("mobileIosSerial")) document.getElementById("mobileIosSerial").innerText = dev?.serial || '--';
    if (document.getElementById("mobileIosImei")) document.getElementById("mobileIosImei").innerText = dev?.imei || '--';
    if (document.getElementById("mobileIosWifiMac")) document.getElementById("mobileIosWifiMac").innerText = dev?.wifi_mac || '--';
    if (document.getElementById("mobileIosBtMac")) document.getElementById("mobileIosBtMac").innerText = dev?.bluetooth_mac || '--';

    const statusEl = document.getElementById("mobileIosStatus");
    if (statusEl) {
        statusEl.innerText = (dev && !dev.trusted) ? 'Device connected but not trusted yet - tap "Trust This Computer?" on the device, then Refresh.' : '';
    }
    const pairBtn = document.getElementById("btnPairIosDevice");
    if (pairBtn) pairBtn.style.display = (dev && !dev.trusted) ? '' : 'none';

    refreshMobileStartButtonState();
}

// A device shows up in `idevice_id -l` (and so in the select above) the moment it's
// plugged in over USB, before the examiner has tapped "Trust This Computer?" on it -
// idevicepair's own pairing request is what actually makes that prompt appear on the
// device in the first place. Without this, an untrusted device has no way to reach that
// prompt at all short of unplugging/replugging and hoping the OS surfaces it on its own.
async function pairIosDevice() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    if (!udid) return;
    const btn = document.getElementById("btnPairIosDevice");
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/mobile/ios/pair', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ udid })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message || 'Pairing request sent - accept "Trust This Computer?" on the device.', 'success');
        } else {
            showToast(data.error || 'Pairing failed.', 'danger');
        }
    } catch (err) {
        showToast('Pairing request failed: ' + err.message, 'danger');
    } finally {
        if (btn) btn.disabled = false;
        refreshMobileDevices();
    }
}

async function pullIosCrashReports() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    const statusEl = document.getElementById("mobileIosCrashReportStatus");
    if (!udid) return showToast('Select a connected, trusted iOS device first.', 'warning');
    const destinationDir = activeCase ? activeCase.case_folder : document.getElementById("mobileDest")?.value || '/mnt';
    if (statusEl) statusEl.textContent = 'Pulling crash reports...';
    try {
        const res = await fetch('/api/mobile/ios/pull_crash_reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ udid, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) {
            if (statusEl) statusEl.textContent = `Failed: ${data.error}`;
            showToast(`Crash report pull failed: ${data.error}`, 'danger');
            return;
        }
        if (statusEl) statusEl.textContent = `${data.files.length} file(s) saved to: ${data.output_dir}`;
        showToast(`Pulled ${data.files.length} crash report file(s).`, 'success');
        loadExplorer(explorerPath);
    } catch (err) {
        if (statusEl) statusEl.textContent = '[REQUEST FAILED]';
    }
}

async function detectPcscReaders() {
    const selectEl = document.getElementById("mobileSimReaderSelect");
    const statusEl = document.getElementById("mobileSimStatus");
    if (selectEl) selectEl.innerHTML = '<option value="">Detecting...</option>';
    if (statusEl) statusEl.textContent = '';
    try {
        const res = await fetch('/api/mobile/sim/readers');
        const data = await res.json();
        if (!data.success) {
            if (selectEl) selectEl.innerHTML = '<option value="">-- Detection failed, try again --</option>';
            showToast(data.error || 'Failed to detect PC/SC readers.', 'danger');
            return;
        }
        if (selectEl) selectEl.innerHTML = '';
        if (!data.readers.length) {
            if (selectEl) selectEl.innerHTML = '<option value="">-- No readers found --</option>';
        } else {
            data.readers.forEach((name, i) => {
                const opt = document.createElement('option');
                opt.value = i;
                opt.textContent = `[${i}] ${name}`;
                if (selectEl) selectEl.appendChild(opt);
            });
        }
    } catch (err) {
        if (selectEl) selectEl.innerHTML = '<option value="">-- Detection failed, try again --</option>';
    }
}

async function readSimCard() {
    const readerIndex = document.getElementById("mobileSimReaderSelect")?.value;
    const outputEl = document.getElementById("mobileSimOutput");
    const statusEl = document.getElementById("mobileSimStatus");
    if (readerIndex === '' || readerIndex === undefined) return showToast('Detect readers and select one first.', 'warning');
    const destinationDir = activeCase ? activeCase.case_folder : document.getElementById("mobileDest")?.value || '/mnt';
    if (statusEl) statusEl.textContent = 'Reading card...';
    if (outputEl) outputEl.textContent = 'Running...';
    try {
        const res = await fetch('/api/mobile/sim/read', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reader_index: readerIndex, destination_dir: destinationDir, case_folder: activeCase ? activeCase.case_folder : null })
        });
        const data = await res.json();
        if (!data.success) {
            if (statusEl) statusEl.textContent = `Failed: ${data.error}`;
            if (outputEl) outputEl.textContent = data.output || `[ERROR] ${data.error}`;
            return;
        }
        if (statusEl) statusEl.textContent = `Saved to: ${data.output_path}`;
        if (outputEl) outputEl.textContent = data.output;
        showToast('Card read successfully.', 'success');
        loadExplorer(explorerPath);
    } catch (err) {
        if (statusEl) statusEl.textContent = '[REQUEST FAILED]';
    }
}

function onMobileAndroidSelect() {
    const serial = document.getElementById("mobileAndroidSelect")?.value;
    const dev = mobileAndroidDevices.find(d => d.serial === serial);

    if (document.getElementById("mobileAndroidModel")) document.getElementById("mobileAndroidModel").innerText = dev?.model || '--';
    if (document.getElementById("mobileAndroidManufacturer")) document.getElementById("mobileAndroidManufacturer").innerText = dev?.manufacturer || '--';
    if (document.getElementById("mobileAndroidState")) document.getElementById("mobileAndroidState").innerText = dev?.state || '--';
    if (document.getElementById("mobileAndroidVersion")) document.getElementById("mobileAndroidVersion").innerText = dev?.android_version || '--';
    if (document.getElementById("mobileAndroidApiLevel")) document.getElementById("mobileAndroidApiLevel").innerText = dev?.api_level || '--';
    if (document.getElementById("mobileAndroidBuildId")) document.getElementById("mobileAndroidBuildId").innerText = dev?.build_id || '--';
    if (document.getElementById("mobileAndroidSerial")) document.getElementById("mobileAndroidSerial").innerText = dev?.serial || '--';

    const statusEl = document.getElementById("mobileAndroidStatus");
    if (statusEl) {
        statusEl.innerText = (dev && !dev.authorized) ? 'Device connected but not authorized yet - approve the USB debugging prompt on the device, then Refresh.' : '';
    }

    // Switching devices while Physical mode is already selected should
    // refresh the root/SELinux banner for the newly-selected device, not
    // leave the previous device's status showing.
    if (document.getElementById("mobileAndroidMode")?.value === 'physical') {
        renderAndroidPhysicalRootBanner();
    }

    const whatsappPanel = document.getElementById("mobileWhatsappKeyPanel");
    if (whatsappPanel) whatsappPanel.style.display = (dev && dev.root_available) ? '' : 'none';
    const whatsappStatus = document.getElementById("mobileWhatsappKeyStatus");
    if (whatsappStatus) whatsappStatus.textContent = '';

    refreshMobileStartButtonState();
}

async function pullWhatsappKey() {
    const dev = _currentlySelectedAndroidDevice();
    const statusEl = document.getElementById("mobileWhatsappKeyStatus");
    if (!dev) return showToast('Select a connected Android device first.', 'warning');
    const destinationDir = activeCase ? activeCase.case_folder : document.getElementById("mobileDest")?.value || '/mnt';
    if (statusEl) statusEl.textContent = 'Pulling key file...';
    try {
        const res = await fetch(`/api/mobile/android/${encodeURIComponent(dev.serial)}/pull_whatsapp_key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ destination_dir: destinationDir })
        });
        const data = await res.json();
        if (!data.success) {
            if (statusEl) statusEl.textContent = `Failed: ${data.error}`;
            showToast(`WhatsApp key pull failed: ${data.error}`, 'danger');
            return;
        }
        if (statusEl) statusEl.textContent = `Key saved to: ${data.path}`;
        showToast('WhatsApp key file pulled successfully.', 'success');
        loadExplorer(explorerPath);
    } catch (err) {
        if (statusEl) statusEl.textContent = '[REQUEST FAILED]';
    }
}

function toggleIosEncryptField() {
    const checked = document.getElementById("mobileIosEncryptToggle")?.checked;
    const row = document.getElementById("mobileIosEncryptRow");
    if (row) row.style.display = checked ? '' : 'none';
}

// Dispatches to the correct platform's start function based on the
// selected device mode - mirrors startRecoveryTool()'s dispatch-by-select
// pattern for File Recovery.
function startMobileAcquisition() {
    const mode = document.getElementById("mobileDeviceMode")?.value || 'ios';
    if (mode === 'ios') return startIosBackup();
    return startAndroidAcquisition();
}

async function startIosBackup() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    if (!udid) return showToast("Select a trusted iOS device first.", 'warning');

    const dest = document.getElementById("mobileDest")?.value || '/mnt';
    const encryptEnabled = document.getElementById("mobileIosEncryptToggle")?.checked;
    const encrypt_password = encryptEnabled ? (document.getElementById("mobileIosEncryptPassword")?.value || '') : '';

    if (encryptEnabled && !encrypt_password) return showToast("Enter an encryption password, or turn off the encrypted backup toggle.", 'warning');

    const metadata = {
        case_number: document.getElementById("mobileCaseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("mobileEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("mobileExaminer")?.value || "UNSPECIFIED",
        notes: "iOS full backup via idevicebackup2"
    };

    try {
        const res = await fetch('/api/mobile/start_ios_backup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ udid, destination: dest, encrypt_password, metadata })
        });
        const data = await res.json();
        if (!data.success) showToast(`Start Failed: ${data.error}`, 'danger');
    } catch (err) {}
}

async function startAndroidAcquisition() {
    const serial = document.getElementById("mobileAndroidSelect")?.value;
    if (!serial) return showToast("Select an authorized Android device first.", 'warning');

    const mode = document.getElementById("mobileAndroidMode")?.value || 'pull';
    const dest = document.getElementById("mobileDest")?.value || '/mnt';

    const metadata = {
        case_number: document.getElementById("mobileCaseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("mobileEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("mobileExaminer")?.value || "UNSPECIFIED",
        notes: `Android ${mode} via adb`
    };

    const body = { serial, mode, destination: dest, metadata };

    if (mode === 'physical') {
        const manualChecked = document.getElementById("mobilePhysicalManualToggle")?.checked;
        const target = manualChecked
            ? (document.getElementById("mobilePhysicalManualTarget")?.value || '').trim()
            : (document.getElementById("mobilePhysicalTargetSelect")?.value || '');
        if (!target) {
            return showToast("Select a target partition (Detect Targets first), or enter a manual device path.", 'warning');
        }
        const hashes = [...document.querySelectorAll('#mobileAndroidPhysicalPanel input[type=checkbox][id^=mobilePhysicalHash]:checked')]
            .map((el) => el.value);
        if (!hashes.length) {
            return showToast("Select at least one verification hash algorithm.", 'warning');
        }
        if (!confirm("Physical/raw acquisition requires the device to already be rooted. Rooting a device is "
            + "itself an evidence-altering action - only continue if that's already true, or rooting is a "
            + "deliberate, documented, examiner-authorized step. Whether this specific device/root method "
            + "actually permits reading raw block devices is unknown until attempted (SELinux enforcing mode "
            + "can block even root). Continue?")) {
            return;
        }
        body.target = target;
        body.format = document.getElementById("mobilePhysicalFormat")?.value || 'dc3dd';
        body.hashes = hashes;
    }

    try {
        const res = await fetch('/api/mobile/start_android', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) showToast(`Start Failed: ${data.error}`, 'danger');
    } catch (err) {}
}

// ===================== ADVANCED SETTINGS =====================

// Change My Password lives in the "Logged in as" dropdown (navbar), not
// Settings - every logged-in account needs to be able to change its own
// password regardless of what its user group can otherwise access, so it
// stays reachable from anywhere rather than behind a tab a limited group
// might not see much reason to visit.
let changePasswordModalInstance = null;

function openChangePasswordModal() {
    if (!changePasswordModalInstance) {
        changePasswordModalInstance = new bootstrap.Modal(document.getElementById('changePasswordModal'));
    }
    document.getElementById("cfgCurrentPass").value = '';
    document.getElementById("cfgNewPass").value = '';
    document.getElementById("cfgConfirmPass").value = '';
    const statusEl = document.getElementById("cfgPassStatus");
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small'; }
    changePasswordModalInstance.show();
}

async function changeAdminPassword() {
    const current = document.getElementById("cfgCurrentPass")?.value || '';
    const next = document.getElementById("cfgNewPass")?.value || '';
    const confirm = document.getElementById("cfgConfirmPass")?.value || '';
    const statusEl = document.getElementById("cfgPassStatus");

    if (!current || !next) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Enter your current and new password.'; }
        return;
    }
    if (next !== confirm) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'New password and confirmation do not match.'; }
        return;
    }

    try {
        const res = await fetch('/api/system/change_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: current, new_password: next })
        });
        const data = await res.json();
        if (!data.success) {
            if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = data.error; }
            return;
        }
        document.getElementById("cfgCurrentPass").value = '';
        document.getElementById("cfgNewPass").value = '';
        document.getElementById("cfgConfirmPass").value = '';
        changePasswordModalInstance?.hide();
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

// --- User Accounts & Groups (Security) ---
// Basic Auth has no real session/logout, so "who's logged in" is only ever
// known by asking the backend what the current request's credentials
// resolved to (see /api/whoami, app.py's g.forensic_user) - there is no
// client-side concept of a logged-in user beyond this cached role/permission
// set, which only exists to hide/gray out controls the caller's group can't
// use anyway, never to actually enforce anything (the backend re-checks
// permissions on every request regardless).
let currentUsername = null;
let currentUserRole = null;
let currentUserPermissions = {};

// Maps each gated sidebar <li> to the permission key that must be true for
// it to stay visible - see PERMISSION_KEYS in app.py, the single source of
// truth this mapping has to stay in sync with by hand (there's no API call
// on every page load just to fetch a key->tab mapping for 5 fixed items).
const SIDEBAR_TAB_PERMISSIONS = {
    navItemAcquisition: 'acquisition',
    navItemMobile: 'mobile',
    navItemRecovery: 'recovery',
    navItemExplorer: 'file_explorer',
    navItemReports: 'reporting',
};

// Home tab tiles mirror the same permission keys as the sidebar entries
// above (Settings has none in either map - never gated) - an account
// without a given tab's permission shouldn't see a tile that would just
// 403 if clicked.
const HOME_CARD_PERMISSIONS = {
    homeCardAcquisition: 'acquisition',
    homeCardMobile: 'mobile',
    homeCardRecovery: 'recovery',
    homeCardExplorer: 'file_explorer',
    homeCardReports: 'reporting',
};

function applySidebarPermissionGating() {
    let activeTabHidden = false;
    for (const [navId, permKey] of Object.entries(SIDEBAR_TAB_PERMISSIONS)) {
        const li = document.getElementById(navId);
        if (!li) continue;
        const allowed = !!currentUserPermissions[permKey];
        li.style.display = allowed ? '' : 'none';
        if (!allowed && li.querySelector('.nav-link.active')) activeTabHidden = true;
    }
    for (const [cardId, permKey] of Object.entries(HOME_CARD_PERMISSIONS)) {
        const col = document.getElementById(cardId);
        if (col) col.style.display = currentUserPermissions[permKey] ? '' : 'none';
    }
    // Settings/Help are never gated (self-service password change and
    // account switching live in Settings, which must stay reachable
    // regardless of group) - if the tab that happened to be active got
    // hidden, land on the first tab this account can actually see instead
    // of a blank pane.
    if (activeTabHidden) {
        const firstVisibleLink = document.querySelector('#forensicAppTabs > li:not([style*="display: none"]) > .nav-link[data-bs-toggle="tab"]');
        if (firstVisibleLink) new bootstrap.Tab(firstVisibleLink).show();
    }
}

async function fetchWhoami() {
    try {
        const res = await fetch('/api/whoami');
        const data = await res.json();
        currentUsername = data.username;
        currentUserRole = data.role;
        currentUserPermissions = data.permissions || {};
        const indicator = document.getElementById("whoamiIndicator");
        if (indicator && currentUsername) {
            indicator.style.display = '';
            indicator.textContent = `Logged in as: ${currentUsername} (${currentUserRole})`;
        }
        applyUserMgmtPermissionGating();
        applySidebarPermissionGating();
    } catch (err) { /* non-fatal - indicator just stays hidden */ }
}

let switchUserModalInstance = null;

function openSwitchUserModal() {
    if (!switchUserModalInstance) {
        switchUserModalInstance = new bootstrap.Modal(document.getElementById('switchUserModal'));
    }
    const statusEl = document.getElementById("switchUserStatus");
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small'; }
    const userEl = document.getElementById("switchUserUsername");
    const passEl = document.getElementById("switchUserPassword");
    if (userEl) userEl.value = '';
    if (passEl) passEl.value = '';
    switchUserModalInstance.show();
}

// Switching identity is now a real, reliable operation - a second /login
// call, exactly like signing in fresh, just while a session already exists.
// (Basic Auth's old embedded-credential-URL trick is gone: it depended on a
// browser evicting one cached credential in favor of another, which browsers
// don't reliably do once more than one has been used in the same profile -
// that's the actual bug that was reported and is what real sessions fix.)
async function submitSwitchUser() {
    const username = document.getElementById("switchUserUsername")?.value.trim();
    const password = document.getElementById("switchUserPassword")?.value || '';
    const statusEl = document.getElementById("switchUserStatus");

    if (!username || !password) {
        if (statusEl) { statusEl.textContent = 'Enter both a username and password.'; statusEl.className = 'small text-danger'; }
        return;
    }

    if (statusEl) { statusEl.textContent = 'Switching...'; statusEl.className = 'small text-info'; }

    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.status === 429) {
            if (statusEl) { statusEl.textContent = data.error || 'Too many failed login attempts. Try again in a few minutes.'; statusEl.className = 'small text-danger'; }
            return;
        }
        if (res.status === 401 || !data.success) {
            if (statusEl) { statusEl.textContent = data.error || 'Incorrect username or password.'; statusEl.className = 'small text-danger'; }
            return;
        }
        // Full reload, deliberately - this app has a lot of per-tab state
        // (activeCase, loaded report data, permission-gated UI) that was
        // never designed to be hot-swapped for a different identity's
        // permissions mid-session; a fresh load is the simple, correct choice.
        location.reload();
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Failed: ${err.message}`; statusEl.className = 'small text-danger'; }
    }
}

async function logout() {
    try {
        await fetch('/logout', { method: 'POST' });
    } catch (err) { /* best-effort - navigating to /login below still ends the visible session either way */ }
    location.href = '/login';
}

function applyUserMgmtPermissionGating() {
    const canManage = !!currentUserPermissions.manage_users;
    const accountsItem = document.getElementById("userAccountsAccordionItem");
    const groupsItem = document.getElementById("userGroupsAccordionItem");
    if (accountsItem) accountsItem.style.display = canManage ? '' : 'none';
    if (groupsItem) groupsItem.style.display = canManage ? '' : 'none';
}

// userListContainer is the <tbody> of the User Accounts table (columns:
// User / Created / Last Login / Group / Reset Password / Delete) - every
// state below (loading/error/empty/populated) renders one <tr> per row so
// the column layout never collapses regardless of what's being shown.
function _userListMessageRow(text, className) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.className = className;
    cell.textContent = text;
    row.appendChild(cell);
    return row;
}

async function loadUserList() {
    const container = document.getElementById("userListContainer");
    if (!container) return;
    container.innerHTML = '';
    container.appendChild(_userListMessageRow('Loading...', 'text-subtle'));

    try {
        const res = await fetch('/api/users/list');
        const data = await res.json();
        container.innerHTML = '';
        if (!data.success) {
            const msg = res.status === 403
                ? "Your account's group doesn't have User & Group Management access."
                : (data.error || 'Failed to load accounts.');
            container.appendChild(_userListMessageRow(msg, 'text-subtle'));
            return;
        }
        if (data.users.length === 0) {
            container.appendChild(_userListMessageRow('No accounts found.', 'text-subtle'));
            return;
        }
        data.users.forEach(u => {
            const row = document.createElement('tr');
            row.className = 'border-bottom border-secondary';

            const nameCell = document.createElement('td');
            nameCell.className = 'text-info fw-bold';
            nameCell.textContent = u.username; // untrusted (examiner-chosen) - text node only
            row.appendChild(nameCell);

            const createdCell = document.createElement('td');
            createdCell.className = 'text-subtle';
            createdCell.textContent = u.created_at || '--';
            row.appendChild(createdCell);

            const lastLoginCell = document.createElement('td');
            lastLoginCell.className = 'text-subtle';
            lastLoginCell.textContent = u.last_login || 'Never';
            row.appendChild(lastLoginCell);

            const groupCell = document.createElement('td');
            const groupBadge = document.createElement('span');
            groupBadge.className = `badge ${u.group_id === 'admin' ? 'bg-warning text-dark' : 'bg-secondary'}`;
            groupBadge.textContent = u.group_name; // group names are examiner-chosen too - text node only
            groupCell.appendChild(groupBadge);
            row.appendChild(groupCell);

            const resetCell = document.createElement('td');
            const resetBtn = document.createElement('button');
            resetBtn.className = 'btn btn-xs btn-outline-warning py-0 px-2';
            resetBtn.textContent = 'Reset Password';
            resetBtn.onclick = () => openUserActionModal('reset', u.username);
            resetCell.appendChild(resetBtn);
            row.appendChild(resetCell);

            const delCell = document.createElement('td');
            const delBtn = document.createElement('button');
            delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-2';
            delBtn.textContent = 'Delete';
            delBtn.onclick = () => openUserActionModal('delete', u.username);
            delCell.appendChild(delBtn);
            row.appendChild(delCell);

            container.appendChild(row);
        });
    } catch (err) {
        container.innerHTML = '';
        container.appendChild(_userListMessageRow('Request failed.', 'text-danger'));
    }
}

async function createUser() {
    const username = document.getElementById("newUserUsername")?.value.trim() || '';
    const password = document.getElementById("newUserPassword")?.value || '';
    const group_id = document.getElementById("newUserGroupId")?.value || 'analyst';
    const statusEl = document.getElementById("userMgmtStatus");

    if (!username || !password) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Enter a username and password.'; }
        return;
    }

    try {
        const res = await fetch('/api/users/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, group_id })
        });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small text-success' : 'small text-danger';
            statusEl.innerText = data.success ? data.message : data.error;
        }
        if (data.success) {
            document.getElementById("newUserUsername").value = '';
            document.getElementById("newUserPassword").value = '';
            loadUserList();
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

// --- User Groups (Security) ---
let userGroupsCache = [];
let permissionKeysCache = [];
let userGroupModalInstance = null;

async function loadUserGroups() {
    const container = document.getElementById("userGroupsListContainer");
    const groupSelect = document.getElementById("newUserGroupId");
    if (container) container.innerHTML = '<span class="text-subtle">Loading groups...</span>';

    try {
        const res = await fetch('/api/user_groups');
        const data = await res.json();
        if (!data.success) {
            if (container) {
                const msg = res.status === 403
                    ? "Your account's group doesn't have User & Group Management access."
                    : (data.error || 'Failed to load groups.');
                container.innerHTML = '';
                const span = document.createElement('span');
                span.className = 'text-subtle';
                span.textContent = msg;
                container.appendChild(span);
            }
            return;
        }
        userGroupsCache = data.groups;
        permissionKeysCache = data.permission_keys;

        if (groupSelect) {
            const prevValue = groupSelect.value;
            groupSelect.innerHTML = '';
            userGroupsCache.forEach(grp => {
                const opt = document.createElement('option');
                opt.value = grp.id;
                opt.textContent = grp.name; // group names are examiner-chosen - text node only
                groupSelect.appendChild(opt);
            });
            groupSelect.value = userGroupsCache.some(g => g.id === prevValue) ? prevValue : 'analyst';
        }

        if (container) {
            container.innerHTML = '';
            userGroupsCache.forEach(grp => {
                const row = document.createElement('div');
                row.className = 'd-flex justify-content-between align-items-center mb-1 pb-1 border-bottom border-secondary';

                const left = document.createElement('div');
                const nameSpan = document.createElement('span');
                nameSpan.className = 'text-info fw-bold';
                nameSpan.textContent = grp.name; // examiner-chosen for custom groups - text node only
                left.appendChild(nameSpan);
                const grantedCount = Object.values(grp.permissions).filter(Boolean).length;
                const countSpan = document.createElement('span');
                countSpan.className = 'text-subtle small ms-2';
                countSpan.textContent = `(${grantedCount}/${permissionKeysCache.length} access)`;
                left.appendChild(countSpan);

                const right = document.createElement('div');
                const editBtn = document.createElement('button');
                editBtn.className = 'btn btn-xs btn-outline-info py-0 px-2';
                editBtn.textContent = grp.id === 'admin' ? 'Always Full Access' : 'Edit';
                editBtn.disabled = grp.id === 'admin';
                editBtn.onclick = () => openUserGroupModal(grp.id);
                right.appendChild(editBtn);

                row.appendChild(left);
                row.appendChild(right);
                container.appendChild(row);
            });
        }
    } catch (err) {
        if (container) {
            container.innerHTML = '';
            const span = document.createElement('span');
            span.className = 'text-danger';
            span.textContent = 'Request failed.';
            container.appendChild(span);
        }
    }
    loadUserList();
}

function openUserGroupModal(groupId) {
    const group = groupId ? userGroupsCache.find(g => g.id === groupId) : null;
    document.getElementById("userGroupEditingId").value = groupId || '';
    document.getElementById("userGroupModalTitle").textContent = group ? `Edit Group: ${group.name}` : 'New Group';
    const nameInput = document.getElementById("userGroupName");
    nameInput.value = group ? group.name : '';
    // Analyst's name is fixed (it's the built-in default new users land in);
    // its permissions are still fully editable below. A brand-new custom
    // group and an existing custom group both allow renaming.
    nameInput.disabled = !!(group && group.id === 'analyst');
    document.getElementById("userGroupModalStatus").innerHTML = '';

    const permsContainer = document.getElementById("userGroupPermissionsContainer");
    permsContainer.innerHTML = '';
    const permissions = group ? group.permissions : {};
    permissionKeysCache.forEach(pk => {
        const wrap = document.createElement('div');
        wrap.className = 'form-check';
        const input = document.createElement('input');
        input.className = 'form-check-input';
        input.type = 'checkbox';
        input.id = `grpPerm_${pk.key}`;
        input.checked = !!permissions[pk.key];
        const label = document.createElement('label');
        label.className = 'form-check-label small';
        label.setAttribute('for', input.id);
        label.textContent = pk.label; // from the backend's fixed PERMISSION_KEYS registry, not user input
        wrap.appendChild(input);
        wrap.appendChild(label);
        permsContainer.appendChild(wrap);
    });

    document.getElementById("btnDeleteUserGroup").style.display = (group && group.id !== 'admin' && group.id !== 'analyst') ? '' : 'none';

    if (!userGroupModalInstance) {
        userGroupModalInstance = new bootstrap.Modal(document.getElementById('userGroupModal'));
    }
    userGroupModalInstance.show();
}

async function saveUserGroup() {
    const groupId = document.getElementById("userGroupEditingId").value;
    const name = document.getElementById("userGroupName")?.value.trim() || '';
    const statusEl = document.getElementById("userGroupModalStatus");
    const permissions = {};
    permissionKeysCache.forEach(pk => {
        permissions[pk.key] = !!document.getElementById(`grpPerm_${pk.key}`)?.checked;
    });

    if (!name) {
        statusEl.className = 'small text-danger'; statusEl.innerText = 'Group name is required.';
        return;
    }

    try {
        const url = groupId ? `/api/user_groups/${encodeURIComponent(groupId)}` : '/api/user_groups';
        const res = await fetch(url, {
            method: groupId ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, permissions })
        });
        const data = await res.json();
        if (!data.success) {
            statusEl.className = 'small text-danger'; statusEl.innerText = data.error;
            return;
        }
        userGroupModalInstance.hide();
        loadUserGroups();
    } catch (err) {
        statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.';
    }
}

async function deleteUserGroupFromModal() {
    const groupId = document.getElementById("userGroupEditingId").value;
    if (!groupId) return;
    if (!confirm('Delete this group? Any users currently in it will be moved to the Analyst group.')) return;

    const statusEl = document.getElementById("userGroupModalStatus");
    try {
        const res = await fetch(`/api/user_groups/${encodeURIComponent(groupId)}`, { method: 'DELETE' });
        const data = await res.json();
        if (!data.success) {
            statusEl.className = 'small text-danger'; statusEl.innerText = data.error;
            return;
        }
        userGroupModalInstance.hide();
        loadUserGroups();
    } catch (err) {
        statusEl.className = 'small text-danger'; statusEl.innerText = 'Request failed.';
    }
}

// Shared modal for the two admin actions that require re-entering the
// caller's own current password (delete / reset another user's password) -
// both are irreversible/account-takeover-equivalent, so both get the same
// extra confirmation friction self-service password changes already have.
let userActionModalInstance = null;
let userActionPendingMode = null;
let userActionPendingTarget = null;

function openUserActionModal(mode, username) {
    userActionPendingMode = mode;
    userActionPendingTarget = username;

    document.getElementById("userActionModalTitle").textContent = mode === 'delete'
        ? `Delete user: ${username}`
        : `Reset password for: ${username}`;
    document.getElementById("userActionTargetName2").textContent = username;
    document.getElementById("userActionNewPassRow").style.display = mode === 'reset' ? '' : 'none';
    document.getElementById("userActionNewPass").value = '';
    document.getElementById("userActionConfirmNewPass").value = '';
    // Re-entering your OWN password only applies to deleting an account -
    // more consequential/irreversible than a password reset, which is
    // already gated by the manage_users permission check alone (see
    // submitUserAction()'s reset branch below for why it doesn't ask here).
    document.getElementById("userActionCurrentPassRow").style.display = mode === 'delete' ? '' : 'none';
    document.getElementById("userActionCurrentPass").value = '';
    document.getElementById("userActionModalStatus").innerHTML = '';

    const warning = document.getElementById("userActionModalWarning");
    warning.style.display = '';
    warning.textContent = mode === 'delete'
        ? 'This permanently removes the account. This cannot be undone.'
        : 'This immediately replaces their password - they will need the new one to log in.';

    const confirmBtn = document.getElementById("userActionConfirmBtn");
    confirmBtn.textContent = mode === 'delete' ? 'Delete User' : 'Reset Password';

    if (!userActionModalInstance) {
        userActionModalInstance = new bootstrap.Modal(document.getElementById('userActionModal'));
    }
    userActionModalInstance.show();
}

async function submitUserAction() {
    const statusEl = document.getElementById("userActionModalStatus");
    let url, body;

    if (userActionPendingMode === 'delete') {
        const currentPassword = document.getElementById("userActionCurrentPass")?.value || '';
        if (!currentPassword) {
            statusEl.className = 'small mt-2 text-danger';
            statusEl.innerText = 'Enter your current password to confirm.';
            return;
        }
        url = '/api/users/delete';
        body = { username: userActionPendingTarget, current_password: currentPassword };
    } else {
        const newPassword = document.getElementById("userActionNewPass")?.value || '';
        const confirmNewPassword = document.getElementById("userActionConfirmNewPass")?.value || '';
        if (!newPassword || newPassword.length < 8) {
            statusEl.className = 'small mt-2 text-danger';
            statusEl.innerText = 'New password must be at least 8 characters.';
            return;
        }
        if (newPassword !== confirmNewPassword) {
            statusEl.className = 'small mt-2 text-danger';
            statusEl.innerText = 'New password and confirmation do not match.';
            return;
        }
        // No re-auth field here on purpose - resetting another user's
        // password is already gated by the manage_users permission check
        // (server-side), unlike deleting an account which asks for your
        // own password too as extra friction on top of that same check.
        url = '/api/users/reset_password';
        body = { username: userActionPendingTarget, new_password: newPassword };
    }

    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.success) {
            statusEl.className = 'small mt-2 text-danger';
            statusEl.innerText = data.error;
            return;
        }
        userActionModalInstance.hide();
        loadUserList();
    } catch (err) {
        statusEl.className = 'small mt-2 text-danger';
        statusEl.innerText = 'Request failed.';
    }
}

// --- TLS Certificate (Security & Privacy) ---
async function loadTlsStatus() {
    const container = document.getElementById("tlsStatusContainer");
    if (!container) return;
    container.innerHTML = '<span class="text-subtle">Loading...</span>';

    try {
        const res = await fetch('/api/system/tls_status');
        const data = await res.json();
        container.innerHTML = '';
        if (!data.success) {
            const err_el = document.createElement('span');
            err_el.className = 'text-danger';
            err_el.textContent = data.error || 'Failed to read certificate status.';
            container.appendChild(err_el);
            return;
        }
        if (!data.configured) {
            const msg = document.createElement('span');
            msg.className = 'text-subtle';
            msg.textContent = 'TLS is not configured on this station. A certificate can still be installed below, but nginx must be set up (via install.py or manually) for it to take effect.';
            container.appendChild(msg);
            return;
        }
        [['Subject', data.subject], ['Issuer', data.issuer], ['Valid From', data.not_before],
         ['Valid Until', data.not_after], ['SHA-256 Fingerprint', data.fingerprint_sha256]].forEach(([label, value]) => {
            const row = document.createElement('div');
            row.className = 'd-flex justify-content-between mb-1';
            const labelSpan = document.createElement('span');
            labelSpan.className = 'text-subtle';
            labelSpan.textContent = label;
            const valueSpan = document.createElement('span');
            valueSpan.className = 'text-info text-break ms-2';
            valueSpan.textContent = value || '--';
            row.appendChild(labelSpan);
            row.appendChild(valueSpan);
            container.appendChild(row);
        });
    } catch (err) {
        container.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

async function generateTlsCertificate() {
    const extraHostname = document.getElementById("tlsGenExtraHostname")?.value.trim() || '';
    const statusEl = document.getElementById("tlsGenerateStatus");

    if (!confirm("Generate a new self-signed certificate and install it now? This replaces the current certificate immediately.")) return;

    if (statusEl) { statusEl.className = 'small mb-2 text-subtle'; statusEl.innerText = 'Generating and installing...'; }

    try {
        const res = await fetch('/api/system/tls_generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ extra_hostname: extraHostname })
        });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small mb-2 text-success' : 'small mb-2 text-danger';
            statusEl.innerText = data.success ? data.message : data.error;
        }
        if (data.success) {
            document.getElementById("tlsGenExtraHostname").value = '';
            loadTlsStatus();
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small mb-2 text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

async function uploadTlsCertificate() {
    const certFile = document.getElementById("tlsCertFile")?.files[0];
    const keyFile = document.getElementById("tlsKeyFile")?.files[0];
    const statusEl = document.getElementById("tlsUploadStatus");

    if (!certFile || !keyFile) {
        if (statusEl) { statusEl.className = 'small mt-2 text-danger'; statusEl.innerText = 'Select both a certificate file and a private key file.'; }
        return;
    }

    if (statusEl) { statusEl.className = 'small mt-2 text-subtle'; statusEl.innerText = 'Validating and installing...'; }

    const formData = new FormData();
    formData.append('cert_file', certFile);
    formData.append('key_file', keyFile);

    try {
        const res = await fetch('/api/system/tls_upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small mt-2 text-success' : 'small mt-2 text-danger';
            statusEl.innerText = data.success ? data.message : data.error;
        }
        if (data.success) {
            document.getElementById("tlsCertFile").value = '';
            document.getElementById("tlsKeyFile").value = '';
            loadTlsStatus();
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small mt-2 text-danger'; statusEl.innerText = 'Request failed.'; }
    }
}

// --- Configuration Backup & Restore ---
async function downloadConfigBackup() {
    const passEl = document.getElementById("configBackupPassphrase");
    const statusEl = document.getElementById("configBackupStatus");
    const passphrase = passEl?.value || '';

    if (passphrase.length < 8) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = 'Choose a backup passphrase of at least 8 characters.'; }
        return;
    }

    if (statusEl) { statusEl.className = 'small text-info'; statusEl.textContent = 'Building backup...'; }

    try {
        const res = await fetch('/api/settings/config_backup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase }),
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = data.error || 'Backup failed.'; }
            return;
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        a.download = `pi-forensics-backup-${stamp}.pfback`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        if (statusEl) { statusEl.className = 'small text-success'; statusEl.textContent = 'Backup downloaded. Keep the passphrase somewhere safe - it cannot be recovered.'; }
        if (passEl) passEl.value = '';
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = 'Request failed.'; }
    }
}

async function submitConfigRestore() {
    const fileEl = document.getElementById("configRestoreFile");
    const passEl = document.getElementById("configRestorePassphrase");
    const statusEl = document.getElementById("configBackupStatus");
    const file = fileEl?.files[0];
    const passphrase = passEl?.value || '';

    if (!file) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = 'Choose a backup file to restore.'; }
        return;
    }
    if (!passphrase) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = 'Enter the passphrase this backup was created with.'; }
        return;
    }
    if (!confirm('Restoring will replace every current user account, group, and setting on this station with the backup\'s contents. Continue?')) {
        return;
    }

    if (statusEl) { statusEl.className = 'small text-info'; statusEl.textContent = 'Restoring...'; }

    const formData = new FormData();
    formData.append('backup_file', file);
    formData.append('passphrase', passphrase);

    try {
        const res = await fetch('/api/settings/config_restore', { method: 'POST', body: formData });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small text-success' : 'small text-danger';
            statusEl.textContent = data.success ? data.message : data.error;
        }
        if (data.success) {
            if (fileEl) fileEl.value = '';
            if (passEl) passEl.value = '';
            loadUserList();
            loadUserGroups();
        }
    } catch (err) {
        if (statusEl) { statusEl.className = 'small text-danger'; statusEl.textContent = 'Request failed.'; }
    }
}

// --- Shared Service Controls & Diagnostics right pane (Advanced Settings) ---
// Every button in that card reports here instead of alert() popups, so the
// examiner has a running record of what was run and what it returned. The
// pane is one of two mutually-exclusive views - a terminal-style <pre> for
// command output, or a table for Check Tool Versions - never both at once.
function showDiagTerminal() {
    const pre = document.getElementById("diagOutput");
    const panel = document.getElementById("toolVersionsPanel");
    const actions = document.getElementById("toolVersionsActions");
    if (pre) pre.style.display = '';
    if (panel) panel.style.display = 'none';
    if (actions) actions.style.display = 'none';
}

function showToolVersionsPanel() {
    const pre = document.getElementById("diagOutput");
    const panel = document.getElementById("toolVersionsPanel");
    const actions = document.getElementById("toolVersionsActions");
    if (pre) pre.style.display = 'none';
    if (panel) panel.style.display = '';
    if (actions) actions.style.display = 'flex';
    loadToolVersions();
}

function diagRunning(label) {
    showDiagTerminal();
    const out = document.getElementById("diagOutput");
    if (out) out.innerText = `$ ${label}\nRunning...`;
}

function diagResult(label, text) {
    const out = document.getElementById("diagOutput");
    if (out) out.innerText = `$ ${label}\n\n${text}`;
}

async function runDiagnostic(key) {
    diagRunning(key);
    try {
        const res = await fetch('/api/system/diagnostics', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: key })
        });
        const data = await res.json();
        diagResult(data.success ? data.command : key, data.success ? data.output : `[ERROR] ${data.error}`);
    } catch (err) {
        diagResult(key, '[REQUEST FAILED]');
    }
}

async function loadToolVersions() {
    const tbody = document.getElementById("toolVersionsBody");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="text-subtle">Checking...</td></tr>';

    try {
        const res = await fetch('/api/system/tool_versions');
        const data = await res.json();

        if (!data.success) {
            tbody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 5;
            cell.className = 'text-danger';
            cell.textContent = data.error;
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
        }

        tbody.innerHTML = '';
        data.tools.forEach(t => {
            const row = document.createElement('tr');

            const nameCell = document.createElement('td');
            nameCell.className = 'text-info fw-bold';
            nameCell.textContent = t.tool;

            const verCell = document.createElement('td');
            verCell.className = t.installed ? 'text-light' : 'text-subtle';
            verCell.textContent = t.installed ? t.version : '--';

            const latestCell = document.createElement('td');
            latestCell.className = t.update_available ? 'text-warning fw-bold' : 'text-subtle';
            latestCell.textContent = t.latest_version || (t.package ? 'Unknown' : '--');

            const statusCell = document.createElement('td');
            const statusBadge = document.createElement('span');
            statusBadge.className = `badge ${t.installed ? 'bg-success' : 'bg-danger'}`;
            statusBadge.textContent = t.installed ? 'Installed' : 'Not Installed';
            statusCell.appendChild(statusBadge);

            const actionCell = document.createElement('td');
            if (!t.installed && t.package) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-xs btn-outline-success py-0 px-2';
                btn.innerHTML = '<i class="bi bi-download me-1"></i>Install';
                btn.onclick = () => installTool(t.package, btn);
                actionCell.appendChild(btn);
            } else if (t.installed && t.update_available && t.package) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-xs btn-outline-warning py-0 px-2';
                btn.innerHTML = '<i class="bi bi-arrow-up-circle me-1"></i>Update';
                btn.onclick = () => installTool(t.package, btn);
                actionCell.appendChild(btn);
            } else if (t.installed && t.package) {
                const upToDate = document.createElement('span');
                upToDate.className = 'text-subtle';
                upToDate.textContent = 'Up to date';
                actionCell.appendChild(upToDate);
            }

            row.appendChild(nameCell);
            row.appendChild(verCell);
            row.appendChild(latestCell);
            row.appendChild(statusCell);
            row.appendChild(actionCell);
            tbody.appendChild(row);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-danger">Request failed.</td></tr>';
    }
}

// Shared by both the "Install" and "Update" buttons - `apt-get install -y
// <pkg>` already upgrades an existing package to the latest candidate when
// one is available, so there's no separate "update" command/endpoint needed.
async function installTool(pkg, btnEl) {
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Working...';
    }

    try {
        const res = await fetch('/api/system/install_tool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ package: pkg })
        });
        const data = await res.json();
        if (!data.success) showToast(`Install/update failed: ${data.error}`, 'danger');
        loadToolVersions(); // refresh the whole table either way
    } catch (err) {
        showToast('Install request failed.', 'danger');
        loadToolVersions();
    }
}

async function ejectTargetDrive() {
    const drive = document.getElementById("ejectDriveSelect")?.value;
    if (!drive) return showToast("Select a drive to detach first.", 'warning');
    if (!confirm(`Safely unmount and flush ${drive}? Only do this once any acquisition using it has finished.`)) return;

    try {
        const res = await fetch('/api/system/eject_drive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive })
        });
        const data = await res.json();
        showToast(data.success ? data.message : `Eject Failed: ${data.error}`, data.success ? 'success' : 'danger');
        if (data.success) refreshDrives();
    } catch (err) {}
}

async function purgeConsoleLogs() {
    try {
        await fetch('/api/system/maintenance/purge_logs', { method: 'POST' });
    } catch (err) {}
}

async function restartForensicService() {
    if (!confirm("Restart the forensic web service now? Any running acquisition job state will be lost, and this page will disconnect briefly.")) return;
    diagRunning("Restart Service");
    try {
        const res = await fetch('/api/system/restart_service', { method: 'POST' });
        const data = await res.json();
        diagResult("Restart Service", data.message || data.error);
    } catch (err) {
        diagResult("Restart Service", "[REQUEST FAILED]");
    }
}

async function restartKioskDisplay() {
    diagRunning("Reload Touch Kiosk");
    try {
        const res = await fetch('/api/system/restart_kiosk', { method: 'POST' });
        const data = await res.json();
        diagResult("Reload Touch Kiosk", data.message || data.error);
    } catch (err) {
        diagResult("Reload Touch Kiosk", "[REQUEST FAILED]");
    }
}

async function gitUpdateApp() {
    if (!confirm("Pull the latest code from the configured git remote and restart the service? Only do this if you trust that remote.")) return;
    switchToTab('settings-tab'); // so the Diagnostics output console below is visible if this was triggered from the update-available toast on a different tab
    diagRunning("Update App (Git Pull)");
    try {
        const res = await fetch('/api/system/git_update', { method: 'POST' });
        const data = await res.json();
        diagResult("Update App (Git Pull)", data.message || data.error);
        if (data.success) {
            const badge = document.getElementById('updateAvailableBadge');
            if (badge) badge.style.display = 'none';
        }
    } catch (err) {
        diagResult("Update App (Git Pull)", "[REQUEST FAILED]");
    }
}

// --- Update-available check + notification ---------------------------------------
// Read-only /api/system/check_update (a plain `git fetch` + commit-count comparison,
// never a pull) is polled once shortly after page load and then periodically in the
// background - this is what lets an update surface as a proactive notification
// instead of only ever being discovered by someone manually opening Settings and
// clicking a button. Gated the same way the backend route itself is (requires
// 'settings' permission) - an account that can't run the real update wouldn't be
// able to act on the notification anyway, so this just quietly no-ops (a 403) for
// anyone else rather than nagging them with something they can't do.
let updateAvailableNotificationShown = false; // only pop the actionable toast once per page load - repeat checks just keep the Settings badge current

async function checkForAppUpdate(manual) {
    const btn = document.getElementById('btnCheckUpdate');
    if (manual && btn) btn.disabled = true;
    try {
        const res = await fetch('/api/system/check_update');
        if (res.status === 403) return; // no 'settings' permission - silent no-op, not an error the examiner needs to see
        const data = await res.json();
        const badge = document.getElementById('updateAvailableBadge');

        if (!data.success) {
            if (manual) showToast(`Could not check for updates: ${data.error}`, 'warning');
            return;
        }

        if (data.update_available) {
            const verText = data.latest_version ? `v${data.latest_version}` : 'a newer version';
            if (badge) {
                badge.textContent = `Update available: ${verText}`;
                badge.style.display = 'inline-block';
            }
            if (!updateAvailableNotificationShown) {
                showUpdateAvailableNotification(verText, data.commits_behind);
                updateAvailableNotificationShown = true;
            } else if (manual) {
                showToast(`Update available: ${verText} (${data.commits_behind} commit(s) behind).`, 'info');
            }
        } else {
            if (badge) badge.style.display = 'none';
            if (manual) showToast(`You're up to date (v${data.current_version}).`, 'success');
        }
    } catch (err) {
        if (manual) showToast('Could not check for updates.', 'warning');
    } finally {
        if (manual && btn) btn.disabled = false;
    }
}

// A dedicated, non-auto-dismissing toast with real action buttons ("Update Now" /
// "Dismiss") - the plain showToast() above is deliberately message-only/auto-hiding
// (see its own comment), which doesn't fit an actionable "something you can act on
// right now, and might want to leave visible until you do" notification like this.
function showUpdateAvailableNotification(verText, commitsBehind) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toastEl = document.createElement('div');
    toastEl.className = 'toast align-items-center text-bg-primary border-0';
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');

    const flexDiv = document.createElement('div');
    flexDiv.className = 'd-flex';

    const body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = `An update is available (${verText}, ${commitsBehind} commit(s) behind).`;
    flexDiv.appendChild(body);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
    closeBtn.setAttribute('data-bs-dismiss', 'toast');
    closeBtn.setAttribute('aria-label', 'Close');
    flexDiv.appendChild(closeBtn);
    toastEl.appendChild(flexDiv);

    const btnRow = document.createElement('div');
    btnRow.className = 'pe-2 pb-2 d-flex gap-2';

    const updateBtn = document.createElement('button');
    updateBtn.type = 'button';
    updateBtn.className = 'btn btn-sm btn-light fw-bold';
    updateBtn.textContent = 'Update Now';
    updateBtn.onclick = () => { bootstrap.Toast.getInstance(toastEl)?.hide(); gitUpdateApp(); };
    btnRow.appendChild(updateBtn);

    const laterBtn = document.createElement('button');
    laterBtn.type = 'button';
    laterBtn.className = 'btn btn-sm btn-outline-light';
    laterBtn.textContent = 'Dismiss';
    laterBtn.onclick = () => { bootstrap.Toast.getInstance(toastEl)?.hide(); };
    btnRow.appendChild(laterBtn);

    toastEl.appendChild(btnRow);
    container.appendChild(toastEl);

    const bsToast = new bootstrap.Toast(toastEl, { autohide: false });
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
    bsToast.show();
}

async function updateOperatingSystem() {
    if (!confirm("Run apt-get update && upgrade -y in the background? This can take a while and should not be interrupted.")) return;
    diagRunning("Update OS Packages");
    try {
        const res = await fetch('/api/system/os_update', { method: 'POST' });
        const data = await res.json();
        diagResult("Update OS Packages", data.message || data.error);
    } catch (err) {
        diagResult("Update OS Packages", "[REQUEST FAILED]");
    }
}

async function triggerSystemPower(action) {
    const label = action === 'poweroff' ? 'Power Off Station' : 'Reboot Appliance';
    const confirmLabel = action === 'poweroff' ? 'power off' : 'reboot';
    if (!confirm(`Are you sure you want to ${confirmLabel} the station now? Any running acquisition will be interrupted.`)) return;
    diagRunning(label);
    try {
        const res = await fetch('/api/system/power', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const data = await res.json();
        diagResult(label, data.message || data.error);
    } catch (err) {
        diagResult(label, "[REQUEST FAILED]");
    }
}

// Shared by fetchNetworkInterfaces() below to build the same pill list
// into whichever container is passed - the navbar's (desktop-only) and
// its Settings > Service Controls & Diagnostics mirror (mobile-only) both
// render from the one /api/system/interfaces fetch, not two separate polls.
function renderInterfacePills(container, interfaces) {
    if (!container) return;
    // Dispose any existing tooltips before rebuilding - otherwise
    // Bootstrap's tooltip instances leak/stay attached to elements
    // that no longer exist once we replace the container's contents.
    container.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        const existing = bootstrap.Tooltip.getInstance(el);
        if (existing) existing.dispose();
    });

    container.innerHTML = '';
    interfaces.forEach(iface => {
        const pill = document.createElement('span');
        pill.className = 'badge bg-dark border border-secondary text-light font-monospace fw-normal';
        pill.style.cursor = 'default';
        pill.setAttribute('data-bs-toggle', 'tooltip');
        pill.setAttribute('data-bs-placement', 'bottom');
        pill.setAttribute('data-bs-html', 'true');
        pill.setAttribute('title', `Status: ${iface.active ? 'UP' : 'DOWN'}<br>IP: ${iface.ip}<br>MAC: ${iface.mac}<br>Download: ${iface.download_mbps} MB/s<br>Upload: ${iface.upload_mbps} MB/s`);

        const dot = document.createElement('span');
        dot.className = 'me-1';
        dot.innerHTML = iface.active ? '<i class="bi bi-circle-fill text-success" style="font-size:8px"></i>' : '<i class="bi bi-circle-fill text-secondary" style="font-size:8px"></i>';
        pill.appendChild(dot);
        pill.appendChild(document.createTextNode(iface.interface));

        container.appendChild(pill);
        new bootstrap.Tooltip(pill, { trigger: 'hover focus' });
    });
}

async function fetchNetworkInterfaces() {
    const headerContainer = document.getElementById("headerInterfacesContainer");
    const settingsContainer = document.getElementById("settingsInterfacesContainer");
    if (!headerContainer && !settingsContainer) return;

    try {
        const res = await fetch('/api/system/interfaces');
        const data = await res.json();

        if (data.success && data.interfaces) {
            renderInterfacePills(headerContainer, data.interfaces);
            renderInterfacePills(settingsContainer, data.interfaces);
        }
    } catch (err) {
        if (headerContainer) headerContainer.innerHTML = '<span class="text-danger small">Error</span>';
        if (settingsContainer) settingsContainer.innerHTML = '<span class="text-danger small">Error</span>';
    }
}

async function fetchProgress() {
    try {
        const res = await fetch('/api/progress');
        const data = await res.json();

        const currentSpeed = data.speed_mbps || 0;
        
        // Update Standard Tab Status
        if (document.getElementById("speedVal")) document.getElementById("speedVal").innerText = `${currentSpeed.toFixed(1)} MB/s`;
        if (document.getElementById("bytesVal") && data.total_bytes > 0) {
            document.getElementById("bytesVal").innerText = `${(data.transferred_bytes / (1024**3)).toFixed(2)} / ${(data.total_bytes / (1024**3)).toFixed(2)} GB`;
        }

        if (data.active) {
            if (document.getElementById("progressBar")) document.getElementById("progressBar").style.width = `${data.progress_percent}%`;
            if (document.getElementById("progressPct")) document.getElementById("progressPct").innerText = `${data.progress_percent.toFixed(1)}%`;
            if (document.getElementById("jobStatus")) document.getElementById("jobStatus").innerText = `Status: ${data.status}`;
            
            const logOutput = document.getElementById("logOutput");
            if (logOutput && data.log) {
                logOutput.innerText = data.log;
                logOutput.scrollTop = logOutput.scrollHeight;
            }

            if (document.getElementById("recoveryProgressBar")) document.getElementById("recoveryProgressBar").style.width = `${data.progress_percent}%`;
            if (document.getElementById("recoveryProgressPct")) document.getElementById("recoveryProgressPct").innerText = `${data.progress_percent.toFixed(1)}%`;
            if (document.getElementById("recoveryJobStatus")) document.getElementById("recoveryJobStatus").innerText = `Status: ${data.status}`;

            const recoveryLogOutput = document.getElementById("recoveryLogOutput");
            if (recoveryLogOutput && data.log) {
                recoveryLogOutput.innerText = data.log;
                recoveryLogOutput.scrollTop = recoveryLogOutput.scrollHeight;
            }

            // Mobile forensics jobs (ios_backup / android_backup / android_pull) don't
            // have a reliable global percentage - just show live bytes + status + log.
            if (document.getElementById("mobileJobStatus")) document.getElementById("mobileJobStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("mobileBytesVal")) {
                document.getElementById("mobileBytesVal").innerText = `${(data.transferred_bytes / (1024**2)).toFixed(1)} MB`;
            }
            const mobileLogOutput = document.getElementById("mobileLogOutput");
            if (mobileLogOutput && data.log) {
                mobileLogOutput.innerText = data.log;
                mobileLogOutput.scrollTop = mobileLogOutput.scrollHeight;
            }
        }

        // File Explorer's in-image Triage Scan and Geolocation Export are
        // the in-image tools that are real background jobs (every other one
        // is synchronous) - mirrors whatever job is active station-wide,
        // same as the Mobile block above does, not gated to just these two
        // job formats specifically for the progress row itself (one shared
        // current_job, shown from every tab that cares, regardless of which
        // tab actually started it).
        const explorerProgress = document.getElementById("explorerJobProgress");
        if (explorerProgress) explorerProgress.style.display = data.active ? 'block' : 'none';
        if (data.active) {
            if (document.getElementById("explorerJobStatus")) document.getElementById("explorerJobStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("explorerJobProgressBar")) document.getElementById("explorerJobProgressBar").style.width = `${data.progress_percent}%`;
        }
        if (document.getElementById("explorerImageTriageBtn")) document.getElementById("explorerImageTriageBtn").disabled = data.active;
        if (document.getElementById("explorerImageGeoBtn")) document.getElementById("explorerImageGeoBtn").disabled = data.active;

        // Case-wide "Verify All Evidence" (A4) - same one-shared-job mirror pattern as the
        // Mobile/Explorer blocks above, scoped to its own format so it never shows stale
        // progress from an unrelated job.
        const verifyProgress = document.getElementById("verifyAllEvidenceProgress");
        const verifyBtn = document.getElementById("btnVerifyAllEvidence");
        if (verifyBtn) verifyBtn.disabled = data.active;
        if (data.format === "verify_all_evidence" && data.active) {
            if (verifyProgress) verifyProgress.style.display = 'block';
            if (document.getElementById("verifyAllEvidenceStatus")) document.getElementById("verifyAllEvidenceStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("verifyAllEvidenceBar")) document.getElementById("verifyAllEvidenceBar").style.width = `${data.progress_percent}%`;
        } else if (verifyProgress) {
            verifyProgress.style.display = 'none';
        }
        // On the exact active->inactive transition for this format, re-load the case so
        // renderCaseDashboard()/renderVerifyAllEvidenceLastResult() pick up the fresh
        // last_verification result the job just wrote - not on every poll, just once.
        if (data.format === "verify_all_evidence" && lastImageJobActiveByFormat["verify_all_evidence"] && !data.active && activeCase) {
            loadCaseForEditing();
        }

        // Case Bundle Export (A5) - same one-shared-job mirror pattern.
        const bundleProgress = document.getElementById("caseBundleExportProgress");
        const bundleBtn = document.getElementById("btnCaseBundleExport");
        if (bundleBtn) bundleBtn.disabled = data.active;
        if (data.format === "case_bundle_export" && data.active) {
            if (bundleProgress) bundleProgress.style.display = 'block';
            if (document.getElementById("caseBundleExportStatus")) document.getElementById("caseBundleExportStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("caseBundleExportBar")) document.getElementById("caseBundleExportBar").style.width = `${data.progress_percent}%`;
        } else if (bundleProgress) {
            bundleProgress.style.display = 'none';
        }

        // The progress row above hides the instant the job goes inactive,
        // which could hide a "Completed Successfully"/"Failed"/"Stopped"
        // result before it's ever seen - this catches that active->inactive
        // transition, per job format, and surfaces it once.
        const completionMsgFn = IMAGE_JOB_COMPLETION_MESSAGES[data.format];
        if (completionMsgFn) {
            if (lastImageJobActiveByFormat[data.format] && !data.active) {
                showToast(completionMsgFn(data.status), 'info');
            }
            lastImageJobActiveByFormat[data.format] = data.active;
        }

        // Same active->inactive transition, generalized across every job format (not
        // just the in-image ones above) to bump that job's owning tab's sidebar badge -
        // but only when the examiner isn't already looking at that tab, since there's
        // nothing to notify them of if they watched it finish themselves.
        if (lastGlobalJobActive && !data.active) {
            // The status/progress/log fields above only update while data.active
            // is true - a fast job (e.g. a small Logical Acquisition, now sharing
            // this same Output panel as of 2026-08-27) can start and finish
            // between two ~2s polls with no active:true frame ever observed,
            // leaving the last mid-run text (e.g. "Copying files...") frozen on
            // screen forever instead of ever showing "Completed Successfully".
            // One final render here, on the exact active->inactive transition,
            // catches that for every shared Output panel in the app.
            if (document.getElementById("jobStatus")) document.getElementById("jobStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("progressBar")) document.getElementById("progressBar").style.width = `${data.progress_percent || 0}%`;
            if (document.getElementById("progressPct")) document.getElementById("progressPct").innerText = `${(data.progress_percent || 0).toFixed(1)}%`;
            const finalLogOutput = document.getElementById("logOutput");
            if (finalLogOutput && data.log) {
                finalLogOutput.innerText = data.log;
                finalLogOutput.scrollTop = finalLogOutput.scrollHeight;
            }

            if (document.getElementById("recoveryJobStatus")) document.getElementById("recoveryJobStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("recoveryProgressBar")) document.getElementById("recoveryProgressBar").style.width = `${data.progress_percent || 0}%`;
            if (document.getElementById("recoveryProgressPct")) document.getElementById("recoveryProgressPct").innerText = `${(data.progress_percent || 0).toFixed(1)}%`;
            const finalRecoveryLogOutput = document.getElementById("recoveryLogOutput");
            if (finalRecoveryLogOutput && data.log) {
                finalRecoveryLogOutput.innerText = data.log;
                finalRecoveryLogOutput.scrollTop = finalRecoveryLogOutput.scrollHeight;
            }

            if (document.getElementById("mobileJobStatus")) document.getElementById("mobileJobStatus").innerText = `Status: ${data.status}`;
            if (document.getElementById("mobileBytesVal")) {
                document.getElementById("mobileBytesVal").innerText = `${((data.transferred_bytes || 0) / (1024**2)).toFixed(1)} MB`;
            }
            const finalMobileLogOutput = document.getElementById("mobileLogOutput");
            if (finalMobileLogOutput && data.log) {
                finalMobileLogOutput.innerText = data.log;
                finalMobileLogOutput.scrollTop = finalMobileLogOutput.scrollHeight;
            }

            const badgeId = JOB_FORMAT_TO_NAV_BADGE[lastGlobalJobFormat];
            if (badgeId) {
                const ownerTabId = NAV_BADGE_TO_TAB_ID[badgeId];
                const activeTabBtn = document.querySelector('#forensicAppTabs .nav-link.active');
                if (!activeTabBtn || activeTabBtn.id !== ownerTabId) {
                    bumpNavBadge(badgeId);
                }
            }
            // Same transition, refreshing the Guided Workflow checklist (now under Help) so a
            // job started elsewhere and left to finish while looking at it updates without
            // waiting for its own slower 20s poll.
            if (document.getElementById('help-tab')?.classList.contains('active') && document.getElementById('helpNavWorkflow')?.classList.contains('active')) {
                refreshGuidedWorkflow();
            }
        }
        lastGlobalJobActive = data.active;
        lastGlobalJobFormat = data.format;

        // Mirrors start_imaging()'s own post-job cleanup thread, which
        // unmounts the dislocker/cryptsetup volume automatically once the
        // acquisition that was using it finishes (success, failure, or
        // Stop) - without this, the UI would keep showing "Lock / Cleanup"
        // for a mount the backend already tore down.
        if (encVolMountConsumedByJob && !data.active) {
            const typeLabel = ENC_VOL_TYPE_LABELS[encVolActiveType] || 'encrypted';
            encVolActiveMountId = null;
            encVolUnlockedSourcePath = null;
            encVolActiveType = null;
            encVolMountConsumedByJob = false;
            const lockBtn = document.getElementById("btnLockEncVol");
            if (lockBtn) lockBtn.style.display = 'none';
            const status = document.getElementById("encVolStatus");
            if (status) status.textContent = `The acquisition job finished - the ${typeLabel} volume has been automatically locked/unmounted.`;
        }

        if (throughputChart) {
            graphData.push(currentSpeed);
            graphData.shift();
            throughputChart.update('none');
        }

        // Logical Acquisition no longer has its own Start/Stop/status mirror
        // (removed 2026-08-27 when it folded into the Format dropdown) - it
        // shares startBtn/stopBtn/jobStatus/logOutput below like every other
        // acquisition format already does, so no separate handling is needed.
        if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = data.active;
        if (document.getElementById("btnRecoveryStart")) document.getElementById("btnRecoveryStart").disabled = data.active;
        if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = !data.active;
        if (document.getElementById("btnRecoveryStop")) document.getElementById("btnRecoveryStop").disabled = !data.active;
        if (document.getElementById("btnMobileStop")) document.getElementById("btnMobileStop").disabled = !data.active;
        if (data.active) {
            if (document.getElementById("btnMobileStart")) document.getElementById("btnMobileStart").disabled = true;
        } else {
            refreshMobileStartButtonState();     // re-derives disabled state from current device trust/selection + mode
        }

    } catch (err) {}
}

document.addEventListener("DOMContentLoaded", async () => {
    if (localStorage.getItem("pi_forensics_sidebar_compact") === "1") {
        const sidebar = document.getElementById("appSidebar");
        const icon = document.getElementById("sidebarToggleIcon");
        if (sidebar) sidebar.classList.add("compact");
        if (icon) icon.className = "bi bi-chevron-double-right";
    }
    initThroughputGraph();
    refreshDrives();
    loadNetworkHistory();
    loadAutoMountShares();
    toggleFormatControls();
    refreshMobileDevices();
    updateDdrescueStrategyHelp();
    updateRecoveryToolControls();
    loadReportingStats();
    updateAndroidModeHelp();
    initHelpTooltips();
    // Awaited before initActiveCaseBar() - that call can synchronously chain into
    // loadCaseForEditing() -> renderCustomFieldsForCase(), which reads this cache. A bare
    // fire-and-forget fetchCustomFieldDefs() here raced /api/report/load and regularly lost,
    // leaving Case Details permanently empty for that whole page load with nothing to
    // re-trigger a render once the cache did arrive (real bug, found via live testing).
    await fetchCustomFieldDefs();
    initActiveCaseBar(); // sets activeCase synchronously (if restored) - must run before File Explorer's first build below so it roots at the right case from the start, not '/mnt' then a moment later re-rooting
    // Explicit call, not just relying on applyActiveCaseToFields()'s own internal call above -
    // that function returns early with no case active, which would otherwise leave the Guided
    // Workflow card showing its default "--" markup instead of the real empty state on a fresh
    // page load with no active case.
    refreshGuidedWorkflow();
    initExplorerTree();
    loadExplorer(getExplorerRootPath());
    fetchWhoami();
    fetchCustomReportTemplates();

    fetchNetworkInterfaces();

    setInterval(fetchSystemInfo, 2000);
    setInterval(fetchProgress, 1000);
    setInterval(fetchNetworkInterfaces, 15000);
    // Deliberately delayed a few seconds past every other startup fetch above rather
    // than fired immediately - this one hits an external git remote (git fetch), which
    // on a station with no internet access (a real, common deployment state for this
    // app - see CLAUDE.md) can take the route's own full 15s timeout to fail; no reason
    // to make that compete with the startup calls that actually populate the page.
    // Six-hour recheck after that - frequent enough to notice a real release without
    // hammering the remote on every page load from every open tab.
    setTimeout(() => checkForAppUpdate(false), 8000);
    setInterval(() => checkForAppUpdate(false), 6 * 60 * 60 * 1000);

    // Restore the last-visited top-level tab, placed last so every other init call above
    // (activeCase, explorer tree, whoami/permissions, etc.) has already run before this tab's own
    // onclick side effects (e.g. Settings' loadChainOfCustodyLog()) fire. Uses a real .click() -
    // not switchToTab()'s bootstrap.Tab(...).show() - so those onclick handlers actually run too,
    // matching a genuine click exactly (.show() alone would switch the pane but skip them).
    const savedTabId = localStorage.getItem(LAST_TAB_STORAGE_KEY);
    if (savedTabId && savedTabId !== 'home-tab') {
        document.getElementById(savedTabId)?.click();
    }
});

function initHelpTooltips() {
    // Bootstrap tooltips need explicit init - "hover focus" so they also
    // work reasonably on touch (tapping a button focuses it first), since
    // this is primarily a touchscreen kiosk interface, not a mouse-driven one.
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        new bootstrap.Tooltip(el, { trigger: 'hover focus', placement: el.getAttribute('data-bs-placement') || 'top' });
    });
}
