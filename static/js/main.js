let isWriteBlockActive = true;
let throughputChart = null;
const maxGraphPoints = 30;
const graphData = Array(maxGraphPoints).fill(0);
const graphLabels = Array(maxGraphPoints).fill('');

let currentDrivesList = [];

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

// activeCase shape: {case_number, examiner, case_folder} | null
let activeCase = null;
let caseManagerModalInstance = null;
const ACTIVE_CASE_STORAGE_KEY = 'pi_forensics_active_case';

async function toggleOnscreenKeyboard() {
    try {
        const res = await fetch('/api/system/toggle_keyboard', { method: 'POST' });
        const data = await res.json();
        if (!data.success) alert(`Keyboard toggle failed: ${data.error}`);
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
    // ddrescue has no built-in hashing the way dc3dd/dcfldd/ewfacquire do -
    // hide the checkboxes rather than show controls that don't apply.
    if (hashRow) hashRow.style.display = (fmt === 'ddrescue') ? 'none' : '';

    const FORMAT_HELP = {
        dd: "Raw bit-for-bit copy using dc3dd, with hashing built in. A solid default for most acquisitions.",
        dcfldd: "Same idea as dc3dd (raw copy + hashing), from a different tool - useful if you specifically need dcfldd's output style.",
        plain_dd: "Plain GNU dd, no built-in hashing (computed separately after). Supports true direct disk access, bypassing the cache on read.",
        e01: "EnCase-compatible format (.E01) - widely used in law enforcement/EnCase workflows, supports compression and splitting into segments.",
        aff: "Advanced Forensic Format - acquires a raw image first, then converts it to .aff. You'll be asked whether to keep the intermediate raw file.",
        ddrescue: "For damaged, clicking, or failing drives - works around bad sectors instead of stopping, with configurable retry strategy below. No built-in hashing; verify the result separately once you have a usable copy.",
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
            "Make sure the case you're reporting on is the active case (top-left \"Case\" button), then open the Reporting tab - it loads that case automatically, no manual file browsing needed.",
            "Use \"Case Notes\" as you work, not just at the end - it's a timestamped, append-only journal (each note gets an author and a local integrity hash; editing keeps the original text rather than overwriting it). This becomes the \"Forensic Analysis / Steps Taken\" section of the exported report.",
            "\"Report Narrative\" holds the polished closing write-up (executive summary, objectives, findings, limitations, conclusion) - a separate, deliberately distinct thing from the running Case Notes journal.",
            "\"Jobs\" shows every acquisition/recovery/mobile job run against this case with full telemetry and hashes; \"Audit Trail\" is the station-wide activity log filtered to this case number.",
            "When ready, go to Export - pick PDF or HTML and choose which sections/evidence items to include, then export. Attached photos and text files get embedded directly in the output, not just listed by path.",
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
    wrap.className = 'p-2 bg-dark border border-secondary rounded-2';

    const titleEl = document.createElement('div');
    titleEl.className = 'text-info fw-bold small mb-2';
    titleEl.textContent = data.title;
    wrap.appendChild(titleEl);

    const ol = document.createElement('ol');
    ol.className = 'small text-light mb-2 ps-3';
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
        goBtn.onclick = () => {
            if (helpModalInstance) helpModalInstance.hide();
            switchToTab(data.tabId);
        };
        wrap.appendChild(goBtn);
    }

    container.appendChild(wrap);
}

// ===================== HELP MODAL =====================
let helpModalInstance = null;

function openHelpModal() {
    if (!helpModalInstance) {
        helpModalInstance = new bootstrap.Modal(document.getElementById('helpModal'));
    }
    populateFaq();
    populateToolReference();
    populateHelpInfo();
    helpModalInstance.show();
}

document.addEventListener('click', (e) => {
    const btn = e.target.closest('#helpTabNav .nav-link');
    if (!btn) return;
    document.querySelectorAll('#helpTabNav .nav-link').forEach(el => el.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.getAttribute('data-help-tab');
    document.querySelectorAll('.help-pane').forEach(pane => {
        pane.classList.toggle('d-none', pane.id !== `helpPane-${target}`);
    });
});

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
        ]
    },
    {
        group: "Case Management & Reporting",
        items: [
            {
                q: "What's an Active Case, and do I have to use one?",
                a: "The \"Case\" button at the top of every page creates or selects a case, which then auto-fills Case #, Examiner, and Destination on every tool below - including Reporting, which loads that case's data automatically with no manual file browsing. It's entirely optional; every tool works the same with no case selected, you'll just fill those fields in by hand."
            },
            {
                q: "Case Notes vs. Report Narrative - what's the difference?",
                a: "Case Notes (Reporting tab) is a timestamped, append-only journal you add to as you work - each note gets an author and a local integrity hash, and editing keeps the original text rather than overwriting it. It becomes the exported report's \"Forensic Analysis / Steps Taken\" section. Report Narrative is the polished closing write-up (executive summary, objectives, findings, limitations, conclusion) you write once, near the end - a deliberately separate thing from the running notes journal."
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
                a: "Yes - Settings > Security lets an account with User & Group Management access create real per-user accounts, each assigned to a group. Admin always has full access to everything; Analyst is the default operational group (every tool, no station configuration or user management); you can also create custom groups with checkboxes for exactly which tabs/actions they can access. The \"Logged in as\" button in the top-right lets you switch accounts without a full logout, since HTTP Basic Auth has no real session to log out of."
            },
            {
                q: "My browser says this site isn't secure or the certificate isn't trusted - what do I do?",
                a: "This station uses a self-signed HTTPS certificate, so every browser warns on first visit until that specific device explicitly trusts it. Settings > Security has a \"Generate & Install\" button if you need a fresh certificate (e.g. after the Pi's IP changed), a \"Download Certificate\" button, and step-by-step trust instructions for Windows, macOS, Linux, iOS, Android, and Firefox specifically."
            },
            {
                q: "How do I access this station from another computer?",
                a: "Navigate to the station's IP address (or hostname, if you set one up) on port 5000, or over HTTPS if a TLS reverse proxy was configured. Every remote connection requires a real login - there's no bypass for remote/LAN access, only for the physical kiosk touchscreen."
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
        ]
    },
];

function populateFaq() {
    const container = document.getElementById("faqAccordion");
    if (!container || container.children.length > 0) return; // build once
    let idx = 0;
    FAQ_GROUPS.forEach(group => {
        const groupLabel = document.createElement('div');
        groupLabel.className = 'text-info fw-bold small text-uppercase mt-3 mb-1';
        groupLabel.style.letterSpacing = '0.5px';
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
            ["MVT (Mobile Verification Toolkit)", "Checks an already-acquired iOS or Android backup for spyware/compromise indicators. Right-click the backup folder and choose the scan for its platform."],
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
        headerCell.className = 'text-info fw-bold small text-uppercase pt-3';
        headerCell.style.letterSpacing = '0.5px';
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

function populateHelpInfo() {
    const container = document.getElementById("infoContent");
    if (!container || container.children.length > 0) return; // build once

    const sections = [
        ["Where does my data go?", "Acquisitions, recovered files, and reports are written under the evidence root (/mnt by default). A case's data (metadata, notes, job telemetry, attachments) consolidates into a single JSON file per case rather than scattered per-job files. Nothing is uploaded anywhere automatically."],
        ["Chain of custody & user accounts", "Settings > Audit Log keeps a station-wide log of significant actions (acquisitions, deletes, copies, report edits, logins) with timestamp, source IP, and - since this station uses real per-user accounts rather than one shared login - which logged-in user did it. Reporting's \"Audit Trail\" sub-tab shows the same log filtered to one case."],
        ["Case management", "The \"Case\" button at the top of every page creates or selects a case, storing its evidence under a real per-case folder instead of loosely filename-prefixed files scattered in one directory. An older case created before consolidated case files existed can be migrated to the new format from the Case Manager, non-destructively - the originals are kept, renamed with a backup suffix."],
        ["Physical kiosk vs. remote access", "The touchscreen kiosk skips the login prompt by default (a setting called FORENSIC_KIOSK_AUTH_BYPASS) - physical access to the device already implies a high level of trust. Remote/LAN access always requires a real login, with no exceptions."],
        ["HTTPS & certificates", "This station can run behind an nginx TLS reverse proxy with a self-signed certificate. Settings > Security can generate a fresh one - including every IP address the station currently has, so browsers don't also flag a hostname mismatch on top of the expected self-signed warning - or you can install your own certificate (e.g. one signed by a real CA) instead. The self-signed warning itself only goes away once a client device explicitly trusts the certificate; step-by-step instructions per OS/browser are right there in Settings."],
        ["Updating this station", "Settings > Service Controls & Diagnostics has buttons to pull the latest app code (git) or update OS packages (apt) - both need internet access and pull from external sources, so only use them on a station where you trust those sources."],
    ];

    sections.forEach(([title, body]) => {
        const wrap = document.createElement('div');
        wrap.className = 'mb-3 p-2 bg-dark border border-secondary rounded-2';
        const titleEl = document.createElement('div');
        titleEl.className = 'text-info fw-bold small mb-1';
        titleEl.textContent = title;
        const bodyEl = document.createElement('div');
        bodyEl.className = 'text-subtle small';
        bodyEl.textContent = body;
        wrap.appendChild(titleEl);
        wrap.appendChild(bodyEl);
        container.appendChild(wrap);
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
    };
    helpText.textContent = MODE_HELP[sel.value] || '';
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

function buildExplorerListingTable() {
    const table = document.createElement('table');
    table.className = 'table table-dark table-sm table-hover mb-0';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    [['name', 'Name'], ['size', 'Size'], ['modified', 'Modified']].forEach(([field, label]) => {
        const th = document.createElement('th');
        th.className = 'explorer-sort-th';
        th.onclick = () => sortExplorerRows(field);
        let text = label;
        if (explorerSortField === field) text += explorerSortDir === 'asc' ? ' ▲' : ' ▼';
        th.textContent = text;
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

    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);

    tr.onclick = () => {
        document.querySelectorAll(`.file-pane .file-item`).forEach(el => el.classList.remove('active'));
        tr.classList.add('active');

        activeSelectedFile = item.path;
        activeSelectedIsDir = item.is_dir;

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

function explorerTreeRealAdapter() {
    return {
        cache: explorerTreeChildrenCache,
        key: (node) => node.path,
        label: (node) => node.name,
        async fetchChildren(node) {
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
                // 'image' kind so the renderer can make its chevron dive
                // straight into Sleuth Kit browsing instead of a normal
                // folder expand.
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
        navigate: (node) => loadExplorer(node.path),
        selectFile: (node) => {
            activeSelectedFile = node.raw.path;
            activeSelectedIsDir = false;
            updateContextToolbar(node.raw);
            previewSelectedFile(node.raw);
            refreshExplorerDetailsView();
        },
        contextMenu: (ev, node) => showFileContextMenu(ev, node.raw),
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
            if (!node.raw.is_dir) previewExplorerImageEntry(node.raw);
            refreshExplorerDetailsView();
        },
        contextMenu: (ev, node) => showExplorerImageContextMenu(ev, node.raw),
    };
}

// Renders one <li> for `node`. `ancestorPath` is the array of nodes from the
// tree root down to (but not including) `node` itself - threaded through so
// image-mode navigation can rebuild explorerImagePathStack without a
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
        : (node.kind === 'image' ? 'bi bi-hdd-stack text-warning me-1' : 'bi bi-file-earmark-text text-info me-1');

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
        if (node.kind === 'image') {
            // Diving into a recognized forensic image swaps the whole tree to
            // Sleuth Kit browsing (enterExplorerImageFor already does this,
            // matching the same entry point double-clicking the file in the
            // Listing table uses) - "Exit Image" in the toolbar is the way
            // back, there's no local collapse for this node once entered.
            enterExplorerImageFor(node.raw);
            return;
        }
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
            children.forEach(child => childrenUl.appendChild(renderExplorerTreeNode(child, adapter, nextAncestors)));
            li.appendChild(childrenUl);
        }
        childrenUl.style.display = '';
        toggle.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
        expanded = true;
    };

    toggle.onclick = async (ev) => {
        ev.stopPropagation();
        if (toggle.classList.contains('no-children')) return;
        if (node.kind === 'image') { await li._expand(); return; } // always (re-)enters, no local collapse state
        if (!expanded) {
            await li._expand();
        } else if (childrenUl) {
            childrenUl.style.display = 'none';
            toggle.innerHTML = '<i class="bi bi-caret-right-fill"></i>';
            expanded = false;
        }
    };

    row.onclick = () => {
        document.querySelectorAll('#explorerTreeContainer .explorer-tree-node.active').forEach(el => el.classList.remove('active'));
        row.classList.add('active');
        if (node.kind === 'dir') {
            adapter.navigate(node, ancestorPath);
        } else {
            adapter.selectFile(node);
        }
    };

    row.oncontextmenu = (ev) => {
        ev.preventDefault();
        adapter.contextMenu(ev, node);
        return false;
    };

    return li;
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
    if (explorerRealTreeRootEl && !forceRebuild) {
        // Re-attach the already-built tree, preserving whatever the examiner
        // had expanded before an image-mode excursion swapped it out - no
        // re-fetch, no lost state.
        container.innerHTML = '';
        container.appendChild(explorerRealTreeRootEl);
        return;
    }
    explorerTreeChildrenCache = {}; // stale once the root changes (e.g. switching active case)
    container.innerHTML = '';
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

        explorerRenderUpRow = data.path !== '/' ? () => {
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
            name: item.name, size: item.size_bytes, modified: item.modified, raw: item
        }));
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

function positionContextMenu(ev) {
    const menu = document.getElementById('fileContextMenu');
    if (!menu) return;
    const x = ev.clientX || (ev.touches && ev.touches[0] && ev.touches[0].clientX) || 0;
    const y = ev.clientY || (ev.touches && ev.touches[0] && ev.touches[0].clientY) || 0;
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.style.display = 'block';
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
    const binwalkBtn = document.getElementById('ctxMenuImageBinwalk');
    if (binwalkBtn) binwalkBtn.disabled = entry.is_dir;
    const stringsBtn = document.getElementById('ctxMenuImageStrings');
    if (stringsBtn) stringsBtn.disabled = entry.is_dir;
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
    const btnVerifyHash = document.getElementById("btnVerifyHash");
    const btnAttachToCase = document.getElementById("btnAttachToCase");
    const btnRecoverFromImage = document.getElementById("btnRecoverFromImage");
    const btnBinwalk = document.getElementById("btnRunBinwalk");
    const btnClamscan = document.getElementById("btnRunClamscan");
    const btnStrings = document.getElementById("btnRunStrings");
    const btnQuickTriage = document.getElementById("btnQuickTriageScan");
    const btnHashdeep = document.getElementById("btnRunHashdeep");
    const btnGeolocation = document.getElementById("btnExtractGeolocation");
    const btnMvtIos = document.getElementById("btnRunMvtIos");
    const btnMvtAndroid = document.getElementById("btnRunMvtAndroid");

    if (btnDelete) btnDelete.disabled = false;
    if (btnCopy) btnCopy.disabled = false;
    if (btnBinwalk) btnBinwalk.disabled = item.is_dir;
    if (btnStrings) btnStrings.disabled = item.is_dir;
    if (btnQuickTriage) btnQuickTriage.disabled = item.is_dir;
    if (btnClamscan) btnClamscan.disabled = false;        // works on either a file or a directory (-r)
    if (btnHashdeep) btnHashdeep.disabled = !item.is_dir;  // recursive manifest - needs a directory
    if (btnGeolocation) btnGeolocation.disabled = !item.is_dir;  // scans a whole folder of photos at once
    if (btnMvtIos) btnMvtIos.disabled = !item.is_dir;      // mvt check-backup needs a backup directory
    if (btnMvtAndroid) btnMvtAndroid.disabled = !item.is_dir;
    if (btnBrowseImage) btnBrowseImage.disabled = item.is_dir || !isImageFile(item.name);
    if (btnVerifyHash) btnVerifyHash.disabled = item.is_dir;
    if (btnAttachToCase) btnAttachToCase.disabled = item.is_dir || !activeCase;
    if (btnRecoverFromImage) btnRecoverFromImage.disabled = item.is_dir || !isImageFile(item.name);
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
            alert(`Copy failed: ${data.error}`);
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
            alert(`Delete failed: ${data.error}`);
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
    const previewBtn = document.getElementById('explorerViewPreviewBtn');
    const hexBtn = document.getElementById('explorerViewHexBtn');
    const metadataBtn = document.getElementById('explorerViewMetadataBtn');
    setPaneVisible(previewPane, view === 'preview');
    setPaneVisible(hexPane, view === 'hex');
    setPaneVisible(metadataPane, view === 'metadata');
    if (previewBtn) previewBtn.className = `btn btn-xs py-0 px-2 ${view === 'preview' ? 'btn-info' : 'btn-outline-info'}`;
    if (hexBtn) hexBtn.className = `btn btn-xs py-0 px-2 ${view === 'hex' ? 'btn-info' : 'btn-outline-info'}`;
    if (metadataBtn) metadataBtn.className = `btn btn-xs py-0 px-2 ${view === 'metadata' ? 'btn-info' : 'btn-outline-info'}`;
    // Preview doesn't need a load call here - previewSelectedFile()/
    // previewExplorerImageEntry() already populated it at selection time.
    // Hex/Metadata are fetched lazily instead, so switching to either one
    // (after selecting a file while looking at Preview) needs its own load.
    refreshExplorerDetailsView();
}

// Single dispatcher for "the currently selected file changed, or the
// examiner switched tabs - make sure whichever non-Preview view is active
// shows current data" - called both from switchExplorerRightView() and from
// every selection point (table row click, tree click, timeline click) in
// both real-fs and image mode, instead of each of those six call sites
// repeating its own `if (explorerRightView === 'x') loadY()` check.
function refreshExplorerDetailsView() {
    if (explorerRightView === 'hex') {
        if (explorerImageMode) loadExplorerImageHexPane();
        else loadExplorerHexPane();
    } else if (explorerRightView === 'metadata') {
        if (explorerImageMode) loadExplorerImageMetadataPane();
        else loadExplorerMetadataPane();
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

async function loadExplorerMetadataPane() {
    const container = document.getElementById('explorerMetadata');
    if (!container) return;

    if (!activeSelectedFile || activeSelectedIsDir) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<i class="bi bi-info-circle fs-1 text-subtle mb-2"></i><span class="text-subtle small">Select a file on the left to view its metadata.</span>';
        return;
    }

    container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
    container.innerHTML = '<span class="text-subtle small">Loading metadata...</span>';

    try {
        const res = await fetch('/api/files/exif', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile })
        });
        const data = await res.json();

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
        const table = document.createElement('table');
        table.className = 'table table-sm table-dark table-striped mb-0';
        const tbody = document.createElement('tbody');
        const entries = Object.entries(data.metadata || {});
        if (entries.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = 'No metadata found.';
            cell.className = 'text-subtle';
            row.appendChild(cell);
            tbody.appendChild(row);
        } else {
            entries.forEach(([key, value]) => renderMetadataRow(tbody, key, value));
        }
        table.appendChild(tbody);
        container.appendChild(table);
    } catch (err) {
        container.className = 'file-pane d-flex flex-column align-items-center justify-content-center text-center p-3';
        container.innerHTML = '<span class="text-danger small">Request failed.</span>';
    }
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
            body: JSON.stringify({ path: activeSelectedFile })
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
            body: JSON.stringify({ path: activeSelectedFile })
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
            body: JSON.stringify({ path: activeSelectedFile })
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
            body: JSON.stringify({ path: activeSelectedFile })
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

    try {
        const res = await fetch('/api/files/hashdeep', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, algorithm: 'sha256' })
        });
        const data = await res.json();
        if (data.success) {
            alert(`Hashed ${data.file_count} file(s).\nManifest written to:\n${data.manifest_path}`);
            loadExplorer(explorerPath);
        } else {
            alert(`hashdeep failed: ${data.error}`);
        }
    } catch (err) {}
}

async function runSelectedGeolocationExport() {
    if (!activeSelectedFile) return;

    try {
        const res = await fetch('/api/files/geolocation_kml', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile })
        });
        const data = await res.json();
        if (data.success) {
            if (data.points_found === 0) {
                alert(`Scanned ${data.files_scanned} photo(s) - none had GPS location data. No KML file was needed.`);
            } else {
                alert(`Found location data in ${data.points_found} of ${data.files_scanned} photo(s).\nKML file written to:\n${data.kml_path}`);
                loadExplorer(explorerPath);
            }
        } else {
            alert(`Geolocation export failed: ${data.error}`);
        }
    } catch (err) {}
}

async function runSelectedMvtScan(platform) {
    if (!activeSelectedFile) return;
    const label = platform === 'ios' ? 'MVT iOS Backup Scan' : 'MVT Android Backup Scan';
    showToolOutputModal(`${label}: ${activeSelectedFile.split('/').pop()}`, 'bi-phone');

    try {
        const res = await fetch('/api/files/mvt_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile, platform })
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
            alert(`MVT indicator update finished:\n\n${summary}`);
        } else {
            alert(`Update failed: ${data.error}`);
        }
    } catch (err) {
        alert('Update request failed.');
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
};
let lastImageJobActiveByFormat = {}; // job format -> was it active as of the last poll
let explorerImagePath = null;
let explorerImageOffset = 0;
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

    loadExplorerImagePartitions();
}

// explorerPath (the JS variable, not the #explorerPath DOM label) is never
// mutated while in image mode - only loadExplorer() touches it, and nothing
// calls that until exitExplorerImage() does - so it still holds the real
// filesystem directory the image lives in, with no separate state needed.
function exitExplorerImage() {
    explorerImageMode = false;
    const toolbar = document.getElementById("explorerImageToolbar");
    if (toolbar) toolbar.style.display = 'none';
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
            name: entry.name, size: entry.size, modified: entry.mtime, raw: entry
        }));
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

    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);

    tr.onclick = () => {
        document.querySelectorAll('.file-pane .file-item').forEach(el => el.classList.remove('active'));
        tr.classList.add('active');
        explorerImageSelected = entry;
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
        alert(data.success ? data.message : `Extraction failed: ${data.error}`);
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
            alert(`Extraction failed: ${extractData.error}`);
            return;
        }

        const attachRes = await fetch('/api/cases/attach_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_folder: activeCase.case_folder, file_path: extractData.path })
        });
        const attachData = await attachRes.json();
        if (attachData.success) {
            alert(`Extracted and attached to ${activeCase.case_number} as a case exhibit (${attachData.file_count} file(s) now attached). Edit captions in Reporting > Files.`);
            if (currentReportPath) loadCaseForEditing();
        } else {
            alert(`Extracted to ${extractData.path}, but attaching to the case failed: ${attachData.error}`);
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
                inode: explorerImageSelected.inode, name: explorerImageSelected.name
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
                inode: explorerImageSelected.inode, name: explorerImageSelected.name
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
            alert(`Could not start geolocation scan: ${data.error}`);
        }
        // No success alert - #explorerJobProgress + the completion
        // notification in fetchProgress() are the feedback.
    } catch (err) {
        alert('Request failed.');
    }
}

async function runImageHashManifest() {
    if (!explorerImagePath) return;
    const destinationDir = activeCase ? activeCase.case_folder : '/mnt';
    try {
        const res = await fetch('/api/image/hash_manifest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: explorerImagePath, destination_dir: destinationDir, algorithm: 'sha256' })
        });
        const data = await res.json();
        if (!data.success) {
            alert(`Hash manifest failed: ${data.error}`);
            return;
        }
        let msg = `Hashed ${data.files_hashed} file(s) inside the image.\nManifest written to:\n${data.manifest_path}`;
        if (data.files_errored > 0) {
            msg += `\n\n${data.files_errored} file(s) could not be read and were skipped.`;
        }
        if (data.truncated) {
            msg += `\n\nNote: this image has more files than could be hashed in one pass - results are partial.`;
        }
        alert(msg);
    } catch (err) {}
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
            alert(`Could not start triage scan: ${data.error}`);
        }
        // On success, no alert - #explorerJobProgress (updated by the
        // existing fetchProgress() poll) is the feedback; a completion
        // message would just be redundant with the progress log itself.
    } catch (err) {
        alert('Request failed.');
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
            alert(`Recovery failed: ${data.error}`);
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
        alert(msg);
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
async function renderReportFilesGallery() {
    const container = document.getElementById("reportFilesGallery");
    if (!container) return;
    container.innerHTML = '<div class="text-subtle small p-2">Loading...</div>';

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

    const attachedSet = new Set(currentAttachedFilesList);
    const extraFiles = discovered.filter(f => !attachedSet.has(f.path));

    container.innerHTML = '';

    if (currentAttachedFilesList.length === 0 && extraFiles.length === 0) {
        container.innerHTML = '<span class="text-subtle small">No files attached, and nothing else found in this case folder yet. Use "Browse Elsewhere..." below, or right-click a file in File Explorer and choose "Attach to Case".</span>';
        return;
    }

    const addRow = (name, sublabel, filePath, checked) => {
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
        line1.className = 'small text-break';
        line1.textContent = name; // untrusted (filename) - text node only
        textWrap.appendChild(line1);
        if (sublabel) {
            const line2 = document.createElement('div');
            line2.className = 'text-subtle small';
            line2.textContent = sublabel;
            textWrap.appendChild(line2);
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

        container.appendChild(row);
    };

    currentAttachedFilesList.forEach(fp => addRow(fp.split('/').pop(), `Attached · ${fp}`, fp, true));
    extraFiles.forEach(f => {
        const kindLabel = f.kind === 'image' ? 'Image' : f.kind === 'text' ? 'Text' : 'File';
        const sizeKb = f.size_bytes ? ` · ${(f.size_bytes / 1024).toFixed(1)} KB` : '';
        addRow(f.name, `Found in case folder · ${kindLabel}${sizeKb}`, f.path, false);
    });

    if (truncated) {
        const note = document.createElement('div');
        note.className = 'text-subtle small p-2';
        note.textContent = 'Showing the first 200 discovered files - some case-folder files were not listed.';
        container.appendChild(note);
    }
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
let reportSectionBlocksCache = []; // [{key, default_title}, ...] - server truth for the builder's palette
let reportTemplateBuilderEditing = null; // array of {key, title, enabled} while the modal is open, else null
let reportTemplateBuilderEditingId = null; // null = creating new, else the id being edited
let currentExportCustomTemplateId = null; // read by #exportEditTemplateBtn's onclick in index.html

async function fetchCustomReportTemplates() {
    try {
        const res = await fetch('/api/report_templates/custom');
        const data = await res.json();
        if (data.success) {
            customReportTemplatesCache = data.templates || [];
            reportSectionBlocksCache = data.blocks || [];
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
    selectEl.querySelectorAll('option[value^="custom:"]').forEach(opt => opt.remove());
    customReportTemplatesCache.forEach(t => {
        const opt = document.createElement('option');
        opt.value = `custom:${t.id}`;
        opt.textContent = t.name; // set via textContent, not innerHTML - template names are examiner-entered
        selectEl.appendChild(opt);
    });
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
        editBtn.onclick = () => openReportTemplateBuilder(t.id);
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-xs btn-outline-danger py-0 px-2';
        delBtn.innerHTML = '<i class="bi bi-trash3"></i>';
        delBtn.onclick = () => deleteCustomReportTemplate(t.id);
        btns.appendChild(editBtn);
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
                reportTemplateBuilderEditing.push({ key: b.key, title: '', enabled: false });
            }
        });
    } else {
        if (nameEl) nameEl.value = '';
        reportTemplateBuilderEditing = reportSectionBlocksCache.map(b => ({ key: b.key, title: '', enabled: true }));
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
        titleInput.oninput = () => { reportTemplateBuilderEditing[idx].title = titleInput.value; };

        wrap.appendChild(moveWrap);
        wrap.appendChild(checkbox);
        wrap.appendChild(titleInput);
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

async function saveReportTemplateBuilder() {
    const statusEl = document.getElementById("rtbStatus");
    const name = document.getElementById("rtbName")?.value.trim();
    if (!name) {
        if (statusEl) { statusEl.textContent = 'Template name is required.'; statusEl.className = 'small mt-2 text-danger'; }
        return;
    }

    const payload = {
        name,
        sections: reportTemplateBuilderEditing.map(r => ({ key: r.key, title: r.title || '', enabled: r.enabled !== false })),
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
            alert(data.error || 'Delete failed.');
        }
    } catch (err) {
        alert('Request failed.');
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
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control form-control-sm custom-field-input';
        input.dataset.fieldKey = def.key;
        input.value = values[def.key] || '';
        col.appendChild(label);
        col.appendChild(input);
        container.appendChild(col);
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
        hint.textContent = "This template has a fixed structure - the section/field checkboxes below only apply to Standard exports. The Forensics Report's Administrative Information section pulls from Case Number/Examiner plus whatever you configure under Custom Case Fields below (e.g. Agency, Badge Number, Requesting Authority).";
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
        row.className = 'd-flex gap-2 mb-2';
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control form-control-sm';
        input.placeholder = 'Field label (e.g. Agency)';
        input.value = def.label || '';
        input.oninput = () => { caseReportingFieldsEditing[idx].label = input.value; };
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-sm btn-outline-danger';
        delBtn.type = 'button';
        delBtn.innerHTML = '<i class="bi bi-trash3"></i>';
        delBtn.onclick = () => { caseReportingFieldsEditing.splice(idx, 1); renderCustomFieldDefsEditor(); };
        row.appendChild(input);
        row.appendChild(delBtn);
        container.appendChild(row);
    });
}

function addCustomFieldDefRow() {
    caseReportingFieldsEditing.push({ key: '', label: '' });
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
        audit_trail: document.getElementById("defSecAuditTrail")?.checked ?? true,
    };
    const jobFields = {
        telemetry: document.getElementById("defFieldTelemetry")?.checked ?? true,
        params: document.getElementById("defFieldParams")?.checked ?? true,
        hashes: document.getElementById("defFieldHashes")?.checked ?? true,
    };
    const headerText = document.getElementById("reportBrandingText")?.value || '';
    const labels = caseReportingFieldsEditing.map(f => (f.label || '').trim()).filter(v => v.length > 0);

    try {
        const res = await fetch('/api/settings/case_reporting', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                report_defaults: { template, sections, job_fields: jobFields, branding: { header_text: headerText } },
                custom_case_fields: labels.map(label => ({ label }))
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
    if (!file) return alert("Select a logo image file first.");

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
        loadCaseHistory();
        renderCaseJobs();

        const attach = currentLoadedReportData.attachments || {};
        currentAttachedFilesList = attach.files || [];
        if (!currentAttachedFilesList.length && attach.image_path) {
            currentAttachedFilesList = [attach.image_path];
        }
        currentAttachmentCaptions = attach.file_captions || {};
        renderReportFilesGallery();

        const editUrls = document.getElementById("editUrls");
        if (editUrls) editUrls.value = (attach.reference_urls || []).join(", ");

        const previewEl = document.getElementById("jsonPreview");
        if (previewEl) {
            previewEl.innerText = JSON.stringify(currentLoadedReportData, null, 2);
        }
    } catch (err) {
        alert(`Failed to load report: ${err.message}`);
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

// --- Case Notes: timestamped, append-only journal (Forensic Analysis / Steps Taken) ---
// case_notes[] rides along inside currentLoadedReportData exactly like
// events[] does for Jobs - no separate list endpoint. Editing never
// overwrites in place: the prior text is preserved in edit_history, see
// /api/cases/notes/edit in app.py.
let editingCaseNoteId = null;

function renderCaseNotesList() {
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

    const formData = new FormData();
    formData.append('report_path', reportPath);
    formData.append('text', text);
    formData.append('category', category);
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
            alert(`Edit failed: ${data.error}`);
        }
    } catch (err) {
        alert(`Edit failed: ${err.message}`);
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
        appendCaseSearchGroup(container, 'Files', 'repFilesTab', [
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
        alert("Select or create a case using the bar above first.");
        return;
    }

    const customFieldValues = gatherCustomFieldValues();

    const narrativeFields = {
        executive_summary: document.getElementById("editExecSummary")?.value || "",
        objectives: document.getElementById("editObjectives")?.value || "",
        findings_summary: document.getElementById("editFindingsSummary")?.value || "",
        limitations: document.getElementById("editLimitations")?.value || "",
        conclusion: document.getElementById("editConclusion")?.value || "",
        iocs: document.getElementById("editIocs")?.value || "",
        recommendations_next_steps: document.getElementById("editRecommendations")?.value || "",
    };

    if (Array.isArray(currentLoadedReportData.events)) {
        // Consolidated case file - narrative fields are top-level;
        // case_number/examiner/notes are no longer editable here (notes
        // is set once at case creation, the other two come read-only from
        // the Active Case Bar) so all three are left untouched, same as
        // events[] and case_notes[] already are.
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

    const urlsRaw = document.getElementById("editUrls")?.value.trim() || "";
    const urlArray = urlsRaw ? urlsRaw.split(',').map(u => u.trim()).filter(u => u.length > 0) : [];

    currentLoadedReportData.attachments = {
        files: currentAttachedFilesList,
        reference_urls: urlArray,
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
            alert("Report JSON saved successfully!");
        } else {
            alert(`Save Error: ${data.error}`);
        }
    } catch (err) {
        alert(`Save failed: ${err.message}`);
    }
}

// --- Export pane (inline, part of Reporting's left-nav/right-pane) ---
// Deliberately a separate action from "Save Report Changes" - Export always
// reads whatever is currently on disk at currentReportPath (same as the old
// exportEditedPdf did after its own auto-save), so unsaved edits in the
// form are not silently included. If the examiner wants their edits in the
// exported file, Save Report Changes first, same as before. Called via the
// Export nav button's onclick, mirroring the Jobs/Audit Trail pattern.
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
        if (hint) hint.textContent = "This template has a fixed structure and always includes every section - the checkboxes below don't apply. It reuses this case's existing data under the reference template's section labels; see the Report Narrative tab for the Indicators of Compromise / Recommendations fields it draws on.";
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
    if (!sel) return;
    const isJson = sel.value === 'json';
    // CSV never touches /api/export_report either (same client-side-only
    // reasoning as JSON - see runExportReport()), so it shares JSON's
    // template/sections-hiding treatment, just without a live preview pane.
    const isRawFormat = isJson || sel.value === 'csv';

    if (templateGroup) templateGroup.style.display = isRawFormat ? 'none' : '';
    if (optionsRow) optionsRow.style.display = isRawFormat ? 'none' : '';
    if (jsonGroup) jsonGroup.style.display = isJson ? 'block' : 'none';

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
    if (!reportPath) return alert("Select an active case first.");

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
            alert("Select at least one evidence item to include.");
            return;
        }
    }

    const attachment_selection = { urls: [], files: [] };
    document.querySelectorAll('.export-attach-check:checked').forEach(cb => {
        (cb.dataset.kind === 'url' ? attachment_selection.urls : attachment_selection.files).push(cb.dataset.value);
    });

    const statusEl = document.getElementById("exportReportStatus");
    if (statusEl) { statusEl.textContent = 'Generating...'; statusEl.className = 'small text-info'; }

    try {
        const res = await fetch('/api/export_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath, format, template, sections, job_fields, event_ids, attachment_selection })
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
                alert(`This file is already attached to ${activeCase.case_number}.`);
            } else {
                alert(`Attached to ${activeCase.case_number} as a case exhibit (${data.file_count} file(s) now attached). Edit captions or reorder exhibits in Reporting > Files.`);
                if (currentReportPath) loadCaseForEditing();
            }
        } else {
            alert(`Attach to case failed: ${data.error}`);
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

    if (!imagePath) return alert("Select a file first.");

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
        if (data.cases.length === 0) {
            listEl.innerHTML = '<div class="text-subtle small p-2">No cases found yet - create one above.</div>';
            return;
        }

        listEl.innerHTML = '';
        data.cases.forEach(c => {
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
    } catch (err) {
        listEl.innerHTML = '<div class="text-danger small p-2">Request failed.</div>';
    }
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
        if (!preview.success) return alert(`Migration preview failed: ${preview.error}`);
        if (preview.already_migrated) {
            alert('This case is already on the consolidated format.');
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
        if (!applyData.success) return alert(`Migration failed: ${applyData.error}`);

        alert(`Migrated ${applyData.events_migrated} job(s) into ${applyData.case_file}.`);
        loadExistingCases();
    } catch (err) {
        alert(`Migration request failed: ${err.message}`);
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
    if (caseManagerModalInstance) caseManagerModalInstance.hide();
}

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
            }

            if (item.is_dir || isSelectableFile) {
                const btn = document.createElement("button");
                btn.className = "list-group-item list-group-item-action bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center";
                
                let icon = item.is_dir ? '<i class="bi bi-folder-fill folder-icon me-2"></i>' : '<i class="bi bi-file-earmark-text text-info me-2 fs-5"></i>';
                if (isSelectableFile) {
                    if (modalPickerMode === 'attachment') icon = '<i class="bi bi-paperclip text-info me-2 fs-5"></i>';
                    else if (modalPickerMode === 'mapfile') icon = '<i class="bi bi-map text-warning me-2 fs-5"></i>';
                    else if (modalPickerMode === 'recoverySource') icon = '<i class="bi bi-disc text-primary me-2 fs-5"></i>';
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
    const targetEl = document.getElementById(targetInputIdForModal);
    if (targetEl) targetEl.value = currentBrowsePath;
    if (folderModalInstance) folderModalInstance.hide();
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
    if (!drive) return alert("Select a connected drive first.");

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
            alert(`Drive ${drive} Write-Blocker status set to: ${newEnableState ? 'PROTECTED (Read-Only)' : 'UNLOCKED (Read-Write)'}`);
        } else {
            alert(`Write Blocker Toggle Failed: ${data.error}`);
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

    if (!host) return alert("Please enter a server IP address.");

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

    if (!share) return alert(protocol === 'sftp' ? "Please enter a remote path first." : "Please select or enter an exported share name first.");
    if (protocol === 'sftp' && !user) return alert("SFTP requires a username.");

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
            alert(`Mount Failed: ${data.error}`);
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
        if (!data.success) alert(`Failed to remove: ${data.error}`);
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
            alert(`Apply failed: ${data.error}`);
        }
    } catch (err) {
        alert(`Apply failed: ${err.message}`);
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
            alert(data.error || 'Confirmation failed.');
        }
    } catch (err) {
        alert(`Confirmation failed: ${err.message}`);
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
    const source = document.getElementById("driveSelect")?.value;
    const dest = document.getElementById("destPath")?.value;
    const fmt = document.getElementById("imageFormatSelect")?.value;

    if (!source) return alert("Select target evidence drive first.");

    const metadata = {
        case_number: document.getElementById("caseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("evidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("examiner")?.value || "UNSPECIFIED",
        notes: document.getElementById("notes")?.value || "None"
    };

    let endpoint, body;

    if (fmt === 'ddrescue') {
        const strategy = document.getElementById("ddrescueStrategySelect")?.value || "stage1_fast";
        const retries = document.getElementById("ddrescueRetries")?.value || "3";
        const directMode = document.getElementById("ddrescueDirect")?.checked ?? false;
        endpoint = '/api/start_ddrescue';
        body = { source, destination: dest, strategy, retry_passes: retries, direct_mode: directMode, metadata };
    } else {
        const compression = document.getElementById("compressionSelect")?.value;
        const split_size = document.getElementById("splitSizeSelect")?.value;
        const keep_raw = document.getElementById("affKeepRaw")?.checked ?? true;
        const selectedHashes = [];
        if (document.getElementById("hashMd5")?.checked) selectedHashes.push("md5");
        if (document.getElementById("hashSha1")?.checked) selectedHashes.push("sha1");
        if (document.getElementById("hashSha256")?.checked) selectedHashes.push("sha256");
        endpoint = '/api/start_imaging';
        body = { source, destination: dest, format: fmt, compression, split_size, hashes: selectedHashes, metadata, keep_raw };
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
        } else alert(`Start Failed: ${data.error}`);
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

function updateRecoveryToolControls() {
    const tool = document.getElementById("recoveryToolSelect")?.value;
    const sourceRow = document.getElementById("recoverySourceRow");
    const destCol = document.getElementById("recoveryDestCol");
    const mapfileRow = document.getElementById("recoveryMapfileRow");
    const metadataRow = document.getElementById("recoveryMetadataRow");
    const stopBtn = document.getElementById("btnRecoveryStop");
    const startLabel = document.getElementById("btnRecoveryStartLabel");
    const helpText = document.getElementById("recoveryToolHelpText");

    resetRecoveryOutputView();

    const isMapfile = tool === 'mapfile_inspect';
    const isTestdisk = tool === 'testdisk_analyze';
    const isSyncTool = isMapfile || isTestdisk;

    if (sourceRow) sourceRow.style.display = isMapfile ? 'none' : '';
    if (mapfileRow) mapfileRow.style.display = isMapfile ? '' : 'none';
    if (destCol) destCol.style.display = isTestdisk ? 'none' : '';
    if (metadataRow) metadataRow.style.display = isSyncTool ? 'none' : '';
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
        alert("Select a source drive, or browse to a source image file, first.");
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

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, destination: dest, metadata })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("btnRecoveryStart")) document.getElementById("btnRecoveryStart").disabled = true;
            if (document.getElementById("btnRecoveryStop")) document.getElementById("btnRecoveryStop").disabled = false;
        } else {
            alert(`Start Failed: ${data.error}`);
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
        alert("Please enter or select a .map file path first.");
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
    const startLabel = document.getElementById("btnMobileStartLabel");

    if (iosControls) iosControls.style.display = mode === 'ios' ? '' : 'none';
    if (androidControls) androidControls.style.display = mode === 'android' ? '' : 'none';
    if (startLabel) startLabel.textContent = mode === 'ios' ? 'Start iOS Backup' : 'Start Android Acquisition';

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

    refreshMobileStartButtonState();
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

    refreshMobileStartButtonState();
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
    if (!udid) return alert("Select a trusted iOS device first.");

    const dest = document.getElementById("mobileDest")?.value || '/mnt';
    const encryptEnabled = document.getElementById("mobileIosEncryptToggle")?.checked;
    const encrypt_password = encryptEnabled ? (document.getElementById("mobileIosEncryptPassword")?.value || '') : '';

    if (encryptEnabled && !encrypt_password) return alert("Enter an encryption password, or turn off the encrypted backup toggle.");

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
        if (!data.success) alert(`Start Failed: ${data.error}`);
    } catch (err) {}
}

async function startAndroidAcquisition() {
    const serial = document.getElementById("mobileAndroidSelect")?.value;
    if (!serial) return alert("Select an authorized Android device first.");

    const mode = document.getElementById("mobileAndroidMode")?.value || 'pull';
    const dest = document.getElementById("mobileDest")?.value || '/mnt';

    const metadata = {
        case_number: document.getElementById("mobileCaseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("mobileEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("mobileExaminer")?.value || "UNSPECIFIED",
        notes: `Android ${mode} via adb`
    };

    try {
        const res = await fetch('/api/mobile/start_android', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ serial, mode, destination: dest, metadata })
        });
        const data = await res.json();
        if (!data.success) alert(`Start Failed: ${data.error}`);
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

function applySidebarPermissionGating() {
    let activeTabHidden = false;
    for (const [navId, permKey] of Object.entries(SIDEBAR_TAB_PERMISSIONS)) {
        const li = document.getElementById(navId);
        if (!li) continue;
        const allowed = !!currentUserPermissions[permKey];
        li.style.display = allowed ? '' : 'none';
        if (!allowed && li.querySelector('.nav-link.active')) activeTabHidden = true;
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

// Basic Auth has no server-side session to swap, so there's no real
// "logout" - the standard client-side technique is: validate the new
// credentials directly with a manual Authorization header (bypassing
// whatever the browser already has cached for this origin), then navigate
// to a same-origin URL with those credentials embedded so the browser
// adopts them as its new cached credential going forward. Best-effort:
// most Chromium/Firefox-based browsers honor this, but it's not a
// guaranteed mechanism in every browser (see CLAUDE.md).
async function submitSwitchUser() {
    const username = document.getElementById("switchUserUsername")?.value.trim();
    const password = document.getElementById("switchUserPassword")?.value || '';
    const statusEl = document.getElementById("switchUserStatus");

    if (!username || !password) {
        if (statusEl) { statusEl.textContent = 'Enter both a username and password.'; statusEl.className = 'small text-danger'; }
        return;
    }

    if (statusEl) { statusEl.textContent = 'Checking credentials...'; statusEl.className = 'small text-info'; }

    try {
        const res = await fetch('/api/whoami', {
            headers: { 'Authorization': 'Basic ' + btoa(`${username}:${password}`) }
        });
        if (res.status === 401) {
            if (statusEl) { statusEl.textContent = 'Incorrect username or password.'; statusEl.className = 'small text-danger'; }
            return;
        }
        if (!res.ok) {
            if (statusEl) { statusEl.textContent = 'Request failed - try again.'; statusEl.className = 'small text-danger'; }
            return;
        }
        if (statusEl) { statusEl.textContent = 'Switching...'; statusEl.className = 'small text-success'; }
        location.href = `${location.protocol}//${encodeURIComponent(username)}:${encodeURIComponent(password)}@${location.host}${location.pathname}`;
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Failed: ${err.message}`; statusEl.className = 'small text-danger'; }
    }
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
        if (!data.success) alert(`Install/update failed: ${data.error}`);
        loadToolVersions(); // refresh the whole table either way
    } catch (err) {
        alert('Install request failed.');
        loadToolVersions();
    }
}

async function ejectTargetDrive() {
    const drive = document.getElementById("ejectDriveSelect")?.value;
    if (!drive) return alert("Select a drive to detach first.");
    if (!confirm(`Safely unmount and flush ${drive}? Only do this once any acquisition using it has finished.`)) return;

    try {
        const res = await fetch('/api/system/eject_drive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive })
        });
        const data = await res.json();
        alert(data.success ? data.message : `Eject Failed: ${data.error}`);
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
    diagRunning("Update App (Git Pull)");
    try {
        const res = await fetch('/api/system/git_update', { method: 'POST' });
        const data = await res.json();
        diagResult("Update App (Git Pull)", data.message || data.error);
    } catch (err) {
        diagResult("Update App (Git Pull)", "[REQUEST FAILED]");
    }
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

        // The progress row above hides the instant the job goes inactive,
        // which could hide a "Completed Successfully"/"Failed"/"Stopped"
        // result before it's ever seen - this catches that active->inactive
        // transition, per job format, and surfaces it once.
        const completionMsgFn = IMAGE_JOB_COMPLETION_MESSAGES[data.format];
        if (completionMsgFn) {
            if (lastImageJobActiveByFormat[data.format] && !data.active) {
                alert(completionMsgFn(data.status));
            }
            lastImageJobActiveByFormat[data.format] = data.active;
        }

        if (throughputChart) {
            graphData.push(currentSpeed);
            graphData.shift();
            throughputChart.update('none');
        }

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

document.addEventListener("DOMContentLoaded", () => {
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
    updateAndroidModeHelp();
    initHelpTooltips();
    initActiveCaseBar(); // sets activeCase synchronously (if restored) - must run before File Explorer's first build below so it roots at the right case from the start, not '/mnt' then a moment later re-rooting
    initExplorerTree();
    loadExplorer(getExplorerRootPath());
    fetchWhoami();
    fetchCustomFieldDefs();
    fetchCustomReportTemplates();

    fetchNetworkInterfaces();

    setInterval(fetchSystemInfo, 2000);
    setInterval(fetchProgress, 1000);
    setInterval(fetchNetworkInterfaces, 15000);
});

function initHelpTooltips() {
    // Bootstrap tooltips need explicit init - "hover focus" so they also
    // work reasonably on touch (tapping a button focuses it first), since
    // this is primarily a touchscreen kiosk interface, not a mouse-driven one.
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        new bootstrap.Tooltip(el, { trigger: 'hover focus', placement: el.getAttribute('data-bs-placement') || 'top' });
    });
}
