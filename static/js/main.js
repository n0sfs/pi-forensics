let gridMain = null;
let gridDdrescue = null;
let gridExplorer = null;
let gridMobile = null;
let gridReports = null;
let gridSettings = null;
let isLayoutLocked = true;
let isWriteBlockActive = true;
let throughputChart = null;
const maxGraphPoints = 30;
const graphData = Array(maxGraphPoints).fill(0);
const graphLabels = Array(maxGraphPoints).fill('');

let savedNetUser = '';
let savedNetPass = '';
let currentDrivesList = [];

let currentBrowsePath = '/mnt';
let folderModalInstance = null;
let modalPickerMode = 'folder';
let targetInputIdForModal = 'destPath';

let explorerPath = '/mnt';
let activeSelectedFile = null;
let activeSelectedIsDir = false;

let currentLoadedReportData = null;
let currentAttachedFilesList = [];
let exportReportModalInstance = null;

// activeCase shape: {case_number, examiner, case_folder} | null
let activeCase = null;
let caseManagerModalInstance = null;
const ACTIVE_CASE_STORAGE_KEY = 'pi_forensics_active_case';

function initGridstack() {
    gridMain = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-main');

    gridDdrescue = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-ddrescue');

    gridExplorer = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-explorer');

    gridMobile = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-mobile');

    gridReports = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-reports');

    gridSettings = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    }, '.grid-stack-settings');

    const savedMainLayout = localStorage.getItem('pi_forensics_layout_main');
    if (savedMainLayout && gridMain) {
        try { gridMain.load(JSON.parse(savedMainLayout)); } catch (e) {}
    }

    const savedDdrLayout = localStorage.getItem('pi_forensics_layout_ddr');
    if (savedDdrLayout && gridDdrescue) {
        try { gridDdrescue.load(JSON.parse(savedDdrLayout)); } catch (e) {}
    }

    const savedExplorerLayout = localStorage.getItem('pi_forensics_layout_explorer');
    if (savedExplorerLayout && gridExplorer) {
        try { gridExplorer.load(JSON.parse(savedExplorerLayout)); } catch (e) {}
    }

    const savedMobileLayout = localStorage.getItem('pi_forensics_layout_mobile');
    if (savedMobileLayout && gridMobile) {
        try { gridMobile.load(JSON.parse(savedMobileLayout)); } catch (e) {}
    }

    const savedReportsLayout = localStorage.getItem('pi_forensics_layout_reports');
    if (savedReportsLayout && gridReports) {
        try { gridReports.load(JSON.parse(savedReportsLayout)); } catch (e) {}
    }

    const savedSettingsLayout = localStorage.getItem('pi_forensics_layout_settings');
    if (savedSettingsLayout && gridSettings) {
        try { gridSettings.load(JSON.parse(savedSettingsLayout)); } catch (e) {}
    }

    if (gridMain) gridMain.on('change', () => { saveDashboardLayout(); });
    if (gridDdrescue) gridDdrescue.on('change', () => { saveDashboardLayout(); });
    if (gridExplorer) gridExplorer.on('change', () => { saveDashboardLayout(); });
    if (gridMobile) gridMobile.on('change', () => { saveDashboardLayout(); });
    if (gridReports) gridReports.on('change', () => { saveDashboardLayout(); });
    if (gridSettings) gridSettings.on('change', () => { saveDashboardLayout(); });
    
    applyLockState();
}

function toggleLayoutLock() {
    isLayoutLocked = !isLayoutLocked;
    applyLockState();
}

async function toggleOnscreenKeyboard() {
    try {
        const res = await fetch('/api/system/toggle_keyboard', { method: 'POST' });
        const data = await res.json();
        if (!data.success) alert(`Keyboard toggle failed: ${data.error}`);
    } catch (err) {}
}

function applyLockState() {
    const lockBtn = document.getElementById("layoutLockBtn");

    [gridMain, gridDdrescue, gridExplorer, gridMobile, gridReports, gridSettings].forEach(g => {
        if (!g) return;
        if (isLayoutLocked) {
            g.enableMove(false);
            g.enableResize(false);
        } else {
            g.enableMove(true);
            g.enableResize(true);
        }
    });

    if (lockBtn) {
        if (isLayoutLocked) {
            lockBtn.className = "btn btn-sm btn-outline-warning fw-bold";
            lockBtn.innerHTML = '<i class="bi bi-lock-fill me-1"></i>Layout Locked';
            document.querySelectorAll('.card-header').forEach(el => el.style.cursor = 'default');
        } else {
            lockBtn.className = "btn btn-sm btn-success fw-bold";
            lockBtn.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>Layout Unlocked';
            document.querySelectorAll('.card-header').forEach(el => el.style.cursor = 'grab');
        }
    }
}

function saveDashboardLayout() {
    if (gridMain) localStorage.setItem('pi_forensics_layout_main', JSON.stringify(gridMain.save(false)));
    if (gridDdrescue) localStorage.setItem('pi_forensics_layout_ddr', JSON.stringify(gridDdrescue.save(false)));
    if (gridExplorer) localStorage.setItem('pi_forensics_layout_explorer', JSON.stringify(gridExplorer.save(false)));
    if (gridMobile) localStorage.setItem('pi_forensics_layout_mobile', JSON.stringify(gridMobile.save(false)));
    if (gridReports) localStorage.setItem('pi_forensics_layout_reports', JSON.stringify(gridReports.save(false)));
    if (gridSettings) localStorage.setItem('pi_forensics_layout_settings', JSON.stringify(gridSettings.save(false)));
}

function resetDashboardLayout() {
    localStorage.removeItem('pi_forensics_layout_main');
    localStorage.removeItem('pi_forensics_layout_ddr');
    localStorage.removeItem('pi_forensics_layout_explorer');
    localStorage.removeItem('pi_forensics_layout_mobile');
    localStorage.removeItem('pi_forensics_layout_reports');
    localStorage.removeItem('pi_forensics_layout_settings');
    location.reload();
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

    // GridStack and Chart.js both size themselves against their container's
    // measured width, which only changes here because of a CSS transition
    // on a *sibling* element - dispatching a resize event prompts both to
    // recompute rather than staying sized for the old sidebar width.
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
            "Stay on this tab. Pick your drive from the dropdown in \"Target Source Selection\" above.",
            "Optional but recommended: check the drive's health first (SMART status shown once selected).",
            "Leave the write-blocker switched on (it's on by default) - this guarantees nothing can be written to the original drive.",
            "Under \"Format\", the default (Raw / dc3dd) is a safe choice for most cases - hover the format menu for what each option means.",
            "Fill in case number, evidence ID, and examiner name, then tap \"Start Acquisition\" and wait for it to finish.",
            "Once done, go to Reporting and check the hash to confirm the copy matches the original.",
        ]
    },
    damaged: {
        title: "Damaged, clicking, or not detected properly",
        steps: [
            "Stay on the Acquisition tab. Select your drive, then change Format to \"Recovery / ddrescue\".",
            "Start with strategy \"1. Fast Copy\" - it copies everything readable quickly without stressing a failing drive.",
            "When it finishes, go to the File Recovery tab's Mapfile Inspector to check for bad sectors.",
            "If bad sectors remain, try strategy 2 (Edge Trimming), then 3 (Intensive Scraping) if needed - each is more thorough but harder on the drive, so go in order.",
            "Once you have a copy, the File Recovery tab (PhotoRec, extundelete, foremost, scalpel) can recover files even from damaged or partly-corrupted areas.",
        ],
        tabId: "acquisition-tab"
    },
    deleted: {
        title: "Need to recover deleted files",
        steps: [
            "If you don't have an image yet, acquire one first (see the \"drive works fine\" guide above).",
            "Go to the File Recovery tab and find the PhotoRec card.",
            "Point it at your image (or the drive directly) - PhotoRec finds files by matching known file signatures rather than trusting the file system, so it works even on formatted or damaged drives.",
            "Recovered files lose their original names and folder structure. If you specifically need files with their original names/paths intact, try \"Browse Image\" (Sleuth Kit) from the file explorer's More Actions menu instead - it can show deleted-but-still-listed entries.",
        ],
        tabId: "ddrescue-tab"
    },
    phone: {
        title: "It's a phone, not a drive",
        steps: [
            "Go to the Mobile Forensics tab and connect the device with a USB cable.",
            "iPhone: tap \"Trust This Computer?\" on the phone's own screen when it appears, then select the device here and start a backup.",
            "Android: approve the USB debugging prompt on the phone's own screen, then select the device here. \"Pull Accessible Storage\" is the most reliable mode for most cases.",
            "Once finished, check Reporting for the resulting report.",
        ],
        tabId: "mobile-tab"
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

const FAQ_ITEMS = [
    {
        q: "What does the write-blocker do, and should I leave it on?",
        a: "It forces the source drive into read-only mode at the kernel level, so nothing - this app or anything else - can accidentally modify the original evidence. Leave it on for any drive you're imaging from. You'd only turn it off for a destination drive you're writing an image to."
    },
    {
        q: "Which format should I use - dd, E01, or AFF?",
        a: "Raw / dc3dd (the default) is a solid choice for most cases and includes built-in hashing. E01 is the standard if you need EnCase compatibility or want compression/splitting into segments. AFF is less common now but supported if your workflow needs it. Hover the format dropdown in the Acquisition tab for a live explanation of whichever one is selected."
    },
    {
        q: "How do I know my acquisition actually completed successfully?",
        a: "Check the status text and log during the job - it'll say \"Completed Successfully\" or \"Failed\" clearly. Afterward, go to Reporting and use \"Verify Image Hash\" to confirm the acquired image's hash matches what was recorded during acquisition."
    },
    {
        q: "What's the difference between PhotoRec and browsing an image with Sleuth Kit?",
        a: "PhotoRec finds files by matching known file signatures in the raw data - it works even on damaged or reformatted drives, but recovered files lose their original names and folder structure. Sleuth Kit's Image Browser reads the actual filesystem structure, so it shows real file names and paths (including deleted-but-still-listed entries), but needs a filesystem it can understand."
    },
    {
        q: "Does this station need an internet connection to work?",
        a: "No - acquisition, recovery, and analysis tools all run locally and don't need internet access. Internet is only used for optional things: the initial software install, ClamAV virus definition updates, and the git-pull self-update feature in Advanced Settings."
    },
    {
        q: "What happens if power is lost mid-acquisition?",
        a: "The partial image file remains on disk, but it won't have a valid hash recorded, since the job never completed. Treat an interrupted acquisition as failed and start over once power is restored - don't rely on a partial image as evidence."
    },
    {
        q: "How do I change the login password?",
        a: "Advanced Settings tab, Security & Account Password card. You'll need the current password to set a new one."
    },
    {
        q: "PhotoRec recovered files but with generic names like f0001234.jpg - is that normal?",
        a: "Yes - PhotoRec identifies file types by content, not by reading filesystem metadata, so it has no way to know the original filename. If you need original names, try browsing the image with Sleuth Kit instead (works only if the filesystem itself is still readable)."
    },
    {
        q: "How do I access this station from another computer?",
        a: "Navigate to the station's IP address (or hostname, if you set one up) on port 5000, or over HTTPS if TLS was configured during install. Every remote connection requires the login you set - there's no bypass for remote/LAN access, only for the physical kiosk touchscreen."
    },
];

function populateFaq() {
    const container = document.getElementById("faqAccordion");
    if (!container || container.children.length > 0) return; // build once
    FAQ_ITEMS.forEach((item, idx) => {
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
    });
}

const TOOL_REFERENCE = [
    ["dc3dd", "Forensic raw disk imaging with built-in hashing. The default acquisition engine."],
    ["dcfldd", "Alternate raw imaging engine, similar to dc3dd - useful if you specifically need its output style."],
    ["GNU dd", "Plain raw copy, no built-in hashing (computed separately). Supports true direct-I/O reads."],
    ["ewfacquire", "Creates EnCase-compatible .E01 images with compression and segment splitting."],
    ["affconvert", "Converts a raw image into AFF (.aff) format."],
    ["ddrescue", "Recovery-focused imaging for damaged/failing drives - select it as a Format in the Acquisition tab. Works around bad sectors instead of stopping."],
    ["extundelete", "Recovers deleted files from ext2/3/4 Linux filesystems by reading the filesystem journal - can restore original filenames/paths, unlike carving tools."],
    ["foremost / scalpel", "Alternative file carvers to PhotoRec - narrower format support but sometimes faster. scalpel is multithreaded and uses a curated signature list (jpg/png/gif/pdf/zip by default)."],
    ["TestDisk (partition analysis)", "Read-only listing of partitions TestDisk can find on a device or image - never writes anything back, unlike TestDisk's separate (and not exposed here) repair mode."],
    ["PhotoRec", "Recovers files by matching known file signatures in raw data, even on damaged/reformatted media. Loses original filenames."],
    ["Quick Triage Scan", "Scans a device or image for emails, URLs, IP addresses, card-like numbers, and phone numbers - built in, no external tool needed."],
    ["ExifTool", "Reads hidden metadata inside a file - camera info, GPS coordinates, document properties."],
    ["Sleuth Kit (mmls/fls/icat)", "Browses the real filesystem inside an acquired image, including deleted-but-listed entries, with original names/paths."],
    ["Binwalk", "Looks for other files or filesystems hidden inside a binary - useful for firmware/router images."],
    ["ClamAV", "Scans a file or folder against known malware signatures."],
    ["hashdeep", "Generates a fingerprint (hash) for every file in a folder at once, as a single manifest."],
    ["adb", "Android Debug Bridge - used to pull files, back up, or capture diagnostics from a connected Android device."],
    ["idevicebackup2 / idevicepair", "Used to pair with and back up a connected iPhone/iPad, the same protocol iTunes/Finder use."],
    ["smartctl", "Reads a drive's built-in health/diagnostic data (SMART) before committing to a long acquisition."],
];

function populateToolReference() {
    const tbody = document.getElementById("toolReferenceBody");
    if (!tbody || tbody.children.length > 0) return; // build once
    TOOL_REFERENCE.forEach(([name, desc]) => {
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
}

function populateHelpInfo() {
    const container = document.getElementById("infoContent");
    if (!container || container.children.length > 0) return; // build once

    const sections = [
        ["Where does my data go?", "Acquisitions, recovered files, and reports are written under the evidence root (/mnt by default). Nothing is uploaded anywhere automatically."],
        ["Chain of custody", "The Reporting tab keeps a station-wide log of significant actions (acquisitions, deletes, copies, report edits) with timestamp and source IP. This station has one shared login rather than per-examiner accounts, so the log shows what happened and when, reliably - not who, beyond the connecting IP."],
        ["Physical kiosk vs. remote access", "The touchscreen kiosk skips the login prompt by default (a setting called FORENSIC_KIOSK_AUTH_BYPASS) - physical access to the device already implies a high level of trust. Remote/LAN access always requires the login you set, with no exceptions."],
        ["Updating this station", "Advanced Settings has buttons to pull the latest app code (git) or update OS packages (apt) - both need internet access and pull from external sources, so only use them on a station where you trust those sources."],
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

        container.innerHTML = '';

        if (data.path !== '/') {
            const upDiv = document.createElement('div');
            upDiv.className = 'file-item text-warning fw-bold';
            upDiv.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. [Up Directory]';
            upDiv.onclick = () => {
                const parent = data.path.split('/').slice(0, -1).join('/') || '/';
                loadExplorer(parent);
            };
            container.appendChild(upDiv);
        }

        data.items.forEach(item => {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'file-item d-flex justify-content-between align-items-center';
            
            const icon = item.is_dir 
                ? '<i class="bi bi-folder-fill folder-icon me-2 fs-6"></i>' 
                : '<i class="bi bi-file-earmark-text text-info me-2 fs-6"></i>';
            
            const labelClass = item.is_dir ? 'folder-text' : 'text-light';

            // Filenames come from browsing evidence/suspect media, i.e. they
            // are attacker-controlled data. Build the label from DOM nodes
            // (item.name as a text node) instead of interpolating it into
            // innerHTML, so a crafted filename can't inject markup/script
            // into the examiner's authenticated session.
            const labelSpan = document.createElement('span');
            labelSpan.className = labelClass;
            labelSpan.innerHTML = icon; // icon markup is static/trusted, not user data
            labelSpan.appendChild(document.createTextNode(item.name));

            const sizeEl = document.createElement('small');
            sizeEl.className = 'text-subtle font-monospace';
            sizeEl.textContent = item.size_str;

            itemDiv.appendChild(labelSpan);
            itemDiv.appendChild(sizeEl);

            itemDiv.onclick = () => {
                document.querySelectorAll(`.file-pane .file-item`).forEach(el => el.classList.remove('active'));
                itemDiv.classList.add('active');

                activeSelectedFile = item.path;
                activeSelectedIsDir = item.is_dir;

                updateContextToolbar(item);
                previewSelectedFile(item);
            };

            itemDiv.ondblclick = () => {
                if (item.is_dir) loadExplorer(item.path);
            };

            itemDiv.oncontextmenu = (ev) => {
                ev.preventDefault();
                showFileContextMenu(ev, item);
                return false;
            };

            container.appendChild(itemDiv);
        });

    } catch (err) {
        container.innerHTML = `<div class="p-2 text-danger small">Error loading files</div>`;
    }
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
    const TEXT_EXT = ['.txt', '.json', '.log', '.md', '.csv', '.xml', '.html', '.htm', '.py', '.js', '.sh', '.conf', '.ini', '.cfg', '.yaml', '.yml'];

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
let contextMenuTargetItem = null;

function showFileContextMenu(ev, item) {
    contextMenuTargetItem = item;
    // Right-click also selects the item, so the same copy/delete
    // functions used by the Actions dropdown work correctly here too.
    activeSelectedFile = item.path;
    activeSelectedIsDir = item.is_dir;
    updateContextToolbar(item);

    const menu = document.getElementById('fileContextMenu');
    if (!menu) return;

    const x = ev.clientX || (ev.touches && ev.touches[0] && ev.touches[0].clientX) || 0;
    const y = ev.clientY || (ev.touches && ev.touches[0] && ev.touches[0].clientY) || 0;

    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.style.display = 'block';
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
    if (copyBtn) copyBtn.onclick = () => { hideFileContextMenu(); promptCopySelected(); };
    if (deleteBtn) deleteBtn.onclick = () => { hideFileContextMenu(); deleteSelectedFile(); };
});

function updateContextToolbar(item) {
    const btnDelete = document.getElementById("btnDeleteFile");
    const btnCopy = document.getElementById("btnCopyFile");
    const btnMetadata = document.getElementById("btnFileMetadata");
    const btnBrowseImage = document.getElementById("btnBrowseImage");
    const btnBinwalk = document.getElementById("btnRunBinwalk");
    const btnClamscan = document.getElementById("btnRunClamscan");
    const btnStrings = document.getElementById("btnRunStrings");
    const btnHashdeep = document.getElementById("btnRunHashdeep");
    const btnMvtIos = document.getElementById("btnRunMvtIos");
    const btnMvtAndroid = document.getElementById("btnRunMvtAndroid");

    if (btnDelete) btnDelete.disabled = false;
    if (btnCopy) btnCopy.disabled = false;
    if (btnMetadata) btnMetadata.disabled = item.is_dir;
    if (btnBinwalk) btnBinwalk.disabled = item.is_dir;
    if (btnStrings) btnStrings.disabled = item.is_dir;
    if (btnClamscan) btnClamscan.disabled = false;        // works on either a file or a directory (-r)
    if (btnHashdeep) btnHashdeep.disabled = !item.is_dir;  // recursive manifest - needs a directory
    if (btnMvtIos) btnMvtIos.disabled = !item.is_dir;      // mvt check-backup needs a backup directory
    if (btnMvtAndroid) btnMvtAndroid.disabled = !item.is_dir;

    const IMAGE_EXTENSIONS = ['.dd', '.raw', '.img', '.e01', '.aff'];
    if (!item.is_dir && IMAGE_EXTENSIONS.some(ext => item.name.toLowerCase().endsWith(ext))) {
        if (btnBrowseImage) btnBrowseImage.disabled = false;
    } else {
        if (btnBrowseImage) btnBrowseImage.disabled = true;
    }
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
            loadExplorer(explorerPath);
        } else {
            alert(`Delete failed: ${data.error}`);
        }
    } catch (err) {}
}

// --- File Metadata Viewer (ExifTool) ---
let metadataModalInstance = null;

async function viewSelectedMetadata() {
    if (!activeSelectedFile) return;

    if (!metadataModalInstance) {
        metadataModalInstance = new bootstrap.Modal(document.getElementById('metadataModal'));
    }
    const container = document.getElementById("metadataContainer");
    const nameEl = document.getElementById("metadataFileName");
    if (container) container.innerHTML = '<span class="text-subtle">Loading...</span>';
    if (nameEl) nameEl.textContent = activeSelectedFile.split('/').pop();
    metadataModalInstance.show();

    try {
        const res = await fetch('/api/files/exif', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: activeSelectedFile })
        });
        const data = await res.json();

        if (!container) return;
        if (!data.success) {
            container.innerHTML = '';
            const err = document.createElement('div');
            err.className = 'text-danger';
            err.textContent = data.error;
            container.appendChild(err);
            return;
        }

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
            for (const [key, value] of entries) {
                const row = document.createElement('tr');
                const keyCell = document.createElement('td');
                keyCell.className = 'text-info fw-bold text-nowrap';
                keyCell.style.width = '35%';
                keyCell.textContent = key; // text node - metadata values come from the file itself, never innerHTML
                const valCell = document.createElement('td');
                valCell.className = 'text-break';
                valCell.textContent = String(value);
                row.appendChild(keyCell);
                row.appendChild(valCell);
                tbody.appendChild(row);
            }
        }
        table.appendChild(tbody);
        container.appendChild(table);
    } catch (err) {
        if (container) container.innerHTML = '<span class="text-danger">Request failed.</span>';
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

// --- Image Browser (Sleuth Kit: mmls/fls/icat) ---
let imageBrowserModalInstance = null;
let imageBrowserImagePath = null;
let imageBrowserOffset = 0;
let imageBrowserPathStack = [];  // [{inode, name}, ...] for breadcrumb + "up" navigation
let imageBrowserSelected = null; // {inode, name}

async function openImageBrowser() {
    if (!activeSelectedFile) return;
    imageBrowserImagePath = activeSelectedFile;
    imageBrowserPathStack = [];
    imageBrowserSelected = null;

    if (!imageBrowserModalInstance) {
        imageBrowserModalInstance = new bootstrap.Modal(document.getElementById('imageBrowserModal'));
    }
    document.getElementById("imageBrowserFileName").textContent = activeSelectedFile.split('/').pop();
    document.getElementById("imageBrowserSelectedFile").textContent = '';
    if (document.getElementById("imageBrowserExtractBtn")) document.getElementById("imageBrowserExtractBtn").disabled = true;
    imageBrowserModalInstance.show();

    // Warn up front if this image's format might not be supported (E01
    // support depends on how this system's sleuthkit was built - not
    // guaranteed just because the package is installed).
    const warningEl = document.getElementById("imageBrowserFormatWarning");
    if (warningEl) warningEl.style.display = 'none';
    if (activeSelectedFile.toLowerCase().endsWith('.e01')) {
        try {
            const res = await fetch('/api/image/format_support');
            const data = await res.json();
            if (data.success && !data.support.ewf && warningEl) {
                warningEl.textContent = 'This system\'s Sleuth Kit build may not support E01 images - if browsing fails below, that\'s likely why.';
                warningEl.style.display = '';
            }
        } catch (err) {}
    }

    await loadImageBrowserPartitions();
}

async function loadImageBrowserPartitions() {
    const select = document.getElementById("imageBrowserPartitionSelect");
    if (select) select.innerHTML = '<option value="0">Loading...</option>';

    try {
        const res = await fetch('/api/image/mmls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: imageBrowserImagePath })
        });
        const data = await res.json();

        if (!select) return;
        select.innerHTML = '';

        if (!data.success || !data.partitions || data.partitions.length === 0) {
            // No partition table detected (or mmls failed) - fall back to
            // treating the whole image as a single filesystem at offset 0,
            // which is common for a single-partition raw dd of e.g. a
            // phone or a small media card.
            const opt = document.createElement('option');
            opt.value = '0';
            opt.textContent = 'Whole image (offset 0, no partition table detected)';
            select.appendChild(opt);
        } else {
            data.partitions.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.start_sector;
                opt.textContent = `Slot ${p.slot}: ${p.description} (offset ${p.start_sector})`;
                select.appendChild(opt);
            });
        }

        imageBrowserPathStack = [];
        await loadImageBrowserDir('');
    } catch (err) {
        if (select) select.innerHTML = '<option value="0">Error loading partitions</option>';
    }
}

async function loadImageBrowserDir(inode) {
    const select = document.getElementById("imageBrowserPartitionSelect");
    imageBrowserOffset = select ? parseInt(select.value, 10) || 0 : 0;

    const listEl = document.getElementById("imageBrowserList");
    if (listEl) listEl.innerHTML = '<span class="text-subtle small p-2">Loading...</span>';
    imageBrowserSelected = null;
    document.getElementById("imageBrowserSelectedFile").textContent = '';
    if (document.getElementById("imageBrowserExtractBtn")) document.getElementById("imageBrowserExtractBtn").disabled = true;

    try {
        const res = await fetch('/api/image/fls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image_path: imageBrowserImagePath, offset: imageBrowserOffset, inode: inode })
        });
        const data = await res.json();

        if (!listEl) return;
        listEl.innerHTML = '';

        if (!data.success) {
            const err = document.createElement('span');
            err.className = 'text-danger small p-2';
            err.textContent = data.error;
            listEl.appendChild(err);
            return;
        }

        if (data.entries.length === 0) {
            listEl.innerHTML = '<span class="text-subtle small p-2">(empty)</span>';
        }

        data.entries.forEach(entry => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'list-group-item list-group-item-action bg-dark text-light border-secondary d-flex justify-content-between align-items-center';

            const icon = entry.is_dir ? 'bi-folder-fill text-info' : 'bi-file-earmark text-light';
            const iconSpan = document.createElement('span');
            iconSpan.innerHTML = `<i class="bi ${icon} me-2"></i>`; // static/trusted markup
            iconSpan.appendChild(document.createTextNode(entry.name)); // untrusted evidence filename, text-only
            if (entry.deleted) {
                const delBadge = document.createElement('span');
                delBadge.className = 'badge bg-danger ms-2';
                delBadge.textContent = 'DELETED';
                iconSpan.appendChild(delBadge);
            }
            item.appendChild(iconSpan);

            item.onclick = () => {
                if (entry.is_dir) {
                    imageBrowserPathStack.push({ inode: entry.inode, name: entry.name });
                    updateImageBrowserPathTrail();
                    loadImageBrowserDir(entry.inode);
                } else {
                    imageBrowserSelected = entry;
                    document.getElementById("imageBrowserSelectedFile").textContent = `Selected: ${entry.name}`;
                    if (document.getElementById("imageBrowserExtractBtn")) document.getElementById("imageBrowserExtractBtn").disabled = false;
                }
            };
            listEl.appendChild(item);
        });
    } catch (err) {
        if (listEl) listEl.innerHTML = '<span class="text-danger small p-2">Request failed.</span>';
    }
}

function updateImageBrowserPathTrail() {
    const trail = document.getElementById("imageBrowserPathTrail");
    if (!trail) return;
    trail.textContent = '/' + imageBrowserPathStack.map(p => p.name).join('/');
}

function imageBrowserGoUp() {
    if (imageBrowserPathStack.length === 0) return;
    imageBrowserPathStack.pop();
    updateImageBrowserPathTrail();
    const parentInode = imageBrowserPathStack.length > 0 ? imageBrowserPathStack[imageBrowserPathStack.length - 1].inode : '';
    loadImageBrowserDir(parentInode);
}

async function extractSelectedImageFile() {
    if (!imageBrowserSelected) return;

    try {
        const res = await fetch('/api/image/extract', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                image_path: imageBrowserImagePath,
                offset: imageBrowserOffset,
                inode: imageBrowserSelected.inode,
                output_name: imageBrowserSelected.name,
                destination_dir: '/mnt'
            })
        });
        const data = await res.json();
        alert(data.success ? data.message : `Extraction failed: ${data.error}`);
        if (data.success) {
            loadExplorer(explorerPath);
        }
    } catch (err) {}
}

// --- Dynamic Attachments List Functions ---
function renderAttachmentsList() {
    const container = document.getElementById("attachmentsContainer");
    if (!container) return;

    if (currentAttachedFilesList.length === 0) {
        container.innerHTML = '<span class="text-subtle small italic">No files attached yet. Click \'Add File Attachment\' to browse.</span>';
        return;
    }

    container.innerHTML = '';
    currentAttachedFilesList.forEach((filePath, idx) => {
        const itemDiv = document.createElement("div");
        itemDiv.className = "d-flex justify-content-between align-items-center bg-dark text-light p-1 px-2 rounded mb-1 border border-secondary font-monospace small";

        const fileName = filePath.split('/').pop();

        const nameSpan = document.createElement('span');
        nameSpan.className = 'text-truncate me-2';
        nameSpan.innerHTML = '<i class="bi bi-file-earmark-arrow-up text-info me-1"></i>'; // static/trusted markup
        nameSpan.appendChild(document.createTextNode(fileName)); // untrusted, appended as text only

        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-xs btn-outline-danger py-0 px-1';
        removeBtn.innerHTML = '<i class="bi bi-x-lg"></i>';
        removeBtn.addEventListener('click', () => removeAttachment(idx));

        itemDiv.appendChild(nameSpan);
        itemDiv.appendChild(removeBtn);
        container.appendChild(itemDiv);
    });
}

function removeAttachment(index) {
    currentAttachedFilesList.splice(index, 1);
    renderAttachmentsList();
}

function addFileAttachment(filePath) {
    if (filePath && !currentAttachedFilesList.includes(filePath)) {
        currentAttachedFilesList.push(filePath);
        renderAttachmentsList();
    }
}

// --- Report Modifier Functions ---
function openReportPickerModal() {
    modalPickerMode = 'report';
    openFolderModal(modalPickerMode);
}

function openFilePickerModal(mode) {
    modalPickerMode = mode;
    openFolderModal(modalPickerMode);
}

async function loadCaseForEditing() {
    const reportPathEl = document.getElementById("editReportPath");
    const reportPath = reportPathEl ? reportPathEl.value.trim() : "";
    if (!reportPath) return alert("Select or enter a report/case JSON file path first.");

    try {
        const res = await fetch('/api/report/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath })
        });
        const data = await res.json();

        if (data.success) {
            currentLoadedReportData = data.report;

            // A consolidated case file has a top-level "events" array; a
            // legacy single-job report has case_number/examiner/notes
            // nested under case_metadata instead. Same Case Information
            // fields, different source location depending on which one
            // was loaded.
            const isConsolidated = Array.isArray(currentLoadedReportData.events);
            const legacyMeta = currentLoadedReportData.case_metadata || {};

            const editCaseNum = document.getElementById("editCaseNum");
            const editExaminer = document.getElementById("editExaminer");
            const editNotes = document.getElementById("editNotes");
            const legacyNotice = document.getElementById("repLegacyNotice");

            if (editCaseNum) editCaseNum.value = (isConsolidated ? currentLoadedReportData.case_number : legacyMeta.case_number) || "";
            if (editExaminer) editExaminer.value = (isConsolidated ? currentLoadedReportData.examiner : legacyMeta.examiner) || "";
            if (editNotes) editNotes.value = (isConsolidated ? currentLoadedReportData.notes : legacyMeta.notes) || "";
            if (legacyNotice) legacyNotice.style.display = isConsolidated ? 'none' : 'block';

            loadCaseHistory();
            renderCaseJobs();

            const attach = currentLoadedReportData.attachments || {};
            currentAttachedFilesList = attach.files || [];
            if (!currentAttachedFilesList.length && attach.image_path) {
                currentAttachedFilesList = [attach.image_path];
            }
            renderAttachmentsList();

            const editUrls = document.getElementById("editUrls");
            if (editUrls) editUrls.value = (attach.reference_urls || []).join(", ");

            const previewEl = document.getElementById("jsonPreview");
            if (previewEl) {
                previewEl.innerText = JSON.stringify(currentLoadedReportData, null, 2);
            }
        } else {
            alert(`Load Error: ${data.error}`);
        }
    } catch (err) {
        alert(`Failed to load report: ${err.message}`);
    }
}

// --- Case Index ---
async function loadCaseIndex() {
    const tbody = document.getElementById("caseIndexBody");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="text-subtle">Loading...</td></tr>';

    try {
        const res = await fetch('/api/reports/index');
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
        if (data.reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-subtle">No reports found under the evidence root.</td></tr>';
            return;
        }

        data.reports.forEach(r => {
            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.title = r.path;

            [r.case_number, r.evidence_id, r.method, r.status, r.timestamp_start].forEach(val => {
                const cell = document.createElement('td');
                cell.textContent = val; // untrusted report data - text node only
                row.appendChild(cell);
            });

            row.onclick = () => {
                const reportPathEl = document.getElementById("editReportPath");
                if (reportPathEl) reportPathEl.value = r.path;
                loadCaseForEditing();
            };
            tbody.appendChild(row);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-danger">Request failed.</td></tr>';
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
        container.innerHTML = '<span class="text-subtle">This is a single-job legacy report with no separate job history - migrate it (Case Index or Case Manager) to see jobs listed individually.</span>';
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

async function loadChainOfCustodyLog() {
    const container = document.getElementById("cocLogContainer");
    if (!container) return;
    container.innerHTML = '<span class="text-subtle">Loading...</span>';

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
        renderCocEntries(container, data.entries);
    } catch (err) {
        container.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

function exportAuditLogCsv() {
    // A plain navigation (not fetch) so the browser's own download handling
    // takes over - the response's Content-Disposition: attachment header
    // means this never actually navigates away from the app.
    window.location.href = '/api/coc/export_csv';
}

// Case-scoped view of the same log, for Reporting's History tab - distinct
// from the station-wide Audit Log above. Uses whatever case number is
// currently loaded into the Case Information block.
async function loadCaseHistory() {
    const container = document.getElementById("caseHistoryContainer");
    if (!container) return;

    const caseNum = document.getElementById("editCaseNum")?.value.trim();
    if (!caseNum) {
        container.innerHTML = '<span class="text-subtle">Load a report above first - History needs a case number to filter by.</span>';
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
        renderCocEntries(container, data.entries);
    } catch (err) {
        container.innerHTML = '<span class="text-danger">Request failed.</span>';
    }
}

async function saveReportMetadata() {
    const reportPathEl = document.getElementById("editReportPath");
    const reportPath = reportPathEl ? reportPathEl.value.trim() : "";

    if (!reportPath) {
        alert("Please select or enter a valid report JSON file path first.");
        return;
    }

    if (!currentLoadedReportData) {
        currentLoadedReportData = { case_metadata: {}, attachments: {} };
    }

    const caseNumber = document.getElementById("editCaseNum")?.value || "";
    const examiner = document.getElementById("editExaminer")?.value || "";
    const notes = document.getElementById("editNotes")?.value || "";

    if (Array.isArray(currentLoadedReportData.events)) {
        // Consolidated case file - case_number/examiner/notes are top-level
        // fields; events[] is left completely untouched so a metadata save
        // can never clobber job history.
        currentLoadedReportData.case_number = caseNumber;
        currentLoadedReportData.examiner = examiner;
        currentLoadedReportData.notes = notes;
    } else {
        // Legacy single-job report - preserve evidence_id (no longer
        // editable here, but still part of this report's own data).
        currentLoadedReportData.case_metadata = {
            ...(currentLoadedReportData.case_metadata || {}),
            case_number: caseNumber,
            examiner: examiner,
            notes: notes
        };
    }

    const urlsRaw = document.getElementById("editUrls")?.value.trim() || "";
    const urlArray = urlsRaw ? urlsRaw.split(',').map(u => u.trim()).filter(u => u.length > 0) : [];

    currentLoadedReportData.attachments = {
        files: currentAttachedFilesList,
        reference_urls: urlArray
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

// --- Export Report Modal ---
// Deliberately a separate action from "Save Report Changes" - Export always
// reads whatever is currently on disk at editReportPath (same as the old
// exportEditedPdf did after its own auto-save), so unsaved edits in the
// form are not silently included. If the examiner wants their edits in the
// exported file, Save Report Changes first, same as before.
function openExportReportModal() {
    const reportPath = document.getElementById("editReportPath")?.value.trim();
    if (!reportPath || !currentLoadedReportData) {
        alert("Load a report/case first.");
        return;
    }

    renderExportItemsList();
    renderExportFilesList();

    const statusEl = document.getElementById("exportReportStatus");
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'small text-subtle'; }

    if (!exportReportModalInstance) {
        exportReportModalInstance = new bootstrap.Modal(document.getElementById('exportReportModal'));
    }
    exportReportModalInstance.show();
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

    const reportPath = document.getElementById("editReportPath")?.value.trim() || "";
    const caseFolder = reportPath.substring(0, reportPath.lastIndexOf('/'));

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

        row.appendChild(cb);
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
    const reportPathEl = document.getElementById("editReportPath");
    const reportPath = reportPathEl ? reportPathEl.value.trim() : "";
    if (!reportPath) return alert("Load a report/case first.");

    const format = document.getElementById("exportFormatSelect")?.value || 'pdf';
    const sections = {
        case_info: !!document.getElementById("expSecCaseInfo")?.checked,
        attachments: !!document.getElementById("expSecAttachments")?.checked,
        audit_trail: !!document.getElementById("expSecAuditTrail")?.checked,
    };
    const job_fields = {
        telemetry: !!document.getElementById("expFieldTelemetry")?.checked,
        params: !!document.getElementById("expFieldParams")?.checked,
        hashes: !!document.getElementById("expFieldHashes")?.checked,
    };

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
            body: JSON.stringify({ report_path: reportPath, format, sections, job_fields, event_ids, attachment_selection })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const ext = format === 'html' ? '.html' : '.pdf';
            a.download = reportPath.split('/').pop().replace('.json', ext);
            document.body.appendChild(a);
            a.click();
            a.remove();
            if (statusEl) { statusEl.textContent = 'Export complete.'; statusEl.className = 'small text-success'; }
            if (exportReportModalInstance) exportReportModalInstance.hide();
        } else {
            const data = await res.json();
            if (statusEl) { statusEl.textContent = `Export failed: ${data.error}`; statusEl.className = 'small text-danger'; }
        }
    } catch (err) {
        if (statusEl) { statusEl.textContent = `Export failed: ${err.message}`; statusEl.className = 'small text-danger'; }
    }
}

// --- Standalone Evidence Hash Verifier Suite ---
async function runStandaloneHashVerification() {
    const imagePathEl = document.getElementById("verifyImagePath");
    const imagePath = imagePathEl ? imagePathEl.value.trim() : "";
    
    const algoEl = document.getElementById("verifyAlgorithmSelect");
    const algorithm = algoEl ? algoEl.value : "sha256";
    
    const expectedEl = document.getElementById("verifyExpectedHash");
    const expectedHash = expectedEl ? expectedEl.value.trim().toLowerCase() : "";
    
    const badge = document.getElementById("hashMatchBadge");
    const output = document.getElementById("computedHashOutput");

    if (!imagePath) return alert("Select an evidence image file first.");

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

// --- Collapsible Settings Cards ---
// Generic chevron-flip for any Bootstrap .collapse toggle - finds whichever
// button targets the collapse element that just opened/closed and flips its
// icon, rather than wiring a dedicated handler per card. Works for any
// future collapsible card too, not just the current five in Settings.
document.addEventListener('show.bs.collapse', (ev) => {
    const btn = document.querySelector(`[data-bs-target="#${ev.target.id}"]`);
    const icon = btn ? btn.querySelector('i') : null;
    if (icon) { icon.classList.remove('bi-chevron-down'); icon.classList.add('bi-chevron-up'); }
});
document.addEventListener('hide.bs.collapse', (ev) => {
    const btn = document.querySelector(`[data-bs-target="#${ev.target.id}"]`);
    const icon = btn ? btn.querySelector('i') : null;
    if (icon) { icon.classList.remove('bi-chevron-up'); icon.classList.add('bi-chevron-down'); }
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
        ['mobileIosCaseNum', 'mobileIosExaminer', 'mobileIosDest'],
        ['mobileAndroidCaseNum', 'mobileAndroidExaminer', 'mobileAndroidDest'],
    ];
    fieldGroups.forEach(([caseNumId, examinerId, destId]) => {
        const caseNumEl = document.getElementById(caseNumId);
        const examinerEl = document.getElementById(examinerId);
        const destEl = document.getElementById(destId);
        if (caseNumEl) caseNumEl.value = activeCase.case_number;
        if (examinerEl) examinerEl.value = activeCase.examiner || '';
        if (destEl) destEl.value = activeCase.case_folder;
    });
}

function openCaseManagerModal() {
    if (!caseManagerModalInstance) {
        caseManagerModalInstance = new bootstrap.Modal(document.getElementById('caseManagerModal'));
    }
    const statusEl = document.getElementById("createCaseStatus");
    if (statusEl) statusEl.textContent = '';
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
        if (document.getElementById('caseIndexBody')) loadCaseIndex();
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

    if (modalPickerMode === 'report') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-file-earmark-code me-2"></i>Select JSON Case Report';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'attachment') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-paperclip me-2"></i>Select Case File / Photo Attachment';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'evidence') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-hdd-fill me-2"></i>Select Target Evidence Image (.dd / .E01)';
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
            
            if (modalPickerMode === 'report' && !item.is_dir && item.name.toLowerCase().endsWith('.json')) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'attachment' && !item.is_dir) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'evidence' && !item.is_dir && (item.name.toLowerCase().endsWith('.dd') || item.name.toLowerCase().endsWith('.e01') || item.name.toLowerCase().endsWith('.raw'))) {
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
                    if (modalPickerMode === 'report') icon = '<i class="bi bi-filetype-json text-warning me-2 fs-5"></i>';
                    else if (modalPickerMode === 'attachment') icon = '<i class="bi bi-paperclip text-info me-2 fs-5"></i>';
                    else if (modalPickerMode === 'evidence') icon = '<i class="bi bi-disc text-primary me-2 fs-5"></i>';
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
                    } else if (modalPickerMode === 'report') {
                        const editReportPath = document.getElementById("editReportPath");
                        if (editReportPath) editReportPath.value = item.path;
                        if (folderModalInstance) folderModalInstance.hide();
                        loadCaseForEditing();
                    } else if (modalPickerMode === 'attachment') {
                        addFileAttachment(item.path);
                        if (folderModalInstance) folderModalInstance.hide();
                    } else if (modalPickerMode === 'evidence') {
                        const verifyImagePath = document.getElementById("verifyImagePath");
                        if (verifyImagePath) verifyImagePath.value = item.path;
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

async function fetchSystemInfo() {
    const activeDrive = getActiveTargetDrive();
    try {
        const res = await fetch(`/api/system_info?drive=${encodeURIComponent(activeDrive)}`);
        const data = await res.json();

        if (document.getElementById("cpuVal")) document.getElementById("cpuVal").innerText = `${data.cpu_percent}%`;
        if (document.getElementById("cpuBar")) document.getElementById("cpuBar").style.width = `${data.cpu_percent}%`;

        if (data.local_storage) {
            if (document.getElementById("storageVal")) document.getElementById("storageVal").innerText = `${data.local_storage.used_gb} / ${data.local_storage.total_gb} GB`;
            if (document.getElementById("storageBar")) document.getElementById("storageBar").style.width = `${data.local_storage.percent_used}%`;
        }

        if (data.memory) {
            if (document.getElementById("memVal")) document.getElementById("memVal").innerText = `${data.memory.used_gb} / ${data.memory.total_gb} GB (${data.memory.percent_used}%)`;
            if (document.getElementById("memBar")) document.getElementById("memBar").style.width = `${data.memory.percent_used}%`;
        }

        if (data.network_speed) {
            if (document.getElementById("netDlVal")) document.getElementById("netDlVal").innerText = `${data.network_speed.download_mbps} MB/s`;
            if (document.getElementById("netUlVal")) document.getElementById("netUlVal").innerText = `${data.network_speed.upload_mbps} MB/s`;
        }

        isWriteBlockActive = data.write_blocker_active;
        const wbBadgeBtn = document.getElementById("wbBadgeBtn");
        if (wbBadgeBtn) {
            if (isWriteBlockActive) {
                wbBadgeBtn.className = "btn btn-sm btn-danger fw-bold fs-6 px-3 py-1 shadow-sm";
                wbBadgeBtn.innerHTML = `<i class="bi bi-lock-fill me-1"></i>Software Write Blocker: PROTECTED (${activeDrive})`;
            } else {
                wbBadgeBtn.className = "btn btn-sm btn-warning text-dark fw-bold fs-6 px-3 py-1 shadow-sm";
                wbBadgeBtn.innerHTML = `<i class="bi bi-unlock-fill me-1"></i>Software Write Blocker: UNLOCKED (${activeDrive})`;
            }
        }
    } catch (err) {}
}

async function toggleWriteBlockGlobal() {
    const activeDrive = getActiveTargetDrive();
    const newEnableState = !isWriteBlockActive;

    try {
        const res = await fetch('/api/toggle_write_block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: newEnableState, drive: activeDrive })
        });
        const data = await res.json();
        if (data.success) {
            await fetchSystemInfo();
            alert(`Drive ${activeDrive} Write-Blocker status set to: ${newEnableState ? 'PROTECTED (Read-Only)' : 'UNLOCKED (Read-Write)'}`);
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

async function queryNetworkShares(hostId, protocolId, shareSelectId, mountStatusId) {
    const hostEl = document.getElementById(hostId);
    const host = hostEl ? hostEl.value.trim() : "";
    const protocol = document.getElementById(protocolId)?.value || "smb";
    const shareSelect = document.getElementById(shareSelectId);
    const mountStatus = document.getElementById(mountStatusId);

    if (!host) return alert("Please enter a server IP address.");

    if (mountStatus) mountStatus.innerText = "Querying available exports...";
    if (shareSelect) shareSelect.innerHTML = '<option value="">Querying...</option>';

    try {
        const res = await fetch('/api/list_server_shares', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, user: savedNetUser, pass: savedNetPass })
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

async function mountNetworkDrive(hostId, protocolId, shareSelectId, destPathId, mountStatusId) {
    const host = document.getElementById(hostId)?.value.trim() || "";
    const protocol = document.getElementById(protocolId)?.value || "smb";
    const shareSelect = document.getElementById(shareSelectId);
    const share = shareSelect ? shareSelect.value : "";
    const mountStatus = document.getElementById(mountStatusId);

    if (!share) return alert("Please select or enter an exported share name first.");

    if (mountStatus) mountStatus.innerText = "Mounting share...";

    try {
        const res = await fetch('/api/mount_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, share, user: savedNetUser, pass: savedNetPass })
        });
        const data = await res.json();

        if (data.success) {
            if (mountStatus) mountStatus.innerText = `Successfully mounted: ${data.mount_point}`;
            
            // Auto-update the destination input field
            const destPathMain = document.getElementById("destPath");
            if (destPathMain) destPathMain.value = data.mount_point;

            loadExplorer(data.mount_point);
            loadNetworkHistory();
            alert(`Share Mounted to ${data.mount_point}! Destination paths updated.`);
        } else {
            if (mountStatus) mountStatus.innerText = `Mount Error: ${data.error}`;
            alert(`Mount Failed: ${data.error}`);
        }
    } catch (err) {
        if (mountStatus) mountStatus.innerText = `Mount Failed: ${err.message}`;
    }
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

function updateRecoveryToolControls() {
    const tool = document.getElementById("recoveryToolSelect")?.value;
    const sourceRow = document.getElementById("recoverySourceRow");
    const destCol = document.getElementById("recoveryDestCol");
    const mapfileRow = document.getElementById("recoveryMapfileRow");
    const metadataRow = document.getElementById("recoveryMetadataRow");
    const stopBtn = document.getElementById("btnRecoveryStop");
    const startLabel = document.getElementById("btnRecoveryStartLabel");
    const helpText = document.getElementById("recoveryToolHelpText");

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

async function inspectDdrescueMapfile() {
    const mapPathEl = document.getElementById("recoveryMapfilePath");
    const mapPath = mapPathEl ? mapPathEl.value.trim() : "";
    const outEl = document.getElementById("recoveryLogOutput");

    if (!mapPath) {
        alert("Please enter or select a .map file path first.");
        return;
    }
    if (outEl) outEl.textContent = "Reading mapfile...";

    try {
        const res = await fetch('/api/ddrescue/inspect_map', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ map_path: mapPath })
        });
        const data = await res.json();

        if (data.success && outEl) {
            outEl.textContent =
                `Mapfile: ${mapPath}\n\n` +
                `Rescued Data:        ${data.rescued_gb} GB\n` +
                `Unattempted Data:    ${data.non_tried_mb} MB\n` +
                `Bad Sectors Size:    ${data.bad_sector_kb} KB\n` +
                `Hard Error Blocks:   ${data.bad_blocks_count}`;
        } else if (outEl) {
            outEl.textContent = `[ERROR] ${data.error}`;
        }
    } catch (err) {
        if (outEl) outEl.textContent = '[REQUEST FAILED]';
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

function onMobileIosSelect() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    const dev = mobileIosDevices.find(d => d.udid === udid);
    const startBtn = document.getElementById("btnMobileIosStart");

    if (document.getElementById("mobileIosModel")) document.getElementById("mobileIosModel").innerText = dev?.model || '--';
    if (document.getElementById("mobileIosVersion")) document.getElementById("mobileIosVersion").innerText = dev?.ios_version || '--';
    if (document.getElementById("mobileIosSerial")) document.getElementById("mobileIosSerial").innerText = dev?.serial || '--';

    const statusEl = document.getElementById("mobileIosStatus");
    if (statusEl) {
        statusEl.innerText = (dev && !dev.trusted) ? 'Device connected but not trusted yet - tap "Trust This Computer?" on the device, then Refresh.' : '';
    }

    if (startBtn) startBtn.disabled = !dev || !dev.trusted;
}

function onMobileAndroidSelect() {
    const serial = document.getElementById("mobileAndroidSelect")?.value;
    const dev = mobileAndroidDevices.find(d => d.serial === serial);
    const startBtn = document.getElementById("btnMobileAndroidStart");

    if (document.getElementById("mobileAndroidModel")) document.getElementById("mobileAndroidModel").innerText = dev?.model || '--';
    if (document.getElementById("mobileAndroidState")) document.getElementById("mobileAndroidState").innerText = dev?.state || '--';
    if (document.getElementById("mobileAndroidSerial")) document.getElementById("mobileAndroidSerial").innerText = dev?.serial || '--';

    const statusEl = document.getElementById("mobileAndroidStatus");
    if (statusEl) {
        statusEl.innerText = (dev && !dev.authorized) ? 'Device connected but not authorized yet - approve the USB debugging prompt on the device, then Refresh.' : '';
    }

    if (startBtn) startBtn.disabled = !dev || !dev.authorized;
}

function toggleIosEncryptField() {
    const checked = document.getElementById("mobileIosEncryptToggle")?.checked;
    const row = document.getElementById("mobileIosEncryptRow");
    if (row) row.style.display = checked ? '' : 'none';
}

async function startIosBackup() {
    const udid = document.getElementById("mobileIosSelect")?.value;
    if (!udid) return alert("Select a trusted iOS device first.");

    const dest = document.getElementById("mobileIosDest")?.value || '/mnt';
    const encryptEnabled = document.getElementById("mobileIosEncryptToggle")?.checked;
    const encrypt_password = encryptEnabled ? (document.getElementById("mobileIosEncryptPassword")?.value || '') : '';

    if (encryptEnabled && !encrypt_password) return alert("Enter an encryption password, or turn off the encrypted backup toggle.");

    const metadata = {
        case_number: document.getElementById("mobileIosCaseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("mobileIosEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("mobileIosExaminer")?.value || "UNSPECIFIED",
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
    const dest = document.getElementById("mobileAndroidDest")?.value || '/mnt';

    const metadata = {
        case_number: document.getElementById("mobileAndroidCaseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("mobileAndroidEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("mobileAndroidExaminer")?.value || "UNSPECIFIED",
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

async function changeAdminPassword() {
    const current = document.getElementById("cfgCurrentPass")?.value || '';
    const next = document.getElementById("cfgNewPass")?.value || '';
    const confirm = document.getElementById("cfgConfirmPass")?.value || '';
    const statusEl = document.getElementById("cfgPassStatus");

    if (!current || !next) {
        if (statusEl) { statusEl.className = 'small mt-2 text-danger'; statusEl.innerText = 'Enter your current and new password.'; }
        return;
    }
    if (next !== confirm) {
        if (statusEl) { statusEl.className = 'small mt-2 text-danger'; statusEl.innerText = 'New password and confirmation do not match.'; }
        return;
    }

    try {
        const res = await fetch('/api/system/change_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: current, new_password: next })
        });
        const data = await res.json();
        if (statusEl) {
            statusEl.className = data.success ? 'small mt-2 text-success' : 'small mt-2 text-danger';
            statusEl.innerText = data.success ? data.message : data.error;
        }
        if (data.success) {
            document.getElementById("cfgCurrentPass").value = '';
            document.getElementById("cfgNewPass").value = '';
            document.getElementById("cfgConfirmPass").value = '';
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
    tbody.innerHTML = '<tr><td colspan="3" class="text-subtle">Checking...</td></tr>';

    try {
        const res = await fetch('/api/system/tool_versions');
        const data = await res.json();

        if (!data.success) {
            tbody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 3;
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
            nameCell.style.width = '30%';
            nameCell.textContent = t.tool;

            const verCell = document.createElement('td');
            verCell.className = t.installed ? 'text-light' : 'text-danger';
            verCell.textContent = t.version;

            const actionCell = document.createElement('td');
            actionCell.style.width = '15%';
            if (!t.installed && t.package) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-xs btn-outline-success py-0 px-2';
                btn.innerHTML = '<i class="bi bi-download me-1"></i>Install';
                btn.onclick = () => installTool(t.package, btn);
                actionCell.appendChild(btn);
            }

            row.appendChild(nameCell);
            row.appendChild(verCell);
            row.appendChild(actionCell);
            tbody.appendChild(row);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-danger">Request failed.</td></tr>';
    }
}

async function installTool(pkg, btnEl) {
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Installing...';
    }

    try {
        const res = await fetch('/api/system/install_tool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ package: pkg })
        });
        const data = await res.json();
        if (!data.success) alert(`Install failed: ${data.error}`);
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

async function fetchNetworkInterfaces() {
    const container = document.getElementById("headerInterfacesContainer");
    if (!container) return;

    try {
        const res = await fetch('/api/system/interfaces');
        const data = await res.json();

        if (data.success && data.interfaces) {
            // Dispose any existing tooltips before rebuilding - otherwise
            // Bootstrap's tooltip instances leak/stay attached to elements
            // that no longer exist once we replace the container's contents.
            container.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
                const existing = bootstrap.Tooltip.getInstance(el);
                if (existing) existing.dispose();
            });

            container.innerHTML = '';
            data.interfaces.forEach(iface => {
                const pill = document.createElement('span');
                pill.className = 'badge bg-dark border border-secondary text-light font-monospace fw-normal';
                pill.style.cursor = 'default';
                pill.setAttribute('data-bs-toggle', 'tooltip');
                pill.setAttribute('data-bs-placement', 'bottom');
                pill.setAttribute('data-bs-html', 'true');
                pill.setAttribute('title', `Status: ${iface.active ? 'UP' : 'DOWN'}<br>IP: ${iface.ip}<br>MAC: ${iface.mac}<br>Speed: ${iface.speed_mbps} Mbps`);

                const dot = document.createElement('span');
                dot.className = 'me-1';
                dot.innerHTML = iface.active ? '<i class="bi bi-circle-fill text-success" style="font-size:8px"></i>' : '<i class="bi bi-circle-fill text-secondary" style="font-size:8px"></i>';
                pill.appendChild(dot);
                pill.appendChild(document.createTextNode(iface.interface));

                container.appendChild(pill);
                new bootstrap.Tooltip(pill, { trigger: 'hover focus' });
            });
        }
    } catch (err) {
        if (container) container.innerHTML = '<span class="text-danger small">Error</span>';
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
        // Mirror to the File Recovery tab's unified card - same single
        // shared job, just shown in two places depending on which tab
        // you're on.
        if (document.getElementById("recoverySpeedVal")) document.getElementById("recoverySpeedVal").innerText = `${currentSpeed.toFixed(1)} MB/s`;
        if (document.getElementById("recoveryBytesVal") && data.total_bytes > 0) {
            document.getElementById("recoveryBytesVal").innerText = `${(data.transferred_bytes / (1024**3)).toFixed(2)} / ${(data.total_bytes / (1024**3)).toFixed(2)} GB`;
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
            if (document.getElementById("btnMobileIosStart")) document.getElementById("btnMobileIosStart").disabled = true;
            if (document.getElementById("btnMobileAndroidStart")) document.getElementById("btnMobileAndroidStart").disabled = true;
        } else {
            onMobileIosSelect();     // re-derives disabled state from current device trust/selection
            onMobileAndroidSelect();
        }

    } catch (err) {}
}

document.addEventListener("DOMContentLoaded", () => {
    // Must run before initGridstack() - GridStack measures its container's
    // width at init time, so the sidebar's final width needs to be settled
    // first, not applied afterward.
    if (localStorage.getItem("pi_forensics_sidebar_compact") === "1") {
        const sidebar = document.getElementById("appSidebar");
        const icon = document.getElementById("sidebarToggleIcon");
        if (sidebar) sidebar.classList.add("compact");
        if (icon) icon.className = "bi bi-chevron-double-right";
    }

    initGridstack();
    initThroughputGraph();
    refreshDrives();
    loadNetworkHistory();
    loadExplorer('/mnt');
    toggleFormatControls();
    refreshMobileDevices();
    updateDdrescueStrategyHelp();
    updateRecoveryToolControls();
    updateAndroidModeHelp();
    initHelpTooltips();
    initActiveCaseBar();

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
