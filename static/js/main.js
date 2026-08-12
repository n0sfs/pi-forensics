let gridMain = null;
let gridDdrescue = null;
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

let paneAPath = '/mnt';
let paneBPath = '/mnt';
let activePane = 'A';
let activeSelectedFile = null;
let selectedPaneAFile = null;
let selectedPaneBFile = null;

let currentLoadedReportData = null;
let currentAttachedFilesList = [];

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

    [gridMain, gridDdrescue, gridMobile, gridReports, gridSettings].forEach(g => {
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
    if (gridMobile) localStorage.setItem('pi_forensics_layout_mobile', JSON.stringify(gridMobile.save(false)));
    if (gridReports) localStorage.setItem('pi_forensics_layout_reports', JSON.stringify(gridReports.save(false)));
    if (gridSettings) localStorage.setItem('pi_forensics_layout_settings', JSON.stringify(gridSettings.save(false)));
}

function resetDashboardLayout() {
    localStorage.removeItem('pi_forensics_layout_main');
    localStorage.removeItem('pi_forensics_layout_ddr');
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
    const helpText = document.getElementById("formatHelpText");

    if (fmt === 'e01') {
        if (compSelect) compSelect.disabled = false;
        if (splitSelect) splitSelect.disabled = false;
    } else {
        if (compSelect) compSelect.disabled = true;
        if (splitSelect) splitSelect.disabled = true;
    }

    if (affRow) affRow.style.display = (fmt === 'aff') ? '' : 'none';

    const FORMAT_HELP = {
        dd: "Raw bit-for-bit copy using dc3dd, with hashing built in. A solid default for most acquisitions.",
        dcfldd: "Same idea as dc3dd (raw copy + hashing), from a different tool - useful if you specifically need dcfldd's output style.",
        plain_dd: "Plain GNU dd, no built-in hashing (computed separately after). Supports true direct disk access, bypassing the cache on read.",
        e01: "EnCase-compatible format (.E01) - widely used in law enforcement/EnCase workflows, supports compression and splitting into segments.",
        aff: "Advanced Forensic Format - acquires a raw image first, then converts it to .aff. You'll be asked whether to keep the intermediate raw file.",
    };
    if (helpText) helpText.textContent = FORMAT_HELP[fmt] || '';
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
            "Once done, go to Reports & Verification and check the hash to confirm the copy matches the original.",
        ]
    },
    damaged: {
        title: "Damaged, clicking, or not detected properly",
        steps: [
            "Go to the DDRescue & File Explorer tab.",
            "Select the drive and start with strategy \"1. Fast Copy\" - it copies everything readable quickly without stressing a failing drive.",
            "When it finishes, check the mapfile summary for bad sectors.",
            "If bad sectors remain, try strategy 2 (Edge Trimming), then 3 (Intensive Scraping) if needed - each is more thorough but harder on the drive, so go in order.",
            "Once you have a copy, you can also run PhotoRec (further down the same tab) on it to recover files even from damaged or partly-corrupted areas.",
        ],
        tabId: "ddrescue-tab"
    },
    deleted: {
        title: "Need to recover deleted files",
        steps: [
            "If you don't have an image yet, acquire one first (see the \"drive works fine\" guide above).",
            "Go to the DDRescue & File Explorer tab and find the PhotoRec card.",
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
            "Once finished, check Reports & Verification for the resulting report.",
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
        a: "Check the status text and log during the job - it'll say \"Completed Successfully\" or \"Failed\" clearly. Afterward, go to Reports & Verification and use \"Verify Image Hash\" to confirm the acquired image's hash matches what was recorded during acquisition."
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
    ["ddrescue", "Recovery-focused imaging for damaged/failing drives - works around bad sectors instead of stopping."],
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
        ["Chain of custody", "The Reports tab keeps a station-wide log of significant actions (acquisitions, deletes, copies, report edits) with timestamp and source IP. This station has one shared login rather than per-examiner accounts, so the log shows what happened and when, reliably - not who, beyond the connecting IP."],
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
    const sel = document.getElementById("tabDdrescueStrategy");
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
            scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: '#2e364f' }, ticks: { color: '#cbd5e1', font: { size: 10 } } } },
            plugins: { legend: { display: false } }
        }
    });
}

// --- Dual Pane File Explorer ---
async function loadPane(pane, path) {
    const container = document.getElementById(pane === 'A' ? 'paneAContainer' : 'paneBContainer');
    const pathLabel = document.getElementById(pane === 'A' ? 'paneAPath' : 'paneBPath');
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
            return;
        }

        if (pane === 'A') paneAPath = data.path; else paneBPath = data.path;
        if (pathLabel) pathLabel.innerText = data.path;

        container.innerHTML = '';
        
        if (data.path !== '/') {
            const upDiv = document.createElement('div');
            upDiv.className = 'file-item text-warning fw-bold';
            upDiv.innerHTML = '<i class="bi bi-arrow-up-left me-1"></i>.. [Up Directory]';
            upDiv.onclick = () => {
                const parent = data.path.split('/').slice(0, -1).join('/') || '/';
                loadPane(pane, parent);
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
                
                activePane = pane;
                activeSelectedFile = item.path;
                if (pane === 'A') selectedPaneAFile = item.path; else selectedPaneBFile = item.path;

                updateContextToolbar(item);
            };

            itemDiv.ondblclick = () => {
                if (item.is_dir) loadPane(pane, item.path);
            };

            container.appendChild(itemDiv);
        });

    } catch (err) {
        container.innerHTML = `<div class="p-2 text-danger small">Error loading pane files</div>`;
    }
}

function updateContextToolbar(item) {
    const btnPdf = document.getElementById("btnPdfExport");
    const btnVerify = document.getElementById("btnVerifyHash");
    const btnDelete = document.getElementById("btnDeleteFile");
    const btnMetadata = document.getElementById("btnFileMetadata");
    const btnBrowseImage = document.getElementById("btnBrowseImage");
    const btnBinwalk = document.getElementById("btnRunBinwalk");
    const btnClamscan = document.getElementById("btnRunClamscan");
    const btnStrings = document.getElementById("btnRunStrings");
    const btnHashdeep = document.getElementById("btnRunHashdeep");

    if (btnDelete) btnDelete.disabled = false;
    if (btnMetadata) btnMetadata.disabled = item.is_dir;
    if (btnBinwalk) btnBinwalk.disabled = item.is_dir;
    if (btnStrings) btnStrings.disabled = item.is_dir;
    if (btnClamscan) btnClamscan.disabled = false;        // works on either a file or a directory (-r)
    if (btnHashdeep) btnHashdeep.disabled = !item.is_dir;  // recursive manifest - needs a directory

    if (!item.is_dir && item.name.toLowerCase().endsWith('_report.json')) {
        if (btnPdf) btnPdf.disabled = false;
    } else {
        if (btnPdf) btnPdf.disabled = true;
    }

    if (!item.is_dir && (item.name.toLowerCase().endsWith('.dd') || item.name.toLowerCase().endsWith('.e01'))) {
        if (btnVerify) btnVerify.disabled = false;
    } else {
        if (btnVerify) btnVerify.disabled = true;
    }

    const IMAGE_EXTENSIONS = ['.dd', '.raw', '.img', '.e01', '.aff'];
    if (!item.is_dir && IMAGE_EXTENSIONS.some(ext => item.name.toLowerCase().endsWith(ext))) {
        if (btnBrowseImage) btnBrowseImage.disabled = false;
    } else {
        if (btnBrowseImage) btnBrowseImage.disabled = true;
    }
}

async function copyPaneFile(fromPane, toPane) {
    const src = fromPane === 'A' ? selectedPaneAFile : selectedPaneBFile;
    const destDir = toPane === 'A' ? paneAPath : paneBPath;

    if (!src) {
        alert(`Select a file in Pane ${fromPane} first.`);
        return;
    }

    try {
        const res = await fetch('/api/files/copy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: src, destination_dir: destDir })
        });
        const data = await res.json();
        if (data.success) {
            loadPane(toPane, destDir);
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
            loadPane(activePane, activePane === 'A' ? paneAPath : paneBPath);
        } else {
            alert(`Delete failed: ${data.error}`);
        }
    } catch (err) {}
}

async function verifySelectedHash() {
    if (!activeSelectedFile) return;

    try {
        const res = await fetch('/api/verify_hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: activeSelectedFile, algorithm: 'sha256' })
        });
        const data = await res.json();
        if (data.success) {
            alert(`Verification Hash (${data.algorithm}):\nFile: ${data.file_name}\nHash: ${data.hash}`);
        } else {
            alert(`Hash verification error: ${data.error}`);
        }
    } catch (err) {}
}

async function exportSelectedPdf() {
    if (!activeSelectedFile) return;
    triggerPdfDownload(activeSelectedFile);
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
            loadPane('A', paneAPath);
            loadPane('B', paneBPath);
        } else {
            alert(`hashdeep failed: ${data.error}`);
        }
    } catch (err) {}
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
            loadPane('A', paneAPath);
            loadPane('B', paneBPath);
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

async function loadReportForEditing() {
    const reportPathEl = document.getElementById("editReportPath");
    const reportPath = reportPathEl ? reportPathEl.value.trim() : "";
    if (!reportPath) return alert("Select or enter a report JSON file path first.");

    try {
        const res = await fetch('/api/report/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath })
        });
        const data = await res.json();

        if (data.success) {
            currentLoadedReportData = data.report;
            
            const meta = currentLoadedReportData.case_metadata || {};
            const editCaseNum = document.getElementById("editCaseNum");
            const editEvidenceId = document.getElementById("editEvidenceId");
            const editExaminer = document.getElementById("editExaminer");
            const editNotes = document.getElementById("editNotes");

            if (editCaseNum) editCaseNum.value = meta.case_number || "";
            if (editEvidenceId) editEvidenceId.value = meta.evidence_id || "";
            if (editExaminer) editExaminer.value = meta.examiner || "";
            if (editNotes) editNotes.value = meta.notes || "";

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
                loadReportForEditing();
            };
            tbody.appendChild(row);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-danger">Request failed.</td></tr>';
    }
}

// --- Chain of Custody Log ---
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

        container.innerHTML = '';
        if (data.entries.length === 0) {
            container.innerHTML = '<span class="text-subtle">No entries logged yet.</span>';
            return;
        }

        data.entries.forEach(entry => {
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

    currentLoadedReportData.case_metadata = {
        case_number: document.getElementById("editCaseNum")?.value || "",
        evidence_id: document.getElementById("editEvidenceId")?.value || "",
        examiner: document.getElementById("editExaminer")?.value || "",
        notes: document.getElementById("editNotes")?.value || ""
    };

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

async function exportEditedPdf() {
    await saveReportMetadata();
    const reportPathEl = document.getElementById("editReportPath");
    const reportPath = reportPathEl ? reportPathEl.value.trim() : "";
    if (reportPath) {
        triggerPdfDownload(reportPath);
    }
}

async function triggerPdfDownload(reportPath) {
    try {
        const res = await fetch('/api/export_pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_path: reportPath })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = reportPath.split('/').pop().replace('.json', '.pdf');
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            const data = await res.json();
            alert(`PDF Export Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("PDF Export error:", err);
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
    } else if (modalPickerMode === 'photorecSource') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-search-heart me-2"></i>Select Source Image for PhotoRec';
        if (selectBtn) selectBtn.style.display = 'none';
    } else if (modalPickerMode === 'triageScanSource') {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-envelope-paper me-2"></i>Select Source Image for Triage Scan';
        if (selectBtn) selectBtn.style.display = 'none';
    } else {
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-folder2-open me-2"></i>Select Destination Directory';
        if (selectBtn) selectBtn.style.display = 'inline-block';
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
            } else if (modalPickerMode === 'photorecSource' && !item.is_dir) {
                isSelectableFile = true;
            } else if (modalPickerMode === 'triageScanSource' && !item.is_dir) {
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
                    else if (modalPickerMode === 'photorecSource') icon = '<i class="bi bi-disc text-primary me-2 fs-5"></i>';
                    else if (modalPickerMode === 'triageScanSource') icon = '<i class="bi bi-envelope-paper text-primary me-2 fs-5"></i>';
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
                        loadReportForEditing();
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
                    } else if (modalPickerMode === 'photorecSource') {
                        const sourcePathEl = document.getElementById("photorecSourcePath");
                        if (sourcePathEl) sourcePathEl.value = item.path;
                        if (folderModalInstance) folderModalInstance.hide();
                    } else if (modalPickerMode === 'triageScanSource') {
                        const sourcePathEl = document.getElementById("triageScanSourcePath");
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
    const targetEl = document.getElementById(targetInputIdForModal);
    if (targetEl) targetEl.value = currentBrowsePath;
    if (folderModalInstance) folderModalInstance.hide();
}

// --- Telemetry & Drives ---
function getActiveTargetDrive() {
    const mainDrive = document.getElementById("driveSelect")?.value;
    const ddrDrive = document.getElementById("tabDdrescueSource")?.value;
    return mainDrive || ddrDrive || "/dev/sda";
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
        checkDdrescueSmartTelemetry();
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

async function checkDdrescueSmartTelemetry() {
    const driveSelect = document.getElementById("tabDdrescueSource");
    const targetDrive = driveSelect ? driveSelect.value : "";
    const healthBadge = document.getElementById("lblDdrescueHealthBadge");

    if (!targetDrive) return;

    try {
        const res = await fetch('/api/smart_check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive: targetDrive })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("lblDdrescueModel")) document.getElementById("lblDdrescueModel").innerText = data.vendor_model || "--";
            if (document.getElementById("lblDdrescueSerial")) document.getElementById("lblDdrescueSerial").innerText = data.serial || "--";
            if (document.getElementById("lblDdrescuePending")) document.getElementById("lblDdrescuePending").innerText = data.pending_sectors !== undefined ? data.pending_sectors : "0";
            
            if (healthBadge) {
                healthBadge.className = data.healthy ? "badge bg-success w-100 py-2" : "badge bg-danger w-100 py-2";
                healthBadge.innerHTML = data.healthy ? 'PASSED (GOOD)' : 'FAILING MEDIA';
            }
        }
        fetchSystemInfo();
    } catch (err) {}
}

// --- Parameterized Network Shares Engine ---
async function loadNetworkHistory() {
    try {
        const res = await fetch('/api/mount_history');
        const history = await res.json();
        const shareSelects = [document.getElementById("serverShareSelect"), document.getElementById("tabDdrescueServerShareSelect")];
        
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
            
            // Auto-update ALL destination input fields across standard and ddrescue tabs
            const destPathMain = document.getElementById("destPath");
            const destPathDdr = document.getElementById("tabDdrescueDest");
            
            if (destPathMain) destPathMain.value = data.mount_point;
            if (destPathDdr) destPathDdr.value = data.mount_point;

            loadPane('B', data.mount_point);
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
    const compression = document.getElementById("compressionSelect")?.value;
    const split_size = document.getElementById("splitSizeSelect")?.value;
    const keep_raw = document.getElementById("affKeepRaw")?.checked ?? true;

    if (!source) return alert("Select target evidence drive first.");

    const selectedHashes = [];
    if (document.getElementById("hashMd5")?.checked) selectedHashes.push("md5");
    if (document.getElementById("hashSha1")?.checked) selectedHashes.push("sha1");
    if (document.getElementById("hashSha256")?.checked) selectedHashes.push("sha256");

    const metadata = {
        case_number: document.getElementById("caseNum")?.value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("evidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("examiner")?.value || "UNSPECIFIED",
        notes: document.getElementById("notes")?.value || "None"
    };

    try {
        const res = await fetch('/api/start_imaging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, destination: dest, format: fmt, compression, split_size, hashes: selectedHashes, metadata, keep_raw })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = true;
            if (document.getElementById("btnTabDdrescueStart")) document.getElementById("btnTabDdrescueStart").disabled = true;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = false;
            if (document.getElementById("btnTabDdrescueStop")) document.getElementById("btnTabDdrescueStop").disabled = false;
        } else alert(`Start Failed: ${data.error}`);
    } catch (err) {}
}

async function startTabDdrescueJob() {
    const sourceSelect = document.getElementById("tabDdrescueSource");
    const source = sourceSelect ? sourceSelect.value : "";
    const dest = document.getElementById("tabDdrescueDest")?.value || "/mnt";
    const strategy = document.getElementById("tabDdrescueStrategy")?.value || "stage1_fast";
    const retries = document.getElementById("tabDdrescueRetries")?.value || "3";
    const directMode = document.getElementById("tabDdrescueDirect")?.checked ?? true;

    if (!source) {
        alert("Please select a target damaged source drive first.");
        return;
    }

    const metadata = {
        case_number: document.getElementById("tabDdrescueCaseNum")?.value || "RECOVERY",
        evidence_id: document.getElementById("tabDdrescueEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("tabDdrescueExaminer")?.value || "UNSPECIFIED",
        notes: `ddrescue ${strategy} execution pass`
    };

    try {
        const res = await fetch('/api/start_ddrescue', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source: source,
                destination: dest,
                strategy: strategy,
                retry_passes: retries,
                direct_mode: directMode,
                metadata: metadata
            })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = true;
            if (document.getElementById("btnTabDdrescueStart")) document.getElementById("btnTabDdrescueStart").disabled = true;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = false;
            if (document.getElementById("btnTabDdrescueStop")) document.getElementById("btnTabDdrescueStop").disabled = false;
            alert(`ddrescue (${strategy}) pass started cleanly!`);
        } else {
            alert(`ddrescue Start Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("Error starting ddrescue:", err);
    }
}

async function startPhotorecJob() {
    // Source can be either the drive dropdown (a whole device) or the
    // typed/browsed image path field - the image path takes priority if
    // both are filled in, since picking a specific image file is a more
    // deliberate choice than whatever happens to be selected in the dropdown.
    const sourcePath = document.getElementById("photorecSourcePath")?.value.trim();
    const sourceDrive = document.getElementById("photorecSourceDrive")?.value;
    const source = sourcePath || sourceDrive;
    const dest = document.getElementById("photorecDest")?.value || "/mnt";

    if (!source) {
        alert("Select a source drive, or browse to a source image file, first.");
        return;
    }

    const metadata = {
        case_number: document.getElementById("photorecCaseNum")?.value || "RECOVERY",
        evidence_id: document.getElementById("photorecEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("photorecExaminer")?.value || "UNSPECIFIED",
        notes: "PhotoRec file carving recovery"
    };

    try {
        const res = await fetch('/api/recovery/start_photorec', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, destination: dest, metadata })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("btnPhotorecStart")) document.getElementById("btnPhotorecStart").disabled = true;
            if (document.getElementById("btnPhotorecStop")) document.getElementById("btnPhotorecStop").disabled = false;
        } else {
            alert(`PhotoRec Start Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("Error starting PhotoRec:", err);
    }
}

async function startTriageScanJob() {
    const sourcePath = document.getElementById("triageScanSourcePath")?.value.trim();
    const sourceDrive = document.getElementById("triageScanSourceDrive")?.value;
    const source = sourcePath || sourceDrive;
    const dest = document.getElementById("triageScanDest")?.value || "/mnt";

    if (!source) {
        alert("Select a source drive, or browse to a source image file, first.");
        return;
    }

    const metadata = {
        case_number: document.getElementById("triageScanCaseNum")?.value || "TRIAGE",
        evidence_id: document.getElementById("triageScanEvidenceId")?.value || "ITEM-01",
        examiner: document.getElementById("triageScanExaminer")?.value || "UNSPECIFIED",
        notes: "Built-in structured data triage scan"
    };

    try {
        const res = await fetch('/api/recovery/start_triage_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, destination: dest, metadata })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("btnTriageScanStart")) document.getElementById("btnTriageScanStart").disabled = true;
            if (document.getElementById("btnTriageScanStop")) document.getElementById("btnTriageScanStop").disabled = false;
        } else {
            alert(`Triage Scan Start Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("Error starting triage scan:", err);
    }
}

async function inspectDdrescueMapfile() {
    const mapPathEl = document.getElementById("tabMapfilePath");
    const mapPath = mapPathEl ? mapPathEl.value.trim() : "";

    if (!mapPath) {
        alert("Please enter or select a .map file path first.");
        return;
    }

    try {
        const res = await fetch('/api/ddrescue/inspect_map', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ map_path: mapPath })
        });
        const data = await res.json();

        if (data.success) {
            document.getElementById("mapRescuedVal").innerText = `${data.rescued_gb} GB`;
            document.getElementById("mapUnattemptedVal").innerText = `${data.non_tried_mb} MB`;
            document.getElementById("mapBadSectorVal").innerText = `${data.bad_sector_kb} KB`;
            document.getElementById("mapErrorBlocksVal").innerText = data.bad_blocks_count;
            
            const badge = document.getElementById("mapStatusBadge");
            if (badge) {
                badge.className = "badge bg-success";
                badge.innerText = "PARSED";
            }
        } else {
            alert(`Map Inspection Error: ${data.error}`);
        }
    } catch (err) {
        console.error("Map inspection error:", err);
    }
}

async function stopAcquisition() {
    if (!confirm("Terminate current process?")) return;
    try {
        const res = await fetch('/api/stop_imaging', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = false;
            if (document.getElementById("btnTabDdrescueStart")) document.getElementById("btnTabDdrescueStart").disabled = false;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = true;
            if (document.getElementById("btnTabDdrescueStop")) document.getElementById("btnTabDdrescueStop").disabled = true;
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

async function runDiagnostic(key) {
    const out = document.getElementById("diagOutput");
    if (out) out.innerText = `$ ${key}\nRunning...`;

    try {
        const res = await fetch('/api/system/diagnostics', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: key })
        });
        const data = await res.json();
        if (out) out.innerText = data.success ? `$ ${data.command}\n\n${data.output}` : `[ERROR] ${data.error}`;
    } catch (err) {
        if (out) out.innerText = '[REQUEST FAILED]';
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
    try {
        const res = await fetch('/api/system/restart_service', { method: 'POST' });
        const data = await res.json();
        alert(data.message || data.error);
    } catch (err) {}
}

async function restartKioskDisplay() {
    try {
        const res = await fetch('/api/system/restart_kiosk', { method: 'POST' });
        const data = await res.json();
        alert(data.message || data.error);
    } catch (err) {}
}

async function gitUpdateApp() {
    if (!confirm("Pull the latest code from the configured git remote and restart the service? Only do this if you trust that remote.")) return;
    try {
        const res = await fetch('/api/system/git_update', { method: 'POST' });
        const data = await res.json();
        alert(data.message || data.error);
    } catch (err) {}
}

async function updateOperatingSystem() {
    if (!confirm("Run apt-get update && upgrade -y in the background? This can take a while and should not be interrupted.")) return;
    try {
        const res = await fetch('/api/system/os_update', { method: 'POST' });
        const data = await res.json();
        alert(data.message || data.error);
    } catch (err) {}
}

async function triggerSystemPower(action) {
    const label = action === 'poweroff' ? 'power off' : 'reboot';
    if (!confirm(`Are you sure you want to ${label} the station now? Any running acquisition will be interrupted.`)) return;
    try {
        const res = await fetch('/api/system/power', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const data = await res.json();
        alert(data.message || data.error);
    } catch (err) {}
}

async function fetchNetworkInterfaces() {
    const container = document.getElementById("interfacesContainer");
    if (!container) return;

    try {
        const res = await fetch('/api/system/interfaces');
        const data = await res.json();

        if (data.success && data.interfaces) {
            container.innerHTML = '';
            data.interfaces.forEach(iface => {
                const item = document.createElement("div");
                item.className = "list-group-item bg-dark text-light border-secondary p-2 d-flex justify-content-between align-items-center";

                const nameSpan = document.createElement('span');
                nameSpan.className = 'fw-bold text-info me-1';
                nameSpan.textContent = iface.interface;

                const statusBadge = document.createElement('span');
                statusBadge.className = iface.active ? 'badge bg-success' : 'badge bg-secondary';
                statusBadge.textContent = iface.active ? 'UP' : 'DOWN';

                const detailDiv = document.createElement('div');
                detailDiv.className = 'font-monospace small text-subtle';
                detailDiv.textContent = `IP: ${iface.ip} | MAC: ${iface.mac}`;

                const leftDiv = document.createElement('div');
                leftDiv.appendChild(nameSpan);
                leftDiv.appendChild(statusBadge);
                leftDiv.appendChild(detailDiv);

                const speedSmall = document.createElement('small');
                speedSmall.className = 'text-subtle font-monospace';
                speedSmall.textContent = `${iface.speed_mbps} Mbps`;

                item.appendChild(leftDiv);
                item.appendChild(speedSmall);
                container.appendChild(item);
            });
        }
    } catch (err) {
        if (container) container.innerHTML = '<span class="text-danger small p-2">Error querying interfaces.</span>';
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
        
        // Update Dedicated ddrescue Tab Status Simultaneously
        if (document.getElementById("ddrescueSpeedVal")) document.getElementById("ddrescueSpeedVal").innerText = `${currentSpeed.toFixed(1)} MB/s`;
        if (document.getElementById("ddrescueBytesVal") && data.total_bytes > 0) {
            document.getElementById("ddrescueBytesVal").innerText = `${(data.transferred_bytes / (1024**3)).toFixed(2)} / ${(data.total_bytes / (1024**3)).toFixed(2)} GB`;
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

            if (document.getElementById("ddrescueProgressBar")) document.getElementById("ddrescueProgressBar").style.width = `${data.progress_percent}%`;
            if (document.getElementById("ddrescueProgressPct")) document.getElementById("ddrescueProgressPct").innerText = `${data.progress_percent.toFixed(1)}%`;
            if (document.getElementById("ddrescueJobStatus")) document.getElementById("ddrescueJobStatus").innerText = `Status: ${data.status}`;

            const ddrescueLogOutput = document.getElementById("ddrescueLogOutput");
            if (ddrescueLogOutput && data.log) {
                ddrescueLogOutput.innerText = data.log;
                ddrescueLogOutput.scrollTop = ddrescueLogOutput.scrollHeight;
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
        if (document.getElementById("btnTabDdrescueStart")) document.getElementById("btnTabDdrescueStart").disabled = data.active;
        if (document.getElementById("btnPhotorecStart")) document.getElementById("btnPhotorecStart").disabled = data.active;
        if (document.getElementById("btnTriageScanStart")) document.getElementById("btnTriageScanStart").disabled = data.active;
        if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = !data.active;
        if (document.getElementById("btnTabDdrescueStop")) document.getElementById("btnTabDdrescueStop").disabled = !data.active;
        if (document.getElementById("btnPhotorecStop")) document.getElementById("btnPhotorecStop").disabled = !data.active;
        if (document.getElementById("btnTriageScanStop")) document.getElementById("btnTriageScanStop").disabled = !data.active;
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
    initGridstack();
    initThroughputGraph();
    refreshDrives();
    loadNetworkHistory();
    loadPane('A', '/mnt');
    loadPane('B', '/mnt');
    toggleFormatControls();
    refreshMobileDevices();
    updateDdrescueStrategyHelp();
    updateAndroidModeHelp();
    initHelpTooltips();

    setInterval(fetchSystemInfo, 2000);
    setInterval(fetchProgress, 1000);
});

function initHelpTooltips() {
    // Bootstrap tooltips need explicit init - "hover focus" so they also
    // work reasonably on touch (tapping a button focuses it first), since
    // this is primarily a touchscreen kiosk interface, not a mouse-driven one.
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        new bootstrap.Tooltip(el, { trigger: 'hover focus', placement: el.getAttribute('data-bs-placement') || 'top' });
    });
}
