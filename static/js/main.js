let grid = null;
let isLayoutLocked = true;
let throughputChart = null;
const maxGraphPoints = 30;
const graphData = Array(maxGraphPoints).fill(0);
const graphLabels = Array(maxGraphPoints).fill('');

let savedNetUser = '';
let savedNetPass = '';
let currentDrivesList = [];

let currentBrowsePath = '/mnt';
let folderModalInstance = null;
let modalPickerMode = 'folder'; // Modes: 'folder', 'report', 'attachment', 'evidence'

let paneAPath = '/mnt';
let paneBPath = '/mnt';
let activePane = 'A';
let activeSelectedFile = null;
let selectedPaneAFile = null;
let selectedPaneBFile = null;

let currentLoadedReportData = null;
let currentAttachedFilesList = [];

function initGridstack() {
    grid = GridStack.init({
        cellHeight: 85,
        margin: 6,
        handle: '.card-header',
        animate: true,
        disableOneColumnMode: true,
        float: true,
        resizable: { handles: 'se, s, e' }
    });

    const savedLayout = localStorage.getItem('pi_forensics_layout');
    if (savedLayout) {
        try { grid.load(JSON.parse(savedLayout)); } catch (e) {}
    }

    grid.on('change', () => { saveDashboardLayout(); });
    applyLockState();
}

function toggleLayoutLock() {
    isLayoutLocked = !isLayoutLocked;
    applyLockState();
}

function applyLockState() {
    const lockBtn = document.getElementById("layoutLockBtn");
    if (!grid) return;

    if (isLayoutLocked) {
        grid.enableMove(false);
        grid.enableResize(false);
        if (lockBtn) {
            lockBtn.className = "btn btn-sm btn-outline-warning fw-bold";
            lockBtn.innerHTML = '<i class="bi bi-lock-fill me-1"></i>Layout Locked';
        }
        document.querySelectorAll('.card-header').forEach(el => el.style.cursor = 'default');
    } else {
        grid.enableMove(true);
        grid.enableResize(true);
        if (lockBtn) {
            lockBtn.className = "btn btn-sm btn-success fw-bold";
            lockBtn.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>Layout Unlocked';
        }
        document.querySelectorAll('.card-header').forEach(el => el.style.cursor = 'grab');
    }
}

function saveDashboardLayout() {
    if (!grid) return;
    localStorage.setItem('pi_forensics_layout', JSON.stringify(grid.save(false)));
}

function resetDashboardLayout() {
    localStorage.removeItem('pi_forensics_layout');
    location.reload();
}

function toggleFormatControls() {
    const fmtSelect = document.getElementById("imageFormatSelect");
    if (!fmtSelect) return;

    const fmt = fmtSelect.value;
    const compSelect = document.getElementById("compressionSelect");
    const splitSelect = document.getElementById("splitSizeSelect");

    if (fmt === 'e01') {
        if (compSelect) compSelect.disabled = false;
        if (splitSelect) splitSelect.disabled = false;
    } else {
        if (compSelect) compSelect.disabled = true;
        if (splitSelect) splitSelect.disabled = true;
    }
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
            container.innerHTML = `<div class="p-2 text-danger small">${data.error}</div>`;
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

            itemDiv.innerHTML = `<span class="${labelClass}">${icon}${item.name}</span><small class="text-subtle font-monospace">${item.size_str}</small>`;
            
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

    if (btnDelete) btnDelete.disabled = false;

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
        itemDiv.innerHTML = `<span class="text-truncate me-2"><i class="bi bi-file-earmark-arrow-up text-info me-1"></i>${fileName}</span>
                             <button class="btn btn-xs btn-outline-danger py-0 px-1" onclick="removeAttachment(${idx})"><i class="bi bi-x-lg"></i></button>`;
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
    modalPickerMode = mode; // 'attachment', 'report', or 'evidence'
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

            // Update JSON Raw Live Preview Box
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

// --- Folder & File Modals ---
function openFolderModal(mode = 'folder') {
    modalPickerMode = mode;
    
    const destPathEl = document.getElementById("destPath");
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
            }

            if (item.is_dir || isSelectableFile) {
                const btn = document.createElement("button");
                btn.className = "list-group-item list-group-item-action bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center";
                
                let icon = item.is_dir ? '<i class="bi bi-folder-fill folder-icon me-2"></i>' : '<i class="bi bi-file-earmark-text text-info me-2 fs-5"></i>';
                if (isSelectableFile) {
                    if (modalPickerMode === 'report') icon = '<i class="bi bi-filetype-json text-warning me-2 fs-5"></i>';
                    else if (modalPickerMode === 'attachment') icon = '<i class="bi bi-paperclip text-info me-2 fs-5"></i>';
                    else if (modalPickerMode === 'evidence') icon = '<i class="bi bi-disc text-primary me-2 fs-5"></i>';
                }

                btn.innerHTML = `<span>${icon}<span class="${item.is_dir ? 'folder-text' : 'text-light'}">${item.name}</span></span><small class="text-subtle font-monospace">${item.size_str}</small>`;
                
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
    const destPathEl = document.getElementById("destPath");
    if (destPathEl) destPathEl.value = currentBrowsePath;
    if (folderModalInstance) folderModalInstance.hide();
}

// --- Telemetry & Drives ---
async function fetchSystemInfo() {
    try {
        const res = await fetch('/api/system_info');
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

        const wbBadge = document.getElementById("wbBadge");
        const wbToggle = document.getElementById("wbToggle");
        if (wbBadge && wbToggle) {
            if (data.write_blocker_active) {
                wbBadge.className = "badge bg-danger fs-6 px-3 py-2";
                wbBadge.innerHTML = '<i class="bi bi-lock-fill me-1"></i>Hardware Write Blocker: ACTIVE';
                wbToggle.checked = true;
            } else {
                wbBadge.className = "badge bg-warning text-dark fs-6 px-3 py-2";
                wbBadge.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>Write Blocker: DISABLED (Read-Write)';
                wbToggle.checked = false;
            }
        }
    } catch (err) {}
}

async function refreshDrives() {
    try {
        const res = await fetch('/api/drives');
        currentDrivesList = await res.json();
        const driveSelect = document.getElementById("driveSelect");
        if (!driveSelect) return;

        driveSelect.innerHTML = '<option value="">-- Choose Target Source Drive --</option>';
        currentDrivesList.forEach(dev => {
            const opt = document.createElement("option");
            opt.value = dev.device;
            opt.innerText = `${dev.device} - [${(dev.transport||'usb').toUpperCase()}] ${dev.model} (${dev.size})`;
            driveSelect.appendChild(opt);
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
    } catch (err) {}
}

// --- Network Shares & History ---
async function loadNetworkHistory() {
    try {
        const res = await fetch('/api/mount_history');
        const history = await res.json();
        const shareSelect = document.getElementById("serverShareSelect");
        
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
    } catch (err) {}
}

document.getElementById("serverShareSelect")?.addEventListener("change", (e) => {
    const selectedOpt = e.target.options[e.target.selectedIndex];
    if (selectedOpt && selectedOpt.dataset.host) {
        const netHost = document.getElementById("netHost");
        const netProtocol = document.getElementById("netProtocol");
        const destPath = document.getElementById("destPath");

        if (netHost) netHost.value = selectedOpt.dataset.host;
        if (netProtocol) netProtocol.value = selectedOpt.dataset.protocol;
        if (selectedOpt.dataset.mountPoint && destPath) {
            destPath.value = selectedOpt.dataset.mountPoint;
            loadPane('B', selectedOpt.dataset.mountPoint);
        }
    }
});

async function queryNetworkShares() {
    const hostEl = document.getElementById("netHost");
    const host = hostEl ? hostEl.value.trim() : "";
    const protocol = document.getElementById("netProtocol")?.value || "smb";
    const shareSelect = document.getElementById("serverShareSelect");
    const mountStatus = document.getElementById("mountStatus");

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

async function mountNetworkDrive() {
    const host = document.getElementById("netHost")?.value.trim() || "";
    const protocol = document.getElementById("netProtocol")?.value || "smb";
    const shareSelect = document.getElementById("serverShareSelect");
    const share = shareSelect ? shareSelect.value : "";
    const mountStatus = document.getElementById("mountStatus");

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
            const destPath = document.getElementById("destPath");
            if (destPath) destPath.value = data.mount_point;
            loadPane('B', data.mount_point);
            loadNetworkHistory();
            alert(`Share Mounted to ${data.mount_point}!`);
        } else {
            if (mountStatus) mountStatus.innerText = `Mount Error: ${data.error}`;
            alert(`Mount Failed: ${data.error}`);
        }
    } catch (err) {
        if (mountStatus) mountStatus.innerText = `Mount Failed: ${err.message}`;
    }
}

async function toggleWriteBlock(e) {
    const enable = e.target.checked;
    const drive = document.getElementById("driveSelect")?.value || "/dev/sda";
    try {
        const res = await fetch('/api/toggle_write_block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable, drive })
        });
        const data = await res.json();
        if (data.success) fetchSystemInfo();
    } catch (err) {}
}

async function startAcquisition() {
    const source = document.getElementById("driveSelect")?.value;
    const dest = document.getElementById("destPath")?.value;
    const fmt = document.getElementById("imageFormatSelect")?.value;
    const compression = document.getElementById("compressionSelect")?.value;
    const split_size = document.getElementById("splitSizeSelect")?.value;

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
            body: JSON.stringify({ source, destination: dest, format: fmt, compression, split_size, hashes: selectedHashes, metadata })
        });
        const data = await res.json();

        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = true;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = false;
        } else alert(`Start Failed: ${data.error}`);
    } catch (err) {}
}

async function stopAcquisition() {
    if (!confirm("Terminate acquisition?")) return;
    try {
        const res = await fetch('/api/stop_imaging', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = false;
            if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = true;
        }
    } catch (err) {}
}

async function fetchProgress() {
    try {
        const res = await fetch('/api/progress');
        const data = await res.json();

        const currentSpeed = data.speed_mbps || 0;
        if (document.getElementById("speedVal")) document.getElementById("speedVal").innerText = `${currentSpeed.toFixed(1)} MB/s`;

        if (document.getElementById("bytesVal") && data.total_bytes > 0) {
            document.getElementById("bytesVal").innerText = `${(data.transferred_bytes / (1024**3)).toFixed(2)} / ${(data.total_bytes / (1024**3)).toFixed(2)} GB`;
        }

        if (document.getElementById("progressBar")) document.getElementById("progressBar").style.width = `${data.progress_percent}%`;
        if (document.getElementById("progressPct")) document.getElementById("progressPct").innerText = `${data.progress_percent.toFixed(1)}%`;
        if (document.getElementById("jobStatus")) document.getElementById("jobStatus").innerText = `Status: ${data.status}`;

        const logOutput = document.getElementById("logOutput");
        if (logOutput && data.log) {
            logOutput.innerText = data.log;
            logOutput.scrollTop = logOutput.scrollHeight;
        }

        if (throughputChart) {
            graphData.push(currentSpeed);
            graphData.shift();
            throughputChart.update('none');
        }

        if (document.getElementById("startBtn")) document.getElementById("startBtn").disabled = data.active;
        if (document.getElementById("stopBtn")) document.getElementById("stopBtn").disabled = !data.active;

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
    
    setInterval(fetchSystemInfo, 2000);
    setInterval(fetchProgress, 1000);
});
