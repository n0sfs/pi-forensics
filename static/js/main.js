let throughputChart = null;
const maxGraphPoints = 30;
const graphData = Array(maxGraphPoints).fill(0);
const graphLabels = Array(maxGraphPoints).fill('');

let savedNetUser = '';
let savedNetPass = '';
let currentDrivesList = [];

let currentBrowsePath = '/mnt';
let folderModalInstance = null;

// --- Initialize Chart.js Live Graph ---
function initThroughputGraph() {
    const canvas = document.getElementById('throughputChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    throughputChart = new Chart(ctx, {
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
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: '#2a2f45' },
                    ticks: { color: '#94a3b8', font: { size: 10 } }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// --- Telemetry Fetching ---
async function fetchSystemInfo() {
    try {
        const res = await fetch('/api/system_info');
        const data = await res.json();

        // 1. CPU
        const cpuVal = document.getElementById("cpuVal");
        const cpuBar = document.getElementById("cpuBar");
        if (cpuVal) cpuVal.innerText = `${data.cpu_percent}%`;
        if (cpuBar) cpuBar.style.width = `${data.cpu_percent}%`;

        // 2. Storage Capacity
        if (data.local_storage) {
            const storageVal = document.getElementById("storageVal");
            const storageBar = document.getElementById("storageBar");
            if (storageVal) storageVal.innerText = `${data.local_storage.used_gb} / ${data.local_storage.total_gb} GB`;
            if (storageBar) storageBar.style.width = `${data.local_storage.percent_used}%`;
        }

        // 3. RAM Memory
        if (data.memory) {
            const memVal = document.getElementById("memVal");
            const memBar = document.getElementById("memBar");
            if (memVal) memVal.innerText = `${data.memory.used_gb} / ${data.memory.total_gb} GB (${data.memory.percent_used}%)`;
            if (memBar) memBar.style.width = `${data.memory.percent_used}%`;
        }

        // 4. Live Network Speed
        if (data.network_speed) {
            const netDlVal = document.getElementById("netDlVal");
            const netUlVal = document.getElementById("netUlVal");
            if (netDlVal) netDlVal.innerText = `${data.network_speed.download_mbps} MB/s`;
            if (netUlVal) netUlVal.innerText = `${data.network_speed.upload_mbps} MB/s`;
        }

        // 5. Hardware Write Blocker Status
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
    } catch (err) {
        console.error("Error fetching system info:", err);
    }
}

// --- Drives & Detailed SMART Enumeration ---
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
            opt.innerText = `${dev.device} - ${dev.model} (${dev.size}) [SN: ${dev.serial}]`;
            driveSelect.appendChild(opt);
        });
    } catch (err) {
        console.error("Error fetching drives:", err);
    }
}

async function checkSmartTelemetry() {
    const driveSelect = document.getElementById("driveSelect");
    const targetDrive = driveSelect ? driveSelect.value : "";

    // Reset Labels
    document.getElementById("lblDevicePath").innerText = targetDrive || "--";
    document.getElementById("lblModel").innerText = "--";
    document.getElementById("lblSerial").innerText = "--";
    document.getElementById("lblCapacity").innerText = "--";
    document.getElementById("lblHealth").innerHTML = "--";
    document.getElementById("lblTemp").innerText = "--";
    document.getElementById("lblReallocated").innerText = "--";
    document.getElementById("lblPending").innerText = "--";
    document.getElementById("lblPowerHours").innerText = "--";

    if (!targetDrive) return;

    // Populate basic lsblk metadata first
    const driveObj = currentDrivesList.find(d => d.device === targetDrive);
    if (driveObj) {
        document.getElementById("lblModel").innerText = driveObj.model || "Generic Media";
        document.getElementById("lblSerial").innerText = driveObj.serial || "N/A";
        document.getElementById("lblCapacity").innerText = driveObj.size || "Unknown";
    }

    try {
        const res = await fetch('/api/smart_check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive: targetDrive })
        });
        const data = await res.json();

        if (data.success) {
            document.getElementById("lblModel").innerText = data.model || (driveObj ? driveObj.model : "Generic Disk");
            document.getElementById("lblSerial").innerText = data.serial || (driveObj ? driveObj.serial : "N/A");
            
            const healthHtml = data.healthy ? '<span class="text-success fw-bold"><i class="bi bi-check-circle-fill me-1"></i>PASSED</span>' : '<span class="text-danger fw-bold"><i class="bi bi-exclamation-triangle-fill me-1"></i>FAILING</span>';
            document.getElementById("lblHealth").innerHTML = healthHtml;
            document.getElementById("lblTemp").innerText = data.temperature ? `${data.temperature} °C` : "N/A";
            document.getElementById("lblReallocated").innerText = data.reallocated_sectors !== undefined ? data.reallocated_sectors : "0";
            document.getElementById("lblPending").innerText = data.pending_sectors !== undefined ? data.pending_sectors : "0";
            document.getElementById("lblPowerHours").innerText = data.power_on_hours ? `${data.power_on_hours} hrs` : "N/A";
        } else {
            document.getElementById("lblHealth").innerHTML = '<span class="text-warning fw-bold">UNSUPPORTED / FLASH</span>';
        }
    } catch (err) {
        console.error("Error checking SMART telemetry:", err);
    }
}

// --- Local Folder Browser Functions ---
function openFolderModal() {
    const currentDest = document.getElementById("destPath").value.trim() || '/mnt';
    currentBrowsePath = currentDest;
    
    if (!folderModalInstance) {
        folderModalInstance = new bootstrap.Modal(document.getElementById('folderBrowserModal'));
    }
    
    loadFolderList(currentBrowsePath);
    folderModalInstance.show();
}

async function loadFolderList(path) {
    const folderListEl = document.getElementById("folderList");
    const pathInputEl = document.getElementById("modalCurrentPath");
    
    if (!folderListEl) return;
    folderListEl.innerHTML = '<div class="p-3 text-muted text-center"><i class="bi bi-hourglass-split me-2"></i>Loading directories...</div>';
    
    try {
        const res = await fetch('/api/list_folders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
        const data = await res.json();
        
        if (data.error) {
            folderListEl.innerHTML = `<div class="p-3 text-danger text-center">Error: ${data.error}</div>`;
            return;
        }
        
        currentBrowsePath = data.current_path;
        if (pathInputEl) pathInputEl.value = currentBrowsePath;
        
        folderListEl.innerHTML = '';
        
        if (data.folders.length === 0) {
            folderListEl.innerHTML = '<div class="p-3 text-muted text-center"><i class="bi bi-folder-x me-2"></i>No subdirectories found in this location.</div>';
            return;
        }
        
        data.folders.forEach(folder => {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "list-group-item list-group-item-action bg-dark text-light border-secondary d-flex align-items-center py-2";
            btn.innerHTML = `<i class="bi bi-folder-fill text-warning me-2 fs-5"></i><span>${folder}</span>`;
            btn.onclick = () => {
                const newPath = currentBrowsePath.endsWith('/') ? `${currentBrowsePath}${folder}` : `${currentBrowsePath}/${folder}`;
                loadFolderList(newPath);
            };
            folderListEl.appendChild(btn);
        });
        
    } catch (err) {
        folderListEl.innerHTML = `<div class="p-3 text-danger text-center">Failed to load directories.</div>`;
    }
}

function navigateFolderUp() {
    if (currentBrowsePath === '/' || currentBrowsePath === '') return;
    const parts = currentBrowsePath.split('/').filter(p => p.length > 0);
    parts.pop();
    const parentPath = '/' + parts.join('/');
    loadFolderList(parentPath || '/');
}

function selectCurrentFolder() {
    const destPathInput = document.getElementById("destPath");
    if (destPathInput) {
        destPathInput.value = currentBrowsePath;
    }
    if (folderModalInstance) {
        folderModalInstance.hide();
    }
}

// --- Network Share Operations ---
async function queryNetworkShares() {
    const host = document.getElementById("netHost").value.trim();
    const protocol = document.getElementById("netProtocol").value;
    const shareSelect = document.getElementById("serverShareSelect");
    const mountStatus = document.getElementById("mountStatus");

    if (!host) {
        alert("Please enter a server IP address.");
        return;
    }

    if (mountStatus) mountStatus.innerText = "Querying available exports...";
    shareSelect.innerHTML = '<option value="">Querying...</option>';

    try {
        const res = await fetch('/api/list_server_shares', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, user: savedNetUser, pass: savedNetPass })
        });
        const data = await res.json();

        if (data.success) {
            shareSelect.innerHTML = '<option value="">Select Exported Share...</option>';
            data.shares.forEach(share => {
                const opt = document.createElement("option");
                opt.value = share;
                opt.innerText = share;
                shareSelect.appendChild(opt);
            });
            if (mountStatus) mountStatus.innerText = `Found ${data.shares.length} exported share(s).`;
        } else {
            shareSelect.innerHTML = '<option value="">Query Failed</option>';
            if (mountStatus) mountStatus.innerText = `Query Error: ${data.error}`;
        }
    } catch (err) {
        console.error("Error querying shares:", err);
    }
}

async function mountNetworkDrive() {
    const host = document.getElementById("netHost").value.trim();
    const protocol = document.getElementById("netProtocol").value;
    const share = document.getElementById("serverShareSelect").value;
    const mountStatus = document.getElementById("mountStatus");

    if (!share) {
        alert("Please select an exported share first.");
        return;
    }

    if (mountStatus) mountStatus.innerText = "Mounting share...";

    try {
        const res = await fetch('/api/mount_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, share, user: savedNetUser, pass: savedNetPass })
        });
        const data = await res.json();

        if (data.success) {
            if (mountStatus) mountStatus.innerText = `Successfully mounted to: ${data.mount_point}`;
            
            const destPath = document.getElementById("destPath");
            if (destPath) destPath.value = data.mount_point;
            
            alert(`Share Mounted!
Destination Target Path updated to: ${data.mount_point}`);
        } else {
            if (mountStatus) mountStatus.innerText = `Mount Error: ${data.error}`;
            alert(`Mount Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("Error mounting share:", err);
    }
}

// --- Write Blocker Toggle ---
async function toggleWriteBlock(e) {
    const enable = e.target.checked;
    const driveSelect = document.getElementById("driveSelect");
    const drive = (driveSelect && driveSelect.value) ? driveSelect.value : "/dev/sda";

    try {
        const res = await fetch('/api/toggle_write_block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable, drive })
        });
        const data = await res.json();

        if (data.success) {
            const wbBadge = document.getElementById("wbBadge");
            if (wbBadge) {
                if (data.write_blocker_active) {
                    wbBadge.className = "badge bg-danger fs-6 px-3 py-2";
                    wbBadge.innerHTML = '<i class="bi bi-lock-fill me-1"></i>Hardware Write Blocker: ACTIVE';
                } else {
                    wbBadge.className = "badge bg-warning text-dark fs-6 px-3 py-2";
                    wbBadge.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>Write Blocker: DISABLED (Read-Write)';
                }
            }
            fetchSystemInfo();
        } else {
            alert(`Failed setting write blocker on ${drive}: ${data.error}`);
            e.target.checked = !enable;
        }
    } catch (err) {
        console.error("Error toggling write blocker:", err);
        e.target.checked = !enable;
    }
}

// --- Acquisition Execution Controls ---
async function startAcquisition() {
    const source = document.getElementById("driveSelect").value;
    const dest = document.getElementById("destPath").value;
    const fmt = document.querySelector('input[name="imageFormat"]:checked').value;

    if (!source) {
        alert("Select a target evidence drive first.");
        return;
    }

    const metadata = {
        case_number: document.getElementById("caseNum").value || "2026-UNASSIGNED",
        evidence_id: document.getElementById("evidenceId").value || "ITEM-01",
        examiner: document.getElementById("examiner").value || "UNSPECIFIED",
        notes: document.getElementById("notes").value || "None"
    };

    try {
        const res = await fetch('/api/start_imaging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, destination: dest, format: fmt, metadata })
        });
        const data = await res.json();

        if (data.success) {
            document.getElementById("startBtn").disabled = true;
            document.getElementById("stopBtn").disabled = false;
        } else {
            alert(`Acquisition Start Failed: ${data.error}`);
        }
    } catch (err) {
        console.error("Error starting acquisition:", err);
    }
}

async function stopAcquisition() {
    if (!confirm("Are you sure you want to terminate the active acquisition?")) return;

    try {
        const res = await fetch('/api/stop_imaging', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            document.getElementById("startBtn").disabled = false;
            document.getElementById("stopBtn").disabled = true;
        }
    } catch (err) {
        console.error("Error stopping acquisition:", err);
    }
}

// --- Polling Progress ---
async function fetchProgress() {
    try {
        const res = await fetch('/api/progress');
        const data = await res.json();

        const currentSpeed = data.speed_mbps || 0;
        
        const speedVal = document.getElementById("speedVal");
        if (speedVal) speedVal.innerText = `${currentSpeed.toFixed(1)} MB/s`;

        const bytesVal = document.getElementById("bytesVal");
        if (bytesVal && data.total_bytes > 0) {
            const xferGb = (data.transferred_bytes / (1024**3)).toFixed(2);
            const totalGb = (data.total_bytes / (1024**3)).toFixed(2);
            bytesVal.innerText = `${xferGb} / ${totalGb} GB`;
        }

        const progressBar = document.getElementById("progressBar");
        const progressPct = document.getElementById("progressPct");
        if (progressBar) progressBar.style.width = `${data.progress_percent}%`;
        if (progressPct) progressPct.innerText = `${data.progress_percent.toFixed(1)}%`;

        const jobStatus = document.getElementById("jobStatus");
        if (jobStatus) jobStatus.innerText = `Status: ${data.status}`;

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

        const startBtn = document.getElementById("startBtn");
        const stopBtn = document.getElementById("stopBtn");
        if (startBtn && stopBtn) {
            startBtn.disabled = data.active;
            stopBtn.disabled = !data.active;
        }

    } catch (err) {
        console.error("Error polling progress:", err);
    }
}

// --- DOM Initialization ---
document.addEventListener("DOMContentLoaded", () => {
    initThroughputGraph();
    refreshDrives();
    
    setInterval(fetchSystemInfo, 2000);
    setInterval(fetchProgress, 1000);
});
