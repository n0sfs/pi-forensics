let currentBrowserPath = "/mnt";
let activeDestType = "local";
let savedNetUser = "";
let savedNetPass = "";
let throughputChart = null;

// Track connected drive signatures to detect hot-plugging
let knownDriveSignature = "";

// Store last queried telemetry for report metadata
let currentDriveTelemetry = {};

document.addEventListener("DOMContentLoaded", () => {
    initThroughputChart();
    
    fetchSystemInfo();
    fetchDrives(); // Initial fetch
    loadSavedNetworkDrives();
    
    // Background polling loops
    setInterval(fetchSystemInfo, 2000);
    setInterval(pollProgress, 1000);
    setInterval(fetchDrives, 2000); // Auto-detect USB / SD / HDD insertions

    document.getElementById("driveSelect").addEventListener("change", inspectDriveTelemetry);
    document.getElementById("writeBlockToggle").addEventListener("change", toggleWriteBlock);
    document.getElementById("startBtn").addEventListener("click", startImaging);
    document.getElementById("stopBtn").addEventListener("click", stopImaging);
    
    document.getElementById("connectServerBtn").addEventListener("click", connectAndQueryShares);
    document.getElementById("submitAuthBtn").addEventListener("click", () => {
        savedNetUser = document.getElementById("modalNetUser").value;
        savedNetPass = document.getElementById("modalNetPass").value;
        connectAndQueryShares();
    });
    
    document.getElementById("mountNetBtn").addEventListener("click", mountNetworkDrive);
    document.getElementById("savedDrivesSelect").addEventListener("change", selectSavedDrive);
    document.getElementById("clearHistoryBtn").addEventListener("click", clearSavedHistory);

    // Tab toggle
    document.getElementById("local-tab").addEventListener("click", () => activeDestType = "local");
    document.getElementById("network-tab").addEventListener("click", () => activeDestType = "network");

    // Modal Folder Navigation
    document.getElementById("folderBrowserModal").addEventListener("show.bs.modal", () => browseFolder(currentBrowserPath));
    document.getElementById("navUpBtn").addEventListener("click", navigateUp);
    document.getElementById("confirmFolderBtn").addEventListener("click", () => {
        document.getElementById("destPath").value = currentBrowserPath;
    });
});

// --- Chart.js Telemetry Initialization ---
function initThroughputChart() {
    const canvas = document.getElementById('throughputChart');
    if (!canvas) return;

    Chart.defaults.color = '#ffffff';
    Chart.defaults.font.family = 'system-ui, -apple-system, sans-serif';

    const ctx = canvas.getContext('2d');
    
    if (throughputChart) {
        throughputChart.destroy();
    }

    throughputChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Speed (MB/s)',
                data: Array(20).fill(0),
                borderColor: '#60a5fa',
                backgroundColor: 'rgba(96, 165, 250, 0.35)',
                borderWidth: 2.5,
                tension: 0.35,
                fill: true,
                pointRadius: 0,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0f172a',
                    titleColor: '#ffffff',
                    bodyColor: '#38bdf8',
                    borderColor: '#334155',
                    borderWidth: 1,
                    padding: 10,
                    callbacks: {
                        label: (context) => ` Speed: ${context.raw} MB/s`
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#ffffff',
                        font: { size: 10, weight: 'bold' }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: { 
                        color: 'rgba(255, 255, 255, 0.15)',
                        lineWidth: 1
                    },
                    ticks: {
                        color: '#ffffff',
                        font: { size: 11, weight: 'bold' },
                        callback: (value) => `${value} MB/s`
                    }
                }
            }
        }
    });
}

function pushThroughputData(speedMBps) {
    if (!throughputChart) return;

    const timeLabel = new Date().toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
    });

    throughputChart.data.labels.shift();
    throughputChart.data.datasets[0].data.shift();

    throughputChart.data.labels.push(timeLabel);
    throughputChart.data.datasets[0].data.push(speedMBps);

    throughputChart.update('none');
}

// --- Auto-Detect Hot-Plugged USB / SD / Drives ---
async function fetchDrives() {
    try {
        const res = await fetch('/api/drives');
        const drives = await res.json();
        
        // Generate a unique fingerprint of connected drives
        const newSignature = drives.map(d => `${d.name}-${d.size}-${d.model}`).join('|');
        
        // If no change in drive topology, exit without disrupting UI
        if (newSignature === knownDriveSignature) return;
        
        knownDriveSignature = newSignature;
        const select = document.getElementById("driveSelect");
        const currentSelection = select.value;
        
        select.innerHTML = '<option value="">-- Choose Target Source Drive --</option>';
        
        drives.forEach(drive => {
            const opt = document.createElement("option");
            opt.value = `/dev/${drive.name}`;
            opt.innerText = `/dev/${drive.name} - ${drive.model || 'Generic Device'} (${drive.size})`;
            select.appendChild(opt);
        });

        // Restore previous selection if drive is still attached
        if (currentSelection && drives.some(d => `/dev/${d.name}` === currentSelection)) {
            select.value = currentSelection;
        } else {
            inspectDriveTelemetry(); // Reset panel if selected drive was unplugged
        }

    } catch (err) {
        console.error("Error polling drive topology:", err);
    }
}

// --- Dynamic Inline Drive Telemetry & SMART Inspector ---
async function inspectDriveTelemetry() {
    const drive = document.getElementById("driveSelect").value;
    
    const badge = document.getElementById("smartStatusBadge");
    const deviceEl = document.getElementById("telemetryDevice");
    const typeEl = document.getElementById("telemetryType");
    const modelEl = document.getElementById("telemetryModel");
    const serialEl = document.getElementById("telemetrySerial");
    const sizeEl = document.getElementById("telemetrySize");
    const stateEl = document.getElementById("telemetryState");
    const tempEl = document.getElementById("telemetryTemp");
    const reallocatedEl = document.getElementById("telemetryReallocated");
    const pendingEl = document.getElementById("telemetryPending");
    const powerOnEl = document.getElementById("telemetryPowerOn");

    if (!drive) {
        badge.className = "badge bg-secondary text-uppercase fs-6";
        badge.innerText = "No Drive Selected";
        deviceEl.innerText = "--";
        typeEl.innerText = "--";
        modelEl.innerText = "--";
        serialEl.innerText = "--";
        sizeEl.innerText = "--";
        stateEl.innerText = "--";
        tempEl.innerText = "--";
        reallocatedEl.innerText = "--";
        pendingEl.innerText = "--";
        powerOnEl.innerText = "--";
        currentDriveTelemetry = {};
        return;
    }

    badge.className = "badge bg-warning text-dark text-uppercase fs-6";
    badge.innerText = "Querying...";
    stateEl.innerText = "Reading Disk Telemetry...";

    try {
        const res = await fetch('/api/smart_check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive })
        });
        const data = await res.json();

        deviceEl.innerText = drive;
        modelEl.innerText = data.model || 'Generic / Flash Device';
        serialEl.innerText = data.serial || 'N/A';
        sizeEl.innerText = data.size || 'N/A';

        // Detect Media Type
        let mediaType = "SATA / ATA Storage";
        if (drive.includes('mmcblk')) {
            mediaType = 'SD / MicroSD Card';
        } else if (data.transport === 'usb' || data.is_usb) {
            mediaType = 'USB Flash / Thumb Drive';
        } else if (drive.includes('nvme')) {
            mediaType = 'NVMe SSD';
        }
        typeEl.innerText = mediaType;

        let healthStatus = "UNKNOWN";
        if (!data.success) {
            badge.className = "badge bg-info text-dark text-uppercase fs-6";
            badge.innerText = "READY (FLASH MEDIA)";
            stateEl.className = "fw-bold text-info";
            stateEl.innerText = "PASSED (Flash Media / No SMART)";
            tempEl.innerText = "N/A";
            reallocatedEl.innerText = "N/A";
            pendingEl.innerText = "N/A";
            powerOnEl.innerText = "N/A";
            healthStatus = "PASSED (Flash Media)";
        } else if (data.healthy) {
            badge.className = "badge bg-success text-uppercase fs-6";
            badge.innerText = "HEALTHY";
            stateEl.className = "fw-bold text-success";
            stateEl.innerText = "PASSED (GOOD DRIVE)";
            tempEl.innerText = data.temperature ? `${data.temperature} °C` : 'N/A';
            reallocatedEl.innerText = data.reallocated_sectors !== undefined ? data.reallocated_sectors : '0';
            reallocatedEl.className = data.reallocated_sectors > 0 ? "text-danger fw-bold" : "text-white";
            pendingEl.innerText = data.pending_sectors !== undefined ? data.pending_sectors : '0';
            pendingEl.className = data.pending_sectors > 0 ? "text-danger fw-bold" : "text-white";
            powerOnEl.innerText = data.power_on_hours ? `${data.power_on_hours} hrs` : 'N/A';
            healthStatus = "PASSED (HEALTHY)";
        } else {
            badge.className = "badge bg-danger text-uppercase fs-6";
            badge.innerText = "FAILING";
            stateEl.className = "fw-bold text-danger";
            stateEl.innerText = "WARNING: BAD SECTORS / FAILING";
            tempEl.innerText = data.temperature ? `${data.temperature} °C` : 'N/A';
            reallocatedEl.innerText = data.reallocated_sectors || 'N/A';
            pendingEl.innerText = data.pending_sectors || 'N/A';
            powerOnEl.innerText = data.power_on_hours ? `${data.power_on_hours} hrs` : 'N/A';
            healthStatus = "FAILING (BAD SECTORS)";
        }

        // Store telemetry for forensic report injection
        currentDriveTelemetry = {
            device: drive,
            media_type: mediaType,
            model: data.model || 'Generic / Flash Device',
            serial: data.serial || 'N/A',
            size: data.size || 'N/A',
            health_status: healthStatus,
            temperature: data.temperature || 'N/A',
            reallocated_sectors: data.reallocated_sectors || 0,
            pending_sectors: data.pending_sectors || 0,
            power_on_hours: data.power_on_hours || 'N/A'
        };

    } catch (err) {
        console.error("Error inspecting drive:", err);
        badge.className = "badge bg-danger text-uppercase fs-6";
        badge.innerText = "ERROR";
        stateEl.className = "fw-bold text-danger";
        stateEl.innerText = "Communication Error";
    }
}

// --- Acquisition Execution & Reporting ---
async function startImaging() {
    const source = document.getElementById("driveSelect").value;
    if (!source) {
        alert("Please select a target source drive first.");
        return;
    }

    const payload = {
        source: source,
        dest_type: activeDestType,
        destination: document.getElementById("destPath").value,
        hashes: {
            md5: document.getElementById("hashMd5").checked,
            sha1: document.getElementById("hashSha1").checked,
            sha256: document.getElementById("hashSha256").checked
        },
        metadata: {
            case_number: document.getElementById("caseNum").value.trim() || "UNASSIGNED",
            evidence_id: document.getElementById("evidenceId").value.trim() || "ITEM-01",
            examiner: document.getElementById("examinerName").value.trim() || "UNSPECIFIED",
            notes: document.getElementById("caseNotes").value.trim() || "None",
            telemetry: currentDriveTelemetry // Direct inclusion into case report
        }
    };

    try {
        const res = await fetch('/api/start_imaging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.error) alert(data.error);
    } catch (err) {
        console.error("Error starting acquisition:", err);
    }
}

async function stopImaging() {
    if (!confirm("Are you sure you want to stop the imaging process?")) return;
    try {
        await fetch('/api/stop_imaging', { method: 'POST' });
    } catch (err) {
        console.error("Error stopping acquisition:", err);
    }
}

function loadSavedNetworkDrives() {
    const select = document.getElementById("savedDrivesSelect");
    const history = JSON.parse(localStorage.getItem("net_drive_history") || "[]");
    
    select.innerHTML = '<option value="">-- Choose a previously used network share --</option>';
    if (history.length === 0) {
        select.innerHTML = '<option value="">No saved network drives yet</option>';
        return;
    }

    history.forEach((item, index) => {
        const opt = document.createElement("option");
        opt.value = index;
        opt.innerText = `[${item.protocol.toUpperCase()}] //${item.host}/${item.share} ${item.user ? '(' + item.user + ')' : ''}`;
        select.appendChild(opt);
    });
}

function selectSavedDrive(e) {
    const index = e.target.value;
    if (index === "") return;

    const history = JSON.parse(localStorage.getItem("net_drive_history") || "[]");
    const item = history[index];
    if (!item) return;

    document.getElementById("netProtocol").value = item.protocol;
    document.getElementById("netHost").value = item.host;
    savedNetUser = item.user || "";
    savedNetPass = item.pass || "";

    const shareSelect = document.getElementById("serverShareSelect");
    shareSelect.innerHTML = `<option value="${item.share}" selected>${item.share}</option>`;
    shareSelect.disabled = false;
    document.getElementById("mountNetBtn").disabled = false;
}

function saveDriveToHistory(protocol, host, share, user, pass) {
    let history = JSON.parse(localStorage.getItem("net_drive_history") || "[]");
    history = history.filter(item => !(item.host === host && item.share === share && item.protocol === protocol));
    history.unshift({ protocol, host, share, user, pass });
    if (history.length > 10) history.pop();
    localStorage.setItem("net_drive_history", JSON.stringify(history));
    loadSavedNetworkDrives();
}

function clearSavedHistory() {
    if (confirm("Clear all saved network drives from history?")) {
        localStorage.removeItem("net_drive_history");
        loadSavedNetworkDrives();
    }
}

async function connectAndQueryShares() {
    const host = document.getElementById("netHost").value.trim();
    const protocol = document.getElementById("netProtocol").value;
    const shareSelect = document.getElementById("serverShareSelect");
    const mountBtn = document.getElementById("mountNetBtn");
    
    if (!host) {
        alert("Please enter a valid Server IP Address.");
        return;
    }

    shareSelect.disabled = true;
    mountBtn.disabled = true;
    shareSelect.innerHTML = '<option value="">Querying server shares...</option>';

    try {
        const res = await fetch('/api/list_server_shares', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol, host, user: savedNetUser, pass: savedNetPass })
        });
        
        if (res.status === 401) {
            const authModal = new bootstrap.Modal(document.getElementById('authModal'));
            authModal.show();
            shareSelect.innerHTML = '<option value="">Authentication required...</option>';
            return;
        }

        const data = await res.json();
        
        if (data.success && data.shares.length > 0) {
            shareSelect.innerHTML = '<option value="">-- Select Discovered Share --</option>';
            data.shares.forEach(share => {
                const opt = document.createElement("option");
                opt.value = share;
                opt.innerText = share;
                shareSelect.appendChild(opt);
            });
            shareSelect.disabled = false;
            mountBtn.disabled = false;
        } else {
            const manualPath = prompt("No public share list broadcasted by server.\nPlease enter the exact share path:");
            if (manualPath) {
                shareSelect.innerHTML = `<option value="${manualPath}" selected>${manualPath}</option>`;
                shareSelect.disabled = false;
                mountBtn.disabled = false;
            } else {
                shareSelect.innerHTML = '<option value="">No shares found</option>';
            }
        }
    } catch (err) {
        console.error("Error querying server:", err);
        alert("Failed to reach network server.");
    }
}

async function mountNetworkDrive() {
    const host = document.getElementById("netHost").value.trim();
    const protocol = document.getElementById("netProtocol").value;
    const share = document.getElementById("serverShareSelect").value;

    if (!share) {
        alert("Please select a share from the dropdown first.");
        return;
    }

    const mountStatus = document.getElementById("mountStatus");
    mountStatus.className = "fs-5 fw-bold text-warning";
    mountStatus.innerText = "Connecting & Mounting...";

    try {
        const res = await fetch('/api/mount_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                protocol: protocol,
                host: host,
                share: share,
                user: savedNetUser,
                pass: savedNetPass
            })
        });
        const data = await res.json();

        if (data.success) {
            mountStatus.className = "fs-5 fw-bold text-success";
            mountStatus.innerText = `Status: Connected to //${host}/${share}`;
            saveDriveToHistory(protocol, host, share, savedNetUser, savedNetPass);
            alert(`Share Mounted Successfully to ${data.mount_point}`);
        } else {
            mountStatus.className = "fs-5 fw-bold text-danger";
            mountStatus.innerText = "Status: Mount Failed";
            alert(data.error);
        }
    } catch (err) {
        console.error("Error mounting drive:", err);
    }
}

async function fetchSystemInfo() {
    try {
        const res = await fetch('/api/system_info');
        const data = await res.json();
        
        document.getElementById("cpuUsage").innerText = `${data.cpu_percent}%`;
        document.getElementById("cpuBar").style.width = `${data.cpu_percent}%`;

        const storage = data.local_storage;
        document.getElementById("storageUsage").innerText = `${storage.used_gb} / ${storage.total_gb} GB`;
        document.getElementById("storageBar").style.width = `${storage.percent_used}%`;

        const wbToggle = document.getElementById("writeBlockToggle");
        const wbLabel = document.getElementById("wbLabel");
        wbToggle.checked = data.write_blocker_active;
        wbLabel.innerText = `Write Blocker: ${data.write_blocker_active ? 'ON' : 'OFF'}`;
        wbLabel.className = `form-check-label fw-bold ms-2 ${data.write_blocker_active ? 'text-danger' : 'text-white'}`;
    } catch (err) {
        console.error("Error fetching system info:", err);
    }
}

async function browseFolder(path) {
    try {
        const res = await fetch('/api/list_folders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
        const data = await res.json();
        if (data.error) return;

        currentBrowserPath = data.current_path;
        document.getElementById("currentPathDisplay").innerText = currentBrowserPath;

        const container = document.getElementById("folderContainer");
        container.innerHTML = "";

        if (data.folders.length === 0) {
            container.innerHTML = '<div class="text-white fs-5 text-center p-3">No subdirectories found</div>';
            return;
        }

        data.folders.forEach(folder => {
            const item = document.createElement("div");
            item.className = "folder-list-item";
            item.innerHTML = `<span>[Folder] <strong>${folder}</strong></span> <button class="btn btn-sm btn-outline-primary fw-bold">Open</button>`;
            item.onclick = () => browseFolder(`${currentBrowserPath}/${folder}`);
            container.appendChild(item);
        });
    } catch (err) {
        console.error("Error browsing directory:", err);
    }
}

function navigateUp() {
    const parts = currentBrowserPath.split('/').filter(Boolean);
    parts.pop();
    browseFolder('/' + parts.join('/'));
}

async function toggleWriteBlock(e) {
    try {
        await fetch('/api/toggle_write_block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: e.target.checked })
        });
        fetchSystemInfo();
    } catch (err) {
        console.error("Failed to set write blocker status:", err);
    }
}

function formatETA(seconds) {
    if (!seconds || seconds <= 0 || !isFinite(seconds)) return "--:--:--";
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

async function pollProgress() {
    try {
        const res = await fetch('/api/progress');
        const data = await res.json();

        const bar = document.getElementById("progressBar");
        bar.style.width = `${data.progress_percent}%`;

        const speed = parseFloat(data.speed_mbps || 0);
        pushThroughputData(speed);

        if (data.status === "Verifying Hashes...") {
            bar.innerText = "99% (Verifying Hashes...)";
            bar.className = "progress-bar progress-bar-striped progress-bar-animated bg-info fs-5 fw-bold";
            document.getElementById("etaDisplay").innerText = "Hashing...";
        } else if (data.status === "Flushing Disk Cache...") {
            bar.innerText = "99% (Flushing Storage Cache...)";
            bar.className = "progress-bar progress-bar-striped progress-bar-animated bg-warning fs-5 fw-bold";
            document.getElementById("etaDisplay").innerText = "Finishing...";
        } else if (data.status === "Completed Successfully") {
            bar.innerText = "100% Complete";
            bar.className = "progress-bar bg-success fs-5 fw-bold";
            document.getElementById("etaDisplay").innerText = "00:00:00";
        } else if (data.status === "Failed") {
            bar.innerText = `${data.progress_percent}% (Failed)`;
            bar.className = "progress-bar bg-danger fs-5 fw-bold";
            document.getElementById("etaDisplay").innerText = "Error";
        } else if (data.active) {
            bar.innerText = `${data.progress_percent}%`;
            bar.className = "progress-bar progress-bar-striped progress-bar-animated bg-success fs-5 fw-bold";
            
            const remainingBytes = data.total_bytes - data.transferred_bytes;
            const speedBytesPerSec = data.speed_mbps * 1024 * 1024;
            const etaSeconds = speedBytesPerSec > 0 ? (remainingBytes / speedBytesPerSec) : 0;
            document.getElementById("etaDisplay").innerText = formatETA(etaSeconds);
        } else {
            bar.innerText = "0%";
            document.getElementById("etaDisplay").innerText = "--:--:--";
        }

        document.getElementById("transferSpeed").innerText = `${data.speed_mbps} MB/s`;
        
        const statusElem = document.getElementById("imagingStatus");
        statusElem.innerText = data.status;
        statusElem.className = data.status === "Failed" ? "fw-bold text-danger" : 
                              (data.status === "Completed Successfully" ? "fw-bold text-success" : 
                              (data.status.includes("Verifying") || data.status.includes("Flushing") ? "fw-bold text-info" : "fw-bold text-warning"));

        const mbTransferred = (data.transferred_bytes / (1024 * 1024)).toFixed(1);
        const mbTotal = (data.total_bytes / (1024 * 1024)).toFixed(1);
        document.getElementById("bytesTransferred").innerText = `${mbTransferred} MB / ${mbTotal} MB`;

        document.getElementById("terminalLog").innerText = data.log;

        document.getElementById("startBtn").disabled = data.active;
        document.getElementById("stopBtn").disabled = !data.active;
    } catch (err) {
        console.error("Error fetching progress:", err);
    }
}