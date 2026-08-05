let currentBrowserPath = "/mnt";
let activeDestType = "local";
let savedNetUser = "";
let savedNetPass = "";

document.addEventListener("DOMContentLoaded", () => {
    fetchSystemInfo();
    fetchDrives();
    loadSavedNetworkDrives();
    
    setInterval(fetchSystemInfo, 2000);
    setInterval(pollProgress, 1000);

    document.getElementById("writeBlockToggle").addEventListener("change", toggleWriteBlock);
    document.getElementById("startBtn").addEventListener("click", startImaging);
    document.getElementById("stopBtn").addEventListener("click", stopImaging);
    document.getElementById("checkSmartBtn").addEventListener("click", checkSmartHealth);
    
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

async function checkSmartHealth() {
    const drive = document.getElementById("driveSelect").value;
    if (!drive) {
        alert("Please select a target source drive first.");
        return;
    }

    const smartModal = new bootstrap.Modal(document.getElementById('smartModal'));
    const statusHeader = document.getElementById('smartStatusHeader');
    const tableBody = document.getElementById('smartTableBody');

    statusHeader.className = "mb-3 p-3 rounded text-center fw-bold fs-4 bg-secondary text-white";
    statusHeader.innerText = "Querying SMART Health Telemetry...";
    tableBody.innerHTML = '<tr><td colspan="2" class="text-center">Communicating with disk controller...</td></tr>';
    smartModal.show();

    try {
        const res = await fetch('/api/smart_check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive })
        });
        const data = await res.json();

        if (!data.success) {
            statusHeader.className = "mb-3 p-3 rounded text-center fw-bold fs-4 bg-danger text-white";
            statusHeader.innerText = "SMART Check Failed or Unsupported Device";
            tableBody.innerHTML = `<tr><td colspan="2" class="text-danger">${data.error}</td></tr>`;
            return;
        }

        if (data.healthy) {
            statusHeader.className = "mb-3 p-3 rounded text-center fw-bold fs-4 bg-success text-white";
            statusHeader.innerText = "OVERALL HEALTH: PASSED (GOOD DRIVE)";
        } else {
            statusHeader.className = "mb-3 p-3 rounded text-center fw-bold fs-4 bg-danger text-white";
            statusHeader.innerText = "WARNING: DRIVE HEALTH FAILING / BAD SECTORS";
        }

        tableBody.innerHTML = `
            <tr><th style="width: 40%;">Model / Family</th><td>${data.model || 'Unknown'}</td></tr>
            <tr><th>Serial Number</th><td><code>${data.serial || 'N/A'}</code></td></tr>
            <tr><th>Temperature</th><td>${data.temperature ? data.temperature + ' °C' : 'N/A'}</td></tr>
            <tr><th>Reallocated Sectors</th><td class="${data.reallocated_sectors > 0 ? 'text-danger fw-bold' : ''}">${data.reallocated_sectors}</td></tr>
            <tr><th>Pending Bad Sectors</th><td class="${data.pending_sectors > 0 ? 'text-danger fw-bold' : ''}">${data.pending_sectors}</td></tr>
            <tr><th>Power On Hours</th><td>${data.power_on_hours ? data.power_on_hours + ' hrs' : 'N/A'}</td></tr>
        `;
    } catch (err) {
        console.error("Error querying SMART status:", err);
        statusHeader.className = "mb-3 p-3 rounded text-center fw-bold fs-4 bg-danger text-white";
        statusHeader.innerText = "Communication Error";
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
        wbLabel.className = `form-check-label fw-bold ms-2 ${data.write_blocker_active ? 'text-danger' : 'text-secondary'}`;
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
            container.innerHTML = '<div class="text-muted fs-5 text-center p-3">No subdirectories found</div>';
            return;
        }

        data.folders.forEach(folder => {
            const item = document.createElement("div");
            item.className = "folder-list-item";
            item.innerHTML = `<span>[Folder] <strong>${folder}</strong></span> <button class="btn btn-sm btn-outline-primary">Open</button>`;
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

async function fetchDrives() {
    try {
        const res = await fetch('/api/drives');
        const drives = await res.json();
        const select = document.getElementById("driveSelect");
        select.innerHTML = '<option value="">-- Choose Target Source Drive --</option>';
        
        drives.forEach(drive => {
            const opt = document.createElement("option");
            opt.value = `/dev/${drive.name}`;
            opt.innerText = `/dev/${drive.name} - ${drive.model || 'Generic Device'} (${drive.size})`;
            select.appendChild(opt);
        });
    } catch (err) {
        console.error("Error fetching drives:", err);
    }
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
            notes: document.getElementById("caseNotes").value.trim() || "None"
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
        statusElem.className = data.status === "Failed" ? "metric-value text-danger" : 
                              (data.status === "Completed Successfully" ? "metric-value text-success" : 
                              (data.status.includes("Verifying") || data.status.includes("Flushing") ? "metric-value text-info" : "metric-value text-warning"));

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
