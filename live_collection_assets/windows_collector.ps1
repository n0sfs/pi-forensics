# Pi Forensics Suite - Live Collection USB, Windows collector.
#
# A small, hand-written, fully readable PowerShell live-triage collector -
# deliberately NOT a heavier third-party tool, so every line here can be
# read and understood before running it on a live system. Collects a
# curated set of VOLATILE artifacts (order-of-volatility ordering, most
# volatile first) and writes each as its own timestamped JSON file into
# .\results\<hostname>_<timestamp>\, mirroring UAC's own directory-per-
# run output shape (the Unix-side collector on this same USB) so both
# platforms' results are discovered the same way when imported back into
# a case. Nothing here modifies the target system, and nothing here ever
# touches a network - every artifact is read-only, and everything
# collected is written only into that one results folder on this
# removable drive.
#
# Runs at whatever privilege level it's launched with. Never fails
# outright for lack of admin rights - each artifact category that needs
# elevation to collect fully is honestly logged as privilege-limited
# rather than silently producing an empty/misleading result.

$ErrorActionPreference = 'Continue'

$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunDir = Join-Path -Path (Join-Path $PSScriptRoot 'results') -ChildPath "$($Hostname)_$($Timestamp)"
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$CollectionLog = @()
function Write-CollectionLog {
    param([string]$Category, [string]$Status, [string]$Detail = '')
    $script:CollectionLog += [PSCustomObject]@{
        category  = $Category
        status    = $Status   # 'ok' | 'partial' | 'failed' | 'skipped'
        detail    = $Detail
        timestamp = (Get-Date).ToString('o')
    }
    Write-Host "[$Status] $Category $(if ($Detail) { "- $Detail" })"
}

function Write-ArtifactJson {
    param([string]$Name, $Data)
    $path = Join-Path $RunDir "$Name.json"
    try {
        $Data | ConvertTo-Json -Depth 6 -ErrorAction Stop | Out-File -FilePath $path -Encoding utf8
        return $true
    } catch {
        Write-CollectionLog -Category $Name -Status 'failed' -Detail $_.Exception.Message
        return $false
    }
}

Write-Host 'Pi Forensics Suite - Live Collection (Windows)'
Write-Host "Running as administrator: $IsElevated"
Write-Host ''

# --- 0. Optional memory (RAM) capture (WinPmem, github.com/Velocidex/
#         WinPmem, Apache-2.0) - runs first, ahead of even the process
#         list below, since memory is the single most volatile artifact
#         this script can collect. Opt-in, asked interactively right here
#         on the target machine - the Pi has no way to know this machine's
#         RAM size or this drive's free space before now, so this is never
#         a choice baked in when the USB was built. Needs administrator
#         (the driver-load WinPmem's own "acquire" command performs
#         requires it) - if not elevated, this is skipped outright without
#         even asking, since it would just fail.
#
#         This build's "acquire" command has no raw-output flag at all -
#         confirmed directly against the real binary's own --help, not
#         assumed from WinPmem's public docs (which describe a different,
#         older winpmem.exe variant's CLI) - it always produces an AFF4
#         container. Rather than accept AFF4 (which this app's own
#         Volatility3 has zero support for - confirmed no aff4.py layer,
#         no pyaff4 installed), this runs the same binary's own real
#         "extract" subcommand immediately afterward to decompress the
#         AFF4 container back into a plain raw file, then discards the
#         AFF4 intermediate - zero new dependency needed anywhere else in
#         this app, and the result is exactly the plain raw memory.raw
#         file the rest of this app's Memory Forensics feature expects. ---
if (-not $IsElevated) {
    Write-CollectionLog -Category 'memory_capture' -Status 'skipped' -Detail 'requires administrator privileges - re-run elevated to capture memory'
} else {
    $WinpmemBin = Join-Path $PSScriptRoot 'memory\winpmem.exe'
    # Independent architecture check - deliberately not reusing Section 1's
    # $os variable, since Section 0 (this section) runs BEFORE Section 1
    # defines it (memory capture is placed first on purpose, ahead of even
    # the process list, as the single most volatile artifact this script
    # collects).
    $archCheck = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).OSArchitecture
    if (-not (Test-Path $WinpmemBin)) {
        Write-CollectionLog -Category 'memory_capture' -Status 'skipped' -Detail 'winpmem.exe was not found on this drive (install.py vendoring may not have run) - skipping'
    } elseif ($archCheck -match 'ARM') {
        Write-CollectionLog -Category 'memory_capture' -Status 'skipped' -Detail 'ARM64 Windows target - no compatible WinPmem binary on this USB'
    } else {
        try {
            $ramBytes = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
            $ramMb = [math]::Round($ramBytes / 1MB)
            $drive = (Get-Item $RunDir).PSDrive
            $freeMb = [math]::Round($drive.Free / 1MB)
            $needMb = $ramMb * 1.1
            if ($freeMb -lt $needMb) {
                Write-CollectionLog -Category 'memory_capture' -Status 'skipped' -Detail "not enough free space (target has ~$ramMb MB RAM, this drive has ~$freeMb MB free)"
            } else {
                Write-Host ''
                Write-Host "Memory capture available: target has ~$ramMb MB RAM, this drive has ~$freeMb MB free."
                Write-Host 'This can take several minutes and will use most of that free space.'
                $memAns = Read-Host 'Also capture a memory (RAM) image? [y/N]'
                if ($memAns -match '^[yY]') {
                    Write-Host 'Capturing memory image (this may take a while)...'
                    $aff4Path = Join-Path $RunDir 'memory.aff4'
                    $rawPath = Join-Path $RunDir 'memory.raw'
                    & $WinpmemBin acquire $aff4Path
                    if ($LASTEXITCODE -eq 0 -and (Test-Path $aff4Path)) {
                        & $WinpmemBin extract $aff4Path $rawPath
                        if ($LASTEXITCODE -eq 0 -and (Test-Path $rawPath)) {
                            Remove-Item $aff4Path -ErrorAction SilentlyContinue
                            Write-CollectionLog -Category 'memory_capture' -Status 'ok' -Detail "$([math]::Round((Get-Item $rawPath).Length / 1MB)) MB captured"
                        } else {
                            Write-CollectionLog -Category 'memory_capture' -Status 'failed' -Detail 'winpmem extract step failed - AFF4 file left in place for manual recovery'
                        }
                    } else {
                        Write-CollectionLog -Category 'memory_capture' -Status 'failed' -Detail 'winpmem acquire step failed or was blocked - continuing without it, not fatal to the rest of the collection'
                        Remove-Item $aff4Path -ErrorAction SilentlyContinue
                    }
                } else {
                    Write-CollectionLog -Category 'memory_capture' -Status 'skipped' -Detail 'declined by examiner'
                }
            }
        } catch {
            Write-CollectionLog -Category 'memory_capture' -Status 'failed' -Detail $_.Exception.Message
        }
    }
}

# --- 1. Basic system info (least volatile of this set, but cheap and
#         always worth having as context for everything else below) ---
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $sysInfo = [PSCustomObject]@{
        hostname          = $Hostname
        os_caption        = $os.Caption
        os_version        = $os.Version
        os_build          = $os.BuildNumber
        os_architecture   = $os.OSArchitecture
        last_boot_time    = $os.LastBootUpTime
        current_time      = (Get-Date).ToString('o')
        timezone          = (Get-TimeZone -ErrorAction SilentlyContinue).Id
        manufacturer      = $cs.Manufacturer
        model             = $cs.Model
        domain            = $cs.Domain
        collected_as_admin = $IsElevated
    }
    if (Write-ArtifactJson -Name 'system_info' -Data $sysInfo) {
        Write-CollectionLog -Category 'system_info' -Status 'ok'
    }
} catch {
    Write-CollectionLog -Category 'system_info' -Status 'failed' -Detail $_.Exception.Message
}

# --- 2. Running processes (most volatile - collect early) ---
try {
    $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            pid            = $_.ProcessId
            parent_pid     = $_.ParentProcessId
            name           = $_.Name
            executable_path = $_.ExecutablePath
            command_line   = $_.CommandLine
            creation_date  = $_.CreationDate
            owner          = try { ($_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop).User } catch { $null }
        }
    }
    if (Write-ArtifactJson -Name 'processes' -Data $procs) {
        Write-CollectionLog -Category 'processes' -Status 'ok' -Detail "$($procs.Count) process(es)"
    }
} catch {
    Write-CollectionLog -Category 'processes' -Status 'failed' -Detail $_.Exception.Message
}

# --- 2b. Process-executable hashes - closes a parity gap against UAC's
#         Unix-side hash_running_processes category, which this script
#         never had an equivalent for. Hashes each UNIQUE executable path
#         from the process list above once, not once per process - a
#         shared service host (svchost.exe) or common DLL would otherwise
#         get hashed dozens of times for no benefit. Written as a separate
#         process_hashes.json rather than folded into processes.json's own
#         shape, so that file's format stays exactly what it always was. ---
try {
    $uniquePaths = $procs | Where-Object { $_.executable_path } | Select-Object -ExpandProperty executable_path -Unique
    $hashFailures = 0
    $procHashes = foreach ($p in $uniquePaths) {
        try {
            $h = Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction Stop
            [PSCustomObject]@{ executable_path = $p; sha256 = $h.Hash }
        } catch {
            $hashFailures++
        }
    }
    if (Write-ArtifactJson -Name 'process_hashes' -Data $procHashes) {
        $status = if ($hashFailures -gt 0) { 'partial' } else { 'ok' }
        Write-CollectionLog -Category 'process_hashes' -Status $status -Detail "$($procHashes.Count) hashed, $hashFailures failed (locked/deleted-since-listed)"
    }
} catch {
    Write-CollectionLog -Category 'process_hashes' -Status 'failed' -Detail $_.Exception.Message
}

# --- 3. Network connections (TCP/UDP) ---
try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $tcp = Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                protocol      = 'TCP'
                local_address = $_.LocalAddress
                local_port    = $_.LocalPort
                remote_address = $_.RemoteAddress
                remote_port   = $_.RemotePort
                state         = $_.State
                owning_pid    = $_.OwningProcess
            }
        }
        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                protocol      = 'UDP'
                local_address = $_.LocalAddress
                local_port    = $_.LocalPort
                owning_pid    = $_.OwningProcess
            }
        }
        $conns = @($tcp) + @($udp)
        if (Write-ArtifactJson -Name 'network_connections' -Data $conns) {
            Write-CollectionLog -Category 'network_connections' -Status 'ok' -Detail "$($conns.Count) connection(s)"
        }
    } else {
        # Legacy fallback for a pre-Windows-8/Server-2012 target where
        # Get-NetTCPConnection doesn't exist - parse netstat's own text
        # output instead, honestly labeled as the fallback source.
        $netstatOut = netstat -ano | Select-Object -Skip 4
        $conns = $netstatOut | ForEach-Object {
            $parts = ($_ -replace '^\s+', '') -split '\s+'
            if ($parts.Count -ge 4) {
                [PSCustomObject]@{
                    protocol = $parts[0]
                    local    = $parts[1]
                    remote   = if ($parts[0] -eq 'UDP') { $null } else { $parts[2] }
                    state    = if ($parts[0] -eq 'UDP') { $null } else { $parts[3] }
                    owning_pid = $parts[-1]
                    source   = 'netstat (legacy fallback)'
                }
            }
        }
        if (Write-ArtifactJson -Name 'network_connections' -Data $conns) {
            Write-CollectionLog -Category 'network_connections' -Status 'partial' -Detail 'used netstat fallback (Get-NetTCPConnection unavailable on this OS)'
        }
    }
} catch {
    Write-CollectionLog -Category 'network_connections' -Status 'failed' -Detail $_.Exception.Message
}

# --- 4. Logged-on users / sessions ---
try {
    $sessions = quser 2>$null | Select-Object -Skip 1 | ForEach-Object {
        $line = $_ -replace '^\s+', ''
        [PSCustomObject]@{ raw_line = $line }
    }
    if ($sessions -and $sessions.Count -gt 0) {
        if (Write-ArtifactJson -Name 'logged_on_users' -Data $sessions) {
            Write-CollectionLog -Category 'logged_on_users' -Status 'ok' -Detail "$($sessions.Count) session(s)"
        }
    } else {
        Write-CollectionLog -Category 'logged_on_users' -Status 'skipped' -Detail 'quser returned nothing (not available, or no other sessions)'
    }
} catch {
    Write-CollectionLog -Category 'logged_on_users' -Status 'failed' -Detail $_.Exception.Message
}

# --- 5. ARP cache ---
try {
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        $arp = Get-NetNeighbor -ErrorAction Stop | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
    } else {
        $arp = (arp -a) | ForEach-Object { [PSCustomObject]@{ raw_line = $_; source = 'arp -a (legacy fallback)' } }
    }
    if (Write-ArtifactJson -Name 'arp_cache' -Data $arp) {
        Write-CollectionLog -Category 'arp_cache' -Status 'ok'
    }
} catch {
    Write-CollectionLog -Category 'arp_cache' -Status 'failed' -Detail $_.Exception.Message
}

# --- 6. DNS resolver cache ---
try {
    if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        $dns = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Data, TimeToLive, Type
    } else {
        $dns = (ipconfig /displaydns) | ForEach-Object { [PSCustomObject]@{ raw_line = $_; source = 'ipconfig /displaydns (legacy fallback)' } }
    }
    if (Write-ArtifactJson -Name 'dns_cache' -Data $dns) {
        Write-CollectionLog -Category 'dns_cache' -Status 'ok'
    }
} catch {
    Write-CollectionLog -Category 'dns_cache' -Status 'failed' -Detail $_.Exception.Message
}

# --- 7. Services ---
try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            name         = $_.Name
            display_name = $_.DisplayName
            state        = $_.State
            start_mode   = $_.StartMode
            path         = $_.PathName
            start_name   = $_.StartName
        }
    }
    if (Write-ArtifactJson -Name 'services' -Data $services) {
        Write-CollectionLog -Category 'services' -Status 'ok' -Detail "$($services.Count) service(s)"
    }
} catch {
    Write-CollectionLog -Category 'services' -Status 'failed' -Detail $_.Exception.Message
}

# --- 8. Scheduled tasks ---
try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                task_name = $_.TaskName
                task_path = $_.TaskPath
                state     = $_.State
                actions   = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            }
        }
    } else {
        # Legacy fallback: schtasks.exe's own CSV output.
        $tasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv
    }
    if (Write-ArtifactJson -Name 'scheduled_tasks' -Data $tasks) {
        Write-CollectionLog -Category 'scheduled_tasks' -Status 'ok' -Detail "$($tasks.Count) task(s)"
    }
} catch {
    Write-CollectionLog -Category 'scheduled_tasks' -Status 'failed' -Detail $_.Exception.Message
}

# --- 9. Autorun / startup items (Run keys + Startup folders) - a
#         deliberately narrow, curated subset (the most commonly-abused
#         persistence locations), not a full autoruns-style sweep ---
try {
    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $autoruns = @()
    foreach ($regPath in $runKeyPaths) {
        if (Test-Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' } | ForEach-Object {
                    $autoruns += [PSCustomObject]@{ source = $regPath; name = $_.Name; value = $_.Value }
                }
            }
        }
    }
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { $_ -and (Test-Path $_) }
    foreach ($folder in $startupFolders) {
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            $autoruns += [PSCustomObject]@{ source = "startup_folder:$folder"; name = $_.Name; value = $_.FullName }
        }
    }
    if (Write-ArtifactJson -Name 'autoruns' -Data $autoruns) {
        Write-CollectionLog -Category 'autoruns' -Status 'ok' -Detail "$($autoruns.Count) entrie(s)"
    }
} catch {
    Write-CollectionLog -Category 'autoruns' -Status 'failed' -Detail $_.Exception.Message
}

# --- 10. Installed hotfixes/patches ---
try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledOn
    if (Write-ArtifactJson -Name 'installed_hotfixes' -Data $hotfixes) {
        Write-CollectionLog -Category 'installed_hotfixes' -Status 'ok' -Detail "$($hotfixes.Count) hotfix(es)"
    }
} catch {
    Write-CollectionLog -Category 'installed_hotfixes' -Status 'failed' -Detail $_.Exception.Message
}

# --- Loaded drivers - admin-only on most systems; honestly logged as
#      privilege-limited when it can't run, never silently skipped ---
if ($IsElevated) {
    try {
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Select-Object Name, DisplayName, State, PathName
        if (Write-ArtifactJson -Name 'loaded_drivers' -Data $drivers) {
            Write-CollectionLog -Category 'loaded_drivers' -Status 'ok' -Detail "$($drivers.Count) driver(s)"
        }
    } catch {
        Write-CollectionLog -Category 'loaded_drivers' -Status 'failed' -Detail $_.Exception.Message
    }
} else {
    Write-CollectionLog -Category 'loaded_drivers' -Status 'skipped' -Detail 'requires administrator privileges - not run'
}

# --- 11. Mapped network drives ---
try {
    if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) {
        $mapped = Get-SmbMapping -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ local_path = $_.LocalPath; remote_path = $_.RemotePath; status = $_.Status }
        }
    } else {
        # Legacy fallback for a target without the SMB PowerShell module -
        # parse net use's own text output, honestly labeled as the fallback
        # source, matching every other category's fallback-labeling
        # convention already used in this script.
        $mapped = (net use) | Select-Object -Skip 4 | ForEach-Object {
            $line = $_.Trim()
            if ($line -and $line -ne '' -and $line -notmatch '^The command completed') {
                [PSCustomObject]@{ local_path = $null; remote_path = $null; status = $null; raw_line = $line; source = 'net use (legacy fallback)' }
            }
        } | Where-Object { $_ }
    }
    if (Write-ArtifactJson -Name 'mapped_drives' -Data $mapped) {
        Write-CollectionLog -Category 'mapped_drives' -Status 'ok' -Detail "$($mapped.Count) mapping(s)"
    }
} catch {
    Write-CollectionLog -Category 'mapped_drives' -Status 'failed' -Detail $_.Exception.Message
}

# --- 12. Clipboard contents ---
try {
    $clipContent = Get-Clipboard -ErrorAction Stop -Raw
    if ($clipContent) {
        $clipData = [PSCustomObject]@{ content = ($clipContent -join "`n"); collected_at = (Get-Date).ToString('o') }
        if (Write-ArtifactJson -Name 'clipboard' -Data $clipData) {
            Write-CollectionLog -Category 'clipboard' -Status 'ok'
        }
    } else {
        Write-CollectionLog -Category 'clipboard' -Status 'skipped' -Detail 'clipboard was empty'
    }
} catch {
    Write-CollectionLog -Category 'clipboard' -Status 'failed' -Detail $_.Exception.Message
}

# --- Final collection log, written last so it reflects every category
#      above (including any that failed/were skipped) ---
Write-ArtifactJson -Name '_collection_log' -Data $CollectionLog | Out-Null

Write-Host ''
Write-Host "Collection complete. Results are in: $RunDir"
Write-Host 'Safely eject this drive, then plug it back into the Pi Forensics Suite'
Write-Host "station and use 'Import Collection Results'."
