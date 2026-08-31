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

# --- Final collection log, written last so it reflects every category
#      above (including any that failed/were skipped) ---
Write-ArtifactJson -Name '_collection_log' -Data $CollectionLog | Out-Null

Write-Host ''
Write-Host "Collection complete. Results are in: $RunDir"
Write-Host 'Safely eject this drive, then plug it back into the Pi Forensics Suite'
Write-Host "station and use 'Import Collection Results'."
