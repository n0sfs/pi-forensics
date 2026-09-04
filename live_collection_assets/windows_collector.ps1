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
        # Explicit .ToString('o') - same reasoning as creation_date above.
        # This is a genuinely useful historical timestamp on its own (when
        # did this machine last start up), not just collection metadata.
        last_boot_time    = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { $null }
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
            # .ToString('o') explicitly, matching every other timestamp in
            # this script - a bare [datetime] handed straight to ConvertTo-
            # Json has no guaranteed format (it's varied across PowerShell
            # versions historically). CreationDate is genuinely null for a
            # few system processes (System Idle Process, sometimes System
            # itself) - the parser on the receiving end falls back to this
            # run's own collection time for those, never crashes on it.
            creation_date  = if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { $null }
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
                # Real, per-connection "when was this established" data -
                # MSFT_NetTCPConnection genuinely exposes this. UDP is
                # connectionless, Get-NetUDPEndpoint has no equivalent
                # property, so this is TCP-only, not an oversight below.
                created       = if ($_.CreationTime) { $_.CreationTime.ToString('o') } else { $null }
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
        # Explicit snake_case object, matching every other collected
        # category's own convention - Select-Object alone would have left
        # PowerShell's PascalCase property names (IPAddress, etc.) in the
        # JSON, inconsistent with the rest of this script.
        $arp = Get-NetNeighbor -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                ip_address  = $_.IPAddress
                mac_address = $_.LinkLayerAddress
                state       = $_.State
                interface   = $_.InterfaceAlias
            }
        }
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
        # Same snake_case normalization as arp_cache above.
        $dns = Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                entry = $_.Entry
                name  = $_.Name
                data  = $_.Data
                ttl   = $_.TimeToLive
                type  = $_.Type
            }
        }
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
            # Get-ScheduledTaskInfo is a SEPARATE, per-task call - not
            # available on the task object Get-ScheduledTask itself
            # returns - the only source of real run-history data
            # (LastRunTime/NextRunTime/LastTaskResult). A per-task
            # failure (a task deleted between the two calls, an access
            # error) never aborts the rest of the list.
            $info = try { $_ | Get-ScheduledTaskInfo -ErrorAction Stop } catch { $null }
            [PSCustomObject]@{
                task_name = $_.TaskName
                task_path = $_.TaskPath
                state     = $_.State
                actions   = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
                # .ToString('o') for the same reason as every other
                # historical timestamp in this script. LastRunTime/
                # NextRunTime are well-documented to come back as a
                # "zero date" sentinel (commonly ~1899) for a task that's
                # never run or has no scheduled next run, rather than
                # $null - the Python-side parser rejects an implausibly
                # old date rather than trusting it, so this is passed
                # through as-is, not filtered here.
                last_run_time = if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString('o') } else { $null }
                next_run_time = if ($info -and $info.NextRunTime) { $info.NextRunTime.ToString('o') } else { $null }
                last_task_result = if ($info) { $info.LastTaskResult } else { $null }
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
                # Get-ItemProperty on the registry provider always injects 5
                # PowerShell meta-properties alongside the real values -
                # PSPath/PSParentPath/PSChildName/PSProvider/PSDrive. Real
                # bug found live (2026-09-03) against a real Windows target:
                # this filter excluded only 4 of the 5 (missing PSDrive), so
                # the PSDrive meta-property - a full PSDriveInfo object,
                # itself carrying a nested ProviderInfo with deep internal
                # PowerShell state - leaked through as if it were a real
                # startup entry and got recursively serialized, bloating a
                # single collection run's autoruns.json to ~13.6MB of
                # PowerShell object internals instead of a small, clean list
                # of actual startup entries.
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } | ForEach-Object {
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
    # Snake_case + explicit .ToString('o') on installed_on (same reasoning
    # as creation_date above) - InstalledOn is also genuinely null for some
    # real hotfix entries, not just a theoretical edge case.
    $hotfixes = Get-HotFix -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            hotfix_id   = $_.HotFixID
            description = $_.Description
            installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null }
        }
    }
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
        # Snake_case, matching every other collected category's convention
        # (see the 2026-09-03 normalization of arp_cache/dns_cache/
        # installed_hotfixes above, for the identical reason).
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                name         = $_.Name
                display_name = $_.DisplayName
                state        = $_.State
                path_name    = $_.PathName
            }
        }
        if (Write-ArtifactJson -Name 'loaded_drivers' -Data $drivers) {
            Write-CollectionLog -Category 'loaded_drivers' -Status 'ok' -Detail "$($drivers.Count) driver(s)"
        }
    } catch {
        Write-CollectionLog -Category 'loaded_drivers' -Status 'failed' -Detail $_.Exception.Message
    }
} else {
    Write-CollectionLog -Category 'loaded_drivers' -Status 'skipped' -Detail 'requires administrator privileges - not run'
}

# --- 11. PowerShell console history (PSReadLine) - real command history,
#      copied as real *_history.txt files (not parsed here) so this app's
#      existing core/powershell_history_utils.py parser reads them
#      unchanged at import time, the same "collect the real file, reuse
#      the already-built parser" pattern as Prefetch below. Always the
#      collecting account's own profile; when elevated, also sweeps every
#      OTHER real user profile on the machine, since the account running
#      this script may not be the one under investigation. Each user's
#      copy lands under its own <username>\PSReadLine\ subfolder - real,
#      unrenamed filenames preserved (ConsoleHost_history.txt etc.),
#      matching that parser's own parent-directory-name-based discovery
#      convention exactly, just with a username folder above it. ---
try {
    $psrOutDir = Join-Path $RunDir 'PSReadLine'
    $psrTargets = @(@{ user = $env:USERNAME; dir = (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine') })
    if ($IsElevated) {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') -and $_.Name -ne $env:USERNAME } |
            ForEach-Object {
                $psrTargets += @{ user = $_.Name; dir = (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine') }
            }
    }
    $psrCopied = 0
    foreach ($target in $psrTargets) {
        if (Test-Path $target.dir) {
            $files = Get-ChildItem -Path $target.dir -Filter '*_history.txt' -ErrorAction SilentlyContinue
            if ($files) {
                $destDir = Join-Path (Join-Path $psrOutDir $target.user) 'PSReadLine'
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                foreach ($f in $files) {
                    try { Copy-Item -Path $f.FullName -Destination $destDir -ErrorAction Stop; $psrCopied++ } catch { }
                }
            }
        }
    }
    if ($psrCopied -gt 0) {
        Write-CollectionLog -Category 'powershell_history' -Status 'ok' -Detail "$psrCopied file(s) copied"
    } else {
        Write-CollectionLog -Category 'powershell_history' -Status 'skipped' -Detail 'no PSReadLine history files found'
    }
} catch {
    Write-CollectionLog -Category 'powershell_history' -Status 'failed' -Detail $_.Exception.Message
}

# --- 12. Prefetch (.pf) files - real execution evidence (run counts,
#      last-run times) this app already knows how to parse. Admin-only
#      on a live system (the Prefetch folder is access-restricted), so
#      this is honestly logged as privilege-limited when skipped, the
#      same pattern as loaded_drivers above - never silently absent with
#      no explanation. Copied as real .pf files, not parsed here - this
#      app's existing core/prefetch_utils.py parser reads them unchanged
#      at import time, same as PSReadLine above. A single locked/in-use
#      file (a program actively launching right now) never aborts the
#      rest of the copy. ---
if ($IsElevated) {
    try {
        $pfSrc = Join-Path $env:WINDIR 'Prefetch'
        $pfFiles = Get-ChildItem -Path $pfSrc -Filter '*.pf' -ErrorAction Stop
        $pfCopied = 0
        if ($pfFiles) {
            $pfDest = Join-Path $RunDir 'prefetch'
            New-Item -ItemType Directory -Path $pfDest -Force | Out-Null
            foreach ($f in $pfFiles) {
                try { Copy-Item -Path $f.FullName -Destination $pfDest -ErrorAction Stop; $pfCopied++ } catch { }
            }
        }
        Write-CollectionLog -Category 'prefetch' -Status 'ok' -Detail "$pfCopied of $($pfFiles.Count) file(s) copied"
    } catch {
        Write-CollectionLog -Category 'prefetch' -Status 'failed' -Detail $_.Exception.Message
    }
} else {
    Write-CollectionLog -Category 'prefetch' -Status 'skipped' -Detail 'requires administrator privileges - not run'
}

# --- 13. Windows Event Log excerpts - exported as real, filtered .evtx
#      snapshot files (not parsed here) via wevtutil, so this app's
#      existing core/evtx_utils.py parser reads them unchanged at import
#      time, same pattern as PSReadLine/Prefetch above. Both exports are
#      bounded to the last 30 days via wevtutil's own XPath time filter -
#      a live collection prioritizes speed and a reasonably-sized
#      artifact over exhaustive history; the full log is still on the
#      machine if a deeper pull is ever needed separately. Real command/
#      query syntax confirmed live (2026-09-03) against a genuine Windows
#      machine before being written here, not assumed from documentation
#      - including a real, live-caught finding: a plain EventID=7036
#      filter also matched an unrelated driver's own reused numeric ID,
#      so the Security-log query below also requires the real, correct
#      Provider for each event (matching core/evtx_utils.py's own,
#      separately-hardened Provider check on the read side). The System
#      log (service start/stop) is readable without elevation on a
#      default configuration; the Security log (logons, workstation
#      lock/unlock, audit-log-cleared) is not, so that half is admin-
#      gated and honestly logged as privilege-limited when skipped, the
#      same pattern as loaded_drivers/Prefetch above. ---
try {
    $evtxOutDir = Join-Path $RunDir 'evtx'
    New-Item -ItemType Directory -Path $evtxOutDir -Force | Out-Null
    $evtxTimeWindowMs = 30 * 24 * 60 * 60 * 1000  # 30 days
    $sysQuery = "*[System[Provider[@Name='Service Control Manager'] and (EventID=7036) and TimeCreated[timediff(@SystemTime) <= $evtxTimeWindowMs]]]"
    $sysOut = Join-Path $evtxOutDir 'System.evtx'
    wevtutil epl System $sysOut "/q:$sysQuery" /ow:true 2>$null
    if (Test-Path $sysOut) {
        Write-CollectionLog -Category 'evtx_system' -Status 'ok'
    } else {
        Write-CollectionLog -Category 'evtx_system' -Status 'failed' -Detail 'wevtutil export produced no file'
    }
} catch {
    Write-CollectionLog -Category 'evtx_system' -Status 'failed' -Detail $_.Exception.Message
}

if ($IsElevated) {
    try {
        $evtxOutDir = Join-Path $RunDir 'evtx'
        New-Item -ItemType Directory -Path $evtxOutDir -Force | Out-Null
        $evtxTimeWindowMs = 30 * 24 * 60 * 60 * 1000
        $secQuery = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625 or EventID=4800 or EventID=4801 or EventID=1102) and TimeCreated[timediff(@SystemTime) <= $evtxTimeWindowMs]]]"
        $secOut = Join-Path $evtxOutDir 'Security.evtx'
        wevtutil epl Security $secOut "/q:$secQuery" /ow:true 2>$null
        if (Test-Path $secOut) {
            Write-CollectionLog -Category 'evtx_security' -Status 'ok'
        } else {
            Write-CollectionLog -Category 'evtx_security' -Status 'failed' -Detail 'wevtutil export produced no file'
        }
    } catch {
        Write-CollectionLog -Category 'evtx_security' -Status 'failed' -Detail $_.Exception.Message
    }
} else {
    Write-CollectionLog -Category 'evtx_security' -Status 'skipped' -Detail 'requires administrator privileges - not run'
}

# --- 14. Live registry pattern-of-life pull - real registry hive exports
#      copied while Windows is still running, via the same backup-API
#      mechanism (reg save) the Windows registry itself exposes for
#      exactly this purpose - no VSS/live-registry-provider parsing
#      needed. Output files are named to EXACTLY match this app's
#      existing REGISTRY_HIVE_FILENAMES so core/registry_utils.py's own,
#      already-built parser (RecentDocs, TypedPaths, RunMRU, UserAssist,
#      RDP connections, Office MRU, WordWheelQuery, USB device history,
#      Shimcache, BAM/DAM, installed programs, Amcache, ShellBags) reads
#      them completely unchanged at import time - the same "collect the
#      real file, reuse the already-built parser" pattern as PSReadLine/
#      Prefetch/Event Logs above.
#
#      Genuinely admin-only, unlike most of those others, and confirmed
#      live rather than assumed: reg save needs SeBackupPrivilege, which
#      even Administrators-group membership doesn't grant unless the
#      process token is ACTUALLY elevated (a standard/UAC-filtered token
#      lacks it entirely) - a non-elevated "reg save HKCU" run against
#      this very collector's own dev machine failed outright with "A
#      required privilege is not held by the client."
#
#      When elevated: pulls the collecting account's own live NTUSER.DAT
#      + UsrClass.dat (via reg save, since both are actively open/locked
#      by this very session); the machine-wide SYSTEM + SOFTWARE hives
#      (also reg save); a best-effort Amcache.hve copy (that file is
#      periodically checkpointed rather than continuously held open, so
#      a plain file copy - not reg save, it isn't a currently-loaded
#      registry key - is the correct mechanism for it); and every OTHER
#      real user profile's on-disk NTUSER.DAT/UsrClass.dat via a plain
#      file copy (works when that user isn't ALSO concurrently logged
#      in, the common case - a currently-active other session's hive may
#      still be exclusively locked and is skipped gracefully per-file,
#      the same disclosed edge-case boundary PSReadLine/Prefetch already
#      accept above rather than build brittle multi-session handling
#      for). Each user's hives land in their own <username>\ subfolder so
#      two different users' identically-named NTUSER.DAT files can never
#      collide on disk. ---
if ($IsElevated) {
    $regOutDir = Join-Path $RunDir 'registry'
    New-Item -ItemType Directory -Path $regOutDir -Force | Out-Null
    $regSaved = 0
    $regFailed = 0

    function Save-LiveHive {
        param([string]$RegKey, [string]$DestPath)
        $destDir = Split-Path -Path $DestPath -Parent
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        try {
            & reg.exe save $RegKey $DestPath /y 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $script:regSaved++ } else { $script:regFailed++ }
        } catch {
            $script:regFailed++
        }
    }

    function Copy-LiveHiveFile {
        param([string]$SourcePath, [string]$DestPath)
        if (Test-Path $SourcePath) {
            $destDir = Split-Path -Path $DestPath -Parent
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            try {
                Copy-Item -Path $SourcePath -Destination $DestPath -ErrorAction Stop
                $script:regSaved++
            } catch {
                $script:regFailed++
            }
        }
    }

    # Own account's live hives - reg save, since these are actively
    # open/locked by this very session right now.
    $ownUserDir = Join-Path $regOutDir $env:USERNAME
    Save-LiveHive -RegKey 'HKCU' -DestPath (Join-Path $ownUserDir 'NTUSER.DAT')
    Save-LiveHive -RegKey 'HKCU\Software\Classes' -DestPath (Join-Path $ownUserDir 'USRCLASS.DAT')

    # Machine-wide live hives - same reg save mechanism, gated on the
    # same elevated backup privilege this whole block already requires.
    Save-LiveHive -RegKey 'HKLM\SYSTEM' -DestPath (Join-Path $regOutDir 'SYSTEM')
    Save-LiveHive -RegKey 'HKLM\SOFTWARE' -DestPath (Join-Path $regOutDir 'SOFTWARE')

    # Amcache.hve - plain file copy, not reg save (it isn't a currently-
    # loaded registry key at all, just a periodically-flushed file).
    Copy-LiveHiveFile -SourcePath (Join-Path $env:WINDIR 'AppCompat\Programs\Amcache.hve') `
        -DestPath (Join-Path $regOutDir 'AMCACHE.HVE')

    # Every OTHER real user profile's on-disk hive files - plain file
    # copy (not reg save, since these aren't loaded under THIS process's
    # own HKCU); succeeds when that user isn't concurrently logged in.
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') -and $_.Name -ne $env:USERNAME } |
        ForEach-Object {
            $userDir = Join-Path $regOutDir $_.Name
            Copy-LiveHiveFile -SourcePath (Join-Path $_.FullName 'NTUSER.DAT') `
                -DestPath (Join-Path $userDir 'NTUSER.DAT')
            Copy-LiveHiveFile -SourcePath (Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat') `
                -DestPath (Join-Path $userDir 'USRCLASS.DAT')
        }

    if ($regSaved -gt 0) {
        $failDetail = if ($regFailed -gt 0) { ", $regFailed hive(s) failed/locked/absent" } else { "" }
        Write-CollectionLog -Category 'registry' -Status 'ok' -Detail "$regSaved hive(s) saved$failDetail"
    } else {
        Write-CollectionLog -Category 'registry' -Status 'failed' -Detail 'no hives could be saved'
    }
} else {
    Write-CollectionLog -Category 'registry' -Status 'skipped' -Detail 'requires administrator privileges - not run'
}

# --- 15. Mapped network drives ---
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

# --- 16. Clipboard contents ---
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
