<#
================================================================================
 SSDetector.ps1 - Screenshare bypass / anti-forensics detector
================================================================================

 WHAT THIS SCRIPT IS
 -------------------
 This is a READ-ONLY forensic scanner. It looks for signs that someone has
 tampered with the parts of Windows that record what a program did - the
 things a screenshare moderator would normally inspect.

 It DETECTS ONLY. It never fixes, deletes, disables, repairs or "cleans"
 anything. It cannot remove a cheat and it cannot break your machine.

 WHAT IT DOES NOT DO
 -------------------
   * It does not detect cheats. It detects tampering with forensic evidence.
   * It makes no network connections of any kind. Nothing is uploaded.
   * It does not scan memory, inject into processes, or touch your game.
   * It writes nothing to disk unless you explicitly pass -OutputPath.
   * It asks you to disable nothing. If antivirus blocks a check, that check
     is reported as 'Unavailable' rather than working around it.

 HOW TO VERIFY THAT FOR YOURSELF
 -------------------------------
 Every check below has a comment header saying exactly which files or
 registry keys it reads and confirming that it writes nothing. There is no
 obfuscation anywhere in this file: no Invoke-Expression, no -EncodedCommand,
 no base64, no assembled cmdlet names. Search the file for "Set-", "Remove-",
 "New-Item", "Stop-Service" or "Invoke-Web" and you will find no calls to any
 of them against the system.

 The single exception to "pure reading" is documented at check 12, which is
 OFF by default and only runs if you pass -IncludeSysMainCheck.

 USAGE
 -----
   .\SSDetector.ps1
   .\SSDetector.ps1 -OutputPath .\report.txt
   .\SSDetector.ps1 -IncludeSysMainCheck -Quiet

 Requires Windows PowerShell 5.1 or later, run as Administrator.

 The run ends by waiting for a keypress, so the window stays open when the
 script is double-clicked. That wait is skipped when input is redirected, so
 automation does not hang.

 EXIT CODES
 ----------
   0  no detections
   1  one or more detections
   2  the run could not complete (not elevated, or a fatal error)
================================================================================
#>

[CmdletBinding()]
param(
    # Enables check 12 (SysMain thread inspection). This is the only check that
    # uses Add-Type / inline C#, so it is opt-in and stays out of the default
    # execution path. See the big comment block at Test-SysMainSuspendedThreads.
    [switch]$IncludeSysMainCheck,

    # Optional path for a plain UTF-8 text copy of the console report.
    # If you do not pass this, the script writes nothing to disk at all.
    [string]$OutputPath,

    # Suppresses the per-check "Clean" lines in the console output.
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------------------
# Domains that matter during a screenshare. A player who has blocked these has
# blocked the moderator's ability to download tools or look things up.
# Used by checks 1 (zone map), 3 (hosts file), 13 (browser policy) and
# 15 (disallowed certificates).
# ------------------------------------------------------------------------------
$script:Watchlist = @(
    'github.com',
    'discord.com',
    'discordapp.com',
    'virustotal.com',
    'telegram.org',
    'mediafire.com',
    'mega.nz',
    'pastebin.com',
    'anonfiles',
    'gofile.io',
    'anticheat.ac',
    'detect.ac',
    'echo.ac'
)

# Used only by check 15, which matches certificate subjects and issuers.
#
# Large services are listed as bare labels because their certificates carry a
# company name rather than a hostname (CN=GitHub, Inc.). Smaller sites are
# listed as full domains, because their certificates use the domain itself and
# a bare label would be far too broad - 'echo' alone would match Echoworx and
# EchoStar, and 'detect' would match Detectify, each reported as a High
# severity finding on a completely clean machine.
#
# Rule of thumb when adding one: use a bare label only when the site is large
# enough to appear in a certificate as a company name. Otherwise use the full
# domain.
$script:WatchlistLabels = @(
    'github', 'discord', 'discordapp', 'virustotal',
    'telegram', 'mediafire', 'mega.nz', 'pastebin', 'anonfiles', 'gofile', 'echo.ac', 'anticheat.ac', 'detect.ac'
)

$script:ReportLines = New-Object System.Collections.Generic.List[string]


#===============================================================================
# SECTION A - helpers
# None of the functions in this section write to the system. They read the
# registry, format text, or build result objects in memory.
#===============================================================================

# Builds the single result shape every check returns. Pure construction, no I/O.
function New-CheckResult {
    param(
        [int]$Id,
        [string]$Name,
        [ValidateSet('Clean', 'Detected', 'Unavailable')][string]$Status,
        [ValidateSet('Info', 'Medium', 'High')][string]$Severity = 'Info',
        [string[]]$Evidence = @(),
        [string]$Detail = ''
    )
    return [PSCustomObject]@{
        Id       = $Id
        Name     = $Name
        Status   = $Status
        Severity = $Severity
        Evidence = @($Evidence)
        Detail   = $Detail
    }
}

# Replaces the current profile name with <user> so a report can be shared
# without leaking who ran it. String manipulation only.
function Get-Redacted {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $userName = $env:USERNAME
    $profilePath = $env:USERPROFILE
    if (-not [string]::IsNullOrEmpty($profilePath)) {
        $leaf = Split-Path -Path $profilePath -Leaf
        if (-not [string]::IsNullOrEmpty($leaf)) {
            $out = [System.Text.RegularExpressions.Regex]::Replace(
                $out, [regex]::Escape($leaf), '<user>',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    if (-not [string]::IsNullOrEmpty($userName)) {
        $out = [System.Text.RegularExpressions.Regex]::Replace(
            $out, [regex]::Escape($userName), '<user>',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $out
}

# Opens a registry key for reading. Returns $null when the key is absent or
# access is denied. Never creates a key: Get-Item cannot create.
function Get-RegKey {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) {
        return Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    }
    return $null
}

# Reads one registry value. Returns $null when the key or value is absent.
function Get-RegVal {
    param([string]$Path, [string]$Name)
    $key = Get-RegKey -Path $Path
    if ($null -eq $key) { return $null }
    try { return $key.GetValue($Name, $null) } catch { return $null }
}

# Lists the value names on a key. Read-only enumeration.
function Get-RegValueNames {
    param($Key)
    if ($null -eq $Key) { return @() }
    try { return @($Key.GetValueNames()) } catch { return @() }
}

# Formats a registry value for a report line, collapsing arrays.
function Format-RegData {
    param($Value)
    if ($null -eq $Value) { return '<null>' }
    if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$Value
}

# True when the given text mentions a watchlist domain.
function Test-Watchlisted {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $lower = $Text.ToLowerInvariant()
    foreach ($d in $script:Watchlist) {
        if ($lower.Contains($d)) { return $true }
    }
    return $false
}

# True when the given text mentions a watchlist organisation label. Looser than
# Test-Watchlisted; used only for certificate subject/issuer matching.
function Test-WatchlistedLabel {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $lower = $Text.ToLowerInvariant()
    foreach ($d in $script:WatchlistLabels) {
        if ($lower.Contains($d)) { return $true }
    }
    return $false
}

# Wrapper around Get-WinEvent that treats "no matching events" as an empty
# result instead of an error, but lets real problems (missing log, access
# denied) propagate so the check reports Unavailable. Reads the event log only.
function Get-EventsSafe {
    param([hashtable]$Filter, [int]$Max = 200)
    try {
        $events = Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop
        if ($null -eq $events) { return @() }
        return @($events)
    }
    catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match 'No events were found') { return @() }
        if ($_.Exception -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException]) { throw }
        throw
    }
}

# Turns an event record's EventData into a name -> value hashtable so checks can
# read named fields instead of guessing array positions. Read-only.
function Get-EventDataMap {
    # Named EventRecord rather than Event because $Event is a PowerShell
    # automatic variable used by the eventing subsystem.
    param($EventRecord)
    $map = @{}
    try {
        $xml = [xml]$EventRecord.ToXml()
        $data = $xml.Event.EventData.Data
        if ($null -ne $data) {
            foreach ($d in @($data)) {
                if ($d -and $d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
            }
        }
    }
    catch {
        # Some records carry no EventData, or carry it in a shape that will not
        # parse. An empty map is the correct answer; the caller handles it.
    }
    return $map
}

# Machine boot time, used by checks 8, 17 and 18 to scope results to this
# session. Reads WMI/CIM only.
function Get-BootTime {
    try { return (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
    catch { return $null }
}


#===============================================================================
# SECTION B - the 22 checks
# Each function reads only. Each is wrapped by the dispatcher in its own
# try/catch so a blocked or failing check reports 'Unavailable' and the run
# continues.
#===============================================================================

# ------------------------------------------------------------------------------
# CHECK 1 - Internet Options: restricted zones
#
# READS  : HKCU and HKLM  ...\Internet Settings\ZoneMap\Domains
#          HKCU and HKLM  ...\Internet Settings\ZoneMap\EscDomains
#          HKLM\SOFTWARE\Policies\...\Internet Settings\ZoneMap
# WRITES : nothing.
#
# Zone 4 is "Restricted sites". Putting github.com in zone 4 is a quiet way to
# stop a moderator downloading tools without touching the firewall.
# ------------------------------------------------------------------------------
function Test-RestrictedZones {
    $evidence = @()
    $severity = 'Medium'
    $hitWatchlist = $false

    $roots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
    )
    $containers = @('Domains', 'EscDomains')

    foreach ($root in $roots) {
        foreach ($container in $containers) {
            $basePath = Join-Path -Path $root -ChildPath $container
            $baseKey = Get-RegKey -Path $basePath
            if ($null -eq $baseKey) { continue }

            $children = @(Get-ChildItem -LiteralPath $basePath -Recurse -ErrorAction SilentlyContinue)
            foreach ($child in $children) {
                $names = Get-RegValueNames -Key $child
                foreach ($valueName in $names) {
                    if ($valueName -notin @('http', 'https', '*', 'ftp', 'file')) { continue }
                    $zone = $child.GetValue($valueName, $null)
                    if ($null -eq $zone) { continue }
                    if ([int]$zone -ne 4) { continue }

                    # Rebuild the hostname: the key layout is Domains\<domain>\<subdomain>
                    $relative = $child.Name.Substring($baseKey.Name.Length).Trim('\')
                    $parts = @($relative -split '\\' | Where-Object { $_ -ne '' })
                    [array]::Reverse($parts)
                    $domainName = ($parts -join '.')

                    $flag = ''
                    if (Test-Watchlisted -Text $domainName) { $hitWatchlist = $true; $flag = '  [WATCHLIST]' }
                    $evidence += ("{0} : {1} ({2}) = zone 4 Restricted{3}" -f $container, $domainName, $valueName, $flag)
                }
            }
        }
    }

    # A policy-locked ZoneMap means the user cannot undo this from the UI, which
    # is a stronger signal than a plain per-user entry.
    $policyLock = Get-RegVal -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -Name 'UNCAsIntranet'
    $policyKey = Get-RegKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
    if ($null -ne $policyKey) {
        $evidence += "Policy ZoneMap key present at HKLM\SOFTWARE\Policies (zone assignments are enforced by policy)"
        if ($null -ne $policyLock) { $evidence += ("  UNCAsIntranet = {0}" -f $policyLock) }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 1 -Name 'Internet Options - Restricted Zones' -Status 'Clean'
    }
    if ($hitWatchlist) { $severity = 'High' }
    return New-CheckResult -Id 1 -Name 'Internet Options - Restricted Zones' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Watchlist domain forced into the Restricted zone. Blocks browsing without touching the firewall.'
}

# ------------------------------------------------------------------------------
# CHECK 2 - Firewall.cpl restrictions
#
# READS  : HKCU\...\Policies\Explorer  DisallowCpl / RestrictCpl (+ their subkeys)
#          HKLM equivalents
#          HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall
# WRITES : nothing.
#
# Hiding firewall.cpl stops the moderator opening the firewall UI to see which
# outbound rules were added.
# ------------------------------------------------------------------------------
function Test-FirewallCplRestrictions {
    $evidence = @()
    $severity = 'Medium'

    $policyRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($root in $policyRoots) {
        foreach ($mode in @('DisallowCpl', 'RestrictCpl')) {
            $flagValue = Get-RegVal -Path $root -Name $mode
            if ($null -ne $flagValue -and [int]$flagValue -ne 0) {
                $evidence += ("{0}\{1} = {2} (control panel applet filtering is active)" -f $root, $mode, $flagValue)
            }

            $listPath = Join-Path -Path $root -ChildPath $mode
            $listKey = Get-RegKey -Path $listPath
            if ($null -eq $listKey) { continue }
            foreach ($name in (Get-RegValueNames -Key $listKey)) {
                $entry = [string]$listKey.GetValue($name, '')
                $marker = ''
                if ($entry -match 'firewall\.cpl') { $marker = '  [FIREWALL]'; $severity = 'High' }
                $evidence += ("{0}\{1} : {2} = {3}{4}" -f $root, $mode, $name, $entry, $marker)
            }
        }
    }

    # Policy values that grey out or hide the firewall UI outright.
    $fwPolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    $fwKey = Get-RegKey -Path $fwPolicyRoot
    if ($null -ne $fwKey) {
        $subKeys = @($fwPolicyRoot) + @(Get-ChildItem -LiteralPath $fwPolicyRoot -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath })
        foreach ($sk in $subKeys) {
            $k = Get-RegKey -Path $sk
            if ($null -eq $k) { continue }
            foreach ($name in (Get-RegValueNames -Key $k)) {
                if ($name -match 'DisableNotifications|DisableUnicastResponses|EnableFirewall|DoNotAllowExceptions|DisableStealthMode') {
                    $evidence += ("{0} : {1} = {2}" -f $k.Name, $name, (Format-RegData $k.GetValue($name, $null)))
                }
            }
        }
        if ($evidence.Count -eq 0) {
            $evidence += ("WindowsFirewall policy key exists at {0} but contains no UI-restricting values" -f $fwPolicyRoot)
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 2 -Name 'Firewall.cpl Restrictions' -Status 'Clean'
    }
    return New-CheckResult -Id 2 -Name 'Firewall.cpl Restrictions' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Control panel applets hidden. A firewall.cpl rule blocks review of outbound rules.'
}

# ------------------------------------------------------------------------------
# CHECK 3 - Hosts file manipulation
#
# READS  : C:\Windows\System32\drivers\etc\hosts (or the relocated path)
#          HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
# WRITES : nothing. The hosts file is opened for reading only.
#
# Mapping a domain to 0.0.0.0 blackholes it. Relocating the hosts file entirely
# means anyone inspecting the standard path sees a clean file.
# ------------------------------------------------------------------------------
function Test-HostsFile {
    $evidence = @()
    $severity = 'Medium'

    $standardDir = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc'
    $dbPath = Get-RegVal -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DataBasePath'

    $hostsDir = $standardDir
    if (-not [string]::IsNullOrEmpty($dbPath)) {
        $expanded = [Environment]::ExpandEnvironmentVariables([string]$dbPath)
        $hostsDir = $expanded
        if ($expanded.TrimEnd('\') -ne $standardDir.TrimEnd('\')) {
            $evidence += ("DataBasePath has been relocated: '{0}' (expected '{1}')" -f $expanded, $standardDir)
            $severity = 'High'
        }
    }

    $hostsPath = Join-Path -Path $hostsDir -ChildPath 'hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) {
        $evidence += ("Hosts file not found at {0}" -f $hostsPath)
        $severity = 'High'
    }
    else {
        $blackholes = @('0.0.0.0', '127.0.0.1', '::1')
        $lines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
        $lineNo = 0
        foreach ($line in $lines) {
            $lineNo++
            $trimmed = $line.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
            $fields = @($trimmed -split '\s+' | Where-Object { $_ -ne '' })
            if ($fields.Count -lt 2) { continue }
            $address = $fields[0]
            for ($i = 1; $i -lt $fields.Count; $i++) {
                $entryHost = $fields[$i]
                if ($entryHost.StartsWith('#')) { break }
                if ((Test-Watchlisted -Text $entryHost) -and ($blackholes -contains $address)) {
                    $evidence += ("line {0}: {1} -> {2}  [WATCHLIST BLACKHOLE]" -f $lineNo, $entryHost, $address)
                    $severity = 'High'
                }
            }
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 3 -Name 'Hosts File Manipulation' -Status 'Clean'
    }
    return New-CheckResult -Id 3 -Name 'Hosts File Manipulation' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Watchlist domain blackholed system-wide, native clients included. A moved DataBasePath hides the real hosts file.'
}

# ------------------------------------------------------------------------------
# CHECK 4 - Taskkill autorun
#
# READS  : Run and RunOnce under HKCU and HKLM CurrentVersion (+ Wow6432Node)
#          AutoRun under HKCU and HKLM \Software\Microsoft\Command Processor
# WRITES : nothing.
#
# An autorun that kills a process closes forensic tools the moment they start.
# Command Processor\AutoRun runs on every single cmd.exe launch and is one of
# the oldest tricks there is - any value there is worth reporting.
# ------------------------------------------------------------------------------
function Test-TaskkillAutorun {
    $evidence = @()
    $severity = 'Medium'

    $runRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion',
        'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion'
    )
    $killPatterns = 'taskkill|tskill|wmic\s+process\s+call\s+terminate'

    foreach ($root in $runRoots) {
        foreach ($runKeyName in @('Run', 'RunOnce', 'RunServices', 'RunServicesOnce')) {
            $path = Join-Path -Path $root -ChildPath $runKeyName
            $key = Get-RegKey -Path $path
            if ($null -eq $key) { continue }
            foreach ($name in (Get-RegValueNames -Key $key)) {
                $data = [string]$key.GetValue($name, '')
                if ($data -match $killPatterns) {
                    $evidence += ("{0}\{1} : {2} = {3}" -f $root, $runKeyName, $name, $data)
                    $severity = 'High'
                }
            }
        }
    }

    foreach ($cmdRoot in @('HKCU:\Software\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Command Processor')) {
        $autoRun = Get-RegVal -Path $cmdRoot -Name 'AutoRun'
        if ($null -ne $autoRun -and [string]$autoRun -ne '') {
            $evidence += ("{0}\AutoRun = {1}  (runs on every cmd.exe launch)" -f $cmdRoot, $autoRun)
            $severity = 'High'
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 4 -Name 'Taskkill Autorun' -Status 'Clean'
    }
    return New-CheckResult -Id 4 -Name 'Taskkill Autorun' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Autorun kills processes as tools open. A Command Processor AutoRun runs before every cmd session.'
}

# ------------------------------------------------------------------------------
# CHECK 5 - DisallowRun
#
# READS  : HKCU and HKLM ...\Policies\Explorer\DisallowRun (flag + list subkey)
# WRITES : nothing.
#
# DisallowRun stops named executables launching at all. A list containing
# forensic tool names is a direct attempt to block the screenshare.
# ------------------------------------------------------------------------------
function Test-DisallowRun {
    $evidence = @()

    $roots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($root in $roots) {
        $flag = Get-RegVal -Path $root -Name 'DisallowRun'
        if ($null -eq $flag) { continue }
        $evidence += ("{0}\DisallowRun = {1}" -f $root, $flag)
        if ([int]$flag -ne 1) { continue }

        $listPath = Join-Path -Path $root -ChildPath 'DisallowRun'
        $listKey = Get-RegKey -Path $listPath
        if ($null -eq $listKey) {
            $evidence += '  DisallowRun is enabled but the blocked-program list is empty or unreadable'
            continue
        }
        foreach ($name in (Get-RegValueNames -Key $listKey)) {
            $evidence += ("  blocked: {0}" -f [string]$listKey.GetValue($name, ''))
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 5 -Name 'DisallowRun' -Status 'Clean'
    }
    return New-CheckResult -Id 5 -Name 'DisallowRun' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Named executables blocked from starting, with an error that looks like ordinary policy.'
}

# ------------------------------------------------------------------------------
# CHECK 6 - Image File Execution Options (IFEO)
#
# READS  : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
#            Image File Execution Options  (+ Wow6432Node twin)
#          all direct subkeys of HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
#          the ACL on HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
# WRITES : nothing. Get-Acl reads a security descriptor, it does not set one.
#
# Four separate techniques are covered here:
#   a) Debugger hijack   - launching X silently launches Y instead
#   b) GlobalFlag        - silent process exit monitoring
#   c) Renamed IFEO key  - entries stay live but move out of the path tools read
#   d) Stripped ACL      - enumeration of the parent key is denied outright
# ------------------------------------------------------------------------------
function Test-ImageFileExecutionOptions {
    $evidence = @()
    $severity = 'Medium'

    $ifeoRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )

    # (a) and (b): Debugger and GlobalFlag values on the standard IFEO keys.
    foreach ($root in $ifeoRoots) {
        if ($null -eq (Get-RegKey -Path $root)) { continue }
        $subKeys = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)
        foreach ($sub in $subKeys) {
            $names = Get-RegValueNames -Key $sub
            if ($names -contains 'Debugger') {
                $evidence += ("Debugger hijack: {0} -> {1}" -f (Split-Path -Path $sub.Name -Leaf), $sub.GetValue('Debugger', ''))
                $severity = 'High'
            }
            if ($names -contains 'GlobalFlag') {
                $gf = $sub.GetValue('GlobalFlag', 0)
                $note = ''
                # 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT) is the bit used to
                # attach behaviour to a process exiting quietly.
                # GlobalFlag is normally a DWORD but can be stored as a string.
                # If it will not convert, report the raw value without the note.
                try { if (([int]$gf -band 0x200) -ne 0) { $note = '  [silent process exit monitor]'; $severity = 'High' } } catch { }
                $evidence += ("GlobalFlag: {0} = 0x{1:X}{2}" -f (Split-Path -Path $sub.Name -Leaf), [int]$gf, $note)
            }
        }
    }

    # (c) Renamed IFEO key. Walk every direct child of Windows NT\CurrentVersion
    # and look one level down for a Debugger value. A key that is not the
    # standard IFEO key but holds Debugger entries is deliberately hidden.
    $cvRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cvChildren = @(Get-ChildItem -LiteralPath $cvRoot -ErrorAction SilentlyContinue)
    foreach ($child in $cvChildren) {
        $leaf = Split-Path -Path $child.Name -Leaf
        if ($leaf -eq 'Image File Execution Options') { continue }
        $grandChildren = @(Get-ChildItem -LiteralPath $child.PSPath -ErrorAction SilentlyContinue)
        foreach ($gc in $grandChildren) {
            if ((Get-RegValueNames -Key $gc) -contains 'Debugger') {
                $evidence += ("Renamed IFEO key: {0} contains a Debugger entry for {1} -> {2}" -f `
                        $leaf, (Split-Path -Path $gc.Name -Leaf), $gc.GetValue('Debugger', ''))
                $severity = 'High'
            }
        }
    }

    # (d) Stripped ACL on the parent key. If Users/Everyone can no longer read
    # it, enumeration above may have been silently incomplete.
    try {
        $acl = Get-Acl -LiteralPath $cvRoot -ErrorAction Stop
        $readableByUsers = $false
        foreach ($rule in $acl.Access) {
            $identity = [string]$rule.IdentityReference
            if ($identity -notmatch '\\(Users|Everyone)$|^Everyone$') { continue }
            if ($rule.AccessControlType -eq 'Deny') {
                $evidence += ("ACL: explicit DENY for {0} on {1} ({2})" -f $identity, $cvRoot, $rule.RegistryRights)
                $severity = 'High'
            }
            elseif ($rule.RegistryRights -match 'ReadKey|FullControl|QueryValues|EnumerateSubKeys') {
                $readableByUsers = $true
            }
        }
        if (-not $readableByUsers) {
            $evidence += ("ACL: no read access for Users/Everyone on {0} - enumeration has been restricted" -f $cvRoot)
            $severity = 'High'
        }
    }
    catch {
        $evidence += ("ACL could not be read on {0}: {1}" -f $cvRoot, $_.Exception.Message)
        $severity = 'High'
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 6 -Name 'IFEO - Image File Execution Options' -Status 'Clean'
    }
    return New-CheckResult -Id 6 -Name 'IFEO - Image File Execution Options' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Launches redirected to another executable. A renamed key hides entries from standard-path tools.'
}

# ------------------------------------------------------------------------------
# CHECK 7 - WinRAR steganography
#
# READS  : HKCU\Software\WinRAR\ArcHistory
# WRITES : nothing.
#
# WinRAR will happily open an archive that has been appended to an image or text
# file. If ArcHistory shows a .png or .txt being opened as an archive, something
# was hidden inside it.
# ------------------------------------------------------------------------------
function Test-WinRarSteganography {
    $evidence = @()
    $archiveExtensions = @('.rar', '.zip', '.7z', '.tar', '.gz', '.iso', '.cab',
        '.bz2', '.xz', '.lzh', '.arj', '.z', '.001')

    $key = Get-RegKey -Path 'HKCU:\Software\WinRAR\ArcHistory'
    if ($null -eq $key) {
        return New-CheckResult -Id 7 -Name 'WinRAR Steganography' -Status 'Clean' `
            -Evidence @('No WinRAR ArcHistory key present')
    }

    foreach ($name in (Get-RegValueNames -Key $key)) {
        $path = [string]$key.GetValue($name, '')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $ext = ''
        try { $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant() } catch { $ext = '' }
        if ($ext -eq '') {
            $evidence += ("{0} : {1}  [no extension]" -f $name, $path)
            continue
        }
        if ($archiveExtensions -notcontains $ext) {
            $evidence += ("{0} : {1}  [{2} opened as an archive]" -f $name, $path, $ext)
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 7 -Name 'WinRAR Steganography' -Status 'Clean'
    }
    return New-CheckResult -Id 7 -Name 'WinRAR Steganography' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'A non-archive file was opened as an archive - payload appended to an image or text file.'
}

# ------------------------------------------------------------------------------
# CHECK 8 - NTFS journal deletion
#
# READS  : Microsoft-Windows-Ntfs/Operational and Security event logs (IDs 3079, 501)
#          output of 'fsutil usn queryjournal C:'
# WRITES : nothing. 'queryjournal' is the read-only fsutil verb; the deleting
#          verb is 'deletejournal' and is not used anywhere in this file.
#
# The USN journal records every file change on the volume. Deleting and
# recreating it erases the record of files that were created and removed.
# ------------------------------------------------------------------------------
function Test-NtfsJournalDeletion {
    $evidence = @()
    $severity = 'Medium'
    $bootTime = Get-BootTime

    # Event side. SearchIndexer legitimately triggers journal events at boot, so
    # those are filtered out to stop this check crying wolf on every machine.
    $logs = @(
        @{ LogName = 'Microsoft-Windows-Ntfs/Operational'; Id = @(3079, 501) },
        @{ LogName = 'Security'; Id = @(3079, 501) }
    )
    foreach ($spec in $logs) {
        try {
            $events = Get-EventsSafe -Filter @{ LogName = $spec.LogName; Id = $spec.Id } -Max 100
        }
        catch {
            $evidence += ("Could not read {0}: {1}" -f $spec.LogName, $_.Exception.Message)
            continue
        }
        foreach ($e in $events) {
            $message = ''
            # Message rendering needs the provider's manifest, which may be
            # absent. The event still counts; it is just reported without text.
            try { $message = [string]$e.Message } catch { }
            if ($message -match 'SearchIndexer|Windows Search|MsMpEng') { continue }
            if ($null -ne $bootTime -and $e.TimeCreated -lt $bootTime.AddSeconds(120) -and $e.TimeCreated -ge $bootTime) {
                # Boot-window journal activity from system services is normal.
                continue
            }
            $summary = $message
            if ($summary.Length -gt 160) { $summary = $summary.Substring(0, 160) + '...' }
            $evidence += ("{0} Event {1} @ {2}: {3}" -f $spec.LogName, $e.Id, $e.TimeCreated, ($summary -replace '\s+', ' '))
            $severity = 'High'
        }
    }

    # Journal side. A journal whose ID timestamp is newer than the last boot was
    # recreated during this session, which is the signature of a deletion.
    try {
        # fsutil writes to stderr when the journal is absent. Under the script's
        # default 'Stop' preference that would be a terminating error, and the
        # absence of a journal is exactly what this check wants to report, so the
        # preference is relaxed here. This assignment is local to the function.
        $ErrorActionPreference = 'Continue'
        $fsutil = & "$env:SystemRoot\System32\fsutil.exe" usn queryjournal C: 2>&1
        $fsutilText = ($fsutil | Out-String)
        if ($LASTEXITCODE -ne 0 -or $fsutilText -match 'not active|not found|Error') {
            $evidence += ("fsutil usn queryjournal C: reports no active journal: {0}" -f ($fsutilText.Trim() -replace '\s+', ' '))
            $severity = 'High'
        }
        else {
            $journalId = $null
            $lowestValid = $null
            $firstUsn = $null
            foreach ($line in ($fsutilText -split "`r?`n")) {
                if ($line -match 'Journal ID\s*:\s*(\S+)') { $journalId = $matches[1] }
                elseif ($line -match 'Lowest Valid Usn\s*:\s*(\S+)') { $lowestValid = $matches[1] }
                elseif ($line -match 'First Usn\s*:\s*(\S+)') { $firstUsn = $matches[1] }
            }
            $evidence += ("Journal ID = {0}, First Usn = {1}, Lowest Valid Usn = {2}" -f $journalId, $firstUsn, $lowestValid)

            # The journal ID is a FILETIME recording when the journal was created.
            if (-not [string]::IsNullOrEmpty($journalId)) {
                try {
                    $raw = $journalId -replace '^0x', ''
                    $ticks = [Convert]::ToInt64($raw, 16)
                    $created = [DateTime]::FromFileTime($ticks)
                    if ($created -gt (Get-Date).AddYears(-30) -and $created -lt (Get-Date).AddYears(1)) {
                        $evidence += ("Journal created: {0}" -f $created)
                        if ($null -ne $bootTime -and $created -gt $bootTime) {
                            $evidence += '  Journal was created AFTER the last boot - consistent with a delete and recreate this session'
                            $severity = 'High'
                        }
                    }
                }
                catch {
                    # The journal ID is not always a valid FILETIME. If it will
                    # not convert, skip the creation-time inference and rely on
                    # the USN values below.
                }
            }

            if ($firstUsn -eq '0x0' -or $lowestValid -eq '0x0') {
                $evidence += '  First/Lowest Valid Usn is zero - the journal holds no prior history'
                $severity = 'High'
            }
        }
    }
    catch {
        $evidence += ("fsutil could not be run: {0}" -f $_.Exception.Message)
    }

    $hasFinding = $false
    foreach ($line in $evidence) {
        if ($line -match 'AFTER the last boot|no active journal|no prior history|Event 3079|Event 501') { $hasFinding = $true }
    }
    if (-not $hasFinding) {
        return New-CheckResult -Id 8 -Name 'NTFS Journal Deletion' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 8 -Name 'NTFS Journal Deletion' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'The volume-wide file create/delete record was destroyed, erasing the trail of a client written then removed.'
}

# ------------------------------------------------------------------------------
# CHECK 9 - FileInfo filter
#
# READS  : System event log (ID 1, filter unload)
#          output of 'fltmc filters'
#          the FileInfo service state via the registry and Get-Service
# WRITES : nothing. 'fltmc filters' lists loaded filters; the loading and
#          unloading verbs are 'fltmc load' / 'fltmc unload' and are not used.
#
# FileInfo is the kernel minifilter that feeds SuperFetch/prefetch. Unloading it
# stops execution traces being recorded while everything still looks normal.
# ------------------------------------------------------------------------------
function Test-FileInfoFilter {
    $evidence = @()
    $severity = 'Medium'
    $detected = $false

    try {
        $events = Get-EventsSafe -Filter @{ LogName = 'System'; Id = 1; ProviderName = 'Microsoft-Windows-FilterManager' } -Max 50
        foreach ($e in $events) {
            $message = ''
            # Message rendering needs the provider's manifest, which may be
            # absent. The event still counts; it is just reported without text.
            try { $message = [string]$e.Message } catch { }
            if ($message -match 'FileInfo') {
                $evidence += ("System Event 1 @ {0}: {1}" -f $e.TimeCreated, ($message -replace '\s+', ' '))
                $detected = $true
                $severity = 'High'
            }
        }
    }
    catch {
        $evidence += ("Could not query FilterManager events: {0}" -f $_.Exception.Message)
    }

    try {
        # Same reasoning as check 8: relax the error preference around the native
        # command so stderr output is captured rather than thrown. Function-local.
        $ErrorActionPreference = 'Continue'
        $fltmc = & "$env:SystemRoot\System32\fltmc.exe" filters 2>&1
        $fltmcText = ($fltmc | Out-String)
        # Only trust an absence when fltmc actually produced a filter listing.
        # If it was blocked or returned an error, "FileInfo is missing" would be
        # a statement about the check failing, not about the machine.
        $listingLooksValid = ($fltmcText -match '(?im)^\s*Filter\s+Name' -or $fltmcText -match '(?im)^\s*\S+\s+\d+\s+\d+')

        if ($fltmcText -match '(?im)^\s*FileInfo\b') {
            $evidence += 'fltmc: FileInfo minifilter is loaded'
        }
        elseif (-not $listingLooksValid) {
            $evidence += ("fltmc did not return a readable filter listing, so its absence proves nothing: {0}" -f ($fltmcText.Trim() -replace '\s+', ' '))
        }
        else {
            $evidence += 'fltmc: FileInfo minifilter is NOT in the loaded filter list'
            $detected = $true
            $severity = 'High'
        }
    }
    catch {
        $evidence += ("fltmc could not be run: {0}" -f $_.Exception.Message)
    }

    try {
        $startValue = Get-RegVal -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\FileInfo' -Name 'Start'
        if ($null -eq $startValue) {
            $evidence += 'FileInfo service key not found under CurrentControlSet\Services'
            $detected = $true
            $severity = 'High'
        }
        else {
            # 0 = boot, 1 = system, 2 = auto, 3 = manual, 4 = disabled
            $evidence += ("FileInfo service Start = {0}{1}" -f $startValue, $(if ([int]$startValue -eq 4) { '  [DISABLED]' } else { '' }))
            if ([int]$startValue -eq 4) { $detected = $true; $severity = 'High' }
        }
    }
    catch {
        $evidence += ("FileInfo service state could not be read: {0}" -f $_.Exception.Message)
    }

    if (-not $detected) {
        return New-CheckResult -Id 9 -Name 'FileInfo Filter' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 9 -Name 'FileInfo Filter' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'The minifilter behind prefetch and SuperFetch is unloaded or disabled. Programs run leaving no execution traces.'
}

# ------------------------------------------------------------------------------
# CHECK 10 - Prefetch: read-only .pf files
#
# READS  : the file listing and attributes of C:\Windows\Prefetch\*.pf
# WRITES : nothing. Only file metadata is read; no .pf file is opened, changed
#          or deleted.
#
# Marking a .pf file read-only stops Windows updating it, freezing the run count
# and last-run timestamp at whatever they were.
# ------------------------------------------------------------------------------
function Test-PrefetchReadOnly {
    $evidence = @()
    $severity = 'Medium'
    $detected = $false

    $prefetchDir = Join-Path -Path $env:SystemRoot -ChildPath 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetchDir)) {
        return New-CheckResult -Id 10 -Name 'Prefetch - Read-Only .pf Files' -Status 'Detected' `
            -Severity 'High' -Evidence @("Prefetch folder not found at $prefetchDir") `
            -Detail 'Prefetch folder missing entirely - no execution history to inspect.'
    }

    $files = @(Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -Force -ErrorAction SilentlyContinue)
    $evidence += ("Total .pf files: {0}" -f $files.Count)

    if ($files.Count -eq 0) {
        $evidence += 'Prefetch folder is empty - all execution history has been removed'
        $detected = $true
        $severity = 'High'
    }
    else {
        $newest = ($files | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1)
        $evidence += ("Newest .pf: {0} @ {1}" -f $newest.Name, $newest.LastWriteTime)

        $bootTime = Get-BootTime
        if ($null -ne $bootTime -and $newest.LastWriteTime -lt $bootTime) {
            $evidence += '  Newest prefetch entry predates the last boot - nothing has been recorded this session'
            $detected = $true
            $severity = 'High'
        }

        foreach ($f in $files) {
            if (($f.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                $evidence += ("READ-ONLY: {0} (last write {1})" -f $f.Name, $f.LastWriteTime)
                $detected = $true
                $severity = 'High'
            }
        }
    }

    if (-not $detected) {
        return New-CheckResult -Id 10 -Name 'Prefetch - Read-Only .pf Files' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 10 -Name 'Prefetch - Read-Only .pf Files' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Read-only .pf files freeze run counts; an empty or stale folder means no execution history.'
}

# ------------------------------------------------------------------------------
# CHECK 11 - Prefetch parameters
#
# READS  : HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\
#            Memory Management\PrefetchParameters
# WRITES : nothing.
#
# EnablePrefetcher must be 3 for application prefetch files to be generated.
# 0 or 1 means new .pf files are never written.
# ------------------------------------------------------------------------------
function Test-PrefetchParameters {
    $evidence = @()
    $detected = $false
    $severity = 'Medium'

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
    $enablePrefetcher = Get-RegVal -Path $path -Name 'EnablePrefetcher'
    $enableSuperfetch = Get-RegVal -Path $path -Name 'EnableSuperfetch'

    if ($null -eq $enablePrefetcher) {
        $evidence += 'EnablePrefetcher value is missing (expected 3)'
        $detected = $true
        $severity = 'High'
    }
    else {
        $meaning = switch ([int]$enablePrefetcher) {
            0 { 'disabled - no prefetch files are generated' }
            1 { 'application prefetch only partially enabled (boot prefetch off)' }
            2 { 'boot prefetch only - application prefetch files are NOT generated' }
            3 { 'application and boot prefetch enabled (expected)' }
            default { 'unrecognised value' }
        }
        $evidence += ("EnablePrefetcher = {0} ({1})" -f $enablePrefetcher, $meaning)
        if ([int]$enablePrefetcher -ne 3) { $detected = $true; $severity = 'High' }
    }

    if ($null -ne $enableSuperfetch) {
        $evidence += ("EnableSuperfetch = {0}" -f $enableSuperfetch)
        if ([int]$enableSuperfetch -eq 0) { $evidence += '  SuperFetch is disabled' }
    }

    if (-not $detected) {
        return New-CheckResult -Id 11 -Name 'Prefetch Parameters' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 11 -Name 'Prefetch Parameters' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'EnablePrefetcher is not 3, so Windows writes no application prefetch files.'
}

# ------------------------------------------------------------------------------
# CHECK 12 - SysMain: suspended sechost.dll threads   [OPT-IN, -IncludeSysMainCheck]
#
# READS  : Win32_Service (to find the SysMain host PID)
#          the module list of that process
#          the thread list of that process, via CreateToolhelp32Snapshot
#          each thread's Win32 start address and suspend count, via
#          NtQueryInformationThread
# WRITES : nothing. See the note on suspend counts below.
#
# WHY THIS IS OPT-IN
# ------------------
# This is the only check that needs Add-Type and inline C#. Compiling C# at
# runtime is a legitimate thing to do, but it is also something a reader should
# consciously agree to, so it is off unless -IncludeSysMainCheck is passed. When
# the switch is absent the check returns 'Unavailable' and no C# is compiled.
#
# WHAT IT LOOKS FOR
# -----------------
# SysMain (SuperFetch) is the service that records which programs ran. Stopping
# the service is obvious. Suspending the individual threads inside it that do
# the recording is not: the service still shows as Running, but it records
# nothing. Those threads start inside sechost.dll, which is the DLL that hosts
# service worker routines.
#
# A thread with a non-zero suspend count whose start address falls inside
# sechost.dll is therefore the signature of the technique.
#
# ON READ-ONLINESS
# ----------------
# The common way to read a suspend count is to call SuspendThread (which returns
# the previous count) and then ResumeThread. That briefly changes the state of
# another process's thread, which would break this tool's read-only promise.
#
# This implementation does NOT do that. It calls NtQueryInformationThread with
# ThreadSuspendCount (class 35), which reads the count without altering it.
# SuspendThread and ResumeThread are not declared, imported or called anywhere
# in this file. If the query is unsupported on this build of Windows, the check
# reports that it could not read suspend counts rather than falling back to the
# invasive method.
# ------------------------------------------------------------------------------
function Test-SysMainSuspendedThreads {
    param([switch]$Enabled)

    $evidence = @()

    # The cheap half runs regardless: is SysMain even running?
    $serviceProcessId = 0
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='SysMain'" -ErrorAction Stop
        if ($null -eq $svc) {
            $evidence += 'SysMain service not found on this machine'
        }
        else {
            $evidence += ("SysMain service: State={0}, StartMode={1}, PID={2}" -f $svc.State, $svc.StartMode, $svc.ProcessId)
            $serviceProcessId = [int]$svc.ProcessId
        }
    }
    catch {
        $evidence += ("SysMain service state could not be read: {0}" -f $_.Exception.Message)
    }

    if (-not $Enabled) {
        $evidence += 'Thread inspection was not run. Pass -IncludeSysMainCheck to enable it.'
        return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Unavailable' `
            -Evidence $evidence `
            -Detail 'Opt-in: the only check that compiles inline C#. The service state above was still read.'
    }

    if ($serviceProcessId -le 0) {
        $evidence += 'SysMain is not running, so it has no threads to inspect.'
        return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Detected' `
            -Severity 'High' -Evidence $evidence `
            -Detail 'SysMain is not running, so nothing is recording execution history.'
    }

    # --- inline C# --------------------------------------------------------
    # Only the four read-only APIs needed are imported:
    #   CreateToolhelp32Snapshot / Thread32First / Thread32Next  - list threads
    #   OpenThread                                               - get a handle
    #   NtQueryInformationThread                                 - read start
    #                                                              address and
    #                                                              suspend count
    # Nothing here writes to another process. There is no WriteProcessMemory,
    # no CreateRemoteThread, no SuspendThread and no ResumeThread.
    if (-not ('SSDetector.ThreadProbe' -as [type])) {
        $cSharp = @'
using System;
using System.Runtime.InteropServices;

namespace SSDetector {

    // Layout must match THREADENTRY32 from tlhelp32.h exactly.
    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32 {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int  tpBasePri;
        public int  tpDeltaPri;
        public uint dwFlags;
    }

    public static class ThreadProbe {

        private const uint TH32CS_SNAPTHREAD        = 0x00000004;
        private const uint THREAD_QUERY_INFORMATION = 0x00000040;

        // THREADINFOCLASS values used, both read-only queries:
        //   9  = ThreadQuerySetWin32StartAddress (read side)
        //   35 = ThreadSuspendCount
        private const int ThreadQuerySetWin32StartAddress = 9;
        private const int ThreadSuspendCount              = 35;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(
            IntPtr threadHandle, int threadInformationClass,
            IntPtr threadInformation, int threadInformationLength, IntPtr returnLength);

        // One row per thread in the target process.
        public class ThreadInfo {
            public uint   ThreadId;
            public long   StartAddress;
            public int    SuspendCount;
            public bool   SuspendCountKnown;
            public bool   StartAddressKnown;
            public string Error;
        }

        public static ThreadInfo[] GetThreads(uint processId) {
            System.Collections.Generic.List<ThreadInfo> results =
                new System.Collections.Generic.List<ThreadInfo>();

            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) {
                throw new InvalidOperationException(
                    "CreateToolhelp32Snapshot failed, error " + Marshal.GetLastWin32Error());
            }

            try {
                THREADENTRY32 entry = new THREADENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

                if (!Thread32First(snapshot, ref entry)) { return results.ToArray(); }

                do {
                    if (entry.th32OwnerProcessID != processId) { continue; }

                    ThreadInfo info = new ThreadInfo();
                    info.ThreadId = entry.th32ThreadID;

                    IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID);
                    if (hThread == IntPtr.Zero) {
                        info.Error = "OpenThread failed, error " + Marshal.GetLastWin32Error();
                        results.Add(info);
                        continue;
                    }

                    try {
                        // Read the thread's Win32 start address.
                        IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
                        try {
                            int status = NtQueryInformationThread(
                                hThread, ThreadQuerySetWin32StartAddress, buffer, IntPtr.Size, IntPtr.Zero);
                            if (status == 0) {
                                info.StartAddress = Marshal.ReadIntPtr(buffer).ToInt64();
                                info.StartAddressKnown = true;
                            }
                        } finally {
                            Marshal.FreeHGlobal(buffer);
                        }

                        // Read the suspend count without changing it.
                        IntPtr countBuffer = Marshal.AllocHGlobal(4);
                        try {
                            int status = NtQueryInformationThread(
                                hThread, ThreadSuspendCount, countBuffer, 4, IntPtr.Zero);
                            if (status == 0) {
                                info.SuspendCount = Marshal.ReadInt32(countBuffer);
                                info.SuspendCountKnown = true;
                            } else {
                                info.Error = "ThreadSuspendCount query returned status 0x"
                                           + status.ToString("X8");
                            }
                        } finally {
                            Marshal.FreeHGlobal(countBuffer);
                        }
                    } finally {
                        CloseHandle(hThread);
                    }

                    results.Add(info);
                } while (Thread32Next(snapshot, ref entry));
            } finally {
                CloseHandle(snapshot);
            }

            return results.ToArray();
        }
    }
}
'@
        Add-Type -TypeDefinition $cSharp -Language CSharp -ErrorAction Stop | Out-Null
    }

    # Work out where sechost.dll sits in the target process so a start address
    # can be attributed to it.
    $sechostStart = 0
    $sechostEnd = 0
    try {
        $proc = Get-Process -Id $serviceProcessId -ErrorAction Stop
        foreach ($module in $proc.Modules) {
            if ($module.ModuleName -ieq 'sechost.dll') {
                $sechostStart = $module.BaseAddress.ToInt64()
                $sechostEnd = $sechostStart + $module.ModuleMemorySize
                break
            }
        }
    }
    catch {
        $evidence += ("Module list of PID {0} could not be read: {1}" -f $serviceProcessId, $_.Exception.Message)
    }

    if ($sechostStart -eq 0) {
        $evidence += 'sechost.dll was not found in the SysMain host process, so start addresses cannot be attributed to it.'
        return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Unavailable' `
            -Evidence $evidence `
            -Detail 'sechost.dll range could not be established - usually architecture or permissions, not tampering.'
    }

    $evidence += ("sechost.dll in PID {0}: 0x{1:X} - 0x{2:X}" -f $serviceProcessId, $sechostStart, $sechostEnd)

    $threads = @([SSDetector.ThreadProbe]::GetThreads([uint32]$serviceProcessId))
    $evidence += ("Threads in PID {0}: {1}" -f $serviceProcessId, $threads.Count)

    $suspended = @()
    $unreadable = 0
    foreach ($t in $threads) {
        if (-not $t.SuspendCountKnown) { $unreadable++ }
        if (-not $t.StartAddressKnown) { continue }
        $inSechost = ($t.StartAddress -ge $sechostStart -and $t.StartAddress -lt $sechostEnd)
        if ($inSechost -and $t.SuspendCountKnown -and $t.SuspendCount -gt 0) {
            $suspended += $t
            $evidence += ("SUSPENDED: TID {0}, start 0x{1:X} (sechost.dll), suspend count {2}" -f `
                    $t.ThreadId, $t.StartAddress, $t.SuspendCount)
        }
    }

    if ($unreadable -gt 0) {
        $evidence += ("Suspend count could not be read for {0} of {1} threads" -f $unreadable, $threads.Count)
    }

    if ($suspended.Count -eq 0) {
        if ($unreadable -eq $threads.Count -and $threads.Count -gt 0) {
            return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Unavailable' `
                -Evidence $evidence `
                -Detail 'No suspend count could be read, so a clean result here proves nothing.'
        }
        return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Clean' -Evidence $evidence
    }

    return New-CheckResult -Id 12 -Name 'SysMain - sechost.dll Suspended Threads' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'sechost.dll threads suspended: SysMain reports Running while recording nothing.'
}

# ------------------------------------------------------------------------------
# CHECK 13 - Browser URL blocklist policy
#
# READS  : URLBlocklist / URLAllowlist under the Chrome, Edge, Brave and Vivaldi
#          policy keys in HKLM and HKCU
# WRITES : nothing.
#
# A '*' in URLBlocklist puts the browser into allowlist-only mode: everything is
# blocked except a short list, which stops any research mid-screenshare.
# ------------------------------------------------------------------------------
function Test-UrlBlocklist {
    $evidence = @()
    $severity = 'Medium'
    $detected = $false

    $browserPolicyRoots = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome',
        'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
        'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave',
        'HKCU:\SOFTWARE\Policies\BraveSoftware\Brave',
        'HKLM:\SOFTWARE\Policies\Vivaldi',
        'HKCU:\SOFTWARE\Policies\Vivaldi'
    )

    foreach ($root in $browserPolicyRoots) {
        foreach ($listName in @('URLBlocklist', 'URLAllowlist', 'URLBlacklist', 'URLWhitelist')) {
            $entries = @()

            # The policy can be a subkey of numbered values, or a multi-string.
            $listKey = Get-RegKey -Path (Join-Path -Path $root -ChildPath $listName)
            if ($null -ne $listKey) {
                foreach ($n in (Get-RegValueNames -Key $listKey)) {
                    $entries += [string]$listKey.GetValue($n, '')
                }
            }
            $direct = Get-RegVal -Path $root -Name $listName
            if ($null -ne $direct) {
                foreach ($d in @($direct)) { $entries += [string]$d }
            }

            foreach ($entry in $entries) {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                $marker = ''
                if ($listName -match 'Blocklist|Blacklist') {
                    if ($entry.Trim() -eq '*') {
                        $marker = '  [ALLOWLIST-ONLY MODE - everything is blocked by default]'
                        $severity = 'High'
                        $detected = $true
                    }
                    elseif (Test-Watchlisted -Text $entry) {
                        $marker = '  [WATCHLIST]'
                        $severity = 'High'
                        $detected = $true
                    }
                    else { $detected = $true }
                }
                $evidence += ("{0}\{1} : {2}{3}" -f $root, $listName, $entry, $marker)
            }
        }
    }

    if (-not $detected) {
        return New-CheckResult -Id 13 -Name 'URL Blocklist' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 13 -Name 'URL Blocklist' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Browser-enforced block, with no firewall or hosts entry to find. "*" means allowlist-only. Browsers only - see check 3.'
}

# ------------------------------------------------------------------------------
# CHECK 14 - CMD colour bypass
#
# READS  : HKCU\Console  ScreenColors / DefaultColor, and every per-title subkey
# WRITES : nothing.
#
# The colour byte packs background in the high nibble and foreground in the low
# nibble. Setting both the same renders console text invisible, so a command run
# during a screenshare produces output nobody can read.
# ------------------------------------------------------------------------------
function Test-CmdColorBypass {
    $evidence = @()

    function Test-ColorValue {
        param([string]$Where, [string]$Name, $Value)
        if ($null -eq $Value) { return $null }
        $int = 0
        try { $int = [int]$Value } catch { return $null }
        $background = ($int -shr 4) -band 0xF
        $foreground = $int -band 0xF
        if ($background -eq $foreground) {
            return ("{0} : {1} = 0x{2:X2} (background {3} = foreground {4} - text is invisible)" -f `
                    $Where, $Name, $int, $background, $foreground)
        }
        return $null
    }

    foreach ($valueName in @('ScreenColors', 'DefaultColor', 'PopupColors')) {
        $hit = Test-ColorValue -Where 'HKCU\Console' -Name $valueName -Value (Get-RegVal -Path 'HKCU:\Console' -Name $valueName)
        if ($null -ne $hit) { $evidence += $hit }
    }

    $consoleKey = Get-RegKey -Path 'HKCU:\Console'
    if ($null -ne $consoleKey) {
        foreach ($sub in @(Get-ChildItem -LiteralPath 'HKCU:\Console' -ErrorAction SilentlyContinue)) {
            $title = Split-Path -Path $sub.Name -Leaf
            foreach ($valueName in @('ScreenColors', 'DefaultColor', 'PopupColors')) {
                $hit = Test-ColorValue -Where ("HKCU\Console\{0}" -f $title) -Name $valueName -Value $sub.GetValue($valueName, $null)
                if ($null -ne $hit) { $evidence += $hit }
            }
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 14 -Name 'CMD Color Bypass' -Status 'Clean'
    }
    return New-CheckResult -Id 14 -Name 'CMD Color Bypass' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Console foreground and background set identical - command output is invisible on screen.'
}

# ------------------------------------------------------------------------------
# CHECK 15 - Disallowed certificates
#
# READS  : Cert:\LocalMachine\Disallowed and Cert:\CurrentUser\Disallowed
# WRITES : nothing. The store is enumerated; no certificate is added or removed.
#
# Putting a site's issuing certificate in the Disallowed (untrusted) store makes
# HTTPS to that site fail with a certificate error, which looks like a network
# problem rather than deliberate blocking.
# ------------------------------------------------------------------------------
function Test-DisallowedCertificates {
    $evidence = @()

    foreach ($storePath in @('Cert:\LocalMachine\Disallowed', 'Cert:\CurrentUser\Disallowed')) {
        if (-not (Test-Path -LiteralPath $storePath -ErrorAction SilentlyContinue)) { continue }
        $certs = @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)
        foreach ($cert in $certs) {
            $subject = [string]$cert.Subject
            $issuer = [string]$cert.Issuer
            if ((Test-WatchlistedLabel -Text $subject) -or (Test-WatchlistedLabel -Text $issuer)) {
                $evidence += ("{0}`n    Thumbprint : {1}`n    Subject    : {2}`n    Issuer     : {3}`n    NotAfter   : {4}" -f `
                        $storePath, $cert.Thumbprint, $subject, $issuer, $cert.NotAfter)
            }
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 15 -Name 'Disallowed Certificates' -Status 'Clean'
    }
    return New-CheckResult -Id 15 -Name 'Disallowed Certificates' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Watchlist certificate placed in the Untrusted store. HTTPS then fails looking like a network error.'
}

# ------------------------------------------------------------------------------
# CHECK 16 - Group policy restrictions
#
# READS  : the policy values listed in the table below, under both HKCU and HKLM
# WRITES : nothing.
#
# Each of these disables a tool a moderator would reach for. They are reported
# individually so the report says exactly what was locked down.
# ------------------------------------------------------------------------------
function Test-GroupPolicyRestrictions {
    $evidence = @()
    $severity = 'Medium'
    $detected = $false

    # value name, HKCU path, description
    $policies = @(
        @{ Name = 'DisableCMD'; Paths = @('HKCU:\Software\Policies\Microsoft\Windows\System', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'); Desc = 'Command Prompt disabled' },
        @{ Name = 'DisableRegistryTools'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'); Desc = 'Registry Editor disabled' },
        @{ Name = 'DisableTaskMgr'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'); Desc = 'Task Manager disabled' },
        @{ Name = 'NoControlPanel'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'); Desc = 'Control Panel and Settings blocked' },
        @{ Name = 'NoRun'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'); Desc = 'Run dialog removed' },
        @{ Name = 'NoFind'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'); Desc = 'Search removed' },
        @{ Name = 'NoFolderOptions'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'); Desc = 'Folder Options removed (hidden files cannot be revealed)' },
        @{ Name = 'NoDispCPL'; Paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'); Desc = 'Display settings blocked' },
        @{ Name = 'ExecutionPolicy'; Paths = @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'); Desc = 'PowerShell execution policy set by policy' },
        @{ Name = 'EnableScripts'; Paths = @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'); Desc = 'PowerShell script execution toggle' }
    )

    foreach ($policy in $policies) {
        foreach ($path in $policy.Paths) {
            $value = Get-RegVal -Path $path -Name $policy.Name
            if ($null -eq $value) { continue }

            $isRestrictive = $false
            if ($policy.Name -eq 'ExecutionPolicy') {
                if ([string]$value -match 'Restricted|AllSigned') { $isRestrictive = $true }
            }
            elseif ($policy.Name -eq 'EnableScripts') {
                # Policy values are occasionally stored as strings. A value that
                # will not convert is reported verbatim rather than judged.
                try { if ([int]$value -eq 0) { $isRestrictive = $true } } catch { }
            }
            else {
                # Same reasoning as above.
                try { if ([int]$value -ne 0) { $isRestrictive = $true } } catch { }
            }

            $marker = ''
            if ($isRestrictive) { $marker = '  [RESTRICTIVE]'; $detected = $true; $severity = 'High' }
            $evidence += ("{0}\{1} = {2}  ({3}){4}" -f $path, $policy.Name, (Format-RegData $value), $policy.Desc, $marker)
        }
    }

    if (-not $detected) {
        if ($evidence.Count -eq 0) {
            return New-CheckResult -Id 16 -Name 'Group Policy Restrictions' -Status 'Clean'
        }
        return New-CheckResult -Id 16 -Name 'Group Policy Restrictions' -Status 'Clean' -Evidence $evidence
    }

    return New-CheckResult -Id 16 -Name 'Group Policy Restrictions' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Screenshare tools disabled by policy. A Restricted ExecutionPolicy here was set after this ran, or is scoped elsewhere.'
}

# ------------------------------------------------------------------------------
# CHECK 17 - System time changes
#
# READS  : Security event log, ID 4616
# WRITES : nothing.
#
# Moving the clock backwards and then forwards again puts file timestamps out of
# order, which breaks a timeline reconstruction. Small adjustments are ordinary
# NTP synchronisation and are filtered out so they do not bury the real finding.
# ------------------------------------------------------------------------------
function Test-SystemTimeChanges {
    $evidence = @()
    $bootTime = Get-BootTime

    $events = Get-EventsSafe -Filter @{ LogName = 'Security'; Id = 4616 } -Max 200
    foreach ($e in $events) {
        $data = Get-EventDataMap -EventRecord $e
        $processName = ''
        if ($data.ContainsKey('ProcessName')) { $processName = $data['ProcessName'] }
        $subject = ''
        if ($data.ContainsKey('SubjectUserName')) { $subject = $data['SubjectUserName'] }

        $previous = $null
        $new = $null
        # If either timestamp will not parse, the delta stays unknown and the
        # event is reported rather than filtered out - failing open is correct
        # here, because silently dropping a clock change would hide a finding.
        try { if ($data.ContainsKey('PreviousTime')) { $previous = [datetime]::Parse($data['PreviousTime'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { }
        try { if ($data.ContainsKey('NewTime')) { $new = [datetime]::Parse($data['NewTime'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { }

        # Filter 1: adjustments of 30 seconds or less are routine NTP drift.
        if ($null -ne $previous -and $null -ne $new) {
            $deltaSeconds = [Math]::Abs(($new - $previous).TotalSeconds)
            if ($deltaSeconds -le 30) { continue }
        }
        else {
            $deltaSeconds = -1
        }

        # Filter 2: the time service and system accounts correcting the clock in
        # the first two minutes after boot is normal behaviour.
        if ($processName -match 'w32tm\.exe|svchost\.exe' -and $null -ne $bootTime -and
            $e.TimeCreated -ge $bootTime -and $e.TimeCreated -lt $bootTime.AddSeconds(120)) {
            continue
        }

        $deltaText = 'unknown'
        if ($deltaSeconds -ge 0) { $deltaText = ("{0:N0}s" -f $deltaSeconds) }
        $evidence += ("{0}  old={1}  new={2}  delta={3}  process={4}  subject={5}" -f `
                $e.TimeCreated, $data['PreviousTime'], $data['NewTime'], $deltaText, $processName, $subject)
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 17 -Name 'System Time Changes' -Status 'Clean' `
            -Evidence @('No clock adjustments over 30 seconds outside routine time-service activity')
    }
    return New-CheckResult -Id 17 -Name 'System Time Changes' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Clock moved beyond NTP drift. Rolling it back then forward puts file and log timestamps out of sequence.'
}

# ------------------------------------------------------------------------------
# CHECK 18 - Event log cleared
#
# READS  : Security event log ID 1102, System event log ID 104
#          Win32_OperatingSystem LastBootUpTime (to scope to this session)
# WRITES : nothing.
#
# Clearing a log is itself logged. Any clear since the last boot is a finding.
# ------------------------------------------------------------------------------
function Test-EventLogCleared {
    $evidence = @()
    $bootTime = Get-BootTime
    if ($null -eq $bootTime) {
        throw 'Boot time could not be read, so log clears cannot be scoped to this session.'
    }
    $evidence += ("Last boot: {0}" -f $bootTime)

    $specs = @(
        @{ LogName = 'Security'; Id = 1102; What = 'Security log cleared' },
        @{ LogName = 'System'; Id = 104; What = 'A log was cleared' }
    )

    $detected = $false
    foreach ($spec in $specs) {
        try {
            $events = Get-EventsSafe -Filter @{ LogName = $spec.LogName; Id = $spec.Id; StartTime = $bootTime } -Max 100
        }
        catch {
            $evidence += ("Could not read {0}: {1}" -f $spec.LogName, $_.Exception.Message)
            continue
        }
        foreach ($e in $events) {
            $data = Get-EventDataMap -EventRecord $e
            $who = ''
            if ($data.ContainsKey('SubjectUserName')) { $who = $data['SubjectUserName'] }
            elseif ($data.ContainsKey('SubjectUserName ')) { $who = $data['SubjectUserName '] }
            $which = ''
            if ($data.ContainsKey('Channel')) { $which = $data['Channel'] }

            $line = ("{0} @ {1}" -f $spec.What, $e.TimeCreated)
            if (-not [string]::IsNullOrEmpty($which)) { $line = $line + (" log='{0}'" -f $which) }
            if (-not [string]::IsNullOrEmpty($who))   { $line = $line + (" by='{0}'" -f $who) }
            $line = $line + (" (Event {0} in {1})" -f $e.Id, $spec.LogName)
            $evidence += $line
            $detected = $true
        }
    }

    if (-not $detected) {
        return New-CheckResult -Id 18 -Name 'Event Log Cleared' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 18 -Name 'Event Log Cleared' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'A log was cleared this boot session, destroying process, service and logon records.'
}

# ------------------------------------------------------------------------------
# CHECK 19 - Smart App Control / app install source
#
# READS  : HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\
#            VerifiedAndReputablePolicyState
#          HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AicEnabled
#          HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen
# WRITES : nothing.
#
# These settings restrict which programs may run at all. Set to their strictest
# values they block unsigned forensic tools, so the screenshare cannot proceed.
# ------------------------------------------------------------------------------
function Test-SmartAppControl {
    $evidence = @()
    $detected = $false
    $severity = 'Medium'

    $sacState = Get-RegVal -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState'
    if ($null -ne $sacState) {
        $meaning = switch ([int]$sacState) {
            0 { 'Off' }
            1 { 'Enforced - only verified and reputable apps may run' }
            2 { 'Evaluation mode' }
            default { 'unrecognised value' }
        }
        $evidence += ("VerifiedAndReputablePolicyState = {0} (Smart App Control: {1})" -f $sacState, $meaning)
        if ([int]$sacState -eq 1) { $detected = $true; $severity = 'High' }
    }

    $aic = Get-RegVal -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'AicEnabled'
    if ($null -ne $aic) {
        $evidence += ("AicEnabled = {0} (app install source restriction)" -f $aic)
        # StoreOnly and PreferStore block unsigned tools outright. Recommendations
        # only shows a warning, so it is reported but not treated as a detection.
        if ([string]$aic -match 'StoreOnly|PreferStore') { $detected = $true; $severity = 'High' }
    }

    $ssRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'
    $ssKey = Get-RegKey -Path $ssRoot
    if ($null -ne $ssKey) {
        foreach ($n in (Get-RegValueNames -Key $ssKey)) {
            $v = $ssKey.GetValue($n, $null)
            $evidence += ("{0}\{1} = {2}" -f $ssRoot, $n, (Format-RegData $v))
            if ($n -match 'ConfigureAppInstallControl' -and [string]$v -match 'StoreOnly|Recommendations') {
                $detected = $true; $severity = 'High'
            }
        }
    }

    if (-not $detected) {
        if ($evidence.Count -eq 0) { $evidence += 'No app-execution restriction policies are configured' }
        return New-CheckResult -Id 19 -Name 'Smart App Control / App Install Source' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 19 -Name 'Smart App Control / App Install Source' -Status 'Detected' `
        -Severity $severity -Evidence $evidence `
        -Detail 'Only Microsoft-recognised apps may run - unsigned forensic tools will not launch.'
}

# ------------------------------------------------------------------------------
# CHECK 20 - USB / disk devices disabled
#
# READS  : HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR, \Enum\USB, \Enum\DISK
# WRITES : nothing.
#
# ConfigFlags bit 0 (CONFIGFLAG_DISABLED) means the device was manually disabled.
# A disabled USB stick does not appear in Process Hacker's device view and
# leaves no timestamp for when files were pulled off the machine.
# ------------------------------------------------------------------------------
function Test-DisabledUsbDevices {
    $evidence = @()
    $accessIssues = 0

    $enumRoots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USB',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\DISK'
    )

    foreach ($root in $enumRoots) {
        if ($null -eq (Get-RegKey -Path $root)) { continue }

        $errors = @()
        $devices = @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue -ErrorVariable errors)
        $accessIssues += $errors.Count

        foreach ($device in $devices) {
            $names = Get-RegValueNames -Key $device
            if ($names -notcontains 'ConfigFlags') { continue }
            $configFlags = $device.GetValue('ConfigFlags', 0)
            $flagsInt = 0
            # A ConfigFlags value that is not an integer cannot be tested for
            # the disabled bit, so move on to the next device.
            try { $flagsInt = [int]$configFlags } catch { continue }
            if (($flagsInt -band 0x1) -eq 0) { continue }

            $friendly = $device.GetValue('FriendlyName', $null)
            if ($null -eq $friendly) { $friendly = $device.GetValue('DeviceDesc', $null) }
            if ($null -eq $friendly) { $friendly = '<no friendly name>' }

            $deviceId = $device.Name -replace '^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\', ''
            $evidence += ("DISABLED: {0}`n    Device ID  : {1}`n    ConfigFlags: 0x{2:X}" -f $friendly, $deviceId, $flagsInt)
        }
    }

    if ($accessIssues -gt 0) {
        $evidence += ("Note: {0} subkeys under Enum could not be read (this is normal - some device keys are SYSTEM-only)" -f $accessIssues)
    }

    $hasDisabled = $false
    foreach ($line in $evidence) { if ($line -match '^DISABLED:') { $hasDisabled = $true } }

    if (-not $hasDisabled) {
        return New-CheckResult -Id 20 -Name 'USB / Disk Devices Disabled' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 20 -Name 'USB / Disk Devices Disabled' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Storage device manually disabled - hidden from device listings, no extraction timestamp.'
}

# ------------------------------------------------------------------------------
# CHECK 21 - SettingsPageVisibility
#
# READS  : SettingsPageVisibility under HKLM and HKCU
#            \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
# WRITES : nothing.
#
# This policy hides pages from the Settings app. Hiding the Windows Security or
# recovery pages stops a moderator checking exclusion lists.
# ------------------------------------------------------------------------------
function Test-SettingsPageVisibility {
    $evidence = @()

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($root in $roots) {
        $value = Get-RegVal -Path $root -Name 'SettingsPageVisibility'
        if ($null -eq $value) { continue }
        $text = [string]$value
        $evidence += ("{0}\SettingsPageVisibility = {1}" -f $root, $text)

        # The value is either "hide:a;b;c" or "showonly:a;b;c".
        if ($text -match '^(?i)\s*hide:(.*)$') {
            $pages = @($matches[1] -split ';' | Where-Object { $_.Trim() -ne '' })
            $evidence += ("  Mode: hide ({0} page(s) concealed)" -f $pages.Count)
            foreach ($p in $pages) { $evidence += ("    hidden: {0}" -f $p.Trim()) }
        }
        elseif ($text -match '^(?i)\s*showonly:(.*)$') {
            $pages = @($matches[1] -split ';' | Where-Object { $_.Trim() -ne '' })
            $evidence += ("  Mode: showonly - every Settings page except these {0} is concealed" -f $pages.Count)
            foreach ($p in $pages) { $evidence += ("    visible: {0}" -f $p.Trim()) }
        }
    }

    if ($evidence.Count -eq 0) {
        return New-CheckResult -Id 21 -Name 'SettingsPageVisibility' -Status 'Clean'
    }
    return New-CheckResult -Id 21 -Name 'SettingsPageVisibility' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Settings pages removed by policy - blocks checking AV exclusions or reset history.'
}

# ------------------------------------------------------------------------------
# CHECK 22 - NotFileMru
#
# READS  : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
#            NotFileMru, and the OpenSavePidlMRU subkey
# WRITES : nothing.
#
# NotFileMru = 1 stops Windows recording files opened through Open/Save dialogs.
# That MRU list is one of the most useful screenshare artifacts there is.
# ------------------------------------------------------------------------------
function Test-NotFileMru {
    $evidence = @()
    $detected = $false

    $comDlgRoot = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32'
    $policyRoot = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ComDlg32'

    foreach ($root in @($comDlgRoot, $policyRoot)) {
        $value = Get-RegVal -Path $root -Name 'NotFileMru'
        if ($null -eq $value) { continue }
        $evidence += ("{0}\NotFileMru = {1}" -f $root, $value)
        # Non-numeric NotFileMru values are reported above but not judged.
        try { if ([int]$value -eq 1) { $detected = $true } } catch { }
    }

    # Corroboration: an existing but empty OpenSavePidlMRU means the history was
    # switched off (or wiped) rather than simply never used.
    $mruPath = Join-Path -Path $comDlgRoot -ChildPath 'OpenSavePidlMRU'
    $mruKey = Get-RegKey -Path $mruPath
    if ($null -eq $mruKey) {
        $evidence += 'OpenSavePidlMRU key does not exist'
        if ($detected) { $evidence += '  (consistent with Open/Save history being disabled)' }
    }
    else {
        $subKeys = @(Get-ChildItem -LiteralPath $mruPath -ErrorAction SilentlyContinue)
        $totalValues = 0
        foreach ($sub in $subKeys) {
            $names = @(Get-RegValueNames -Key $sub) | Where-Object { $_ -ne 'MRUListEx' }
            $totalValues += $names.Count
        }
        $evidence += ("OpenSavePidlMRU: {0} file-type subkeys, {1} recorded entries" -f $subKeys.Count, $totalValues)
        if ($totalValues -eq 0) {
            $evidence += '  MRU exists but holds no entries - history is disabled or has been cleared'
            $detected = $true
        }
    }

    if (-not $detected) {
        return New-CheckResult -Id 22 -Name 'NotFileMru' -Status 'Clean' -Evidence $evidence
    }
    return New-CheckResult -Id 22 -Name 'NotFileMru' -Status 'Detected' `
        -Severity 'High' -Evidence $evidence `
        -Detail 'Open/Save dialog history disabled or empty - removes the record of files opened via file pickers.'
}


#===============================================================================
# SECTION C - dispatcher
#===============================================================================

# Runs one check inside its own try/catch. A check that throws is reported as
# 'Unavailable' with the error text preserved - a blocked check is itself data,
# and it must never take down the run.
function Invoke-Check {
    param(
        [int]$Id,
        [string]$Name,
        [scriptblock]$Body
    )
    try {
        $result = & $Body
        if ($null -eq $result) {
            return New-CheckResult -Id $Id -Name $Name -Status 'Unavailable' `
                -Evidence @('The check returned no result.')
        }
        return $result
    }
    catch {
        $message = [string]$_.Exception.Message
        $where = ''
        # Position information is a nicety; its absence must not mask the error.
        try { $where = [string]$_.InvocationInfo.PositionMessage } catch { }
        $lines = @("Error: $message")
        if (-not [string]::IsNullOrWhiteSpace($where)) {
            $lines += ($where -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
        }
        return New-CheckResult -Id $Id -Name $Name -Status 'Unavailable' -Evidence $lines `
            -Detail 'Check could not complete. Not a clean result - the artifact was not examined.'
    }
}

function Invoke-AllChecks {
    param([switch]$IncludeSysMain)

    # Held at script scope so the check 12 scriptblock below resolves it the same
    # way regardless of which scope the dispatcher invokes it from.
    $script:SysMainEnabled = [bool]$IncludeSysMain

    $checks = @(
        @{ Id = 1;  Name = 'Internet Options - Restricted Zones';      Body = { Test-RestrictedZones } },
        @{ Id = 2;  Name = 'Firewall.cpl Restrictions';                Body = { Test-FirewallCplRestrictions } },
        @{ Id = 3;  Name = 'Hosts File Manipulation';                  Body = { Test-HostsFile } },
        @{ Id = 4;  Name = 'Taskkill Autorun';                         Body = { Test-TaskkillAutorun } },
        @{ Id = 5;  Name = 'DisallowRun';                              Body = { Test-DisallowRun } },
        @{ Id = 6;  Name = 'IFEO - Image File Execution Options';      Body = { Test-ImageFileExecutionOptions } },
        @{ Id = 7;  Name = 'WinRAR Steganography';                     Body = { Test-WinRarSteganography } },
        @{ Id = 8;  Name = 'NTFS Journal Deletion';                    Body = { Test-NtfsJournalDeletion } },
        @{ Id = 9;  Name = 'FileInfo Filter';                          Body = { Test-FileInfoFilter } },
        @{ Id = 10; Name = 'Prefetch - Read-Only .pf Files';           Body = { Test-PrefetchReadOnly } },
        @{ Id = 11; Name = 'Prefetch Parameters';                      Body = { Test-PrefetchParameters } },
        @{ Id = 12; Name = 'SysMain - sechost.dll Suspended Threads';  Body = { Test-SysMainSuspendedThreads -Enabled:$script:SysMainEnabled } },
        @{ Id = 13; Name = 'URL Blocklist';                            Body = { Test-UrlBlocklist } },
        @{ Id = 14; Name = 'CMD Color Bypass';                         Body = { Test-CmdColorBypass } },
        @{ Id = 15; Name = 'Disallowed Certificates';                  Body = { Test-DisallowedCertificates } },
        @{ Id = 16; Name = 'Group Policy Restrictions';                Body = { Test-GroupPolicyRestrictions } },
        @{ Id = 17; Name = 'System Time Changes';                      Body = { Test-SystemTimeChanges } },
        @{ Id = 18; Name = 'Event Log Cleared';                        Body = { Test-EventLogCleared } },
        @{ Id = 19; Name = 'Smart App Control / App Install Source';   Body = { Test-SmartAppControl } },
        @{ Id = 20; Name = 'USB / Disk Devices Disabled';              Body = { Test-DisabledUsbDevices } },
        @{ Id = 21; Name = 'SettingsPageVisibility';                   Body = { Test-SettingsPageVisibility } },
        @{ Id = 22; Name = 'NotFileMru';                               Body = { Test-NotFileMru } }
    )

    $results = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($check in $checks) {
        $index++
        Write-Progress -Activity 'SSDetector' -Status ("[{0}/{1}] {2}" -f $index, $checks.Count, $check.Name) `
            -PercentComplete (($index / $checks.Count) * 100)
        $results.Add((Invoke-Check -Id $check.Id -Name $check.Name -Body $check.Body))
    }
    Write-Progress -Activity 'SSDetector' -Completed
    return $results.ToArray()
}


#===============================================================================
# SECTION D - output
# Console first, then an optional plain-text copy. Nothing is opened, uploaded
# or copied to the clipboard.
#===============================================================================

# Writes one line to the console and records it for the optional report file.
# Every line passes through Get-Redacted so no username reaches either.
function Write-Line {
    param([string]$Text = '', [string]$Color = 'Gray')
    $safe = Get-Redacted -Text $Text
    $script:ReportLines.Add($safe)
    if ($Color -eq 'None') { Write-Host $safe }
    else { Write-Host $safe -ForegroundColor $Color }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'High' { return 'Red' }
        'Medium' { return 'Yellow' }
        default { return 'Gray' }
    }
}

function Write-Report {
    param(
        [object[]]$Results,
        [switch]$QuietMode,
        [bool]$SysMainEnabled
    )

    $detections = @($Results | Where-Object { $_.Status -eq 'Detected' } |
        Sort-Object -Property @{ Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, Id)
    $unavailable = @($Results | Where-Object { $_.Status -eq 'Unavailable' } | Sort-Object -Property Id)
    $clean = @($Results | Where-Object { $_.Status -eq 'Clean' } | Sort-Object -Property Id)

    Write-Line ''
    Write-Line '================================================================================' 'Cyan'
    Write-Line ' SSDetector - screenshare bypass / anti-forensics scan' 'Cyan'
    Write-Line '================================================================================' 'Cyan'
    Write-Line ("  Scanned      : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K'))
    Write-Line ("  Machine      : {0}" -f $env:COMPUTERNAME)
    Write-Line ("  PowerShell   : {0}" -f $PSVersionTable.PSVersion)
    Write-Line ("  SysMain check: {0}" -f $(if ($SysMainEnabled) { 'enabled (-IncludeSysMainCheck)' } else { 'not run (opt-in)' }))
    Write-Line '  This scan is read-only. Nothing on this machine was modified.'
    Write-Line ''

    # --- detections -----------------------------------------------------------
    Write-Line '--------------------------------------------------------------------------------'
    Write-Line (" DETECTIONS ({0})" -f $detections.Count) $(if ($detections.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Line '--------------------------------------------------------------------------------'
    if ($detections.Count -eq 0) {
        Write-Line '  None.' 'Green'
    }
    else {
        foreach ($d in $detections) {
            $color = Get-SeverityColor -Severity $d.Severity
            Write-Line ''
            Write-Line ("  [{0}] #{1} {2}" -f $d.Severity.ToUpper(), $d.Id, $d.Name) $color
            if (-not [string]::IsNullOrWhiteSpace($d.Detail)) {
                # Wrap the explanation at roughly 76 columns so it stays readable.
                $words = $d.Detail -split '\s+'
                $line = '       '
                foreach ($word in $words) {
                    if (($line.Length + $word.Length + 1) -gt 78) {
                        Write-Line $line 'DarkGray'
                        $line = '       ' + $word
                    }
                    else {
                        $line = $line + $(if ($line.Trim() -eq '') { '' } else { ' ' }) + $word
                    }
                }
                if ($line.Trim() -ne '') { Write-Line $line 'DarkGray' }
            }
            foreach ($e in $d.Evidence) {
                foreach ($sub in ($e -split "`n")) {
                    Write-Line ("       - {0}" -f $sub.TrimEnd()) $color
                }
            }
        }
    }
    Write-Line ''

    # --- unavailable ----------------------------------------------------------
    Write-Line '--------------------------------------------------------------------------------'
    Write-Line (" UNAVAILABLE ({0}) - these checks did not run, which is not the same as clean" -f $unavailable.Count) 'Yellow'
    Write-Line '--------------------------------------------------------------------------------'
    if ($unavailable.Count -eq 0) {
        Write-Line '  None. Every check completed.' 'Green'
    }
    else {
        foreach ($u in $unavailable) {
            Write-Line ("  #{0} {1}" -f $u.Id, $u.Name) 'Yellow'
            foreach ($e in $u.Evidence) {
                foreach ($sub in ($e -split "`n")) {
                    Write-Line ("       {0}" -f $sub.TrimEnd()) 'DarkYellow'
                }
            }
        }
    }
    Write-Line ''

    # --- clean ----------------------------------------------------------------
    if (-not $QuietMode) {
        Write-Line '--------------------------------------------------------------------------------'
        Write-Line (" CLEAN ({0})" -f $clean.Count) 'Green'
        Write-Line '--------------------------------------------------------------------------------'
        foreach ($c in $clean) {
            Write-Line ("  #{0,-2} {1}" -f $c.Id, $c.Name) 'Green'
        }
        Write-Line ''
    }

    # --- summary --------------------------------------------------------------
    Write-Line '--------------------------------------------------------------------------------'
    Write-Line (" SUMMARY: {0} detected, {1} clean, {2} unavailable, {3} checks total" -f `
            $detections.Count, $clean.Count, $unavailable.Count, $Results.Count) `
        $(if ($detections.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Line '--------------------------------------------------------------------------------'
    Write-Line ''

    return $detections.Count
}


#===============================================================================
# SECTION E - entry point
#===============================================================================

# ------------------------------------------------------------------------------
# Holds the console open at the end of the run.
#
# READS  : a single keypress from the console.
# WRITES : nothing. The prompt goes to the console only - it is deliberately not
#          added to the report, so an -OutputPath file is unaffected.
#
# When the script is launched by double-clicking it, or through the Explorer
# "Run with PowerShell" entry, the console window closes the instant the script
# ends and the whole report scrolls away unread.
#
# This is skipped automatically when there is no interactive console to read
# from - stdin redirected from a file or pipe, or a host that exposes no RawUI -
# so a scheduled or scripted run cannot hang forever waiting for a key that
# nobody is there to press.
# ------------------------------------------------------------------------------
function Wait-ForKeyPress {
    # Redirected input means nobody is sitting at a keyboard.
    try {
        if ([Console]::IsInputRedirected) { return }
    }
    catch {
        # IsInputRedirected is unavailable on this host. Fall through and let the
        # RawUI check below decide.
    }

    $rawUI = $null
    try { $rawUI = $Host.UI.RawUI } catch { }
    if ($null -eq $rawUI) { return }

    Write-Host ''
    Write-Host ' Press any key to exit...' -ForegroundColor Cyan

    try {
        # NoEcho keeps the key itself off the screen; IncludeKeyDown returns on
        # the press rather than waiting for the release.
        $null = $rawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        # Some hosts (the ISE, some remoting sessions) do not implement ReadKey.
        # Waiting for Enter is a reasonable substitute there.
        try { $null = Read-Host } catch { }
    }
}

# Elevation check. Without admin rights, several checks read nothing and the
# report would look reassuringly clean while actually being blind, so the script
# stops rather than producing a misleading result.
function Test-Elevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

try {
    if (-not (Test-Elevated)) {
        Write-Host ''
        Write-Host ' SSDetector must be run as Administrator.' -ForegroundColor Red
        Write-Host ''
        Write-Host ' Without elevation the following cannot be read at all:' -ForegroundColor Yellow
        Write-Host '   - HKLM policy keys (checks 1, 2, 4, 5, 6, 13, 16, 19, 21)'
        Write-Host '   - the Security event log (checks 8, 17, 18)'
        Write-Host '   - the USN journal and loaded filter list (checks 8, 9)'
        Write-Host '   - the Prefetch folder (check 10)'
        Write-Host ''
        Write-Host ' Those checks would silently return nothing, and the report would read as'
        Write-Host ' clean when it is simply blind. Re-run from an elevated PowerShell prompt:'
        Write-Host ''
        Write-Host '   Right-click Windows PowerShell -> Run as administrator' -ForegroundColor Cyan
        Write-Host ''
        exit 2
    }

    $results = Invoke-AllChecks -IncludeSysMain:$IncludeSysMainCheck
    $detectionCount = Write-Report -Results $results -QuietMode:$Quiet -SysMainEnabled ([bool]$IncludeSysMainCheck)

    # The only write this script ever performs, and only when explicitly asked.
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        try {
            $text = ($script:ReportLines -join [Environment]::NewLine) + [Environment]::NewLine
            # Plain UTF-8, no byte order mark. This is the only write in the file.
            $resolved = [System.IO.Path]::GetFullPath(
                [System.IO.Path]::Combine((Get-Location -PSProvider FileSystem).ProviderPath, $OutputPath))
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($resolved, $text, $utf8NoBom)
            Write-Host (" Report written to: {0}" -f $resolved) -ForegroundColor Cyan
            Write-Host ' (Not opened, not uploaded, not copied to the clipboard.)' -ForegroundColor DarkGray
            Write-Host ''
        }
        catch {
            Write-Host (" Could not write the report to '{0}': {1}" -f $OutputPath, $_.Exception.Message) -ForegroundColor Red
            Write-Host ''
            exit 2
        }
    }

    if ($detectionCount -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Host ''
    Write-Host ' SSDetector could not complete the run.' -ForegroundColor Red
    Write-Host ("   {0}" -f $_.Exception.Message) -ForegroundColor Red
    # As above: print the location if we have it, but never fail while failing.
    try { Write-Host ("   {0}" -f $_.InvocationInfo.PositionMessage) -ForegroundColor DarkGray } catch { }
    Write-Host ''
    exit 2
}
finally {
    # Runs on every path out of the block above, including each 'exit', so the
    # window is held open exactly once whether the run was clean, found
    # something, was refused for lack of elevation, or failed outright.
    # PowerShell preserves the exit code across this block.
    Wait-ForKeyPress
}
