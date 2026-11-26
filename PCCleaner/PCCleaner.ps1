<#
    PCCleaner.ps1  -  Virus scan + safe disk cleanup for Windows 10 / 11

    Start it with "Run-PCCleaner.bat" (it asks for administrator rights by itself).
    Uses only what's already built into Windows (Microsoft Defender, DISM, the
    Recycle Bin API) - nothing is downloaded or installed.

    Options (for advanced use):
      -Action Scan|Clean|Both             what to run (default: Both)
      -ScanType Quick|Full                Defender scan depth (default: Quick)
      -Deep                               also clean Windows Update leftovers and offer to remove Windows.old
      -NoPrompt                           don't ask before deleting anything (use with care)
      -NoElevate -NoOpen
      -OutRoot <folder>                   where to save reports (default: .\Reports next to this script)
#>
[CmdletBinding()]
param(
    [ValidateSet('Scan','Clean','Both')][string]$Action = 'Both',
    [ValidateSet('Quick','Full')][string]$ScanType = 'Quick',
    [switch]$Deep,
    [switch]$NoPrompt,
    [switch]$NoElevate,
    [switch]$NoOpen,
    [string]$OutRoot
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:ToolVersion    = '1.0.0'
$script:Start          = Get-Date
try { $Host.UI.RawUI.WindowTitle = 'PC Cleaner' } catch {}

#region ===================== elevation =====================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$script:IsAdmin = Test-IsAdmin
if (-not $script:IsAdmin -and -not $NoElevate) {
    Write-Host 'Asking for administrator rights (needed to scan and clean system areas)...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" } }
        else { $a += "-$($kv.Key)"; $a += ('"{0}"' -f $kv.Value) }
    }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($a -join ' ') -ErrorAction Stop; exit 0 }
    catch { Write-Host 'Administrator rights were not given. Continuing in LIMITED mode - cleanup of system folders and the Defender scan will be skipped.' -ForegroundColor Yellow }
}
#endregion

#region ===================== helpers =====================
$script:Results = New-Object System.Collections.ArrayList
function Add-R {
    param([string]$Cat, [string]$Check, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status, [string]$Detail = '')
    [void]$script:Results.Add([pscustomobject]@{ Category = $Cat; Check = $Check; Status = $Status; Detail = $Detail })
    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Gray' } }
    Write-Host ('   [{0,-4}] {1}' -f $Status, $Check) -ForegroundColor $color
    if ($Detail) { Write-Host ('          ' + $Detail) -ForegroundColor DarkGray }
}
function Invoke-Section([string]$Name, [scriptblock]$Body) {
    Write-Host ''
    Write-Host ("== $Name ==") -ForegroundColor Cyan
    try { & $Body } catch { Add-R $Name 'Section error' 'INFO' $_.Exception.Message }
}
function HE([object]$s) { if ($null -eq $s) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Confirm-Action([string]$Prompt) {
    if ($NoPrompt) { return $true }
    $r = Read-Host "$Prompt [y/N]"
    return ($r -match '^(y|yes)$')
}
function Get-FolderSize([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    try { (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } catch { 0 }
}
function Remove-FolderContents([string]$Path) {
    $before = Get-FolderSize $Path
    if (Test-Path -LiteralPath $Path) {
        Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch {}
        }
    }
    $after = Get-FolderSize $Path
    return [math]::Max(0, $before - $after)
}
function Format-Bytes([double]$n) {
    if ($n -ge 1GB) { return ('{0:N2} GB' -f ($n / 1GB)) }
    if ($n -ge 1MB) { return ('{0:N1} MB' -f ($n / 1MB)) }
    if ($n -ge 1KB) { return ('{0:N0} KB' -f ($n / 1KB)) }
    return "$n B"
}
$script:FreedBytes = 0
#endregion

#region ===================== output locations =====================
$ScriptDir = Split-Path -Parent $PSCommandPath
if (-not $OutRoot) { $OutRoot = Join-Path $ScriptDir 'Reports' }
$Stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$RunDir  = Join-Path $OutRoot $Stamp
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
$ReportPath = Join-Path $RunDir 'report.html'

Write-Host "PC Cleaner v$($script:ToolVersion)" -ForegroundColor Cyan
Write-Host "Mode: $Action   Admin: $($script:IsAdmin)" -ForegroundColor DarkGray
#endregion

#region ===================== VIRUS / MALWARE SCAN =====================
if ($Action -in 'Scan','Both') {
    Invoke-Section 'Microsoft Defender status' {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($mp.RealTimeProtectionEnabled) { Add-R 'Defender' 'Real-time protection' 'PASS' }
            else { Add-R 'Defender' 'Real-time protection' 'FAIL' 'Real-time protection is OFF. Turn it on in Windows Security.' }
            $age = $mp.AntivirusSignatureAge
            if ($null -ne $age -and $age -le 2) { Add-R 'Defender' 'Virus definitions' 'PASS' "$age day(s) old" }
            elseif ($null -ne $age) { Add-R 'Defender' 'Virus definitions' 'WARN' "$age day(s) old - updating now" }
            if ($mp.AntivirusEnabled -eq $false) { Add-R 'Defender' 'Antivirus engine' 'FAIL' 'Microsoft Defender antivirus is disabled (a third-party antivirus may be in charge instead).' }
        } catch { Add-R 'Defender' 'Status check' 'INFO' "Could not read Defender status: $($_.Exception.Message)" }

        if ($script:IsAdmin) {
            try { Update-MpSignature -ErrorAction Stop; Add-R 'Defender' 'Signature update' 'PASS' 'Definitions updated' }
            catch { Add-R 'Defender' 'Signature update' 'INFO' "Could not update definitions: $($_.Exception.Message)" }
        }
    }

    if ($script:IsAdmin) {
        Invoke-Section "Microsoft Defender $ScanType scan" {
            Write-Host "   Running a $ScanType scan - this can take a while, especially Full..." -ForegroundColor DarkGray
            try {
                Start-MpScan -ScanType $ScanType -ErrorAction Stop
                Add-R 'Scan' "$ScanType scan" 'PASS' 'Completed with no errors reported by Defender'
            } catch { Add-R 'Scan' "$ScanType scan" 'INFO' "Scan did not complete: $($_.Exception.Message)" }

            try {
                $threats = @(Get-MpThreatDetection -ErrorAction Stop)
                if ($threats.Count -eq 0) { Add-R 'Scan' 'Threats found' 'PASS' 'No active detections' }
                else {
                    foreach ($t in $threats) { Add-R 'Scan' 'Threat detected' 'FAIL' ("$($t.ThreatID) - resource: $($t.Resources -join '; ')") }
                }
            } catch { Add-R 'Scan' 'Threat history' 'INFO' "Could not read threat detections: $($_.Exception.Message)" }
        }
    } else {
        Add-R 'Scan' "$ScanType scan" 'INFO' 'Skipped - needs administrator rights'
    }

    Invoke-Section 'Start-up programs' {
        $items = @()
        foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
            try { (Get-Item -LiteralPath $k -ErrorAction Stop).Property | ForEach-Object {
                    $v = (Get-ItemProperty -LiteralPath $k -Name $_).$_
                    $items += [pscustomobject]@{ Name = $_; Command = $v; Source = $k }
                } } catch {}
        }
        foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (Test-Path $folder) { Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object { $items += [pscustomobject]@{ Name = $_.Name; Command = $_.FullName; Source = 'Startup folder' } } }
        }
        Add-R 'Start-up' 'Entries found' 'INFO' "$($items.Count) start-up item(s) - review them in Task Manager > Start-up apps if any look unfamiliar"
        $items | Select-Object -First 25 | ForEach-Object { Add-R 'Start-up' $_.Name 'INFO' (($_.Command) -replace '\s+',' ') }
    }

    Invoke-Section 'Hosts file check' {
        $hosts = "$env:WinDir\System32\drivers\etc\hosts"
        try {
            $lines = Get-Content -LiteralPath $hosts -ErrorAction Stop | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
            if ($lines.Count -eq 0) { Add-R 'Network' 'Hosts file' 'PASS' 'No custom entries' }
            else { Add-R 'Network' 'Hosts file' 'WARN' "$($lines.Count) custom entrie(s) - malware sometimes redirects sites this way, check they're ones you added"; $lines | Select-Object -First 15 | ForEach-Object { Add-R 'Network' 'Hosts entry' 'INFO' $_ } }
        } catch { Add-R 'Network' 'Hosts file' 'INFO' "Could not read hosts file: $($_.Exception.Message)" }
    }
}
#endregion

#region ===================== CLEANUP =====================
if ($Action -in 'Clean','Both') {
    Invoke-Section 'Temporary files' {
        $targets = @("$env:TEMP")
        if ($script:IsAdmin) { $targets += "$env:WinDir\Temp" }
        foreach ($t in $targets) {
            $freed = Remove-FolderContents $t
            $script:FreedBytes += $freed
            Add-R 'Cleanup' "Temp files ($t)" 'PASS' "Freed $(Format-Bytes $freed)"
        }
    }

    Invoke-Section 'Recycle Bin' {
        try {
            $sizeBefore = (New-Object -ComObject Shell.Application).NameSpace(10).Items() | Measure-Object -Property Size -Sum
            $sz = [double]($sizeBefore.Sum)
            if ($sz -gt 0) {
                if (Confirm-Action "Empty the Recycle Bin ($(Format-Bytes $sz))?") {
                    Clear-RecycleBin -Force -ErrorAction Stop
                    $script:FreedBytes += $sz
                    Add-R 'Cleanup' 'Recycle Bin' 'PASS' "Emptied, freed $(Format-Bytes $sz)"
                } else { Add-R 'Cleanup' 'Recycle Bin' 'INFO' 'Skipped by user' }
            } else { Add-R 'Cleanup' 'Recycle Bin' 'PASS' 'Already empty' }
        } catch { Add-R 'Cleanup' 'Recycle Bin' 'INFO' "Could not empty: $($_.Exception.Message)" }
    }

    Invoke-Section 'Browser cache' {
        $paths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
            "$env:APPDATA\Mozilla\Firefox\Profiles"
        )
        foreach ($p in $paths) {
            if ($p -like '*Firefox*Profiles') {
                if (Test-Path $p) {
                    Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $cachePath = Join-Path $_.FullName 'cache2'
                        if (Test-Path $cachePath) { $freed = Remove-FolderContents $cachePath; $script:FreedBytes += $freed; Add-R 'Cleanup' "Firefox cache ($($_.Name))" 'PASS' "Freed $(Format-Bytes $freed)" }
                    }
                }
                continue
            }
            if (Test-Path $p) { $freed = Remove-FolderContents $p; $script:FreedBytes += $freed; Add-R 'Cleanup' "Cache ($p)" 'PASS' "Freed $(Format-Bytes $freed)" }
        }
        Add-R 'Cleanup' 'Browser cache' 'INFO' 'Only cache/temp internet files were removed - saved passwords, cookies and history were left alone'
    }

    if ($Deep -and $script:IsAdmin) {
        Invoke-Section 'Windows Update cleanup (Deep)' {
            if (Confirm-Action 'Run DISM component store cleanup? (removes old Windows Update files, can take several minutes)') {
                try {
                    $out = & dism.exe /Online /Cleanup-Image /StartComponentCleanup 2>&1
                    Add-R 'Cleanup' 'Windows Update files' 'PASS' 'DISM component cleanup completed'
                } catch { Add-R 'Cleanup' 'Windows Update files' 'INFO' "DISM failed: $($_.Exception.Message)" }
            } else { Add-R 'Cleanup' 'Windows Update files' 'INFO' 'Skipped by user' }
        }

        Invoke-Section 'Windows.old (Deep)' {
            $oldPath = "$env:SystemDrive\Windows.old"
            if (Test-Path $oldPath) {
                $sz = Get-FolderSize $oldPath
                if (Confirm-Action "Delete Windows.old ($(Format-Bytes $sz))? This removes the ability to roll back to the previous Windows install - make sure you don't need that first") {
                    try {
                        & cmd.exe /c "rd /s /q `"$oldPath`"" | Out-Null
                        $script:FreedBytes += $sz
                        Add-R 'Cleanup' 'Windows.old' 'PASS' "Removed, freed $(Format-Bytes $sz)"
                    } catch { Add-R 'Cleanup' 'Windows.old' 'INFO' "Could not remove: $($_.Exception.Message)" }
                } else { Add-R 'Cleanup' 'Windows.old' 'INFO' 'Skipped by user' }
            } else { Add-R 'Cleanup' 'Windows.old' 'PASS' 'Not present' }
        }
    } elseif ($Deep -and -not $script:IsAdmin) {
        Add-R 'Cleanup' 'Deep cleanup' 'INFO' 'Skipped - needs administrator rights'
    }
}
#endregion

#region ===================== report =====================
$rows = $script:Results | ForEach-Object {
    $cls = $_.Status.ToLower()
    "<tr class='$cls'><td>$(HE $_.Category)</td><td>$(HE $_.Check)</td><td class='status'>$(HE $_.Status)</td><td>$(HE $_.Detail)</td></tr>"
}
$summary = if ($Action -in 'Clean','Both') { "<p><b>Space freed:</b> $(Format-Bytes $script:FreedBytes)</p>" } else { '' }
$html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>PC Cleaner report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#ddd;margin:2em}
h1{color:#5cc8ff} table{border-collapse:collapse;width:100%} td,th{padding:6px 10px;border-bottom:1px solid #333;text-align:left;vertical-align:top}
tr.pass td.status{color:#6fcf6f} tr.warn td.status{color:#f2c94c} tr.fail td.status{color:#eb5757} tr.info td.status{color:#9aa}
</style></head><body>
<h1>PC Cleaner report</h1>
<p>Run: $(Get-Date $script:Start -Format 'yyyy-MM-dd HH:mm') &nbsp; Mode: $(HE $Action) &nbsp; Admin: $($script:IsAdmin)</p>
$summary
<table><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr>
$($rows -join "`n")
</table>
</body></html>
"@
$html | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host ''
Write-Host "Report saved to: $ReportPath" -ForegroundColor Cyan
if ($Action -in 'Clean','Both') { Write-Host "Space freed: $(Format-Bytes $script:FreedBytes)" -ForegroundColor Green }
if (-not $NoOpen) { try { Start-Process $ReportPath } catch {} }
#endregion
