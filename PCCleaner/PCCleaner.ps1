<#
    PCCleaner.ps1  -  Virus scan, pop-up fix and safe clean-up for Windows 10 / 11

    Don't double-click this file: Windows deliberately opens .ps1 files with "Open with".
    Double-click "START HERE.bat" instead - it asks for administrator rights by itself.

    Uses only what is built into Windows (Microsoft Defender, the Malicious Software Removal
    Tool, DISM, Disk Clean-up). Nothing is downloaded or installed. Your own files are only
    touched in the "recent downloads" option, and only moved to the Recycle Bin when you say so.

    All questions are asked at the start; after that it runs by itself.

    Options:
      -Action Scan|Clean|Both     scan and fix, clean, or both (default: Both)
              Recent              review downloads and programs from the last -Weeks weeks
              FreshStart          guide to resetting Windows, opens Settings > Recovery
      -ScanType Quick|Full        Defender scan depth (default: Quick)
      -Deep                       also clean Windows Update leftovers, setup/upgrade leftovers, crash
                                  dumps, shader and thumbnail caches, and offer to remove Windows.old
      -Weeks <n>                  how far back -Action Recent looks (default: 2)
      -OfflineScan                at the end, offer a Microsoft Defender Offline scan (restarts the PC)
      -NoPrompt                   answer yes to the routine questions. It still never empties the Recycle
                                  Bin, deletes Windows.old, removes browser policies, closes browsers,
                                  uninstalls programs or moves your files without asking.
      -NoElevate -NoOpen
      -OutRoot <folder>           where to save reports (default: .\Reports next to this script)
#>
[CmdletBinding()]
param(
    [ValidateSet('Scan','Clean','Both','Recent','FreshStart')][string]$Action = 'Both',
    [ValidateSet('Quick','Full')][string]$ScanType = 'Quick',
    [switch]$Deep,
    [ValidateRange(1, 520)][int]$Weeks = 2,
    [switch]$OfflineScan,
    [switch]$NoPrompt,
    [switch]$NoElevate,
    [switch]$NoOpen,
    [string]$OutRoot
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:ToolVersion    = '1.3.0'
$script:Start          = Get-Date
$ScriptDir             = Split-Path -Parent $PSCommandPath
try { $Host.UI.RawUI.WindowTitle = 'PC Cleaner' } catch {}

# A downloaded ZIP marks every file as "from the internet", which makes Windows block them.
try { Get-ChildItem -LiteralPath $ScriptDir -Recurse -File -ErrorAction Stop | Unblock-File -ErrorAction SilentlyContinue } catch {}

#region ===================== elevation =====================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$script:IsAdmin = Test-IsAdmin
# Recent and FreshStart work on the signed-in user's own files and settings, so they run without elevation.
if (-not $script:IsAdmin -and -not $NoElevate -and $Action -notin 'FreshStart', 'Recent') {
    Write-Host 'Asking for administrator rights (needed to scan and clean system areas)...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" } }
        else { $v = [string]$kv.Value; if ($v.EndsWith('\')) { $v += '\' }; $a += "-$($kv.Key)"; $a += ('"{0}"' -f $v) }
    }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($a -join ' ') -ErrorAction Stop; exit 0 }
    catch { Write-Host 'Administrator rights were not given. Continuing in LIMITED mode - some checks and the system-wide clean-up will be skipped.' -ForegroundColor Yellow }
}
#endregion

#region ===================== whose account to look at =====================
# A standard user who elevates with a separate administrator account gets the administrator's
# %LOCALAPPDATA%, HKCU and so on. Look at the account signed in to this desktop instead.
$script:UserProfile  = $env:USERPROFILE
$script:LocalAppData = $env:LOCALAPPDATA
$script:AppData      = $env:APPDATA
$script:HKCU         = 'HKCU:'
$script:OtherUser    = $null
try {
    $mySession = (Get-Process -Id $PID).SessionId
    $exp = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Where-Object { $_.SessionId -eq $mySession } | Select-Object -First 1
    if ($exp) {
        $own = Invoke-CimMethod -InputObject $exp -MethodName GetOwner -ErrorAction Stop
        if ($own.ReturnValue -eq 0 -and $own.User) {
            $sid = (New-Object System.Security.Principal.NTAccount($own.Domain, $own.User)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
                $prof = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction Stop).LocalPath
                if ($prof -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid")) {
                    $sf = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -ErrorAction SilentlyContinue
                    $script:OtherUser    = "$($own.Domain)\$($own.User)"
                    $script:UserProfile  = $prof
                    $script:LocalAppData = if ($sf -and $sf.'Local AppData') { $sf.'Local AppData' } else { Join-Path $prof 'AppData\Local' }
                    $script:AppData      = if ($sf -and $sf.AppData) { $sf.AppData } else { Join-Path $prof 'AppData\Roaming' }
                    $script:HKCU         = "Registry::HKEY_USERS\$sid"
                }
            }
        }
    }
} catch {}
$script:UserTemp = if ($script:OtherUser) { Join-Path $script:LocalAppData 'Temp' } else { $env:TEMP }
#endregion

#region ===================== helpers =====================
$script:Results    = New-Object System.Collections.ArrayList
$script:FreedBytes = 0.0
$script:SigCache   = @{}
$script:ScanRan    = $false
$script:OtherAV    = @()
$script:Do         = @{}
$script:Asked      = 0
$script:DefenderRx = '^(Windows|Microsoft) Defender'

function Add-R {
    param([string]$Cat, [string]$Check, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status, [string]$Detail = '')
    [void]$script:Results.Add([pscustomobject]@{ Category = $Cat; Check = $Check; Status = $Status; Detail = $Detail })
    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Gray' } }
    Write-Host ('   [{0,-4}] {1}' -f $Status, $Check) -ForegroundColor $color
    if ($Detail) { Write-Host ('          ' + $Detail) -ForegroundColor DarkGray }
}
function Invoke-Section([string]$Name, [scriptblock]$Body) {
    Write-Host ''
    Write-Host "== $Name ==" -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Body } catch { Add-R $Name 'Section error' 'INFO' ('This part hit an error and may be incomplete: ' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')') }
    Write-Host ('   ({0:N0}s)' -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}
function HE([object]$s) { if ($null -eq $s) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Short([string]$s, [int]$n = 200) { if (-not $s) { return '' }; $s = ($s -replace '\s+', ' ').Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) + '...' } else { $s } }
# -NeverAuto: with -NoPrompt the answer is "no" (anything permanent, or that touches your programs or files).
function Read-YesNo([string]$Prompt, [bool]$Default = $false, [switch]$NeverAuto) {
    if ($NoPrompt) { return (-not $NeverAuto) }
    $script:Asked++
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    Write-Host ''
    $r = Read-Host "  $Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
    return ($r -match '^\s*(y|yes)\s*$')
}
function Format-Bytes([double]$n) {
    if ($n -ge 1GB) { return ('{0:N2} GB' -f ($n / 1GB)) }
    if ($n -ge 1MB) { return ('{0:N1} MB' -f ($n / 1MB)) }
    if ($n -ge 1KB) { return ('{0:N0} KB' -f ($n / 1KB)) }
    return ('{0:N0} B' -f $n)
}
function Get-FreeBytes { try { [double](Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop).FreeSpace } catch { 0.0 } }
function Get-Reg([string]$Path, [string]$Name) { $p = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue; if ($p) { $p.$Name } }
function Read-Json([string]$Path) { try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { $null } }
function Get-Domain([string]$Url) { if (-not $Url) { return '' }; try { ([uri]$Url).Host } catch { $Url } }
function Format-RegPath([string]$k) { $k -replace '^Registry::HKEY_USERS\\[^\\]+', 'HKCU' -replace '^HK(LM|CU):', 'HK$1' }
function Get-FolderSize([string]$Path) {
    $s = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($s) { [double]$s } else { 0.0 }
}
function ConvertTo-InstallDate([string]$s) { if ($s -match '^\d{8}$') { try { return [datetime]::ParseExact($s, 'yyyyMMdd', $null) } catch {} }; $null }
function Get-UserFolder([string]$Name, [string]$Default) {
    $v = Get-Reg "$script:HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" $Name
    if ($v) { [Environment]::ExpandEnvironmentVariables(($v -replace '(?i)%USERPROFILE%', $script:UserProfile)) } else { Join-Path $script:UserProfile $Default }
}
function Get-DownloadsPath { Get-UserFolder '{374DE290-123F-4565-9164-39C4925E467B}' 'Downloads' }

# Folders that must never be emptied, whatever a path or environment variable resolves to.
$script:Protected = @("$env:SystemDrive\", $env:WinDir, "$env:WinDir\System32", $env:USERPROFILE, $script:UserProfile, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, $script:LocalAppData, $script:AppData, $env:PUBLIC) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() } | Sort-Object -Unique
function Test-SafeTarget([string]$Path) {
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\').ToLower() } catch { return $false }
    if ($full.Length -le 3) { return $false }
    return ($script:Protected -notcontains $full)
}

# Deletes a file or folder tree and returns the bytes actually freed. Never follows links/junctions out of
# the target. Files created or changed after $Cutoff are kept, so programs running right now don't break.
function Remove-Tree([IO.FileSystemInfo]$Item, [datetime]$Cutoff = [datetime]::MaxValue) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 0.0 }
    if ($Item -is [IO.DirectoryInfo]) {
        $n = 0.0
        foreach ($c in @(Get-ChildItem -LiteralPath $Item.FullName -Force -ErrorAction SilentlyContinue)) { $n += Remove-Tree $c $Cutoff }
        try { $Item.Delete() } catch {}
        return $n
    }
    if ($Item.LastWriteTime -gt $Cutoff -or $Item.CreationTime -gt $Cutoff) { return 0.0 }
    $len = [double]$Item.Length
    try { if ($Item.IsReadOnly) { $Item.IsReadOnly = $false }; $Item.Delete(); return $len } catch { return 0.0 }
}

# Empties folders / deletes files (wildcards allowed) and reports the space freed. Silent if none of the paths exist.
function Clear-Group([string]$Label, [string[]]$Paths, [string]$Note = '', [int]$MinAgeHours = 0) {
    $cutoff = if ($MinAgeHours -gt 0) { (Get-Date).AddHours(-$MinAgeHours) } else { [datetime]::MaxValue }
    $items = foreach ($p in $Paths) {
        if (-not $p) { continue }
        if ($p.Contains('*')) { Get-Item -Path $p -Force -ErrorAction SilentlyContinue }
        elseif (Test-Path -LiteralPath $p) { Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    $items = @($items | Where-Object { $_ })
    if ($items.Count -eq 0) { return }
    $freed = 0.0
    foreach ($it in $items) {
        if (-not (Test-SafeTarget $it.FullName)) { Add-R 'Clean-up' $Label 'WARN' "Skipped $($it.FullName) - it looked like a system or profile folder"; continue }
        if ($it -is [IO.DirectoryInfo] -and -not ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($c in @(Get-ChildItem -LiteralPath $it.FullName -Force -ErrorAction SilentlyContinue)) { $freed += Remove-Tree $c $cutoff }
        } else { $freed += Remove-Tree $it $cutoff }
    }
    $script:FreedBytes += $freed
    $d = "Freed $(Format-Bytes $freed)"; if ($Note) { $d += " - $Note" }
    Add-R 'Clean-up' $Label 'PASS' $d
}

function Resolve-Exe([string]$p) {
    if (-not $p) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^(?i)\\SystemRoot\\', "$env:WinDir\"
    try { if ([IO.Path]::IsPathRooted($p)) { return $p } } catch { return $p }
    $c = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    $p
}
function Get-ExePath([string]$Cmd) {
    if (-not $Cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    $p = $null
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $p = $c.Substring(1, $e - 1) } }
    elseif ($c -match '^(.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|scr|dll|lnk))(\s|,|$)') { $p = $Matches[1] }
    else { $p = ($c -split '\s+')[0] }
    Resolve-Exe $p
}
function Get-SigStatus([string]$Path) {
    if (-not $Path) { return 'Missing' }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = 'Missing'
    $exists = try { Test-Path -LiteralPath $Path -PathType Leaf } catch { $false }
    if ($exists) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r = switch ([string]$s.Status) {
                'Valid'        { 'Signed: ' + $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
                'NotSigned'    { 'Not signed' }
                'HashMismatch' { 'Broken signature' }
                default        { "Not signed ($($s.Status))" }
            }
        } catch { $r = 'Unknown' }
    }
    $script:SigCache[$Path] = $r
    $r
}

$script:RiskyCmd     = '(?i)(powershell|pwsh)(\.exe)?"?\s.*\s-(e|ec|enc|encodedcommand)\s|\bmshta\b|\bwscript\b|\bcscript\b|regsvr32.*(/i:|scrobj)|certutil.*-(urlcache|decode)|\bbitsadmin\b|downloadstring|downloadfile|invoke-webrequest|\biwr\b|frombase64string|--load-extension|DisableLoadExtensionCommandLineSwitch'
$script:RiskyPath    = '(?i)\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\Downloads\\|\\AppData\\Roaming\\[^\\]+$|^[a-z]:\\ProgramData\\[^\\]+$'
$script:UserWritable = '(?i)^[a-z]:\\Users\\|^[a-z]:\\ProgramData\\'
$script:UrlOpeners   = '(?i)^(chrome|msedge|firefox|iexplore|brave|opera|launcher|vivaldi|explorer|cmd|rundll32)\.exe$'
$script:KnownAdware  = '(?i)onelaunch|wavesor|wave ?browser|swupdater|pcappstore|shift ?browser|webcompanion|segurazo|santivirus|bytefence|reimage|restoro|mindspark|search ?protect|conduit|chromeloader|choziosi'
$script:KnownSite    = '(?i)(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.[a-z.]+|ecosia\.org|startpage\.com|search\.brave\.com|brave\.com|qwant\.com|yandex\.[a-z.]+|baidu\.com|naver\.com|perplexity\.ai|chatgpt\.com|msn\.com|microsoft\.com|live\.com|office\.com|outlook\.com)$'
$script:HijackWords  = '(?i)search|start|home|tab|feed|news|portal'
$script:ScareWords   = '(?i)virus|antivirus|security|protect|defender|scan|mcafee|norton|avast|cleaner|alert|warning|support'
$script:PupRx        = '(?i)toolbar|search ?protect|mywebsearch|conduit|babylon|wajam|onelaunch|webdiscover|segurazo|santivirus|safebytes|pc ?accelerate|reimage|restoro|bytefence|driver ?(booster|support|easy|updater|genius|reviver)|advanced ?systemcare|pc ?(optimizer|speed ?up|mechanic|app ?store|protect)|systweak|outbyte|wave ?browser|shopping ?(assistant|helper)|web ?companion|mindspark|crossrider|superfish|spigot|opencandy|installcore|relevant ?knowledge|dealply|sweetim|delta ?search|webadvisor|totalav|scanguard|shield ?antivirus'
$script:AdwareExt    = '(?i)search ?(manager|protect|bar|tab|plus)|search for (chrome|edge|firefox)|(music|movie|video|sports|game|recipe|package|flight|track) ?search|safe ?search|pdf ?(converter|maker|pro)|maps ?galaxy|weather ?(forecast|now)|coupon|cashback|web ?companion|webadvisor'

# Judges a start-up command line: WARN only when there is a concrete reason to look at it.
function Get-Verdict([string]$Command) {
    $target = Get-ExePath $Command
    $leaf = try { [IO.Path]::GetFileName($target) } catch { '' }
    if ($leaf -ieq 'rundll32.exe' -and $Command -match '(?i)rundll32(\.exe)?"?\s+"?([^",]+\.dll)') { $target = Resolve-Exe $Matches[2] }
    $sig = Get-SigStatus $target
    $why = New-Object System.Collections.Generic.List[string]
    if ($Command -match $script:KnownAdware) { $why.Add('belongs to known adware') }
    if ($Command -match $script:RiskyCmd) { $why.Add('starts a script, a download command or a hidden browser extension') }
    if ($Command -match '(?i)https?://' -and $leaf -match $script:UrlOpeners) { $why.Add('opens a website when it runs (typical of adware)') }
    if ($target -and $target -match $script:RiskyPath -and $sig -notlike 'Signed: *') { $why.Add('runs from a temp, download or public folder without a valid signature') }
    if ($sig -eq 'Broken signature') { $why.Add('its digital signature is broken, so the file was modified') }
    elseif ($sig -like 'Not signed*' -and $target -match $script:UserWritable) { $why.Add('not digitally signed and stored in a user folder') }
    $signer = if ($sig -like 'Signed: *') { $sig.Substring(8) } else { '' }
    $note = (Short $Command 160) + '  |  ' + $(if ($sig -eq 'Missing') { 'file not found (leftover entry)' } else { $sig })
    if ($why.Count) { $note += '  |  REVIEW: ' + ($why -join '; ') }
    [pscustomobject]@{ Status = $(if ($why.Count) { 'WARN' } else { 'INFO' }); Note = $note; Signer = $signer }
}

# ---- browsers ----
$script:BrowserRoots = [ordered]@{
    'Chrome'   = "$script:LocalAppData\Google\Chrome\User Data"
    'Edge'     = "$script:LocalAppData\Microsoft\Edge\User Data"
    'Brave'    = "$script:LocalAppData\BraveSoftware\Brave-Browser\User Data"
    'Vivaldi'  = "$script:LocalAppData\Vivaldi\User Data"
    'Opera'    = "$script:AppData\Opera Software\Opera Stable"
    'Opera GX' = "$script:AppData\Opera Software\Opera GX Stable"
}
$script:BrowserProc   = @{ 'Chrome' = 'chrome'; 'Edge' = 'msedge'; 'Brave' = 'brave'; 'Vivaldi' = 'vivaldi'; 'Opera' = 'opera'; 'Opera GX' = 'opera'; 'Firefox' = 'firefox' }
$script:BrowserScheme = @{ 'Chrome' = 'chrome'; 'Edge' = 'edge'; 'Brave' = 'brave'; 'Vivaldi' = 'vivaldi'; 'Opera' = 'opera'; 'Opera GX' = 'opera' }

function Get-FixHint([string]$Browser, [string]$What) {
    $s = $script:BrowserScheme[$Browser]; if (-not $s) { $s = 'chrome' }
    switch ($What) {
        'notifications' { "in $Browser go to $($s)://settings/content/notifications and remove every site under 'Allowed to send notifications'" }
        'extensions'    { "in $Browser go to $($s)://extensions and click Remove on it" }
        'apps'          { "in $Browser go to $($s)://apps, right-click it and choose Remove (or Uninstall), then clear that site's data in Settings > Privacy > Site settings" }
        'reset'         { "in $Browser go to $($s)://settings/reset and choose 'Restore settings to their original defaults' (keeps bookmarks, history and passwords)" }
    }
}
function Get-OpenBrowsers { @($script:BrowserProc.GetEnumerator() | Where-Object { Get-Process -Name $_.Value -ErrorAction SilentlyContinue } | ForEach-Object { $_.Key } | Where-Object { $_ -ne 'Opera GX' } | Sort-Object -Unique) }
function Close-Browsers {
    $names = @($script:BrowserProc.Values | Sort-Object -Unique)
    $procs = @(Get-Process -Name $names -ErrorAction SilentlyContinue)
    if (-not $procs.Count) { return }
    Write-Host '   Closing browsers...' -ForegroundColor DarkGray
    foreach ($p in $procs) { try { if ($p.MainWindowHandle -ne [IntPtr]::Zero) { [void]$p.CloseMainWindow() } } catch {} }
    Start-Sleep -Seconds 5
    Get-Process -Name $names -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
function Get-ExtName($Manifest, [string]$Dir, [string]$Id) {
    if (-not $Manifest) { return $Id }
    $name = [string]$Manifest.name
    if ($name -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        foreach ($loc in @(@($Manifest.default_locale, 'en', 'en_US', 'en_GB') | Where-Object { $_ })) {
            $msgs = Read-Json (Join-Path $Dir "_locales\$loc\messages.json")
            if (-not $msgs) { continue }
            $hit = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1
            if ($hit) { return [string]$hit.Value.message }
        }
    }
    if ($name) { $name } else { $Id }
}
# Changes every "allowed" notification permission to "blocked" in a closed browser's Preferences file.
# Writes to a temporary file first and swaps it in, so a failure can't leave a half-written file.
function Block-NotificationSites([string]$ProfileDir) {
    $ErrorActionPreference = 'Stop'
    $pf = Join-Path $ProfileDir 'Preferences'
    $j = Get-Content -LiteralPath $pf -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $n = $j.profile.content_settings.exceptions.notifications
    $count = 0
    if ($n) { foreach ($p in @($n.PSObject.Properties)) { if ($p.Value.setting -eq 1) { $p.Value.setting = 2; $count++ } } }
    if ($count -eq 0) { return 0 }
    $out = $j | ConvertTo-Json -Depth 100 -Compress
    $null = $out | ConvertFrom-Json -ErrorAction Stop
    $tmp = "$pf.pccleaner-tmp"
    $bak = "$pf.pccleaner-backup"
    try {
        [IO.File]::WriteAllText($tmp, $out, (New-Object System.Text.UTF8Encoding($false)))
        if (-not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $pf -Destination $bak -Force }
        [IO.File]::Replace($tmp, $pf, [NullString]::Value)
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $count
}

function Split-Command([string]$Cmd) {
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return @($c.Substring(1, $e - 1), $c.Substring($e + 1).Trim()) } }
    if ($c -match '^(.+?\.exe)(\s+(.*))?$') { return @($Matches[1], [string]$Matches[3]) }
    @($c, '')
}
function Get-UninstallEntries { foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',"$script:HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") { Get-ItemProperty -Path $k -ErrorAction SilentlyContinue } }
function Invoke-Uninstall([string]$Name, [string]$Command) {
    Write-Host ''
    Write-Host "   Opening the uninstaller for $Name - follow its steps. Choose 'remove completely' if it asks." -ForegroundColor Yellow
    try {
        if ($Command -match '(?i)msiexec(\.exe)?"?\s+/[IX]\s*(\{[0-9A-F-]+\})') { $p = Start-Process -FilePath "$env:WinDir\System32\msiexec.exe" -ArgumentList "/x $($Matches[2])" -PassThru -ErrorAction Stop }
        else {
            $parts = Split-Command ([Environment]::ExpandEnvironmentVariables($Command))
            $p = if ($parts[1]) { Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -PassThru -ErrorAction Stop } else { Start-Process -FilePath $parts[0] -PassThru -ErrorAction Stop }
        }
        $p.WaitForExit()
    } catch { Add-R 'Uninstall' $Name 'WARN' "Could not start its uninstaller: $($_.Exception.Message.Trim()) - remove it in Settings > Apps"; return }
    if (-not $NoPrompt) { Read-Host '   When its uninstaller has finished (or if no window appeared), press Enter here' | Out-Null }
    if (Get-UninstallEntries | Where-Object { $_.DisplayName -eq $Name }) { Add-R 'Uninstall' $Name 'WARN' 'Still installed - its uninstaller may need a restart to finish, or it was cancelled. Otherwise remove it in Settings > Apps.' }
    else { Add-R 'Uninstall' $Name 'PASS' 'Uninstalled' }
}
#endregion

#region ===================== output locations =====================
if (-not $OutRoot) { $OutRoot = Join-Path $ScriptDir 'Reports' }
$RunDir = Join-Path $OutRoot (Get-Date -Format 'yyyy-MM-dd_HHmmss')
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
$ReportPath = Join-Path $RunDir 'report.html'
try { Start-Transcript -Path (Join-Path $RunDir 'log.txt') -ErrorAction Stop | Out-Null; $script:Transcript = $true } catch { $script:Transcript = $false }

$doScan  = $Action -in 'Scan', 'Both'
$doClean = $Action -in 'Clean', 'Both'

Write-Host ''
Write-Host "PC Cleaner v$($script:ToolVersion)" -ForegroundColor Cyan
$modeText = switch ($Action) { 'Recent' { "Recent downloads and programs (last $Weeks week(s))" } 'FreshStart' { 'Fresh start guide' } default { $Action + $(if ($doScan) { "   Scan: $ScanType" }) + $(if ($Deep) { '   Deep clean' }) } }
Write-Host "Mode: $modeText   Admin: $($script:IsAdmin)" -ForegroundColor DarkGray
if ($script:OtherUser) { Write-Host "Checking the account signed in to this PC: $($script:OtherUser) (administrator rights come from $env:USERDOMAIN\$env:USERNAME)." -ForegroundColor Yellow }
if (-not $script:IsAdmin -and $Action -notin 'FreshStart', 'Recent') { Write-Host 'Not running as administrator: the second-opinion scan, threat removal and system-wide clean-up will be skipped.' -ForegroundColor Yellow }
$script:FreeBefore = Get-FreeBytes
#endregion

#region ===================== quick look before asking anything =====================
$script:Apps = @(@(Get-UninstallEntries | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName }) | Sort-Object DisplayName -Unique)

if ($doScan -or $doClean) {
    Write-Host ''
    Write-Host 'Taking a quick look first...' -ForegroundColor DarkGray

    $script:AVs = @()
    try {
        foreach ($av in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $hex = '{0:x6}' -f [int]$av.productState
            $script:AVs += [pscustomobject]@{ Name = [string]$av.displayName; On = ($hex.Substring(2, 2) -in '10', '11'); Current = ($hex.Substring(4, 2) -eq '00') }
        }
    } catch { $script:AVError = $_.Exception.Message }
    $script:OtherAV = @($script:AVs | Where-Object { $_.On -and $_.Name -notmatch $script:DefenderRx } | ForEach-Object { $_.Name })
    $script:Mp = try { Get-MpComputerStatus -ErrorAction Stop } catch { $null }
    $script:MpPref = try { Get-MpPreference -ErrorAction Stop } catch { $null }
    $script:DefenderOn = [bool]($script:Mp -and $script:Mp.AntivirusEnabled -and $script:Mp.RealTimeProtectionEnabled)

    # Programs worth offering to uninstall: bundleware, and security products that are installed but switched
    # off (usually expired trials, which show "your PC is at risk" pop-ups to sell a subscription). Only the
    # security product itself is offered - never the same vendor's browser, password manager, VPN or parental app.
    $offVendors = @($script:AVs | Where-Object { -not $_.On -and $_.Name -notmatch $script:DefenderRx } | ForEach-Object { ($_.Name -split '\s+')[0] } | Where-Object { $_.Length -ge 3 } | Sort-Object -Unique)
    $script:Removable = New-Object System.Collections.ArrayList
    foreach ($a in $script:Apps) {
        if (-not $a.UninstallString) { continue }
        $dn = [string]$a.DisplayName
        $why = $null
        foreach ($v in $offVendors) {
            $ve = [regex]::Escape($v)
            $isSuite = $dn -match "(?i)^\s*$ve\s*$" -or ($dn -match "(?i)\b$ve\b" -and $dn -match '(?i)anti-?virus|security|protection|livesafe|total|360|endpoint|safety' -and $dn -notmatch '(?i)browser|password|true ?key|vpn|family|safe ?connect|identity|backup')
            if ($isSuite) { $why = "a $v security product that is switched off - usually an expired trial, and these show 'your PC is at risk' pop-ups to sell a subscription. Only uninstall it if you don't pay for it; Microsoft Defender already protects you"; break }
        }
        if (-not $why -and $dn -match $script:PupRx) { $why = 'often bundled with other software or pushed by ads, and shows pop-ups or changes your browser' }
        if ($why) { [void]$script:Removable.Add([pscustomobject]@{ Name = $dn; Why = $why; Uninstall = [string]$a.UninstallString; Do = $false }) }
    }

    $script:Profiles = @(foreach ($b in $script:BrowserRoots.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $b.Value)) { continue }
        $dirs = if ($b.Key -like 'Opera*') { @(Get-Item -LiteralPath $b.Value) } else { @(Get-ChildItem -LiteralPath $b.Value -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'System Profile', 'Guest Profile' }) }
        foreach ($d in $dirs) {
            $pf = Join-Path $d.FullName 'Preferences'
            if (-not (Test-Path -LiteralPath $pf)) { continue }
            $prefs = Read-Json $pf
            $n = if ($prefs) { $prefs.profile.content_settings.exceptions.notifications } else { $null }
            $sites = @(); if ($n) { $sites = @($n.PSObject.Properties | Where-Object { $_.Value.setting -eq 1 } | ForEach-Object { ($_.Name -split ',')[0] }) }
            [pscustomobject]@{ Browser = $b.Key; Profile = $(if ($b.Key -like 'Opera*') { 'Default' } else { $d.Name }); Path = $d.FullName; Prefs = $prefs; Unreadable = (-not $prefs); Secure = (Read-Json (Join-Path $d.FullName 'Secure Preferences')); NotifSites = $sites }
        }
    })

    $regExt = @{}
    foreach ($k in 'HKLM:\SOFTWARE\Google\Chrome\Extensions','HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\Extensions',"$script:HKCU\SOFTWARE\Google\Chrome\Extensions",'HKLM:\SOFTWARE\Microsoft\Edge\Extensions','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions',"$script:HKCU\SOFTWARE\Microsoft\Edge\Extensions") {
        foreach ($e in @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) { $regExt[$e.PSChildName] = Format-RegPath $k }
    }
    $script:Extensions = New-Object System.Collections.ArrayList
    foreach ($pr in $script:Profiles) {
        $seenIds = @{}
        $extDir = Join-Path $pr.Path 'Extensions'
        foreach ($ext in @(Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Temp' })) {
            $ver = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if (-not $ver) { continue }
            $seenIds[$ext.Name] = $true
            $m = Read-Json (Join-Path $ver.FullName 'manifest.json')
            $name = Get-ExtName $m $ver.FullName $ext.Name
            $takeover = New-Object System.Collections.Generic.List[string]
            $ov = if ($m) { $m.chrome_settings_overrides } else { $null }
            if ($ov) {
                if ($ov.search_provider -and $ov.search_provider.search_url) { $d = Get-Domain $ov.search_provider.search_url; if ($d -and $d -notmatch $script:KnownSite) { $takeover.Add("search engine (sends your searches to $d)") } }
                if ($ov.homepage) { $d = Get-Domain $ov.homepage; if ($d -and $d -notmatch $script:KnownSite) { $takeover.Add("home page ($d)") } }
                foreach ($u in @($ov.startup_pages)) { $d = Get-Domain $u; if ($d -and $d -notmatch $script:KnownSite) { $takeover.Add("start-up page ($d)") } }
            }
            $st = $null
            foreach ($src in @($pr.Secure, $pr.Prefs)) { if ($src -and $src.extensions -and $src.extensions.settings) { $s = $src.extensions.settings.($ext.Name); if ($s) { $st = $s; break } } }
            $off = [bool]($st -and ((@($st.disable_reasons) | Where-Object { $_ -and $_ -ne 0 }) -or $st.state -eq 0))
            $kind = if ($takeover.Count) { 'Hijacker' } elseif ($name -match $script:AdwareExt) { 'Adware' } else { '' }
            [void]$script:Extensions.Add([pscustomobject]@{ Browser = $pr.Browser; Where = "$($pr.Browser) ($($pr.Profile))"; Id = $ext.Name; Name = $name; Kind = $kind; Takeover = ($takeover -join ', '); Off = $off; Registry = $regExt[$ext.Name]; Path = '' })
        }
        # Extensions loaded from a folder outside the browser (unpacked = 4, command line = 8) are how loaders like ChromeLoader work.
        foreach ($src in @($pr.Secure, $pr.Prefs)) {
            if (-not ($src -and $src.extensions -and $src.extensions.settings)) { continue }
            foreach ($e in @($src.extensions.settings.PSObject.Properties)) {
                if ($seenIds[$e.Name] -or $e.Value.location -notin 4, 8) { continue }
                $seenIds[$e.Name] = $true
                $path = [string]$e.Value.path
                $m = if ($path) { Read-Json (Join-Path $path 'manifest.json') } else { $null }
                $name = if ($m) { Get-ExtName $m $path $e.Name } else { $e.Name }
                [void]$script:Extensions.Add([pscustomobject]@{ Browser = $pr.Browser; Where = "$($pr.Browser) ($($pr.Profile))"; Id = $e.Name; Name = $name; Kind = 'Sideloaded'; Takeover = ''; Off = $false; Registry = $null; Path = $path })
            }
        }
    }
    foreach ($prof in @(Get-ChildItem -LiteralPath "$script:AppData\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue)) {
        $ej = Read-Json (Join-Path $prof.FullName 'extensions.json')
        if (-not $ej) { continue }
        foreach ($ad in @($ej.addons | Where-Object { $_.location -eq 'app-profile' })) {
            $nm = [string]$ad.defaultLocale.name
            [void]$script:Extensions.Add([pscustomobject]@{ Browser = 'Firefox'; Where = "Firefox ($($prof.Name))"; Id = [string]$ad.id; Name = $nm; Kind = $(if ($nm -match $script:AdwareExt) { 'Adware' } else { '' }); Takeover = ''; Off = (-not $ad.active); Registry = $null; Path = '' })
        }
    }

    $script:Policies = @(foreach ($k in 'HKLM:\SOFTWARE\Policies\Google\Chrome',"$script:HKCU\SOFTWARE\Policies\Google\Chrome",'HKLM:\SOFTWARE\Policies\Microsoft\Edge',"$script:HKCU\SOFTWARE\Policies\Microsoft\Edge",'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave',"$script:HKCU\SOFTWARE\Policies\BraveSoftware\Brave",'HKLM:\SOFTWARE\Policies\Mozilla\Firefox',"$script:HKCU\SOFTWARE\Policies\Mozilla\Firefox") {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $keys = @(Get-Item -LiteralPath $k) + @(Get-ChildItem -LiteralPath $k -Recurse -ErrorAction SilentlyContinue)
        $vals = @(foreach ($key in $keys) { foreach ($vn in $key.GetValueNames()) { "$vn=$($key.GetValue($vn))" } })
        $sum = Short ($vals -join '; ') 300
        if ($sum -match 'ScarewareBlockerProtectionEnabled=0') { $sum += "  (this switches OFF Edge's scam pop-up blocker)" }
        [pscustomobject]@{ Key = $k; Display = (Format-RegPath $k); Summary = $(if ($sum) { $sum } else { '(empty)' }) }
    })
    $script:Managed = $false
    try { $script:Managed = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    if (-not $script:Managed) { try { if ((& "$env:WinDir\System32\dsregcmd.exe" /status 2>$null) -match 'AzureAdJoined\s*:\s*YES') { $script:Managed = $true } } catch {} }
    $script:RecycleBytes = if ($script:OtherUser) { 0.0 } else { try { [double]((New-Object -ComObject Shell.Application).NameSpace(10).Items() | Measure-Object -Property Size -Sum).Sum } catch { 0.0 } }
    $script:OldWin = Join-Path $env:SystemDrive 'Windows.old'
}
#endregion

#region ===================== questions (all asked up front) =====================
if ($doScan -or $doClean) {
    if (-not $NoPrompt) {
        Write-Host ''
        Write-Host '== A few questions first. After these, PC Cleaner runs by itself and you can leave it. ==' -ForegroundColor Cyan
        Write-Host '   Type y or n and press Enter. Just pressing Enter picks the answer in capitals.' -ForegroundColor DarkGray
    }

    if ($doScan -and $script:IsAdmin) { $script:Do.RemoveThreats = Read-YesNo 'If the virus scan finds threats, remove them straight away?' $true }
    if ($doScan -and $script:IsAdmin -and $script:DefenderOn -and $script:MpPref -and $script:MpPref.PUAProtection -ne 1) {
        $script:Do.EnablePUA = Read-YesNo "Turn on Defender's blocking of unwanted apps (adware, bundled junk, fake optimisers)? Microsoft recommends it; it is $(if ($script:MpPref.PUAProtection -eq 2) { 'only watching, not blocking,' } else { 'off' }) at the moment" $true
    }

    $notif = @($script:Profiles | Where-Object { $_.NotifSites.Count })
    if ($doScan -and $notif.Count) {
        Write-Host ''
        Write-Host '  These websites are allowed to send you pop-up notifications. Fake "virus found",' -ForegroundColor Yellow
        Write-Host '  "McAfee" or "Norton" warnings almost always come from sites like these:' -ForegroundColor Yellow
        foreach ($p in $notif) { foreach ($s in $p.NotifSites) { Write-Host "     $($p.Browser) ($($p.Profile)): $s" -ForegroundColor Yellow } }
        $script:Do.BlockNotif = Read-YesNo 'Block all of these sites from sending notifications? (stops the spam pop-ups)' $true
    }

    if ($doScan -and $script:Policies.Count -and -not $script:Managed) {
        Write-Host ''
        Write-Host '  Browser policies are set on this PC (the browser shows "Managed by your organization").' -ForegroundColor Yellow
        Write-Host '  This PC is not run by a company or school, so a program probably added them to force an' -ForegroundColor Yellow
        Write-Host '  extension, search engine or home page. Parental-control software also uses them, so check:' -ForegroundColor Yellow
        foreach ($pol in $script:Policies) { Write-Host "     $($pol.Display): $($pol.Summary)" -ForegroundColor Yellow }
        if (-not $script:IsAdmin -and ($script:Policies | Where-Object { $_.Key -like 'HKLM:*' })) { Write-Host '     (the HKLM ones need administrator rights to remove)' -ForegroundColor DarkGray }
        $script:Do.RemovePolicies = Read-YesNo 'Remove these browser policies? Say no if you set up parental controls. (A backup is saved in the report folder.)' $false -NeverAuto
    }

    $open = @(Get-OpenBrowsers)
    if ($open.Count -and ($doClean -or $script:Do.BlockNotif)) {
        $what = @(); if ($script:Do.BlockNotif) { $what += 'fix the notification spam' }; if ($doClean) { $what += 'clean the browser cache fully' }
        $script:Do.CloseBrowsers = Read-YesNo "Close $($open -join ', ') now so PC Cleaner can $($what -join ' and ')? Save anything you are typing first. Your tabs come back when you reopen it." ([bool]$script:Do.BlockNotif) -NeverAuto
    }

    $flagged = @($script:Extensions | Where-Object { $_.Kind })
    if ($doScan -and $flagged.Count) {
        Write-Host ''
        Write-Host '  These browser extensions look like adware, take over your search engine, or were loaded from outside the browser:' -ForegroundColor Yellow
        foreach ($x in $flagged) { Write-Host "     $($x.Where): $($x.Name)$(if ($x.Takeover) { ' - changes your ' + $x.Takeover })" -ForegroundColor Yellow }
        if ($script:OtherUser) { Write-Host "     (remove them while signed in as $($script:OtherUser) - PC Cleaner can't open that account's browser)" -ForegroundColor DarkGray }
        else { $script:Do.OpenExt = Read-YesNo 'At the end, open the browser''s Extensions page so you can click Remove on them?' $true -NeverAuto }
    }

    if ($doScan -and $script:Removable.Count) {
        Write-Host ''
        Write-Host '  These programs are usually not wanted. Each one you say yes to has its own uninstaller' -ForegroundColor Yellow
        Write-Host '  opened near the end of the run - follow its steps there.' -ForegroundColor Yellow
        foreach ($r in $script:Removable) { $r.Do = Read-YesNo "Uninstall $($r.Name)? ($($r.Why))" $false -NeverAuto }
    }

    if ($doClean -and $script:RecycleBytes -gt 0) { $script:Do.EmptyBin = Read-YesNo "Empty the Recycle Bin ($(Format-Bytes $script:RecycleBytes))? Files in it can't be recovered afterwards." $false -NeverAuto }
    if ($doClean -and $Deep -and $script:IsAdmin) {
        $script:Do.Dism    = Read-YesNo 'Remove old copies of updated Windows files with DISM? (5-30 minutes; Windows would otherwise do this itself after 30 days)' $true
        $script:Do.WUCache = Read-YesNo 'Also clear the Windows Update download cache? Only needed if Windows Update is stuck or failing - Windows downloads anything it still needs again.' $false
        if (Test-Path -LiteralPath $script:OldWin) { $script:Do.WinOld = Read-YesNo 'Delete Windows.old (your previous Windows installation, often 10-30 GB)? You will no longer be able to go back to that version.' $false -NeverAuto }
    }

    if (-not $NoPrompt) {
        Write-Host ''
        if ($script:Asked) { Write-Host '  Thanks - that is everything. PC Cleaner now runs by itself.' -ForegroundColor Green }
        Write-Host ("  This takes about " + $(if ($doScan -and $ScanType -eq 'Full') { '1-2 hours (Full scan)' } else { '5-15 minutes' }) + '. The report opens in your browser at the end.') -ForegroundColor Green
        if (@($script:Removable | Where-Object { $_.Do }).Count) { Write-Host '  Come back near the end: the uninstallers you chose need you to click through them.' -ForegroundColor Green }
    }
    if ($script:Do.CloseBrowsers) { Close-Browsers; $script:BrowsersClosed = $true }
}
#endregion

#region ===================== SCAN AND FIX =====================
if ($doScan) {

    Invoke-Section 'Pop-ups, notifications and browser hijacks' {
        $any = $false
        foreach ($pr in $script:Profiles) {
            $where = "$($pr.Browser) ($($pr.Profile))"
            if ($pr.Unreadable) { Add-R 'Pop-ups' "Could not read settings: $where" 'INFO' "PC Cleaner couldn't read this profile's settings file, so check it by hand: $(Get-FixHint $pr.Browser 'notifications')"; continue }
            if (-not $pr.NotifSites.Count) { continue }
            $any = $true
            $list = $pr.NotifSites -join ', '
            if (-not $script:Do.BlockNotif) { Add-R 'Pop-ups' "Notification spam: $where" 'WARN' "Allowed to send notifications: $list  |  to stop them: $(Get-FixHint $pr.Browser 'notifications')"; continue }
            if (Get-Process -Name $script:BrowserProc[$pr.Browser] -ErrorAction SilentlyContinue) { Add-R 'Pop-ups' "Notification spam: $where" 'WARN' "$($pr.Browser) was open, so this could not be fixed automatically. Allowed: $list  |  to stop them: $(Get-FixHint $pr.Browser 'notifications')"; continue }
            try { $n = Block-NotificationSites $pr.Path; Add-R 'Pop-ups' "Notification spam: $where" 'PASS' "Blocked $n site(s) from sending notifications: $list" }
            catch { Add-R 'Pop-ups' "Notification spam: $where" 'WARN' "Could not change the setting ($($_.Exception.Message.Trim())). Allowed: $list  |  to stop them: $(Get-FixHint $pr.Browser 'notifications')" }
        }
        if (-not $any -and @($script:Profiles | Where-Object { -not $_.Unreadable }).Count) { Add-R 'Pop-ups' 'Websites allowed to send notifications' 'PASS' 'None' }
        if (Test-Path -LiteralPath "$script:AppData\Mozilla\Firefox\Profiles") { Add-R 'Pop-ups' 'Firefox notifications' 'INFO' "PC Cleaner can't read Firefox's list. Check it: Firefox > Settings > Privacy & Security > Permissions > Notifications > Settings, and remove sites you don't know." }

        foreach ($pr in $script:Profiles) {
            if (-not $pr.Prefs) { continue }
            $where = "$($pr.Browser) ($($pr.Profile))"
            $pp = $pr.Prefs.profile.content_settings.exceptions.popups
            if ($pp) { $allowed = @($pp.PSObject.Properties | Where-Object { $_.Value.setting -eq 1 } | ForEach-Object { ($_.Name -split ',')[0] }); if ($allowed.Count) { Add-R 'Pop-ups' "Pop-up windows allowed: $where" 'INFO' (($allowed -join ', ') + ' - remove any you do not know in the browser''s Site settings > Pop-ups') } }
            $sp = $pr.Prefs.default_search_provider_data.template_url_data
            if ($sp -and $sp.url) { $d = Get-Domain $sp.url; if ($d -and $d -notmatch $script:KnownSite) { Add-R 'Hijack' "Search engine: $where" 'WARN' "Set to $d - if you did not choose it, a hijacker did. To fix: $(Get-FixHint $pr.Browser 'reset')" } }
            if ($pr.Prefs.session.restore_on_startup -eq 4) {
                $urls = @($pr.Prefs.session.startup_urls | Where-Object { $_ })
                $bad = @($urls | Where-Object { $d = Get-Domain $_; $d -and $d -notmatch $script:KnownSite -and $d -match $script:HijackWords })
                if ($bad.Count) { Add-R 'Hijack' "Start-up pages: $where" 'WARN' (($bad -join ', ') + " - looks like a hijacked start page. To fix: $(Get-FixHint $pr.Browser 'reset')") }
                elseif ($urls.Count) { Add-R 'Hijack' "Start-up pages: $where" 'INFO' ($urls -join ', ') }
            }
            $hp = [string]$pr.Prefs.homepage
            if ($hp -and $pr.Prefs.homepage_is_newtabpage -ne $true) { $d = Get-Domain $hp; if ($d -and $d -notmatch $script:KnownSite -and $d -match $script:HijackWords) { Add-R 'Hijack' "Home page: $where" 'WARN' "$hp - looks like a hijacked home page. To fix: $(Get-FixHint $pr.Browser 'reset')" } }
            if ($pr.Prefs.extensions.ui.developer_mode -eq $true) { Add-R 'Hijack' "Developer mode: $where" 'INFO' 'Extension developer mode is on, which lets extensions be loaded from any folder. Switch it off on the Extensions page unless you build extensions.' }
        }

        foreach ($x in @($script:Extensions | Where-Object { $_.Kind -eq 'Hijacker' })) {
            Add-R 'Hijack' "$($x.Name) ($($x.Where))" 'WARN' ("Browser hijacker: it takes over your $($x.Takeover)" + $(if ($x.Off) { '. It is switched off at the moment but still installed' }) + ". To remove it: $(Get-FixHint $x.Browser 'extensions')")
        }
        foreach ($x in @($script:Extensions | Where-Object { $_.Kind -eq 'Sideloaded' })) {
            Add-R 'Hijack' "$($x.Name) ($($x.Where))" 'WARN' "Loaded from a folder outside the browser ($($x.Path)). Malware such as ChromeLoader installs extensions this way. Unless you made it yourself: $(Get-FixHint $x.Browser 'extensions'), then $(Get-FixHint $x.Browser 'reset')"
        }
        $seen = @{}
        foreach ($x in @($script:Extensions | Where-Object { $_.Registry })) {
            if ($seen[$x.Id]) { continue }; $seen[$x.Id] = $true
            $st = if ($x.Kind) { 'WARN' } else { 'INFO' }
            Add-R 'Hijack' "Added by a program: $($x.Name)" $st "A program on this PC puts this extension into $($x.Browser) (registry: $($x.Registry)), so it comes back if you only remove it in the browser$(if ($x.Kind) { ' - uninstall the program that came with it' })"
        }

        if ($script:Policies.Count) {
            if ($script:Managed) { Add-R 'Hijack' 'Browser policies' 'INFO' ('This PC is joined to a company or school, so browser policies are expected: ' + (($script:Policies | ForEach-Object { $_.Display }) -join ', ')) }
            else {
                foreach ($pol in $script:Policies) {
                    if ($script:Do.RemovePolicies -and ($pol.Key -notlike 'HKLM:*' -or $script:IsAdmin)) {
                        try {
                            $bk = Join-Path $RunDir ('policy-backup_' + ($pol.Display -replace '[:\\ ]+', '_') + '.reg')
                            $regPath = $pol.Key -replace '^Registry::HKEY_USERS\\', 'HKU\' -replace '^HK(LM|CU):\\', 'HK$1\'
                            & "$env:WinDir\System32\reg.exe" export $regPath $bk /y 2>&1 | Out-Null
                            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $bk)) { throw "the backup could not be saved (reg.exe code $LASTEXITCODE), so nothing was removed" }
                            Remove-Item -LiteralPath $pol.Key -Recurse -Force -ErrorAction Stop
                            Add-R 'Hijack' "Browser policy removed: $($pol.Display)" 'PASS' "Was: $($pol.Summary)  |  backup: $bk (double-click it to put it back)"
                        } catch { Add-R 'Hijack' "Browser policy: $($pol.Display)" 'WARN' "Not removed: $($_.Exception.Message.Trim())  |  $($pol.Summary)" }
                    } else { Add-R 'Hijack' "Browser policy: $($pol.Display)" 'WARN' "$($pol.Summary)  |  makes the browser say 'Managed by your organization'; hijackers use this to force extensions and search engines (parental controls use it too)" }
                }
            }
        } else { Add-R 'Hijack' 'Browser policies' 'PASS' 'None' }

        foreach ($f in "$env:ProgramFiles\Google\Chrome\Application\initial_preferences", "$env:ProgramFiles\Google\Chrome\Application\master_preferences", "${env:ProgramFiles(x86)}\Google\Chrome\Application\initial_preferences", "${env:ProgramFiles(x86)}\Google\Chrome\Application\master_preferences", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\initial_preferences", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\master_preferences", "$env:ProgramFiles\Mozilla Firefox\distribution\policies.json", "${env:ProgramFiles(x86)}\Mozilla Firefox\distribution\policies.json") {
            if ($f -and (Test-Path -LiteralPath $f)) { Add-R 'Hijack' "Browser start-up settings file: $(Split-Path -Leaf $f)" 'INFO' "$f exists. It sets up the browser's defaults; a normal home install doesn't have one. If the browser keeps getting the wrong search engine or home page, delete this file (as administrator) and reset the browser." }
        }
    }

    Invoke-Section 'Shortcuts and installed web apps' {
        $shell = New-Object -ComObject WScript.Shell
        $places = @((Get-UserFolder 'Desktop' 'Desktop'), "$env:PUBLIC\Desktop", "$script:AppData\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$script:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar") | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        $links = @(foreach ($pl in $places) { Get-ChildItem -LiteralPath $pl -Filter '*.lnk' -Recurse -File -Force -ErrorAction SilentlyContinue })
        $bad = 0; $apps = New-Object System.Collections.ArrayList
        foreach ($l in $links) {
            try { $s = $shell.CreateShortcut($l.FullName) } catch { continue }
            $leaf = try { [IO.Path]::GetFileName([string]$s.TargetPath) } catch { '' }
            if ($leaf -notmatch '(?i)^(chrome|msedge|brave|vivaldi|opera|launcher|firefox|chrome_proxy|msedge_proxy|brave_proxy)\.exe$') { continue }
            $lnkArgs = [string]$s.Arguments
            $name = [IO.Path]::GetFileNameWithoutExtension($l.Name)
            if ($lnkArgs -match '(?i)--app-id=') { [void]$apps.Add($name); if ($name -match $script:ScareWords) { $bad++; Add-R 'Shortcuts' "Web app: $name" 'WARN' "An installed web app with a security-sounding name ($($l.FullName)). Fake 'security check' sites install themselves like this and keep sending alerts. If you didn't install it: $(Get-FixHint $(if ($leaf -match 'msedge') { 'Edge' } else { 'Chrome' }) 'apps')" }; continue }
            $why = @()
            if ($lnkArgs -match '(?i)https?://') { $why += 'opens a website every time you start the browser' }
            if ($lnkArgs -match '(?i)--load-extension|DisableLoadExtensionCommandLineSwitch') { $why += 'loads a hidden extension (a known malware trick)' }
            if ($why.Count) { $bad++; Add-R 'Shortcuts' "Shortcut: $name" 'WARN' ("$($l.FullName) $($why -join ' and '): $(Short $lnkArgs 160)  |  delete this shortcut and pin the browser again from the Start menu") }
        }
        if ($apps.Count) { Add-R 'Shortcuts' 'Installed web apps' 'INFO' ((($apps | Sort-Object -Unique) -join ', ') + ' - remove any you do not recognise (chrome://apps or edge://apps)') }
        Add-R 'Shortcuts' 'Summary' $(if ($bad) { 'WARN' } else { 'PASS' }) "$($links.Count) shortcut(s) checked, $bad tampered with or suspicious"
    }

    Invoke-Section 'Security settings' {
        if ($script:AVError) { Add-R 'Security' 'Antivirus list' 'INFO' "Could not read Windows Security Center: $script:AVError" }
        foreach ($av in $script:AVs) {
            if ($av.On) { Add-R 'Security' "Antivirus: $($av.Name)" $(if ($av.Current) { 'PASS' } else { 'WARN' }) ('On, ' + $(if ($av.Current) { 'definitions up to date' } else { 'definitions OUT OF DATE - update it' })) }
            elseif ($av.Name -match $script:DefenderRx) { Add-R 'Security' "Antivirus: $($av.Name)" 'INFO' 'Off (another antivirus is in charge)' }
            else { Add-R 'Security' "Antivirus: $($av.Name)" 'WARN' "Installed but switched off - usually an expired pre-installed trial. These show 'your PC is at risk' pop-ups to sell a subscription. If you don't pay for it, uninstall it; Microsoft Defender already protects you." }
        }
        if ($script:AVs.Count -and -not @($script:AVs | Where-Object { $_.On }).Count) { Add-R 'Security' 'Antivirus protection' 'FAIL' 'No antivirus is switched on. Open Windows Security > Virus & threat protection and turn it on.' }
        elseif (@($script:AVs | Where-Object { $_.On }).Count -gt 1) { Add-R 'Security' 'Antivirus protection' 'INFO' 'More than one antivirus is on at once - that slows the PC down without adding much protection' }

        try {
            foreach ($fp in @(Get-NetFirewallProfile -ErrorAction Stop)) {
                if ($fp.Enabled) { Add-R 'Security' "Firewall ($($fp.Name) networks)" 'PASS' 'On' }
                else { Add-R 'Security' "Firewall ($($fp.Name) networks)" 'WARN' 'OFF - unless another firewall program manages it, turn it on in Windows Security > Firewall' }
            }
        } catch { Add-R 'Security' 'Firewall' 'INFO' "Could not read firewall settings: $($_.Exception.Message)" }

        $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ((Get-Reg $uacKey 'EnableLUA') -eq 0) { Add-R 'Security' 'User Account Control' 'FAIL' 'UAC is switched off - programs get full control without asking. Malware often does this.' }
        elseif ((Get-Reg $uacKey 'ConsentPromptBehaviorAdmin') -eq 0) { Add-R 'Security' 'User Account Control' 'WARN' 'Set to never notify - programs get admin rights without asking' }
        else { Add-R 'Security' 'User Account Control' 'PASS' 'On' }

        $sac = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
        if ($null -ne $sac) { Add-R 'Security' 'Smart App Control' $(if ($sac -eq 1) { 'PASS' } else { 'INFO' }) $(switch ($sac) { 1 { 'On - blocks untrusted apps' } 2 { 'Evaluation mode - Windows is deciding whether to turn it on' } default { 'Off (see Windows Security > App & browser control)' } }) }

        try {
            $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($hf) {
                $days = [int]((Get-Date) - $hf.InstalledOn).TotalDays
                $st = if ($days -le 45) { 'PASS' } else { 'WARN' }
                Add-R 'Security' 'Windows Update' $st "Last update installed $days day(s) ago ($($hf.HotFixID))$(if ($st -eq 'WARN') { ' - open Settings > Windows Update and install updates' })"
            }
        } catch { Add-R 'Security' 'Windows Update' 'INFO' "Could not read update history: $($_.Exception.Message)" }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { Add-R 'Security' 'Pending restart' 'WARN' 'Windows has installed updates that need a restart to finish' }
    }

    Invoke-Section 'Microsoft Defender' {
        $mp = $script:Mp
        if (-not $mp) { Add-R 'Defender' 'Status' 'INFO' 'Could not read Defender status' }
        else {
            if ($script:DefenderOn) { Add-R 'Defender' 'Real-time protection' 'PASS' 'On' }
            elseif ($script:OtherAV.Count) { Add-R 'Defender' 'Real-time protection' 'INFO' "Off because $($script:OtherAV -join ', ') is your antivirus - that is normal" }
            else { Add-R 'Defender' 'Real-time protection' 'FAIL' 'OFF and no other antivirus is on. Turn it on in Windows Security > Virus & threat protection.' }
            if ($script:DefenderOn) {
                if ($mp.IsTamperProtected) { Add-R 'Defender' 'Tamper protection' 'PASS' 'On' }
                else { Add-R 'Defender' 'Tamper protection' 'WARN' 'Off - malware can switch Defender off. Turn it on in Windows Security > Virus & threat protection settings.' }
            }
        }

        if ($script:DefenderOn) {
            Write-Host '   Updating virus definitions...' -ForegroundColor DarkGray
            try { Update-MpSignature -ErrorAction Stop; $mp = Get-MpComputerStatus; Add-R 'Defender' 'Virus definitions' 'PASS' "Updated (version $($mp.AntivirusSignatureVersion))" }
            catch {
                $age = if ($mp) { $mp.AntivirusSignatureAge } else { $null }
                Add-R 'Defender' 'Virus definitions' $(if ($null -ne $age -and $age -le 2) { 'PASS' } else { 'WARN' }) "Could not update now ($($_.Exception.Message.Trim())); current definitions are $age day(s) old"
            }
        }

        if ($script:MpPref -and $script:DefenderOn) {
            $pua = $script:MpPref.PUAProtection
            if ($script:Do.EnablePUA) {
                try { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; Add-R 'Defender' 'Blocking unwanted apps (PUA)' 'PASS' 'Turned on - Defender now blocks adware and bundled junk (undo: Windows Security > App & browser control > Reputation-based protection)' }
                catch { Add-R 'Defender' 'Blocking unwanted apps (PUA)' 'WARN' "Could not turn it on: $($_.Exception.Message.Trim()) - turn it on in Windows Security > App & browser control > Reputation-based protection" }
            }
            elseif ($pua -eq 1) { Add-R 'Defender' 'Blocking unwanted apps (PUA)' 'PASS' 'On' }
            else { Add-R 'Defender' 'Blocking unwanted apps (PUA)' 'WARN' "$(if ($pua -eq 2) { 'Only watching, not blocking' } else { 'Off' }) - turn on 'Potentially unwanted app blocking' in Windows Security > App & browser control > Reputation-based protection" }
        }

        if ($script:MpPref) {
            $list = @(@($script:MpPref.ExclusionPath) + @($script:MpPref.ExclusionProcess) + @($script:MpPref.ExclusionExtension) + @($script:MpPref.ExclusionIpAddress) | Where-Object { $_ -and $_ -notmatch '^N/A' })
            if (-not $script:IsAdmin) { Add-R 'Defender' 'Exclusions' 'INFO' 'Needs administrator rights to read' }
            elseif ($list.Count -eq 0) { Add-R 'Defender' 'Exclusions' 'PASS' 'None - Defender scans everything' }
            else { Add-R 'Defender' 'Exclusions' 'WARN' ("Defender skips these: " + ($list -join '; ') + ' - malware adds exclusions to hide; remove any you did not add (Windows Security > Virus & threat protection settings > Exclusions)') }
        }

        if (-not $script:DefenderOn) {
            Add-R 'Defender' "$ScanType scan" 'INFO' $(if ($script:OtherAV.Count) { "Skipped - run a full scan from $($script:OtherAV -join ', ') instead" } else { 'Skipped - Defender is not running' })
        } else {
            $mpType = if ($ScanType -eq 'Full') { 'FullScan' } else { 'QuickScan' }
            Write-Host "   Running a $ScanType scan$(if ($ScanType -eq 'Full') { ' - this can take 1-2 hours' } else { ' - usually 1-10 minutes' })..." -ForegroundColor DarkGray
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { Start-MpScan -ScanType $mpType -ErrorAction Stop; $script:ScanRan = $true; Add-R 'Defender' "$ScanType scan" 'PASS' ('Finished in {0:N0} min' -f $sw.Elapsed.TotalMinutes) }
            catch { Add-R 'Defender' "$ScanType scan" 'WARN' "The scan did not run: $($_.Exception.Message.Trim())$(if (-not $script:IsAdmin) { ' (needs administrator rights)' })" }
        }

        try {
            $threats = @(Get-MpThreat -ErrorAction Stop)
            $active  = @($threats | Where-Object { $_.IsActive })
            $old     = @($threats | Where-Object { -not $_.IsActive })
            if ($active.Count -eq 0) { Add-R 'Defender' 'Active threats' 'PASS' 'None found' }
            else {
                foreach ($t in $active) { Add-R 'Defender' "THREAT: $($t.ThreatName)" 'FAIL' ('Found in: ' + (Short (($t.Resources | Select-Object -First 3) -join '; ') 300) + $(if ($t.DidThreatExecute) { '  |  it has RUN on this PC' })) }
                if (-not $script:IsAdmin) { Add-R 'Defender' 'Remove threats' 'WARN' 'Run PC Cleaner as administrator to remove them, or use Windows Security > Protection history' }
                elseif ($script:Do.RemoveThreats) {
                    try {
                        Remove-MpThreat -ErrorAction Stop
                        $left = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive })
                        if ($left.Count -eq 0) { Add-R 'Defender' 'Remove threats' 'PASS' 'All active threats removed or quarantined. Restart the PC, then run a Full scan (option 2) to be sure.' }
                        else { Add-R 'Defender' 'Remove threats' 'FAIL' "$($left.Count) could not be removed automatically - run a Microsoft Defender Offline scan (option 5 in START HERE.bat)" }
                    } catch { Add-R 'Defender' 'Remove threats' 'FAIL' "Removal failed: $($_.Exception.Message.Trim()) - open Windows Security > Protection history" }
                } else { Add-R 'Defender' 'Remove threats' 'WARN' 'Not removed (you said no) - open Windows Security > Protection history to deal with them' }
            }
            if ($old.Count) { Add-R 'Defender' 'Earlier detections' 'INFO' ("Already handled by Defender: " + (($old | Select-Object -ExpandProperty ThreatName -Unique) -join ', ')) }
        } catch { Add-R 'Defender' 'Threat list' 'INFO' "Could not read the threat list: $($_.Exception.Message.Trim())" }
    }

    Invoke-Section 'Malicious Software Removal Tool (second opinion)' {
        $mrt = "$env:WinDir\System32\MRT.exe"
        if (-not $script:IsAdmin) { Add-R 'MRT' 'Second-opinion scan' 'INFO' 'Skipped - needs administrator rights'; return }
        if (-not (Test-Path -LiteralPath $mrt)) { Add-R 'MRT' 'Second-opinion scan' 'INFO' 'MRT.exe is not on this PC (Windows Update normally installs it)'; return }
        Write-Host "   Running Microsoft's Malicious Software Removal Tool (quick scan, usually 2-10 minutes)..." -ForegroundColor DarkGray
        $p = Start-Process -FilePath $mrt -ArgumentList '/Q' -Wait -PassThru
        $log = "$env:WinDir\debug\mrt.log"
        $text = [string](Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue)
        $i = $text.LastIndexOf('Results Summary:')
        $last = if ($i -ge 0) { $text.Substring($i) } else { '' }
        if ($last -match 'No infection found') { Add-R 'MRT' 'Second-opinion scan' 'PASS' 'No infection found' }
        elseif ($last -match '(?s)Results Summary:\s*-+\s*(.+?)(Successfully Submitted|Microsoft Windows Malicious Software Removal Tool Finished|$)') { Add-R 'MRT' 'Second-opinion scan' 'WARN' ('Result: ' + (Short $Matches[1] 400) + "  |  full log: $log") }
        else { Add-R 'MRT' 'Second-opinion scan' 'INFO' "Finished (exit code $($p.ExitCode)) - see $log" }
    }

    Invoke-Section 'Start-up programs' {
        $entries = New-Object System.Collections.ArrayList
        $skip = 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider'
        foreach ($k in "$script:HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "$script:HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                       'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                       'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
            $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($pr in $props.PSObject.Properties) { if ($skip -notcontains $pr.Name -and $pr.Value) { [void]$entries.Add([pscustomobject]@{ Name = $pr.Name; Command = [string]$pr.Value }) } }
        }
        $shell = New-Object -ComObject WScript.Shell
        foreach ($f in @("$script:AppData\Microsoft\Windows\Start Menu\Programs\Startup", [Environment]::GetFolderPath('CommonStartup'))) {
            if (-not $f -or -not (Test-Path -LiteralPath $f)) { continue }
            foreach ($file in @(Get-ChildItem -LiteralPath $f -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                $cmd = '"' + $file.FullName + '"'
                if ($file.Extension -eq '.lnk') { try { $l = $shell.CreateShortcut($file.FullName); if ($l.TargetPath) { $cmd = ('"{0}" {1}' -f $l.TargetPath, $l.Arguments).Trim() } } catch {} }
                [void]$entries.Add([pscustomobject]@{ Name = "$($file.Name) (Start-up folder)"; Command = $cmd })
            }
        }
        $flag = 0
        foreach ($e in $entries) { $v = Get-Verdict $e.Command; if ($v.Status -eq 'WARN') { $flag++ }; Add-R 'Start-up' $e.Name $v.Status $v.Note }
        Add-R 'Start-up' 'Summary' $(if ($flag) { 'WARN' } else { 'PASS' }) "$($entries.Count) program(s) start with Windows, $flag need a look. Turn off ones you don't need in Task Manager > Start-up apps (makes the PC start faster)."
    }

    Invoke-Section 'Scheduled tasks' {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })
        $flag = 0
        foreach ($t in $tasks) {
            foreach ($a in @($t.Actions)) {
                if (-not $a.Execute) { continue }
                $v = Get-Verdict (('"{0}" {1}' -f $a.Execute.Trim('"'), $a.Arguments).Trim())
                if ($v.Status -ne 'WARN' -and $t.TaskName -match $script:KnownAdware) { $v.Status = 'WARN'; $v.Note += '  |  REVIEW: the task name belongs to known adware' }
                if ($v.Status -eq 'WARN') { $flag++; Add-R 'Scheduled tasks' ($t.TaskPath + $t.TaskName) 'WARN' $v.Note }
            }
        }
        Add-R 'Scheduled tasks' 'Summary' $(if ($flag) { 'WARN' } else { 'PASS' }) "$($tasks.Count) non-Microsoft task(s) checked, $flag need a look. To remove one: Task Scheduler > find it > Delete (after uninstalling the program it belongs to)."
    }

    Invoke-Section 'Services' {
        $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName })
        $third = 0; $flag = 0
        foreach ($s in $svcs) {
            $v = Get-Verdict $s.PathName
            if ($v.Signer -match 'Microsoft') { continue }
            $third++
            if ($v.Status -eq 'WARN') { $flag++; Add-R 'Services' "$($s.DisplayName) ($($s.Name))" 'WARN' $v.Note }
        }
        Add-R 'Services' 'Summary' $(if ($flag) { 'WARN' } else { 'PASS' }) "$third non-Microsoft auto-start service(s) checked, $flag need a look"
    }

    Invoke-Section 'Hidden start-up hooks (WMI)' {
        try {
            $cons = @(Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer -ErrorAction Stop) + @(Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
            $cons = @($cons | Where-Object { $_ })
            if (-not $cons.Count) { Add-R 'WMI' 'Hidden start-up hooks' 'PASS' 'None' }
            foreach ($c in $cons) {
                $what = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptFileName) { $c.ScriptFileName } else { $c.ScriptText }
                Add-R 'WMI' "Hidden start-up hook: $($c.Name)" 'WARN' ((Short $what 200) + '  |  Windows runs this automatically. Malware uses these to come back after removal. Run the Offline virus scan (option 5); if it is still listed afterwards, get help from someone who knows PCs.')
            }
        } catch { Add-R 'WMI' 'Hidden start-up hooks' 'INFO' $(if ($script:IsAdmin) { "Could not check: $($_.Exception.Message.Trim())" } else { 'Needs administrator rights to check' }) }
    }

    Invoke-Section 'Running programs' {
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Sort-Object Path -Unique)
        $flag = 0
        foreach ($p in $procs) {
            $v = Get-Verdict ('"' + $p.Path + '"')
            if ($v.Status -eq 'WARN') { $flag++; Add-R 'Processes' "$($p.ProcessName) (PID $($p.Id))" 'WARN' $v.Note }
        }
        Add-R 'Processes' 'Summary' $(if ($flag) { 'WARN' } else { 'PASS' }) "$($procs.Count) running program(s) checked, $flag need a look$(if (-not $script:IsAdmin) { ' (programs running as administrator were not visible)' })"
    }

    Invoke-Section 'Browser extensions' {
        foreach ($x in $script:Extensions) {
            $state = if ($x.Off) { ' (switched off)' } else { '' }
            switch ($x.Kind) {
                'Hijacker'   { Add-R 'Browser extensions' $x.Name 'WARN' "$($x.Where)$state - browser hijacker, see the Pop-ups section" }
                'Sideloaded' { Add-R 'Browser extensions' $x.Name 'WARN' "$($x.Where) - loaded from outside the browser, see the Pop-ups section" }
                'Adware'     { Add-R 'Browser extensions' $x.Name 'WARN' "$($x.Where)$state - this kind of extension usually comes bundled with other software and shows ads or changes your browser; remove it if you didn't add it yourself" }
                default      { Add-R 'Browser extensions' $x.Name 'INFO' "$($x.Where)$state" }
            }
        }
        $flag = @($script:Extensions | Where-Object { $_.Kind }).Count
        Add-R 'Browser extensions' 'Summary' $(if ($flag) { 'WARN' } else { 'PASS' }) "$($script:Extensions.Count) extension(s) installed, $flag look like adware or hijackers. Remove any you don't recognise from the browser's Extensions page."
    }

    Invoke-Section 'Installed programs' {
        foreach ($r in $script:Removable) { Add-R 'Programs' $r.Name 'WARN' ("Usually not wanted: $($r.Why)." + $(if ($r.Do) { ' You chose to uninstall it - see the end of the run.' } else { ' Uninstall it in Settings > Apps if you did not choose it.' })) }
        $recent = @($script:Apps | Where-Object { $d = ConvertTo-InstallDate $_.InstallDate; $d -and $d -ge (Get-Date).AddDays(-14) })
        if ($recent.Count) { Add-R 'Programs' 'Installed or updated in the last 14 days' 'INFO' (($recent | ForEach-Object { $_.DisplayName }) -join '; ') }
        Add-R 'Programs' 'Summary' $(if ($script:Removable.Count) { 'WARN' } else { 'PASS' }) "$($script:Apps.Count) program(s) installed, $($script:Removable.Count) usually not wanted"
    }

    Invoke-Section 'Network settings' {
        $hosts = "$env:WinDir\System32\drivers\etc\hosts"
        $watch = '(?i)microsoft|windowsupdate|google|facebook|bank|paypal|amazon|apple|icloud|defender|avast|avg|norton|mcafee|kaspersky|malwarebytes|eset|bitdefender|virustotal|steam|discord'
        try {
            $lines = @(Get-Content -LiteralPath $hosts -ErrorAction Stop | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
            $bad = @($lines | Where-Object { $_ -match $watch -and $_ -notmatch 'docker\.internal' })
            if ($lines.Count -eq 0) { Add-R 'Network' 'Hosts file' 'PASS' 'No custom entries' }
            elseif ($bad.Count) { Add-R 'Network' 'Hosts file' 'WARN' ("These redirect or block well-known sites (a common malware trick): " + ($bad -join ' ; ') + "  |  edit $hosts as administrator to remove them") }
            else { Add-R 'Network' 'Hosts file' 'INFO' ("$($lines.Count) custom entr$(if ($lines.Count -eq 1) { 'y' } else { 'ies' }): " + (Short ($lines -join ' ; ') 300)) }
        } catch { Add-R 'Network' 'Hosts file' 'INFO' "Could not read the hosts file: $($_.Exception.Message)" }

        $is = "$script:HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $pac = Get-Reg $is 'AutoConfigURL'
        if ((Get-Reg $is 'ProxyEnable') -eq 1) { Add-R 'Network' 'Proxy' 'WARN' "Web traffic goes through a proxy: $(Get-Reg $is 'ProxyServer') - fine on a work/school network, otherwise switch it off in Settings > Network & internet > Proxy" }
        elseif ($pac) { Add-R 'Network' 'Proxy' 'WARN' "A proxy script is set: $pac - fine on a work/school network, otherwise remove it in Settings > Network & internet > Proxy" }
        else { Add-R 'Network' 'Proxy' 'PASS' 'None' }

        try {
            $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
            if ($dns.Count) { Add-R 'Network' 'DNS servers' 'INFO' (($dns -join ', ') + ' - normally your router or internet provider; if you did not set these and do not recognise them, malware may have changed them') }
        } catch {}
    }
}
#endregion

#region ===================== CLEAN =====================
if ($doClean) {

    Invoke-Section 'Temporary files' {
        if ($script:UserTemp -match '(?i)\\Temp(\\\d+)?\\?$') { Clear-Group 'Your temp files' @($script:UserTemp) 'files from the last 24 hours were kept' 24 }
        else { Add-R 'Clean-up' 'Your temp files' 'WARN' "Skipped - the temp folder is set to $($script:UserTemp), which doesn't look like a normal Temp folder" }
        if ($script:IsAdmin) { Clear-Group 'Windows temp files' @("$env:WinDir\Temp") 'files from the last 24 hours were kept' 24 }
        else { Add-R 'Clean-up' 'Windows temp files' 'INFO' 'Skipped - needs administrator rights' }
    }

    Invoke-Section 'Browser and app caches' {
        if ($script:Do.CloseBrowsers -and -not $script:BrowsersClosed) { Close-Browsers }
        $open = @(Get-OpenBrowsers)
        $sub = 'Cache', 'Code Cache', 'GPUCache'
        foreach ($b in $script:BrowserRoots.GetEnumerator()) {
            if ($b.Key -like 'Opera*' -or -not (Test-Path -LiteralPath $b.Value)) { continue }
            $paths = @($sub | ForEach-Object { Join-Path $b.Value "*\$_" }) + @('ShaderCache', 'GrShaderCache', 'GraphiteDawnCache' | ForEach-Object { Join-Path $b.Value $_ })
            Clear-Group "$($b.Key) cache" $paths
        }
        Clear-Group 'Opera cache' @("$script:LocalAppData\Opera Software\*\Cache")
        Clear-Group 'Firefox cache' @("$script:LocalAppData\Mozilla\Firefox\Profiles\*\cache2")
        Clear-Group 'Discord cache' @($sub | ForEach-Object { Join-Path "$script:AppData\discord" $_ })
        Clear-Group 'Steam web cache' @("$script:LocalAppData\Steam\htmlcache")
        Add-R 'Clean-up' 'What was kept' 'INFO' 'Only cache files were removed - saved passwords, cookies, logins, history and bookmarks were left alone'
        if ($open.Count) { Add-R 'Clean-up' 'Browsers open' 'INFO' "$($open -join ', ') $(if ($open.Count -gt 1) { 'were' } else { 'was' }) running, so cache files in use were skipped. Close $(if ($open.Count -gt 1) { 'them' } else { 'it' }) and run again for a fuller clean." }
    }

    Invoke-Section 'Error reports and update sharing cache' {
        Clear-Group 'Your error reports' @("$script:LocalAppData\Microsoft\Windows\WER\ReportArchive", "$script:LocalAppData\Microsoft\Windows\WER\ReportQueue")
        if ($script:IsAdmin) {
            Clear-Group 'Windows error reports' @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue")
            if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
                $before = Get-FreeBytes
                try {
                    Delete-DeliveryOptimizationCache -Force -ErrorAction Stop | Out-Null
                    $freed = [math]::Max(0.0, (Get-FreeBytes) - $before); $script:FreedBytes += $freed
                    Add-R 'Clean-up' 'Delivery Optimization cache' 'PASS' "Freed about $(Format-Bytes $freed) (copies of updates shared with other PCs)"
                } catch { Add-R 'Clean-up' 'Delivery Optimization cache' 'INFO' "Could not clear: $($_.Exception.Message.Trim())" }
            }
        } else { Add-R 'Clean-up' 'System error reports and update cache' 'INFO' 'Skipped - needs administrator rights' }
    }

    Invoke-Section 'Recycle Bin' {
        if ($script:OtherUser) { Add-R 'Clean-up' 'Recycle Bin' 'INFO' "Not touched - empty it yourself while signed in as $($script:OtherUser)" }
        elseif ($script:RecycleBytes -le 0) { Add-R 'Clean-up' 'Recycle Bin' 'PASS' 'Already empty' }
        elseif ($script:Do.EmptyBin) {
            try { Clear-RecycleBin -Force -ErrorAction Stop; $script:FreedBytes += $script:RecycleBytes; Add-R 'Clean-up' 'Recycle Bin' 'PASS' "Emptied, freed $(Format-Bytes $script:RecycleBytes)" }
            catch { Add-R 'Clean-up' 'Recycle Bin' 'INFO' "Could not empty it: $($_.Exception.Message)" }
        } else { Add-R 'Clean-up' 'Recycle Bin' 'INFO' "Kept ($(Format-Bytes $script:RecycleBytes))" }
    }

    if ($Deep) {
        Invoke-Section 'Deep clean' {
            Clear-Group 'Your crash dumps' @("$script:LocalAppData\CrashDumps")
            Clear-Group 'Graphics shader caches' @("$script:LocalAppData\D3DSCache", "$script:LocalAppData\NVIDIA\DXCache", "$script:LocalAppData\NVIDIA\GLCache", "$script:LocalAppData\AMD\DxCache", "$script:LocalAppData\AMD\DxcCache", "$script:LocalAppData\AMD\GLCache") 'games rebuild these, so their first launch may stutter briefly'
            Clear-Group 'Thumbnail cache' @("$script:LocalAppData\Microsoft\Windows\Explorer\thumbcache_*.db") 'files in use by File Explorer are rebuilt on their own'

            if (-not $script:IsAdmin) { Add-R 'Clean-up' 'System deep clean' 'INFO' 'Skipped - Windows Update leftovers, crash dumps and Windows.old need administrator rights'; return }

            Clear-Group 'Windows crash dumps' @("$env:WinDir\Minidump", "$env:WinDir\MEMORY.DMP")

            if (Get-Process -Name TiWorker, TrustedInstaller -ErrorAction SilentlyContinue) { Add-R 'Clean-up' 'Windows Update clean-up' 'INFO' 'Skipped - Windows Update is installing something right now. Run the deep clean again later.' }
            else {
                if ($script:Do.Dism) {
                    Write-Host '   Running DISM component clean-up (5-30 minutes)...' -ForegroundColor DarkGray
                    $before = Get-FreeBytes
                    & "$env:WinDir\System32\dism.exe" /Online /Cleanup-Image /StartComponentCleanup
                    $freed = [math]::Max(0.0, (Get-FreeBytes) - $before); $script:FreedBytes += $freed
                    if ($LASTEXITCODE -eq 0) { Add-R 'Clean-up' 'Old copies of updated Windows files' 'PASS' "Freed about $(Format-Bytes $freed)" }
                    else { Add-R 'Clean-up' 'Old copies of updated Windows files' 'INFO' "DISM finished with code $LASTEXITCODE (freed about $(Format-Bytes $freed))" }
                } else { Add-R 'Clean-up' 'Old copies of updated Windows files' 'INFO' 'Kept - you said no' }

                if ($script:Do.WUCache) {
                    $svc = 'wuauserv', 'bits'
                    $was = @{}; foreach ($s in $svc) { $was[$s] = [string](Get-Service -Name $s -ErrorAction SilentlyContinue).Status }
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Clear-Group 'Windows Update download cache' @("$env:WinDir\SoftwareDistribution\Download")
                    foreach ($s in $svc) { if ($was[$s] -eq 'Running') { Start-Service -Name $s -ErrorAction SilentlyContinue } }
                }
            }

            # Disk Clean-up handlers that only hold setup/upgrade leftovers. Not used: Downloads, ESD files
            # (needed for "Reset this PC"), file versions, language packs, driver packages.
            $handlers = @('Temporary Setup Files', 'Setup Log Files', 'Windows Upgrade Log Files', 'Upgrade Discarded Files', 'Old ChkDsk Files', 'Windows Reset Log Files', 'Feedback Hub Archive log files', 'Diagnostic Data Viewer database files')
            if (Test-Path -LiteralPath $script:OldWin) { if ($script:Do.WinOld) { $handlers += 'Previous Installations' } else { Add-R 'Clean-up' 'Windows.old' 'INFO' 'Kept - you said no' } }
            $cleanmgr = "$env:WinDir\System32\cleanmgr.exe"
            if (Test-Path -LiteralPath $cleanmgr) {
                $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
                $flag = 'StateFlags7351'
                $set = @(foreach ($h in $handlers) { $k = Join-Path $root $h; if (Test-Path -LiteralPath $k) { New-ItemProperty -LiteralPath $k -Name $flag -Value 2 -PropertyType DWord -Force | Out-Null; $k } })
                Write-Host '   Running Windows Disk Clean-up for setup and upgrade leftovers...' -ForegroundColor DarkGray
                $before = Get-FreeBytes
                try { Start-Process -FilePath $cleanmgr -ArgumentList '/sagerun:7351' -Wait -ErrorAction Stop } catch {}
                foreach ($k in $set) { Remove-ItemProperty -LiteralPath $k -Name $flag -ErrorAction SilentlyContinue }
                $freed = [math]::Max(0.0, (Get-FreeBytes) - $before); $script:FreedBytes += $freed
                Add-R 'Clean-up' 'Setup and upgrade leftovers' 'PASS' "Freed about $(Format-Bytes $freed)"
                if ($handlers -contains 'Previous Installations') {
                    if (Test-Path -LiteralPath $script:OldWin) { Add-R 'Clean-up' 'Windows.old' 'WARN' 'Still there - remove it in Settings > System > Storage > Temporary files > "Previous Windows installation(s)"' }
                    else { Add-R 'Clean-up' 'Windows.old' 'PASS' 'Removed' }
                }
            } else { Add-R 'Clean-up' 'Setup and upgrade leftovers' 'INFO' 'Disk Clean-up is not available - use Settings > System > Storage > Temporary files' }
        }
    }
}
#endregion

#region ===================== uninstall what was chosen, and things to decide =====================
$chosen = @($script:Removable | Where-Object { $_.Do })
if ($chosen.Count) {
    Invoke-Section 'Uninstalling what you chose' {
        try { [Console]::Beep(880, 300) } catch {}
        foreach ($r in $chosen) { Invoke-Uninstall $r.Name $r.Uninstall }
    }
}

if ($doClean) {
    Invoke-Section 'Things only you should decide on' {
        $dl = Get-DownloadsPath
        if (Test-Path -LiteralPath $dl) {
            $files = @(Get-ChildItem -LiteralPath $dl -File -Force -ErrorAction SilentlyContinue)
            $inst  = @($files | Where-Object { $_.Extension -in '.exe', '.msi', '.iso', '.zip' -and $_.LastWriteTime -lt (Get-Date).AddDays(-30) })
            $size  = [double]($files | Measure-Object -Property Length -Sum).Sum
            $isize = [double]($inst  | Measure-Object -Property Length -Sum).Sum
            Add-R 'Your files' 'Downloads folder' 'INFO' ("$($files.Count) file(s), $(Format-Bytes $size). $($inst.Count) old installer/ZIP/ISO file(s) over 30 days old take $(Format-Bytes $isize). Use option 6 in START HERE.bat to review recent downloads, or delete old ones yourself.")
        }
        if (-not $Deep -and (Test-Path -LiteralPath $script:OldWin)) { Add-R 'Your files' 'Windows.old' 'INFO' 'Your previous Windows installation is still on the disk (often 10-30 GB). Run the Deep clean to remove it once you are sure you will not go back.' }
    }
}
#endregion

#region ===================== RECENT DOWNLOADS AND PROGRAMS =====================
if ($Action -eq 'Recent') {
    $since = (Get-Date).AddDays(-7 * $Weeks)
    Write-Host ''
    Write-Host "Looking at what arrived on this PC since $($since.ToString('d MMMM yyyy'))." -ForegroundColor Cyan
    Write-Host 'Nothing is removed unless you say so. Files go to the Recycle Bin, so you can still get them back.' -ForegroundColor DarkGray

    Invoke-Section "Downloads from the last $Weeks week(s)" {
        $dl = Get-DownloadsPath
        $items = @(Get-ChildItem -LiteralPath $dl -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' -and ($_.CreationTime -ge $since -or $_.LastWriteTime -ge $since) } | Sort-Object CreationTime -Descending)
        if (-not $items.Count) { Add-R 'Recent' 'Downloads' 'PASS' "Nothing new in $dl"; return }
        $total = 0.0; $i = 0
        foreach ($it in $items) {
            $i++
            $sz = if ($it -is [IO.DirectoryInfo]) { Get-FolderSize $it.FullName } else { [double]$it.Length }
            $total += $sz
            $it | Add-Member -NotePropertyName Size -NotePropertyValue $sz -Force
            Write-Host ('   {0,3}. {1,-58} {2,10}   {3:yyyy-MM-dd}' -f $i, (Short $it.Name 58), (Format-Bytes $sz), $it.CreationTime)
        }
        Write-Host "   Total: $($items.Count) item(s), $(Format-Bytes $total) in $dl"
        $pick = @()
        if (-not $NoPrompt) {
            $c = Read-Host '   Move to the Recycle Bin - A = all of them, O = choose one by one, N = none [a/o/N]'
            if ($c -match '^\s*a') { $pick = $items }
            elseif ($c -match '^\s*o') { foreach ($it in $items) { if (Read-YesNo "Move '$($it.Name)' ($(Format-Bytes $it.Size)) to the Recycle Bin?" $false) { $pick += $it } } }
        }
        if (-not $pick.Count) { Add-R 'Recent' 'Downloads' 'INFO' "$($items.Count) recent item(s) kept ($(Format-Bytes $total))"; return }
        Add-Type -AssemblyName Microsoft.VisualBasic
        $moved = 0; $msize = 0.0
        foreach ($it in $pick) {
            try {
                # AllDialogs: if an item can't go to the Recycle Bin (too big, USB or network drive), Windows asks before deleting it for good.
                if ($it -is [IO.DirectoryInfo]) { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($it.FullName, 'AllDialogs', 'SendToRecycleBin') }
                else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($it.FullName, 'AllDialogs', 'SendToRecycleBin') }
                $moved++; $msize += $it.Size
                Add-R 'Recent' $it.Name 'PASS' 'Moved to the Recycle Bin'
            } catch { Add-R 'Recent' $it.Name 'WARN' "Not moved: $($_.Exception.Message.Trim())" }
        }
        Add-R 'Recent' 'Downloads' 'PASS' "Moved $moved item(s), $(Format-Bytes $msize), to the Recycle Bin. Empty the Recycle Bin later to free the space for good."
    }

    Invoke-Section "Programs installed or updated in the last $Weeks week(s)" {
        $recent = @($script:Apps | Where-Object { $d = ConvertTo-InstallDate $_.InstallDate; $d -and $d -ge $since } | Sort-Object { ConvertTo-InstallDate $_.InstallDate } -Descending)
        if (-not $recent.Count) { Add-R 'Recent' 'Programs' 'PASS' 'Nothing new'; return }
        Write-Host '   Updates also change the install date, so programs you know well can appear here too.' -ForegroundColor DarkGray
        Write-Host '   Programs from Microsoft, Intel, NVIDIA, AMD, Realtek or your PC maker are usually drivers or system parts - keep those.' -ForegroundColor DarkGray
        $todo = @()
        foreach ($a in $recent) {
            $when = (ConvertTo-InstallDate $a.InstallDate).ToString('yyyy-MM-dd')
            $sys = $a.Publisher -match '(?i)microsoft|intel|nvidia|advanced micro|\bamd\b|realtek|hp inc|hewlett|dell|lenovo|asus|acer|\bmsi\b|samsung|qualcomm|synaptics|elan|dolby|waves'
            $label = "$($a.DisplayName) - $(if ($a.Publisher) { $a.Publisher } else { 'unknown publisher' }), $when$(if ($sys) { ' (from Microsoft or a hardware maker - usually keep)' })"
            if (-not $a.UninstallString) { Add-R 'Recent' $a.DisplayName 'INFO' "$label - no uninstaller registered; use Settings > Apps"; continue }
            if (Read-YesNo "Uninstall $label?" $false -NeverAuto) { $todo += $a } else { Add-R 'Recent' $a.DisplayName 'INFO' "Kept - $label" }
        }
        foreach ($a in $todo) { Invoke-Uninstall ([string]$a.DisplayName) ([string]$a.UninstallString) }
    }
}
#endregion

#region ===================== FRESH START =====================
if ($Action -eq 'FreshStart') {
    Invoke-Section 'Fresh start: reset Windows to like-new' {
        $listFile = Join-Path $RunDir 'installed-programs.txt'
        ($script:Apps | Sort-Object DisplayName | ForEach-Object { '{0}   ({1})' -f $_.DisplayName, $(if ($_.Publisher) { $_.Publisher } else { 'unknown publisher' }) }) | Out-File -FilePath $listFile -Encoding utf8
        Add-R 'Fresh start' 'List of your programs' 'PASS' "Saved to $listFile - use it to reinstall what you need afterwards. Copy it somewhere safe (USB stick, OneDrive, email it to yourself)."
        $guide = @"

   A reset reinstalls Windows. It removes every program and setting (and every
   virus, adware and pop-up maker with them). You choose what happens to your files:

     Keep my files     - removes apps and settings, keeps documents, photos etc.
                         Good for a slow PC or pop-ups/adware that won't go away.
     Remove everything - wipes the whole PC. Best for a serious infection, or
                         before selling or giving the PC away (then also choose
                         "Change settings" > "Clean data" = Yes).

   Then choose how to reinstall:
     Cloud download    - fresh copy of Windows from Microsoft (about 4 GB).
                         Best choice if the PC is infected.
     Local reinstall   - uses files already on the PC. Faster, no download.

   BEFORE YOU START
     1. Back up anything you want to keep to OneDrive or a USB drive - even with
        "Keep my files". Browser bookmarks and passwords: sign in to the browser
        (Chrome/Edge sync) so they come back.
     2. Plug in the charger. It takes 30-90 minutes and restarts several times.
     3. Know your Microsoft account password and your Wi-Fi password.
     4. If the PC is encrypted (BitLocker / Device encryption), have the recovery
        key ready - find it at aka.ms/myrecoverykey (sign in with your Microsoft account).
     5. Keep the program list saved above.

   WHERE IT IS
     Windows 11: Settings > System > Recovery > Reset PC
     Windows 10: Settings > Update & Security > Recovery > Reset this PC > Get started
     If Windows won't start: hold Shift while clicking Restart, then
     Troubleshoot > Reset this PC.

   AFTERWARDS
     Run Windows Update until there is nothing left, install your browser and
     programs again from their official websites, and run PC Cleaner once more.
"@
        Write-Host $guide
        Add-R 'Fresh start' 'How to reset' 'INFO' 'Settings > System > Recovery > Reset PC (Windows 10: Settings > Update & Security > Recovery). Choose Keep my files or Remove everything, then Cloud download. Back up first, plug in the charger, and have your BitLocker recovery key (aka.ms/myrecoverykey) if the PC is encrypted.'
        if (Read-YesNo 'Open Settings > Recovery now? (Nothing starts until you click Reset PC there and confirm.)' $true -NeverAuto) {
            Start-Process 'ms-settings:recovery'
            Add-R 'Fresh start' 'Settings > Recovery' 'PASS' 'Opened'
        }
    }
}
#endregion

#region ===================== report =====================
$script:FreeAfter = Get-FreeBytes
$fails = @($script:Results | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($script:Results | Where-Object { $_.Status -eq 'WARN' })

Write-Host ''
Write-Host '== Summary ==' -ForegroundColor Cyan
if ($doScan) {
    if ($fails.Count) { Write-Host "   $($fails.Count) problem(s) need fixing - see the report" -ForegroundColor Red }
    if ($warns.Count) { Write-Host "   $($warns.Count) item(s) worth a look - see the report" -ForegroundColor Yellow }
    if (-not $fails.Count -and -not $warns.Count) { Write-Host '   No problems found' -ForegroundColor Green }
}
if ($doClean) {
    Write-Host "   Space freed: $(Format-Bytes $script:FreedBytes)" -ForegroundColor Green
    Write-Host "   Free space on drive $($env:SystemDrive) $(Format-Bytes $script:FreeBefore) before, $(Format-Bytes $script:FreeAfter) now" -ForegroundColor Green
}

$rows = foreach ($r in $script:Results) { "<tr class='$($r.Status.ToLower())'><td>$(HE $r.Category)</td><td>$(HE $r.Check)</td><td class='st'>$(HE $r.Status)</td><td>$(HE $r.Detail)</td></tr>" }
$todo = foreach ($r in @($fails) + @($warns)) { "<li class='$($r.Status.ToLower())'><b>$(HE $r.Check)</b> - <span>$(HE $r.Detail)</span></li>" }
$verdict = if (-not $doScan) { '' }
    elseif ($fails.Count) { "<p class='big fail'>$($fails.Count) problem(s) need fixing</p>" }
    elseif (-not $script:ScanRan) { "<p class='big warn'>The virus scan did not run (see Defender below) - $($warns.Count) item(s) worth a look</p>" }
    elseif ($warns.Count) { "<p class='big warn'>No viruses found - $($warns.Count) item(s) worth a look</p>" }
    else { "<p class='big pass'>No viruses or problems found</p>" }
$space = if ($doClean) { "<p><b>Space freed:</b> $(Format-Bytes $script:FreedBytes) &nbsp;|&nbsp; <b>Free space on drive $(HE $env:SystemDrive)</b> $(Format-Bytes $script:FreeBefore) before, $(Format-Bytes $script:FreeAfter) now</p>" } else { '' }
$who = if ($script:OtherUser) { " &nbsp;|&nbsp; Account checked: $(HE $script:OtherUser)" } else { '' }
$html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>PC Cleaner report - $(HE $env:COMPUTERNAME)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#ddd;margin:2em;max-width:1200px}
h1{color:#5cc8ff;margin-bottom:.2em} h2{color:#9ad;margin-top:1.6em} .meta{color:#999}
table{border-collapse:collapse;width:100%} td,th{padding:6px 10px;border-bottom:1px solid #333;text-align:left;vertical-align:top} th{color:#aaa}
td:last-child{word-break:break-word} .st{font-weight:600}
tr.pass .st,.pass{color:#6fcf6f} tr.warn .st,.warn{color:#f2c94c} tr.fail .st,.fail{color:#eb5757} tr.info .st{color:#9aa}
li{margin:.4em 0} li span{color:#ddd} .big{font-size:1.4em;font-weight:600;margin:.6em 0}
</style></head><body>
<h1>PC Cleaner report</h1>
<p class='meta'>$(HE $env:COMPUTERNAME) &nbsp;|&nbsp; $(Get-Date $script:Start -Format 'yyyy-MM-dd HH:mm') &nbsp;|&nbsp; Mode: $(HE $modeText) &nbsp;|&nbsp; Administrator: $(if ($script:IsAdmin) { 'yes' } else { 'no - some checks were skipped' })$who &nbsp;|&nbsp; v$($script:ToolVersion)</p>
$verdict
$space
$(if ($todo) { "<h2>What to do</h2><ul>$($todo -join "`n")</ul>" })
<h2>Everything that was checked and done</h2>
<table><tr><th>Area</th><th>Item</th><th>Result</th><th>Details</th></tr>
$($rows -join "`n")
</table>
<p class='meta'>Full log: log.txt in this folder. To have Claude look at this PC's results, give it this folder (see "Ask Claude to look at a PC" in README.md).</p>
</body></html>
"@
$html | Out-File -FilePath $ReportPath -Encoding utf8
Write-Host ''
Write-Host "Report saved to: $ReportPath" -ForegroundColor Cyan
if ($script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }
if (-not $NoOpen) { try { Start-Process $ReportPath } catch {} }

if ($script:Do.OpenExt) {
    foreach ($b in @($script:Extensions | Where-Object { $_.Kind -and $_.Browser -ne 'Firefox' } | ForEach-Object { $_.Browser } | Sort-Object -Unique)) {
        try { Start-Process -FilePath "$($script:BrowserProc[$b]).exe" -ArgumentList "$($script:BrowserScheme[$b])://extensions" -ErrorAction Stop } catch {}
    }
    if (@($script:Extensions | Where-Object { $_.Kind -and $_.Browser -eq 'Firefox' }).Count) { try { Start-Process -FilePath 'firefox.exe' -ArgumentList 'about:addons' -ErrorAction Stop } catch {} }
    Write-Host 'Opened the Extensions page - click Remove on the extensions listed in the report.' -ForegroundColor Yellow
}

if ($OfflineScan) {
    if (-not $script:IsAdmin) { Write-Host 'The offline scan needs administrator rights - skipped.' -ForegroundColor Yellow }
    else {
        Write-Host ''
        Write-Host 'Microsoft Defender Offline scan: the PC RESTARTS straight away and scans before Windows starts (about 15 minutes).' -ForegroundColor Yellow
        $r = Read-Host '   Save your work and close your programs first. Restart and scan now? [y/N]'
        if ($r -match '^\s*(y|yes)\s*$') { Start-MpWDOScan }
    }
}

if (-not $NoPrompt) { Write-Host ''; Read-Host 'Finished. Press Enter to close this window' | Out-Null }
exit 0
#endregion
