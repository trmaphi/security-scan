<#
.SYNOPSIS
  Windows security/software hygiene scan: outdated apps, missing OS updates, vulnerable dependencies.

.DESCRIPTION
  Combines three independent sources into one timestamped report:

    1. winget          - installed apps with newer versions available (outdated, not CVE-mapped)
    2. Windows Update  - pending OS updates + last installed patch
    3. Trivy           - HIGH/CRITICAL CVEs in dependency manifests under the scan paths

  Output is Markdown for humans plus JSON/TXT evidence. Nothing is installed or changed.

.PARAMETER Path
  Directories to scan for dependency manifests. Defaults to paths.txt next to this script,
  else "Documents" under the user profile.

.PARAMETER OutDir
  Report root. Defaults to "%USERPROFILE%\security-scan\reports".

.PARAMETER Severity
  Trivy severity filter. Default "HIGH,CRITICAL".

.PARAMETER TrivyPath
  Explicit path to trivy.exe. Defaults to PATH, then "%USERPROFILE%\security-scan\bin\trivy.exe".

.PARAMETER SkipWinget
  Skip the winget audit.

.PARAMETER SkipWindowsUpdate
  Skip the Windows Update query.

.EXAMPLE
  .\vuln-scan.ps1

.EXAMPLE
  .\vuln-scan.ps1 -Path "$HOME\source","$HOME\Documents" -OutDir D:\reports
#>
[CmdletBinding()]
param(
  [string[]]$Path,
  [string]$OutDir = (Join-Path $HOME 'security-scan\reports'),
  [string]$Severity = 'HIGH,CRITICAL',
  [string]$TrivyPath,
  [switch]$SkipWinget,
  [switch]$SkipWindowsUpdate
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$out   = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'run.log'

function Log([string]$msg) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
  Add-Content -Path $log -Value $line -Encoding utf8
  Write-Host $line
}

function Resolve-Trivy {
  if ($TrivyPath -and (Test-Path $TrivyPath)) { return $TrivyPath }
  $cmd = Get-Command trivy.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $local = Join-Path $HOME 'security-scan\bin\trivy.exe'
  if (Test-Path $local) { return $local }
  return $null
}

Log "security scan started -> $out"

# ---------------------------------------------------------------- winget audit
$pkgs = @()
if (-not $SkipWinget) {
  Log 'winget: checking for available upgrades'
  $wingetRaw = (& winget upgrade --include-unknown --accept-source-agreements 2>&1 | Out-String)
  $wingetRaw | Out-File -FilePath (Join-Path $out 'winget-upgrades.raw.txt') -Encoding utf8
  foreach ($line in ($wingetRaw -split "`r?`n")) {
    $m = [regex]::Match($line, '^(?<name>.+?)\s{2,}(?<id>\S+)\s+(?<ver>\S+)\s+(?<new>\S+)\s+(?<src>winget|msstore)\s*$')
    if ($m.Success) {
      $pkgs += [pscustomobject]@{
        Name      = $m.Groups['name'].Value.Trim()
        Id        = $m.Groups['id'].Value
        Current   = $m.Groups['ver'].Value
        Available = $m.Groups['new'].Value
        Source    = $m.Groups['src'].Value
      }
    }
  }
  $pkgs | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $out 'winget-upgrades.json') -Encoding utf8
  if ($pkgs.Count -gt 0) {
    $pkgs | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 200 |
      Out-File -FilePath (Join-Path $out 'winget-upgrades.txt') -Encoding utf8
  }
  Log ("winget: {0} package(s) with newer versions available" -f $pkgs.Count)
}

# ------------------------------------------------------ Windows OS patch status
$osUpdates = @()
$lastKb = 'unknown'
if (-not $SkipWindowsUpdate) {
  Log 'windows: querying Windows Update for pending patches'
  try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    foreach ($u in $result.Updates) {
      $sev = if ($u.MsrcSeverity) { [string]$u.MsrcSeverity } else { '' }
      $cat = if ($u.Title -match 'Defender Antivirus') { 'Defender signature' }
             elseif ($sev) { "OS $sev" }
             else { 'Other' }
      $osUpdates += [pscustomobject]@{
        Title      = $u.Title
        Category   = $cat
        KB         = ($u.KBArticleIDs -join ',')
        Downloaded = [bool]$u.IsDownloaded
      }
    }
    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1)
    if ($hf.Count -gt 0) { $lastKb = "$($hf[0].HotFixID) ($($hf[0].InstalledOn.ToString('yyyy-MM-dd')))" }
  } catch {
    Log "WARN: Windows Update query failed: $($_.Exception.Message)"
  }
  $osUpdates | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $out 'windows-os-updates.json') -Encoding utf8
  if ($osUpdates.Count -gt 0) {
    $osUpdates | Format-Table -AutoSize | Out-String -Width 220 |
      Out-File -FilePath (Join-Path $out 'windows-os-updates.txt') -Encoding utf8
  }
  Log ("windows: {0} pending update(s); last patch {1}" -f $osUpdates.Count, $lastKb)
}

# ------------------------------------------------------ dependency CVE scan
$trivy = Resolve-Trivy
$depVulns = @()
if ($trivy) {
  $targets = @()
  if ($Path) { $targets = $Path }
  else {
    $pathsFile = Join-Path $PSScriptRoot 'paths.txt'
    if (Test-Path $pathsFile) {
      $targets = Get-Content $pathsFile |
        Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim()) }
    }
    if (-not $targets) { $targets = @(Join-Path $HOME 'Documents') }
  }
  $targets = @($targets | Where-Object { Test-Path $_ })
  $cache = Join-Path $HOME 'security-scan\cache'

  foreach ($t in $targets) {
    $safe = ($t -replace '[^A-Za-z0-9]+', '_')
    Log "trivy fs: $t"
    $json = Join-Path $out "deps-$safe.json"
    & $trivy fs $t --pkg-types library --scanners vuln --severity $Severity --ignore-unfixed `
        --cache-dir $cache --format json --output $json --quiet 2>> $log | Out-Null
    & $trivy fs $t --pkg-types library --scanners vuln --severity $Severity --ignore-unfixed `
        --cache-dir $cache --format table --output (Join-Path $out "deps-$safe.txt") --quiet 2>> $log | Out-Null
    if (Test-Path $json) {
      try {
        $j = Get-Content $json -Raw | ConvertFrom-Json
        foreach ($res in @($j.Results)) {
          foreach ($v in @($res.Vulnerabilities)) {
            if ($null -eq $v) { continue }
            $depVulns += [pscustomobject]@{
              Target    = $t
              Package   = $v.PkgName
              Installed = $v.InstalledVersion
              Fixed     = $v.FixedVersion
              CVE       = $v.VulnerabilityID
              Severity  = $v.Severity
              Title     = $v.Title
            }
          }
        }
      } catch { Log "WARN: could not parse $json" }
    }
  }
  Log ("trivy: {0} dependency finding(s)" -f $depVulns.Count)
} else {
  Log 'WARN: trivy.exe not found - skipping dependency scan (see windows/install.ps1)'
}

# ------------------------------------------------------------------- summary
$crit = @($depVulns | Where-Object Severity -eq 'CRITICAL').Count
$high = @($depVulns | Where-Object Severity -eq 'HIGH').Count
$wuCritical = @($osUpdates | Where-Object Category -eq 'OS Critical').Count
$wuImportant = @($osUpdates | Where-Object Category -eq 'OS Important').Count

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# Security scan - $stamp")
[void]$sb.AppendLine()
[void]$sb.AppendLine('| Area | HIGH | CRITICAL |')
[void]$sb.AppendLine('|---|---|---|')
[void]$sb.AppendLine("| Windows dependencies (Trivy) | $high | $crit |")
[void]$sb.AppendLine("| Windows apps with updates (winget, not CVE-mapped) | $($pkgs.Count) | - |")
[void]$sb.AppendLine()
[void]$sb.AppendLine(("**Windows OS:** {0} pending update(s) (Critical {1}, Important {2}). Last installed patch: {3}." -f `
  $osUpdates.Count, $wuCritical, $wuImportant, $lastKb))
[void]$sb.AppendLine()

if ($depVulns.Count -gt 0) {
  [void]$sb.AppendLine('## Windows dependencies - fixable vulnerabilities')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Target | Package | Installed | Fixed | CVE | Severity |')
  [void]$sb.AppendLine('|---|---|---|---|---|---|')
  foreach ($v in ($depVulns | Sort-Object @{e={$_.Severity -ne 'CRITICAL'}}, Package | Select-Object -First 40)) {
    [void]$sb.AppendLine("| $($v.Target) | $($v.Package) | $($v.Installed) | $($v.Fixed) | $($v.CVE) | $($v.Severity) |")
  }
  [void]$sb.AppendLine()
}

if ($osUpdates.Count -gt 0) {
  [void]$sb.AppendLine('## Windows OS - pending updates')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Update | Category | KB |')
  [void]$sb.AppendLine('|---|---|---|')
  foreach ($u in ($osUpdates | Sort-Object Category, Title)) {
    [void]$sb.AppendLine("| $($u.Title -replace '\|', '/') | $($u.Category) | $($u.KB) |")
  }
  [void]$sb.AppendLine()
}

if ($pkgs.Count -gt 0) {
  [void]$sb.AppendLine('## Windows packages with updates available (winget)')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Package | Current | Available |')
  [void]$sb.AppendLine('|---|---|---|')
  foreach ($p in ($pkgs | Sort-Object Name | Select-Object -First 40)) {
    [void]$sb.AppendLine("| $($p.Name) | $($p.Current) | $($p.Available) |")
  }
  [void]$sb.AppendLine()
}

[void]$sb.AppendLine('## Notes')
[void]$sb.AppendLine()
[void]$sb.AppendLine('- Windows installed apps have no public CVE feed; the winget list means "outdated", not "vulnerable".')
[void]$sb.AppendLine('- Windows Update is the authoritative source for OS patches.')
[void]$sb.AppendLine('- Full evidence: JSON/TXT files in this folder.')

$sb.ToString() | Out-File -FilePath (Join-Path $out 'summary.md') -Encoding utf8
Log "summary written: $(Join-Path $out 'summary.md')"
exit 0
