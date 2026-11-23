<#
.SYNOPSIS
  Weekly vulnerability scan: Windows dependencies (Trivy), Windows package upgrades (winget),
  and the WSL Ubuntu system (Trivy OS + dependency scan inside WSL).

.DESCRIPTION
  Produces a timestamped folder under C:\Users\trmaphi\vulnscan\reports with:
    winget-upgrades.txt / .json   - installed Windows packages with newer versions available
    windows-deps-*.txt / .json    - HIGH/CRITICAL CVEs in language dependencies (with fixes)
    ubuntu-os.txt / .json         - HIGH/CRITICAL CVEs in installed Ubuntu packages
    wsl-deps-*.txt / .json        - HIGH/CRITICAL CVEs in dependencies inside WSL
    summary.md                    - human-readable rollup
    run.log                       - execution log

.PARAMETER Upgrade
  Additionally run "winget upgrade --all" (silent) after reporting. Off by default.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File run-weekly.ps1
#>
param([switch]$Upgrade)

$ErrorActionPreference = 'Continue'
$root   = 'C:\Users\trmaphi\vulnscan'
$trivy  = Join-Path $root 'bin\trivy.exe'
$cache  = Join-Path $root 'cache'
$stamp  = Get-Date -Format 'yyyy-MM-dd_HHmm'
$out    = Join-Path $root "reports\$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'run.log'

function Log([string]$msg) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
  Add-Content -Path $log -Value $line -Encoding utf8
  Write-Host $line
}

Log "VulnScan weekly run started -> $out"

# ---------------------------------------------------------------- winget audit
Log 'winget: checking for available upgrades'
try {
  $wingetRaw = (& winget upgrade --include-unknown --accept-source-agreements 2>&1 | Out-String)
} catch {
  $wingetRaw = "winget failed: $($_.Exception.Message)"
}
$wingetRaw | Out-File -FilePath (Join-Path $out 'winget-upgrades.raw.txt') -Encoding utf8

$pkgs = @()
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

# ------------------------------------------------------ Windows OS patch status
# Windows has no package-CVE feed like Ubuntu's, so report pending Windows Update
# items (security/quality/driver) plus the last installed security update.
Log 'windows: querying Windows Update for pending patches'
$osUpdates = New-Object System.Collections.Generic.List[object]
try {
  $wuSession = New-Object -ComObject Microsoft.Update.Session
  $wuSearcher = $wuSession.CreateUpdateSearcher()
  $wuResult = $wuSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
  foreach ($u in $wuResult.Updates) {
    $sev = if ($u.MsrcSeverity) { [string]$u.MsrcSeverity } else { '' }
    $cat = if ($u.Title -match 'Defender Antivirus') { 'Defender signature' }
           elseif ($sev) { "OS $sev" }
           else { 'Other' }
    $osUpdates.Add([pscustomobject]@{
      Title      = $u.Title
      Severity   = $sev
      Category   = $cat
      KB         = ($u.KBArticleIDs -join ',')
      Downloaded = [bool]$u.IsDownloaded
    })
  }
} catch {
  Log "WARN: Windows Update query failed: $($_.Exception.Message)"
}
$osUpdates | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $out 'windows-os-updates.json') -Encoding utf8
if ($osUpdates.Count -gt 0) {
  $osUpdates | Format-Table -AutoSize | Out-String -Width 220 |
    Out-File -FilePath (Join-Path $out 'windows-os-updates.txt') -Encoding utf8
}
$wuCritical  = @($osUpdates | Where-Object Category -eq 'OS Critical').Count
$wuImportant = @($osUpdates | Where-Object Category -eq 'OS Important').Count
$wuDefender  = @($osUpdates | Where-Object Category -eq 'Defender signature').Count
$lastHotfix = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1)
$lastKb = if ($lastHotfix.Count -gt 0) { "$($lastHotfix[0].HotFixID) ($($lastHotfix[0].InstalledOn.ToString('yyyy-MM-dd')))" } else { 'unknown' }
Log ("windows: {0} pending OS update(s) (Critical {1}, Important {2}, Defender {3}); last patch {4}" -f $osUpdates.Count, $wuCritical, $wuImportant, $wuDefender, $lastKb)

# --------------------------------------------------- Windows dependency scan
$vulns = New-Object System.Collections.Generic.List[object]
$pathsFile = Join-Path $root 'paths-windows.txt'
$targets = @()
if (Test-Path $pathsFile) {
  $targets = Get-Content $pathsFile |
    Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') -and (Test-Path $_) }
}
if ($targets.Count -eq 0) { $targets = @('C:\Users\trmaphi\Documents') }

foreach ($t in $targets) {
  $safe = ($t -replace '[^A-Za-z0-9]+', '_')
  $json = Join-Path $out "windows-deps-$safe.json"
  $tbl  = Join-Path $out "windows-deps-$safe.txt"
  Log "trivy fs (dependencies): $t"
  & $trivy fs $t --pkg-types library --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed `
      --cache-dir $cache --format json --output $json --quiet 2>> $log | Out-Null
  & $trivy fs $t --pkg-types library --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed `
      --cache-dir $cache --format table --output $tbl --quiet 2>> $log | Out-Null
  if (Test-Path $json) {
    try {
      $j = Get-Content $json -Raw | ConvertFrom-Json
      foreach ($res in @($j.Results)) {
        foreach ($v in @($res.Vulnerabilities)) {
          if ($null -eq $v) { continue }
          $vulns.Add([pscustomobject]@{
            Source    = 'windows'
            Target    = $t
            Package   = $v.PkgName
            Installed = $v.InstalledVersion
            Fixed     = $v.FixedVersion
            CVE       = $v.VulnerabilityID
            Severity  = $v.Severity
            Title     = $v.Title
          })
        }
      }
    } catch { Log "WARN: could not parse $json" }
  }
}

# ------------------------------------------------------------- WSL Ubuntu scan
$wslOut = "/mnt/c/Users/trmaphi/vulnscan/reports/$stamp"
Log 'WSL: launching Ubuntu scan (OS packages + project dependencies)'
& wsl.exe -d Ubuntu -- /home/trmaphi/vulnscan/scan-wsl.sh $wslOut 2>&1 | Out-Null
Log "WSL: scan finished (exit=$LASTEXITCODE)"

$ubuntuVulns = @()
# apt candidate versions produced by the WSL scan: a package is only truly
# upgradable when apt offers a candidate that differs from what is installed.
$aptStatus = @{}
$aptTsv = Join-Path $out 'apt-status.tsv'
if (Test-Path $aptTsv) {
  foreach ($line in (Get-Content $aptTsv)) {
    $parts = $line -split "`t"
    if ($parts.Count -ge 3 -and $parts[0] -ne 'package') {
      $aptStatus[$parts[0]] = [pscustomobject]@{ Installed = $parts[1]; Candidate = $parts[2] }
    }
  }
}
$ubuntuJson = Join-Path $out 'ubuntu-os.json'
if (Test-Path $ubuntuJson) {
  try {
    $uj = Get-Content $ubuntuJson -Raw | ConvertFrom-Json
    foreach ($res in @($uj.Results)) {
      foreach ($v in @($res.Vulnerabilities)) {
        if ($null -eq $v) { continue }
        $legacy = $false
        if ($aptStatus.ContainsKey($v.PkgName)) {
          $st = $aptStatus[$v.PkgName]
          $legacy = (-not $st.Candidate) -or ($st.Candidate -eq $st.Installed)
        } elseif ($v.FixedVersion) {
          $im = ($v.InstalledVersion -split '\.')[0]
          $fm = ($v.FixedVersion -split '\.')[0]
          $legacy = ($im -ne $fm)
        }
        $ubuntuVulns += [pscustomobject]@{
          Package   = $v.PkgName
          Installed = $v.InstalledVersion
          Fixed     = $v.FixedVersion
          CVE       = $v.VulnerabilityID
          Severity  = $v.Severity
          Title     = $v.Title
          Legacy    = $legacy
        }
      }
    }
  } catch { Log 'WARN: could not parse ubuntu-os.json' }
} else {
  Log 'WARN: ubuntu-os.json missing; OS package findings unavailable for this run'
}

# --------------------------------------------- WSL dependency results (OSV)
$wslDeps = New-Object System.Collections.Generic.List[object]
$wslSummary = $null
Get-ChildItem -Path $out -Filter 'wsl-deps-*.md' -ErrorAction SilentlyContinue | ForEach-Object {
  $lines = Get-Content $_.FullName
  $totalLine = $lines | Where-Object { $_ -match '^Total .* known vulnerabilities' } | Select-Object -First 1
  if ($totalLine) {
    $m = [regex]::Match($totalLine, 'Total (?<pkgs>\d+) packages affected by (?<vulns>\d+) known vulnerabilities \((?<detail>[^)]*)\)')
    if ($m.Success) {
      $detail = @{}
      foreach ($part in ($m.Groups['detail'].Value -split ',')) {
        $p = $part.Trim() -split '\s+', 2
        if ($p.Count -eq 2) { $detail[$p[1]] = [int]$p[0] }
      }
      $wslSummary = [pscustomobject]@{
        Packages        = [int]$m.Groups['pkgs'].Value
        Vulnerabilities = [int]$m.Groups['vulns'].Value
        Critical        = [int]$detail['Critical']
        High            = [int]$detail['High']
        Medium          = [int]$detail['Medium']
        Low             = [int]$detail['Low']
      }
    }
  }
  foreach ($line in $lines) {
    if ($line -notmatch '^\|\s*https?://') { continue }
    $cols = $line.Trim().Trim('|') -split '\|'
    if ($cols.Count -lt 7) { continue }
    $ids = [regex]::Matches($cols[0], 'osv\.dev/([A-Za-z0-9\-]+)') | ForEach-Object { $_.Groups[1].Value }
    $cvss = 0.0
    [void][double]::TryParse($cols[1].Trim(), [ref]$cvss)
    $sev = if ($cvss -ge 9.0) { 'CRITICAL' } elseif ($cvss -ge 7.0) { 'HIGH' } elseif ($cvss -ge 4.0) { 'MEDIUM' } else { 'LOW' }
    $wslDeps.Add([pscustomobject]@{
      Package   = $cols[3].Trim()
      Version   = $cols[4].Trim()
      Ecosystem = $cols[2].Trim()
      Fixed     = $cols[5].Trim()
      Id        = ($ids -join ';')
      Severity  = $sev
      Cvss      = $cvss
      Source    = ($cols[6..($cols.Count - 1)] -join '|').Trim()
    })
  }
}

# ---------------------------------------------------------------- summary
$crit = @($vulns | Where-Object Severity -eq 'CRITICAL').Count
$high = @($vulns | Where-Object Severity -eq 'HIGH').Count
$ucrit = @($ubuntuVulns | Where-Object Severity -eq 'CRITICAL').Count
$uhigh = @($ubuntuVulns | Where-Object Severity -eq 'HIGH').Count
# The same advisory shows up once per lockfile that pins the package; count unique
# (package, version, advisory) triples for the headline numbers.
$wslUniq = $wslDeps | Sort-Object Package, Version, Id -Unique
if ($wslUniq.Count -gt 0) {
  $wcrit = @($wslUniq | Where-Object Severity -eq 'CRITICAL').Count
  $whigh = @($wslUniq | Where-Object Severity -eq 'HIGH').Count
} else {
  $wcrit = 0
  $whigh = 0
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# Vulnerability scan - $stamp")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Area | HIGH | CRITICAL |")
[void]$sb.AppendLine("|---|---|---|")
[void]$sb.AppendLine("| WSL Ubuntu OS packages | $uhigh | $ucrit |")
[void]$sb.AppendLine("| WSL dependencies (OSV) | $whigh | $wcrit |")
[void]$sb.AppendLine("| Windows dependencies | $high | $crit |")
[void]$sb.AppendLine("| Windows packages with updates (winget, not CVE-mapped) | $($pkgs.Count) | - |")
[void]$sb.AppendLine()
[void]$sb.AppendLine(("**Windows OS:** {0} pending update(s) (Critical {1}, Important {2}, Defender signature {3}). Last installed patch: {4}." -f `
  $osUpdates.Count, $wuCritical, $wuImportant, $wuDefender, $lastKb))
[void]$sb.AppendLine()

if ($ubuntuVulns.Count -gt 0) {
  [void]$sb.AppendLine('## WSL Ubuntu - OS vulnerabilities with fixes')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Package | Installed | Fixed | CVE | Severity | Note |')
  [void]$sb.AppendLine('|---|---|---|---|---|---|')
  foreach ($v in ($ubuntuVulns | Sort-Object @{e={$_.Severity -ne 'CRITICAL'}}, Legacy, Package | Select-Object -First 25)) {
    $note = if ($v.Legacy) { 'legacy pkg - no repo upgrade' } else { '' }
    [void]$sb.AppendLine("| $($v.Package) | $($v.Installed) | $($v.Fixed) | $($v.CVE) | $($v.Severity) | $note |")
  }
  [void]$sb.AppendLine()
  $upgradable = @($ubuntuVulns | Where-Object { -not $_.Legacy } | ForEach-Object Package | Sort-Object -Unique)
  $legacyPkgs = @($ubuntuVulns | Where-Object Legacy | ForEach-Object Package | Sort-Object -Unique)
  if ($upgradable.Count -gt 0) {
    [void]$sb.AppendLine('Remediate: `sudo apt-get update && sudo apt-get install --only-upgrade ' + ($upgradable -join ' ') + '`')
    [void]$sb.AppendLine()
  }
  if ($legacyPkgs.Count -gt 0) {
    [void]$sb.AppendLine(('**No repository fix available for: {0}.** These are manually installed / legacy packages (typically left behind by apps that need an old ABI). They cannot be upgraded in place - the fix is to replace or remove them together with the dependents that require them.' -f ($legacyPkgs -join ', ')))
    [void]$sb.AppendLine()
  }
}

if ($wslDeps.Count -gt 0) {
  [void]$sb.AppendLine('## WSL dependencies - OSV advisories')
  [void]$sb.AppendLine()
  if ($wslSummary) {
    [void]$sb.AppendLine(('{0} raw occurrences across {1} packages collapsed to {2} unique advisories.' -f `
      $wslSummary.Vulnerabilities, $wslSummary.Packages, $wslUniq.Count))
    [void]$sb.AppendLine()
  }
  [void]$sb.AppendLine('| Package | Version | Ecosystem | Advisory | Severity | Fixed |')
  [void]$sb.AppendLine('|---|---|---|---|---|---|')
  $uniq = $wslDeps | Sort-Object Package, Version, Id -Unique |
    Sort-Object @{e={$_.Severity -ne 'CRITICAL'}}, Package | Select-Object -First 25
  foreach ($d in $uniq) {
    [void]$sb.AppendLine("| $($d.Package) | $($d.Version) | $($d.Ecosystem) | $($d.Id) | $($d.Severity) | $($d.Fixed) |")
  }
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('Fix: bump each package to the "Fixed" version. Full report: `wsl-deps-*.md`.')
  [void]$sb.AppendLine()
}

if ($vulns.Count -gt 0) {
  [void]$sb.AppendLine('## Windows dependencies - fixable vulnerabilities')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Target | Package | Installed | Fixed | CVE | Severity |')
  [void]$sb.AppendLine('|---|---|---|---|---|---|')
  foreach ($v in ($vulns | Sort-Object @{e={$_.Severity -ne 'CRITICAL'}}, Package | Select-Object -First 25)) {
    [void]$sb.AppendLine("| $($v.Target) | $($v.Package) | $($v.Installed) | $($v.Fixed) | $($v.CVE) | $($v.Severity) |")
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
  [void]$sb.AppendLine('Upgrade all: `winget upgrade --all --silent`')
  [void]$sb.AppendLine()
}

if ($osUpdates.Count -gt 0) {
  [void]$sb.AppendLine('## Windows OS - pending updates')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Update | Category | KB |')
  [void]$sb.AppendLine('|---|---|---|')
  foreach ($u in ($osUpdates | Sort-Object Category, Title)) {
    $title = $u.Title -replace '\|', '/'
    [void]$sb.AppendLine("| $title | $($u.Category) | $($u.KB) |")
  }
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('Install with Settings > Windows Update, or `powershell -Command "Start-Process ms-settings:windowsupdate"`. Defender signatures update automatically.')
  [void]$sb.AppendLine()
}

[void]$sb.AppendLine('## Notes')
[void]$sb.AppendLine()
[void]$sb.AppendLine('- Ubuntu security updates are already applied automatically by `unattended-upgrades` (apt-daily-upgrade.timer); this report shows what is still fixable.')
[void]$sb.AppendLine('- Windows installed-app CVEs are not covered by open-source scanners; the winget list is "outdated", not "vulnerable". Defender covers OS-level patching.')
[void]$sb.AppendLine('- Full evidence: JSON files in this folder.')

$sb.ToString() | Out-File -FilePath (Join-Path $out 'summary.md') -Encoding utf8
Log ("summary: Ubuntu {0} findings (H={1}, C={2}); WSL deps {3} (H={4}, C={5}); Windows deps {6} (H={7}, C={8}); winget {9} updates; Windows OS {10} pending" -f `
    $ubuntuVulns.Count, $uhigh, $ucrit, $wslDeps.Count, $whigh, $wcrit, $vulns.Count, $high, $crit, $pkgs.Count, $osUpdates.Count)

# ------------------------------------------------------------- optional upgrade
if ($Upgrade) {
  Log 'winget: upgrading all packages (silent)'
  & winget upgrade --all --silent --accept-package-agreements --accept-source-agreements 2>&1 |
    Tee-Object -FilePath (Join-Path $out 'winget-upgrade.log') -Append | Out-Null
  Log "winget upgrade exit=$LASTEXITCODE"
}

Log 'VulnScan weekly run finished'
exit 0
