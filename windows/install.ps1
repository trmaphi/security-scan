<#
.SYNOPSIS
  Install Trivy and register the daily scan/upgrade tasks on Windows.

.DESCRIPTION
  Downloads the latest Trivy release into "%USERPROFILE%\security-scan\bin" and (unless
  -NoTasks) registers two per-user scheduled tasks:

    Security Scan Daily    runs windows\vuln-scan.ps1
    Winget Upgrade Daily   runs windows\winget-upgrade.ps1 (scope=user)

  Creating the tasks does not require elevation. Machine-scope winget upgrades do; see the
  README section "Elevated upgrades".

.PARAMETER TrivyVersion
  Release tag (e.g. v0.76.2) or "latest".

.PARAMETER InstallDir
  Root for binaries/cache. Defaults to "%USERPROFILE%\security-scan".

.PARAMETER ScanTime
  Daily time for the vulnerability scan (HH:mm). Default 03:00.

.PARAMETER UpgradeTime
  Daily time for the winget upgrade job (HH:mm). Default 04:00.

.PARAMETER NoTasks
  Only install binaries.

.EXAMPLE
  .\install.ps1
#>
[CmdletBinding()]
param(
  [string]$TrivyVersion = 'latest',
  [string]$InstallDir = (Join-Path $HOME 'security-scan'),
  [string]$ScanTime = '03:00',
  [string]$UpgradeTime = '04:00',
  [switch]$NoTasks
)

$ErrorActionPreference = 'Stop'
$binDir = Join-Path $InstallDir 'bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

function Get-LatestTrivyTag {
  $headers = @{ 'User-Agent' = 'security-scan-installer' }
  $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/aquasecurity/trivy/releases/latest' -Headers $headers
  return $release.tag_name
}

if ($TrivyVersion -eq 'latest') {
  Write-Host 'Resolving latest Trivy release...'
  $TrivyVersion = Get-LatestTrivyTag
}
$verNoV = $TrivyVersion.TrimStart('v')
$zipName = "trivy_${verNoV}_windows-64bit.zip"
$url = "https://github.com/aquasecurity/trivy/releases/download/$TrivyVersion/$zipName"
$zipPath = Join-Path $env:TEMP $zipName

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $binDir -Force
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

$trivy = Join-Path $binDir 'trivy.exe'
if (-not (Test-Path $trivy)) { throw "Trivy binary not found after extraction: $trivy" }
Write-Host ("Installed Trivy: " + (& $trivy --version))
& $trivy fs --download-db-only --cache-dir (Join-Path $InstallDir 'cache') 2>&1 | Out-Null
Write-Host 'Vulnerability DB primed.'

if (-not $NoTasks) {
  $scanScript = Join-Path $PSScriptRoot 'vuln-scan.ps1'
  $upgradeScript = Join-Path $PSScriptRoot 'winget-upgrade.ps1'
  if (-not (Test-Path $scanScript)) { throw "Missing $scanScript" }
  if (-not (Test-Path $upgradeScript)) { throw "Missing $upgradeScript" }

  $ps = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File'
  schtasks.exe /Create /TN "Security Scan Daily" /TR "$ps `"$scanScript`"" /SC DAILY /ST $ScanTime /F | Out-Null
  schtasks.exe /Create /TN "Winget Upgrade Daily" /TR "$ps `"$upgradeScript`" -Scope user" /SC DAILY /ST $UpgradeTime /F | Out-Null

  Write-Host ''
  Write-Host "Tasks registered:"
  Write-Host "  Security Scan Daily   at $ScanTime"
  Write-Host "  Winget Upgrade Daily  at $UpgradeTime (scope=user)"
  Write-Host ''
  Write-Host 'Machine-scope upgrades need elevation. From an ADMIN PowerShell run:'
  Write-Host ('  schtasks /Create /TN "Winget Upgrade Daily" /TR ''{0} "{1}" -Scope any'' /SC DAILY /ST {2} /RL HIGHEST /F' -f $ps, $upgradeScript, $UpgradeTime)
}
