<#
.SYNOPSIS
  Scan a single file with Microsoft Defender before you open it.

.DESCRIPTION
  Prints the file's SHA-256, whether it carries a Mark-of-the-Web (downloaded from the
  internet), and runs a Defender custom scan on that file only. A verdict of "clean" means
  Defender found nothing at scan time - it is not a guarantee, especially for brand-new files.

.PARAMETER Path
  File to scan. Required.

.PARAMETER Quiet
  Only print the verdict line.

.EXAMPLE
  .\scan-file.ps1 -Path .\invoice.pdf

.EXAMPLE
  Get-ChildItem .\inbox\*.docx | ForEach-Object { .\scan-file.ps1 -Path $_.FullName }
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Path,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$file = Get-Item -LiteralPath $Path -ErrorAction Stop
if ($file.PSIsContainer) { throw "$Path is a directory, not a file" }

$hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash

# Mark-of-the-Web lives in the Zone.Identifier alternate data stream.
$zone = $null
try {
  $zone = Get-Content -LiteralPath $file.FullName -Stream Zone.Identifier -ErrorAction Stop
} catch { }
$motw = if ($zone) { 'YES (downloaded)' } else { 'no' }

$detectionsBefore = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
$started = Get-Date
$scanError = $null
try {
  Start-MpScan -ScanType CustomScan -ScanPath $file.FullName -ErrorAction Stop
} catch {
  $scanError = $_.Exception.Message
}

$newDetections = @()
if (-not $scanError) {
  $newDetections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
    Where-Object { $_.InitialDetectionTime -ge $started.AddSeconds(-5) -and
                   ($_.Resources -join ';') -match [regex]::Escape($file.Name) })
}

$verdict = if ($scanError) { "ERROR: $scanError" }
           elseif ($newDetections.Count -gt 0) { 'THREAT DETECTED' }
           else { 'clean' }

if ($Quiet) {
  "{0}: {1}" -f $file.Name, $verdict
  exit $(if ($verdict -eq 'clean') { 0 } else { 2 })
}

Write-Host ''
Write-Host "File     : $($file.FullName)"
Write-Host "Size     : $($file.Length) bytes"
Write-Host "SHA-256  : $hash"
Write-Host "MOTW     : $motw"
Write-Host "Scanned  : $($started.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Verdict  : $verdict"
if ($newDetections.Count -gt 0) {
  Write-Host ''
  foreach ($d in $newDetections) {
    Write-Host "  Threat: $($d.ThreatID)  $($d.Resources -join ';')"
    Write-Host "  Action: $($d.ActionSuccess)  $(($d.InitialDetectionTime))"
  }
  Write-Host ''
  Write-Host 'Do NOT open this file. If you already did, run a full scan and check startup items.'
}
exit $(if ($verdict -eq 'clean') { 0 } else { 2 })
