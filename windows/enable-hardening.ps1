<#
.SYNOPSIS
  Harden Windows document handling: ASR rules, SmartScreen, Windows Sandbox, scan context menu.

.DESCRIPTION
  Requires an elevated PowerShell. Applies, idempotently:

    * Attack Surface Reduction rules that matter for documents (Office child processes,
      Office code injection, Office executable content, Office macros calling Win32,
      email/webmail executable content, Adobe Reader child processes, lsass protection,
      PSExec/WMI process creation)
    * SmartScreen reputation checks in Block mode (policy + shell setting)
    * Windows Sandbox optional feature (Containers-DisposableClientVM)
    * a per-user "Scan with Microsoft Defender" context menu for files

  Start with -AuditOnly for a week to see what ASR would have blocked, then re-run without
  it to enforce. Use -Preview to print the planned changes without elevation.

.PARAMETER AuditOnly
  Put ASR rules in AuditMode instead of Enabled.

.PARAMETER Preview
  Print what would change; touch nothing. Works without elevation.

.PARAMETER SkipSandbox
  Do not enable the Windows Sandbox feature.

.PARAMETER SkipSmartScreen
  Do not change SmartScreen settings.

.EXAMPLE
  .\enable-hardening.ps1 -Preview

.EXAMPLE
  # elevated
  .\enable-hardening.ps1 -AuditOnly

.EXAMPLE
  # elevated, enforce everything
  .\enable-hardening.ps1
#>
[CmdletBinding()]
param(
  [switch]$AuditOnly,
  [switch]$Preview,
  [switch]$SkipSandbox,
  [switch]$SkipSmartScreen
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Preview) {
  throw 'Run this from an elevated PowerShell (Right-click > Run as administrator), or use -Preview.'
}

function Step([string]$what, [scriptblock]$action) {
  if ($Preview) {
    Write-Host "  [preview] $what"
    return
  }
  & $action
  Write-Host "  [ok] $what"
}

# Document-relevant ASR rules. GUIDs from Microsoft's ASR reference.
$rules = [ordered]@{
  'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office applications from creating child processes'
  '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office applications from injecting code into other processes'
  '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office applications from creating executable content'
  '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
  'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email client and webmail'
  '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
  '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from lsass.exe'
  'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creations originating from PSExec and WMI commands'
}

$mode = if ($AuditOnly) { 'AuditMode' } else { 'Enabled' }
Write-Host "ASR mode: $mode"

$applied = 0
foreach ($id in $rules.Keys) {
  $name = $rules[$id]
  Step "$name ($id)" {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $mode
  }
  $applied++
}
Write-Host "ASR rules: $applied/$($rules.Count) set to $mode"

# ---------------------------------------------------------------- SmartScreen
if (-not $SkipSmartScreen) {
  $shellKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
  $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
  Step 'Explorer SmartScreenEnabled = Block' {
    New-Item -Path $shellKey -Force | Out-Null
    Set-ItemProperty -Path $shellKey -Name SmartScreenEnabled -Value 'Block' -Type String
  }
  Step 'Policy EnableSmartScreen=1, ShellSmartScreenLevel=Block' {
    New-Item -Path $policyKey -Force | Out-Null
    Set-ItemProperty -Path $policyKey -Name EnableSmartScreen -Value 1 -Type DWord
    Set-ItemProperty -Path $policyKey -Name ShellSmartScreenLevel -Value 'Block' -Type String
  }
}

# --------------------------------------------------------------- Windows Sandbox
if (-not $SkipSandbox) {
  $feature = $null
  if ($isAdmin) {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction SilentlyContinue
  }
  if ($null -eq $feature) {
    $hint = if (-not $isAdmin) { '(needs elevation to inspect)' } else { '(feature not available on this edition)' }
    Write-Host "  [skip] Windows Sandbox state unknown $hint"
  } elseif ($feature.State -eq 'Enabled') {
    Write-Host '  [ok] Windows Sandbox already enabled'
  } else {
    Step 'Enable Windows Sandbox (reboot required)' {
      Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All -NoRestart | Out-Null
    }
  }
}

# --------------------------------------------------- per-user scan context menu
$cmd = 'powershell.exe -NoProfile -NoExit -Command "Start-MpScan -ScanType CustomScan -ScanPath ''%1''"'
$base = 'HKCU:\Software\Classes\*\shell\ScanWithDefender'
Step 'Add "Scan with Microsoft Defender" context menu' {
  New-Item -Path $base -Force | Out-Null
  Set-ItemProperty -LiteralPath $base -Name '(default)' -Value 'Scan with Microsoft Defender'
  Set-ItemProperty -LiteralPath $base -Name 'Icon' -Value 'C:\Program Files\Windows Defender\EppManifest.dll'
  New-Item -Path "$base\command" -Force | Out-Null
  Set-Item -LiteralPath "$base\command" -Value $cmd
}

Write-Host ''
Write-Host 'Verify with:'
Write-Host '  Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions'
Write-Host '  Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureVersion'
Write-Host '  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer").SmartScreenEnabled'
Write-Host '  Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Select-Object State'
