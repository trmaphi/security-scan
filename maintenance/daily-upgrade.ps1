<#
.SYNOPSIS
  Daily automated winget upgrade (user-scope only) with logging, exclusions and pre/post diff.

.DESCRIPTION
  Unattended winget upgrades are only reliable for user-scope packages: machine-scope
  installers raise a UAC prompt that blocks a scheduled task forever. This job therefore
  restricts itself to --scope user, and every winget invocation runs under a hard timeout
  so a stray installer prompt can never wedge the task.

.PARAMETER DryRun
  Only list what would be upgraded; changes nothing.
#>
param(
  [switch]$DryRun,
  [ValidateSet('user', 'machine', 'any')]
  [string]$Scope = 'user',
  [int]$TimeoutSeconds = 3600,
  [int]$PerPackageTimeoutSeconds = 600
)

$ErrorActionPreference = 'Continue'
$root    = 'C:\Users\trmaphi\winget-upgrade'
$logDir  = Join-Path $root 'logs'
$repDir  = Join-Path $root 'reports'
$stamp   = Get-Date -Format 'yyyy-MM-dd_HHmm'
$logFile = Join-Path $logDir "$stamp.log"
New-Item -ItemType Directory -Force -Path $logDir, $repDir | Out-Null

function Log([string]$msg) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
  Add-Content -Path $logFile -Value $line -Encoding utf8
  Write-Host $line
}

function Invoke-Winget {
  param([string[]]$WingetArgs, [int]$TimeoutSec)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'winget.exe'
  $psi.Arguments = ($WingetArgs -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $proc = [System.Diagnostics.Process]::Start($psi)
  $stdout = $proc.StandardOutput.ReadToEndAsync()
  $stderr = $proc.StandardError.ReadToEndAsync()
  $timedOut = -not $proc.WaitForExit($TimeoutSec * 1000)
  if ($timedOut) {
    & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null
  }
  $text = ''
  try { $text = $stdout.Result + $stderr.Result } catch { }
  return [pscustomobject]@{
    TimedOut = $timedOut
    ExitCode = if ($timedOut) { -1 } else { $proc.ExitCode }
    Output   = $text
  }
}

function Get-WingetUpgrades {
  $raw = (& winget upgrade --include-unknown --accept-source-agreements 2>&1 | Out-String)
  $rows = @()
  foreach ($line in ($raw -split "`r?`n")) {
    $m = [regex]::Match($line, '^(?<name>.+?)\s{2,}(?<id>\S+)\s+(?<ver>\S+)\s+(?<new>\S+)\s+(?<src>winget|msstore)\s*$')
    if ($m.Success) {
      $rows += [pscustomobject]@{
        Name      = $m.Groups['name'].Value.Trim()
        Id        = $m.Groups['id'].Value
        Current   = $m.Groups['ver'].Value
        Available = $m.Groups['new'].Value
      }
    }
  }
  return @($rows)
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "Winget daily upgrade started (admin=$isAdmin, dryRun=$($DryRun.IsPresent))"

$excludeFile = Join-Path $root 'exclude.txt'
$excluded = @()
if (Test-Path $excludeFile) {
  $excluded = Get-Content $excludeFile |
    Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }
}
$exclText = if ($excluded.Count -gt 0) { $excluded -join ', ' } else { 'none' }
Log ("exclusions: {0}" -f $exclText)

$before = Get-WingetUpgrades
$before | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 200 |
  Out-File -FilePath (Join-Path $logDir "$stamp-before.txt") -Encoding utf8
Log ("pre-upgrade: {0} package(s) pending" -f $before.Count)

if ($DryRun) {
  Log 'DRY RUN - not upgrading anything'
  foreach ($p in $before) {
    $flag = if ($excluded -contains $p.Id) { ' [excluded]' } else { '' }
    Write-Host ("  {0} {1} -> {2}{3}" -f $p.Id, $p.Current, $p.Available, $flag)
  }
  exit 0
}

$scopeArgs = @()
if ($Scope -ne 'any') { $scopeArgs = @('--scope', $Scope) }
if ($before.Count -gt 0) {
  if ($excluded.Count -gt 0) {
    $targets = @($before | Where-Object { $excluded -notcontains $_.Id })
    Log ("upgrading {0} package(s) individually, scope={1} (exclusions active)" -f $targets.Count, $Scope)
    foreach ($p in $targets) {
      Log "upgrade: $($p.Id) $($p.Current) -> $($p.Available)"
      $wingetArgs = @('upgrade', '--id', $p.Id, '--exact') + $scopeArgs + @(
        '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
      $r = Invoke-Winget $wingetArgs $PerPackageTimeoutSeconds
      Add-Content -Path $logFile -Value $r.Output -Encoding utf8
      $status = if ($r.TimedOut) { 'TIMEOUT (killed)' } else { "exit=$($r.ExitCode)" }
      Log "  $status"
      $results += [pscustomobject]@{ Id = $p.Id; TimedOut = $r.TimedOut; ExitCode = $r.ExitCode }
    }
  } else {
    Log ("upgrading all pending packages (winget upgrade --all, scope={0})" -f $Scope)
    $wingetArgs = @('upgrade', '--all') + $scopeArgs + @(
      '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    $r = Invoke-Winget $wingetArgs $TimeoutSeconds
    Add-Content -Path $logFile -Value $r.Output -Encoding utf8
    $status = if ($r.TimedOut) { 'TIMEOUT (killed after timeout)' } else { "exit=$($r.ExitCode)" }
    Log "winget upgrade --all: $status"
  }
}

$after = Get-WingetUpgrades
$after | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 200 |
  Out-File -FilePath (Join-Path $logDir "$stamp-after.txt") -Encoding utf8
$remaining = $after.Count
$fixed = [Math]::Max(0, $before.Count - $remaining)
Log ("post-upgrade: {0} still pending ({1} resolved)" -f $remaining, $fixed)

$failed = @($results | Where-Object { $_.ExitCode -ne 0 })

$repOut = Join-Path $repDir $stamp
New-Item -ItemType Directory -Force -Path $repOut | Out-Null
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# Winget daily upgrade - $stamp")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Metric | Value |")
[void]$sb.AppendLine("|---|---|")
[void]$sb.AppendLine("| Pending before | $($before.Count) |")
[void]$sb.AppendLine("| Pending after | $remaining |")
[void]$sb.AppendLine("| Resolved | $fixed |")
[void]$sb.AppendLine("| Elevated | $isAdmin |")
[void]$sb.AppendLine("| Scope | user only (machine-scope needs an elevated task) |")
[void]$sb.AppendLine()

if ($after.Count -gt 0) {
  [void]$sb.AppendLine('## Still pending')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Package | Id | Current | Available |')
  [void]$sb.AppendLine('|---|---|---|---|')
  foreach ($p in ($after | Sort-Object Name)) {
    [void]$sb.AppendLine("| $($p.Name) | $($p.Id) | $($p.Current) | $($p.Available) |")
  }
  [void]$sb.AppendLine()
}

if ($failed.Count -gt 0) {
  [void]$sb.AppendLine('## Failed or timed-out upgrades')
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('| Package | Result |')
  [void]$sb.AppendLine('|---|---|')
  foreach ($f in $failed) {
    $label = if ($f.TimedOut) { 'timeout (killed)' } else { "exit $($f.ExitCode)" }
    [void]$sb.AppendLine("| $($f.Id) | $label |")
  }
  [void]$sb.AppendLine()
}

[void]$sb.AppendLine('## Notes')
[void]$sb.AppendLine()
[void]$sb.AppendLine('- Logs: `logs\<timestamp>.log`, `-before.txt`, `-after.txt`.')
[void]$sb.AppendLine('- Machine-scope packages are skipped by design; they would raise UAC prompts and hang the task.')
[void]$sb.AppendLine('- A timeout means an installer waited for consent; the process tree was killed.')

$sb.ToString() | Out-File -FilePath (Join-Path $repOut 'summary.md') -Encoding utf8
Log "report: $(Join-Path $repOut 'summary.md')"
Log 'Winget daily upgrade finished'
exit 0
