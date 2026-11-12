<#
 REFEREE Fleet - Multi-Host Runner & Aggregator
 Runs the DeepScan across a fleet of Windows hosts over PowerShell Remoting,
 pulls each host's JSON report back, and merges them into one fleet dataset.

 Turns REFEREE from a single-box demo into a blue-team fleet audit: scan N
 machines, see which driver categories are reachable fleet-wide, and find
 the drivers that are reachable on some boxes but not others.

 Usage:
   # Scan the local host only (no remoting needed):
   powershell -File Referee-Fleet.ps1 -Local

   # Scan a list of remote hosts (requires WinRM + admin creds):
   powershell -File Referee-Fleet.ps1 -Hosts gpc01,dev02,ent03 -Credential (Get-Credential)

   # Aggregate already-collected per-host JSONs without scanning:
   powershell -File Referee-Fleet.ps1 -AggregateOnly -ReportDir .\out\fleet

 DEFENSIVE: runs the read-only DeepScan on each host; collects JSON only.
#>
[CmdletBinding()]
param(
  [string[]]$Hosts = @(),
  [switch]$Local,
  [switch]$AggregateOnly,
  [System.Management.Automation.PSCredential]$Credential,
  [string]$ScannerPath = "$PSScriptRoot\Referee-DeepScan.ps1",
  [string]$OutDir = "$PSScriptRoot\out\fleet"
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

Write-Host "`n=== REFEREE Fleet Runner ===" -ForegroundColor Cyan

function Invoke-LocalScan {
  Write-Host "[*] Scanning local host: $env:COMPUTERNAME" -ForegroundColor Yellow
  $scanDir = Split-Path $ScannerPath -Parent
  if (Test-Path $ScannerPath) {
    & powershell -ExecutionPolicy Bypass -File $ScannerPath | Out-Null
  } else {
    Write-Host "    Scanner not at $ScannerPath — using latest existing report" -ForegroundColor Yellow
  }
  $latest = Get-ChildItem "$scanDir\out\deepscan-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($latest) {
    $dest = "$OutDir\$($env:COMPUTERNAME)-$($latest.Name)"
    Copy-Item $latest.FullName $dest -Force
    Write-Host "    collected -> $dest" -ForegroundColor Green
    return $dest
  }
  return $null
}

function Invoke-RemoteScan([string]$Target) {
  Write-Host "[*] Scanning remote host: $Target" -ForegroundColor Yellow
  $scanner = Get-Content $ScannerPath -Raw
  $lol = "$PSScriptRoot\loldrivers-simple.json"
  $sig = "$PSScriptRoot\signatures.json"
  $so = if ($Credential) { @{ComputerName=$Target; Credential=$Credential} } else { @{ComputerName=$Target} }
  try {
    $sess = New-PSSession @so -ErrorAction Stop
    # Stage DB + signatures + scanner into a temp dir on the remote host
    $remoteDir = Invoke-Command -Session $sess -ScriptBlock {
      $d = Join-Path $env:TEMP "referee"
      New-Item -ItemType Directory -Path $d -Force | Out-Null
      $d
    }
    Copy-Item $lol -Destination "$remoteDir\loldrivers-simple.json" -ToSession $sess -Force
    Copy-Item $sig -Destination "$remoteDir\signatures.json" -ToSession $sess -Force
    Copy-Item $ScannerPath -Destination "$remoteDir\Referee-DeepScan.ps1" -ToSession $sess -Force
    # Run it
    Invoke-Command -Session $sess -ScriptBlock {
      param($d)
      & powershell -ExecutionPolicy Bypass -File "$d\Referee-DeepScan.ps1" | Out-Null
    } -ArgumentList $remoteDir
    # Pull the JSON back
    $remoteJson = Invoke-Command -Session $sess -ScriptBlock {
      param($d)
      (Get-ChildItem "$d\out\deepscan-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    } -ArgumentList $remoteDir
    if ($remoteJson) {
      $dest = "$OutDir\$Target-$(Split-Path $remoteJson -Leaf)"
      Copy-Item $remoteJson -Destination $dest -FromSession $sess -Force
      Write-Host "    collected -> $dest" -ForegroundColor Green
      Remove-PSSession $sess
      return $dest
    }
    Remove-PSSession $sess
  } catch {
    Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
  }
  return $null
}

# ---- Collect per-host reports ----
$reports = @()
if (-not $AggregateOnly) {
  if ($Local -or $Hosts.Count -eq 0) { $r = Invoke-LocalScan; if ($r) { $reports += $r } }
  foreach ($h in $Hosts) { $r = Invoke-RemoteScan $h; if ($r) { $reports += $r } }
} else {
  $reports = (Get-ChildItem "$OutDir\*deepscan-*.json").FullName
}

if ($reports.Count -eq 0) { Write-Error "No host reports collected."; exit 1 }
Write-Host "`n[*] Aggregating $($reports.Count) host report(s)..." -ForegroundColor Yellow

# ---- Aggregate ----
$hostsData = @()
$driverFleet = @{}   # driver -> list of {host, reachable, tier, score, hash}
foreach ($rp in $reports) {
  $rep = Get-Content $rp -Raw -Encoding UTF8 | ConvertFrom-Json
  $hostsData += [pscustomobject]@{
    host = $rep.host; os = $rep.os; generated = $rep.generated
    total = $rep.total_drivers; flagged = $rep.flagged
    critical = $rep.stats.critical; high = $rep.stats.high
    user_reachable = $rep.stats.user_reachable
    low_tier = $rep.stats.reach_low_tier
  }
  foreach ($f in $rep.findings) {
    if (-not $driverFleet.ContainsKey($f.driver)) { $driverFleet[$f.driver] = @() }
    $driverFleet[$f.driver] += [pscustomobject]@{
      host = $rep.host; reachable = $f.acl_status; tier = $f.reach_tier
      score = $f.total_score; risk = $f.risk_level; category = $f.category
    }
  }
}

# Drivers reachable on SOME hosts but not others (config drift = interesting)
$driftDrivers = @()
foreach ($drv in $driverFleet.Keys) {
  $obs = $driverFleet[$drv]
  $reach = ($obs | Where-Object { $_.reachable -eq "USER_REACHABLE" }).Count
  $seen  = $obs.Count
  if ($reach -gt 0 -and $reach -lt $seen) {
    $driftDrivers += [pscustomobject]@{
      driver = $drv; category = $obs[0].category
      reachable_on = $reach; seen_on = $seen
      hosts_reachable = (($obs | Where-Object { $_.reachable -eq "USER_REACHABLE" }).host -join ",")
    }
  }
}

Write-Host "`n=== FLEET SUMMARY ===" -ForegroundColor Cyan
$hostsData | Format-Table host, os, total, flagged, critical, high, user_reachable, low_tier -AutoSize

if ($driftDrivers.Count -gt 0) {
  Write-Host "CONFIG-DRIFT DRIVERS (reachable on some hosts, restricted on others):" -ForegroundColor Yellow
  $driftDrivers | Sort-Object reachable_on -Descending | Format-Table driver, category, reachable_on, seen_on -AutoSize
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fleet = [pscustomobject]@{
  tool = "referee-fleet"; version = "1.0"; generated = (Get-Date -Format o)
  host_count = $hostsData.Count
  hosts = $hostsData
  unique_flagged_drivers = $driverFleet.Count
  drift_drivers = $driftDrivers
}
$jsonOut = "$OutDir\fleet-$stamp.json"
$fleet | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8
Write-Host "`nFleet dataset: $jsonOut"
Write-Host "=== FLEET COMPLETE ===" -ForegroundColor Cyan
