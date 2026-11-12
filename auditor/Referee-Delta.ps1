<#
 REFEREE Delta - Before/After Attack-Surface Diff
 Compares two DeepScan JSON reports (a "before" and "after" snapshot) and
 reports how the user-reachable kernel attack surface changed.

 The headline use case: snapshot a machine, install a game / consumer app,
 snapshot again -> quantify exactly which user-reachable kernel drivers the
 install ADDED to the attack surface.

 A "snapshot" is simply a DeepScan run:
   powershell -File Referee-DeepScan.ps1          # before -> out\deepscan-<ts>.json
   <install the software>
   powershell -File Referee-DeepScan.ps1          # after  -> out\deepscan-<ts>.json
   powershell -File Referee-Delta.ps1 -Before <before.json> -After <after.json>

 DEFENSIVE: read-only. Consumes JSON only; touches no drivers.
#>
param(
  [Parameter(Mandatory=$true)][string]$Before,
  [Parameter(Mandatory=$true)][string]$After,
  [string]$OutDir = "",
  [string]$Label  = ""   # e.g. "install:Valorant"
)
$ErrorActionPreference = "Stop"
# $PSScriptRoot is unreliable in a param default when the script has mandatory
# params invoked via -File; resolve OutDir here in the body where it is set.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot "out" }
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
if (!(Test-Path $Before)) { Write-Error "Before report not found: $Before"; exit 1 }
if (!(Test-Path $After))  { Write-Error "After report not found: $After";  exit 1 }

Write-Host "`n=== REFEREE Delta: Attack-Surface Change Analysis ===" -ForegroundColor Cyan
if ($Label) { Write-Host "Event: $Label" -ForegroundColor White }

$b = Get-Content $Before -Raw -Encoding UTF8 | ConvertFrom-Json
$a = Get-Content $After  -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host "Before: $($b.host) @ $($b.generated)  ($($b.findings.Count) flagged)"
Write-Host "After : $($a.host) @ $($a.generated)  ($($a.findings.Count) flagged)`n"

# Index by driver filename
$bIdx = @{}; foreach ($f in $b.findings) { $bIdx[$f.driver] = $f }
$aIdx = @{}; foreach ($f in $a.findings) { $aIdx[$f.driver] = $f }

$added   = @()  # present after, absent before
$removed = @()  # present before, absent after
$changed = @()  # present both, risk posture moved

foreach ($drv in $aIdx.Keys) {
  if (-not $bIdx.ContainsKey($drv)) {
    $added += $aIdx[$drv]
  } else {
    $bf = $bIdx[$drv]; $af = $aIdx[$drv]
    $deltas = @()
    if ($bf.total_score -ne $af.total_score) { $deltas += "score $($bf.total_score)->$($af.total_score)" }
    if ($bf.acl_status  -ne $af.acl_status)  { $deltas += "reach $($bf.acl_status)->$($af.acl_status)" }
    if ($bf.reach_tier  -ne $af.reach_tier)  { $deltas += "tier $($bf.reach_tier)->$($af.reach_tier)" }
    if ("$($bf.lol_hash)" -ne "$($af.lol_hash)") { $deltas += "lol $($bf.lol_hash)->$($af.lol_hash)" }
    if ($deltas.Count -gt 0) {
      $changed += [pscustomobject]@{
        driver = $drv; category = $af.category
        before_score = $bf.total_score; after_score = $af.total_score
        before_reach = $bf.acl_status;  after_reach = $af.acl_status
        changes = ($deltas -join "; ")
      }
    }
  }
}
foreach ($drv in $bIdx.Keys) {
  if (-not $aIdx.ContainsKey($drv)) { $removed += $bIdx[$drv] }
}

# The important subset: drivers the event ADDED that are user-reachable
$addedReachable = $added | Where-Object { $_.acl_status -eq "USER_REACHABLE" } | Sort-Object total_score -Descending
$addedDangerous = $addedReachable | Where-Object { $_.risk_level -in @("CRITICAL","HIGH") }

Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Drivers ADDED:   $($added.Count)   (user-reachable: $($addedReachable.Count), CRITICAL/HIGH: $($addedDangerous.Count))" -ForegroundColor $(if($addedDangerous.Count){"Red"}else{"Gray"})
Write-Host "Drivers REMOVED: $($removed.Count)"
Write-Host "Drivers CHANGED: $($changed.Count)`n"

if ($addedReachable.Count -gt 0) {
  Write-Host "NEWLY USER-REACHABLE KERNEL DRIVERS (attack surface added):" -ForegroundColor Red
  $addedReachable | Select-Object driver, category, risk_level, total_score, reach_tier, lol_match |
    Format-Table -AutoSize
}
if ($changed.Count -gt 0) {
  Write-Host "RISK-POSTURE CHANGES (same driver, moved):" -ForegroundColor Yellow
  $changed | Format-Table driver, category, changes -AutoSize
}

# Save
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$delta = [pscustomobject]@{
  tool = "referee-delta"; version = "1.0"
  label = $Label
  before = @{ host=$b.host; generated=$b.generated; flagged=$b.findings.Count }
  after  = @{ host=$a.host; generated=$a.generated; flagged=$a.findings.Count }
  summary = @{
    added = $added.Count; removed = $removed.Count; changed = $changed.Count
    added_user_reachable = $addedReachable.Count
    added_dangerous = $addedDangerous.Count
  }
  added_reachable = $addedReachable
  added_all = $added
  removed = $removed
  changed = $changed
}
$jsonOut = "$OutDir\delta-$stamp.json"
$delta | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8

$mdOut = "$OutDir\delta-$stamp.md"
$md = @()
$md += "# REFEREE Attack-Surface Delta"
$md += ""
if ($Label) { $md += "**Event:** $Label`n" }
$md += "| | Before | After |"
$md += "|---|--------|-------|"
$md += "| Host | ``$($b.host)`` | ``$($a.host)`` |"
$md += "| Generated | $($b.generated) | $($a.generated) |"
$md += "| Flagged drivers | $($b.findings.Count) | $($a.findings.Count) |"
$md += ""
$md += "## What changed"
$md += "- **Added:** $($added.Count) (user-reachable: **$($addedReachable.Count)**, CRITICAL/HIGH: **$($addedDangerous.Count)**)"
$md += "- **Removed:** $($removed.Count)"
$md += "- **Changed posture:** $($changed.Count)"
$md += ""
if ($addedReachable.Count -gt 0) {
  $md += "## Newly user-reachable kernel drivers"
  $md += "_These device objects became openable from an unprivileged process after the event._"
  $md += ""
  $md += "| Driver | Category | Risk | Score | Tier | LOLDrivers |"
  $md += "|--------|----------|------|-------|------|------------|"
  foreach ($r in $addedReachable) {
    $md += "| ``$($r.driver)`` | $($r.category) | **$($r.risk_level)** | $($r.total_score) | $($r.reach_tier) | $($r.lol_match) |"
  }
  $md += ""
}
if ($changed.Count -gt 0) {
  $md += "## Risk-posture changes"
  $md += "| Driver | Category | Change |"
  $md += "|--------|----------|--------|"
  foreach ($c in $changed) { $md += "| ``$($c.driver)`` | $($c.category) | $($c.changes) |" }
}
$md -join "`n" | Out-File $mdOut -Encoding utf8

Write-Host "`nJSON:   $jsonOut"
Write-Host "Report: $mdOut"
Write-Host "=== DELTA COMPLETE ===" -ForegroundColor Cyan
