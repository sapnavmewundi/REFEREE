<#
 REFEREE Gap Analysis - What Catalogs Miss
 Proves REFEREE's value over catalog-only approaches (loldrivers.io, static
 blocklists) by finding drivers that are HIGH-CAPABILITY and USER-REACHABLE
 but ABSENT from the known-vulnerable catalog.

 The thesis: a reachable, high-capability driver is part of your attack
 surface whether or not anyone has catalogued it yet. Catalog-only triage
 misses exactly these. REFEREE's reachability axis surfaces them.

 Consumes a DeepScan JSON report.
 Usage: powershell -File Referee-Gap.ps1 -Report .\out\deepscan-<ts>.json

 DEFENSIVE: read-only JSON analysis.
#>
param(
  [Parameter(Mandatory=$true)][string]$Report,
  [string]$OutDir = ""
)
$ErrorActionPreference = "Stop"
# $PSScriptRoot is unreliable in a param default when the script has mandatory
# params invoked via -File; resolve OutDir here in the body where it is set.
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot "out" }
if (!(Test-Path $Report)) { Write-Error "Report not found: $Report"; exit 1 }
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$rep = Get-Content $Report -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host "`n=== REFEREE Gap Analysis ===" -ForegroundColor Cyan
Write-Host "Host: $($rep.host) | Flagged drivers: $($rep.findings.Count)`n"

$findings = $rep.findings

# Four quadrants of the capability x catalog matrix
$reachable   = $findings | Where-Object { $_.acl_status -eq "USER_REACHABLE" }
$highCap     = $findings | Where-Object { $_.cap_score -ge 10 }

# THE GAP: reachable + high-capability + NOT in loldrivers catalog
$gap = $findings | Where-Object {
  $_.acl_status -eq "USER_REACHABLE" -and $_.cap_score -ge 10 -and -not $_.lol_match
} | Sort-Object total_score -Descending

# Catalog hits that are NOT reachable = catalog over-flags vs real exposure
$catalogButRestricted = $findings | Where-Object {
  $_.lol_match -and $_.acl_status -ne "USER_REACHABLE"
}

# Both reachable AND catalogued = the overlap everyone already knows
$overlap = $findings | Where-Object { $_.lol_match -and $_.acl_status -eq "USER_REACHABLE" }

Write-Host "CAPABILITY x CATALOG MATRIX:" -ForegroundColor White
Write-Host ("  {0,-42} {1}" -f "Reachable + high-cap + NOT catalogued:", "$($gap.Count)  <- REFEREE's unique value") -ForegroundColor Red
Write-Host ("  {0,-42} {1}" -f "Reachable + catalogued (known overlap):", "$($overlap.Count)")
Write-Host ("  {0,-42} {1}" -f "Catalogued but NOT reachable:", "$($catalogButRestricted.Count)  <- catalog over-triage") -ForegroundColor DarkYellow
Write-Host ""

if ($gap.Count -gt 0) {
  Write-Host "GAP DRIVERS (reachable attack surface the catalog does not list):" -ForegroundColor Red
  $gap | Select-Object driver, category, risk_level, total_score, cap_score, reach_tier |
    Format-Table -AutoSize
}
if ($catalogButRestricted.Count -gt 0) {
  Write-Host "CATALOG-BUT-RESTRICTED (known-bad names that are not user-reachable here):" -ForegroundColor DarkYellow
  $catalogButRestricted | Select-Object driver, category, lol_hash, acl_status | Format-Table -AutoSize
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = [pscustomobject]@{
  tool = "referee-gap"; version = "1.0"; generated = (Get-Date -Format o)
  host = $rep.host
  matrix = @{
    reachable_total = $reachable.Count
    high_cap_total = $highCap.Count
    gap_reachable_uncatalogued = $gap.Count
    overlap_reachable_catalogued = $overlap.Count
    catalogued_but_restricted = $catalogButRestricted.Count
  }
  gap_drivers = $gap
  catalog_but_restricted = $catalogButRestricted
}
$jsonOut = "$OutDir\gap-$stamp.json"
$out | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8

$mdOut = "$OutDir\gap-$stamp.md"
$md = @()
$md += "# REFEREE Gap Analysis: What Catalogs Miss"
$md += ""
$md += "**Host:** ``$($rep.host)``  |  **Generated:** $(Get-Date -Format o)"
$md += ""
$md += "## Capability x Catalog matrix"
$md += "| Quadrant | Count | Meaning |"
$md += "|----------|-------|---------|"
$md += "| Reachable + high-cap + **uncatalogued** | **$($gap.Count)** | REFEREE's unique value |"
$md += "| Reachable + catalogued | $($overlap.Count) | Known overlap |"
$md += "| Catalogued but restricted | $($catalogButRestricted.Count) | Catalog over-triage |"
$md += ""
if ($gap.Count -gt 0) {
  $md += "## Gap drivers"
  $md += "_User-reachable, high-capability kernel drivers absent from the known-vulnerable catalog. These are attack surface a catalog-only triage would miss._"
  $md += ""
  $md += "| Driver | Category | Risk | Score | Cap | Tier |"
  $md += "|--------|----------|------|-------|-----|------|"
  foreach ($g in $gap) {
    $md += "| ``$($g.driver)`` | $($g.category) | **$($g.risk_level)** | $($g.total_score) | $($g.cap_score) | $($g.reach_tier) |"
  }
}
$md -join "`n" | Out-File $mdOut -Encoding utf8

Write-Host "`nJSON:   $jsonOut"
Write-Host "Report: $mdOut"
Write-Host "=== GAP ANALYSIS COMPLETE ===" -ForegroundColor Cyan
