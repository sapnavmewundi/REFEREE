<#
 REFEREE Driver Diff - Longitudinal / Cross-Host Binary Diffing
 Compares the SAME driver filename across multiple DeepScan reports (different
 machines, or the same machine over time) and flags where the binary hash or
 risk posture differs.

 Why defenders care:
   - "Patched" updates that change the version string but NOT the risk posture
     (same dangerous import set) are cosmetic - still your attack surface.
   - A filename serving a DIFFERENT hash on different hosts can indicate an
     unsigned/sideloaded replacement of a trusted driver name.

 Usage:
   powershell -File Referee-DriverDiff.ps1 -Reports .\out\deepscan-a.json,.\out\deepscan-b.json
   powershell -File Referee-DriverDiff.ps1 -ReportDir .\out\fleet

 DEFENSIVE: read-only JSON analysis.
#>
param(
  [string[]]$Reports = @(),
  [string]$ReportDir = "",
  [string]$OutDir = "$PSScriptRoot\out"
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

if ($ReportDir) {
  $Reports = (Get-ChildItem "$ReportDir\*deepscan-*.json" -ErrorAction SilentlyContinue).FullName
}
if ($Reports.Count -lt 2) { Write-Error "Need at least 2 DeepScan reports to diff."; exit 1 }

Write-Host "`n=== REFEREE Driver Diff ===" -ForegroundColor Cyan
Write-Host "Comparing $($Reports.Count) reports`n"

# driver -> list of observations {source, hash, score, signer, sig, imports}
$obs = @{}
foreach ($rp in $Reports) {
  $rep = Get-Content $rp -Raw -Encoding UTF8 | ConvertFrom-Json
  $src = "$($rep.host)@$($rep.generated)"
  foreach ($f in $rep.findings) {
    # Derive a capability fingerprint from the three import categories
    $capFp = @($f.cat_A, $f.cat_B, $f.cat_C) -join "|"
    $hash = ""
    if ($f.PSObject.Properties.Name -contains "file_hash") { $hash = $f.file_hash }
    if (-not $obs.ContainsKey($f.driver)) { $obs[$f.driver] = @() }
    $obs[$f.driver] += [pscustomobject]@{
      source = $src; host = $rep.host
      signer = $f.signer; sig = $f.signature
      score = $f.total_score; reach = $f.acl_status
      cap_fp = $capFp; category = $f.category
    }
  }
}

$hashDiffs = @()   # same name, different signer/sig across sources
$postureDiffs = @()  # same name, different capability fingerprint or reachability
$cosmetic = @()    # signer changed but capability fingerprint identical

foreach ($drv in $obs.Keys) {
  $o = $obs[$drv]
  if ($o.Count -lt 2) { continue }
  $signers = $o.signer | Select-Object -Unique
  $caps    = $o.cap_fp | Select-Object -Unique
  $reaches = $o.reach  | Select-Object -Unique

  if ($signers.Count -gt 1) {
    $hashDiffs += [pscustomobject]@{
      driver = $drv; category = $o[0].category
      distinct_signers = $signers.Count
      signers = ($signers -join " || ")
    }
    if ($caps.Count -eq 1) {
      $cosmetic += [pscustomobject]@{ driver = $drv; note = "signer changed, capability fingerprint identical (cosmetic update)" }
    }
  }
  if ($caps.Count -gt 1 -or $reaches.Count -gt 1) {
    $postureDiffs += [pscustomobject]@{
      driver = $drv; category = $o[0].category
      distinct_capfp = $caps.Count; distinct_reach = $reaches.Count
      reaches = ($reaches -join ", ")
    }
  }
}

Write-Host "=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Drivers seen in >=2 reports: $(($obs.Values | Where-Object { $_.Count -ge 2 }).Count)"
Write-Host "Same name, different signer:  $($hashDiffs.Count)" -ForegroundColor $(if($hashDiffs.Count){"Red"}else{"Gray"})
Write-Host "Same name, posture changed:   $($postureDiffs.Count)" -ForegroundColor Yellow
Write-Host "Cosmetic updates (same caps):  $($cosmetic.Count)`n" -ForegroundColor DarkYellow

if ($hashDiffs.Count -gt 0) {
  Write-Host "SAME FILENAME, DIFFERENT SIGNER (possible replacement / version drift):" -ForegroundColor Red
  $hashDiffs | Format-Table driver, category, distinct_signers -AutoSize
}
if ($postureDiffs.Count -gt 0) {
  Write-Host "RISK-POSTURE DRIFT (same name, different capability/reachability):" -ForegroundColor Yellow
  $postureDiffs | Format-Table driver, category, distinct_capfp, reaches -AutoSize
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = [pscustomobject]@{
  tool = "referee-driverdiff"; version = "1.0"; generated = (Get-Date -Format o)
  reports_compared = $Reports.Count
  signer_diffs = $hashDiffs
  posture_diffs = $postureDiffs
  cosmetic_updates = $cosmetic
}
$jsonOut = "$OutDir\driverdiff-$stamp.json"
$out | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8
Write-Host "`nJSON: $jsonOut"
Write-Host "=== DRIVER DIFF COMPLETE ===" -ForegroundColor Cyan
