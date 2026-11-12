<#
 REFEREE LOLDrivers Cross-Reference
 Cross-references loaded kernel drivers against the loldrivers.io database
 to find known-vulnerable or known-abused drivers on this host.

 Uses a pre-processed simplified DB (loldrivers-simple.json) to avoid
 PowerShell JSON parsing issues with the raw loldrivers.io API response.

 DEFENSIVE: read-only, no IOCTLs, no device interaction.
 Usage: powershell -ExecutionPolicy Bypass -File Referee-LOLCheck.ps1
#>
param(
  [string]$OutDir = "$PSScriptRoot\out",
  [string]$DbPath = "$PSScriptRoot\loldrivers-simple.json"
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Write-Host "`n=== REFEREE LOLDrivers Cross-Reference ===" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME  |  $(Get-Date -Format o)`n"

if (!(Test-Path $DbPath)) {
  Write-Error "LOLDrivers DB not found at $DbPath. Run the build script or download it."
  exit 1
}

$lolData = Get-Content $DbPath -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host "LOLDrivers DB loaded: $($lolData.Count) entries"

# Build filename -> entry index
$lolIndex = @{}
foreach ($entry in $lolData) {
  foreach ($fn in $entry.filenames) {
    $key = $fn.ToLower()
    if (-not $lolIndex.ContainsKey($key)) { $lolIndex[$key] = @() }
    $lolIndex[$key] += $entry
  }
}
Write-Host "Index built: $($lolIndex.Count) unique driver filenames`n"

# Enumerate loaded drivers
$drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, PathName

function Resolve-Path2([string]$raw) {
  if (-not $raw) { return $null }
  $p = $raw -replace '^\\\?\?\\',''
  $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
  if ($p -notmatch '^[A-Za-z]:\\') {
    if (Test-Path "$env:SystemRoot\System32\drivers\$p") { $p = "$env:SystemRoot\System32\drivers\$p" }
  }
  return $p
}

$hits = @()
foreach ($drv in $drivers) {
  $path = Resolve-Path2 $drv.PathName
  if (-not $path) { continue }
  $fname = [System.IO.Path]::GetFileName($path).ToLower()
  if ($lolIndex.ContainsKey($fname)) {
    # Hash check
    $fileHash = ""
    if (Test-Path $path) {
      try { $fileHash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() } catch {}
    }
    foreach ($match in $lolIndex[$fname]) {
      $hashMatch = "NAME_ONLY"
      if ($fileHash -and $match.hashes) {
        $lowerHashes = $match.hashes | ForEach-Object { $_.ToLower() }
        if ($fileHash -in $lowerHashes) { $hashMatch = "EXACT_HASH" }
      }
      $hits += [pscustomobject]@{
        driver     = $fname
        service    = $drv.Name
        state      = $drv.State
        path       = $path
        lol_id     = $match.id
        category   = $match.category
        usecase    = $match.usecase
        hash_match = $hashMatch
        file_hash  = $fileHash
      }
    }
  }
}

# Also scan drivers directory for on-disk (not loaded) matches
$driverDir = "$env:SystemRoot\System32\drivers"
$diskHits = @()
Get-ChildItem $driverDir -Filter "*.sys" -ErrorAction SilentlyContinue | ForEach-Object {
  $fname = $_.Name.ToLower()
  if ($lolIndex.ContainsKey($fname)) {
    $already = $hits | Where-Object { $_.driver -eq $fname }
    if (-not $already) {
      $fileHash = ""
      try { $fileHash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() } catch {}
      foreach ($match in $lolIndex[$fname]) {
        $hashMatch = "NAME_ONLY"
        if ($fileHash -and $match.hashes) {
          $lowerHashes = $match.hashes | ForEach-Object { $_.ToLower() }
          if ($fileHash -in $lowerHashes) { $hashMatch = "EXACT_HASH" }
        }
        $diskHits += [pscustomobject]@{
          driver     = $fname
          service    = "(not loaded)"
          state      = "OnDisk"
          path       = $_.FullName
          lol_id     = $match.id
          category   = $match.category
          usecase    = $match.usecase
          hash_match = $hashMatch
          file_hash  = $fileHash
        }
      }
    }
  }
}
$allHits = $hits + $diskHits

Write-Host "=== RESULTS ===" -ForegroundColor Cyan
Write-Host "LOLDrivers DB entries: $($lolData.Count)"
Write-Host "Loaded drivers checked: $(($drivers | Measure-Object).Count)"
Write-Host "Matches (loaded): $($hits.Count)"
Write-Host "Matches (on disk, not loaded): $($diskHits.Count)"
Write-Host "Total matches: $($allHits.Count)`n"

if ($allHits.Count -gt 0) {
  $allHits | Format-Table driver, state, lol_id, category, hash_match, usecase -AutoSize
} else {
  Write-Host "No LOLDrivers matches found on this host." -ForegroundColor Green
  Write-Host "(This is good - no known-vulnerable drivers detected.)`n"
}

# Save reports
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$report = [pscustomobject]@{
  tool = "referee-lolcheck"; version = "0.2"
  host = $env:COMPUTERNAME; generated = (Get-Date -Format o)
  loldrivers_count = $lolData.Count
  loaded_checked = ($drivers | Measure-Object).Count
  matches_loaded = $hits.Count
  matches_ondisk = $diskHits.Count
  findings = $allHits
}
$json = "$OutDir\lolcheck-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File $json -Encoding utf8

$md = "$OutDir\lolcheck-$stamp.md"
$mdLines = @()
$mdLines += "# REFEREE LOLDrivers Cross-Reference Report"
$mdLines += ""
$mdLines += "- **Host:** ``$env:COMPUTERNAME``"
$mdLines += "- **Generated:** $(Get-Date -Format o)"
$mdLines += "- **LOLDrivers DB entries:** $($lolData.Count)"
$mdLines += "- **Drivers checked:** $(($drivers | Measure-Object).Count)"
$mdLines += "- **Matches (loaded):** $($hits.Count)"
$mdLines += "- **Matches (on disk):** $($diskHits.Count)"
$mdLines += ""
if ($allHits.Count -gt 0) {
  $mdLines += "| Driver | State | LOL ID | Category | Hash Match | Use Case |"
  $mdLines += "|--------|-------|--------|----------|------------|----------|"
  foreach ($h in $allHits) {
    $mdLines += "| ``$($h.driver)`` | $($h.state) | $($h.lol_id) | $($h.category) | $($h.hash_match) | $($h.usecase) |"
  }
} else {
  $mdLines += "_No LOLDrivers matches found. No known-vulnerable drivers on this host._"
}
$mdLines -join "`n" | Out-File $md -Encoding utf8

Write-Host "JSON: $json"
Write-Host "Markdown: $md`n"
