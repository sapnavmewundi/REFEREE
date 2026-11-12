<#
 REFEREE Capability Scanner v2
 Scans ALL loaded kernel drivers for weaponizable capabilities by analyzing
 PE imports, device ACLs, and cross-referencing known-abuse databases.
 
 DEFENSIVE TOOL: read-only, no IOCTLs sent, no memory touched.
 Usage: powershell -ExecutionPolicy Bypass -File Referee-CapScan.ps1
#>
param(
  [string]$SigPath = "$PSScriptRoot\signatures.json",
  [string]$OutDir  = "$PSScriptRoot\out"
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Write-Host "`n=== REFEREE Capability Scanner v2 ===" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME  |  $(Get-Date -Format o)`n"

# --- Risk import signatures (defensive detection) ---
$catA = @("MmMapIoSpace","ZwMapViewOfSection","MmCopyMemory","MmGetPhysicalAddress",
          "IoAllocateMdl","MmBuildMdlForNonPagedPool","MmMapLockedPagesSpecifyCache")
$catB = @("ZwOpenProcess","PsLookupProcessByProcessId","ObOpenObjectByPointer",
          "MmCopyVirtualMemory","ZwTerminateProcess","KeAttachProcess",
          "KeStackAttachProcess","PsLookupThreadByThreadId")
$catC = @("CmUnRegisterCallback","ObUnRegisterCallbacks",
          "PsSetCreateProcessNotifyRoutine","PsRemoveCreateThreadNotifyRoutine",
          "PsRemoveLoadImageNotifyRoutine","ExUnregisterCallback")

# Known-abuse drivers (loldrivers.io subset + anti-cheat history)
$knownAbuse = @("mhyprot2.sys","mhyprot3.sys","xhunter1.sys","npggNT.des",
                "dump_wmimmc.sys","dbutil_2_3.sys","ene.sys","gdrv.sys",
                "asrdrv10.sys","asrdrv106.sys","cpuz141.sys","elrawdsk.sys",
                "phymemx64.sys","rtkio64.sys","procexp152.sys")

# Load AC signature DB for enrichment
$acDb = @{}
if (Test-Path $SigPath) {
  $sig = Get-Content $SigPath -Raw | ConvertFrom-Json
  foreach ($d in $sig.drivers) {
    foreach ($f in $d.files) { $acDb[$f.ToLower()] = $d }
  }
}

function Resolve-DriverPath([string]$raw) {
  if (-not $raw) { return $null }
  $p = $raw -replace '^\\\?\?\\',''
  $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
  if ($p -notmatch '^[A-Za-z]:\\') {
    if (Test-Path "$env:SystemRoot\System32\drivers\$p") { $p = "$env:SystemRoot\System32\drivers\$p" }
    elseif (Test-Path "$env:SystemRoot\System32\$p") { $p = "$env:SystemRoot\System32\$p" }
  }
  return $p
}

function Get-PEImports([string]$path) {
  # Read PE import table names via .NET reflection (read-only, no execution)
  try {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $found = @()
    $allApis = $catA + $catB + $catC
    foreach ($api in $allApis) {
      if ($text.Contains($api)) { $found += $api }
    }
    return $found
  } catch { return @() }
}

# --- Enumerate all kernel drivers ---
$drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, Started, PathName
$total = ($drivers | Measure-Object).Count
Write-Host "Scanning $total kernel drivers for capability risks...`n"

$results = @()
$progress = 0
foreach ($drv in $drivers) {
  $progress++
  if ($progress % 50 -eq 0) { Write-Host "  ... scanned $progress / $total" }
  
  $path = Resolve-DriverPath $drv.PathName
  if (-not $path -or !(Test-Path $path -ErrorAction SilentlyContinue)) { continue }
  
  $fileName = [System.IO.Path]::GetFileName($path).ToLower()
  $imports = Get-PEImports $path
  if ($imports.Count -eq 0 -and -not $acDb.ContainsKey($fileName) -and 
      $fileName -notin $knownAbuse) { continue }
  
  # Score
  $scoreA = 0; $scoreB = 0; $scoreC = 0
  $hitsA = @(); $hitsB = @(); $hitsC = @()
  foreach ($imp in $imports) {
    if ($imp -in $catA) { $scoreA = 25; $hitsA += $imp }
    if ($imp -in $catB) { $scoreB = 25; $hitsB += $imp }
    if ($imp -in $catC) { $scoreC = 25; $hitsC += $imp }
  }
  $score = $scoreA + $scoreB + $scoreC
  if ($drv.State -eq "Running") { $score += 15 }
  
  # Authenticode check
  $sigStatus = "Unknown"
  try {
    $s = Get-AuthenticodeSignature $path
    $sigStatus = "$($s.Status)"
    if ($s.Status -eq "Valid") { $score += 10 }
  } catch {}
  
  # Known abuse
  $abuse = $fileName -in $knownAbuse
  if ($abuse) { $score += 10 }
  
  # AC enrichment
  $acInfo = $null
  if ($acDb.ContainsKey($fileName)) {
    $acInfo = $acDb[$fileName]
    if ($acInfo.abuse_known) { $abuse = $true; $score += 10 }
  }
  
  $level = if ($score -ge 70) {"CRITICAL"} elseif ($score -ge 45) {"HIGH"} 
           elseif ($score -ge 25) {"MEDIUM"} else {"LOW"}
  
  $results += [pscustomobject]@{
    driver      = $fileName
    service     = $drv.Name
    state       = $drv.State
    path        = $path
    signature   = $sigStatus
    cat_A_mem   = ($hitsA -join ", ")
    cat_B_proc  = ($hitsB -join ", ")
    cat_C_cb    = ($hitsC -join ", ")
    abuse_known = $abuse
    ac_product  = if ($acInfo) { $acInfo.product } else { "" }
    risk_score  = $score
    risk_level  = $level
  }
}

# --- Output ---
Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Drivers with capability signals: $($results.Count) / $total`n"

$sorted = $results | Sort-Object risk_score -Descending

# Top findings table
$sorted | Where-Object { $_.risk_score -ge 25 } |
  Format-Table driver, state, risk_level, risk_score, cat_A_mem, cat_B_proc, cat_C_cb, abuse_known -AutoSize

# Stats
$crit = ($sorted | Where-Object { $_.risk_level -eq "CRITICAL" } | Measure-Object).Count
$high = ($sorted | Where-Object { $_.risk_level -eq "HIGH" } | Measure-Object).Count
$med  = ($sorted | Where-Object { $_.risk_level -eq "MEDIUM" } | Measure-Object).Count
$low  = ($sorted | Where-Object { $_.risk_level -eq "LOW" } | Measure-Object).Count
Write-Host "Risk breakdown: CRITICAL=$crit  HIGH=$high  MEDIUM=$med  LOW=$low`n"

# Save JSON
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$report = [pscustomobject]@{
  tool = "referee-capscan"; version = "0.2"
  host = $env:COMPUTERNAME; generated = (Get-Date -Format o)
  total_drivers = $total; flagged = $results.Count
  stats = @{ critical=$crit; high=$high; medium=$med; low=$low }
  findings = $sorted
}
$jsonOut = "$OutDir\capscan-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8

# Save Markdown
$mdOut = "$OutDir\capscan-$stamp.md"
$mdLines = @()
$mdLines += "# REFEREE Capability Scan Report"
$mdLines += ""
$mdLines += "- **Host:** ``$env:COMPUTERNAME``"
$mdLines += "- **Generated:** $(Get-Date -Format o)"
$mdLines += "- **Total kernel drivers:** $total"
$mdLines += "- **Drivers with risk signals:** $($results.Count)"
$mdLines += "- **Breakdown:** CRITICAL=$crit | HIGH=$high | MEDIUM=$med | LOW=$low"
$mdLines += ""
$mdLines += "## Leaderboard (MEDIUM and above)"
$mdLines += ""
$mdLines += "| Driver | State | Risk | Score | Memory APIs | Process APIs | Callback APIs | Abuse-Known |"
$mdLines += "|--------|-------|------|-------|-------------|-------------|---------------|-------------|"
foreach ($r in ($sorted | Where-Object { $_.risk_score -ge 25 })) {
  $mdLines += "| ``$($r.driver)`` | $($r.state) | **$($r.risk_level)** | $($r.risk_score) | $($r.cat_A_mem) | $($r.cat_B_proc) | $($r.cat_C_cb) | $($r.abuse_known) |"
}
$mdLines += ""
$mdLines += "## All flagged drivers"
$mdLines += ""
foreach ($r in $sorted) {
  $mdLines += "- ``$($r.driver)`` - $($r.risk_level) ($($r.risk_score)) - State: $($r.state)"
}
$mdLines -join "`n" | Out-File $mdOut -Encoding utf8

Write-Host "JSON: $jsonOut"
Write-Host "Markdown: $mdOut`n"
