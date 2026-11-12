<#
 REFEREE Auditor — enumerates kernel drivers, flags known anti-cheat drivers,
 checks Authenticode signer, and scores weaponizable (ring-0 R/W) risk.
 DEFENSIVE: read-only. Does not open device objects or send IOCTLs.
 Usage: powershell -ExecutionPolicy Bypass -File Referee-Audit.ps1
#>
param(
  [string]$SigPath = "$PSScriptRoot\signatures.json",
  [string]$OutDir  = "$PSScriptRoot\out"
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$sig = Get-Content $SigPath -Raw | ConvertFrom-Json

Write-Host "`n=== REFEREE Auditor ===" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME  |  $(Get-Date -Format o)`n"

# 1. Enumerate installed/loaded kernel drivers
$drivers = Get-CimInstance Win32_SystemDriver |
  Select-Object Name, State, Started, PathName, ServiceType

function Resolve-Path2([string]$raw){
  if (-not $raw) { return $null }
  $p = $raw -replace '^\\\?\?\\',''
  $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
  if ($p -notmatch '^[A-Za-z]:\\' -and $p -match 'System32') { $p = "$env:SystemRoot\$p" }
  return $p
}

$findings = @()
foreach ($d in $sig.drivers) {
  $hit = $null; $how = $null
  foreach ($svc in $d.services) {
    $m = $drivers | Where-Object { $_.Name -ieq $svc }
    if ($m) { $hit = $m; $how = "service:$svc"; break }
  }
  if (-not $hit) {
    foreach ($f in $d.files) {
      $m = $drivers | Where-Object { $_.PathName -and ($_.PathName -match [regex]::Escape($f)) }
      if ($m) { $hit = $m; $how = "file:$f"; break }
      # also scan drivers dir on disk even if not registered
      $disk = Get-ChildItem "$env:SystemRoot\System32\drivers\$f" -ErrorAction SilentlyContinue
      if ($disk) { $how = "ondisk:$f" }
    }
  }
  if (-not $hit -and -not $how) { continue }

  $path = if ($hit) { Resolve-Path2 $hit.PathName } else { "$env:SystemRoot\System32\drivers\" + ($d.files[0]) }
  $signer = "n/a"; $sigStatus = "n/a"
  if ($path -and (Test-Path $path)) {
    try {
      $s = Get-AuthenticodeSignature $path
      $sigStatus = $s.Status
      if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
    } catch { $sigStatus = "error" }
  }

  # Risk score
  $score = 0
  if ($hit -and $hit.State -eq "Running") { $score += 40 } elseif ($hit) { $score += 20 }
  if ($d.abuse_known) { $score += 40 }
  if ($d.device_names.Count -gt 0) { $score += 10 }
  if ($sigStatus -eq "Valid") { $score += 10 }  # valid-signed = AV-trusted = worse for abuse
  $level = if ($score -ge 70) {"CRITICAL"} elseif ($score -ge 45) {"HIGH"} elseif ($score -ge 25) {"MEDIUM"} else {"LOW"}

  $findings += [pscustomobject]@{
    product     = $d.product
    vendor      = $d.vendor
    detected_by = $how
    state       = if ($hit) { $hit.State } else { "NotRegistered" }
    running     = if ($hit) { [bool]$hit.Started } else { $false }
    path        = $path
    signer      = $signer
    sig_status  = "$sigStatus"
    abuse_known = $d.abuse_known
    device_ifaces = ($d.device_names -join "; ")
    risk_score  = $score
    risk_level  = $level
    notes       = $d.notes
  }
}

# 2. Report
$total = ($drivers | Measure-Object).Count
Write-Host "Total kernel drivers on host : $total"
Write-Host "Known anti-cheat drivers hit : $($findings.Count)`n"

if ($findings.Count -gt 0) {
  $findings | Sort-Object risk_score -Descending |
    Format-Table product, state, risk_level, risk_score, sig_status -AutoSize
} else {
  Write-Host "No known anti-cheat drivers detected on this host." -ForegroundColor Yellow
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$report = [pscustomobject]@{
  tool = "referee-auditor"; version = "0.1"
  host = $env:COMPUTERNAME; generated = (Get-Date -Format o)
  total_drivers = $total; ac_detected = $findings.Count
  findings = $findings
}
$json = "$OutDir\audit-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File $json -Encoding utf8

# Markdown report
$md = "$OutDir\audit-$stamp.md"
$lines = @()
$lines += "# REFEREE Audit Report"
$lines += ""
$lines += "- Host: ``$env:COMPUTERNAME``"
$lines += "- Generated: $(Get-Date -Format o)"
$lines += "- Total kernel drivers: **$total**"
$lines += "- Known anti-cheat drivers detected: **$($findings.Count)**"
$lines += ""
if ($findings.Count -gt 0) {
  $lines += "| Product | State | Risk | Score | Signature | Abuse-known |"
  $lines += "|---|---|---|---|---|---|"
  foreach ($f in ($findings | Sort-Object risk_score -Descending)) {
    $lines += "| $($f.product) | $($f.state) | **$($f.risk_level)** | $($f.risk_score) | $($f.sig_status) | $($f.abuse_known) |"
  }
} else {
  $lines += "_No known anti-cheat drivers detected on this host._"
  $lines += ""
  $lines += "The auditor still enumerated **$total** kernel drivers and cross-checked them against the signature DB; a clean result confirms the scanner runs end-to-end."
}
$lines -join "`n" | Out-File $md -Encoding utf8

Write-Host "`nJSON report : $json"
Write-Host "MD report   : $md`n"
