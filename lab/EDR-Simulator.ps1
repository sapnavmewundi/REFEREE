<#
 REFEREE Lab - EDR Telemetry Simulator
 Simulates the telemetry events that a real EDR would generate when
 anti-cheat driver abuse occurs, so Sigma rules can be tested against
 the output without needing a real EDR deployment.
 
 Generates Windows Event Log-style JSON events matching the patterns
 our Sigma rules detect.
 
 Usage: powershell -ExecutionPolicy Bypass -File EDR-Simulator.ps1
#>
param(
  [string]$OutDir = "$PSScriptRoot\sim-output",
  [switch]$WriteEventLog  # Actually write to Windows Event Log (requires admin)
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Write-Host "`n=== REFEREE EDR Telemetry Simulator ===" -ForegroundColor Cyan
Write-Host "Generating synthetic telemetry for detection rule testing`n"

$events = @()

# --- Scenario 1: Anti-cheat driver loaded from suspicious path ---
# Matches Sigma rule ref-001
Write-Host "[SIM] Scenario 1: AC driver service created outside game install path" -ForegroundColor Yellow
$events += [pscustomobject]@{
  scenario    = "AC driver suspicious registration"
  sigma_rule  = "ref-001"
  EventID     = 7045
  Provider    = "Service Control Manager"
  TimeCreated = (Get-Date).AddMinutes(-30).ToString("o")
  ServiceName = "vgk"
  ImagePath   = "C:\Users\attacker\tools\vgk.sys"
  ServiceType = "kernel driver"
  StartType   = "boot"
  AccountName = "LocalSystem"
  expected_detection = "HIGH - AC driver registered outside Program Files/game paths"
}

$events += [pscustomobject]@{
  scenario    = "AC driver suspicious registration (mhyprot)"
  sigma_rule  = "ref-001"
  EventID     = 7045
  Provider    = "Service Control Manager"
  TimeCreated = (Get-Date).AddMinutes(-25).ToString("o")
  ServiceName = "mhyprot2"
  ImagePath   = "C:\Windows\Temp\mhyprot2.sys"
  ServiceType = "kernel driver"
  StartType   = "demand"
  AccountName = "LocalSystem"
  expected_detection = "HIGH - Known-abuse driver loaded from temp directory"
}

# --- Scenario 2: Non-game process accessing AC driver device ---
# Matches Sigma rule ref-002 (Security Auditing 4663, Object Access)
Write-Host "[SIM] Scenario 2: Non-game process opens AC driver device handle" -ForegroundColor Yellow
$events += [pscustomobject]@{
  scenario    = "Non-game device handle access"
  sigma_rule  = "ref-002"
  EventID     = 4663
  Provider    = "Microsoft-Windows-Security-Auditing"
  TimeCreated = (Get-Date).AddMinutes(-20).ToString("o")
  ProcessName = "C:\Users\attacker\tools\exploit.exe"
  ObjectName  = "\Device\vgk"
  AccessMask  = "0x120089"
  ProcessId   = 4444
  expected_detection = "CRITICAL - Non-game process accessing Vanguard device"
}

$events += [pscustomobject]@{
  scenario    = "Non-game device handle access (mhyprot)"
  sigma_rule  = "ref-002"
  EventID     = 4663
  Provider    = "Microsoft-Windows-Security-Auditing"
  TimeCreated = (Get-Date).AddMinutes(-18).ToString("o")
  ProcessName = "C:\Windows\System32\cmd.exe"
  ObjectName  = "\Device\mhyprot2"
  AccessMask  = "0x120089"
  ProcessId   = 5555
  expected_detection = "CRITICAL - cmd.exe accessing mhyprot device"
}

# --- Scenario 3: Suspicious AC driver load from non-game path ---
# Matches Sigma rule ref-003 (Sysmon EventID 6 driver load)
Write-Host "[SIM] Scenario 3: Suspicious AC driver load (non-game path, telemetry blind precursor)" -ForegroundColor Yellow
$events += [pscustomobject]@{
  scenario    = "AC driver loaded from suspicious path"
  sigma_rule  = "ref-003"
  EventID     = 6
  Provider    = "Microsoft-Windows-Sysmon"
  TimeCreated = (Get-Date).AddMinutes(-15).ToString("o")
  ImageLoaded = "C:\Users\attacker\tools\vgk.sys"
  Hashes      = "SHA256=AABBCCDD00112233"
  Signed      = "false"
  SignatureStatus = "Unavailable"
  expected_detection = "HIGH - AC driver loaded from non-game path, unsigned"
}

$events += [pscustomobject]@{
  scenario    = "mhyprot loaded from temp directory"
  sigma_rule  = "ref-003"
  EventID     = 6
  Provider    = "Microsoft-Windows-Sysmon"
  TimeCreated = (Get-Date).AddMinutes(-14).ToString("o")
  ImageLoaded = "C:\Windows\Temp\mhyprot2.sys"
  Hashes      = "SHA256=DEADBEEF44556677"
  Signed      = "true"
  SignatureStatus = "Valid"
  expected_detection = "HIGH - Known-abuse driver loaded from temp directory"
}

# --- Scenario 4: Legitimate baseline (should NOT trigger) ---
Write-Host "[SIM] Scenario 4: Legitimate AC driver load (baseline, should not alert)" -ForegroundColor Green
$events += [pscustomobject]@{
  scenario    = "Legitimate Vanguard installation"
  sigma_rule  = "ref-001 (should NOT match)"
  EventID     = 7045
  Provider    = "Service Control Manager"
  TimeCreated = (Get-Date).AddMinutes(-60).ToString("o")
  ServiceName = "vgk"
  ImagePath   = "C:\Program Files\Riot Vanguard\vgk.sys"
  ServiceType = "kernel driver"
  StartType   = "boot"
  AccountName = "LocalSystem"
  expected_detection = "NONE - Legitimate path, filter should exclude"
}

$events += [pscustomobject]@{
  scenario    = "Legitimate VALORANT accessing Vanguard"
  sigma_rule  = "ref-002 (should NOT match)"
  EventID     = 4663
  Provider    = "Microsoft-Windows-Security-Auditing"
  TimeCreated = (Get-Date).AddMinutes(-55).ToString("o")
  ProcessName = "C:\Riot Games\VALORANT\VALORANT.exe"
  ObjectName  = "\Device\vgk"
  AccessMask  = "0x120089"
  ProcessId   = 6666
  expected_detection = "NONE - Legitimate game process"
}

# Output
Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Generated $($events.Count) synthetic events (6 should trigger, 2 baselines should not)`n"

$events | Format-Table scenario, sigma_rule, EventID, expected_detection -AutoSize -Wrap

# Save
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$json = "$OutDir\edr-sim-$stamp.json"
$events | ConvertTo-Json -Depth 4 | Out-File $json -Encoding utf8
Write-Host "Events JSON: $json"

# Save as EVTX-compatible XML for Sigma testing tools
$xml = "$OutDir\edr-sim-$stamp.xml"
$xmlLines = @()
$xmlLines += '<?xml version="1.0" encoding="utf-8"?>'
$xmlLines += '<Events>'
foreach ($e in $events) {
  $xmlLines += "  <Event>"
  $xmlLines += "    <System>"
  $xmlLines += "      <Provider Name=`"$($e.Provider)`" />"
  $xmlLines += "      <EventID>$($e.EventID)</EventID>"
  $xmlLines += "      <TimeCreated SystemTime=`"$($e.TimeCreated)`" />"
  $xmlLines += "      <Computer>$env:COMPUTERNAME</Computer>"
  $xmlLines += "    </System>"
  $xmlLines += "    <EventData>"
  if ($e.ServiceName) { $xmlLines += "      <Data Name=`"ServiceName`">$($e.ServiceName)</Data>" }
  if ($e.ImagePath) { $xmlLines += "      <Data Name=`"ImagePath`">$($e.ImagePath)</Data>" }
  if ($e.ProcessName) { $xmlLines += "      <Data Name=`"ProcessName`">$($e.ProcessName)</Data>" }
  if ($e.ObjectName) { $xmlLines += "      <Data Name=`"ObjectName`">$($e.ObjectName)</Data>" }
  if ($e.ImageLoaded) { $xmlLines += "      <Data Name=`"ImageLoaded`">$($e.ImageLoaded)</Data>" }
  if ($e.Signed) { $xmlLines += "      <Data Name=`"Signed`">$($e.Signed)</Data>" }
  if ($e.SignatureStatus) { $xmlLines += "      <Data Name=`"SignatureStatus`">$($e.SignatureStatus)</Data>" }
  if ($e.Hashes) { $xmlLines += "      <Data Name=`"Hashes`">$($e.Hashes)</Data>" }
  if ($e.ProcessId) { $xmlLines += "      <Data Name=`"ProcessId`">$($e.ProcessId)</Data>" }
  $xmlLines += "    </EventData>"
  $xmlLines += "  </Event>"
}
$xmlLines += '</Events>'
$xmlLines -join "`n" | Out-File $xml -Encoding utf8
Write-Host "Events XML: $xml"

# Validation summary
Write-Host "`n--- Detection Rule Validation Guide ---" -ForegroundColor Cyan
Write-Host "To test Sigma rules against this output:"
Write-Host "  1. Install sigmac or sigma-cli"
Write-Host "  2. Convert: sigma convert -t <backend> ../detections/ac-driver-abuse.yml"
Write-Host "  3. Run against: $xml"
Write-Host "  4. Scenarios 1-3 should trigger; Scenario 4 should not.`n"
