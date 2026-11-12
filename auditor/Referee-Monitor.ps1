<#
 REFEREE Monitor - Real-Time Driver Load Watcher
 Turns REFEREE from a point-in-time scan into a continuous control. Watches
 for new kernel driver loads and scores each one on the capability axis as it
 happens, alerting on high-risk loads.

 Two event sources (auto-selected by availability):
   1. Sysmon Event ID 6 (Driver Loaded)  - richest: includes hash + signature
   2. Kernel-PnP / System log service-install events - fallback if no Sysmon

 Each new load is scored with the same capability taxonomy as DeepScan and
 written to an alert log. Intended to run alongside the Sigma rules.

 Usage:
   powershell -File Referee-Monitor.ps1               # watch until Ctrl+C
   powershell -File Referee-Monitor.ps1 -Once         # replay last 24h and exit
   powershell -File Referee-Monitor.ps1 -Since (Get-Date).AddDays(-7)

 DEFENSIVE: read-only. Consumes the event log; loads no drivers itself.
#>
param(
  [switch]$Once,
  [datetime]$Since = (Get-Date).AddHours(-24),
  [string]$OutDir = "$PSScriptRoot\out",
  [int]$PollSeconds = 15
)
$ErrorActionPreference = "SilentlyContinue"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$catA = @("MmMapIoSpace","ZwMapViewOfSection","MmCopyMemory","MmGetPhysicalAddress",
          "IoAllocateMdl","MmBuildMdlForNonPagedPool","MmMapLockedPagesSpecifyCache")
$catB = @("ZwOpenProcess","PsLookupProcessByProcessId","ObOpenObjectByPointer",
          "MmCopyVirtualMemory","ZwTerminateProcess","KeAttachProcess",
          "KeStackAttachProcess","PsLookupThreadByThreadId")
$catC = @("CmUnRegisterCallback","ObUnRegisterCallbacks",
          "PsSetCreateProcessNotifyRoutine","PsRemoveCreateThreadNotifyRoutine",
          "PsRemoveLoadImageNotifyRoutine","ExUnregisterCallback")

function Score-DriverFile([string]$path) {
  $r = [pscustomobject]@{ capA=@(); capB=@(); capC=@(); score=0; signer=""; sig="Unknown" }
  if (-not $path -or !(Test-Path $path)) { return $r }
  try {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    foreach ($a in $catA) { if ($text.Contains($a)) { $r.capA += $a } }
    foreach ($a in $catB) { if ($text.Contains($a)) { $r.capB += $a } }
    foreach ($a in $catC) { if ($text.Contains($a)) { $r.capC += $a } }
  } catch {}
  try {
    $s = Get-AuthenticodeSignature $path
    $r.sig = "$($s.Status)"
    if ($s.SignerCertificate) { $r.signer = $s.SignerCertificate.Subject }
  } catch {}
  $sc = 0
  if ($r.capA.Count) { $sc += 10 }; if ($r.capA.Count -ge 3) { $sc += 5 }
  if ($r.capB.Count) { $sc += 10 }; if ($r.capC.Count) { $sc += 5 }
  if ($r.sig -ne "Valid") { $sc += 10 }
  $r.score = $sc
  return $r
}

function Get-DriverLoadEvents([datetime]$after) {
  $events = @()
  # Source 1: Sysmon driver-load (Event ID 6)
  $sysmon = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=6; StartTime=$after } -ErrorAction SilentlyContinue
  foreach ($e in $sysmon) {
    $x = [xml]$e.ToXml()
    $data = @{}; foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    $events += [pscustomobject]@{
      time = $e.TimeCreated; source = "Sysmon:6"
      image = $data['ImageLoaded']; hashes = $data['Hashes']
      signed = $data['Signed']; signer = $data['Signature']
    }
  }
  # Source 2 (fallback): service install of a kernel driver (System log, 7045)
  if ($events.Count -eq 0) {
    $svc = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045; StartTime=$after } -ErrorAction SilentlyContinue
    foreach ($e in $svc) {
      $x = [xml]$e.ToXml()
      $data = @{}; foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
      if ($data['ServiceType'] -match 'kernel' -or $data['ImagePath'] -match '\.sys') {
        $events += [pscustomobject]@{
          time = $e.TimeCreated; source = "System:7045"
          image = $data['ImagePath']; hashes = ""
          signed = ""; signer = $data['ServiceName']
        }
      }
    }
  }
  return $events | Sort-Object time
}

function Resolve-ImagePath([string]$raw) {
  if (-not $raw) { return $null }
  $p = $raw -replace '^\\\?\?\\',''
  $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
  $p = $p -replace '^System32', "$env:SystemRoot\System32"
  return $p
}

$alertLog = "$OutDir\monitor-alerts.jsonl"
Write-Host "`n=== REFEREE Real-Time Driver Monitor ===" -ForegroundColor Cyan
Write-Host "Alert log: $alertLog"
Write-Host "Mode: $(if($Once){'replay once'}else{'continuous (Ctrl+C to stop)'})`n"

$seen = @{}
function Process-Events([datetime]$after) {
  $evts = Get-DriverLoadEvents $after
  foreach ($e in $evts) {
    $key = "$($e.time.Ticks)|$($e.image)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $path = Resolve-ImagePath $e.image
    $sc = Score-DriverFile $path
    $level = if ($sc.score -ge 25) {"HIGH"} elseif ($sc.score -ge 15) {"MEDIUM"} else {"LOW"}
    $color = switch ($level) { "HIGH"{"Red"} "MEDIUM"{"Yellow"} default{"Gray"} }
    $name = [System.IO.Path]::GetFileName($path)
    Write-Host ("[{0}] {1,-6} {2,-28} score={3} sig={4}" -f $e.time.ToString("HH:mm:ss"), $level, $name, $sc.score, $sc.sig) -ForegroundColor $color
    $alert = [pscustomobject]@{
      time = $e.time.ToString("o"); source = $e.source; driver = $name; path = $path
      level = $level; score = $sc.score; signature = $sc.sig; signer = $sc.signer
      capA = ($sc.capA -join ","); capB = ($sc.capB -join ","); capC = ($sc.capC -join ",")
      event_hashes = $e.hashes
    }
    $alert | ConvertTo-Json -Compress | Out-File $alertLog -Append -Encoding utf8
  }
}

Process-Events $Since
if ($Once) { Write-Host "`nReplay complete."; exit 0 }

$lastPoll = Get-Date
while ($true) {
  Start-Sleep -Seconds $PollSeconds
  Process-Events $lastPoll
  $lastPoll = Get-Date
}
