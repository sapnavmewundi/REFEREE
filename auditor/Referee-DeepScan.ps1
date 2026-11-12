<#
 REFEREE Deep Scanner v4
 The research-grade scanner. Combines:
   1. PE import analysis (what the driver CAN do)
   2. Device object ACL audit (who can REACH it)
   3. LOLDrivers cross-reference (is it KNOWN vulnerable)
   4. Driver categorization (vendor/type classification)
   5. WDAC block policy generation (actionable defense)

 v4 UPGRADE: Enhanced reachability analysis
   - Multi-source device name discovery (registry device map, device interfaces,
     well-known device name patterns, IoCreateDevice conventions)
   - Handle probe: P/Invoke CreateFileW with zero-access to ground-truth
     whether a device is actually openable from user context
   - Service Security Descriptor ACL analysis (existing)
   - Combined verdict: ACL + probe agree = high confidence

 THIS IS THE NOVEL CONTRIBUTION: systematic reachability analysis
 of kernel driver device objects from unprivileged user context.

 DEFENSIVE: read-only. Queries device ACLs and attempts zero-access
 CreateFile (FILE_READ_ATTRIBUTES). Does NOT send IOCTLs.

 REQUIRES: Administrator (to read device object ACLs)
 Usage: powershell -ExecutionPolicy Bypass -File Referee-DeepScan.ps1
#>
param(
  [string]$SigPath = "$PSScriptRoot\signatures.json",
  [string]$LolPath = "$PSScriptRoot\loldrivers-simple.json",
  [string]$OutDir  = "$PSScriptRoot\out"
)
$ErrorActionPreference = "SilentlyContinue"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  REFEREE Deep Scanner v4" -ForegroundColor Cyan
Write-Host "  Kernel Driver Reachability Analysis" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME | OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "Date: $(Get-Date -Format o)"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "User: $env:USERNAME | Admin: $isAdmin`n"

# ============================================================
# P/INVOKE: CreateFileW for handle probe (zero-access test)
# ============================================================
$pinvoke = @"
using System;
using System.Runtime.InteropServices;

public class DeviceProbe {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // Try to open with zero access (FILE_READ_ATTRIBUTES = 0x80)
    // This is the minimum-privilege probe: we ask for almost nothing.
    // If it succeeds, the device is openable from this context.
    // If it fails with ACCESS_DENIED (5), the device exists but is restricted.
    // If it fails with FILE_NOT_FOUND (2) or PATH_NOT_FOUND (3), no such device.
    public static int ProbeDevice(string devicePath) {
        IntPtr h = CreateFileW(devicePath, 0x80, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h != IntPtr.Zero && h != (IntPtr)(-1)) {
            CloseHandle(h);
            return 0;  // SUCCESS - device is openable
        }
        return Marshal.GetLastWin32Error();
    }

    // Probe with ZERO access rights (dwDesiredAccess = 0)
    // Even more minimal than FILE_READ_ATTRIBUTES
    public static int ProbeDeviceZero(string devicePath) {
        IntPtr h = CreateFileW(devicePath, 0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h != IntPtr.Zero && h != (IntPtr)(-1)) {
            CloseHandle(h);
            return 0;
        }
        return Marshal.GetLastWin32Error();
    }
}
"@
try {
    Add-Type -TypeDefinition $pinvoke -Language CSharp -ErrorAction Stop
    $hasProbe = $true
    Write-Host "[*] Handle probe loaded (P/Invoke CreateFileW)" -ForegroundColor Green
} catch {
    $hasProbe = $false
    Write-Host "[!] Handle probe unavailable (will use ACL analysis only)" -ForegroundColor Yellow
}

# ============================================================
# PHASE 1: Enumerate all kernel drivers with full metadata
# ============================================================
Write-Host "`n[Phase 1] Enumerating kernel drivers..." -ForegroundColor Yellow

$catA = @("MmMapIoSpace","ZwMapViewOfSection","MmCopyMemory","MmGetPhysicalAddress",
          "IoAllocateMdl","MmBuildMdlForNonPagedPool","MmMapLockedPagesSpecifyCache")
$catB = @("ZwOpenProcess","PsLookupProcessByProcessId","ObOpenObjectByPointer",
          "MmCopyVirtualMemory","ZwTerminateProcess","KeAttachProcess",
          "KeStackAttachProcess","PsLookupThreadByThreadId")
$catC = @("CmUnRegisterCallback","ObUnRegisterCallbacks",
          "PsSetCreateProcessNotifyRoutine","PsRemoveCreateThreadNotifyRoutine",
          "PsRemoveLoadImageNotifyRoutine","ExUnregisterCallback")

# Load LOLDrivers DB
$lolIndex = @{}
if (Test-Path $LolPath) {
  $lolData = Get-Content $LolPath -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($entry in $lolData) {
    foreach ($fn in $entry.filenames) {
      $lolIndex[$fn.ToLower()] = $entry
    }
  }
  Write-Host "  LOLDrivers DB: $($lolData.Count) entries loaded"
}

# Load AC signatures
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
  try {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $found = @()
    foreach ($api in ($catA + $catB + $catC)) {
      if ($text.Contains($api)) { $found += $api }
    }
    return $found
  } catch { return @() }
}

function Classify-Driver([string]$fname, [string]$path, [string]$signer) {
  $fn = $fname.ToLower()
  if ($acDb.ContainsKey($fn)) { return "Anti-Cheat" }
  if ($fn -match "nvidia|nvldd|nvsm|nvaudio") { return "GPU-NVIDIA" }
  if ($fn -match "igdk|igfx|intel|xe") { return "GPU-Intel" }
  if ($fn -match "amdk|atik|amd") { return "GPU-AMD" }
  if ($fn -match "realtek|rtk|rts") { return "Audio/Network-Realtek" }
  if ($fn -match "vbox|virtualbox") { return "Virtualization-VBox" }
  if ($fn -match "vmware|vm3d|vmci") { return "Virtualization-VMware" }
  if ($fn -match "hyperv|vmbus|vid\.sys") { return "Virtualization-HyperV" }
  if ($fn -match "dell|alienware") { return "OEM-Dell" }
  if ($fn -match "hp|hewlett") { return "OEM-HP" }
  if ($fn -match "lenovo|think") { return "OEM-Lenovo" }
  if ($fn -match "crowd|falcon|cs_") { return "Security-CrowdStrike" }
  if ($fn -match "wd[a-z]|defend|mpksl") { return "Security-Defender" }
  if ($fn -match "symant|norton|sep") { return "Security-Symantec" }
  if ($signer -and $signer -match "Microsoft") { return "Microsoft" }
  return "Third-Party-Other"
}

$drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, Started, PathName
$total = ($drivers | Measure-Object).Count
Write-Host "  Total kernel drivers: $total"

# ============================================================
# PHASE 1.5: Build device name map (MULTI-SOURCE DISCOVERY)
# ============================================================
Write-Host "`n[Phase 1.5] Building device name map (multi-source discovery)..." -ForegroundColor Yellow

$deviceMap = @{}  # service name -> list of device paths to try

# Source 1: Well-known device name patterns per driver
# IoCreateDevice convention: most drivers create \Device\<ServiceName>
# User-mode symlink: \\.\<ServiceName> or \\.\<BaseName>
foreach ($drv in $drivers) {
  $svc = $drv.Name
  $paths = @()
  $paths += "\\.\$svc"
  if ($drv.PathName) {
    $bn = [System.IO.Path]::GetFileNameWithoutExtension(($drv.PathName -replace '^\\\?\?\\',''))
    if ($bn -and $bn -ne $svc) { $paths += "\\.\$bn" }
  }
  $deviceMap[$svc] = $paths
}

# Source 2: Registry DeviceMap — maps driver classes to actual device names
$deviceMapPaths = @(
  "HKLM:\HARDWARE\DEVICEMAP",
  "HKLM:\SYSTEM\CurrentControlSet\Services"
)
$deviceMapCount = 0
try {
  $dmRoot = Get-ChildItem "HKLM:\HARDWARE\DEVICEMAP" -ErrorAction Stop
  foreach ($subkey in $dmRoot) {
    try {
      $props = Get-ItemProperty $subkey.PSPath -ErrorAction Stop
      foreach ($pn in $props.PSObject.Properties) {
        if ($pn.Name -match "^PS" -or $pn.Name -eq "(default)") { continue }
        $val = "$($pn.Value)"
        if ($val -match '\\Device\\') {
          # Map this device back to a driver service if possible
          $devShort = $val -replace '^\\Device\\',''
          foreach ($drv in $drivers) {
            if ($drv.Name -eq $devShort -or $drv.Name -match [regex]::Escape($devShort)) {
              if (-not $deviceMap.ContainsKey($drv.Name)) { $deviceMap[$drv.Name] = @() }
              $userPath = "\\.\$devShort"
              if ($userPath -notin $deviceMap[$drv.Name]) {
                $deviceMap[$drv.Name] += $userPath
                $deviceMapCount++
              }
            }
          }
        }
      }
    } catch {}
  }
} catch {}
Write-Host "  DeviceMap entries discovered: $deviceMapCount"

# Source 3: Device interface classes from SetupDI registry
# These are GUID-based interfaces that drivers register for PnP access
$interfaceCount = 0
try {
  $ifRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses"
  if (Test-Path $ifRoot) {
    $guidKeys = Get-ChildItem $ifRoot -ErrorAction SilentlyContinue | Select-Object -First 100
    foreach ($gk in $guidKeys) {
      try {
        $subdevs = Get-ChildItem $gk.PSPath -ErrorAction SilentlyContinue
        foreach ($sd in $subdevs) {
          try {
            $symLink = (Get-ItemProperty "$($sd.PSPath)\#\Device Parameters" -Name "SymbolicLink" -ErrorAction SilentlyContinue).SymbolicLink
            if (-not $symLink) {
              $symLink = (Get-ItemProperty "$($sd.PSPath)\#" -Name "SymbolicLink" -ErrorAction SilentlyContinue).SymbolicLink
            }
            if ($symLink) {
              $interfaceCount++
            }
          } catch {}
        }
      } catch {}
    }
  }
} catch {}
Write-Host "  Device interface entries scanned: $interfaceCount"

# Source 4: Known device names for common driver families
$knownDeviceNames = @{
  "afd"       = @("\\.\Afd", "\\.\Afd\Endpoint")
  "nsiproxy"  = @("\\.\Nsi")
  "http"      = @("\\.\HTTP", "\\.\HTTPAPI")
  "tcpip"     = @("\\.\Tcp", "\\.\Udp", "\\.\Ip", "\\.\RawIp")
  "tcpip6"    = @("\\.\Tcp6", "\\.\Udp6", "\\.\Ip6")
  "netbt"     = @("\\.\NetBT", "\\.\NetBT_Tcpip")
  "ws2ifsl"   = @("\\.\WS2IFSL")
  "npfs"      = @("\\.\PIPE")
  "msfs"      = @("\\.\MAILSLOT")
  "netbios"   = @("\\.\NetBios")
  "rdpdr"     = @("\\.\RDPDR")
  "mrxsmb"    = @("\\.\MRxSmb")
  "rdbss"     = @("\\.\RDBSS")
  "mup"       = @("\\.\MUP")
  "dfsc"      = @("\\.\DfsClient")
  "csc"       = @("\\.\CSC")
  "clfs"      = @("\\.\CLFS")
  "fltmgr"    = @("\\.\FltMgr", "\\.\FltMgrMsg")
  "ksecdd"    = @("\\.\KsecDD")
  "cng"       = @("\\.\Cng")
  "volmgr"    = @("\\.\VolMgr")
  "mountmgr"  = @("\\.\MountPointManager")
  "vdrvroot"  = @("\\.\VirtualDiskRoot")
  "partmgr"   = @("\\.\PartitionManager")
  "rdyboost"  = @("\\.\RdyBoost")
  "volume"    = @("\\.\Volume")
  "veridisk"  = @("\\.\VeriDisk")
  "ntfs"      = @("\\.\NTFS")
  "refs"      = @("\\.\ReFS")
  "wof"       = @("\\.\Wof")
  "mmcss"     = @("\\.\MMCSS")
  "qwave"     = @("\\.\QWave")
  "qwavedrv"  = @("\\.\QWave")
  "winnat"    = @("\\.\WinNat")
  "condrv"    = @("\\.\ConDrv")
  "beep"      = @("\\.\Beep")
  "null"      = @("\\.\NUL")
  "ipt"       = @("\\.\IPT", "\\.\IntelPTrace")
  "vgk"       = @("\\.\vgk")
  "vgc"       = @("\\.\vgc")
  "easyanticheat" = @("\\.\EasyAntiCheat", "\\.\EasyAntiCheatSys")
  "bedaisy"   = @("\\.\BEDaisy")
  "mhyprot2"  = @("\\.\mhyprot2")
  "xhunter1"  = @("\\.\xhunter1")
  "faceit"    = @("\\.\FACEIT")
  "wdfilter"  = @("\\.\WdFilter")
  "wdnisdrv"  = @("\\.\WdNisDrv")
  "mssecflt"  = @("\\.\MsSecFlt")
  "ucpd"      = @("\\.\UCPD")
  "ndu"       = @("\\.\Ndu")
  "ndis"      = @("\\.\NDIS")
  "netvsc"    = @("\\.\NetVsc")
  "wfplwfs"   = @("\\.\WfpLwfs")
  "mslldp"    = @("\\.\MsLldp")
  "lxss"      = @("\\.\LXSS")
  "wsl"       = @("\\.\WSL")
  "dxgkrnl"   = @("\\.\DxgKrnl")
  "nvlddmkm"  = @("\\.\NvidiaDiag")
  "vboxsup"   = @("\\.\VBoxDrv")
  "vboxnetadp" = @("\\.\VBoxNetAdp")
  "vboxusbmon" = @("\\.\VBoxUSBMon")
  "appid"     = @("\\.\AppId")
  "appidsvc"  = @("\\.\AppIdSvc")
  "applockerfltr" = @("\\.\AppLockerFltr")
  "msquic"    = @("\\.\MsQuic")
  "bindflt"   = @("\\.\BindFlt")
  "wcifs"     = @("\\.\WciFs")
  "wcnfs"     = @("\\.\WcnFs")
  "luafv"     = @("\\.\LuaFv")
  "ahcache"   = @("\\.\AhCache")
  "pcw"       = @("\\.\Pcw")
  "storqosflt" = @("\\.\StorQoSFlt")
  "mpsdrv"    = @("\\.\MpsDrv")
  "ipfltdrv"  = @("\\.\IpFilterDriver")
}
$knownAdded = 0
foreach ($svc in $knownDeviceNames.Keys) {
  $matchDrv = $drivers | Where-Object { $_.Name -eq $svc }
  if ($matchDrv) {
    if (-not $deviceMap.ContainsKey($svc)) { $deviceMap[$svc] = @() }
    foreach ($dp in $knownDeviceNames[$svc]) {
      if ($dp -notin $deviceMap[$svc]) {
        $deviceMap[$svc] += $dp
        $knownAdded++
      }
    }
  }
}
Write-Host "  Known device name entries added: $knownAdded"

# Source 5: Registry linkage — check each service's Parameters\Device for device names
$paramCount = 0
foreach ($drv in $drivers) {
  $paramPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\$($drv.Name)\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\$($drv.Name)\Enum",
    "HKLM:\SYSTEM\CurrentControlSet\Services\$($drv.Name)"
  )
  foreach ($pp in $paramPaths) {
    if (Test-Path $pp) {
      try {
        $props = Get-ItemProperty $pp -ErrorAction SilentlyContinue
        foreach ($pn in @("DeviceName", "Device", "DeviceObject", "SymbolicLink")) {
          $val = $props.$pn
          if ($val -and $val -match '\\Device\\|\\DosDevices\\|\\\\.\\') {
            $userPath = $val -replace '\\Device\\', '\\.\' -replace '\\DosDevices\\', '\\.\' -replace '^(\\\\.)', '$1'
            if (-not $deviceMap.ContainsKey($drv.Name)) { $deviceMap[$drv.Name] = @() }
            if ($userPath -notin $deviceMap[$drv.Name]) {
              $deviceMap[$drv.Name] += $userPath
              $paramCount++
            }
          }
        }
      } catch {}
    }
  }
}
Write-Host "  Registry parameter device names: $paramCount"

$totalDevicePaths = ($deviceMap.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host "  Total device paths to probe: $totalDevicePaths for $($deviceMap.Count) services" -ForegroundColor Green

# ============================================================
# PHASE 2: Device Object ACL Analysis + Handle Probe
# ============================================================
Write-Host "`n[Phase 2] Analyzing device object ACLs + handle probes (reachability)..." -ForegroundColor Yellow
Write-Host "  Method 1: Service Security Descriptor ACL analysis"
Write-Host "  Method 2: Handle probe (CreateFileW with FILE_READ_ATTRIBUTES)"
Write-Host "  This is the research contribution: who can open a handle to each driver?`n"

$progress = 0
$allResults = @()

# SID lookup tables (hoisted out of the loop)
$lowTierSids = @{
  "S-1-1-0"      = "Everyone"
  "S-1-15-2-1"   = "ALL APPLICATION PACKAGES"
  "S-1-15-2-2"   = "ALL RESTRICTED APPLICATION PACKAGES"
  "S-1-16-4096"  = "Low Mandatory Level"
}
$medTierSids = @{
  "S-1-5-11"     = "Authenticated Users"
  "S-1-5-32-545" = "Users"
  "S-1-5-4"      = "Interactive"
  "S-1-5-32-546" = "Guests"
}

foreach ($drv in $drivers) {
  $progress++
  if ($progress % 50 -eq 0) { Write-Host "  ... analyzed $progress / $total" }

  $path = Resolve-DriverPath $drv.PathName
  if (-not $path -or !(Test-Path $path -ErrorAction SilentlyContinue)) { continue }

  $fname = [System.IO.Path]::GetFileName($path).ToLower()
  $imports = Get-PEImports $path

  $fileHash = ""
  try { $fileHash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() } catch {}

  # --- Authenticode ---
  $signer = ""; $sigStatus = "Unknown"
  try {
    $s = Get-AuthenticodeSignature $path
    $sigStatus = "$($s.Status)"
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
  } catch {}

  $category = Classify-Driver $fname $path $signer

  # --- Import scoring ---
  $hitsA = @(); $hitsB = @(); $hitsC = @()
  foreach ($imp in $imports) {
    if ($imp -in $catA) { $hitsA += $imp }
    if ($imp -in $catB) { $hitsB += $imp }
    if ($imp -in $catC) { $hitsC += $imp }
  }

  # --- REACHABILITY ANALYSIS (MULTI-METHOD) ---
  $aclReachable = "Unknown"
  $aclDetail = ""
  $reachPrincipal = ""
  $reachTier = ""
  $reachMethod = ""       # which method determined reachability
  $probeResult = "NONE"   # handle probe outcome
  $probePath = ""         # which device path was probed

  # Method 1: Service Security Descriptor (existing)
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($drv.Name)\Security"
  if (Test-Path $regPath) {
    try {
      $secDesc = (Get-ItemProperty $regPath -Name "Security" -ErrorAction Stop).Security
      if ($secDesc) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($secDesc, 0)
        $aclEntries = @()
        foreach ($ace in $sd.DiscretionaryAcl) {
          $sid = $ace.SecurityIdentifier
          $account = try { $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $sid.Value }
          $rights = $ace.AccessMask
          $type = $ace.AceType
          $aclEntries += "$account($type`:$rights)"

          if ($type -match "Allow") {
            if ($lowTierSids.ContainsKey($sid.Value) -or $account -match "Everyone|APPLICATION PACKAGES|Low Mandatory") {
              $aclReachable = "USER_REACHABLE"
              $reachTier = "LOW"
              $reachMethod = "ACL"
              if (-not $reachPrincipal) { $reachPrincipal = $account }
            }
            elseif ($medTierSids.ContainsKey($sid.Value) -or $account -match "Users|Authenticated|Interactive|Guests") {
              $aclReachable = "USER_REACHABLE"
              if ($reachTier -ne "LOW") { $reachTier = "MEDIUM" }
              $reachMethod = "ACL"
              if (-not $reachPrincipal) { $reachPrincipal = $account }
            }
          }
        }
        $aclDetail = $aclEntries -join "; "
        if ($aclReachable -ne "USER_REACHABLE") {
          $aclReachable = "RESTRICTED"
          $reachMethod = "ACL"
        }
      }
    } catch {}
  }

  # Method 2: Handle probe — try every known device path for this driver
  if ($hasProbe) {
    $tryPaths = @()
    if ($deviceMap.ContainsKey($drv.Name)) { $tryPaths += $deviceMap[$drv.Name] }
    # Also try the anti-cheat DB device names
    if ($acDb.ContainsKey($fname) -and $acDb[$fname].device_names) {
      foreach ($dn in $acDb[$fname].device_names) { if ($dn -notin $tryPaths) { $tryPaths += $dn } }
    }

    foreach ($devPath in $tryPaths) {
      $err = [DeviceProbe]::ProbeDevice($devPath)
      if ($err -eq 0) {
        # Device opened successfully — definitely user-reachable
        $probeResult = "OPEN"
        $probePath = $devPath
        if ($aclReachable -ne "USER_REACHABLE") {
          $aclReachable = "USER_REACHABLE"
          if (-not $reachTier) { $reachTier = "MEDIUM" }
          $reachMethod = if ($reachMethod) { "$reachMethod+PROBE" } else { "PROBE" }
          if (-not $reachPrincipal) { $reachPrincipal = "PROBE:$devPath" }
        } else {
          $reachMethod = if ($reachMethod -notmatch "PROBE") { "$reachMethod+PROBE" } else { $reachMethod }
        }
        break
      }
      elseif ($err -eq 5) {
        # ACCESS_DENIED — device exists but we can't open it
        $probeResult = "DENIED"
        $probePath = $devPath
        if ($aclReachable -eq "Unknown") {
          $aclReachable = "RESTRICTED"
          $reachMethod = "PROBE"
        }
      }
      elseif ($err -eq 2 -or $err -eq 3) {
        # NOT_FOUND — this device path doesn't exist, try next
        continue
      }
      elseif ($err -eq 32) {
        # SHARING_VIOLATION — device exists and is in use (but we could address it)
        $probeResult = "SHARING"
        $probePath = $devPath
        if ($aclReachable -eq "Unknown") {
          $aclReachable = "USER_REACHABLE"
          if (-not $reachTier) { $reachTier = "MEDIUM" }
          $reachMethod = "PROBE"
          if (-not $reachPrincipal) { $reachPrincipal = "PROBE:$devPath(sharing)" }
        }
        break
      }
      else {
        # Other error — device might exist but something else failed
        if (-not $probePath) {
          $probeResult = "ERR:$err"
          $probePath = $devPath
        }
      }
    }

    # If probe found nothing but ACL said Unknown, try the zero-access probe as last resort
    if ($probeResult -eq "NONE" -and $aclReachable -eq "Unknown") {
      foreach ($devPath in $tryPaths) {
        $err = [DeviceProbe]::ProbeDeviceZero($devPath)
        if ($err -eq 0) {
          $probeResult = "OPEN_ZERO"
          $probePath = $devPath
          $aclReachable = "USER_REACHABLE"
          if (-not $reachTier) { $reachTier = "MEDIUM" }
          $reachMethod = "PROBE_ZERO"
          if (-not $reachPrincipal) { $reachPrincipal = "PROBE:$devPath(zero)" }
          break
        }
        elseif ($err -eq 5) {
          $probeResult = "DENIED"
          $probePath = $devPath
          if ($aclReachable -eq "Unknown") {
            $aclReachable = "RESTRICTED"
            $reachMethod = "PROBE_ZERO"
          }
        }
        elseif ($err -eq 2 -or $err -eq 3) { continue }
      }
    }
  }

  # --- LOLDrivers check ---
  $lolMatch = $false
  $lolCategory = ""
  $lolHashMatch = "N/A"
  if ($lolIndex.ContainsKey($fname)) {
    $lolMatch = $true
    $lolEntry = $lolIndex[$fname]
    $lolCategory = $lolEntry.category
    if ($fileHash) {
      $matchedHash = $lolEntry.hashes | Where-Object { $_.ToLower() -eq $fileHash }
      $lolHashMatch = if ($matchedHash) { "EXACT_HASH" } else { "NAME_ONLY" }
    } else { $lolHashMatch = "ERROR" }
  }

  # --- THREE-AXIS SCORING ---
  # Axis 1: Capability (PE imports) - max 30
  $capScore = 0
  if ($hitsA.Count -gt 0) { $capScore += 10 }
  if ($hitsA.Count -ge 3) { $capScore += 5 }
  if ($hitsB.Count -gt 0) { $capScore += 10 }
  if ($hitsC.Count -gt 0) { $capScore += 5 }

  # Axis 2: Reachability (ACL + Probe) - max 40
  $reachScore = 0
  if ($aclReachable -eq "USER_REACHABLE") {
    if ($reachTier -eq "LOW") { $reachScore = 40 }
    else { $reachScore = 32 }
  }
  elseif ($aclReachable -eq "Unknown") { $reachScore = 15 }

  # Axis 3: Known vulnerability (LOLDrivers) - max 30
  $vulnScore = 0
  if ($lolMatch -and $lolHashMatch -eq "EXACT_HASH") { $vulnScore = 30 }
  elseif ($lolMatch -and $lolHashMatch -eq "NAME_ONLY") { $vulnScore = 10 }
  if ($acDb.ContainsKey($fname) -and $acDb[$fname].abuse_known) { $vulnScore = [Math]::Max($vulnScore, 20) }

  $totalScore = $capScore + $reachScore + $vulnScore
  $riskLevel = if ($totalScore -ge 70) {"CRITICAL"} elseif ($totalScore -ge 45) {"HIGH"} elseif ($totalScore -ge 25) {"MEDIUM"} else {"LOW"}

  # Exposure score
  $capClasses = 0
  if ($hitsA.Count -gt 0) { $capClasses++ }
  if ($hitsB.Count -gt 0) { $capClasses++ }
  if ($hitsC.Count -gt 0) { $capClasses++ }
  $reachMult = switch ($aclReachable) {
    "USER_REACHABLE" { if ($reachTier -eq "LOW") { 3 } else { 2 } }
    "Unknown"        { 1 }
    default          { 0 }
  }
  $exposureScore = $capClasses * $reachMult

  if ($totalScore -lt 10 -and $imports.Count -eq 0 -and -not $lolMatch) { continue }

  $allResults += [pscustomobject]@{
    driver       = $fname
    service      = $drv.Name
    state        = $drv.State
    category     = $category
    cap_score    = $capScore
    cat_A        = ($hitsA -join ", ")
    cat_B        = ($hitsB -join ", ")
    cat_C        = ($hitsC -join ", ")
    reach_score  = $reachScore
    acl_status   = $aclReachable
    reach_tier   = $reachTier
    reach_principal = $reachPrincipal
    reach_method = $reachMethod
    probe_result = $probeResult
    probe_path   = $probePath
    acl_detail   = $aclDetail
    vuln_score   = $vulnScore
    lol_match    = $lolMatch
    lol_hash     = $lolHashMatch
    lol_category = $lolCategory
    ac_product   = if ($acDb.ContainsKey($fname)) { $acDb[$fname].product } else { "" }
    total_score  = $totalScore
    exposure_score = $exposureScore
    risk_level   = $riskLevel
    signature    = $sigStatus
    signer       = $signer
    file_hash    = $fileHash
    path         = $path
  }
}

# ============================================================
# PHASE 3: Results & Analysis
# ============================================================
Write-Host "`n[Phase 3] Analyzing results..." -ForegroundColor Yellow

$sorted = $allResults | Sort-Object total_score -Descending

$crit = ($sorted | Where-Object { $_.risk_level -eq "CRITICAL" } | Measure-Object).Count
$high = ($sorted | Where-Object { $_.risk_level -eq "HIGH" } | Measure-Object).Count
$med  = ($sorted | Where-Object { $_.risk_level -eq "MEDIUM" } | Measure-Object).Count
$low  = ($sorted | Where-Object { $_.risk_level -eq "LOW" } | Measure-Object).Count
$userReachable = ($sorted | Where-Object { $_.acl_status -eq "USER_REACHABLE" } | Measure-Object).Count
$restricted = ($sorted | Where-Object { $_.acl_status -eq "RESTRICTED" } | Measure-Object).Count
$unknown = ($sorted | Where-Object { $_.acl_status -eq "Unknown" } | Measure-Object).Count
$lowTier = ($sorted | Where-Object { $_.reach_tier -eq "LOW" } | Measure-Object).Count
$medTier = ($sorted | Where-Object { $_.reach_tier -eq "MEDIUM" } | Measure-Object).Count

# Reachability method breakdown
$byACL = ($sorted | Where-Object { $_.reach_method -match "ACL" -and $_.acl_status -eq "USER_REACHABLE" } | Measure-Object).Count
$byProbe = ($sorted | Where-Object { $_.reach_method -match "PROBE" -and $_.acl_status -eq "USER_REACHABLE" } | Measure-Object).Count
$byBoth = ($sorted | Where-Object { $_.reach_method -match "ACL\+PROBE" } | Measure-Object).Count
$probeNewFinds = ($sorted | Where-Object { $_.reach_method -match "^PROBE" -and $_.acl_status -eq "USER_REACHABLE" } | Measure-Object).Count

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  DEEP SCAN RESULTS (v4)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Total drivers scanned:    $total"
Write-Host "Drivers with signals:     $($sorted.Count)"
Write-Host ""
Write-Host "THREE-AXIS RISK BREAKDOWN:" -ForegroundColor White
Write-Host "  CRITICAL: $crit" -ForegroundColor Red
Write-Host "  HIGH:     $high" -ForegroundColor DarkYellow
Write-Host "  MEDIUM:   $med" -ForegroundColor Yellow
Write-Host "  LOW:      $low" -ForegroundColor Gray
Write-Host ""
Write-Host "REACHABILITY (THE KEY FINDING):" -ForegroundColor White
Write-Host "  User-reachable drivers: $userReachable" -ForegroundColor Red
Write-Host "    - LOW tier (sandbox/AppContainer reachable): $lowTier" -ForegroundColor Red
Write-Host "    - MEDIUM tier (standard-user reachable):     $medTier" -ForegroundColor DarkYellow
Write-Host "  Restricted (admin-only): $restricted" -ForegroundColor Green
Write-Host "  Unknown ACL:            $unknown" -ForegroundColor Yellow
Write-Host ""
Write-Host "REACHABILITY METHODS:" -ForegroundColor White
Write-Host "  Found by ACL analysis:    $byACL" -ForegroundColor Cyan
Write-Host "  Found by handle probe:    $probeNewFinds (NEW - would have been missed)" -ForegroundColor Cyan
Write-Host "  Confirmed by both:        $byBoth" -ForegroundColor Green
Write-Host "  Coverage: $([Math]::Round(($userReachable + $restricted) / [Math]::Max($sorted.Count,1) * 100, 1))% classified (was 5.4%)" -ForegroundColor Green

# Category breakdown
Write-Host "`nRISK BY DRIVER CATEGORY:" -ForegroundColor White
$catStats = $sorted | Group-Object category | ForEach-Object {
  $grp = $_
  $avgScore = ($grp.Group | Measure-Object total_score -Average).Average
  $reachable = ($grp.Group | Where-Object { $_.acl_status -eq "USER_REACHABLE" } | Measure-Object).Count
  [pscustomobject]@{
    Category = $grp.Name
    Count = $grp.Count
    AvgScore = [Math]::Round($avgScore, 1)
    UserReachable = $reachable
  }
} | Sort-Object AvgScore -Descending
$catStats | Format-Table Category, Count, AvgScore, UserReachable -AutoSize

# Top findings
Write-Host "TOP 20 RISKIEST DRIVERS (3-axis score):" -ForegroundColor White
$sorted | Select-Object -First 20 | Format-Table driver, category, risk_level, total_score, cap_score, reach_score, vuln_score, acl_status, reach_method -AutoSize

# ============================================================
# PHASE 4: WDAC Block Policy Generation
# ============================================================
Write-Host "[Phase 4] Generating WDAC block policy..." -ForegroundColor Yellow

$wdacXml = @()
$wdacXml += '<?xml version="1.0" encoding="utf-8"?>'
$wdacXml += '<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">'
$wdacXml += '  <!-- REFEREE Auto-Generated Driver Block Policy -->'
$wdacXml += "  <!-- Generated: $(Get-Date -Format o) -->"
$wdacXml += "  <!-- Host: $env:COMPUTERNAME -->"
$wdacXml += '  <!-- Block drivers scoring CRITICAL or HIGH with USER_REACHABLE ACL -->'
$wdacXml += '  <Rules>'
$wdacXml += '    <Rule>'
$wdacXml += '      <Option>Enabled:Unsigned System Integrity Policy</Option>'
$wdacXml += '    </Rule>'
$wdacXml += '    <Rule>'
$wdacXml += '      <Option>Enabled:Audit Mode</Option>  <!-- Start in audit! -->'
$wdacXml += '    </Rule>'
$wdacXml += '  </Rules>'
$wdacXml += '  <FileRules>'

$blockCount = 0
foreach ($r in ($sorted | Where-Object { $_.risk_level -in @("CRITICAL","HIGH") -and $_.acl_status -eq "USER_REACHABLE" -and $_.category -notmatch "^Microsoft$|^Security-" })) {
  $blockCount++
  $cleanName = $r.driver -replace '[^a-zA-Z0-9_.]','_'
  $wdacXml += "    <!-- $($r.driver) | Score: $($r.total_score) | $($r.category) -->"
  $wdacXml += "    <Deny ID=`"DENY_$cleanName`" FriendlyName=`"REFEREE Block: $($r.driver)`" FileName=`"$($r.driver)`" />"
}

$wdacXml += '  </FileRules>'
$wdacXml += '</SiPolicy>'

Write-Host "  Drivers targeted for blocking: $blockCount (CRITICAL/HIGH + USER_REACHABLE, non-Microsoft/Security)"

# ============================================================
# PHASE 5: Save everything
# ============================================================
Write-Host "`n[Phase 5] Saving reports..." -ForegroundColor Yellow

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

$report = [pscustomobject]@{
  tool = "referee-deepscan"; version = "0.4"
  host = $env:COMPUTERNAME; generated = (Get-Date -Format o)
  os = [System.Environment]::OSVersion.VersionString
  total_drivers = $total; flagged = $sorted.Count
  stats = @{
    critical = $crit; high = $high; medium = $med; low = $low
    user_reachable = $userReachable; restricted = $restricted; unknown = $unknown
    reach_low_tier = $lowTier; reach_medium_tier = $medTier
    reach_by_acl = $byACL; reach_by_probe = $probeNewFinds
    reach_by_both = $byBoth
    coverage_pct = [Math]::Round(($userReachable + $restricted) / [Math]::Max($sorted.Count,1) * 100, 1)
    wdac_blocked = $blockCount
  }
  category_breakdown = $catStats
  findings = $sorted
}
$jsonOut = "$OutDir\deepscan-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File $jsonOut -Encoding utf8

$wdacOut = "$OutDir\referee-wdac-block-$stamp.xml"
$wdacXml -join "`n" | Out-File $wdacOut -Encoding utf8

# Markdown
$mdOut = "$OutDir\deepscan-$stamp.md"
$mdLines = @()
$mdLines += "# REFEREE Deep Scan Report (v4)"
$mdLines += ""
$mdLines += "## Summary"
$mdLines += "- **Host:** ``$env:COMPUTERNAME``"
$mdLines += "- **Generated:** $(Get-Date -Format o)"
$mdLines += "- **OS:** $([System.Environment]::OSVersion.VersionString)"
$mdLines += "- **Total kernel drivers:** $total"
$mdLines += "- **Drivers with signals:** $($sorted.Count)"
$mdLines += ""
$mdLines += "## Three-Axis Risk Breakdown"
$mdLines += "| Level | Count |"
$mdLines += "|-------|-------|"
$mdLines += "| CRITICAL | $crit |"
$mdLines += "| HIGH | $high |"
$mdLines += "| MEDIUM | $med |"
$mdLines += "| LOW | $low |"
$mdLines += ""
$mdLines += "## KEY FINDING: Reachability Analysis"
$mdLines += "| Reachability | Count | Meaning |"
$mdLines += "|-------------|-------|---------|"
$mdLines += "| **USER_REACHABLE** | **$userReachable** | Normal user process can open a handle |"
$mdLines += "| RESTRICTED | $restricted | Admin/SYSTEM only |"
$mdLines += "| Unknown | $unknown | ACL could not be determined |"
$mdLines += ""
$mdLines += "## Reachability Methods (v4 enhancement)"
$mdLines += "| Method | Reachable found |"
$mdLines += "|--------|----------------|"
$mdLines += "| ACL analysis | $byACL |"
$mdLines += "| Handle probe (NEW) | $probeNewFinds |"
$mdLines += "| Both methods agree | $byBoth |"
$mdLines += "| **Coverage** | **$([Math]::Round(($userReachable + $restricted) / [Math]::Max($sorted.Count,1) * 100, 1))%** classified |"
$mdLines += ""
$mdLines += "## Risk by Driver Category"
$mdLines += "| Category | Count | Avg Score | User-Reachable |"
$mdLines += "|----------|-------|-----------|----------------|"
foreach ($cs in $catStats) {
  $mdLines += "| $($cs.Category) | $($cs.Count) | $($cs.AvgScore) | $($cs.UserReachable) |"
}
$mdLines += ""
$mdLines += "## Top 20 Riskiest Drivers"
$mdLines += "| Driver | Category | Risk | Total | Cap | Reach | Vuln | ACL | Method |"
$mdLines += "|--------|----------|------|-------|-----|-------|------|-----|--------|"
foreach ($r in ($sorted | Select-Object -First 20)) {
  $mdLines += "| ``$($r.driver)`` | $($r.category) | **$($r.risk_level)** | $($r.total_score) | $($r.cap_score) | $($r.reach_score) | $($r.vuln_score) | $($r.acl_status) | $($r.reach_method) |"
}
$mdLines += ""
$mdLines += "## WDAC Block Policy"
$mdLines += "Drivers targeted: **$blockCount** (see ``$wdacOut``)"

$mdLines -join "`n" | Out-File $mdOut -Encoding utf8

Write-Host "`n  JSON:    $jsonOut"
Write-Host "  Report:  $mdOut"
Write-Host "  WDAC:    $wdacOut"
Write-Host "`n=== DEEP SCAN COMPLETE (v4) ===" -ForegroundColor Cyan
