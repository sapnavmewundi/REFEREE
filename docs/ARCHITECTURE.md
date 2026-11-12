# REFEREE Architecture

## System Overview

REFEREE is a modular, pipeline-based toolkit where each tool can run independently or compose into larger workflows. The architecture follows a **scan → score → report → respond** pattern.

```
                         ┌─────────────────────────┐
                         │     Windows Kernel       │
                         │  (loaded driver objects)  │
                         └────────────┬────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
              ┌─────▼─────┐   ┌──────▼──────┐   ┌─────▼─────┐
              │ PE Import  │   │ Device Name  │   │ LOLDrivers│
              │ Analysis   │   │ Discovery    │   │ Database  │
              │            │   │ (5 sources)  │   │ (702 hashes│
              │ MmMapIo*   │   │              │   │  + names) │
              │ ZwOpen*    │   │ ┌──────────┐ │   │           │
              │ ObRegister*│   │ │ CreateFi │ │   │ SHA256    │
              │ PsSetCreate│   │ │ leW probe│ │   │ verify    │
              └─────┬──────┘   │ └────┬─────┘ │   └─────┬─────┘
                    │          │      │       │         │
                    │          └──────┼───────┘         │
                    │                 │                 │
              ┌─────▼─────┐   ┌──────▼──────┐   ┌─────▼─────┐
              │ Capability │   │Reachability │   │ Known-Vuln│
              │ Score      │   │ Score       │   │ Score     │
              │ (0-30)     │   │ (0-30)      │   │ (0-40)    │
              └─────┬──────┘   └──────┬──────┘   └─────┬─────┘
                    │                 │                 │
                    └────────┬────────┘────────┬───────┘
                             ▼                 ▼
                    ┌─────────────────────────────────┐
                    │     Composite Risk Score         │
                    │          (0-100)                  │
                    │                                   │
                    │  CRITICAL ≥60  HIGH ≥40           │
                    │  MEDIUM ≥20    LOW <20            │
                    │                                   │
                    │  + 12-category driver taxonomy    │
                    └────────────────┬─────────────────┘
                                     │
        ┌──────────┬─────────┬───────┼───────┬──────────┬──────────┐
        ▼          ▼         ▼       ▼       ▼          ▼          ▼
   ┌────────┐ ┌────────┐ ┌──────┐ ┌─────┐ ┌──────┐ ┌────────┐ ┌──────┐
   │  JSON  │ │Markdown│ │ WDAC │ │Delta│ │ Gap  │ │Dashboard│ │Fleet │
   │ Report │ │Summary │ │Policy│ │ Diff│ │Matrix│ │ (HTML) │ │Aggr. │
   └────────┘ └────────┘ └──────┘ └─────┘ └──────┘ └────────┘ └──────┘
```

## Component Architecture

### Tier 1: Core Scanner

**`Referee-DeepScan.ps1`** — the headline tool. Orchestrates all three axes.

```
Input: Live Windows system (loaded drivers from Get-CimInstance Win32_SystemDriver)
  │
  ├── Phase 1: Driver Enumeration
  │   └── Get-CimInstance → 482 driver objects with paths, state, start mode
  │
  ├── Phase 2: Capability Analysis (Axis 1)
  │   ├── PE header parsing (MZ check → PE offset → import table)
  │   ├── Import categorization:
  │   │   ├── Memory access (MmMapIoSpaceEx, ZwMapViewOfSection, ...)
  │   │   ├── Cross-process (ZwOpenProcess, PsLookupProcessByProcessId, ...)
  │   │   └── Callback removal (ObUnRegisterCallbacks, PsRemoveCreateThreadNotifyRoutine, ...)
  │   └── Score: 0-30 based on category count and severity
  │
  ├── Phase 3: Reachability Analysis (Axis 2)
  │   ├── Device name discovery (5 cascading sources):
  │   │   ├── Registry DeviceMap (HKLM:\SYSTEM\CurrentControlSet\Control\DeviceMap)
  │   │   ├── Device interface classes (via SetupAPI)
  │   │   ├── IoCreateDevice naming conventions (\\.\<ServiceName>)
  │   │   ├── Known driver→device mapping table (70+ entries)
  │   │   └── Service Parameters registry keys
  │   ├── P/Invoke CreateFileW handle probe:
  │   │   ├── Opens each device at FILE_READ_ATTRIBUTES (zero-access)
  │   │   ├── Success → USER_REACHABLE, failure → RESTRICTED
  │   │   └── Integrity tier: LOW (AppContainer) vs MEDIUM (standard user)
  │   └── Score: 0-30 based on reachability + tier
  │
  ├── Phase 4: Known Vulnerability Check (Axis 3)
  │   ├── Load loldrivers-simple.json (702 entries)
  │   ├── SHA256 hash computation for each driver binary
  │   ├── Hash match → EXACT (confirmed vulnerable)
  │   ├── Name match only → NAME_ONLY (likely patched)
  │   └── Score: 0-40 (highest weight — a known-bad driver is the strongest signal)
  │
  ├── Phase 5: Scoring + Classification
  │   ├── Composite score = capability + reachability + known_vuln
  │   ├── Risk level: CRITICAL (≥60), HIGH (≥40), MEDIUM (≥20), LOW (<20)
  │   └── Category assignment (12 categories via service/signer heuristics)
  │
  └── Phase 6: Output Generation
      ├── JSON report (full structured data)
      ├── Markdown summary (human-readable)
      └── WDAC block policy (for CRITICAL/HIGH + reachable drivers)
```

### Tier 2: Analysis Tools

These tools consume DeepScan JSON output for secondary analysis.

| Tool | Input | Output | Use Case |
|------|-------|--------|----------|
| **Gap** | DeepScan JSON | Gap matrix JSON + MD | What catalogs miss |
| **Delta** | Two DeepScan JSONs | Diff report | Attack surface change after install |
| **Fleet** | Multiple hosts | Aggregated JSON | Config-drift detection |
| **DriverDiff** | Two scan JSONs | Change report | Longitudinal binary tracking |

### Tier 3: Response Tools

These tools generate deployable countermeasures from findings.

| Tool | Input | Output | Deployment |
|------|-------|--------|------------|
| **WDACValidate** | DeepScan JSON | `.p7b` policy + validation | Group Policy / MDM |
| **Sigma rules** | Event logs | Alert triggers | SIEM (Splunk, Elastic, Sentinel) |
| **YARA rules** | Driver binaries | Binary detection | Endpoint scanning |

### Tier 4: Monitoring

| Tool | Mode | Event Source |
|------|------|-------------|
| **Monitor** | Continuous / one-shot | Sysmon EID 6, System EID 7045 |
| **EDR Simulator** | Test generation | Synthetic events for rule validation |

## Data Flow

```
                     Single Host                           Fleet
                     ──────────                           ─────
                         │                                  │
                    DeepScan.ps1                       Fleet.ps1
                         │                            ┌────┼────┐
                         ▼                            │    │    │
                  deepscan-*.json              Host1  Host2  Host3
                         │                     │      │      │
            ┌────────────┼────────────┐        └──────┼──────┘
            │            │            │               │
         Gap.ps1    Delta.ps1   WDACValidate    fleet-*.json
            │            │            │               │
        gap-*.json  delta-*.md  policy.p7b     DriverDiff.ps1
            │            │            │               │
            └────────────┴────────────┘          drift report
                         │
                   dashboard.html
                   (interactive)
                         │
                   analyze.py
                   (reproducible
                    figures)
```

## Security Model

### What REFEREE does NOT do

| Action | Status | Why |
|--------|--------|-----|
| Send IOCTLs to drivers | **NEVER** | Could trigger driver behavior |
| Load kernel drivers | **NEVER** | Would require ring-0 access |
| Modify driver binaries | **NEVER** | Integrity preservation |
| Write to device objects | **NEVER** | Read-only handle probe |
| Extract dispatch tables | **NEVER** | Exploit-adjacent |
| Fuzz IOCTL interfaces | **NEVER** | Offensive technique |

### What REFEREE does

| Action | Method | Risk |
|--------|--------|------|
| Read PE imports | File I/O on `System32\drivers\*.sys` | None — static file read |
| Probe device handles | `CreateFileW` at `FILE_READ_ATTRIBUTES` | None — OS-level read check |
| Read registry ACLs | `Get-Acl` on service keys | None — registry read |
| Compute SHA256 hashes | `Get-FileHash` on driver binaries | None — hash only |
| Query CIM/WMI | `Get-CimInstance` for driver state | None — standard admin query |

### Integrity Tier Classification

```
Process Integrity Level          Driver Reachability Tier
───────────────────────          ───────────────────────
SYSTEM / High                    Not tested (admin access assumed)
Medium (standard user)    ──▶    MEDIUM tier (standard-user reachable)
Low (restricted)                 Not tested (subset of Medium)
Untrusted / AppContainer  ──▶   LOW tier (sandbox-reachable = worst finding)
```

A LOW-tier finding means a sandboxed process (browser renderer, containerized app) can reach the driver — this is the most severe reachability classification.

## Output Schema

### DeepScan JSON

```json
{
  "tool": "referee-deepscan",
  "version": "4.0",
  "host": "HOSTNAME",
  "os": "Windows 11 26300",
  "generated": "2026-11-09T16:16:46+05:30",
  "total_drivers": 482,
  "flagged": 480,
  "stats": {
    "critical": 1,
    "high": 44,
    "medium": 266,
    "low": 169,
    "user_reachable": 56,
    "reach_low_tier": 5,
    "restricted": 6,
    "unknown": 418,
    "wdac_block_candidates": 2
  },
  "findings": [
    {
      "driver": "ipt.sys",
      "path": "C:\\Windows\\System32\\drivers\\ipt.sys",
      "signer": "Microsoft Windows",
      "category": "Microsoft",
      "acl_status": "USER_REACHABLE",
      "reach_tier": "LOW",
      "reach_method": "HANDLE_PROBE",
      "device_path": "\\\\.\\IPT",
      "capability_score": 20,
      "reachability_score": 30,
      "known_vuln_score": 20,
      "total_score": 70,
      "risk_level": "CRITICAL",
      "imports": { "memory_access": [...], "cross_process": [...], "callback_removal": [...] },
      "loldrivers_match": "NONE"
    }
  ]
}
```

## Extending REFEREE

### Adding a new device name discovery source

In `Referee-DeepScan.ps1`, the `Get-DeviceNames` function cascades through discovery sources. Add a new source by:

1. Adding a discovery function that returns `[string[]]` device paths
2. Registering it in the cascade array
3. Tagging results with the source name for method attribution

### Adding a new driver category

In the `Get-DriverCategory` function, add a new pattern-match block:

```powershell
if ($svc -match 'yourpattern' -or $signer -match 'Vendor') { return "Category-Name" }
```

### Adding Sigma rules

Follow the existing pattern in `detections/ac-driver-abuse.yml`:
- Use correct logsource (Sysmon for EID 6, Security for 4663, System for 7045)
- Include path-based filters to suppress legitimate game installs
- Test with `lab/EDR-Simulator.ps1`
