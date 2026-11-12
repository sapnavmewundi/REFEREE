# REFEREE Lab - Safe Testing Environment

## Overview
The REFEREE lab lets you reproduce all scanner findings and test detection
rules in an isolated environment. No game installs or live anti-cheat
drivers required.

## Components

### 1. EDR Telemetry Simulator (`EDR-Simulator.ps1`)
Generates synthetic Windows Event Log-style events matching the patterns
our Sigma/YARA rules detect. Produces JSON + XML output that can be fed
into Sigma testing tools.

```powershell
powershell -ExecutionPolicy Bypass -File lab\EDR-Simulator.ps1
```

**Scenarios generated:**
| # | Scenario | Sigma Rule | Expected |
|---|----------|-----------|----------|
| 1 | AC driver registered outside game path | ref-001 | ALERT |
| 2 | mhyprot loaded from temp directory | ref-001 | ALERT |
| 3 | Non-game process opens Vanguard device | ref-002 | ALERT |
| 4 | cmd.exe opens mhyprot device | ref-002 | ALERT |
| 5 | Kernel callback removal | ref-003 | ALERT |
| 6 | Image load callback removal | ref-003 | ALERT |
| 7 | Legitimate Vanguard install (baseline) | ref-001 | NO ALERT |
| 8 | VALORANT accessing Vanguard (baseline) | ref-002 | NO ALERT |

### 2. Capability Scanner (`auditor/Referee-CapScan.ps1`)
Run the capability scanner in the VM to get a clean baseline scan.
Compare results between VMs with and without games installed.

### 3. LOLDrivers Cross-Reference (`auditor/Referee-LOLCheck.ps1`)
Downloads the latest loldrivers.io database and checks for
known-vulnerable drivers. Safe to run anywhere.

## Lab Setup

### Option A: Windows VM (Recommended)
1. **VM software:** VirtualBox, VMware, or Hyper-V
2. **OS:** Windows 10/11 (any edition, even evaluation)
3. **Requirements:** 4GB RAM, 40GB disk
4. **Snapshot** the clean VM before testing

```
# In the VM:
git clone <referee-repo>
cd referee

# Run all scanners
powershell -ExecutionPolicy Bypass -File auditor\Referee-Audit.ps1
powershell -ExecutionPolicy Bypass -File auditor\Referee-CapScan.ps1
powershell -ExecutionPolicy Bypass -File auditor\Referee-LOLCheck.ps1

# Generate visual dashboard
powershell -ExecutionPolicy Bypass -File auditor\Generate-Report.ps1

# Run EDR simulator for detection testing
powershell -ExecutionPolicy Bypass -File lab\EDR-Simulator.ps1

# Open dashboard
start auditor\out\dashboard-*.html
```

### Option B: Live host (non-destructive)
All REFEREE tools are **read-only** - they enumerate drivers and read PE
headers but never send IOCTLs, open device objects, or modify anything.
Safe to run on a production machine for fleet assessment.

## Testing detection rules

### Using sigma-cli
```bash
# Install sigma-cli
pip install sigma-cli

# Convert Sigma rules to your SIEM format
sigma convert -t splunk detections/ac-driver-abuse.yml
sigma convert -t elastic detections/ac-driver-abuse.yml

# Test against simulator output
# Import lab/sim-output/edr-sim-*.xml into your SIEM test instance
```

### Using YARA
```bash
# Install yara
# Scan the drivers directory
yara -r detections/ac-driver-imports.yar C:\Windows\System32\drivers\
```

## Reproducing the demo

For the BSides live demo:
1. Open the HTML dashboard (shows the scan results visually)
2. Run the capability scanner live (audience sees drivers being scored)
3. Run the LOLDrivers check (real-time cross-reference)
4. Show the EDR simulator output (what defenders should look for)
5. Show the Sigma/YARA rules (what to deploy today)

The entire demo is read-only and safe to run on stage with a live machine.
